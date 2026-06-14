/*=============================================================================
 * dhcp.c - DHCP Client Implementation
 *============================================================================*/
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "kernel.h"
#include "net.h"
#include "dhcp.h"
#include "kprintf.h"
#include "util.h"
#include "dns.h"
#include "firewall.h"
#include "crypto.h"  // For csprng_random_bytes()

/*=============================================================================
 * GLOBAL STATE
 *============================================================================*/
static dhcp_client_t dhcp_client;

/*=============================================================================
 * DHCP TRANSACTION ID GENERATION
 * SECURITY FIX: Use CSPRNG for Unpredictable Transaction IDs
 *=============================================================================*/

/**
 * @brief Generate a new transaction ID with cryptographic randomness
 * SECURITY FIX: Previous implementation used predictable LCG with timer mixing:
 *   dhcp_xid_state = (dhcp_xid_state * 1103515245u + 12345u) ^ (ticks * 31337u);
 *
 * Attack: DHCP server spoofing / Man-in-the-middle via XID prediction
 * 1. Attacker observes a few DHCP DISCOVER packets to extract XID pattern
 * 2. Attacker predicts next XID using LCG formula (fixed seed 0x12345678)
 * 3. On victim's next DHCP request, attacker races to send forged DHCP OFFER
 *    with predicted XID before legitimate server responds
 * 4. Victim accepts attacker's OFFER: malicious IP config, DNS, gateway
 * 5. All victim traffic now routes through attacker (full MitM)
 *
 * Impact severity:
 * - Attacker becomes default gateway → intercepts ALL network traffic
 * - Attacker controls DNS → redirects google.com to phishing site
 * - Attacker can inject JavaScript into HTTP responses
 * - Breaks SSH, HTTPS by MitM certificate injection
 *
 * The fix: Use ChaCha20-based CSPRNG for 2^32 uniformly-distributed XIDs.
 * Makes prediction computationally infeasible even with millions of samples.
 *
 * This is CRITICAL for any perimeter/firewall deployment where the network
 * may contain malicious devices (coffee shop WiFi, conference networks, etc.).
 */
static uint32_t generate_xid(void) {
    uint32_t xid;
    csprng_random_bytes(&global_csprng, (uint8_t*)&xid, sizeof(uint32_t));

    /* Ensure non-zero XID (RFC 2131 doesn't require it, but convention) */
    if (xid == 0) {
        xid = 1;
    }

    return xid;
}

/*=============================================================================
 * HELPER FUNCTIONS
 *============================================================================*/

/**
 * @brief Parse DHCP options from a DHCP packet
 * SECURITY: Protected against buffer over-read attacks by validating all lengths
 */
static void parse_dhcp_options(const uint8_t* options, size_t options_len,
                               uint8_t* msg_type, uint8_t* server_ip,
                               uint8_t* subnet_mask_out, uint8_t* router,
                               uint8_t* dns_server, uint32_t* lease_time)
{
    size_t i = 0;

    /*=========================================================================
     * SECURITY: Limit maximum iterations to prevent infinite loop DoS
     * With 312 bytes of DHCP options (max), worst case is 312 iterations
     * Add safety factor: 512 iterations max
     *=======================================================================*/
    #define MAX_DHCP_OPTION_ITERATIONS 512
    int iterations = 0;

    while (i < options_len) {
        /* Safety: Prevent infinite loop from malformed options */
        if (++iterations > MAX_DHCP_OPTION_ITERATIONS) {
            kprintf("DHCP: Warning - excessive option iterations, stopping parse\n");
            break;
        }

        uint8_t option = options[i++];

        if (option == DHCP_OPTION_END) {
            break;
        }

        if (option == 0) { // Pad option
            continue;
        }

        /* SECURITY: Ensure we can read the length byte */
        if (i >= options_len) {
            kprintf("DHCP: Malformed options - truncated length field\n");
            break;
        }

        uint8_t len = options[i++];

        /*=====================================================================
         * SECURITY: Validate option data doesn't exceed buffer bounds
         * CRITICAL: Check for integer overflow before adding len to i
         * If len is large (e.g., 0xFF) and i is near options_len, the
         * addition could overflow, causing us to skip validation and read
         * past the buffer boundary.
         *===================================================================*/
        // First check: ensure we can safely add len to i without overflow
        if (len > (options_len - i)) {
            kprintf("DHCP: Malformed option %d - length %d exceeds remaining %u bytes\n",
                    option, len, (unsigned int)(options_len - i));
            break;
        }

        /* NOTE: len is uint8_t so it cannot exceed 255 by definition */

        switch (option) {
            case DHCP_OPTION_MESSAGE_TYPE:
                if (len >= 1 && msg_type) {
                    *msg_type = options[i];
                }
                break;

            case DHCP_OPTION_SERVER_ID:
                /* SECURITY: Exact length check - must be exactly 4 bytes for IPv4 */
                if (len == 4 && server_ip) {
                    memcpy(server_ip, &options[i], 4);
                }
                break;

            case DHCP_OPTION_SUBNET_MASK:
                if (len == 4 && subnet_mask_out) {
                    memcpy(subnet_mask_out, &options[i], 4);
                }
                break;

            case DHCP_OPTION_ROUTER:
                if (len >= 4 && router) {
                    /* Only use first router if multiple provided */
                    memcpy(router, &options[i], 4);
                }
                break;

            case DHCP_OPTION_DNS_SERVER:
                if (len >= 4 && dns_server) {
                    /* Only use first DNS server if multiple provided */
                    memcpy(dns_server, &options[i], 4);
                }
                break;

            case DHCP_OPTION_LEASE_TIME:
                if (len == 4 && lease_time) {
                    /* SECURITY: Safe unaligned read - copy to aligned temp first */
                    uint32_t temp;
                    memcpy(&temp, &options[i], 4);
                    *lease_time = ntohl(temp);
                }
                break;
        }

        i += len;
    }

    #undef MAX_DHCP_OPTION_ITERATIONS
}

/**
 * @brief Build and send a DHCP message
 */
static void send_dhcp_message(uint8_t msg_type, const uint8_t* requested_ip, 
                             const uint8_t* server_ip)
{
    uint8_t packet[1024];
    memset(packet, 0, sizeof(packet));
    
    size_t offset = 0;
    
    // Ethernet header
    eth_header_t* eth = (eth_header_t*)(packet + offset);
    memset(eth->dest_mac, 0xFF, 6); // Broadcast
    memcpy(eth->src_mac, my_mac, 6);
    eth->ethertype = htons(ETH_TYPE_IPV4);
    offset += sizeof(eth_header_t);
    
    // IP header
    ip_header_t* ip = (ip_header_t*)(packet + offset);
    ip->version_ihl = 0x45; // IPv4, 20 byte header
    ip->tos = 0;
    ip->identification = 0;
    ip->flags_fragment = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    memset(ip->src_ip, 0, 4);  // 0.0.0.0 for discovery
    memset(ip->dest_ip, 0xFF, 4); // Broadcast
    offset += sizeof(ip_header_t);
    
    // UDP header
    udp_header_t* udp = (udp_header_t*)(packet + offset);
    udp->src_port = htons(DHCP_CLIENT_PORT);
    udp->dest_port = htons(DHCP_SERVER_PORT);
    offset += sizeof(udp_header_t);
    
    // DHCP header
    dhcp_header_t* dhcp = (dhcp_header_t*)(packet + offset);
    dhcp->op = DHCP_OP_BOOTREQUEST;
    dhcp->htype = DHCP_HTYPE_ETHERNET;
    dhcp->hlen = DHCP_HLEN_ETHERNET;
    dhcp->hops = 0;
    dhcp->xid = htonl(dhcp_client.xid);
    dhcp->secs = 0;
    dhcp->flags = htons(0x8000); // Broadcast flag
    memset(dhcp->ciaddr, 0, 4);
    memset(dhcp->yiaddr, 0, 4);
    memset(dhcp->siaddr, 0, 4);
    memset(dhcp->giaddr, 0, 4);
    memcpy(dhcp->chaddr, my_mac, 6);
    memset(dhcp->chaddr + 6, 0, 10);
    dhcp->magic_cookie = htonl(DHCP_MAGIC_COOKIE);
    offset += sizeof(dhcp_header_t);

    /*=========================================================================
     * SECURITY: Define maximum DHCP options capacity
     * CRITICAL: packet[1024] - headers ≈ 746 bytes available for options.
     * We conservatively limit to 512 bytes to account for variable headers.
     *========================================================================*/
    #define DHCP_MAX_OPTIONS 512

    // DHCP options
    uint8_t* options = packet + offset;
    size_t opt_offset = 0;

    // Message Type (3 bytes needed)
    if (opt_offset + 3 > DHCP_MAX_OPTIONS) goto options_overflow;
    options[opt_offset++] = DHCP_OPTION_MESSAGE_TYPE;
    options[opt_offset++] = 1;
    options[opt_offset++] = msg_type;

    // Client Identifier (9 bytes needed: tag + len + htype + 6-byte MAC)
    if (opt_offset + 9 > DHCP_MAX_OPTIONS) goto options_overflow;
    options[opt_offset++] = DHCP_OPTION_CLIENT_ID;
    options[opt_offset++] = 7;
    options[opt_offset++] = DHCP_HTYPE_ETHERNET;
    memcpy(&options[opt_offset], my_mac, 6);
    opt_offset += 6;

    // Requested IP (for REQUEST) (6 bytes needed: tag + len + 4-byte IP)
    if (msg_type == DHCP_REQUEST && requested_ip) {
        if (opt_offset + 6 > DHCP_MAX_OPTIONS) goto options_overflow;
        options[opt_offset++] = DHCP_OPTION_REQUESTED_IP;
        options[opt_offset++] = 4;
        memcpy(&options[opt_offset], requested_ip, 4);
        opt_offset += 4;
    }

    // Server Identifier (for REQUEST) (6 bytes needed: tag + len + 4-byte IP)
    if (msg_type == DHCP_REQUEST && server_ip) {
        if (opt_offset + 6 > DHCP_MAX_OPTIONS) goto options_overflow;
        options[opt_offset++] = DHCP_OPTION_SERVER_ID;
        options[opt_offset++] = 4;
        memcpy(&options[opt_offset], server_ip, 4);
        opt_offset += 4;
    }

    // Parameter Request List (6 bytes needed: tag + len + 4 params)
    if (opt_offset + 6 > DHCP_MAX_OPTIONS) goto options_overflow;
    options[opt_offset++] = DHCP_OPTION_PARAM_REQUEST;
    options[opt_offset++] = 4;
    options[opt_offset++] = DHCP_OPTION_SUBNET_MASK;
    options[opt_offset++] = DHCP_OPTION_ROUTER;
    options[opt_offset++] = DHCP_OPTION_DNS_SERVER;
    options[opt_offset++] = DHCP_OPTION_LEASE_TIME;

    // Hostname (variable length: tag + len + hostname_len bytes)
    const char* hostname = "TinyOS";
    size_t hostname_len = strlen(hostname);
    if (opt_offset + 2 + hostname_len > DHCP_MAX_OPTIONS) goto options_overflow;
    options[opt_offset++] = DHCP_OPTION_HOSTNAME;
    options[opt_offset++] = hostname_len;
    memcpy(&options[opt_offset], hostname, hostname_len);
    opt_offset += hostname_len;

    // End option (1 byte needed)
    if (opt_offset + 1 > DHCP_MAX_OPTIONS) goto options_overflow;
    options[opt_offset++] = DHCP_OPTION_END;
    
    offset += opt_offset;
    
    // Calculate lengths
    uint16_t udp_len = sizeof(udp_header_t) + sizeof(dhcp_header_t) + opt_offset;
    uint16_t ip_len = sizeof(ip_header_t) + udp_len;
    
    udp->length = htons(udp_len);
    udp->checksum = 0; // Optional for UDP over IPv4
    
    ip->total_length = htons(ip_len);
    ip->checksum = 0;
    ip->checksum = htons(calculate_checksum(ip, sizeof(ip_header_t)));
    
    // Send packet
    e1000_send(packet, offset);

    const char* msg_name = (msg_type == DHCP_DISCOVER) ? "DISCOVER" :
                          (msg_type == DHCP_REQUEST) ? "REQUEST" : "UNKNOWN";
    kprintf("[DHCP] Sent %s (XID: 0x%x, size: %u bytes)\n", msg_name, dhcp_client.xid, (unsigned int)offset);
    return;

options_overflow:
    /*=========================================================================
     * SECURITY: DHCP options buffer overflow detected
     * CRITICAL: This should never happen with our hardcoded options, but
     * prevents stack corruption if future code adds more options without
     * checking capacity.
     *========================================================================*/
    kprintf("[DHCP] SECURITY: Options buffer overflow prevented (offset=%u, max=%d)\n",
            (unsigned int)opt_offset, DHCP_MAX_OPTIONS);
    return;
}

/*=============================================================================
 * PUBLIC FUNCTIONS
 *============================================================================*/

/**
 * @brief Initialize DHCP client
 */
void dhcp_init(void) {
    memset(&dhcp_client, 0, sizeof(dhcp_client));
    dhcp_client.state = DHCP_STATE_INIT;
    dhcp_client.configured = false;

    /*
     * CRITICAL: Allow UDP port 68 (DHCP client) through firewall
     * Without this, the firewall blocks incoming DHCP OFFER/ACK responses
     * from the DHCP server, preventing DHCP from working.
     */
    firewall_allow_port(DHCP_CLIENT_PORT, IPPROTO_UDP, "DHCP Client");

    kprintf("[NET] DHCP: Client initialized...... [OK]\n");
}

/**
 * @brief Start DHCP discovery process
 */
void dhcp_start(void) {
    kprintf("[NET] DHCP: Starting discovery...... [OK]\n");
    
    dhcp_client.xid = generate_xid();
    dhcp_client.state = DHCP_STATE_SELECTING;
    
    // Send DHCP DISCOVER
    send_dhcp_message(DHCP_DISCOVER, NULL, NULL);
}

/**
 * @brief Handle received DHCP packet
 */
void handle_dhcp(const uint8_t* data, size_t len) {
    /* Suppress noisy logging of invalid packets to avoid interfering with VGA display.
     * Only log valid packets that pass XID validation (see below). */
    // kprintf("[DHCP] Received packet (%u bytes)\n", (unsigned int)len);

    if (len < sizeof(dhcp_header_t)) {
        kprintf("[DHCP] Packet too short (need %u bytes)\n", (unsigned int)sizeof(dhcp_header_t));
        return;
    }

    const dhcp_header_t* dhcp = (const dhcp_header_t*)data;

    // Check if this is a reply for us
    if (dhcp->op != DHCP_OP_BOOTREPLY) {
        /* Silently ignore - not for us */
        return;
    }

    // Check transaction ID
    if (ntohl(dhcp->xid) != dhcp_client.xid) {
        /* Silently ignore late/stale DHCP responses to avoid VGA spam during user interaction */
        return;
    }

    kprintf("[DHCP] Valid BOOTREPLY received (%u bytes, XID: 0x%x)\n",
            (unsigned int)len, dhcp_client.xid);
    
    // Check magic cookie
    if (ntohl(dhcp->magic_cookie) != DHCP_MAGIC_COOKIE) {
        kprintf("DHCP: Invalid magic cookie\n");
        return;
    }
    
    // Parse options
    const uint8_t* options = data + sizeof(dhcp_header_t);
    size_t options_len = len - sizeof(dhcp_header_t);
    
    uint8_t msg_type = 0;
    uint8_t server_ip[4] = {0};
    uint8_t dhcp_subnet_mask[4] = {0};
    uint8_t router[4] = {0};
    uint8_t dns_server[4] = {0};
    uint32_t lease_time = 0;

    parse_dhcp_options(options, options_len, &msg_type, server_ip,
                      dhcp_subnet_mask, router, dns_server, &lease_time);

    // Handle based on message type
    switch (msg_type) {
        case DHCP_OFFER:
            if (dhcp_client.state == DHCP_STATE_SELECTING) {
                // Save offered configuration
                memcpy(dhcp_client.offered_ip, dhcp->yiaddr, 4);
                memcpy(dhcp_client.server_ip, server_ip, 4);
                memcpy(dhcp_client.subnet_mask, dhcp_subnet_mask, 4);
                memcpy(dhcp_client.router_ip, router, 4);
                memcpy(dhcp_client.dns_server, dns_server, 4);
                dhcp_client.lease_time = lease_time;

                // kprintf("DHCP: Received OFFER - IP: %d.%d.%d.%d\n",
                //         dhcp_client.offered_ip[0], dhcp_client.offered_ip[1],
                //         dhcp_client.offered_ip[2], dhcp_client.offered_ip[3]);
                // kprintf("      Server: %d.%d.%d.%d\n",
                //         server_ip[0], server_ip[1], server_ip[2], server_ip[3]);  // Commented for less verbosity
                // kprintf("      Gateway: %d.%d.%d.%d\n",
                //         router[0], router[1], router[2], router[3]);  // Commented for less verbosity
                
                // Send REQUEST
                dhcp_client.state = DHCP_STATE_REQUESTING;
                send_dhcp_message(DHCP_REQUEST, dhcp_client.offered_ip, 
                                dhcp_client.server_ip);
            }
            break;
            
        case DHCP_ACK:
            if (dhcp_client.state == DHCP_STATE_REQUESTING ||
                dhcp_client.state == DHCP_STATE_RENEWING ||
                dhcp_client.state == DHCP_STATE_REBINDING) {
                /*=================================================================
                 * SECURITY: Validate DHCP Server Identifier
                 * This prevents rogue DHCP servers from injecting malicious
                 * network configurations by verifying the ACK comes from the
                 * same server that sent the OFFER.
                 *===============================================================*/
                if (memcmp(server_ip, dhcp_client.server_ip, 4) != 0) {
                    kprintf("DHCP: SECURITY: ACK from different server! Expected %d.%d.%d.%d, got %d.%d.%d.%d\n",
                            dhcp_client.server_ip[0], dhcp_client.server_ip[1],
                            dhcp_client.server_ip[2], dhcp_client.server_ip[3],
                            server_ip[0], server_ip[1], server_ip[2], server_ip[3]);
                    kprintf("DHCP: Possible rogue DHCP server attack detected. Dropping ACK.\n");
                    return;
                }

                /*=================================================================
                 * SECURITY: DHCP Lease Time Integer Wraparound Protection
                 * CRITICAL: If lease_time is near UINT32_MAX, calculating the
                 * expiration time (lease_start + lease_time) will wrap around to
                 * zero or a small value, causing the lease to appear expired
                 * immediately. This forces the client into continuous DISCOVER
                 * loops (DHCP Client DoS).
                 *
                 * Protection: Cap lease time at a reasonable maximum (30 days).
                 * If the server sends a larger value, clamp it to prevent overflow.
                 *
                 * Note: lease_time is in seconds, not ticks. Conversion to ticks
                 * for expiration checking must also use saturating arithmetic.
                 *===============================================================*/
                #define MAX_DHCP_LEASE_SECONDS (30UL * 86400UL)  // 30 days in seconds

                // Honor a lease time supplied in the ACK itself (option 51)
                if (lease_time != 0) {
                    dhcp_client.lease_time = lease_time;
                }

                // A zero/tiny lease would make t1_base and jitter_window zero,
                // causing a divide-by-zero (#DE) in the modulo below.
                if (dhcp_client.lease_time < 60) {
                    kprintf("DHCP: WARNING - Lease time (%u sec) too small. Clamping to 600 sec.\n",
                            dhcp_client.lease_time);
                    dhcp_client.lease_time = 600;
                }

                if (dhcp_client.lease_time > MAX_DHCP_LEASE_SECONDS) {
                    kprintf("DHCP: WARNING - Lease time (%u sec = %u days) exceeds maximum.\n",
                            dhcp_client.lease_time, dhcp_client.lease_time / 86400);
                    kprintf("DHCP: Clamping to %lu sec (30 days) to prevent integer wraparound DoS.\n",
                            MAX_DHCP_LEASE_SECONDS);
                    dhcp_client.lease_time = MAX_DHCP_LEASE_SECONDS;
                }

                // Configuration acknowledged - apply it
                dhcp_client.state = DHCP_STATE_BOUND;
                dhcp_client.configured = true;
                dhcp_client.lease_start = get_timer_ticks();

                /*=================================================================
                 * SECURITY: DHCP Renewal Jitter (Thundering Herd Prevention)
                 * CRITICAL: Calculate renewal time with CSPRNG-based jitter
                 *
                 * RFC 2131 specifies T1 = 0.5 * lease_time (50% of lease)
                 * Without jitter, all clients receiving the same lease duration
                 * will renew simultaneously at T1, overwhelming the DHCP server.
                 *
                 * ATTACK SCENARIO:
                 * 1. Network of 10,000 IoT devices using this stack
                 * 2. All receive 24-hour lease from DHCP server
                 * 3. All calculate T1 = 12 hours exactly
                 * 4. At T=12h, all 10,000 devices send DHCP REQUEST simultaneously
                 * 5. DHCP server receives 10,000 packets in <1 second
                 * 6. Server crashes or drops most requests
                 * 7. Devices fail to renew, lose IP addresses, network outage
                 *
                 * MITIGATION: Add randomized jitter to T1 renewal time
                 * - Base T1 = lease_time / 2 (in ticks at 100Hz)
                 * - Jitter window = ±10% of T1 (±5% of total lease)
                 * - Use CSPRNG to ensure unpredictable, uniformly distributed jitter
                 * - Spreads renewal requests over 10% of lease window
                 *
                 * Example: 24-hour lease (86400 seconds, 8640000 ticks)
                 * - T1 base = 4320000 ticks (12 hours)
                 * - Jitter window = ±432000 ticks (±1.2 hours)
                 * - Actual renewal: 10.8 to 13.2 hours (spread over 2.4h window)
                 *===============================================================*/
                uint32_t lease_ticks = dhcp_client.lease_time * 100;  // Convert seconds to ticks (100 Hz)
                uint32_t t1_base = lease_ticks / 2;  // T1 = 50% of lease

                // Jitter window = ±10% of T1 = ±5% of total lease
                uint32_t jitter_window = t1_base / 10;  // 10% of T1

                // Generate cryptographically random jitter in range [0, 2*jitter_window)
                uint32_t t1_jittered;
                if (jitter_window == 0) {
                    t1_jittered = t1_base;
                } else {
                    uint32_t random_jitter;
                    csprng_random_bytes(&global_csprng, (uint8_t*)&random_jitter, sizeof(uint32_t));
                    random_jitter = random_jitter % (2 * jitter_window);  // [0, 2*jitter_window)

                    // Apply jitter: T1_jittered = T1 - jitter_window + random_jitter
                    // This gives range: [T1 - jitter_window, T1 + jitter_window)
                    t1_jittered = t1_base - jitter_window + random_jitter;
                }

                dhcp_client.renewal_time = dhcp_client.lease_start + t1_jittered;

                // Log renewal time calculation (for debugging)
                kprintf("DHCP: Lease renewal scheduled at T1 + jitter = %u ticks (%u seconds from now)\n",
                        t1_jittered, t1_jittered / 100);

                // Apply complete network configuration
                set_network_config(dhcp->yiaddr, dhcp_client.subnet_mask, dhcp_client.router_ip);

                // Proactively ARP for gateway to cache its MAC address
                // kprintf("DHCP: Sending ARP request for gateway...\n");
                send_arp_request(dhcp_client.router_ip);

                kprintf("\n    (\\_/)  \n");
                kprintf("    (o.o)  Network Home Found!\n");
                kprintf("    (> <)  \n");
                kprintf("~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~\n");
                kprintf("    Address:  %d.%d.%d.%d\n", my_ip[0], my_ip[1], my_ip[2], my_ip[3]);
                kprintf("    Netmask:  %d.%d.%d.%d\n",
                        dhcp_client.subnet_mask[0], dhcp_client.subnet_mask[1],
                        dhcp_client.subnet_mask[2], dhcp_client.subnet_mask[3]);
                kprintf("    Gateway:  %d.%d.%d.%d\n",
                        dhcp_client.router_ip[0], dhcp_client.router_ip[1],
                        dhcp_client.router_ip[2], dhcp_client.router_ip[3]);
                kprintf("    DNS:      %d.%d.%d.%d\n",
                        dhcp_client.dns_server[0], dhcp_client.dns_server[1],
                        dhcp_client.dns_server[2], dhcp_client.dns_server[3]);
                kprintf("    Lease:    %u days\n", dhcp_client.lease_time / 86400);
                kprintf("~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~\n\n");

                // Use DNS from DHCP (router knows best)
                set_dns_server(dhcp_client.dns_server);
            }
            break;
            
        case DHCP_NAK:
            kprintf("DHCP: Received NAK - restarting discovery\n");
            dhcp_client.state = DHCP_STATE_INIT;
            dhcp_start();
            break;
    }
}

/**
 * @brief Get current DHCP state
 */
dhcp_state_t dhcp_get_state(void) {
    return dhcp_client.state;
}

/**
 * @brief Check if DHCP has configured the network
 */
bool dhcp_is_configured(void) {
    return dhcp_client.configured;
}

/**
 * @brief Get DHCP client info
 */
const dhcp_client_t* dhcp_get_client_info(void) {
    return &dhcp_client;
}

/**
 * @brief DHCP periodic timer tick for lease renewal
 * SECURITY: Implements RFC 2131 lease renewal with jitter to prevent thundering herd DoS
 */
void dhcp_tick(uint32_t current_time) {
    /* Suppress unused parameter warning - we use get_timer_ticks() for consistency */
    (void)current_time;

    // Only process if we have a configured lease
    if (!dhcp_client.configured) {
        return;
    }

    uint32_t current_ticks = get_timer_ticks();

    /*=========================================================================
     * DHCP LEASE RENEWAL STATE MACHINE (RFC 2131 Section 4.4.5)
     *
     * Timeline for a lease:
     * T=0:    Lease acquired (BOUND state)
     * T=T1:   Start RENEWING (50% of lease + jitter)
     * T=T2:   Start REBINDING (87.5% of lease, if renewal failed)
     * T=100%: Lease expires, must reacquire
     *
     * RENEWING: Unicast DHCP REQUEST to original server
     * REBINDING: Broadcast DHCP REQUEST to any server
     *========================================================================*/

    switch (dhcp_client.state) {
        case DHCP_STATE_BOUND:
            /*=================================================================
             * SECURITY: BOUND → RENEWING transition with jittered T1
             *
             * Check if current time has reached the jittered renewal time.
             * The renewal_time was calculated with CSPRNG jitter when the
             * lease was acquired, spreading renewal requests across clients.
             *================================================================*/
            if (current_ticks >= dhcp_client.renewal_time) {
                kprintf("DHCP: Lease renewal time reached (T1 + jitter). Entering RENEWING state.\n");

                dhcp_client.state = DHCP_STATE_RENEWING;
                dhcp_client.xid = generate_xid();  // New transaction ID for renewal

                // Send unicast DHCP REQUEST to original server
                // Note: In RENEWING, we REQUEST the same IP from the same server
                send_dhcp_message(DHCP_REQUEST, dhcp_client.offered_ip, dhcp_client.server_ip);

                kprintf("DHCP: Sent renewal REQUEST to server %d.%d.%d.%d for IP %d.%d.%d.%d\n",
                        dhcp_client.server_ip[0], dhcp_client.server_ip[1],
                        dhcp_client.server_ip[2], dhcp_client.server_ip[3],
                        dhcp_client.offered_ip[0], dhcp_client.offered_ip[1],
                        dhcp_client.offered_ip[2], dhcp_client.offered_ip[3]);
            }
            break;

        case DHCP_STATE_RENEWING:
            /*=================================================================
             * SECURITY: RENEWING → REBINDING transition at T2
             *
             * If renewal fails (no ACK from original server), transition to
             * REBINDING at T2 = 87.5% of lease time.
             *
             * NOTE: For simplicity, we check if 87.5% of lease has elapsed.
             * In production, this should track retransmission attempts and
             * timeout separately.
             *================================================================*/
            {
                uint32_t lease_ticks = dhcp_client.lease_time * 100;
                uint32_t t2_time = dhcp_client.lease_start + (lease_ticks * 7 / 8);

                if (current_ticks >= t2_time) {
                    kprintf("DHCP: Renewal failed. Entering REBINDING state (T2 = 87.5%% of lease).\n");

                    dhcp_client.state = DHCP_STATE_REBINDING;
                    dhcp_client.xid = generate_xid();  // New XID for rebinding

                    // Send broadcast DHCP REQUEST to any server
                    // In REBINDING, server_ip is NULL to indicate broadcast
                    send_dhcp_message(DHCP_REQUEST, dhcp_client.offered_ip, NULL);

                    kprintf("DHCP: Sent broadcast REBINDING REQUEST for IP %d.%d.%d.%d\n",
                            dhcp_client.offered_ip[0], dhcp_client.offered_ip[1],
                            dhcp_client.offered_ip[2], dhcp_client.offered_ip[3]);
                }
            }
            break;

        case DHCP_STATE_REBINDING:
            /*=================================================================
             * SECURITY: REBINDING → INIT transition at lease expiration
             *
             * If rebinding fails and lease expires (100% of lease time),
             * we must release the IP and restart DHCP discovery.
             *================================================================*/
            {
                uint32_t lease_ticks = dhcp_client.lease_time * 100;
                uint32_t expiration_time = dhcp_client.lease_start + lease_ticks;

                if (current_ticks >= expiration_time) {
                    kprintf("DHCP: Lease expired. Releasing IP and restarting discovery.\n");

                    // Clear configuration
                    dhcp_client.configured = false;
                    dhcp_client.state = DHCP_STATE_INIT;

                    // Restart DHCP discovery
                    dhcp_start();
                }
            }
            break;

        default:
            // No action needed for other states (INIT, SELECTING, REQUESTING)
            break;
    }
}
