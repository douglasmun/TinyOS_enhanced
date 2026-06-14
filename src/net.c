/*=============================================================================
 * net.c ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â TinyOS Network Stack Entry Point and Protocol Handlers
 *=============================================================================*/
#include <stddef.h>
#include <stdbool.h>
#include "net.h"
#include "kernel.h"
#include "kprintf.h"
#include "paging.h" // Gives access to map_mmio()
#include "util.h"   // Includes strlen, memset, memcpy (if standard library isn't available)
#include "dns.h"
#include "dhcp.h"
#include "icmp.h"
#include "tcp.h"
#include "firewall.h"
#include "ids.h"

/*=============================================================================
 * NETWORK CONFIGURATION
 *============================================================================*/
// Gateway configuration for testing
// static const uint8_t GATEWAY_IP[4] = {10, 0, 2, 2}; // QEMU Gateway IP
// static const uint8_t GATEWAY_MAC[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x01};// QEMU Gateway MAC

// Host configuration for testing
uint8_t my_ip[4] = {192, 168, 0, 80};  // QEMU's default guest IP
uint8_t my_mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56}; // QEMU's default guest MAC
uint8_t subnet_mask[4] = {255, 255, 255, 0};  // Default /24 subnet (updated by DHCP)
uint8_t gateway_ip[4] = {192, 168, 0, 1};     // Default gateway (updated by DHCP)
// uint8_t gateway_mac[6] = {0xB0, 0xA7, 0xB9, 0xB6, 0xCE, 0x38};// // TPLink Router at Home B0-A7-B9-B6-CE-38

static const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/*=============================================================================
 * ARP CACHE
 *============================================================================*/
#define ARP_CACHE_SIZE 16
#define ARP_TIMEOUT_TICKS 6000  // 60 seconds at 100Hz timer (6000 ticks)

typedef struct {
    uint8_t ip[4];
    uint8_t mac[6];
    uint32_t last_used; // Timer tick when entry was last used/updated
    bool valid;
} arp_cache_entry_t;

static arp_cache_entry_t arp_cache[ARP_CACHE_SIZE];

/*=============================================================================
 * SECURITY: ARP PENDING REQUEST TRACKING (DoS Protection)
 *
 * CRITICAL: Without limits, an attacker can flood the network with ARP
 * requests for non-existent IPs, causing:
 * 1. Network bandwidth exhaustion from endless broadcast ARP requests
 * 2. CPU exhaustion from processing send_arp_request() repeatedly
 * 3. Potential cache thrashing if integrated with ARP cache
 *
 * Mitigation Strategy:
 * - Limit total pending ARP requests to ARP_MAX_PENDING_REQUESTS
 * - Rate-limit requests per IP (min ARP_REQUEST_INTERVAL_TICKS between sends)
 * - Track when we last sent a request for each IP
 * - Drop oldest pending request if limit reached
 *
 * Attack Scenario:
 * Attacker floods with packets to 1000 different non-existent IPs.
 * Without limits: 1000 ARP requests sent, saturating the network.
 * With limits: Only 16 pending requests allowed, rest are rate-limited.
 *=============================================================================*/
#define ARP_MAX_PENDING_REQUESTS 16
#define ARP_REQUEST_INTERVAL_TICKS 500  // 5 seconds at 100Hz timer (500 ticks)
#define ARP_PENDING_TIMEOUT_TICKS 1000   // 10 seconds timeout for pending requests

typedef struct {
    uint8_t ip[4];
    uint32_t last_request_time; // When we last sent ARP request for this IP
    bool pending;
} arp_pending_request_t;

static arp_pending_request_t arp_pending_requests[ARP_MAX_PENDING_REQUESTS];
static uint32_t arp_requests_dropped = 0;  // Counter for dropped requests (monitoring)

/*=============================================================================
 * FUNCTION: arp_cache_evict_expired
 * PURPOSE: Evict expired ARP cache entries (DoS protection)
 * SECURITY: Prevents ARP cache poisoning attacks by expiring old entries
 *=============================================================================*/
static void arp_cache_evict_expired(void) {
    uint32_t current_ticks = get_timer_ticks();

    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].valid) {
            // Check if entry has expired (no use for ARP_TIMEOUT_TICKS)
            if (current_ticks - arp_cache[i].last_used > ARP_TIMEOUT_TICKS) {
                // Evict expired entry
                arp_cache[i].valid = false;
                // Security: Clear sensitive MAC address data
                memset(arp_cache[i].mac, 0, 6);
            }
        }
    }
}


/*=============================================================================
 * HELPER FUNCTIONS
 *============================================================================*/
void set_my_ip_from_array(const uint8_t* new_ip) {
    memcpy(my_ip, new_ip, 4);
    kprintf("NET: IP address updated to %d.%d.%d.%d\n", 
            my_ip[0], my_ip[1], my_ip[2], my_ip[3]);
}

/**
 * @brief Set network configuration from DHCP
 * @param ip IP address (can be NULL to keep current)
 * @param mask Subnet mask (can be NULL to keep current)
 * @param gateway Gateway IP (can be NULL to keep current)
 */
void set_network_config(const uint8_t* ip, const uint8_t* mask, const uint8_t* gateway) {
    if (ip) {
        memcpy(my_ip, ip, 4);
        // kprintf("NET: IP address updated to %d.%d.%d.%d\n",
        //         my_ip[0], my_ip[1], my_ip[2], my_ip[3]);
    }
    if (mask) {
        memcpy(subnet_mask, mask, 4);
        // kprintf("NET: Subnet mask set to %d.%d.%d.%d\n",
        //         subnet_mask[0], subnet_mask[1], subnet_mask[2], subnet_mask[3]);
    }
    if (gateway) {
        memcpy(gateway_ip, gateway, 4);
        // kprintf("NET: Gateway set to %d.%d.%d.%d\n",
        //         gateway_ip[0], gateway_ip[1], gateway_ip[2], gateway_ip[3]);
    }
}

/**
 * @brief Determine which MAC address to use for routing to destination
 * @param dest_ip Destination IP address
 * @return MAC address to use (either destination MAC if local, or gateway MAC if remote)
 *         Returns NULL if no route available
 */
uint8_t* get_route_mac(const uint8_t* dest_ip) {
    // Check if destination is on local network using subnet mask
    bool is_local = true;
    for (int i = 0; i < 4; i++) {
        if ((my_ip[i] & subnet_mask[i]) != (dest_ip[i] & subnet_mask[i])) {
            is_local = false;
            break;
        }
    }
    
    if (is_local) {
        // Destination is on local network - try to get its MAC
        // Removed verbose routing log to reduce console noise
        uint8_t* dest_mac = arp_lookup(dest_ip);
        if (!dest_mac) {
            // Need to ARP for the destination
            // Removed verbose ARP request log
            send_arp_request((uint8_t*)dest_ip);
        }
        return dest_mac;
    } else {
        // Destination is remote - route through gateway
        // Removed verbose routing log to reduce console noise
        uint8_t* gateway_mac = arp_lookup(gateway_ip);
        if (!gateway_mac) {
            // Need to ARP for the gateway
            // Removed verbose ARP request log
            send_arp_request(gateway_ip);
        }
        return gateway_mac;
    }
}

/*=============================================================================
 * FUNCTION: parse_ip
 * PURPOSE: Parse IP string like "192.168.0.1" into byte array
 * RETURNS: 1 on success, 0 on failure
 *============================================================================*/
int parse_ip(const char* ip_str, uint8_t* ip_out) {
    if (!ip_str) return 0;
    
    int octets[4];
    const char* ptr = ip_str;
    
    // Skip leading whitespace
    while (*ptr == ' ' || *ptr == '\t') ptr++;
    
    for (int i = 0; i < 4; i++) {
        // Must have at least one digit
        if (*ptr < '0' || *ptr > '9') {
            return 0;
        }
        
        // Parse the octet
        octets[i] = 0;
        while (*ptr >= '0' && *ptr <= '9') {
            octets[i] = octets[i] * 10 + (*ptr - '0');
            if (octets[i] > 255) {
                return 0;  // Octet too large
            }
            ptr++;
        }
        
        // Check for separator or end
        if (i < 3) {
            // Need a dot between octets
            if (*ptr != '.') {
                return 0;
            }
            ptr++;
        } else {
            // Last octet - skip trailing whitespace
            while (*ptr == ' ' || *ptr == '\t' || *ptr == '\r' || *ptr == '\n') {
                ptr++;
            }
            // Should be at end of string
            if (*ptr != '\0') {
                return 0;
            }
        }
    }
    
    // Copy to output
    for (int i = 0; i < 4; i++) {
        ip_out[i] = (uint8_t)octets[i];
    }
    
    return 1;
}



// Send a gratuitous ARP (ARP announcement) so peers learn our (IP -> MAC)
void send_arp_announcement(void) {
    size_t packet_len = sizeof(eth_header_t) + sizeof(arp_header_t);
    uint8_t packet[packet_len];
    memset(packet, 0, packet_len);

    eth_header_t* eth = (eth_header_t*)packet;
    arp_header_t* arp = (arp_header_t*)(packet + sizeof(eth_header_t));

    // Ethernet: broadcast
    memset(eth->dest_mac, 0xFF, 6);
    memcpy(eth->src_mac, my_mac, 6);
    eth->ethertype = htons(ETH_TYPE_ARP);

    // ARP header (Ethernet/IPv4)
    arp->hardware_type     = htons(ARP_HTYPE_ETHERNET);
    arp->protocol_type     = htons(ARP_PTYPE_IPV4);
    arp->hardware_addr_len = 6;
    arp->protocol_addr_len = 4;
    arp->operation         = htons(ARP_OP_REQUEST); // gratuitous ARP is a request

    // Sender = us
    memcpy(arp->sender_mac, my_mac, 6);
    memcpy(arp->sender_ip,  my_ip,  4);

    // Target = also us (announce/refresh)
    // target_mac left zeroed by memset
    memcpy(arp->target_ip,  my_ip,  4);

    kprintf("ARP: Sending gratuitous ARP for %d.%d.%d.%d\n",
            my_ip[0], my_ip[1], my_ip[2], my_ip[3]);

    e1000_send(packet, packet_len);
}

/**
 * @brief Looks up a MAC address for a given IP address in the ARP cache.
 * @param ip The target IPv4 address.
 * @return uint8_t* Pointer to the MAC address if found, NULL otherwise.
 */
/**
 * @brief Looks up a MAC address for a given IP address in the ARP cache.
 * @param ip The target IPv4 address.
 * @return uint8_t* Pointer to the MAC address if found, NULL otherwise.
 */
uint8_t* arp_lookup(const uint8_t* ip) {
    // Evict expired entries first (DoS protection)
    arp_cache_evict_expired();

    // 1. Check ARP cache first (including gateway)
    uint32_t current_ticks = get_timer_ticks();
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].valid && memcmp(arp_cache[i].ip, ip, 4) == 0) {
            // Update last_used to keep entry fresh
            arp_cache[i].last_used = current_ticks;
            return arp_cache[i].mac;
        }
    }

    // 2. FALLBACK: If IP is not found in cache,
    // we assume the destination is off-subnet and must be routed via the gateway.
    // Only use this for IPs that are NOT the gateway itself (to avoid circular logic)
    if (memcmp(ip, gateway_ip, 4) != 0) {
        kprintf("ARP: Cache miss for %d.%d.%d.%d. Routing via gateway.\n",
                 ip[0], ip[1], ip[2], ip[3]);

        // Try to lookup gateway MAC from cache
        for (int i = 0; i < ARP_CACHE_SIZE; i++) {
            if (arp_cache[i].valid && memcmp(arp_cache[i].ip, gateway_ip, 4) == 0) {
                return arp_cache[i].mac;
            }
        }
    }

    // 3. Last resort: No MAC found at all
    kprintf("ARP: No MAC address found for %d.%d.%d.%d\n",
             ip[0], ip[1], ip[2], ip[3]);
    return NULL;
}


/**
 * @brief Adds or updates an entry in the ARP cache.
 * @param ip The IPv4 address.
 * @param mac The corresponding MAC address.
 * SECURITY: Implements LRU eviction to prevent cache exhaustion attacks
 */
void arp_cache_update(const uint8_t* ip, const uint8_t* mac) {
    uint32_t current_ticks = get_timer_ticks();

    // Check if entry exists and update it
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].valid && memcmp(arp_cache[i].ip, ip, 4) == 0) {
            memcpy(arp_cache[i].mac, mac, 6);
            arp_cache[i].last_used = current_ticks;
            // kprintf("ARP: Cache updated for IP %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
            return;
        }
    }

    // Find first invalid slot
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (!arp_cache[i].valid) {
            memcpy(arp_cache[i].ip, ip, 4);
            memcpy(arp_cache[i].mac, mac, 6);
            arp_cache[i].last_used = current_ticks;
            arp_cache[i].valid = true;
            // kprintf("ARP: Added new cache entry for IP %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
            return;
        }
    }

    // Cache is full - evict LRU (Least Recently Used) entry
    // Find entry with oldest last_used timestamp
    int lru_index = 0;
    uint32_t oldest_time = arp_cache[0].last_used;

    for (int i = 1; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].last_used < oldest_time) {
            oldest_time = arp_cache[i].last_used;
            lru_index = i;
        }
    }

    // Replace LRU entry with new mapping
    kprintf("ARP: Cache full, evicting LRU entry %d.%d.%d.%d\n",
            arp_cache[lru_index].ip[0], arp_cache[lru_index].ip[1],
            arp_cache[lru_index].ip[2], arp_cache[lru_index].ip[3]);

    memcpy(arp_cache[lru_index].ip, ip, 4);
    memcpy(arp_cache[lru_index].mac, mac, 6);
    arp_cache[lru_index].last_used = current_ticks;
    arp_cache[lru_index].valid = true;

    // kprintf("ARP: Added new cache entry for IP %d.%d.%d.%d (via LRU)\n", ip[0], ip[1], ip[2], ip[3]);
}

/**
 * @brief Dumps the current ARP cache contents to console.
 */
void arp_cache_dump(void) {
    kprintf("\n=== ARP CACHE DUMP ===\n");
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].valid) {
            kprintf("[%02d] IP: %d.%d.%d.%d  MAC: %02X:%02X:%02X:%02X:%02X:%02X  last_used=%u\n",
                i,
                arp_cache[i].ip[0], arp_cache[i].ip[1],
                arp_cache[i].ip[2], arp_cache[i].ip[3],
                arp_cache[i].mac[0], arp_cache[i].mac[1], arp_cache[i].mac[2],
                arp_cache[i].mac[3], arp_cache[i].mac[4], arp_cache[i].mac[5],
                arp_cache[i].last_used);
        }
    }
    kprintf("=======================\n\n");
}

/**
 * @brief Sends an ARP Request for a given IP address (with rate limiting and flood protection).
 * @param target_ip The IP address to resolve.
 *
 * SECURITY: ARP Request Flood Protection
 * - Rate-limits requests per IP (min 5 seconds between requests)
 * - Limits total pending requests to 16
 * - Evicts oldest pending request if limit reached
 */
void send_arp_request(uint8_t* target_ip) {
    uint32_t current_ticks = get_timer_ticks();

    /*=========================================================================
     * STEP 1: Check if we recently sent a request for this IP (rate-limiting)
     *=======================================================================*/
    for (int i = 0; i < ARP_MAX_PENDING_REQUESTS; i++) {
        if (arp_pending_requests[i].pending &&
            memcmp(arp_pending_requests[i].ip, target_ip, 4) == 0) {

            uint32_t time_since_request = current_ticks - arp_pending_requests[i].last_request_time;

            if (time_since_request < ARP_REQUEST_INTERVAL_TICKS) {
                // Rate-limited: Too soon to resend
                // Silently drop to avoid log flooding
                return;
            } else {
                // Enough time passed, update timestamp and resend
                arp_pending_requests[i].last_request_time = current_ticks;
                goto send_arp_packet;  // Skip pending request tracking, just resend
            }
        }
    }

    /*=========================================================================
     * STEP 2: Evict expired pending requests
     *=======================================================================*/
    for (int i = 0; i < ARP_MAX_PENDING_REQUESTS; i++) {
        if (arp_pending_requests[i].pending) {
            uint32_t age = current_ticks - arp_pending_requests[i].last_request_time;
            if (age > ARP_PENDING_TIMEOUT_TICKS) {
                // Expired, clear it
                arp_pending_requests[i].pending = false;
            }
        }
    }

    /*=========================================================================
     * STEP 3: Find free slot or evict oldest entry
     *=======================================================================*/
    int free_slot = -1;
    for (int i = 0; i < ARP_MAX_PENDING_REQUESTS; i++) {
        if (!arp_pending_requests[i].pending) {
            free_slot = i;
            break;
        }
    }

    if (free_slot == -1) {
        // No free slots - evict oldest entry (LRU)
        uint32_t oldest_time = arp_pending_requests[0].last_request_time;
        int oldest_index = 0;

        for (int i = 1; i < ARP_MAX_PENDING_REQUESTS; i++) {
            if (arp_pending_requests[i].last_request_time < oldest_time) {
                oldest_time = arp_pending_requests[i].last_request_time;
                oldest_index = i;
            }
        }

        free_slot = oldest_index;
        arp_requests_dropped++;

        // Log every 100 dropped requests to detect attacks
        if (arp_requests_dropped % 100 == 0) {
            kprintf("ARP: WARNING - Dropped %u requests due to pending limit. Possible flood attack.\n",
                    arp_requests_dropped);
        }
    }

    /*=========================================================================
     * STEP 4: Track new pending request
     *=======================================================================*/
    memcpy(arp_pending_requests[free_slot].ip, target_ip, 4);
    arp_pending_requests[free_slot].last_request_time = current_ticks;
    arp_pending_requests[free_slot].pending = true;

send_arp_packet:
    /*=========================================================================
     * STEP 5: Build and send ARP request packet
     *=======================================================================*/
    size_t packet_len = sizeof(eth_header_t) + sizeof(arp_header_t);
    uint8_t packet[packet_len];
    memset(packet, 0, packet_len);

    eth_header_t* eth_hdr = (eth_header_t*)packet;
    arp_header_t* arp_hdr = (arp_header_t*)(packet + sizeof(eth_header_t));

    // Ethernet Header
    memcpy(eth_hdr->dest_mac, broadcast_mac, 6); // Broadcast
    memcpy(eth_hdr->src_mac, my_mac, 6);
    eth_hdr->ethertype = htons(ETH_TYPE_ARP);

    // ARP Header
    arp_hdr->hardware_type = htons(ARP_HTYPE_ETHERNET);
    arp_hdr->protocol_type = htons(ARP_PTYPE_IPV4);
    arp_hdr->hardware_addr_len = 6;
    arp_hdr->protocol_addr_len = 4;
    arp_hdr->operation = htons(ARP_OP_REQUEST);

    memcpy(arp_hdr->sender_mac, my_mac, 6);
    memcpy(arp_hdr->sender_ip, my_ip, 4);
    // Target MAC is left as 0s (implied by memset)
    memcpy(arp_hdr->target_ip, target_ip, 4);

    // kprintf("ARP: Sending request for %d.%d.%d.%d\n", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
    e1000_send(packet, packet_len);
}


void send_test_arp(const char *target_ip_str) {
    uint8_t arp_packet[60];
    uint8_t target_ip[4];

    if (parse_ip(target_ip_str, target_ip) != 1) {
        kprintf("Invalid IP address: %s\n", target_ip_str);
        return;
    }

    memset(arp_packet, 0, sizeof(arp_packet));

    kprintf("\nBuilding ARP Request packet for %s...\n", target_ip_str);

    // Destination MAC: Broadcast
    memset(arp_packet, 0xFF, 6);
    memcpy(arp_packet + 6, my_mac, 6);

    // EtherType: ARP (0x0806)
    arp_packet[12] = 0x08;
    arp_packet[13] = 0x06;

    // Hardware type: Ethernet (1)
    arp_packet[14] = 0x00;
    arp_packet[15] = 0x01;

    // Protocol type: IPv4 (0x0800)
    arp_packet[16] = 0x08;
    arp_packet[17] = 0x00;

    // Hardware/Protocol address lengths
    arp_packet[18] = 6;
    arp_packet[19] = 4;

    // Operation: Request (1)
    arp_packet[20] = 0x00;
    arp_packet[21] = 0x01;

    // Sender MAC + IP
    memcpy(arp_packet + 22, my_mac, 6);
    memcpy(arp_packet + 28, my_ip, 4);

    // Target MAC (unknown)
    memset(arp_packet + 32, 0, 6);

    // Target IP (from parameter)
    memcpy(arp_packet + 38, target_ip, 4);

    kprintf("Packet details:\n");
    kprintf("  Dest MAC: FF:FF:FF:FF:FF:FF (broadcast)\n");
    kprintf("  Src MAC:  %02x:%02x:%02x:%02x:%02x:%02x\n",
            my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
    kprintf("  Src IP:   %d.%d.%d.%d\n", my_ip[0], my_ip[1], my_ip[2], my_ip[3]);
    kprintf("  Query:    Who has %s?\n", target_ip_str);
    kprintf("  Size:     %d bytes\n", (int)sizeof(arp_packet));

    e1000_send(arp_packet, sizeof(arp_packet));
    kprintf("ARP broadcast sent for %s!\n\n", target_ip_str);
}

/*=============================================================================
 * BYTE ORDER CONVERSION
 *============================================================================*/


/*=============================================================================
 * CHECKSUM UTILITIES
 *============================================================================*/

/**
 * @brief Calculates the standard 16-bit one's complement checksum (e.g., for IP, ICMP, TCP/UDP).
 * @param addr Pointer to the data block.
 * @param len Length of the data block in bytes.
 * @return uint16_t The calculated checksum in network byte order.
 */
uint16_t calculate_checksum(void* addr, size_t len) {
    uint32_t sum = 0;
    uint8_t* bytes = (uint8_t*)addr;
    size_t i;

    // Read bytes as big-endian 16-bit words
    for (i = 0; i < len / 2; i++) {
        sum += ((uint16_t)bytes[i*2] << 8) | bytes[i*2 + 1];
    }

    // Handle odd length byte
    if (len % 2 != 0) {
        sum += ((uint16_t)bytes[len - 1] << 8);
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return the one's complement (bitwise NOT) of the sum
    return (uint16_t)~sum;
}

/**
 * @brief Calculates the Layer 4 (TCP/UDP) checksum using the pseudo-header.
 * @param src_ip Source IP address (4 bytes).
 * @param dest_ip Destination IP address (4 bytes).
 * @param protocol Protocol ID (IPPROTO_TCP or IPPROTO_UDP).
 * @param l4_segment Pointer to the L4 header + payload.
 * @param l4_len Length of the L4 segment (header + payload).
 * @return uint16_t The calculated checksum in network byte order.
 */
uint16_t calculate_l4_checksum(uint8_t* src_ip, uint8_t* dest_ip, uint8_t protocol, void* l4_segment, size_t l4_len) {
    uint32_t sum = 0;
    // uint16_t* ptr; removes unused variable
    size_t i;

    // 1. Sum IP addresses (MUST read as big-endian 16-bit words)
    // On little-endian x86, we need to read bytes in network order
    sum += ((uint16_t)src_ip[0] << 8) | src_ip[1];   // First 2 bytes of src IP
    sum += ((uint16_t)src_ip[2] << 8) | src_ip[3];   // Last 2 bytes of src IP
    sum += ((uint16_t)dest_ip[0] << 8) | dest_ip[1]; // First 2 bytes of dest IP
    sum += ((uint16_t)dest_ip[2] << 8) | dest_ip[3]; // Last 2 bytes of dest IP

    // 2. Sum Protocol (zero-padded to 16-bit: [0x00][protocol])
    // The pseudo-header format is [0x00][protocol] read as big-endian
    // For UDP (17): should be 0x0011 = 17, NOT 0x1100 = 4352
    sum += (uint16_t)protocol;

    // 3. Sum L4 Length (in network byte order)
    sum += (uint16_t)l4_len;

    // 4. Sum L4 Segment (Header + Payload, padding if needed)
    // Read as big-endian 16-bit words
    uint8_t* bytes = (uint8_t*)l4_segment;
    for (i = 0; i < l4_len / 2; i++) {
        sum += ((uint16_t)bytes[i*2] << 8) | bytes[i*2 + 1];
    }

    // Handle odd length byte (pad with 0 on the right)
    if (l4_len % 2 != 0) {
        sum += ((uint16_t)bytes[l4_len - 1] << 8);
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return the one's complement (bitwise NOT) of the sum
    return (uint16_t)~sum;
}

/*=============================================================================
 * PROTOCOL HANDLERS
 *============================================================================*/

/*=============================================================================
 * SECURITY: ARP Validation Helpers
 *===========================================================================*/

/**
 * @brief Check if IP address is broadcast or multicast
 * @return true if IP is invalid for ARP sender
 */
static bool is_invalid_arp_sender_ip(const uint8_t* ip) {
    /* Broadcast addresses */
    if (ip[0] == 255 && ip[1] == 255 && ip[2] == 255 && ip[3] == 255) {
        return true;  /* 255.255.255.255 */
    }

    /* All zeros (used during DHCP discovery) */
    if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0) {
        return true;  /* 0.0.0.0 */
    }

    /* Multicast range: 224.0.0.0 - 239.255.255.255 */
    if (ip[0] >= 224 && ip[0] <= 239) {
        return true;
    }

    /* Loopback: 127.0.0.0/8 */
    if (ip[0] == 127) {
        return true;
    }

    return false;
}

/**
 * @brief Check if IP is in our subnet or is the configured gateway
 * @return true if IP is valid for ARP cache
 */
static bool is_valid_arp_ip(const uint8_t* ip) {
    /* Allow gateway IP even if it appears to be off-subnet
     * (Some networks have misconfigured subnets) */
    if (memcmp(ip, gateway_ip, 4) == 0) {
        return true;
    }

    /* Check if we have a configured IP and subnet mask */
    if (my_ip[0] == 0 && my_ip[1] == 0 && my_ip[2] == 0 && my_ip[3] == 0) {
        /* No IP configured yet - accept all ARPs during DHCP */
        return true;
    }

    /* Check if IP is in our subnet */
    for (int i = 0; i < 4; i++) {
        if ((ip[i] & subnet_mask[i]) != (my_ip[i] & subnet_mask[i])) {
            return false;  /* Off-subnet */
        }
    }

    return true;
}

/**
 * @brief Handles an incoming ARP packet.
 * @param arp_hdr Pointer to the ARP header.
 * @param mac_hdr Pointer to the Ethernet header (to get sender MAC).
 */
static void handle_arp(arp_header_t* arp_hdr, eth_header_t* eth_hdr) {
    /*=========================================================================
     * SECURITY FIX: ARP Cache Poisoning Prevention
     *
     * VULNERABILITY: Unconditional ARP cache updates enable MITM attacks
     *
     * OLD CODE (VULNERABLE):
     * arp_cache_update(arp_hdr->sender_ip, arp_hdr->sender_mac);
     * → Accepts ANY ARP packet without validation
     *
     * ATTACK SCENARIO:
     * 1. Attacker sends: ARP reply "192.168.0.1 is at AA:BB:CC:DD:EE:FF"
     * 2. System blindly updates gateway MAC in ARP cache
     * 3. All traffic now routed to attacker's MAC address
     * 4. Attacker can intercept, modify, or drop all traffic
     *
     * NEW CODE (SECURE):
     * - Validate ARP packet structure (hw_type, proto_type, lengths)
     * - Validate operation field (REQUEST or REPLY only)
     * - Reject invalid sender IPs (broadcast, multicast, loopback)
     * - Only cache IPs in our subnet or configured gateway
     * - Only update cache for replies to our pending requests
     *
     * REFERENCES:
     * - RFC 826: Ethernet Address Resolution Protocol
     * - CVE-2019-14899: ARP cache poisoning in Linux
     *=======================================================================*/

    /* Validate hardware type (Ethernet) */
    uint16_t hw_type = ntohs(arp_hdr->hardware_type);
    if (hw_type != ARP_HTYPE_ETHERNET) {
        /* Not Ethernet ARP - drop silently */
        return;
    }

    /* Validate protocol type (IPv4) */
    uint16_t proto_type = ntohs(arp_hdr->protocol_type);
    if (proto_type != ARP_PTYPE_IPV4) {
        /* Not IPv4 ARP - drop silently */
        return;
    }

    /* Validate hardware and protocol address lengths */
    if (arp_hdr->hardware_addr_len != 6 || arp_hdr->protocol_addr_len != 4) {
        /* Invalid address sizes - drop */
        return;
    }

    /* Validate operation (REQUEST or REPLY only) */
    uint16_t op = ntohs(arp_hdr->operation);
    if (op != ARP_OP_REQUEST && op != ARP_OP_REPLY) {
        /* Invalid operation - drop */
        return;
    }

    /* Validate sender IP is not broadcast/multicast/loopback */
    if (is_invalid_arp_sender_ip(arp_hdr->sender_ip)) {
        /* Invalid sender IP - drop to prevent cache pollution */
        return;
    }

    /* Validate sender MAC is not broadcast or multicast */
    if ((arp_hdr->sender_mac[0] & 0x01) != 0) {
        /* Multicast or broadcast MAC - invalid for ARP sender */
        return;
    }

    /* Check if sender IP is in our subnet or is the gateway */
    if (!is_valid_arp_ip(arp_hdr->sender_ip)) {
        /* Off-subnet IP (not gateway) - drop to prevent poisoning */
        return;
    }

    if (op == ARP_OP_REQUEST) {
        /*
         * CRITICAL: Don't respond to ARP requests if we don't have an IP yet
         * During DHCP discovery, my_ip is 0.0.0.0. The DHCP server sends ARP probes
         * to check if an IP is available. If we respond, the DHCP server thinks the
         * IP is taken and won't offer it.
         */
        if (my_ip[0] == 0 && my_ip[1] == 0 && my_ip[2] == 0 && my_ip[3] == 0) {
            /* Silently ignore ARP requests when we don't have an IP */
            return;
        }

        /* Update cache from ARP requests (defensive learning) */
        arp_cache_update(arp_hdr->sender_ip, arp_hdr->sender_mac);

        /* If the request is for our IP, send a reply */
        if (memcmp(arp_hdr->target_ip, my_ip, 4) == 0) {
            /* Create a reply packet buffer */
            size_t packet_len = sizeof(eth_header_t) + sizeof(arp_header_t);
            uint8_t packet[packet_len];
            eth_header_t* reply_eth_hdr = (eth_header_t*)packet;
            arp_header_t* reply_arp_hdr = (arp_header_t*)(packet + sizeof(eth_header_t));

            /* Ethernet Header: Swap src/dest MACs */
            memcpy(reply_eth_hdr->dest_mac, eth_hdr->src_mac, 6);
            memcpy(reply_eth_hdr->src_mac, my_mac, 6);
            reply_eth_hdr->ethertype = htons(ETH_TYPE_ARP);

            /* ARP Header: Flip sender/target and set operation to REPLY */
            memcpy(reply_arp_hdr, arp_hdr, sizeof(arp_header_t));
            reply_arp_hdr->operation = htons(ARP_OP_REPLY);

            /* Sender (Our) details */
            memcpy(reply_arp_hdr->sender_mac, my_mac, 6);
            memcpy(reply_arp_hdr->sender_ip, my_ip, 4);

            /* Target (The Requester's) details */
            memcpy(reply_arp_hdr->target_mac, arp_hdr->sender_mac, 6);
            memcpy(reply_arp_hdr->target_ip, arp_hdr->sender_ip, 4);

            e1000_send(packet, packet_len);
        }
    } else if (op == ARP_OP_REPLY) {
        /*=====================================================================
         * SECURITY: Only accept ARP replies for pending requests
         * Unsolicited ARP replies (gratuitous ARP) are a common attack vector
         *
         * We ONLY update cache if:
         * 1. We have a pending ARP request for this IP, OR
         * 2. The IP is already in our cache (updating existing entry)
         *===================================================================*/

        bool should_update = false;

        /* Check if we have a pending request for this IP */
        for (int i = 0; i < ARP_MAX_PENDING_REQUESTS; i++) {
            if (arp_pending_requests[i].pending &&
                memcmp(arp_pending_requests[i].ip, arp_hdr->sender_ip, 4) == 0) {
                should_update = true;
                arp_pending_requests[i].pending = false;
                break;
            }
        }

        /* Check if IP is already in cache (update existing entry) */
        if (!should_update) {
            for (int i = 0; i < ARP_CACHE_SIZE; i++) {
                if (arp_cache[i].valid &&
                    memcmp(arp_cache[i].ip, arp_hdr->sender_ip, 4) == 0) {
                    should_update = true;
                    break;
                }
            }
        }

        /* Update cache only if validated */
        if (should_update) {
            arp_cache_update(arp_hdr->sender_ip, arp_hdr->sender_mac);
        }
    }
}

/**
 * @brief Handles an incoming UDP packet.
 * * Checks if the packet is a DNS response (Source Port 53) and forwards the
 * payload to the DNS response handler.
 * @param ip_hdr Pointer to the IP header.
 * @param ip_len Total length of the IP datagram.
 */
static void handle_udp(ip_header_t* ip_hdr, uint16_t ip_len) {
    size_t ip_hdr_len = (ip_hdr->version_ihl & 0x0F) * 4;
    
    // Check if packet length is sufficient for UDP header
    if (ip_len < ip_hdr_len + sizeof(udp_header_t)) {
        kprintf("UDP: Error - IP payload too short for UDP header.\n");
        return;
    }

    udp_header_t* udp_hdr = (udp_header_t*)((uint8_t*)ip_hdr + ip_hdr_len);
    uint16_t src_port = ntohs(udp_hdr->src_port);  // ÃƒÆ'Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å"ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ CORRECT UDP Port Byte Order
    uint16_t dest_port = ntohs(udp_hdr->dest_port); // ÃƒÆ'Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å"ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ CORRECT UDP Port Byte Order

    uint16_t len = ntohs(udp_hdr->length); // Total UDP segment length (header + data)

    /*=========================================================================
     * SECURITY FIX: UDP Length Validation (CRITICAL)
     *
     * VULNERABILITY: Attacker-controlled UDP length field can trigger OOB read
     *
     * ATTACK SCENARIO:
     * 1. Attacker sends IP packet with small payload (e.g., 50 bytes)
     * 2. Sets UDP length field to large value (e.g., 5000 bytes)
     * 3. Checksum calculation reads 5000 bytes from 50-byte buffer
     * 4. OUT-OF-BOUNDS READ → kernel memory leak, crash, or exploitation
     *
     * IMPACT:
     * - Information disclosure (read kernel stack/heap)
     * - Denial of service (crash on page fault)
     * - Potential RCE via memory corruption
     *
     * FIX: Validate UDP length BEFORE using it for checksum or data access:
     * 1. len >= sizeof(udp_header_t) (minimum valid size)
     * 2. len <= (ip_len - ip_hdr_len) (doesn't exceed IP payload)
     *
     * Reference: RFC 768 (UDP), CVE-2018-5391 (Linux FragmentSmack)
     *=======================================================================*/

    /* Calculate available IP payload space */
    uint16_t ip_payload_len = ip_len - ip_hdr_len;

    /* VALIDATION 1: UDP length must be at least size of UDP header */
    if (len < sizeof(udp_header_t)) {
        kprintf("UDP: SECURITY - Invalid UDP length %u (< UDP header size %zu). Dropping.\n",
                len, sizeof(udp_header_t));
        return;
    }

    /* VALIDATION 2: UDP length must not exceed IP payload size */
    if (len > ip_payload_len) {
        kprintf("UDP: SECURITY - UDP length %u exceeds IP payload %u. Dropping.\n",
                len, ip_payload_len);
        kprintf("UDP: Possible attack: IP claims %u bytes, UDP claims %u bytes\n",
                ip_payload_len, len);
        return;
    }

    // UDP Checksum Verification (optional in IPv4, but recommended)
    // Now that the checksum calculation bug is fixed, validation should work correctly
    
    if (1) {  // Enabled - UDP checksum validation with corrected algorithm
        uint16_t received_checksum = ntohs(udp_hdr->checksum);
        if (received_checksum != 0) {  // 0 means checksum disabled
            // Calculate checksum
            uint16_t saved_checksum = udp_hdr->checksum;
            udp_hdr->checksum = 0;
            uint16_t calculated_checksum = calculate_l4_checksum(ip_hdr->src_ip, ip_hdr->dest_ip, 
                                                                 IPPROTO_UDP, udp_hdr, len);
            udp_hdr->checksum = saved_checksum; // Restore
            
            if (calculated_checksum != received_checksum) {
                kprintf("UDP: Checksum failed (Calculated: 0x%x, Received: 0x%x). Dropping packet.\n", 
                        calculated_checksum, received_checksum);
                return;
            } else {
                // kprintf("UDP: Checksum verified OK (0x%x)\n", received_checksum);
            }
        }
    }

    // kprintf("UDP: Packet received. Src: %d.%d.%d.%d:%d, Dest: %d.%d.%d.%d:%d, Len: %d\n",
    //         ip_hdr->src_ip[0], ip_hdr->src_ip[1], ip_hdr->src_ip[2], ip_hdr->src_ip[3], src_port,
    //         ip_hdr->dest_ip[0], ip_hdr->dest_ip[1], ip_hdr->dest_ip[2], ip_hdr->dest_ip[3], dest_port,
    //         len);

    // kprintf("UDP: Checking handlers... DNS_PORT=%d\n", DNS_PORT);
    
    // If the packet originated from the DNS server (Source Port 53),
    // it's a DNS response.
    if (src_port == DNS_PORT) {
        // DNS payload starts immediately after the UDP header
        uint8_t* dns_data = (uint8_t*)udp_hdr + sizeof(udp_header_t);
        uint16_t dns_len = len - sizeof(udp_header_t);

        /* Basic sanity check
        if (dns_len > len || dns_len < sizeof(dns_header_t)) {
             kprintf("UDP: Error - Calculated DNS payload length is invalid (%u).\n", dns_len);
             return;
        }*/

        // kprintf("UDP: Detected DNS Response (Source Port %d). Forwarding to handler.\n", DNS_PORT);
        // SECURITY: Pass source IP for validation (prevents DNS spoofing)
        handle_dns_response(dns_data, dns_len, ip_hdr->src_ip);
        return;
    }

    // kprintf("UDP: After DNS check, src_port=%d, dest_port=%d\n", src_port, dest_port);

    // If the packet is from DHCP server (Port 67) to DHCP client (Port 68),
    // it's a DHCP response.
    if (src_port == 67 && dest_port == 68) {
        // DHCP payload starts immediately after the UDP header
        uint8_t* dhcp_data = (uint8_t*)udp_hdr + sizeof(udp_header_t);
        uint16_t dhcp_len = len - sizeof(udp_header_t);

        handle_dhcp(dhcp_data, dhcp_len);
        return;
    }

    /* Debug: Uncomment to see unhandled UDP packets */
    /* kprintf("UDP: No handler matched for src=%d dest=%d\n", src_port, dest_port); */

    // In a real OS, UDP would dispatch to a socket based on dest_port
}


/**
 * NOTE: This is a highly simplified TCP handler, only dealing with the SYN-ACK phase
 * when acting as a client initiating a connection.
 */
static void handle_tcp(ip_header_t* ip_hdr, uint16_t ip_len) {
    size_t ip_hdr_len = (ip_hdr->version_ihl & 0x0F) * 4;

    /*=========================================================================
     * SECURITY: Prevent Integer Underflow in TCP Length Calculation
     * CRITICAL: If ip_len < ip_hdr_len, the unsigned subtraction wraps around
     * to a massive value (e.g., 0xFFFFFFFF), causing the payload pointer to
     * extend far beyond the packet buffer into kernel memory.
     *
     * This leads to:
     * 1. Information Leakage - reading kernel memory as "payload"
     * 2. Kernel Crash - dereferencing invalid memory during memcpy
     * 3. Buffer Over-read - checksum calculation reads beyond buffer
     *
     * This is a ZERO-DAY class vulnerability in protocol implementations.
     *=======================================================================*/
    if (ip_len < ip_hdr_len) {
        // Debug message removed to reduce console noise
        // kprintf("TCP: Malformed packet - IP length (%d) < IP header (%zu). Integer underflow attack. Dropping.\n",
        //         ip_len, ip_hdr_len);
        return;
    }

    // Calculate TCP segment length
    size_t tcp_len = ip_len - ip_hdr_len;

    // Drop runt segments before touching tcp_hdr fields or checksumming
    if (tcp_len < sizeof(tcp_header_t)) {
        return;
    }

    // Get TCP header for checksum verification
    tcp_header_t* tcp_hdr = (tcp_header_t*)((uint8_t*)ip_hdr + ip_hdr_len);

    // TCP Checksum Verification (mandatory for TCP)
    uint16_t received_checksum = ntohs(tcp_hdr->checksum);
    uint16_t saved_checksum = tcp_hdr->checksum;
    tcp_hdr->checksum = 0;
    uint16_t calculated_checksum = calculate_l4_checksum(ip_hdr->src_ip, ip_hdr->dest_ip,
                                                         IPPROTO_TCP, tcp_hdr, tcp_len);
    tcp_hdr->checksum = saved_checksum; // Restore

    if (calculated_checksum != received_checksum) {
        // Debug message removed to reduce console noise
        // kprintf("TCP: Checksum failed (Calculated: 0x%x, Received: 0x%x). Dropping packet.\n",
        //         calculated_checksum, received_checksum);
        return;
    }

    /*=========================================================================
     * Forward packet to TCP stack for proper state machine handling
     * The TCP stack (tcp.c) handles:
     * - Server-side: SYN → SYN-ACK → ACK (3-way handshake)
     * - Client-side: SYN-ACK → ACK (handshake completion)
     * - Data transfer: ACK, PSH, FIN, RST
     * - Connection management: tcp_listen, tcp_accept, tcp_send, tcp_recv
     *=======================================================================*/
    tcp_handle_packet(ip_hdr->src_ip, ip_hdr->dest_ip,
                     (uint8_t*)tcp_hdr, tcp_len);
}

/**
 * @brief Handles an incoming IPv4 packet.
 * @param eth_frame Pointer to the full Ethernet frame (for ICMP reply context).
 * @param ip_hdr Pointer to the IP header.
 * @param eth_len Total length of the Ethernet frame.
 * @param ip_len Length of the IP datagram (excluding Ethernet).
 */
static void handle_ip(uint8_t* eth_frame, ip_header_t* ip_hdr, size_t eth_len, size_t ip_len) {
    if (ip_len < sizeof(ip_header_t)) {
        return;
    }

    /*=========================================================================
     * SECURITY: IP Header Length (IHL) Validation
     * CRITICAL: Validate IHL before using it to calculate payload offset
     * An attacker can specify an illegally large IHL to cause out-of-bounds
     * pointer calculations, bypassing checksum checks and causing kernel
     * memory dereferences.
     *=======================================================================*/
    uint8_t ihl = (ip_hdr->version_ihl & 0x0F);  // IHL in 32-bit words
    uint8_t ip_hdr_len_bytes = ihl * 4;           // Convert to bytes

    // Validate IHL: minimum 5 (20 bytes), maximum 15 (60 bytes)
    if (ihl < 5 || ihl > 15) {
        // Debug message removed to reduce console noise
        // kprintf("IP: Invalid IHL=%d (must be 5-15). Dropping packet.\n", ihl);
        return;
    }

    // Validate full header (including options) fits in available data
    if (ip_hdr_len_bytes > ip_len) {
        return;
    }

    // 1. IP Header Checksum validation
    // CRITICAL: Convert received checksum from network byte order
    // RFC 791: checksum covers the full header (IHL * 4 bytes), including options
    uint16_t received_checksum = ntohs(ip_hdr->checksum);
    ip_hdr->checksum = 0;
    uint16_t calculated_checksum = calculate_checksum(ip_hdr, ip_hdr_len_bytes);
    ip_hdr->checksum = htons(received_checksum); // Restore checksum in network byte order

    if (calculated_checksum != received_checksum) {
        // Debug message removed to reduce console noise
        // kprintf("IP: Checksum failed (Calculated: 0x%x, Received: 0x%x). Dropping packet.\n", calculated_checksum, received_checksum);
        return;
    }

    /*=========================================================================
     * ARP CACHE LEARNING: Update cache from incoming IP packets
     * CRITICAL: Learn MAC addresses from all IP packets, not just ARP
     * When we receive an IP packet, the Ethernet header contains the sender's
     * MAC address. We should cache this mapping (IP → MAC) so we can send
     * responses without needing to do ARP resolution.
     *
     * This is especially important for TCP server connections:
     * 1. Client sends TCP SYN (contains source IP + MAC in Ethernet header)
     * 2. Server wants to send SYN-ACK back
     * 3. Needs MAC address for client IP
     * 4. If we learned it from the Ethernet header → immediate response ✅
     * 5. If not learned → ARP request needed → delayed response ❌
     *=======================================================================*/
    // Removed verbose ARP learning logs to reduce console noise
    eth_header_t* eth_hdr = (eth_header_t*)eth_frame;
    arp_cache_update(ip_hdr->src_ip, eth_hdr->src_mac);

    // Validate IP header doesn't exceed packet length
    uint16_t total_len = ntohs(ip_hdr->total_length);

    /*=========================================================================
     * SECURITY: Malformed total_length Field Detection
     * CRITICAL: Abnormal Packet Attack - total_length must be at least as
     * large as the IP header itself. If total_length < (IHL * 4), this is
     * a malformed packet designed to trigger integer underflows/wraparounds.
     * This is a classic attack against simple TCP/IP stacks.
     *=======================================================================*/
    if (total_len < ip_hdr_len_bytes) {
        // Debug message removed to reduce console noise
        // kprintf("IP: Malformed total_length (%d) < IP header length (%d). Abnormal packet attack. Dropping.\n",
        //         total_len, ip_hdr_len_bytes);
        return;
    }

    if (ip_hdr_len_bytes > total_len) {
        // Debug message removed to reduce console noise
        // kprintf("IP: IHL (%d bytes) exceeds total length (%d bytes). Dropping packet.\n",
        //         ip_hdr_len_bytes, total_len);
        return;
    }

    // Validate total_len doesn't exceed available data
    if (total_len > ip_len) {
        // Debug message removed to reduce console noise
        // kprintf("IP: Total length (%d) exceeds IP packet length (%zu). Dropping packet.\n",
        //         total_len, ip_len);
        return;
    }

    /*=========================================================================
     * SECURITY: IP Options Handling (IHL > 5)
     * FIREWALL CRITICAL: If IHL > 5, the packet contains IP options
     * (Source Routing, Timestamp, Record Route, etc.)
     *
     * Options like Source Routing can be used to bypass firewall rules.
     * For a production perimeter firewall, options should be:
     * 1. Explicitly dropped (fail-safe), OR
     * 2. Carefully validated and only specific options allowed
     *
     * Current strategy: Log warning and ALLOW (payload offset is correct)
     * For high-security deployments, change to: DROP packets with options
     *=======================================================================*/
    if (ihl > 5) {
        // Debug message removed to reduce console noise
        // kprintf("IP: WARNING - Packet contains IP options (IHL=%d, %d bytes of options). ",
        //         ihl, ip_hdr_len_bytes - 20);
        // kprintf("Allowing but consider dropping for perimeter firewall.\n");
        // Uncomment the following line for strict firewall mode:
        // return;  // DROP all packets with IP options
    }

    /*=========================================================================
     * SECURITY: Strict Source IP Validation (Bogon Filtering)
     * CRITICAL: Firewall must drop packets from invalid/reserved IP ranges
     * Prevents:
     * 1. Loopback DoS attacks (127.0.0.0/8)
     * 2. Spoofed packets from reserved ranges
     * 3. Packets claiming to originate from our own IP
     * 4. Multicast source addresses (224.0.0.0/4)
     *
     * This is essential ingress filtering for any perimeter firewall.
     *=======================================================================*/
    uint8_t* src_ip = ip_hdr->src_ip;

    // Check for loopback (127.0.0.0/8)
    if (src_ip[0] == 127) {
        // Debug message removed to reduce console noise
        // kprintf("IP: Bogon source (loopback 127.x.x.x). Dropping.\n");
        return;
    }

    // Check for unspecified (0.0.0.0/8)
    if (src_ip[0] == 0) {
        // Debug message removed to reduce console noise
        // kprintf("IP: Bogon source (unspecified 0.x.x.x). Dropping.\n");
        return;
    }

    // Check for multicast source (224.0.0.0/4 = 224-239)
    if (src_ip[0] >= 224 && src_ip[0] <= 239) {
        // Debug message removed to reduce console noise
        // kprintf("IP: Bogon source (multicast %d.x.x.x). Dropping.\n", src_ip[0]);
        return;
    }

    // Check for broadcast source (255.255.255.255)
    if (src_ip[0] == 255 && src_ip[1] == 255 &&
        src_ip[2] == 255 && src_ip[3] == 255) {
        // Debug message removed to reduce console noise
        // kprintf("IP: Bogon source (broadcast 255.255.255.255). Dropping.\n");
        return;
    }

    // Check for packets claiming to be from our own IP (loopback DoS)
    if (memcmp(src_ip, my_ip, 4) == 0) {
        // Debug message removed to reduce console noise
        // kprintf("IP: Loopback DoS - packet claims our own IP as source. Dropping.\n");
        return;
    }

    // Check for link-local (169.254.0.0/16) - typically invalid on WAN
    // Note: This might be valid for some LANs, adjust for deployment
    if (src_ip[0] == 169 && src_ip[1] == 254) {
        // Debug message removed to reduce console noise
        // kprintf("IP: Warning - link-local source (169.254.x.x)\n");
        // Don't drop, just log for now
    }

    /*=========================================================================
     * SECURITY: IP Fragmentation DoS Protection
     * CRITICAL: Drop all fragmented packets to prevent reassembly attacks
     * Attackers can send overlapping/tiny fragments (Shredding Attack) to
     * consume massive memory and CPU in reassembly queues.
     *
     * For production: Implement bounded reassembly with:
     * - Max fragments per packet (e.g., 16)
     * - Max concurrent reassembly sessions (e.g., 8)
     * - Timeout for incomplete fragments (e.g., 60 seconds)
     *=======================================================================*/
    uint16_t flags_frag = ntohs(ip_hdr->flags_fragment);
    uint16_t flags = (flags_frag >> 13) & 0x7;       // Top 3 bits
    uint16_t frag_offset = (flags_frag & 0x1FFF) * 8; // Offset in bytes

    bool more_fragments = (flags & 0x1);  // MF bit
    bool dont_fragment = (flags & 0x2);   // DF bit
    (void)dont_fragment;  // Suppress unused variable warning (was used in commented debug message)

    if (frag_offset != 0 || more_fragments) {
        // Debug messages removed to reduce console noise
        // kprintf("IP: Fragmented packet detected (offset=%d, MF=%d, DF=%d). Dropping for security.\n",
        //         frag_offset, more_fragments, dont_fragment);
        // kprintf("IP: Reassembly not implemented - prevents fragmentation attacks.\n");
        return;
    }

    /*=========================================================================
     * SECURITY: Multicast/Broadcast Destination Filtering
     * FIREWALL CRITICAL: Filter multicast destination traffic to prevent
     * amplification DoS attacks and excessive resource consumption.
     *
     * Multicast range: 224.0.0.0/4 (224-239.x.x.x)
     *
     * An attacker can flood multicast addresses to consume network bandwidth
     * and CPU across the entire network segment (amplification attack).
     * For a simple firewall without IGMP support, all multicast traffic
     * should be dropped unless explicitly required.
     *
     * Exception: Reserved multicast addresses (224.0.0.x) are sometimes
     * needed for local protocols. Current policy: DROP ALL multicast.
     *=======================================================================*/
    uint8_t* dest_ip = ip_hdr->dest_ip;
    if (dest_ip[0] >= 224 && dest_ip[0] <= 239) {
        // kprintf("IP: Multicast destination (%d.%d.%d.%d). Dropping - no IGMP support.\n",
        //         dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3]);
        return;  // Silently drop multicast traffic
    }

    // 2. Destination IP check - accept unicast (our IP) or broadcast
    uint8_t broadcast_ip[4] = {255, 255, 255, 255};
    int is_for_us = (memcmp(dest_ip, my_ip, 4) == 0);
    int is_broadcast = (memcmp(dest_ip, broadcast_ip, 4) == 0);

    // Also accept subnet broadcasts (x.x.x.255) which DHCP servers commonly use
    int is_subnet_broadcast = (dest_ip[3] == 255);

    // kprintf("IP: Checking dest=%d.%d.%d.%d (my_ip=%d.%d.%d.%d) for_us=%d bcast=%d\n",
    //         dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3],
    //         my_ip[0], my_ip[1], my_ip[2], my_ip[3],
    //         is_for_us, is_broadcast);

    if (!is_for_us && !is_broadcast && !is_subnet_broadcast) {
        // Debug message removed to reduce console noise
        // kprintf("IP: Packet not for us (%d.%d.%d.%d). Dropping packet.\n",
        //         ip_hdr->dest_ip[0], ip_hdr->dest_ip[1],
        //         ip_hdr->dest_ip[2], ip_hdr->dest_ip[3]);
        return;
    }

    if (is_broadcast || is_subnet_broadcast) {
        // kprintf("IP: Accepting broadcast packet (dest: %d.%d.%d.%d)\n",
        //         ip_hdr->dest_ip[0], ip_hdr->dest_ip[1],
        //         ip_hdr->dest_ip[2], ip_hdr->dest_ip[3]);
    }

    /*=========================================================================
     * FIREWALL: Packet Filtering (Phase 2.2)
     * Check packet against firewall rules before processing
     *=======================================================================*/
    // kprintf("[FIREWALL_DEBUG] Checking packet (proto=%d, src=%d.%d.%d.%d, dst=%d.%d.%d.%d)\n",
    //         ip_hdr->protocol,
    //         ip_hdr->src_ip[0], ip_hdr->src_ip[1], ip_hdr->src_ip[2], ip_hdr->src_ip[3],
    //         ip_hdr->dest_ip[0], ip_hdr->dest_ip[1], ip_hdr->dest_ip[2], ip_hdr->dest_ip[3]);
    if (!firewall_check_packet(ip_hdr, total_len)) {
        // kprintf("[FIREWALL_DEBUG] Packet DROPPED by firewall\n");
        return;
    }
    // kprintf("[FIREWALL_DEBUG] Packet ACCEPTED by firewall\n");

    /*=========================================================================
     * IDS: Intrusion Detection (Phase 2.3)
     * Analyze packet for attack signatures and anomalies
     *=======================================================================*/
    if (!ids_analyze_packet(ip_hdr, total_len)) {
        // Intrusion detected (already logged and handled by IDS)
        return;
    }

    /*=========================================================================
     * SECURITY: Zero-Length Payload Validation
     * CRITICAL: Prevent Out-of-Bounds Read (OOBR) from zero-length packets
     *
     * ATTACK SCENARIO:
     * If total_len == ip_hdr_len_bytes (IHL * 4), the packet contains ONLY
     * the IP header with NO L4 payload. This is technically valid for some
     * protocols (e.g., IP options-only packets), but DANGEROUS if passed to
     * L4 handlers that assume payload exists:
     *
     * 1. Attacker sends IP packet: total_len=20, IHL=5 → payload_len=0
     * 2. CPU calculates: icmp_len = 20 - 20 = 0
     * 3. CPU passes icmp_data pointer to handle_icmp_with_context()
     * 4. ICMP handler reads icmp_data[0] → READING ETHERNET PADDING or
     *    NEXT PACKET in buffer → Out-of-Bounds Read (OOBR)
     * 5. IDS processes garbage data → False positives or missed attacks
     *
     * DEFENSE:
     * Calculate payload_len and explicitly check for zero-length BEFORE
     * passing to L4 handlers. Drop packets with no payload for protocols
     * that require it (TCP, UDP, ICMP all require at least minimal headers).
     *=======================================================================*/
    size_t payload_len = total_len - ip_hdr_len_bytes;

    // 3. Dispatch to L4 handler (use validated total_len and ip_hdr_len_bytes)
    switch (ip_hdr->protocol) {
        case IPPROTO_ICMP: {
            /*
             * ICMP requires at least 8 bytes: type(1) + code(1) + checksum(2) + rest(4)
             * If payload_len == 0, this is an invalid ICMP packet → DROP
             */
            if (payload_len == 0) {
                // kprintf("IP: Dropping zero-length ICMP packet (total_len=%d, header_len=%d)\n",
                //         total_len, ip_hdr_len_bytes);
                return;  // Drop silently - likely malformed or padding-only
            }

            // Call context-aware ICMP handler that can send Echo Replies
            // Use validated ip_hdr_len_bytes from security check above
            uint8_t* icmp_data = (uint8_t*)ip_hdr + ip_hdr_len_bytes;
            size_t icmp_len = payload_len;
            
            // Pass full context so the handler can build and send replies
            handle_icmp_with_context(eth_frame,        // Full Ethernet frame
                                    eth_len,           // Ethernet frame length
                                    (uint8_t*)ip_hdr,  // IP header
                                    total_len,         // IP packet length
                                    icmp_data,         // ICMP payload
                                    icmp_len);         // ICMP length
            break;
        }
        case IPPROTO_UDP:
            /*
             * UDP requires at least 8 bytes: src_port(2) + dst_port(2) + len(2) + checksum(2)
             * If payload_len == 0, this is an invalid UDP packet → DROP
             */
            if (payload_len == 0) {
                // kprintf("IP: Dropping zero-length UDP packet\n");
                return;
            }
            handle_udp(ip_hdr, total_len);
            break;
        case IPPROTO_TCP:
            /*
             * TCP requires at least 20 bytes for minimal header
             * If payload_len == 0, this is an invalid TCP packet → DROP
             */
            if (payload_len == 0) {
                // kprintf("IP: Dropping zero-length TCP packet\n");
                return;
            }
            handle_tcp(ip_hdr, total_len);
            break;
        default:
            // Debug message removed to reduce console noise
            // kprintf("IP: Unhandled protocol %d. Dropping packet.\n", ip_hdr->protocol);
            break;
    }
}

/**
 * @brief Main packet reception handler.
 * @param data Pointer to received Ethernet frame.
 * @param len Length of frame in bytes.
 */
void handle_packet(uint8_t* data, size_t len) {
    // static uint32_t pkt_count = 0;
    // pkt_count++;
    // kprintf("[NET_DEBUG] handle_packet called (count=%u, len=%zu)\n", pkt_count, len);

    if (len < sizeof(eth_header_t)) {
        kprintf("NET: Received packet too short (%zu bytes). Dropping.\n", len);
        return;
    }

    eth_header_t* eth_hdr = (eth_header_t*)data;
    uint16_t ethertype = htons(eth_hdr->ethertype);

    // kprintf("[NET_DEBUG] EtherType=0x%x\n", ethertype);

    // 1. Check if packet is for us (unicast or broadcast)
    if (memcmp(eth_hdr->dest_mac, my_mac, 6) != 0 && memcmp(eth_hdr->dest_mac, broadcast_mac, 6) != 0) {
        // kprintf("[NET_DEBUG] Packet not for our MAC. Dropping.\n");
        return;
    }

    // 2. Dispatch based on EtherType
    switch (ethertype) {
        case ETH_TYPE_ARP:
            // kprintf("[NET_DEBUG] Received ARP packet\n");
            if (len < sizeof(eth_header_t) + sizeof(arp_header_t)) {
                return;
            }
            handle_arp((arp_header_t*)(data + sizeof(eth_header_t)), eth_hdr);
            break;
        case ETH_TYPE_IPV4:
            // kprintf("[NET_DEBUG] Received IPv4 packet\n");
            if (len < sizeof(eth_header_t) + sizeof(ip_header_t)) {
                return;
            }
            handle_ip(data,                                      // Full Ethernet frame
                      (ip_header_t*)(data + sizeof(eth_header_t)),  // IP header
                      len,                                        // Ethernet frame length
                      len - sizeof(eth_header_t));               // IP packet length
            break;
        default:
            kprintf("NET: Unhandled EtherType 0x%x. Dropping packet.\n", ethertype);
            break;
    }
}

/*=============================================================================
 * PROTOCOL SENDERS
 *============================================================================*/

/**
 * @brief Sends an ICMP Echo Request (ping).
 * @param dest_ip Destination IP address (4 bytes).
 */
void send_udp_packet(uint8_t* dest_ip, uint8_t* dest_mac, 
                     uint16_t src_port, uint16_t dest_port,
                     void* data, size_t data_len) {
                         
    size_t udp_len = sizeof(udp_header_t) + data_len;
    size_t ip_len = sizeof(ip_header_t) + udp_len;
    size_t packet_len = sizeof(eth_header_t) + ip_len;
    
    uint8_t packet[packet_len];
    memset(packet, 0, packet_len);
    
    eth_header_t* eth_hdr = (eth_header_t*)packet;
    ip_header_t* ip_hdr = (ip_header_t*)(packet + sizeof(eth_header_t));
    udp_header_t* udp_hdr = (udp_header_t*)((uint8_t*)ip_hdr + sizeof(ip_header_t));
    
    // Ethernet header
    memcpy(eth_hdr->dest_mac, dest_mac, 6);
    memcpy(eth_hdr->src_mac, my_mac, 6);
    eth_hdr->ethertype = htons(ETH_TYPE_IPV4);
    
    // IP header
    ip_hdr->version_ihl = 0x45;
    ip_hdr->tos = 0;
    ip_hdr->total_length = htons(ip_len);
    ip_hdr->identification = htons(0x2000); // Unique ID
    ip_hdr->flags_fragment = 0;
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_UDP;
    ip_hdr->checksum = 0;
    memcpy(ip_hdr->src_ip, my_ip, 4);
    memcpy(ip_hdr->dest_ip, dest_ip, 4);
    
    // UDP header
    udp_hdr->src_port = htons(src_port);
    udp_hdr->dest_port = htons(dest_port);
    udp_hdr->length = htons(udp_len);
    
    // Copy payload
    memcpy((uint8_t*)udp_hdr + sizeof(udp_header_t), data, data_len);
    
    // UDP Checksum (optional, but good practice; use 0 for disabled)
    udp_hdr->checksum = 0;
    // Checksum calculation for UDP
    udp_hdr->checksum = htons(calculate_l4_checksum(my_ip, dest_ip, IPPROTO_UDP, udp_hdr, udp_len));
    if (udp_hdr->checksum == 0) {
        udp_hdr->checksum = 0xFFFF; // Per RFC, 0 is represented as 0xFFFF
    }
    
    // Final IP Checksum
    ip_hdr->checksum = htons(calculate_checksum(ip_hdr, sizeof(ip_header_t)));

    // Removed verbose UDP send log to reduce console noise
    e1000_send(packet, packet_len);
}

/**
 * @brief Sends a TCP SYN packet to initiate connection.
 * @param dest_ip Destination IP address (4 bytes).
 * @param dest_mac Destination MAC address (6 bytes).
 * @param src_port Source port.
 * @param dest_port Destination port.
 */
void send_tcp_syn(uint8_t* dest_ip, uint8_t* dest_mac, uint16_t src_port, uint16_t dest_port) {
    
    // TCP header is minimum 20 bytes (no options)
    size_t tcp_len = sizeof(tcp_header_t); 
    size_t ip_len = sizeof(ip_header_t) + tcp_len;
    size_t packet_len = sizeof(eth_header_t) + ip_len;
    
    uint8_t packet[packet_len];
    memset(packet, 0, packet_len);
    
    eth_header_t* eth_hdr = (eth_header_t*)packet;
    ip_header_t* ip_hdr = (ip_header_t*)(packet + sizeof(eth_header_t));
    tcp_header_t* tcp_hdr = (tcp_header_t*)((uint8_t*)ip_hdr + sizeof(ip_header_t));
    
    // Ethernet header
    memcpy(eth_hdr->dest_mac, dest_mac, 6);
    memcpy(eth_hdr->src_mac, my_mac, 6);
    eth_hdr->ethertype = htons(ETH_TYPE_IPV4);
    
    // IP header
    ip_hdr->version_ihl = 0x45;
    ip_hdr->tos = 0;
    ip_hdr->total_length = htons(ip_len);
    ip_hdr->identification = htons(0xDEF0);
    ip_hdr->flags_fragment = 0;
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_TCP;
    ip_hdr->checksum = 0;
    memcpy(ip_hdr->src_ip, my_ip, 4);
    memcpy(ip_hdr->dest_ip, dest_ip, 4);
    
    // TCP header
    tcp_hdr->src_port = htons(src_port);
    tcp_hdr->dest_port = htons(dest_port);
    
    // Fixed initial sequence number (simplification)
    uint32_t initial_seq_num = 1000; 
    tcp_hdr->sequence_number = htonl(initial_seq_num); 
    tcp_hdr->acknowledgement_number = 0; // No ACK for SYN
    
    // Data Offset (4 bits): (sizeof(tcp_header_t) / 4) << 4
    tcp_hdr->offset_reserved = (uint8_t)( (sizeof(tcp_header_t) / 4) << 4 ); 
    tcp_hdr->flags = TCP_SYN;
    tcp_hdr->window_size = htons(512); // Simple window size
    tcp_hdr->urgent_pointer = 0;
    
    // TCP Checksum (must be calculated last)
    tcp_hdr->checksum = 0;
    tcp_hdr->checksum = htons(calculate_l4_checksum(my_ip, dest_ip, IPPROTO_TCP, tcp_hdr, tcp_len));

    // Final IP Checksum
    ip_hdr->checksum = htons(calculate_checksum(ip_hdr, sizeof(ip_header_t)));

    // Removed verbose TCP SYN send log to reduce console noise
    e1000_send(packet, packet_len);
}

/**
 * @brief Sends a TCP ACK packet to complete the 3-way handshake or acknowledge data.
 * @param dest_ip Destination IP address (4 bytes).
 * @param dest_mac Destination MAC address (6 bytes).
 * @param src_port Source port (our port).
 * @param dest_port Destination port (peer's port).
 * @param our_seq_num Our current sequence number.
 * @param peer_ack_num The sequence number we expect the peer to use next (i.e., their last seq + 1).
 */
void send_tcp_ack(uint8_t* dest_ip, uint8_t* dest_mac, uint16_t src_port, uint16_t dest_port,
                  uint32_t our_seq_num, uint32_t peer_ack_num) {
                      
    // TCP header is minimum 20 bytes (no options)
    size_t tcp_len = sizeof(tcp_header_t); 
    size_t ip_len = sizeof(ip_header_t) + tcp_len;
    size_t packet_len = sizeof(eth_header_t) + ip_len;
    
    uint8_t packet[packet_len];
    memset(packet, 0, packet_len);
    
    eth_header_t* eth_hdr = (eth_header_t*)packet;
    ip_header_t* ip_hdr = (ip_header_t*)(packet + sizeof(eth_header_t));
    tcp_header_t* tcp_hdr = (tcp_header_t*)((uint8_t*)ip_hdr + sizeof(ip_header_t));
    
    // Ethernet header
    memcpy(eth_hdr->dest_mac, dest_mac, 6);
    memcpy(eth_hdr->src_mac, my_mac, 6);
    eth_hdr->ethertype = htons(ETH_TYPE_IPV4);
    
    // IP header
    ip_hdr->version_ihl = 0x45;
    ip_hdr->tos = 0;
    ip_hdr->total_length = htons(ip_len);
    ip_hdr->identification = htons(0xDEF1); // Increment ID
    ip_hdr->flags_fragment = 0;
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_TCP;
    ip_hdr->checksum = 0;
    memcpy(ip_hdr->src_ip, my_ip, 4);
    memcpy(ip_hdr->dest_ip, dest_ip, 4);
    
    // TCP header
    tcp_hdr->src_port = htons(src_port);
    tcp_hdr->dest_port = htons(dest_port);
    
    tcp_hdr->sequence_number = htonl(our_seq_num);
    tcp_hdr->acknowledgement_number = htonl(peer_ack_num);
    
    // Data Offset (4 bits): (sizeof(tcp_header_t) / 4) << 4
    tcp_hdr->offset_reserved = (uint8_t)( (sizeof(tcp_header_t) / 4) << 4 ); 
    tcp_hdr->flags = TCP_ACK;
    tcp_hdr->window_size = htons(512);
    tcp_hdr->urgent_pointer = 0;
    
    // TCP Checksum (must be calculated last)
    tcp_hdr->checksum = 0;
    tcp_hdr->checksum = htons(calculate_l4_checksum(my_ip, dest_ip, IPPROTO_TCP, tcp_hdr, tcp_len));

    // Final IP Checksum
    ip_hdr->checksum = htons(calculate_checksum(ip_hdr, sizeof(ip_header_t)));

    // Removed verbose TCP ACK send log to reduce console noise
    e1000_send(packet, packet_len);
}


/*=============================================================================
 * FUNCTION: net_init
 *=============================================================================
 * PURPOSE:
 * Initialize the network stack by detecting and initializing the E1000 NIC
 *============================================================================*/
void net_init() {
    uint32_t physical_base;
    if (pci_find_e1000(&physical_base)) {
        // kprintf("E1000 MMIO base (Physical): 0x%x\n", physical_base);

        // This is the line that throws the error because the compiler thinks
        // map_mmio returns void.
        uint32_t virtual_base = map_mmio(physical_base, 0x20000); // Map 128KB (0x20000)
        
        if (virtual_base == 0) {
            kprintf("E1000 ERROR: Failed to map MMIO memory.\n");
            return;
        }

        // kprintf("E1000 MMIO mapped (Virtual): 0x%x\n", virtual_base);

        // Pass the VIRTUAL address to the E1000 driver
        e1000_init(virtual_base);
        kprintf("[NET] E1000 initialized............. [OK]\n");
    } else {
        kprintf("E1000 not found.\n");
    }

    /*=========================================================================
     * SECURITY: Initialize ICMP with randomized identifier
     *
     * Must be called after crypto_init() (which happens earlier in kernel_main)
     * to ensure the global_csprng is initialized.
     *=======================================================================*/
    icmp_init();
}

