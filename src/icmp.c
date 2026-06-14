/*=============================================================================
 * icmp.c - ICMP Protocol Implementation (Ping)
 *============================================================================*/
#include <stddef.h>
#include <stdint.h>
#include "kernel.h"
#include "net.h"
#include "icmp.h"
#include "kprintf.h"
#include "util.h"
#include "scheduler.h"  /* For scheduler_yield() */
#include "crypto.h"     /* For CSPRNG */

/*=============================================================================
 * GLOBAL STATE
 *============================================================================*/
static uint16_t ping_identifier;  // Randomized ID (set in icmp_init())
static uint16_t ping_sequence = 0;
static uint32_t pings_sent = 0;
static uint32_t pings_received = 0;

/*=============================================================================
 * ICMP RATE LIMITING (DoS Protection)
 * SECURITY: Limits ICMP Echo Reply processing to prevent CPU exhaustion from
 * ping floods. Attackers can easily flood the network with ICMP packets to
 * consume all CPU time in interrupt handlers.
 *=============================================================================*/
#define ICMP_RATE_LIMIT_TICKS 10  // Min 100ms between replies (at 100Hz timer)
static uint32_t last_icmp_reply_time = 0;
static uint32_t icmp_replies_dropped = 0;

/*=============================================================================
 * FUNCTION: calculate_icmp_checksum
 *
 * SECURITY: Odd-Length Padding Safety
 * CRITICAL: When computing checksum over odd-length data, we must read one
 * additional byte beyond the 16-bit word boundary. The caller MUST ensure
 * the data buffer has this byte allocated and accessible.
 *
 * If a malicious ICMP packet has odd length and the buffer is not properly
 * padded, reading the last byte could cause a page fault or leak kernel memory.
 *
 * This function trusts the caller to provide valid bounds. All callers in this
 * file use fixed-size stack buffers (1514 bytes max), so this is safe.
 *============================================================================*/
static uint16_t calculate_icmp_checksum(const void* data, size_t len) {
    const uint16_t* ptr = (const uint16_t*)data;
    const uint8_t* byte_ptr = (const uint8_t*)data;
    uint32_t sum = 0;
    size_t original_len = len;

    // Empty checksum case
    if (len == 0) {
        return 0xFFFF;  // Checksum of empty data
    }

    // Sum all 16-bit words
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    /*=========================================================================
     * SECURITY: Odd-Length Byte Read Boundary Safety
     * When len is odd, we need to read the final byte. Instead of casting
     * ptr (which has been incremented and might be misaligned), we use
     * explicit byte_ptr indexing from the original buffer start.
     *
     * This ensures we're reading exactly at offset (original_len - 1), which
     * the caller guarantees is within bounds.
     *=======================================================================*/
    if (len > 0) {
        size_t last_byte_offset = original_len - 1;
        sum += byte_ptr[last_byte_offset];
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

/*=============================================================================
 * FUNCTION: send_icmp_ping
 * PURPOSE: Send an ICMP Echo Request (ping)
 *============================================================================*/
void send_icmp_ping(const uint8_t* dest_ip, const uint8_t* dest_mac, uint16_t seq) {
    uint8_t packet[128];  // Ethernet + IP + ICMP + 56 bytes data
    memset(packet, 0, sizeof(packet));
    
    size_t offset = 0;
    
    /*=========================================================================
     * ETHERNET HEADER (14 bytes)
     *=======================================================================*/
    // Destination MAC
    memcpy(packet + offset, dest_mac, 6);
    offset += 6;
    
    // Source MAC
    memcpy(packet + offset, my_mac, 6);
    offset += 6;
    
    // EtherType: IPv4 (0x0800)
    packet[offset++] = 0x08;
    packet[offset++] = 0x00;
    
    /*=========================================================================
     * IP HEADER (20 bytes)
     *=======================================================================*/
    size_t ip_header_start = offset;
    
    packet[offset++] = 0x45;        // Version 4, Header length 5 (20 bytes)
    packet[offset++] = 0x00;        // DSCP/ECN
    
    // Total length: IP header (20) + ICMP header (8) + data (56) = 84
    uint16_t total_length = 84;
    packet[offset++] = (total_length >> 8) & 0xFF;
    packet[offset++] = total_length & 0xFF;
    
    packet[offset++] = 0x00;        // Identification (high)
    packet[offset++] = seq & 0xFF;  // Identification (low) - use sequence
    
    packet[offset++] = 0x00;        // Flags + Fragment offset
    packet[offset++] = 0x00;
    
    packet[offset++] = 64;          // TTL
    packet[offset++] = 0x01;        // Protocol: ICMP
    
    packet[offset++] = 0x00;        // Checksum (calculate later)
    packet[offset++] = 0x00;
    
    // Source IP
    memcpy(packet + offset, my_ip, 4);
    offset += 4;
    
    // Destination IP
    memcpy(packet + offset, dest_ip, 4);
    offset += 4;
    
    // Calculate IP checksum
    uint16_t ip_checksum = calculate_icmp_checksum(packet + ip_header_start, 20);
    packet[ip_header_start + 10] = (ip_checksum     ) & 0xFF;  // Low byte
    packet[ip_header_start + 11] = (ip_checksum >> 8) & 0xFF;  // High byte
    
    /*=========================================================================
     * ICMP HEADER (8 bytes) + DATA (56 bytes)
     *=======================================================================*/
    size_t icmp_start = offset;
    
    packet[offset++] = ICMP_ECHO_REQUEST;  // Type: Echo Request
    packet[offset++] = 0x00;               // Code: 0
    packet[offset++] = 0x00;               // Checksum (calculate later)
    packet[offset++] = 0x00;
    
    packet[offset++] = (ping_identifier >> 8) & 0xFF;  // Identifier
    packet[offset++] = ping_identifier & 0xFF;
    
    packet[offset++] = (seq >> 8) & 0xFF;  // Sequence number
    packet[offset++] = seq & 0xFF;
    
    // Data payload (56 bytes of pattern)
    for (int i = 0; i < 56; i++) {
        packet[offset++] = 0x10 + (i % 16);  // Simple pattern
    }
    
    // Calculate ICMP checksum (over header + data = 64 bytes)
    uint16_t icmp_checksum = calculate_icmp_checksum(packet + icmp_start, 64);
    packet[icmp_start + 2] = (icmp_checksum     ) & 0xFF;  // Low byte
    packet[icmp_start + 3] = (icmp_checksum >> 8) & 0xFF;  // High byte
    
    /*=========================================================================
     * SEND PACKET
     *=======================================================================*/
    e1000_send(packet, offset);
    pings_sent++;
}

/*=============================================================================
 * FUNCTION: handle_icmp_with_context
 * PURPOSE: Process received ICMP packets with full context for proper replies
 *============================================================================*/
void handle_icmp_with_context(const uint8_t* eth_frame,
                              size_t eth_len,
                              const uint8_t* ip_hdr,
                              size_t ip_len,
                              const uint8_t* icmp_payload,
                              size_t icmp_len)
{
    // Sanity: need enough for minimal headers
    if (eth_len < 14 || ip_len < 20 || icmp_len < sizeof(icmp_header_t)) {
        return;
    }

    const icmp_header_t* icmp = (const icmp_header_t*)icmp_payload;
    
    // Handle Echo Reply (responses to our pings)
    if (icmp->type == ICMP_ECHO_REPLY && icmp->code == 0) {
        // Convert from network byte order (if needed)
        uint16_t identifier = ntohs(icmp->identifier);
        uint16_t sequence = ntohs(icmp->sequence);
        
        if (identifier == ping_identifier) {
            pings_received++;
            const uint8_t* req_ip_src = ip_hdr + 12;
            kprintf("  64 bytes from %d.%d.%d.%d: icmp_seq=%d ttl=64 time<1ms\n", 
                    req_ip_src[0], req_ip_src[1], req_ip_src[2], req_ip_src[3], sequence);
        }
        return;
    }

    // Handle Echo Request (someone pinging us - auto-reply)
    if (icmp->type == ICMP_ECHO_REQUEST && icmp->code == 0) {
        /*=====================================================================
         * SECURITY: ICMP Rate Limiting (DoS Protection)
         * Drop Echo Requests if we're processing them too frequently
         *===================================================================*/
        uint32_t current_ticks = get_timer_ticks();
        if (current_ticks - last_icmp_reply_time < ICMP_RATE_LIMIT_TICKS) {
            icmp_replies_dropped++;
            // Silently drop - don't flood logs
            if (icmp_replies_dropped % 100 == 0) {
                kprintf("ICMP: Rate limit - dropped %u requests\n", icmp_replies_dropped);
            }
            return;
        }
        last_icmp_reply_time = current_ticks;

        const uint8_t* req_eth_src = eth_frame + 6;   // peer MAC (requester)
        const uint16_t req_ethertype = (eth_frame[12] << 8) | eth_frame[13];

        if (req_ethertype != 0x0800) return;          // only IPv4

        const uint8_t* req_ip_src = ip_hdr + 12;

        kprintf("ICMP: Echo Request from %d.%d.%d.%d, replying...\n",
                req_ip_src[0], req_ip_src[1], req_ip_src[2], req_ip_src[3]);

        // ---- Build reply frame: ETH(14) + IP(20) + ICMP(8 + data) ----
        const size_t ip_header_len = 20;
        const size_t icmp_header_len = sizeof(icmp_header_t);
        const size_t reply_icmp_len = icmp_len; // mirror header+data size
        const size_t reply_ip_len   = ip_header_len + reply_icmp_len;
        const size_t reply_total    = 14 + reply_ip_len;

        // Safety upper bound
        if (reply_total > 1514) {
            kprintf("ICMP: Reply too large (%u bytes), dropping.\n", (unsigned)reply_total);
            return;
        }

        uint8_t buf[1514];
        size_t off = 0;

        // ---- Ethernet ----
        memcpy(buf + off, req_eth_src, 6); off += 6;  // dest = requester MAC
        memcpy(buf + off, my_mac, 6);      off += 6;  // src = our MAC
        buf[off++] = 0x08; buf[off++] = 0x00;         // EtherType IPv4

        // ---- IPv4 header ----
        size_t ip_start = off;
        buf[off++] = 0x45;            // Version 4, IHL 5
        buf[off++] = 0x00;            // DSCP/ECN
        buf[off++] = (reply_ip_len >> 8) & 0xFF;
        buf[off++] = (reply_ip_len     ) & 0xFF;

        buf[off++] = ip_hdr[4];       // ID high  (mirror request)
        buf[off++] = ip_hdr[5];       // ID low

        buf[off++] = 0x00;            // Flags/Frag offset
        buf[off++] = 0x00;

        buf[off++] = 64;              // TTL
        buf[off++] = 1;               // Protocol = ICMP

        buf[off++] = 0x00;            // Checksum placeholder
        buf[off++] = 0x00;

        memcpy(buf + off, my_ip,    4); off += 4;  // Source IP = our IP
        memcpy(buf + off, req_ip_src, 4); off += 4; // Dest IP = requester IP

        // Compute IP header checksum
        uint16_t ip_ck = calculate_icmp_checksum(buf + ip_start, ip_header_len);
        buf[ip_start + 10] = (ip_ck     ) & 0xFF;  // Low byte
        buf[ip_start + 11] = (ip_ck >> 8) & 0xFF;  // High byte

        // ---- ICMP Echo Reply ----
        size_t icmp_start = off;

        buf[off++] = ICMP_ECHO_REPLY;    // Type: Echo Reply
        buf[off++] = 0x00;               // Code: 0

        buf[off++] = 0x00;               // Checksum placeholder
        buf[off++] = 0x00;

        // Mirror identifier and sequence - copy raw bytes directly from packet
        // Bytes 4-5: identifier, Bytes 6-7: sequence (already in network byte order)
        buf[off++] = icmp_payload[4];  // ID high byte
        buf[off++] = icmp_payload[5];  // ID low byte
        buf[off++] = icmp_payload[6];  // Seq high byte
        buf[off++] = icmp_payload[7];  // Seq low byte

        // Copy original ICMP payload (if any)
        const size_t req_data_len = icmp_len > icmp_header_len ? (icmp_len - icmp_header_len) : 0;
        if (req_data_len) {
            memcpy(buf + off, icmp_payload + icmp_header_len, req_data_len);
            off += req_data_len;
        }

        // Compute ICMP checksum
        uint16_t icmp_ck = calculate_icmp_checksum(buf + icmp_start, reply_icmp_len);
        buf[icmp_start + 2] = (icmp_ck     ) & 0xFF;  // Low byte
        buf[icmp_start + 3] = (icmp_ck >> 8) & 0xFF;  // High byte

        // ---- Send ----
        e1000_send(buf, off);
        kprintf("ICMP: Echo Reply sent to %d.%d.%d.%d\n",
                req_ip_src[0], req_ip_src[1], req_ip_src[2], req_ip_src[3]);
    }
}


/*=============================================================================
 * FUNCTION: send_test_ping
 * PURPOSE: Send test pings to a target IP address
 * PARAMS: target_ip_str - IP address string like "192.168.0.1"
 *         count - Number of pings to send
 *============================================================================*/
void send_test_ping(const char* target_ip_str, int count) {
    uint8_t target_ip[4];
    
    // Parse IP address
    if (!parse_ip(target_ip_str, target_ip)) {
        kprintf("ERROR: Invalid IP address format: %s\n", target_ip_str);
        kprintf("Expected format: xxx.xxx.xxx.xxx (e.g., 192.168.0.1)\n");
        return;
    }
    
    // Check for loopback address (127.x.x.x)
    if (target_ip[0] == 127) {
        kprintf("\n=== PING %s ===\n", target_ip_str);
        kprintf("PING %s: 56 data bytes (loopback - internal)\n", target_ip_str);
        
        // Simulate loopback responses immediately
        for (int i = 0; i < count; i++) {
            kprintf("  64 bytes from %s: icmp_seq=%d ttl=64 time=0.001ms (loopback)\n", 
                    target_ip_str, i);
            
            /*=================================================================
             * SECURITY FIX (v1.18): Use scheduler_yield() instead of hlt
             *
             * While hlt is better than busy-waiting, scheduler_yield() is
             * more efficient as it allows other tasks to run and properly
             * integrates with the scheduler's task rotation.
             *===============================================================*/
            uint32_t start = get_timer_ticks();
            while (get_timer_ticks() - start < 10) {
                scheduler_yield();
            }
        }
        
        kprintf("\n--- %s ping statistics ---\n", target_ip_str);
        kprintf("%d packets transmitted, %d packets received, 0%% packet loss\n", count, count);
        kprintf("Note: Loopback packets handled internally, not sent to network\n\n");
        return;
    }
    
    kprintf("\n=== PING %s ===\n", target_ip_str);
    kprintf("PING %s: 56 data bytes\n", target_ip_str);
    
    // Reset statistics
    pings_sent = 0;
    pings_received = 0;
    
    // Determine destination MAC address using routing logic
    uint8_t* dest_mac = get_route_mac(target_ip);
    
    // If no MAC available, try fallback
    if (!dest_mac) {
        kprintf("Warning: No route to host, attempting fallback\n");
        /*=====================================================================
         * SECURITY FIX (v1.18): Use scheduler_yield() for ARP wait
         *===================================================================*/
        uint32_t start = get_timer_ticks();
        while (get_timer_ticks() - start < 100) {  // 1 second
            scheduler_yield();
        }
        
        // Try again
        dest_mac = get_route_mac(target_ip);
        
        if (!dest_mac) {
            kprintf("Error: Unable to reach %s (no route to host)\n", target_ip_str);
            return;
        }
    }
    
    // Send pings
    for (int i = 0; i < count; i++) {
        send_icmp_ping(target_ip, dest_mac, i);
        
        /*=====================================================================
         * SECURITY FIX (v1.18): Use scheduler_yield() for ping response wait
         *===================================================================*/
        uint32_t start = get_timer_ticks();
        while (get_timer_ticks() - start < 50) {  // 500ms @ 100Hz
            scheduler_yield();
        }
    }
    
    // Print statistics
    kprintf("\n--- %s ping statistics ---\n", target_ip_str);
    kprintf("%d packets transmitted, %d packets received, %d%% packet loss\n",
            pings_sent, pings_received,
            pings_sent > 0 ? ((pings_sent - pings_received) * 100 / pings_sent) : 0);
    kprintf("\n");
}

/*=============================================================================
 * FUNCTION: icmp_init
 *=============================================================================
 *
 * PURPOSE:
 *   Initialize ICMP subsystem with cryptographically secure random ICMP ID.
 *
 * SECURITY RATIONALE:
 *   The fixed ICMP identifier (0x1234) allows trivial host enumeration and
 *   fingerprinting. By randomizing this value with a CSPRNG at boot, we
 *   prevent attackers from easily identifying/tracking the system based on
 *   predictable ICMP Echo Request identifiers.
 *
 * IMPLEMENTATION:
 *   Uses the global CSPRNG (already initialized by crypto_init()) to generate
 *   a random 16-bit identifier.
 *
 * USAGE:
 *   Must be called after crypto_init() during system initialization (net_init).
 *
 *============================================================================*/
void icmp_init(void) {
    /*=========================================================================
     * SECURITY: Randomize ICMP Identifier with CSPRNG
     *
     * This prevents host enumeration/fingerprinting attacks based on
     * predictable ICMP Echo Request IDs.
     *=======================================================================*/
    ping_identifier = (uint16_t)csprng_random_u32(&global_csprng);

    /* Reset statistics */
    ping_sequence = 0;
    pings_sent = 0;
    pings_received = 0;
    last_icmp_reply_time = 0;
    icmp_replies_dropped = 0;
}

/*=============================================================================
 * FUNCTION: reset_ping_stats
 *============================================================================*/
void reset_ping_stats(void) {
    pings_sent = 0;
    pings_received = 0;
    ping_sequence = 0;
}
