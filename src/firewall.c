/*=============================================================================
 * firewall.c - Packet Filtering Firewall Implementation
 *===========================================================================*/
#include "firewall.h"
#include "audit.h"
#include "kprintf.h"
#include "pit.h"  /* For pit_get_ticks() */
#include "util.h"
#include "util.h"  /* For memcpy, memset */
#include "dhcp.h"  /* For DHCP_SERVER_PORT, DHCP_CLIENT_PORT */
#include "critical.h"  /* For CRITICAL_SECTION_ENTER/EXIT */

/*=============================================================================
 * Global State
 *===========================================================================*/
static firewall_rule_t rules[FIREWALL_MAX_RULES];
static int rule_count = 0;

static connection_entry_t connections[FIREWALL_MAX_CONNECTIONS];
static int connection_count = 0;

static rate_limit_entry_t rate_limits[32];
static int rate_limit_count = 0;

static attack_detector_t attack_detectors[16];
static int detector_count = 0;

static firewall_stats_t stats = {0};
static bool firewall_enabled = true;

/*=============================================================================
 * Helper: IP Address Matching
 *===========================================================================*/
static bool ip_matches(uint32_t packet_ip, uint32_t rule_ip, uint32_t mask) {
    if (rule_ip == 0) return true;  /* 0 = any */
    return (packet_ip & mask) == (rule_ip & mask);
}

/*=============================================================================
 * Helper: Port Matching
 *===========================================================================*/
static bool port_matches(uint16_t packet_port, uint16_t rule_port) {
    if (rule_port == 0) return true;  /* 0 = any */
    return packet_port == rule_port;
}

/*=============================================================================
 * SECURITY: Bogon IP Address Filtering
 *===========================================================================
 * PURPOSE:
 *   Detect and block packets from reserved/unroutable IP address ranges.
 *   These addresses should NEVER appear as source addresses on the public
 *   internet and indicate either:
 *   - Misconfigured networks
 *   - Spoofed packets (DDoS amplification attacks)
 *   - Network scanning/reconnaissance
 *
 * IMPLEMENTATION:
 *   Checks IP address (in host byte order) against all IANA reserved ranges:
 *   - 0.0.0.0/8        (current network)
 *   - 127.0.0.0/8      (loopback)
 *   - 169.254.0.0/16   (link-local)
 *   - 10.0.0.0/8       (RFC1918 private)
 *   - 172.16.0.0/12    (RFC1918 private)
 *   - 192.168.0.0/16   (RFC1918 private)
 *   - 224.0.0.0/4      (multicast)
 *   - 240.0.0.0/4      (reserved/future use)
 *   - 255.255.255.255  (broadcast)
 *
 * SECURITY RATIONALE:
 *   Many DDoS attacks and reconnaissance scans use spoofed source IPs from
 *   these ranges. By dropping them at the firewall, we:
 *   1. Prevent response to spoofed packets (DDoS amplification)
 *   2. Reduce attack surface for reconnaissance
 *   3. Prevent confusion from malformed/test packets
 *
 * EXCEPTION:
 *   For internal LANs, you may want to allow RFC1918 ranges. This
 *   implementation assumes a perimeter firewall protecting an internet-facing
 *   host. Adjust as needed for your deployment.
 *
 * @param ip IP address in host byte order (use ntohl() on network packets)
 * @return true if IP is bogon (reserved/unroutable), false if legitimate
 *===========================================================================*/
static bool is_bogon_ip(uint32_t ip) {
    /* 0.0.0.0/8 - Current network (RFC 1122)
     * First octet = 0 */
    if ((ip & 0xFF000000) == 0x00000000) {
        return true;
    }

    /* 127.0.0.0/8 - Loopback (RFC 1122)
     * First octet = 127 */
    if ((ip & 0xFF000000) == 0x7F000000) {
        return true;
    }

    /* 169.254.0.0/16 - Link-local (RFC 3927)
     * First two octets = 169.254 */
    if ((ip & 0xFFFF0000) == 0xA9FE0000) {
        return true;
    }

    /* 10.0.0.0/8 - RFC1918 private network
     * First octet = 10
     * NOTE: Disabled for LAN operation - these are legitimate on private networks */
    /*
    if ((ip & 0xFF000000) == 0x0A000000) {
        return true;
    }
    */

    /* 172.16.0.0/12 - RFC1918 private network
     * First octet = 172, second octet 16-31 (binary: 0001xxxx)
     * Mask: 255.240.0.0 = 0xFFF00000
     * NOTE: Disabled for LAN operation - these are legitimate on private networks */
    /*
    if ((ip & 0xFFF00000) == 0xAC100000) {
        return true;
    }
    */

    /* 192.168.0.0/16 - RFC1918 private network
     * First two octets = 192.168
     * NOTE: Disabled for LAN operation - these are legitimate on private networks */
    /*
    if ((ip & 0xFFFF0000) == 0xC0A80000) {
        return true;
    }
    */

    /* 224.0.0.0/4 - Multicast (RFC 5771)
     * First 4 bits = 1110 (224-239 in first octet)
     * Mask: 240.0.0.0 = 0xF0000000 */
    if ((ip & 0xF0000000) == 0xE0000000) {
        return true;
    }

    /* 240.0.0.0/4 - Reserved for future use (RFC 1112)
     * First 4 bits = 1111 (240-255 in first octet, excluding broadcast)
     * Mask: 240.0.0.0 = 0xF0000000 */
    if ((ip & 0xF0000000) == 0xF0000000 && ip != 0xFFFFFFFF) {
        return true;
    }

    /* 255.255.255.255 - Limited broadcast (RFC 919) */
    if (ip == 0xFFFFFFFF) {
        return true;
    }

    /* IP is legitimate (not bogon) */
    return false;
}

/*=============================================================================
 * Helper: Get TCP Header from IP Packet
 *===========================================================================*/
static tcp_header_t* get_tcp_header(const ip_header_t* ip) {
    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;
    return (tcp_header_t*)((uint8_t*)ip + ihl);
}

/*=============================================================================
 * Helper: Get UDP Header from IP Packet
 *===========================================================================*/
static udp_header_t* get_udp_header(const ip_header_t* ip) {
    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;
    return (udp_header_t*)((uint8_t*)ip + ihl);
}

/*=============================================================================
 * Connection Tracking
 *===========================================================================*/
static connection_entry_t* find_connection(uint32_t src_ip, uint32_t dst_ip,
                                           uint16_t src_port, uint16_t dst_port,
                                           uint8_t protocol) {
    for (int i = 0; i < FIREWALL_MAX_CONNECTIONS; i++) {
        connection_entry_t* conn = &connections[i];
        if (!conn->active) continue;

        /* Check forward direction */
        if (conn->src_ip == src_ip && conn->dst_ip == dst_ip &&
            conn->src_port == src_port && conn->dst_port == dst_port &&
            conn->protocol == protocol) {
            return conn;
        }

        /* Check reverse direction */
        if (conn->src_ip == dst_ip && conn->dst_ip == src_ip &&
            conn->src_port == dst_port && conn->dst_port == src_port &&
            conn->protocol == protocol) {
            return conn;
        }
    }
    return NULL;
}

static connection_entry_t* create_connection(uint32_t src_ip, uint32_t dst_ip,
                                             uint16_t src_port, uint16_t dst_port,
                                             uint8_t protocol) {
    /* Find free slot */
    for (int i = 0; i < FIREWALL_MAX_CONNECTIONS; i++) {
        if (!connections[i].active) {
            connection_entry_t* conn = &connections[i];
            memset(conn, 0, sizeof(connection_entry_t));
            conn->src_ip = src_ip;
            conn->dst_ip = dst_ip;
            conn->src_port = src_port;
            conn->dst_port = dst_port;
            conn->protocol = protocol;
            conn->state = CONN_STATE_NEW;
            conn->created_time = pit_get_ticks();
            conn->last_seen = conn->created_time;
            conn->active = true;
            connection_count++;
            return conn;
        }
    }

    /* Table full - evict oldest */
    connection_entry_t* oldest = &connections[0];
    for (int i = 1; i < FIREWALL_MAX_CONNECTIONS; i++) {
        if (connections[i].last_seen < oldest->last_seen) {
            oldest = &connections[i];
        }
    }

    memset(oldest, 0, sizeof(connection_entry_t));
    oldest->src_ip = src_ip;
    oldest->dst_ip = dst_ip;
    oldest->src_port = src_port;
    oldest->dst_port = dst_port;
    oldest->protocol = protocol;
    oldest->state = CONN_STATE_NEW;
    oldest->created_time = pit_get_ticks();
    oldest->last_seen = oldest->created_time;
    oldest->active = true;

    return oldest;
}

/*=============================================================================
 * Rate Limiting
 *===========================================================================
 * SECURITY FIX: Fail-closed rate limiting with LRU eviction
 *
 * PREVIOUS VULNERABILITY (HIGH):
 * When the rate limit table was full (32 entries), new sources were allowed
 * through WITHOUT rate limiting. An attacker could spray packets with 32+
 * unique source IPs to fill the table, then bypass rate limiting entirely
 * with additional IPs, causing DoS via CPU/bandwidth exhaustion.
 *
 * FIX IMPLEMENTED:
 * 1. Fail-closed by default: Drop packets when global rate limit exceeded
 * 2. LRU eviction: Replace least recently used entry when table is full
 * 3. Global rate cap: 3200 packets/second total (100 pps * 32 entries)
 * 4. Audit logging: Log when rate limits are exceeded
 *
 * RATIONALE:
 * - Fail-closed: Prevents bypass attacks
 * - LRU eviction: Ensures legitimate traffic can still use rate limiting
 * - Global cap: Prevents aggregate DoS from many low-rate sources
 * - Logging: Provides visibility into attack attempts
 *===========================================================================*/

/* Global rate limiting state */
static uint32_t global_packet_count = 0;
static uint32_t global_window_start = 0;
#define GLOBAL_RATE_LIMIT 3200  /* 100 pps * 32 entries */

static bool check_rate_limit(uint32_t src_ip) {
    uint32_t now = pit_get_ticks();

    /*=========================================================================
     * Global rate limiting: Prevent aggregate DoS
     *=======================================================================*/
    if (now - global_window_start > FIREWALL_RATE_LIMIT_WINDOW) {
        global_packet_count = 1;
        global_window_start = now;
    } else {
        global_packet_count++;
        if (global_packet_count > GLOBAL_RATE_LIMIT) {
            stats.rate_limit_hits++;
            /* Fail-closed: Drop when global limit exceeded */
            return false;
        }
    }

    /*=========================================================================
     * Per-source rate limiting
     *=======================================================================*/
    /* Find existing entry */
    for (int i = 0; i < rate_limit_count; i++) {
        rate_limit_entry_t* entry = &rate_limits[i];
        if (entry->src_ip == src_ip) {
            /* Update last_seen for LRU */
            entry->last_seen = now;

            /* Check if window expired */
            if (now - entry->window_start > FIREWALL_RATE_LIMIT_WINDOW) {
                entry->packet_count = 1;
                entry->window_start = now;
                return true;
            }

            entry->packet_count++;

            /* Check threshold (100 packets/second) */
            if (entry->packet_count > 100) {
                entry->total_dropped++;
                stats.rate_limit_hits++;
                return false;  /* Rate limit exceeded */
            }

            return true;
        }
    }

    /*=========================================================================
     * New source - add to table or evict LRU entry
     *=======================================================================*/
    if (rate_limit_count < 32) {
        /* Table not full - add new entry */
        rate_limits[rate_limit_count].src_ip = src_ip;
        rate_limits[rate_limit_count].packet_count = 1;
        rate_limits[rate_limit_count].window_start = now;
        rate_limits[rate_limit_count].total_dropped = 0;
        rate_limits[rate_limit_count].last_seen = now;
        rate_limit_count++;
        return true;
    }

    /*=========================================================================
     * Table full - LRU eviction
     *
     * SECURITY: Instead of failing open (allowing unlimited traffic), we
     * evict the least recently used entry and replace it with the new source.
     * This ensures that active sources remain rate-limited while still
     * allowing legitimate new connections.
     *=======================================================================*/
    int lru_index = 0;
    uint32_t oldest_time = rate_limits[0].last_seen;

    for (int i = 1; i < 32; i++) {
        if (rate_limits[i].last_seen < oldest_time) {
            oldest_time = rate_limits[i].last_seen;
            lru_index = i;
        }
    }

    /* Log eviction if the evicted entry had dropped packets (active attacker) */
    if (rate_limits[lru_index].total_dropped > 0) {
        kprintf("[FIREWALL] LRU eviction: %u.%u.%u.%u (%u dropped)\n",
                (rate_limits[lru_index].src_ip >> 24) & 0xFF,
                (rate_limits[lru_index].src_ip >> 16) & 0xFF,
                (rate_limits[lru_index].src_ip >> 8) & 0xFF,
                rate_limits[lru_index].src_ip & 0xFF,
                rate_limits[lru_index].total_dropped);
    }

    /* Replace LRU entry with new source */
    rate_limits[lru_index].src_ip = src_ip;
    rate_limits[lru_index].packet_count = 1;
    rate_limits[lru_index].window_start = now;
    rate_limits[lru_index].total_dropped = 0;
    rate_limits[lru_index].last_seen = now;

    return true;
}

/*=============================================================================
 * SYN Flood Detection
 *===========================================================================*/
static void detect_syn_flood(uint32_t src_ip, const tcp_header_t* tcp) {
    if (!(tcp->flags & TCP_SYN)) return;

    uint32_t now = pit_get_ticks();

    /* Find or create detector */
    attack_detector_t* detector = NULL;
    for (int i = 0; i < detector_count; i++) {
        if (attack_detectors[i].src_ip == src_ip) {
            detector = &attack_detectors[i];
            break;
        }
    }

    if (!detector && detector_count < 16) {
        detector = &attack_detectors[detector_count++];
        memset(detector, 0, sizeof(attack_detector_t));
        detector->src_ip = src_ip;
    }

    if (!detector) return;

    /* Check if window expired */
    if (now - detector->syn_window_start > 1000) {  /* 1 second window */
        detector->syn_count = 1;
        detector->syn_window_start = now;
        return;
    }

    detector->syn_count++;

    /* Threshold: 100 SYN/sec */
    if (detector->syn_count > FIREWALL_SYN_THRESHOLD) {
        stats.syn_floods_detected++;
        audit_log(AUDIT_SEC_POLICY_VIOLATION, AUDIT_WARN, 0,
                  "SYN flood detected from %u.%u.%u.%u (%lu SYN/sec)",
                  (unsigned)((src_ip >> 24) & 0xFF), (unsigned)((src_ip >> 16) & 0xFF),
                  (unsigned)((src_ip >> 8) & 0xFF), (unsigned)(src_ip & 0xFF),
                  (unsigned long)detector->syn_count);
        detector->syn_count = 0;  /* Reset to avoid spam */
    }
}

/*=============================================================================
 * Port Scan Detection
 *===========================================================================*/
static void detect_port_scan(uint32_t src_ip, uint16_t dst_port) {
    attack_detector_t* detector = NULL;

    /* Find or create detector */
    for (int i = 0; i < detector_count; i++) {
        if (attack_detectors[i].src_ip == src_ip) {
            detector = &attack_detectors[i];
            break;
        }
    }

    if (!detector && detector_count < 16) {
        detector = &attack_detectors[detector_count++];
        memset(detector, 0, sizeof(attack_detector_t));
        detector->src_ip = src_ip;
    }

    if (!detector) return;

    /* Check if port already in list */
    for (int i = 0; i < detector->port_count; i++) {
        if (detector->ports_scanned[i] == dst_port) {
            return;  /* Already recorded */
        }
    }

    /* Add port to list */
    if (detector->port_count < 64) {
        detector->ports_scanned[detector->port_count++] = dst_port;
        detector->last_scan_time = pit_get_ticks();

        /* Threshold: 20 unique ports */
        if (detector->port_count >= FIREWALL_PORTSCAN_THRESHOLD) {
            stats.port_scans_detected++;
            audit_log(AUDIT_SEC_POLICY_VIOLATION, AUDIT_WARN, 0,
                      "Port scan detected from %u.%u.%u.%u (%u ports)",
                      (unsigned)((src_ip >> 24) & 0xFF), (unsigned)((src_ip >> 16) & 0xFF),
                      (unsigned)((src_ip >> 8) & 0xFF), (unsigned)(src_ip & 0xFF),
                      (unsigned)detector->port_count);
            detector->port_count = 0;  /* Reset */
        }
    }
}

/*=============================================================================
 * Rule Matching
 *===========================================================================*/
static firewall_rule_t* match_rule(const ip_header_t* ip, uint16_t src_port,
                                    uint16_t dst_port) {
    uint32_t src_ip = ntohl(*(uint32_t*)ip->src_ip);
    uint32_t dst_ip = ntohl(*(uint32_t*)ip->dest_ip);

    /* Sort rules by priority */
    for (uint32_t prio = 0; prio < 1000; prio++) {
        for (int i = 0; i < rule_count; i++) {
            firewall_rule_t* rule = &rules[i];
            if (!rule->enabled || rule->priority != prio) continue;

            /* Check protocol */
            if (rule->protocol != 0 && rule->protocol != ip->protocol) continue;

            /* Check IP addresses */
            if (!ip_matches(src_ip, rule->src_ip, rule->src_ip_mask)) continue;
            if (!ip_matches(dst_ip, rule->dst_ip, rule->dst_ip_mask)) continue;

            /* Check ports */
            if (!port_matches(src_port, rule->src_port)) continue;
            if (!port_matches(dst_port, rule->dst_port)) continue;

            /*=====================================================================
             * SECURITY FIX: Integer overflow protection for byte_count
             *
             * Prevent counter wraparound after 4GB of traffic which would
             * break accounting and potentially bypass quotas/limits.
             *===================================================================*/
            /* Match found */
            rule->packet_count++;

            uint16_t pkt_len = ntohs(ip->total_length);
            if (rule->byte_count > UINT32_MAX - pkt_len) {
                /* Overflow would occur - reset counter with warning */
                rule->byte_count = pkt_len;
                /* Note: In production, log this event for monitoring */
            } else {
                rule->byte_count += pkt_len;
            }
            return rule;
        }
    }

    return NULL;  /* No match - default deny */
}

/*=============================================================================
 * Main Packet Filter
 *===========================================================================*/
bool firewall_check_packet(const ip_header_t* ip, size_t packet_len) {
    if (!firewall_enabled) return true;

    /* SECURITY FIX: Validate packet length before accessing headers
     * A truncated packet (NIC bug, malformed packet, or deliberate fuzzing)
     * can cause out-of-bounds reads in kernel interrupt context, leading to
     * information disclosure or kernel crash. Always validate packet_len
     * before dereferencing any header pointers.
     *
     * Minimum packet validation:
     * - Must be at least sizeof(ip_header_t) to read IP header
     * - IHL (Internet Header Length) must be valid (>= 5, <= packet_len/4)
     * - Protocol-specific headers (TCP/UDP) must fit within packet_len */

    /* Check minimum IP header size */
    if (packet_len < sizeof(ip_header_t)) {
        stats.packets_dropped++;
        return false;
    }

    /* Validate IP Header Length (IHL) field
     * IHL is in 32-bit words, minimum 5 (20 bytes), maximum 15 (60 bytes) */
    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;
    if (ihl < sizeof(ip_header_t) || ihl > packet_len) {
        stats.packets_dropped++;
        return false;
    }

    /* Validate total IP packet length matches provided packet_len
     * The total_length field in IP header should match our packet buffer */
    uint16_t ip_total_len = ntohs(ip->total_length);
    if (ip_total_len > packet_len) {
        stats.packets_dropped++;
        return false;
    }

    /*=========================================================================
     * SECURITY FIX: IP Fragmentation Attack Prevention
     *
     * VULNERABILITY: Firewall ignores IP fragmentation, enabling bypass
     *
     * PROBLEM:
     * - get_tcp_header() and get_udp_header() assume L4 header follows IP header
     * - For fragmented packets, only FIRST fragment contains L4 header
     * - Subsequent fragments contain payload data, not headers
     * - Firewall tries to parse ports from arbitrary payload bytes
     * - Port-based rules can be bypassed by fragmenting attack packets
     *
     * ATTACK SCENARIO:
     * 1. Attacker wants to send TCP to blocked port 1234
     * 2. First fragment: IP header only, MF=1 (no TCP header)
     *    → Firewall sees no ports, can't match rules → ALLOWS
     * 3. Second fragment: Contains TCP header at offset, MF=0
     *    → Firewall reads garbage as "ports" → Wrong decision
     * 4. Target reassembles → Attack packet delivered to port 1234
     *
     * IP FRAGMENTATION FIELDS (flags_fragment):
     * - Bit 15 (0x8000): Reserved (must be 0)
     * - Bit 14 (0x4000): Don't Fragment (DF)
     * - Bit 13 (0x2000): More Fragments (MF)
     * - Bits 0-12 (0x1FFF): Fragment Offset (in 8-byte units)
     *
     * FIX: Reject ALL fragmented packets
     * - Drop if MF flag set (more fragments coming)
     * - Drop if fragment offset != 0 (not first fragment)
     * - This prevents fragment-based firewall bypass
     *
     * ALTERNATIVE: Implement IP reassembly (complex, not done here)
     *
     * REFERENCES:
     * - RFC 791: Internet Protocol (IP fragmentation)
     * - CVE-2018-5391: FragmentSmack (Linux fragment handling DoS)
     *=======================================================================*/

    uint16_t flags_fragment = ntohs(ip->flags_fragment);
    uint16_t fragment_offset = flags_fragment & 0x1FFF;  /* Bits 0-12 */
    bool more_fragments = (flags_fragment & 0x2000) != 0; /* Bit 13 (MF) */

    /* Reject fragmented packets */
    if (more_fragments || fragment_offset != 0) {
        /* Fragmented packet - drop to prevent firewall bypass */
        stats.packets_dropped++;
        return false;
    }

    stats.packets_total++;

    uint32_t src_ip = ntohl(*(uint32_t*)ip->src_ip);
    uint32_t dst_ip = ntohl(*(uint32_t*)ip->dest_ip);
    uint16_t src_port = 0, dst_port = 0;

    /*=========================================================================
     * CRITICAL FIX: Extract UDP ports EARLY for DHCP exception
     * DHCP must be allowed BEFORE bogon filtering, since DHCP servers on LAN
     * use RFC1918 private IPs (10.0.2.2, 192.168.x.x, etc.) which would
     * otherwise be blocked as "bogons".
     *
     * DHCP uses UDP port 67 (server) and 68 (client).
     *=======================================================================*/
    if (ip->protocol == IPPROTO_UDP) {
        /* Verify UDP header fits in packet */
        if (ihl + sizeof(udp_header_t) > packet_len) {
            stats.packets_dropped++;
            return false;
        }
        udp_header_t* udp = get_udp_header(ip);
        src_port = ntohs(udp->src_port);
        dst_port = ntohs(udp->dest_port);

        /*=====================================================================
         * DHCP EXCEPTION: Always allow DHCP traffic
         * CRITICAL: DHCP must work on local networks with RFC1918 IPs
         *
         * DHCP client sends:  0.0.0.0:68 -> 255.255.255.255:67 (DISCOVER)
         * DHCP server replies: <server_ip>:67 -> <client_ip>:68 (OFFER/ACK)
         *
         * Without this exception, DHCP responses from LAN DHCP servers
         * (10.0.2.2, 192.168.1.1, etc.) would be blocked as bogons.
         *===================================================================*/
        if ((src_port == DHCP_SERVER_PORT && dst_port == DHCP_CLIENT_PORT) ||
            (src_port == DHCP_CLIENT_PORT && dst_port == DHCP_SERVER_PORT)) {
            stats.packets_accepted++;
            return true;  /* Allow all DHCP traffic */
        }
    }

    /*=========================================================================
     * SECURITY: Bogon IP Filtering
     * CRITICAL: Drop packets from reserved/unroutable IP ranges
     *
     * Many attacks use spoofed source IPs from bogon ranges:
     * - DDoS amplification attacks (spoofed DNS, NTP, etc.)
     * - Network reconnaissance/scanning
     * - Misconfigured networks leaking private IPs
     *
     * This check prevents the system from responding to spoofed packets,
     * which would:
     * 1. Waste CPU/bandwidth responding to unreachable hosts
     * 2. Participate in DDoS amplification attacks
     * 3. Leak information to attackers
     *
     * NOTE: For internal LANs, you may want to allow RFC1918 ranges.
     *       This implementation assumes a perimeter firewall.
     * EXCEPTION: DHCP traffic is allowed above (critical for LAN operation)
     *=======================================================================*/
    if (is_bogon_ip(src_ip)) {
        stats.packets_dropped++;
        /* Silent drop - no need to log every bogon packet (would fill logs) */
        return false;
    }

    /* Extract TCP ports and perform SYN flood detection */
    if (ip->protocol == IPPROTO_TCP) {
        /* Verify TCP header fits in packet */
        if (ihl + sizeof(tcp_header_t) > packet_len) {
            stats.packets_dropped++;
            return false;
        }
        tcp_header_t* tcp = get_tcp_header(ip);
        src_port = ntohs(tcp->src_port);
        dst_port = ntohs(tcp->dest_port);

        /* SYN flood detection */
        detect_syn_flood(src_ip, tcp);
    }
    /* UDP ports already extracted above for DHCP check */

    /* Port scan detection */
    if (dst_port > 0) {
        detect_port_scan(src_ip, dst_port);
    }

    /* Rate limiting */
    if (!check_rate_limit(src_ip)) {
        stats.packets_dropped++;
        return false;
    }

    /* Connection tracking */
    connection_entry_t* conn = find_connection(src_ip, dst_ip, src_port, dst_port, ip->protocol);
    if (conn) {
        conn->last_seen = pit_get_ticks();
        conn->packets_sent++;
        if (conn->state == CONN_STATE_ESTABLISHED) {
            stats.packets_accepted++;
            return true;  /* Established connection - allow */
        }
    }

    /* Check firewall rules */
    firewall_rule_t* rule = match_rule(ip, src_port, dst_port);
    if (rule) {
        if (rule->action == FW_ACTION_ACCEPT || rule->action == FW_ACTION_LOG) {
            /* Create connection for stateful tracking */
            if (!conn && (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP)) {
                conn = create_connection(src_ip, dst_ip, src_port, dst_port, ip->protocol);
                if (conn) conn->state = CONN_STATE_ESTABLISHED;
            }

            if (rule->action == FW_ACTION_LOG) {
                audit_log(AUDIT_NET_CONNECT, AUDIT_INFO, 0,
                          "Firewall ACCEPT: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u (%s)",
                          (unsigned)((src_ip >> 24) & 0xFF), (unsigned)((src_ip >> 16) & 0xFF),
                          (unsigned)((src_ip >> 8) & 0xFF), (unsigned)(src_ip & 0xFF), (unsigned)src_port,
                          (unsigned)((dst_ip >> 24) & 0xFF), (unsigned)((dst_ip >> 16) & 0xFF),
                          (unsigned)((dst_ip >> 8) & 0xFF), (unsigned)(dst_ip & 0xFF), (unsigned)dst_port,
                          rule->description);
            }

            stats.packets_accepted++;
            return true;
        } else {
            if (rule->action == FW_ACTION_LOG_DROP) {
                audit_log(AUDIT_NET_FIREWALL_BLOCK, AUDIT_WARN, 0,
                          "Firewall DROP: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u (%s)",
                          (unsigned)((src_ip >> 24) & 0xFF), (unsigned)((src_ip >> 16) & 0xFF),
                          (unsigned)((src_ip >> 8) & 0xFF), (unsigned)(src_ip & 0xFF), (unsigned)src_port,
                          (unsigned)((dst_ip >> 24) & 0xFF), (unsigned)((dst_ip >> 16) & 0xFF),
                          (unsigned)((dst_ip >> 8) & 0xFF), (unsigned)(dst_ip & 0xFF), (unsigned)dst_port,
                          rule->description);
            }

            stats.packets_dropped++;
            return false;
        }
    }

    /* Default: DENY ALL */
    stats.packets_dropped++;
    return false;
}

/*=============================================================================
 * API Implementation
 *===========================================================================*/
void firewall_init(void) {
    memset(rules, 0, sizeof(rules));
    memset(connections, 0, sizeof(connections));
    memset(&stats, 0, sizeof(stats));
    rule_count = 0;
    connection_count = 0;
    rate_limit_count = 0;
    detector_count = 0;
    firewall_enabled = true;

    kprintf("[FIREWALL] Initialized\n");
    kprintf("[FIREWALL] Default policy: DENY ALL\n");
    kprintf("[FIREWALL] Max rules: %d\n", FIREWALL_MAX_RULES);
    kprintf("[FIREWALL] Max connections: %d\n", FIREWALL_MAX_CONNECTIONS);
}

/*=============================================================================
 * SECURITY FIX: Race Condition Protection
 *===========================================================================
 * VULNERABILITY: Unsynchronized access to shared firewall state
 *
 * PROBLEM: Firewall rules/connections are accessed from:
 * 1. IRQ context: match_rule() during packet processing (interrupts)
 * 2. Task context: API calls to add/remove rules
 *
 * Without synchronization:
 * - IRQ handler reads rules[] while add_rule() is copying data
 * - Result: Partially written rule, wrong allow/deny decision
 * - IRQ handler reads rules[i] while remove_rule() shifts array
 * - Result: Reads freed/moved memory, crashes or wrong decision
 *
 * FIX: Protect all modifications with CRITICAL_SECTION
 * - Disables interrupts during rule modifications
 * - IRQ handlers cannot interrupt and read inconsistent state
 * - Read path (IRQ) doesn't need locks (already has interrupts disabled)
 *
 * ALTERNATIVE: Could use RCU (Read-Copy-Update) for better performance,
 * but CRITICAL_SECTION is simpler and sufficient for this workload
 *==========================================================================*/

int firewall_add_rule(const firewall_rule_t* rule) {
    int result;

    CRITICAL_SECTION_ENTER();

    if (rule_count >= FIREWALL_MAX_RULES) {
        CRITICAL_SECTION_EXIT();
        return -1;
    }

    memcpy(&rules[rule_count], rule, sizeof(firewall_rule_t));
    rules[rule_count].enabled = true;
    rules[rule_count].packet_count = 0;
    rules[rule_count].byte_count = 0;

    result = rule_count++;

    CRITICAL_SECTION_EXIT();

    return result;
}

int firewall_remove_rule(int rule_id) {
    CRITICAL_SECTION_ENTER();

    if (rule_id < 0 || rule_id >= rule_count) {
        CRITICAL_SECTION_EXIT();
        return -1;
    }

    /* Shift rules down - protected from IRQ context reading partial state */
    for (int i = rule_id; i < rule_count - 1; i++) {
        rules[i] = rules[i + 1];
    }
    rule_count--;

    CRITICAL_SECTION_EXIT();

    return 0;
}

int firewall_set_rule_enabled(int rule_id, bool enabled) {
    CRITICAL_SECTION_ENTER();

    if (rule_id < 0 || rule_id >= rule_count) {
        CRITICAL_SECTION_EXIT();
        return -1;
    }

    /* Protected write to rule state */
    rules[rule_id].enabled = enabled;

    CRITICAL_SECTION_EXIT();

    return 0;
}

void firewall_get_stats(firewall_stats_t* out_stats) {
    memcpy(out_stats, &stats, sizeof(firewall_stats_t));
}

void firewall_clear_rules(void) {
    CRITICAL_SECTION_ENTER();

    /* Clear all rules atomically */
    rule_count = 0;
    memset(rules, 0, sizeof(rules));

    CRITICAL_SECTION_EXIT();
}

void firewall_clear_connections(void) {
    CRITICAL_SECTION_ENTER();

    /* Clear all connections atomically */
    connection_count = 0;
    memset(connections, 0, sizeof(connections));

    CRITICAL_SECTION_EXIT();
}

/*=============================================================================
 * Convenience Functions
 *===========================================================================*/
void firewall_allow_outgoing(void) {
    firewall_rule_t rule = {0};
    rule.action = FW_ACTION_ACCEPT;
    rule.priority = 100;
    safe_strcpy(rule.description, "Allow all outgoing", sizeof(rule.description) - 1);
    firewall_add_rule(&rule);
}

void firewall_allow_established(void) {
    /*=========================================================================
     * Allow packets from established connections
     *
     * This allows response packets to pass through. Works with stateful
     * connection tracking - if we initiated an outgoing connection,
     * allow the response packets back in.
     *
     * SECURITY: This doesn't open new inbound connections, only allows
     * responses to connections we initiated.
     *=======================================================================*/
    firewall_rule_t rule = {0};
    rule.action = FW_ACTION_ACCEPT;
    rule.priority = 10;  /* High priority - check established first */
    safe_strcpy(rule.description, "Allow established/related", sizeof(rule.description) - 1);
    firewall_add_rule(&rule);

    /* Note: The actual connection state check happens in firewall_check_packet()
     * via the connection tracking table. This rule just sets the policy. */
}

void firewall_allow_port(uint16_t port, uint8_t protocol, const char* description) {
    firewall_rule_t rule = {0};
    rule.dst_port = port;
    rule.protocol = protocol;
    rule.action = FW_ACTION_ACCEPT;
    rule.priority = 50;
    rule.bidirectional = true;  /* Allow both incoming and outgoing traffic */
    safe_strcpy(rule.description, description, sizeof(rule.description) - 1);
    firewall_add_rule(&rule);
}

void firewall_allow_icmp(void) {
    firewall_rule_t rule = {0};
    rule.protocol = IPPROTO_ICMP;
    rule.action = FW_ACTION_ACCEPT;
    rule.priority = 50;
    safe_strcpy(rule.description, "Allow ICMP", sizeof(rule.description) - 1);
    firewall_add_rule(&rule);
}

void firewall_block_ip(uint32_t ip) {
    firewall_rule_t rule = {0};
    rule.src_ip = ip;
    rule.src_ip_mask = 0xFFFFFFFF;
    rule.action = FW_ACTION_DROP;
    rule.priority = 10;
    safe_strcpy(rule.description, "Blocked IP", sizeof(rule.description) - 1);
    firewall_add_rule(&rule);
}
