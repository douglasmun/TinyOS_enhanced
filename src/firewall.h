/*=============================================================================
 * firewall.h - Packet Filtering Firewall for TinyOS
 *=============================================================================
 *
 * Features:
 * - Stateless packet filtering (5-tuple rules)
 * - Stateful inspection (connection tracking)
 * - Rate limiting (DoS protection)
 * - SYN flood protection
 * - Port scan detection
 * - Default DENY ALL policy (whitelist approach)
 *
 * Security Model:
 * - All traffic denied by default
 * - Explicit rules required to allow traffic
 * - Integrates with audit logging
 * - Real-time attack detection
 *
 * Standards Compliance:
 * - Similar to iptables/netfilter (Linux)
 * - Follows NIST SP 800-41 (firewall guidelines)
 *
 * Priority: HIGH (Phase 2.2)
 * Effort: 3 weeks
 * Version: 1.0
 * Date: 2025-01-14
 *===========================================================================*/
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "net.h"

/*=============================================================================
 * Constants
 *===========================================================================*/
#define FIREWALL_MAX_RULES          64      /* Maximum firewall rules */
#define FIREWALL_MAX_CONNECTIONS    128     /* Connection tracking table size */
#define FIREWALL_RATE_LIMIT_WINDOW  1000    /* Rate limit window (ms) */
#define FIREWALL_SYN_THRESHOLD      100     /* SYN packets/sec before alert */
#define FIREWALL_PORTSCAN_THRESHOLD 20      /* Ports scanned before alert */

/*=============================================================================
 * Firewall Actions
 *===========================================================================*/
typedef enum {
    FW_ACTION_ACCEPT,       /* Allow packet */
    FW_ACTION_DROP,         /* Silently drop packet */
    FW_ACTION_REJECT,       /* Drop and send ICMP unreachable */
    FW_ACTION_LOG,          /* Log and accept */
    FW_ACTION_LOG_DROP      /* Log and drop */
} firewall_action_t;

/*=============================================================================
 * Firewall Rule
 *===========================================================================*/
typedef struct {
    /* Match criteria (5-tuple) */
    uint32_t src_ip;            /* Source IP (0 = any) */
    uint32_t src_ip_mask;       /* Source IP mask */
    uint32_t dst_ip;            /* Destination IP (0 = any) */
    uint32_t dst_ip_mask;       /* Destination IP mask */
    uint16_t src_port;          /* Source port (0 = any) */
    uint16_t dst_port;          /* Destination port (0 = any) */
    uint8_t  protocol;          /* Protocol: TCP, UDP, ICMP (0 = any) */

    /* Action */
    firewall_action_t action;

    /* Flags */
    bool enabled;               /* Is rule active? */
    bool bidirectional;         /* Match both directions? */

    /* Statistics */
    uint32_t packet_count;      /* Packets matched */
    uint32_t byte_count;        /* Bytes matched */

    /* Metadata */
    char description[64];       /* Human-readable rule description */
    uint32_t priority;          /* Rule priority (lower = higher priority) */
} firewall_rule_t;

/*=============================================================================
 * Connection State (for stateful inspection)
 *===========================================================================*/
typedef enum {
    CONN_STATE_NEW,             /* New connection (first packet) */
    CONN_STATE_ESTABLISHED,     /* Connection established */
    CONN_STATE_RELATED,         /* Related to established connection */
    CONN_STATE_INVALID,         /* Invalid state transition */
    CONN_STATE_CLOSED           /* Connection closed */
} conn_state_t;

typedef struct {
    /* 5-tuple */
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;

    /* Connection state */
    conn_state_t state;
    uint32_t seq_num;           /* TCP sequence number */
    uint32_t ack_num;           /* TCP acknowledgment number */

    /* Timestamps */
    uint32_t created_time;      /* Connection creation time */
    uint32_t last_seen;         /* Last packet time */

    /* Counters */
    uint32_t packets_sent;      /* Packets in forward direction */
    uint32_t packets_recv;      /* Packets in reverse direction */

    bool active;
} connection_entry_t;

/*=============================================================================
 * Rate Limiting
 *===========================================================================*/
typedef struct {
    uint32_t src_ip;
    uint32_t packet_count;      /* Packets in current window */
    uint32_t window_start;      /* Window start time (ms) */
    uint32_t total_dropped;     /* Total dropped packets */
    uint32_t last_seen;         /* Last packet time (for LRU eviction) */
} rate_limit_entry_t;

/*=============================================================================
 * Attack Detection
 *===========================================================================*/
typedef struct {
    uint32_t src_ip;
    uint16_t ports_scanned[64]; /* Ports attempted */
    uint8_t  port_count;        /* Number of unique ports */
    uint32_t last_scan_time;    /* Last port scan timestamp */
    uint32_t syn_count;         /* SYN packets in current window */
    uint32_t syn_window_start;  /* SYN tracking window start */
} attack_detector_t;

/*=============================================================================
 * Firewall Statistics
 *===========================================================================*/
typedef struct {
    uint64_t packets_total;         /* Total packets processed */
    uint64_t packets_accepted;      /* Packets accepted */
    uint64_t packets_dropped;       /* Packets dropped */
    uint64_t packets_rejected;      /* Packets rejected */
    uint64_t syn_floods_detected;   /* SYN flood attacks detected */
    uint64_t port_scans_detected;   /* Port scans detected */
    uint64_t rate_limit_hits;       /* Rate limit violations */
} firewall_stats_t;

/*=============================================================================
 * Firewall API
 *===========================================================================*/

/**
 * @brief Initialize firewall subsystem
 *
 * Sets up connection tracking, rate limiting, and default rules.
 * Default policy: DENY ALL (whitelist approach)
 */
void firewall_init(void);

/**
 * @brief Add firewall rule
 *
 * @param rule Pointer to firewall rule structure
 * @return Rule ID on success, -1 on failure
 *
 * Rules are evaluated in priority order (lower priority value = higher precedence)
 */
int firewall_add_rule(const firewall_rule_t* rule);

/**
 * @brief Remove firewall rule by ID
 *
 * @param rule_id Rule ID returned by firewall_add_rule()
 * @return 0 on success, -1 on failure
 */
int firewall_remove_rule(int rule_id);

/**
 * @brief Enable/disable firewall rule
 *
 * @param rule_id Rule ID
 * @param enabled true to enable, false to disable
 * @return 0 on success, -1 on failure
 */
int firewall_set_rule_enabled(int rule_id, bool enabled);

/**
 * @brief Check if packet should be allowed
 *
 * This is the main packet filtering function called by the network stack.
 *
 * @param ip_header Pointer to IP header
 * @param packet_len Total packet length
 * @return true if packet allowed, false if dropped
 *
 * Side effects:
 * - Updates connection tracking table
 * - Updates rate limiting counters
 * - Logs to audit system if action is LOG
 * - Detects SYN floods and port scans
 */
bool firewall_check_packet(const ip_header_t* ip_header, size_t packet_len);

/**
 * @brief Get firewall statistics
 *
 * @param stats Output statistics structure
 */
void firewall_get_stats(firewall_stats_t* stats);

/**
 * @brief Clear all firewall rules (except default deny)
 */
void firewall_clear_rules(void);

/**
 * @brief Clear connection tracking table
 */
void firewall_clear_connections(void);

/**
 * @brief Print firewall rules (for debugging)
 */
void firewall_print_rules(void);

/**
 * @brief Print active connections (for debugging)
 */
void firewall_print_connections(void);

/*=============================================================================
 * Convenience Functions for Common Rules
 *===========================================================================*/

/**
 * @brief Allow all outgoing connections
 */
void firewall_allow_outgoing(void);

/**
 * @brief Allow established connections (stateful)
 */
void firewall_allow_established(void);

/**
 * @brief Allow incoming connections on specific port
 *
 * @param port Port number
 * @param protocol Protocol (IPPROTO_TCP, IPPROTO_UDP)
 * @param description Rule description
 */
void firewall_allow_port(uint16_t port, uint8_t protocol, const char* description);

/**
 * @brief Block IP address
 *
 * @param ip IP address to block (network byte order)
 */
void firewall_block_ip(uint32_t ip);

/**
 * @brief Allow ICMP (ping)
 */
void firewall_allow_icmp(void);

/*=============================================================================
 * Attack Detection API
 *===========================================================================*/

/**
 * @brief Check if source IP is under attack detection
 *
 * @param src_ip Source IP address
 * @return true if suspicious activity detected
 */
bool firewall_is_under_attack(uint32_t src_ip);

/**
 * @brief Get number of port scans detected
 */
uint32_t firewall_get_portscan_count(void);

/**
 * @brief Get number of SYN floods detected
 */
uint32_t firewall_get_synflood_count(void);
