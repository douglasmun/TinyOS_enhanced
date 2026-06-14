/*=============================================================================
 * ids.h - Intrusion Detection System for TinyOS
 *=============================================================================
 *
 * Features:
 * - Signature-based detection (known attack patterns)
 * - Anomaly-based detection (statistical deviation)
 * - Behavior-based detection (process activity monitoring)
 * - Integration with firewall for automatic blocking
 * - Audit logging for all alerts
 * - Fail-safe mode triggering
 *
 * Detection Layers:
 * 1. Network IDS (NIDS) - Analyzes packets
 * 2. Host IDS (HIDS) - Monitors system calls and processes
 *
 * Standards Compliance:
 * - Similar to Snort/Suricata (open-source IDS)
 * - NIST SP 800-94 (Intrusion Detection and Prevention Systems)
 *
 * Priority: HIGH (Phase 2.3)
 * Effort: 4 weeks
 * Version: 1.0
 * Date: 2025-01-14
 *===========================================================================*/
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "net.h"
#include "process.h"

/*=============================================================================
 * Constants
 *===========================================================================*/
#define IDS_MAX_SIGNATURES          128     /* Maximum attack signatures */
#define IDS_MAX_ALERTS              1000    /* Alert history size */
#define IDS_BASELINE_WINDOW         60000   /* Baseline window (60 seconds) */
#define IDS_BRUTEFORCE_THRESHOLD    5       /* Failed login attempts before alert */
#define IDS_SYSCALL_ANOMALY_THRESHOLD 100   /* Unusual syscalls per second */

/*=============================================================================
 * Alert Types
 *===========================================================================*/
typedef enum {
    /* Network-based alerts */
    IDS_ALERT_PORTSCAN,             /* Port scanning detected */
    IDS_ALERT_SYNFLOOD,             /* SYN flood attack */
    IDS_ALERT_MALFORMED_PACKET,     /* Malformed packet detected */
    IDS_ALERT_BUFFER_OVERFLOW,      /* Buffer overflow attempt */
    IDS_ALERT_BRUTEFORCE,           /* Brute-force login attempt */
    IDS_ALERT_DOS,                  /* Denial of Service */
    IDS_ALERT_SHELLCODE,            /* Shellcode pattern detected */
    IDS_ALERT_SQL_INJECTION,        /* SQL injection attempt */

    /* Host-based alerts */
    IDS_ALERT_PRIVILEGE_ESCALATION, /* Privilege escalation attempt */
    IDS_ALERT_SUSPICIOUS_SYSCALL,   /* Unusual system call pattern */
    IDS_ALERT_FORK_BOMB,            /* Fork bomb detected */
    IDS_ALERT_FILE_TAMPERING,       /* Critical file modified */
    IDS_ALERT_ROOTKIT,              /* Rootkit behavior detected */

    /* Anomaly-based alerts */
    IDS_ALERT_TRAFFIC_ANOMALY,      /* Abnormal traffic pattern */
    IDS_ALERT_BEHAVIOR_ANOMALY,     /* Abnormal process behavior */

    IDS_ALERT_MAX
} ids_alert_type_t;

/*=============================================================================
 * Alert Severity
 *===========================================================================*/
typedef enum {
    IDS_SEVERITY_INFO,      /* Informational only */
    IDS_SEVERITY_LOW,       /* Low severity */
    IDS_SEVERITY_MEDIUM,    /* Medium severity */
    IDS_SEVERITY_HIGH,      /* High severity */
    IDS_SEVERITY_CRITICAL   /* Critical - immediate action required */
} ids_severity_t;

/*=============================================================================
 * Response Action
 *===========================================================================*/
typedef enum {
    IDS_ACTION_LOG,         /* Log only */
    IDS_ACTION_ALERT,       /* Log and send alert */
    IDS_ACTION_BLOCK,       /* Block offending IP/process */
    IDS_ACTION_QUARANTINE,  /* Quarantine process */
    IDS_ACTION_FAILSAFE     /* Trigger fail-safe mode */
} ids_action_t;

/*=============================================================================
 * Signature Structure
 *===========================================================================*/
typedef struct {
    char name[64];              /* Signature name */
    char description[128];      /* Attack description */
    uint8_t* pattern;           /* Byte pattern to match */
    size_t pattern_len;         /* Pattern length */
    ids_alert_type_t alert_type;
    ids_severity_t severity;
    ids_action_t action;
    bool enabled;
    uint32_t match_count;       /* Times this signature matched */
} ids_signature_t;

/*=============================================================================
 * Alert Structure
 *===========================================================================*/
typedef struct {
    ids_alert_type_t type;
    ids_severity_t severity;
    uint32_t timestamp;         /* Time of alert */
    uint32_t src_ip;            /* Source IP (for network alerts) */
    uint16_t src_port;          /* Source port */
    uint16_t dst_port;          /* Destination port */
    uint32_t pid;               /* Process ID (for host alerts) */
    char description[128];      /* Alert description */
    bool blocked;               /* Was action taken? */
} ids_alert_t;

/*=============================================================================
 * Traffic Baseline (for anomaly detection)
 *===========================================================================*/
typedef struct {
    uint64_t packets_per_sec;       /* Average packets/sec */
    uint64_t bytes_per_sec;         /* Average bytes/sec */
    uint32_t avg_packet_size;       /* Average packet size */
    uint32_t connections_per_sec;   /* Average new connections/sec */
    uint32_t window_start;          /* Baseline window start time */
    bool established;               /* Is baseline established? */
} traffic_baseline_t;

/*=============================================================================
 * Process Baseline (for behavior-based detection)
 *===========================================================================*/
typedef struct {
    uint32_t pid;
    uint32_t syscalls_per_sec;      /* Average syscalls/sec */
    uint32_t fork_rate;             /* Average fork rate */
    bool privileged;                /* Is process privileged? */
    uint32_t baseline_time;         /* Time baseline was established */
} process_baseline_t;

/*=============================================================================
 * IDS Statistics
 *===========================================================================*/
typedef struct {
    uint64_t packets_analyzed;      /* Total packets analyzed */
    uint64_t syscalls_analyzed;     /* Total syscalls analyzed */
    uint64_t alerts_generated;      /* Total alerts */
    uint64_t alerts_by_type[IDS_ALERT_MAX];
    uint64_t ips_blocked;           /* IPs blocked by IDS */
    uint64_t processes_killed;      /* Processes terminated */
    uint32_t signatures_loaded;     /* Active signatures */
} ids_stats_t;

/*=============================================================================
 * IDS API
 *===========================================================================*/

/**
 * @brief Initialize IDS subsystem
 *
 * Sets up signature database, baseline tracking, and alert system.
 */
void ids_init(void);

/**
 * @brief Analyze network packet for intrusion attempts
 *
 * @param ip_header Pointer to IP header
 * @param packet_len Total packet length
 * @return true if packet is clean, false if intrusion detected
 *
 * Performs:
 * - Signature-based detection (pattern matching)
 * - Anomaly detection (deviation from baseline)
 * - Protocol validation
 */
bool ids_analyze_packet(const ip_header_t* ip_header, size_t packet_len);

/**
 * @brief Analyze system call for suspicious behavior
 *
 * @param syscall_num System call number
 * @param task Pointer to calling task
 * @return true if syscall is clean, false if suspicious
 *
 * Detects:
 * - Privilege escalation attempts
 * - Fork bombs
 * - Unusual syscall patterns
 */
bool ids_analyze_syscall(uint32_t syscall_num, const task_t* task);

/**
 * @brief Add attack signature to IDS
 *
 * @param sig Pointer to signature structure
 * @return Signature ID on success, -1 on failure
 */
int ids_add_signature(const ids_signature_t* sig);

/**
 * @brief Remove signature by ID
 *
 * @param sig_id Signature ID
 * @return 0 on success, -1 on failure
 */
int ids_remove_signature(int sig_id);

/**
 * @brief Generate IDS alert
 *
 * @param type Alert type
 * @param severity Alert severity
 * @param src_ip Source IP (0 for host-based alerts)
 * @param description Alert description
 *
 * Actions:
 * - Logs to audit system
 * - Blocks IP if action is IDS_ACTION_BLOCK
 * - Triggers fail-safe if critical
 */
void ids_generate_alert(ids_alert_type_t type, ids_severity_t severity,
                        uint32_t src_ip, const char* description);

/**
 * @brief Get IDS statistics
 *
 * @param stats Output statistics structure
 */
void ids_get_stats(ids_stats_t* stats);

/**
 * @brief Print IDS status (for debugging)
 */
void ids_print_status(void);

/**
 * @brief Establish traffic baseline
 *
 * Called automatically during normal operation to learn baseline traffic.
 * Takes ~60 seconds to establish.
 */
void ids_establish_baseline(void);

/**
 * @brief Check if traffic is anomalous
 *
 * @param current_rate Current packet rate
 * @return true if anomalous, false if within baseline
 */
bool ids_is_traffic_anomalous(uint64_t current_rate);

/*=============================================================================
 * Convenience Functions
 *===========================================================================*/

/**
 * @brief Register brute-force attempt
 *
 * @param src_ip Source IP attempting login
 * @param username Username attempted
 * @return true if threshold exceeded (block IP)
 */
bool ids_register_login_attempt(uint32_t src_ip, const char* username);

/**
 * @brief Check for fork bomb
 *
 * @param pid Process ID
 * @return true if fork bomb detected
 */
bool ids_check_fork_bomb(uint32_t pid);

/**
 * @brief Load default attack signatures
 *
 * Loads common attack patterns:
 * - Buffer overflow signatures
 * - Shellcode patterns
 * - SQL injection patterns
 */
void ids_load_default_signatures(void);

/*=============================================================================
 * Alert Type Names (for printing)
 *===========================================================================*/
const char* ids_alert_type_name(ids_alert_type_t type);
const char* ids_severity_name(ids_severity_t severity);
