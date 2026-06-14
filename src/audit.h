/*
 * TinyOS Security Audit Logging System
 * Version: 1.0
 * Date: 2025-01-14
 *
 * Provides tamper-evident logging of security-critical events using HMAC chaining.
 * All security-relevant actions (login, privilege changes, file access, network
 * activity, policy violations) are logged with cryptographic integrity protection.
 *
 * Features:
 * - Circular buffer (1000 events in memory)
 * - HMAC-SHA512 chain (prevents tampering)
 * - Severity levels (DEBUG, INFO, WARN, ERROR, CRITICAL)
 * - Event categories (auth, file, network, system, security)
 * - Query/search API
 * - Shell integration (auditlog command)
 *
 * Compliance:
 * - Common Criteria (EAL4+) audit requirements
 * - NIST 800-53 logging requirements
 * - PCI DSS audit trail requirements
 */

#ifndef AUDIT_H
#define AUDIT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * ============================================================================
 * Audit Event Types
 * ============================================================================
 */

typedef enum {
    /* Authentication Events (0x0000-0x00FF) */
    AUDIT_AUTH_LOGIN_SUCCESS        = 0x0001,
    AUDIT_AUTH_LOGIN_FAILURE        = 0x0002,
    AUDIT_AUTH_LOGOUT               = 0x0003,
    AUDIT_AUTH_PASSWORD_CHANGE      = 0x0004,
    AUDIT_AUTH_ACCOUNT_LOCKED       = 0x0005,
    AUDIT_AUTH_ACCOUNT_UNLOCKED     = 0x0006,
    AUDIT_AUTH_PASSWORD_CHANGE_FAILURE = 0x0007,  /* Failed password change (wrong old password) */
    AUDIT_AUTH_SU_FAILURE           = 0x0008,  /* Failed su/switch user attempt */

    /* Privilege Events (0x0100-0x01FF) */
    AUDIT_PRIV_SETUID               = 0x0101,
    AUDIT_PRIV_SETGID               = 0x0102,
    AUDIT_PRIV_ESCALATION           = 0x0103,
    AUDIT_PRIV_DEESCALATION         = 0x0104,
    AUDIT_USER_SWITCH               = 0x0105,  /* User switch via sys_switch_user() */
    AUDIT_USER_PASSWORD_CHANGE      = 0x0106,  /* User password change via sys_change_password() */

    /* File Operations (0x0200-0x02FF) */
    AUDIT_FILE_OPEN                 = 0x0201,
    AUDIT_FILE_CREATE               = 0x0202,
    AUDIT_FILE_DELETE               = 0x0203,
    AUDIT_FILE_CHMOD                = 0x0204,
    AUDIT_FILE_CHOWN                = 0x0205,
    AUDIT_FILE_READ                 = 0x0206,
    AUDIT_FILE_WRITE                = 0x0207,

    /* Network Events (0x0300-0x03FF) */
    AUDIT_NET_CONNECT               = 0x0301,
    AUDIT_NET_DISCONNECT            = 0x0302,
    AUDIT_NET_SEND                  = 0x0303,
    AUDIT_NET_RECV                  = 0x0304,
    AUDIT_NET_FIREWALL_BLOCK        = 0x0305,

    /* Security Violations (0x0400-0x04FF) */
    AUDIT_SEC_PERMISSION_DENIED     = 0x0401,
    AUDIT_SEC_INVALID_SIGNATURE     = 0x0402,
    AUDIT_SEC_TAMPER_DETECTED       = 0x0403,
    AUDIT_SEC_POLICY_VIOLATION      = 0x0404,
    AUDIT_SEC_INTRUSION_DETECTED    = 0x0405,
    AUDIT_SEC_STACK_CORRUPTION      = 0x0406,  /* Stack canary violation */
    AUDIT_SEC_MEMORY_VIOLATION      = 0x0407,  /* Page fault / access violation */
    AUDIT_SEC_SYSCALL_VIOLATION     = 0x0408,  /* Invalid syscall attempt */
    AUDIT_SEC_EXPLOIT_ATTEMPT       = 0x0409,  /* Generic exploit detection */
    AUDIT_MEMORY_SEAL               = 0x040A,  /* PHASE 14: Memory sealing (mseal) */

    /* System Events (0x0500-0x05FF) */
    AUDIT_SYS_BOOT                  = 0x0501,
    AUDIT_SYS_SHUTDOWN              = 0x0502,
    AUDIT_SYS_CRASH                 = 0x0503,
    AUDIT_SYS_CONFIG_CHANGE         = 0x0504,
    AUDIT_SYS_TIME_CHANGE           = 0x0505,

    /* Process Events (0x0600-0x06FF) */
    AUDIT_PROC_CREATE               = 0x0601,
    AUDIT_PROC_EXIT                 = 0x0602,
    AUDIT_PROC_KILL                 = 0x0603,

} audit_event_type_t;

/*
 * ============================================================================
 * Audit Severity Levels
 * ============================================================================
 */

typedef enum {
    AUDIT_DEBUG    = 0,    /* Detailed debug information */
    AUDIT_INFO     = 1,    /* Informational events */
    AUDIT_WARN     = 2,    /* Warning - potential security issue */
    AUDIT_ERROR    = 3,    /* Error - security event failed */
    AUDIT_CRITICAL = 4     /* Critical - immediate attention required */
} audit_severity_t;

/*
 * ============================================================================
 * Audit Event Structure
 * ============================================================================
 */

#define AUDIT_DESC_MAX      96      /* Maximum description length */
#define AUDIT_HMAC_SIZE     64      /* HMAC-SHA512 output size */

typedef struct {
    /* Event metadata */
    uint32_t timestamp;             /* Unix timestamp (seconds since epoch) */
    uint32_t sequence;              /* Monotonic sequence number */
    uint16_t uid;                   /* User ID that triggered event */
    uint16_t pid;                   /* Process ID (if applicable) */

    /* Event details */
    audit_event_type_t type;        /* Event type */
    audit_severity_t severity;      /* Severity level */
    char description[AUDIT_DESC_MAX]; /* Human-readable description */

    /* Integrity protection */
    uint8_t hmac[AUDIT_HMAC_SIZE];  /* HMAC-SHA512 of (previous_hmac || this_event) */

} audit_event_t;

/*
 * ============================================================================
 * Audit Log Statistics
 * ============================================================================
 */

typedef struct {
    uint32_t total_events;          /* Total events logged since boot */
    uint32_t events_in_buffer;      /* Current events in circular buffer */
    uint32_t events_dropped;        /* Events dropped (buffer full) */
    uint32_t tamper_detections;     /* Number of tamper attempts detected */
    uint32_t oldest_sequence;       /* Sequence number of oldest event */
    uint32_t newest_sequence;       /* Sequence number of newest event */
} audit_stats_t;

/*
 * ============================================================================
 * Audit Query Filters
 * ============================================================================
 */

typedef struct {
    /* Filter by event type (0 = any) */
    audit_event_type_t type;

    /* Filter by severity (or higher) */
    audit_severity_t min_severity;

    /* Filter by user ID (0xFFFF = any) */
    uint16_t uid;

    /* Filter by time range (0 = no limit) */
    uint32_t start_time;
    uint32_t end_time;

} audit_filter_t;

/*
 * ============================================================================
 * Audit API
 * ============================================================================
 */

/**
 * Initialize audit logging system
 * Must be called once during boot
 */
void audit_init(void);

/**
 * Log an audit event
 *
 * @param type Event type
 * @param severity Severity level
 * @param uid User ID (0 for kernel/system events)
 * @param format Printf-style format string
 * @param ... Format arguments
 *
 * Example:
 *   audit_log(AUDIT_AUTH_LOGIN_SUCCESS, AUDIT_INFO, 1000,
 *             "User %s logged in from %s", username, source);
 */
void audit_log(audit_event_type_t type, audit_severity_t severity,
               uint16_t uid, const char* format, ...)
               __attribute__((format(printf, 4, 5)));

/**
 * Log an audit event (raw, no formatting)
 *
 * @param type Event type
 * @param severity Severity level
 * @param uid User ID
 * @param description Event description (max AUDIT_DESC_MAX chars)
 */
void audit_log_raw(audit_event_type_t type, audit_severity_t severity,
                   uint16_t uid, const char* description);

/**
 * Query audit log
 *
 * @param filter Filter criteria (NULL = all events)
 * @param results Output buffer for matching events
 * @param max_results Maximum number of results to return
 * @return Number of events returned
 *
 * Example:
 *   audit_event_t results[100];
 *   audit_filter_t filter = {
 *       .type = AUDIT_AUTH_LOGIN_FAILURE,
 *       .min_severity = AUDIT_WARN,
 *       .uid = 0xFFFF,  // any user
 *   };
 *   int count = audit_query(&filter, results, 100);
 */
int audit_query(const audit_filter_t* filter, audit_event_t* results, int max_results);

/**
 * Get audit log statistics
 *
 * @param stats Output buffer for statistics
 */
void audit_get_stats(audit_stats_t* stats);

/**
 * Verify audit log integrity
 *
 * Checks HMAC chain for all events in buffer.
 * Returns true if chain is valid, false if tampering detected.
 *
 * @return true if audit log is intact, false if tampered
 */
bool audit_verify_integrity(void);

/**
 * Clear audit log (requires privilege)
 *
 * Securely clears all audit events and resets chain.
 * This operation itself is logged.
 *
 * @param uid User ID performing the clear
 * @return 0 on success, -1 on permission denied
 */
int audit_clear(uint16_t uid);

/*
 * ============================================================================
 * Convenience Macros
 * ============================================================================
 */

/* Log with automatic UID from current task */
#define AUDIT_LOG(type, severity, fmt, ...) \
    audit_log(type, severity, task_current() ? task_current()->uid : 0, fmt, ##__VA_ARGS__)

/* Log authentication events */
#define AUDIT_AUTH(type, uid, fmt, ...) \
    audit_log(type, AUDIT_INFO, uid, fmt, ##__VA_ARGS__)

/* Log security violations (always CRITICAL) */
#define AUDIT_SECURITY(type, fmt, ...) \
    audit_log(type, AUDIT_CRITICAL, task_current() ? task_current()->uid : 0, fmt, ##__VA_ARGS__)

/* Log system events (kernel, no specific user) */
#define AUDIT_SYSTEM(type, severity, fmt, ...) \
    audit_log(type, severity, 0, fmt, ##__VA_ARGS__)

/*
 * ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * Convert event type to human-readable string
 */
const char* audit_event_type_str(audit_event_type_t type);

/**
 * Convert severity to human-readable string
 */
const char* audit_severity_str(audit_severity_t severity);

/**
 * Print audit event to serial/console
 */
void audit_print_event(const audit_event_t* event);

#endif /* AUDIT_H */
