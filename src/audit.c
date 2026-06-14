/*
 * TinyOS Security Audit Logging System
 * Version: 1.0
 * Date: 2025-01-14
 *
 * Implementation of tamper-evident audit logging using HMAC-SHA512 chaining.
 */

#include "audit.h"
#include "crypto.h"
#include "time.h"
#include "process.h"
#include "critical.h"
#include "kprintf.h"
#include "util.h"
#include "util.h"  /* For memcpy, memset */
#include <stdarg.h>

/*
 * ============================================================================
 * Audit Log Storage
 * ============================================================================
 */

#define AUDIT_BUFFER_SIZE   1000    /* Number of events in circular buffer */

/* Circular buffer for audit events */
static audit_event_t audit_buffer[AUDIT_BUFFER_SIZE];
static uint32_t audit_head = 0;         /* Next write position */
static uint32_t audit_count = 0;        /* Number of events in buffer */
static uint32_t audit_sequence = 0;     /* Monotonic sequence number */

/* Statistics */
static audit_stats_t audit_statistics = {0};

/* HMAC key for audit chain (generated at boot) */
static uint8_t audit_hmac_key[32];

/* Previous HMAC (for chaining) */
static uint8_t audit_prev_hmac[AUDIT_HMAC_SIZE];

/* Mutex for thread-safe access */
static bool audit_initialized = false;

/*
 * ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/* Compute HMAC for an audit event */
static void audit_compute_hmac(const audit_event_t* event, uint8_t* hmac_out) {
    hmac_ctx_t ctx;

    /* Initialize HMAC with audit key */
    hmac_init(&ctx, audit_hmac_key, sizeof(audit_hmac_key));

    /* Include previous HMAC (chain) */
    hmac_update(&ctx, audit_prev_hmac, AUDIT_HMAC_SIZE);

    /* Include event metadata (excluding HMAC field) */
    hmac_update(&ctx, (const uint8_t*)&event->timestamp, sizeof(event->timestamp));
    hmac_update(&ctx, (const uint8_t*)&event->sequence, sizeof(event->sequence));
    hmac_update(&ctx, (const uint8_t*)&event->uid, sizeof(event->uid));
    hmac_update(&ctx, (const uint8_t*)&event->pid, sizeof(event->pid));
    hmac_update(&ctx, (const uint8_t*)&event->type, sizeof(event->type));
    hmac_update(&ctx, (const uint8_t*)&event->severity, sizeof(event->severity));
    hmac_update(&ctx, (const uint8_t*)event->description, AUDIT_DESC_MAX);

    /* Finalize HMAC */
    hmac_final(&ctx, hmac_out);
    hmac_destroy(&ctx);
}

/*
 * ============================================================================
 * Public API Implementation
 * ============================================================================
 */

void audit_init(void) {
    /* Generate random HMAC key */
    csprng_random_bytes(&global_csprng, audit_hmac_key, sizeof(audit_hmac_key));

    /* Initialize previous HMAC to zero */
    memset(audit_prev_hmac, 0, AUDIT_HMAC_SIZE);

    /* Clear buffer */
    memset(audit_buffer, 0, sizeof(audit_buffer));
    audit_head = 0;
    audit_count = 0;
    audit_sequence = 0;

    /* Reset statistics */
    memset(&audit_statistics, 0, sizeof(audit_statistics));

    audit_initialized = true;

    /* Log system boot event */
    audit_log(AUDIT_SYS_BOOT, AUDIT_INFO, 0, "TinyOS audit system initialized");
}

void audit_log_raw(audit_event_type_t type, audit_severity_t severity,
                   uint16_t uid, const char* description) {
    if (!audit_initialized) return;

    /*=========================================================================
     * SECURITY FIX: IRQ-Safe Audit Logging
     *
     * PROBLEM: audit_log() can be called from both normal context (kernel init)
     * and interrupt context (SSH from network IRQ). Calling task_current() from
     * IRQ context can return invalid/NULL pointer, causing page faults.
     *
     * FIX: Safely handle task_current() with defensive checks, and ensure we
     * never call task_current() without validation.
     *=======================================================================*/

    audit_event_t* event;

    /* Enter critical section */
    CRITICAL_SECTION_ENTER();

    /* Get next event slot (circular buffer) */
    event = &audit_buffer[audit_head];

    /* Fill event metadata */
    event->timestamp = time_get_uptime_seconds();
    event->sequence = audit_sequence++;
    event->uid = uid;

    /* SECURITY FIX: Safe PID retrieval for IRQ context compatibility.
     * Validate against the real tasks[] pool (correct slot, in bounds, aligned)
     * rather than a bare ">= 1MB" address heuristic — a stray in-range pointer
     * can no longer be dereferenced as a task. */
    task_t* current_task = task_current();
    if (task_is_valid_ptr(current_task)) {
        event->pid = current_task->pid;
    } else {
        /* NULL or invalid pointer - likely in IRQ context or early boot */
        event->pid = 0;
    }

    event->type = type;
    event->severity = severity;

    /* Copy description (ensure null-termination) */
    safe_strcpy(event->description, description, AUDIT_DESC_MAX);

    /* Compute HMAC (includes previous HMAC for chaining) */
    audit_compute_hmac(event, event->hmac);

    /* Update previous HMAC for next event */
    memcpy(audit_prev_hmac, event->hmac, AUDIT_HMAC_SIZE);

    /* Update circular buffer pointers */
    audit_head = (audit_head + 1) % AUDIT_BUFFER_SIZE;
    if (audit_count < AUDIT_BUFFER_SIZE) {
        audit_count++;
    } else {
        audit_statistics.events_dropped++;
    }

    /* Update statistics */
    audit_statistics.total_events++;
    audit_statistics.events_in_buffer = audit_count;
    audit_statistics.newest_sequence = event->sequence;
    if (audit_count == AUDIT_BUFFER_SIZE) {
        audit_statistics.oldest_sequence = audit_buffer[audit_head].sequence;
    } else {
        audit_statistics.oldest_sequence = audit_buffer[0].sequence;
    }

    /*=========================================================================
     * SECURITY FIX (Issue 7.2): Atomic Audit Log Writes
     *
     * CRITICAL: The kprintf() call MUST happen inside the critical section
     * to ensure atomic write of the entire log message (buffer + serial output).
     *
     * WHY: If kprintf() happens outside the critical section, concurrent
     * audit_log() calls from different tasks can interleave their serial
     * output, corrupting the audit trail and making forensic analysis
     * impossible.
     *
     * EXAMPLE OF BUG:
     *   Task A: Logs "Login failed for user admin"
     *   Task B: Logs "File deleted: /etc/passwd"
     *   Without atomicity: "[AUDIT] ERROR: Login failed [AUDIT] CRITICAL:
     *   for user admin File deleted: /etc/passwd"
     *
     * TRADEOFF: Keeping kprintf() inside the critical section increases
     * interrupt latency, but this only affects ERROR/CRITICAL events
     * (checked below), not normal INFO/DEBUG logging. Security trumps
     * performance for forensic-critical events.
     *=======================================================================*/

    /* Print critical events immediately to serial (INSIDE critical section) */
    if (severity >= AUDIT_ERROR) {
        kprintf("[AUDIT] %s: %s\n",
                audit_severity_str(severity),
                description);
    }

    CRITICAL_SECTION_EXIT();
}

void audit_log(audit_event_type_t type, audit_severity_t severity,
               uint16_t uid, const char* format, ...) {
    char description[AUDIT_DESC_MAX];
    va_list args;

    /* Format description string */
    va_start(args, format);
    vsnprintf_impl(description, AUDIT_DESC_MAX, format, args);
    va_end(args);

    /* Log the event */
    audit_log_raw(type, severity, uid, description);
}

int audit_query(const audit_filter_t* filter, audit_event_t* results, int max_results) {
    int count = 0;
    uint32_t start_idx;

    if (!audit_initialized || !results || max_results <= 0) {
        return 0;
    }

    /* Enter critical section to prevent buffer changes */
    CRITICAL_SECTION_ENTER();

    /* Calculate start index (oldest event) */
    if (audit_count < AUDIT_BUFFER_SIZE) {
        start_idx = 0;
    } else {
        start_idx = audit_head;
    }

    /* Iterate through all events in buffer */
    for (uint32_t i = 0; i < audit_count && count < max_results; i++) {
        uint32_t idx = (start_idx + i) % AUDIT_BUFFER_SIZE;
        audit_event_t* event = &audit_buffer[idx];

        /* Apply filters */
        bool match = true;

        if (filter) {
            /* Filter by event type */
            if (filter->type != 0 && event->type != filter->type) {
                match = false;
            }

            /* Filter by severity (or higher) */
            if (event->severity < filter->min_severity) {
                match = false;
            }

            /* Filter by UID */
            if (filter->uid != 0xFFFF && event->uid != filter->uid) {
                match = false;
            }

            /* Filter by time range */
            if (filter->start_time != 0 && event->timestamp < filter->start_time) {
                match = false;
            }
            if (filter->end_time != 0 && event->timestamp > filter->end_time) {
                match = false;
            }
        }

        /* Add to results if matches */
        if (match) {
            memcpy(&results[count], event, sizeof(audit_event_t));
            count++;
        }
    }

    CRITICAL_SECTION_EXIT();

    return count;
}

void audit_get_stats(audit_stats_t* stats) {
    if (!audit_initialized || !stats) return;

    CRITICAL_SECTION_ENTER();
    memcpy(stats, &audit_statistics, sizeof(audit_stats_t));
    CRITICAL_SECTION_EXIT();
}

bool audit_verify_integrity(void) {
    if (!audit_initialized) return false;

    uint8_t computed_hmac[AUDIT_HMAC_SIZE];
    uint8_t chain_hmac[AUDIT_HMAC_SIZE];
    uint32_t start_idx;
    bool valid = true;

    CRITICAL_SECTION_ENTER();

    /* Start with zero HMAC (initial state) */
    memset(chain_hmac, 0, AUDIT_HMAC_SIZE);

    /* Calculate start index */
    if (audit_count < AUDIT_BUFFER_SIZE) {
        start_idx = 0;
    } else {
        start_idx = audit_head;
    }

    /* Verify HMAC chain */
    for (uint32_t i = 0; i < audit_count; i++) {
        uint32_t idx = (start_idx + i) % AUDIT_BUFFER_SIZE;
        audit_event_t* event = &audit_buffer[idx];

        /* Save previous HMAC for this event */
        uint8_t saved_prev[AUDIT_HMAC_SIZE];
        memcpy(saved_prev, audit_prev_hmac, AUDIT_HMAC_SIZE);

        /* Temporarily set prev_hmac to chain value */
        memcpy(audit_prev_hmac, chain_hmac, AUDIT_HMAC_SIZE);

        /* Recompute HMAC */
        audit_compute_hmac(event, computed_hmac);

        /* Restore prev_hmac */
        memcpy(audit_prev_hmac, saved_prev, AUDIT_HMAC_SIZE);

        /* Compare */
        if (!crypto_constant_time_compare(computed_hmac, event->hmac, AUDIT_HMAC_SIZE)) {
            valid = false;
            audit_statistics.tamper_detections++;
            kprintf("[AUDIT] TAMPER DETECTED at sequence %u!\n", event->sequence);
            break;
        }

        /* Update chain for next event */
        memcpy(chain_hmac, event->hmac, AUDIT_HMAC_SIZE);
    }

    CRITICAL_SECTION_EXIT();

    return valid;
}

int audit_clear(uint16_t uid) {
    /* Only root (UID 0) can clear audit log */
    if (uid != 0) {
        audit_log(AUDIT_SEC_PERMISSION_DENIED, AUDIT_WARN, uid,
                  "Attempt to clear audit log denied");
        return -1;
    }

    /* Log the clear operation before clearing */
    audit_log(AUDIT_SYS_CONFIG_CHANGE, AUDIT_WARN, uid,
              "Audit log cleared by UID %u", uid);

    CRITICAL_SECTION_ENTER();

    /* Clear buffer */
    memset(audit_buffer, 0, sizeof(audit_buffer));
    audit_head = 0;
    audit_count = 0;

    /* Reset HMAC chain */
    memset(audit_prev_hmac, 0, AUDIT_HMAC_SIZE);

    /* Keep sequence number (monotonic) */
    /* Reset some statistics */
    audit_statistics.events_in_buffer = 0;
    audit_statistics.events_dropped = 0;

    CRITICAL_SECTION_EXIT();

    return 0;
}

/*
 * ============================================================================
 * Utility Functions
 * ============================================================================
 */

const char* audit_event_type_str(audit_event_type_t type) {
    switch (type) {
        /* Authentication */
        case AUDIT_AUTH_LOGIN_SUCCESS:      return "AUTH_LOGIN_SUCCESS";
        case AUDIT_AUTH_LOGIN_FAILURE:      return "AUTH_LOGIN_FAILURE";
        case AUDIT_AUTH_LOGOUT:             return "AUTH_LOGOUT";
        case AUDIT_AUTH_PASSWORD_CHANGE:    return "AUTH_PASSWORD_CHANGE";
        case AUDIT_AUTH_ACCOUNT_LOCKED:     return "AUTH_ACCOUNT_LOCKED";
        case AUDIT_AUTH_ACCOUNT_UNLOCKED:   return "AUTH_ACCOUNT_UNLOCKED";

        /* Privilege */
        case AUDIT_PRIV_SETUID:             return "PRIV_SETUID";
        case AUDIT_PRIV_SETGID:             return "PRIV_SETGID";
        case AUDIT_PRIV_ESCALATION:         return "PRIV_ESCALATION";
        case AUDIT_PRIV_DEESCALATION:       return "PRIV_DEESCALATION";

        /* File Operations */
        case AUDIT_FILE_OPEN:               return "FILE_OPEN";
        case AUDIT_FILE_CREATE:             return "FILE_CREATE";
        case AUDIT_FILE_DELETE:             return "FILE_DELETE";
        case AUDIT_FILE_CHMOD:              return "FILE_CHMOD";
        case AUDIT_FILE_CHOWN:              return "FILE_CHOWN";
        case AUDIT_FILE_READ:               return "FILE_READ";
        case AUDIT_FILE_WRITE:              return "FILE_WRITE";

        /* Network */
        case AUDIT_NET_CONNECT:             return "NET_CONNECT";
        case AUDIT_NET_DISCONNECT:          return "NET_DISCONNECT";
        case AUDIT_NET_SEND:                return "NET_SEND";
        case AUDIT_NET_RECV:                return "NET_RECV";
        case AUDIT_NET_FIREWALL_BLOCK:      return "NET_FIREWALL_BLOCK";

        /* Security */
        case AUDIT_SEC_PERMISSION_DENIED:   return "SEC_PERMISSION_DENIED";
        case AUDIT_SEC_INVALID_SIGNATURE:   return "SEC_INVALID_SIGNATURE";
        case AUDIT_SEC_TAMPER_DETECTED:     return "SEC_TAMPER_DETECTED";
        case AUDIT_SEC_POLICY_VIOLATION:    return "SEC_POLICY_VIOLATION";
        case AUDIT_SEC_INTRUSION_DETECTED:  return "SEC_INTRUSION_DETECTED";
        case AUDIT_SEC_STACK_CORRUPTION:    return "SEC_STACK_CORRUPTION";
        case AUDIT_SEC_MEMORY_VIOLATION:    return "SEC_MEMORY_VIOLATION";
        case AUDIT_SEC_SYSCALL_VIOLATION:   return "SEC_SYSCALL_VIOLATION";
        case AUDIT_SEC_EXPLOIT_ATTEMPT:     return "SEC_EXPLOIT_ATTEMPT";

        /* System */
        case AUDIT_SYS_BOOT:                return "SYS_BOOT";
        case AUDIT_SYS_SHUTDOWN:            return "SYS_SHUTDOWN";
        case AUDIT_SYS_CRASH:               return "SYS_CRASH";
        case AUDIT_SYS_CONFIG_CHANGE:       return "SYS_CONFIG_CHANGE";
        case AUDIT_SYS_TIME_CHANGE:         return "SYS_TIME_CHANGE";

        /* Process */
        case AUDIT_PROC_CREATE:             return "PROC_CREATE";
        case AUDIT_PROC_EXIT:               return "PROC_EXIT";
        case AUDIT_PROC_KILL:               return "PROC_KILL";

        default:                            return "UNKNOWN";
    }
}

const char* audit_severity_str(audit_severity_t severity) {
    switch (severity) {
        case AUDIT_DEBUG:    return "DEBUG";
        case AUDIT_INFO:     return "INFO";
        case AUDIT_WARN:     return "WARN";
        case AUDIT_ERROR:    return "ERROR";
        case AUDIT_CRITICAL: return "CRITICAL";
        default:             return "UNKNOWN";
    }
}

void audit_print_event(const audit_event_t* event) {
    if (!event) return;

    kprintf("[%u] %s | %s | UID=%u PID=%u | %s\n",
            event->sequence,
            audit_severity_str(event->severity),
            audit_event_type_str(event->type),
            event->uid,
            event->pid,
            event->description);
}
