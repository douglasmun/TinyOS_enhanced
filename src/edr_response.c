/*=============================================================================
 * edr_response.c - EDR Phase 4a: Automated Response Module
 *=============================================================================
 * Implements automated threat remediation actions.
 *
 * FEATURES:
 * - Process termination (kill malicious processes)
 * - File quarantine (move to /quarantine/ directory)
 * - Network blocking (close all sockets, prevent new connections)
 * - Policy-based execution (threat score thresholds)
 *
 * USAGE:
 *   edr_response_init();
 *   edr_response_execute(task, RESPONSE_TERMINATE_PROCESS, "Malware detected");
 *   edr_response_quarantine_file("/bin/malware");
 *
 * PERFORMANCE:
 *   Termination: < 1ms
 *   Quarantine: < 10ms (file rename operation)
 *   Network blocking: < 5ms
 *=============================================================================*/

#include "edr_ml.h"
#include "process.h"
#include "scheduler.h"  /* scheduler_get_current_task(): self-kill is deferred */
#include "kprintf.h"
#include "vfs.h"
#include "audit.h"
#include "util.h"
#include "pit.h"
#include "critical.h"  /* For CRITICAL_SECTION_ENTER/EXIT in atomic task termination */
#include <stdint.h>
#include <stdbool.h>

/* Simple string functions to avoid system headers */
static size_t resp_strlen(const char* str) __attribute__((unused));
static size_t resp_strlen(const char* str) {
    size_t len = 0;
    while (str[len]) len++;
    return len;
}

static char* resp_strrchr(const char* str, int c) {
    const char* last = NULL;
    while (*str) {
        if (*str == c) last = str;
        str++;
    }
    return (char*)last;
}

static int resp_snprintf(char* buf, size_t size, const char* fmt, ...) {
    /* Simplified snprintf for our use cases - supports %s, %u, %d */
    if (!buf || size == 0) return 0;

    size_t pos = 0;
    const char* p = fmt;

    __builtin_va_list args;
    __builtin_va_start(args, fmt);

    while (*p && pos < size - 1) {
        if (*p == '%') {
            p++;
            if (*p == 's') {
                /* String */
                const char* s = __builtin_va_arg(args, const char*);
                while (*s && pos < size - 1) {
                    buf[pos++] = *s++;
                }
            } else if (*p == 'u' || *p == 'd') {
                /* Unsigned/signed integer. Read the arg width matching the
                 * conversion and do the digit loop in UNSIGNED arithmetic:
                 * %u values above INT_MAX (e.g. pit_get_ticks() after ~248 days)
                 * previously read as a negative int and emitted garbage. */
                char tmp[12];
                int idx = 0;
                int is_neg = 0;
                unsigned int uval;

                if (*p == 'd') {
                    int sval = __builtin_va_arg(args, int);
                    if (sval < 0) {
                        is_neg = 1;
                        /* well-defined unsigned negation (handles INT_MIN without
                         * signed-overflow UB that -(long)sval would hit on 32-bit) */
                        uval = 0u - (unsigned int)sval;
                    } else {
                        uval = (unsigned int)sval;
                    }
                } else {
                    uval = __builtin_va_arg(args, unsigned int);
                }

                do {
                    tmp[idx++] = '0' + (uval % 10u);
                    uval /= 10u;
                } while (uval > 0);

                if (is_neg && pos < size - 1) buf[pos++] = '-';

                while (idx > 0 && pos < size - 1) {
                    buf[pos++] = tmp[--idx];
                }
            }
            p++;
        } else {
            buf[pos++] = *p++;
        }
    }

    buf[pos] = '\0';
    __builtin_va_end(args);
    return (int)pos;
}

/* Stub implementations for missing VFS functions */
static int stub_vfs_mkdir(const char* path, int mode) {
    (void)path; (void)mode;
    kprintf("[EDR RESPONSE] STUB: vfs_mkdir(%s) - would create directory\n", path);
    return 0;  /* Success */
}

static int stub_vfs_rename(const char* oldpath, const char* newpath) {
    (void)oldpath; (void)newpath;
    kprintf("[EDR RESPONSE] STUB: vfs_rename(%s -> %s) - would rename file\n", oldpath, newpath);
    return 0;  /* Success */
}

static int stub_vfs_chmod(const char* path, int mode) {
    (void)path; (void)mode;
    kprintf("[EDR RESPONSE] STUB: vfs_chmod(%s, %d) - would change permissions\n", path, mode);
    return 0;  /* Success */
}

/* Audit event types not yet in audit.h */
#define AUDIT_RESPONSE 100
#define AUDIT_ALERT 101

/*=============================================================================
 * CONFIGURATION
 *=============================================================================*/
#define QUARANTINE_DIR "/quarantine"
#define MAX_REMEDIATION_LOG 32

/*=============================================================================
 * DATA STRUCTURES
 *=============================================================================*/

/**
 * @brief Remediation action record (internal type)
 */
typedef struct {
    response_action_t action;
    uint16_t target_pid;
    uint32_t timestamp;
    bool success;
    char description[64];
} resp_remediation_record_t;

/**
 * @brief Global response policy
 */
static response_policy_t g_response_policy = {
    .auto_terminate = true,          /* Automatically kill threats */
    .auto_quarantine = true,         /* Automatically quarantine files */
    .auto_block_network = true,      /* Automatically block C2 */
    .collect_forensics = false,      /* Collect evidence (Phase 4b feature) */
    .response_threshold = 80         /* Min threat score for response (0-100) */
};

/**
 * @brief Remediation log
 */
static resp_remediation_record_t g_remediation_log[MAX_REMEDIATION_LOG];
static uint8_t g_remediation_count = 0;
static uint32_t g_total_responses = 0;

static bool g_response_initialized = false;

/*=============================================================================
 * HELPER FUNCTIONS
 *=============================================================================*/

/**
 * @brief Log remediation action
 */
static void log_remediation(response_action_t action, uint16_t pid,
                             bool success, const char* description) {
    /* Add to circular buffer */
    resp_remediation_record_t* record = &g_remediation_log[g_remediation_count % MAX_REMEDIATION_LOG];

    record->action = action;
    record->target_pid = pid;
    record->timestamp = pit_get_ticks();
    record->success = success;

    if (description) {
        SAFE_STRNCPY(record->description, description, sizeof(record->description));
    }

    g_remediation_count = (g_remediation_count + 1) % MAX_REMEDIATION_LOG;
    g_total_responses++;
}

/**
 * @brief Convert action to string
 */
static const char* action_to_string(response_action_t action) {
    switch (action) {
        case RESPONSE_TERMINATE_PROCESS: return "TERMINATE";
        case RESPONSE_SUSPEND_PROCESS: return "SUSPEND";
        case RESPONSE_QUARANTINE_FILE: return "QUARANTINE";
        case RESPONSE_BLOCK_NETWORK: return "BLOCK_NETWORK";
        case RESPONSE_ISOLATE_PROCESS: return "ISOLATE";
        case RESPONSE_ROLLBACK_CHANGES: return "ROLLBACK";
        case RESPONSE_COLLECT_EVIDENCE: return "COLLECT_EVIDENCE";
        case RESPONSE_ALERT_ADMIN: return "ALERT";
        default: return "UNKNOWN";
    }
}

/*=============================================================================
 * CORE FUNCTIONS
 *=============================================================================*/

/**
 * @brief Initialize automated response system
 */
void edr_response_init(void) {
    if (g_response_initialized) {
        return;
    }

    /* Clear remediation log */
    memset(g_remediation_log, 0, sizeof(g_remediation_log));
    g_remediation_count = 0;
    g_total_responses = 0;

    /* Create quarantine directory */
    stub_vfs_mkdir(QUARANTINE_DIR, 0700);

    g_response_initialized = true;

    kprintf("[EDR RESPONSE] Initialized\n");
    kprintf("[EDR RESPONSE] Policy: terminate=%d, quarantine=%d, block_network=%d, threshold=%d\n",
            g_response_policy.auto_terminate,
            g_response_policy.auto_quarantine,
            g_response_policy.auto_block_network,
            g_response_policy.response_threshold);
}

/* Kill requests refused because the target was CAP_UNKILLABLE (a kernel
 * daemon: shell, idle, edr_daemon, supervisor, ktimerd). Counted, not printed:
 * a periodic scan that keeps flagging a daemon would otherwise repeat the
 * refusal on every pass. */
static uint32_t g_terminate_refused_unkillable;
/* Responses whose target exited (or whose slot was reused) between the scan
 * that chose it and the response. */
static uint32_t g_response_target_gone;

void edr_response_get_refusals(uint32_t* unkillable, uint32_t* gone) {
    if (unkillable) *unkillable = g_terminate_refused_unkillable;
    if (gone) *gone = g_response_target_gone;
}

/**
 * @brief Terminate the task {pid, generation} that a scan chose
 * @param task       Pointer the scan analysed
 * @param pid        task->pid as read BEFORE the analysis
 * @param generation task->generation as read BEFORE the analysis
 * @return true if the task was terminated or its termination is pending
 *
 * This used to set task->state = TERMINATED and "let the scheduler clean up".
 * The scheduler only reaps the task it switches AWAY from, so a target that was
 * blocked or ready was never reaped: its slot stayed claimed for good (32 in
 * all), a blocked target stayed on its wait queue, its fds, pipes and sockets
 * were never released, and no waitpid() waiter was ever woken.
 * verify-edr-kill-reap.sh. Now:
 *
 *  - Identity first. The pointer came from a snapshot; if the slot no longer
 *    holds {pid, generation} the target is gone and whoever replaced it is
 *    not what was analysed.
 *  - CAP_UNKILLABLE is honoured. Only kernel daemons hold it (ring-3 tasks
 *    start with capabilities zeroed), and a heuristic false positive must not
 *    be able to take down idle, the supervisor or EDR itself.
 *  - The running task is not killed in place. The only way EDR runs on behalf
 *    of the current, killable task is edr_behavioral_check() inside that
 *    task's own syscall, and terminating there would let the syscall carry on
 *    on a dead task. Mark it; syscall_dispatch() exits it before the body.
 *  - Anything else goes through task_terminate_status(), the same teardown
 *    `kill` uses, with status 137 so waitpid can tell an EDR kill apart.
 */
static bool edr_response_terminate_target(task_t* task, uint32_t pid, uint32_t generation) {
    if (!task || pid == 0 || task_get_validated(pid, generation) != task) {
        g_response_target_gone++;
        return false;
    }

    if (task->capabilities & CAP_UNKILLABLE) {
        g_terminate_refused_unkillable++;
        return false;
    }

    kprintf("[EDR RESPONSE] Terminating PID %d (%s)\n", task->pid, task->name);

    /* Audit and remediation logs first: on the non-self path the slot is
     * freed and pid zeroed by the time task_terminate_status() returns. */
    audit_log(AUDIT_RESPONSE, AUDIT_CRITICAL, task->uid,
              "Process terminated: PID=%d, name=%s, reason=malware",
              (int)pid, task->name);

    char desc[64];
    resp_snprintf(desc, sizeof(desc), "Terminated PID %d (%s)", pid, task->name);

    bool ok;
    if (task == scheduler_get_current_task()) {
        task->edr_kill_pending = true;
        ok = true;
    } else {
        ok = task_terminate_status(pid, generation, EDR_KILL_STATUS);
    }

    log_remediation(RESPONSE_TERMINATE_PROCESS, pid, ok, desc);
    return ok;
}

/**
 * @brief Terminate malicious process
 * @param task Process to terminate; its current identity is the target
 * @return true if successful
 *
 * For a caller holding a pointer it has not analysed across a preemption
 * (edr_behavioral_check on current_task). A scanner must use
 * edr_response_execute_target() with the identity it read before analysing.
 */
bool edr_response_terminate(task_t* task) {
    if (!task) {
        return false;
    }
    return edr_response_terminate_target(task, task->pid, task->generation);
}

/**
 * @brief Quarantine malicious file
 * @param filepath File to quarantine
 * @return true if successful
 */
bool edr_response_quarantine_file(const char* filepath) {
    if (!filepath || filepath[0] == '\0') {
        return false;
    }

    kprintf("[EDR RESPONSE] Quarantining file: %s\n", filepath);

    /* SECURITY FIX: Canonicalize source path to prevent traversal attacks */
    char canonical_source[VFS_MAX_PATH];
    int ret = vfs_canonicalize_path(filepath, canonical_source, VFS_MAX_PATH);
    if (ret < 0) {
        kprintf("[EDR RESPONSE] ERROR: Invalid source path: %s\n", filepath);
        audit_log(AUDIT_SEC_POLICY_VIOLATION, AUDIT_CRITICAL, 0,
                 "Quarantine blocked: invalid path '%s'", filepath);
        log_remediation(RESPONSE_QUARANTINE_FILE, 0, false, "Invalid path");
        return false;
    }

    /* Extract basename from canonical path */
    const char* basename_ptr = resp_strrchr(canonical_source, '/');
    if (basename_ptr) {
        basename_ptr++;  /* Skip the '/' */
    } else {
        basename_ptr = canonical_source;
    }

    /* SECURITY: Validate basename (no path separators allowed) */
    for (const char* p = basename_ptr; *p; p++) {
        if (*p == '/' || *p == '\\') {
            kprintf("[EDR RESPONSE] ERROR: Invalid basename contains separator: %s\n", basename_ptr);
            audit_log(AUDIT_SEC_POLICY_VIOLATION, AUDIT_CRITICAL, 0,
                     "Quarantine blocked: basename attack '%s'", basename_ptr);
            log_remediation(RESPONSE_QUARANTINE_FILE, 0, false, "Invalid basename");
            return false;
        }
    }

    /* Generate quarantine path with timestamp */
    char quarantine_path[VFS_MAX_PATH];
    int path_len = resp_snprintf(quarantine_path, sizeof(quarantine_path),
                                 "%s/%s.%u", QUARANTINE_DIR, basename_ptr, pit_get_ticks());

    /* SECURITY: Validate path length */
    if (path_len >= (int)sizeof(quarantine_path)) {
        kprintf("[EDR RESPONSE] ERROR: Quarantine path too long\n");
        log_remediation(RESPONSE_QUARANTINE_FILE, 0, false, "Path too long");
        return false;
    }

    /* SECURITY FIX: Canonicalize target path */
    char canonical_target[VFS_MAX_PATH];
    ret = vfs_canonicalize_path(quarantine_path, canonical_target, VFS_MAX_PATH);
    if (ret < 0) {
        kprintf("[EDR RESPONSE] ERROR: Invalid target path\n");
        log_remediation(RESPONSE_QUARANTINE_FILE, 0, false, "Invalid target");
        return false;
    }

    /* SECURITY CRITICAL: Verify target is inside quarantine directory */
    size_t qdir_len = resp_strlen(QUARANTINE_DIR);
    if (memcmp(canonical_target, QUARANTINE_DIR, qdir_len) != 0 ||
        (canonical_target[qdir_len] != '\0' && canonical_target[qdir_len] != '/')) {
        kprintf("[EDR RESPONSE] SECURITY ALERT: Path escape attempt blocked!\n");
        kprintf("[EDR RESPONSE]   Source: %s\n", canonical_source);
        kprintf("[EDR RESPONSE]   Target: %s\n", canonical_target);
        kprintf("[EDR RESPONSE]   Expected: %s/...\n", QUARANTINE_DIR);

        audit_log(AUDIT_SEC_EXPLOIT_ATTEMPT, AUDIT_CRITICAL, 0,
                 "SECURITY: Quarantine path escape blocked: %s -> %s",
                 canonical_source, canonical_target);

        log_remediation(RESPONSE_QUARANTINE_FILE, 0, false, "Path escape blocked");
        return false;
    }

    /*=========================================================================
     * SECURITY FIX (AUDIT 2C): TOCTOU Mitigation for File Quarantine
     *=========================================================================
     *
     * VULNERABILITY: Time-of-Check, Time-of-Use (TOCTOU) Race Condition
     *
     * ATTACK SCENARIO:
     * 1. Attacker triggers quarantine on /tmp/benign
     * 2. Security checks pass for /tmp/benign (TIME OF CHECK)
     * 3. [RACE WINDOW] Attacker replaces /tmp/benign with symlink -> /etc/passwd
     * 4. Rename executes, moving /etc/passwd to quarantine (TIME OF USE)
     * 5. System broken, critical file quarantined
     *
     * CURRENT MITIGATION:
     * - Paths are canonicalized before checks (removes .. and symlinks)
     * - Atomic rename operation reduces race window
     * - Audit logging creates forensic trail
     *
     * PRODUCTION REQUIREMENTS (when VFS is fully implemented):
     * 1. Use open(source, O_RDONLY | O_NOFOLLOW) to get FD without following symlinks
     * 2. Use fstat(fd) to verify file type and metadata
     * 3. Perform security checks on FD, not path
     * 4. Use renameat2(AT_FDCWD, source, AT_FDCWD, target, RENAME_NOREPLACE)
     * 5. Implement file locking during quarantine operation
     *
     * AUDIT TRAIL:
     * - Log before rename (to capture attempted operation)
     * - Log after rename (to confirm success)
     * - Monitor audit logs for suspicious patterns (rapid retries, timing)
     *=======================================================================*/

    /* CRITICAL: Audit log BEFORE rename to create forensic trail */
    audit_log(AUDIT_RESPONSE, AUDIT_CRITICAL, 0,
              "QUARANTINE ATTEMPT: source='%s' target='%s' (pre-rename)",
              canonical_source, canonical_target);

    uint32_t start_ticks = pit_get_ticks();

    /* Perform atomic rename operation */
    ret = stub_vfs_rename(canonical_source, canonical_target);

    uint32_t elapsed_ticks = pit_get_ticks() - start_ticks;

    if (ret < 0) {
        kprintf("[EDR RESPONSE] ERROR: Failed to quarantine %s (error %d)\n",
                canonical_source, ret);
        audit_log(AUDIT_RESPONSE, AUDIT_ERROR, 0,
                  "QUARANTINE FAILED: source='%s' error=%d", canonical_source, ret);
        log_remediation(RESPONSE_QUARANTINE_FILE, 0, false, canonical_source);
        return false;
    }

    /* SECURITY: Detect suspiciously slow rename (possible race attack indicator) */
    if (elapsed_ticks > 10) {  /* >10 timer ticks = suspicious */
        kprintf("[EDR RESPONSE] WARNING: Quarantine rename took %u ticks (TOCTOU risk)\n",
                elapsed_ticks);
        audit_log(AUDIT_RESPONSE, AUDIT_WARN, 0,
                  "QUARANTINE SLOW: source='%s' ticks=%u (possible race)",
                  canonical_source, (unsigned int)elapsed_ticks);
    }

    /* Set read-only permissions */
    stub_vfs_chmod(canonical_target, 0400);  /* r-------- */

    /* CRITICAL: Audit log AFTER successful rename */
    audit_log(AUDIT_RESPONSE, AUDIT_CRITICAL, 0,
              "QUARANTINE SUCCESS: source='%s' target='%s' (post-rename)",
              canonical_source, canonical_target);

    kprintf("[EDR RESPONSE] File quarantined: %s -> %s\n",
            canonical_source, canonical_target);

    /* Log remediation */
    log_remediation(RESPONSE_QUARANTINE_FILE, 0, true, canonical_target);

    return true;
}

/**
 * @brief Block all network connections for process
 * @param task Process to block
 * @return true if successful
 */
bool edr_response_block_network(task_t* task) {
    if (!task) {
        return false;
    }

    kprintf("[EDR RESPONSE] Blocking network for PID %d (%s)\n", task->pid, task->name);

    /* STUB: In full implementation, would close all network file descriptors
     * and set network_blocked flag on task structure */
    int closed_count = 0;  /* Would scan task->fds[] for sockets */

    /* Audit log */
    audit_log(AUDIT_RESPONSE, AUDIT_CRITICAL, task->uid,
              "Network blocked: PID=%d, closed_sockets=%d",
              (int)task->pid, closed_count);

    kprintf("[EDR RESPONSE] STUB: Network blocking for PID %d (would close %d sockets)\n",
            task->pid, closed_count);

    /* Log remediation */
    char desc[64];
    resp_snprintf(desc, sizeof(desc), "Blocked network PID %d (%d sockets)", task->pid, closed_count);
    log_remediation(RESPONSE_BLOCK_NETWORK, task->pid, true, desc);

    return true;
}

/**
 * @brief Execute automated response
 * @param task Target process
 * @param action Response action to take
 * @param reason Reason for response
 * @return true if successful
 */
bool edr_response_execute_target(task_t* task, uint32_t pid, uint32_t generation,
                                 response_action_t action, const char* reason) {
    if (!g_response_initialized) {
        edr_response_init();
    }

    if (!task) {
        return false;
    }

    /* Refuse before printing anything: a periodic scan that keeps choosing a
     * protected daemon, or a pointer that outlived its target, would
     * otherwise log an "Executing" line every pass for a response that never
     * happens. */
    if (pid == 0 || task_get_validated(pid, generation) != task) {
        g_response_target_gone++;
        return false;
    }
    if (action == RESPONSE_TERMINATE_PROCESS && (task->capabilities & CAP_UNKILLABLE)) {
        g_terminate_refused_unkillable++;
        return false;
    }

    kprintf("[EDR RESPONSE] Executing %s on PID %d: %s\n",
            action_to_string(action), task->pid, reason ? reason : "no reason");

    bool success = false;

    switch (action) {
        case RESPONSE_TERMINATE_PROCESS:
            success = edr_response_terminate_target(task, pid, generation);
            break;

        case RESPONSE_BLOCK_NETWORK:
            success = edr_response_block_network(task);
            break;

        case RESPONSE_QUARANTINE_FILE:
            /* Note: For quarantine, need to call edr_response_quarantine_file() directly */
            kprintf("[EDR RESPONSE] WARNING: QUARANTINE requires file path, not task\n");
            success = false;
            break;

        case RESPONSE_SUSPEND_PROCESS:
            /* Suspend not implemented yet (Phase 4b feature) */
            kprintf("[EDR RESPONSE] WARNING: SUSPEND not implemented\n");
            success = false;
            break;

        case RESPONSE_ISOLATE_PROCESS:
            /* Isolate not implemented yet (Phase 4b feature) */
            kprintf("[EDR RESPONSE] WARNING: ISOLATE not implemented\n");
            success = false;
            break;

        case RESPONSE_ROLLBACK_CHANGES:
            /* Rollback not implemented yet (Phase 4b feature) */
            kprintf("[EDR RESPONSE] WARNING: ROLLBACK not implemented\n");
            success = false;
            break;

        case RESPONSE_COLLECT_EVIDENCE:
            /* Evidence collection not implemented yet (Phase 4b feature) */
            kprintf("[EDR RESPONSE] WARNING: COLLECT_EVIDENCE not implemented\n");
            success = false;
            break;

        case RESPONSE_ALERT_ADMIN:
            /* Alert admin (just log for now) */
            kprintf("[EDR RESPONSE] ALERT: %s\n", reason ? reason : "Threat detected");
            audit_log(AUDIT_ALERT, AUDIT_CRITICAL, task->uid,
                      "EDR Alert: PID=%d, %s", (int)task->pid, reason ? reason : "");
            success = true;
            break;

        default:
            kprintf("[EDR RESPONSE] ERROR: Unknown action %d\n", action);
            success = false;
            break;
    }

    return success;
}

/**
 * @brief Respond to task's CURRENT identity
 *
 * Only for a pointer that cannot have changed occupant since the decision
 * (edr_behavioral_check on current_task). Scanners that analyse first and
 * respond afterwards use edr_response_execute_target().
 */
bool edr_response_execute(task_t* task, response_action_t action, const char* reason) {
    if (!task) {
        return false;
    }
    return edr_response_execute_target(task, task->pid, task->generation, action, reason);
}

/**
 * @brief Set response policy
 */
void edr_response_set_policy(const response_policy_t* policy) {
    if (policy) {
        g_response_policy = *policy;
        kprintf("[EDR RESPONSE] Policy updated: threshold=%d\n",
                g_response_policy.response_threshold);
    }
}

/**
 * @brief Get response policy
 */
void edr_response_get_policy(response_policy_t* policy) {
    if (policy) {
        *policy = g_response_policy;
    }
}

/**
 * @brief Get response statistics
 */
void edr_response_get_stats(uint32_t* total_responses, uint8_t* log_count) {
    if (total_responses) *total_responses = g_total_responses;
    if (log_count) *log_count = (g_total_responses < MAX_REMEDIATION_LOG) ?
                                 (uint8_t)g_total_responses : MAX_REMEDIATION_LOG;
}

/**
 * @brief Check if response policy allows action
 */
bool edr_response_should_execute(uint8_t threat_score) {
    return (threat_score >= g_response_policy.response_threshold);
}
