/*=============================================================================
 * edr_behavioral.c - EDR Behavioral Detection Engine Implementation
 *=============================================================================*/
#include "edr_behavioral.h"
#include "process.h"
#include "syscall.h"
#include "kprintf.h"
#include "pit.h"  /* For time_get_ticks() */
#include "util.h"
#include "edr_ml.h"  /* Phase 4a: Automated Response */

/*=============================================================================
 * RARE SYSCALLS (potential ROP gadgets)
 *
 * These syscalls are rarely used in normal operation but common in exploits.
 * Detecting their usage in rapid succession may indicate ROP chain execution.
 *=============================================================================*/
static const uint32_t rare_syscalls[] = {
    SYS_SETUID, SYS_SETGID, SYS_SETEUID, SYS_SETEGID,
    /* Future: SYS_PTRACE, SYS_MODULE_LOAD, SYS_IOPL, SYS_REBOOT */
};
static const int rare_syscalls_count = sizeof(rare_syscalls) / sizeof(rare_syscalls[0]);

/*=============================================================================
 * INITIALIZATION
 *=============================================================================*/

void edr_behavioral_init(task_t* task) {
    if (!task) return;

    /* Clear history buffer */
    for (int i = 0; i < 32; i++) {
        task->edr_state.history[i].syscall_num = 0xFFFFFFFF;  // Invalid syscall
        task->edr_state.history[i].timestamp = 0;
        task->edr_state.history[i].arg0 = 0;
    }

    /* Initialize state */
    task->edr_state.history_head = 0;
    task->edr_state.history_count = 0;
    task->edr_state.anomaly_score = 0;
    task->edr_state.alert_count = 0;
    task->edr_state.flags = EDR_FLAG_DETECTION_ENABLED;  // Enable by default
    task->edr_state.last_signature = EDR_SIG_NONE;
    task->edr_state.last_alert_tick = 0;
}

/*=============================================================================
 * SYSCALL HISTORY MANAGEMENT
 *=============================================================================*/

void edr_record_syscall(task_t* task, uint32_t syscall_num, uint32_t timestamp, uint32_t arg0) {
    if (!task) return;

    /* Add to circular buffer */
    uint8_t head = task->edr_state.history_head;
    task->edr_state.history[head].syscall_num = syscall_num;
    task->edr_state.history[head].timestamp = timestamp;
    task->edr_state.history[head].arg0 = arg0;

    /* Advance head (wrap around) */
    task->edr_state.history_head = (head + 1) % 32;

    /* Update count (max 32) */
    if (task->edr_state.history_count < 32) {
        task->edr_state.history_count++;
    }
}

uint32_t edr_get_history_syscall(task_t* task, uint8_t offset) {
    if (!task || offset >= 32) return 0xFFFFFFFF;
    if (offset >= task->edr_state.history_count) return 0xFFFFFFFF;

    /* Calculate index (head - 1 - offset, with wrap-around) */
    int index = (int)task->edr_state.history_head - 1 - offset;
    if (index < 0) index += 32;

    return task->edr_state.history[index].syscall_num;
}

/*=============================================================================
 * RARE SYSCALL DETECTION
 *=============================================================================
 *
 * SECURITY FIX (AUDIT 4A): Constant-Time Lookup to Prevent Timing Side-Channel
 *
 * VULNERABILITY: Variable-Time Linear Scan with Early Return
 *
 * OLD APPROACH (VULNERABLE):
 *   for (i = 0; i < count; i++) {
 *       if (syscall_num == rare_syscalls[i]) return true;  // EARLY RETURN
 *   }
 *
 * TIMING SIDE-CHANNEL ATTACK:
 * 1. Attacker calls various syscalls and measures execution time
 * 2. Syscalls matching first array element return fastest
 * 3. Syscalls matching last element (or no match) return slowest
 * 4. Timing differences reveal detection list contents and order
 * 5. Attacker can evade detection by avoiding known-monitored syscalls
 *
 * EXPLOITATION SCENARIO:
 * - Attacker measures timing for all possible syscall numbers
 * - Creates timing profile showing "fast" vs "slow" syscalls
 * - Fast syscalls = monitored rare syscalls (high-value intel)
 * - Attacker crafts exploit avoiding monitored syscalls
 * - Result: Complete EDR behavioral detection bypass
 *
 * CONSTANT-TIME MITIGATION:
 * - Always scan entire array (no early return)
 * - Use bitwise accumulator instead of conditional branches
 * - Compiler optimizations disabled for this function (if needed)
 * - Execution time independent of input or match location
 *
 * PERFORMANCE IMPACT:
 * - Minimal: rare_syscalls_count = 4 elements
 * - Always 4 comparisons vs average 2.5 comparisons
 * - Security benefit >> negligible performance cost
 *===========================================================================*/

bool edr_is_rare_syscall(uint32_t syscall_num) {
    /* SECURITY: Constant-time lookup to prevent timing side-channel */
    uint32_t match = 0;

    /* Always scan entire array - no early return, no timing leak */
    for (int i = 0; i < rare_syscalls_count; i++) {
        /* Use bitwise OR to accumulate matches without branching */
        match |= (syscall_num == rare_syscalls[i]) ? 1 : 0;
    }

    /* Return result after ALL comparisons complete */
    return (match != 0);
}

/*=============================================================================
 * SIGNATURE DETECTION: ROP CHAIN
 *
 * ROP (Return-Oriented Programming) chains execute gadgets that often make
 * unusual syscall sequences. Detecting rapid changes in rare syscalls may
 * indicate ROP execution.
 *
 * INDICATORS:
 * - Multiple rare syscalls in short succession (< 5 ticks apart)
 * - Non-sequential syscall numbers (jumping around)
 * - Setuid/setgid in rapid succession
 *=============================================================================*/

bool edr_detect_rop_chain(task_t* task) {
    if (!task || task->edr_state.history_count < EDR_ROP_CHAIN_THRESHOLD) {
        return false;
    }

    /* Count rare syscalls in last 10 syscalls */
    int rare_count = 0;
    uint32_t first_timestamp = 0;
    uint32_t last_timestamp = 0;

    for (int i = 0; i < 10 && i < task->edr_state.history_count; i++) {
        int index = (int)task->edr_state.history_head - 1 - i;
        if (index < 0) index += 32;

        uint32_t syscall_num = task->edr_state.history[index].syscall_num;
        uint32_t timestamp = task->edr_state.history[index].timestamp;

        if (i == 0) last_timestamp = timestamp;
        first_timestamp = timestamp;

        if (edr_is_rare_syscall(syscall_num)) {
            rare_count++;
        }
    }

    /* ROP detected if: 5+ rare syscalls in < 10 ticks */
    if (rare_count >= EDR_ROP_CHAIN_THRESHOLD &&
        (last_timestamp - first_timestamp) < 10) {
        return true;
    }

    return false;
}

/*=============================================================================
 * SIGNATURE DETECTION: SHELLCODE EXECUTION
 *
 * Shellcode often follows this pattern:
 * 1. Network read (receive payload)
 * 2. Memory operations (write shellcode to executable memory)
 * 3. Exec (execute shell or command)
 *
 * FUTURE: Add SYS_EXEC when implemented
 *=============================================================================*/

bool edr_detect_shellcode(task_t* task, uint32_t syscall_num) {
    if (!task) return false;

    /* Check for exec after network activity */
    /* PLACEHOLDER: Add when SYS_EXEC is implemented */
    /* For now, just check for suspicious exec intent after network */
    (void)syscall_num;  // Suppress unused parameter warning

    /* Check if process has network activity flag set */
    if (task->edr_state.flags & EDR_FLAG_NETWORK_ACTIVITY) {
        /* Future: Check for exec syscall here */
        /* return true; */
    }

    return false;
}

/*=============================================================================
 * SIGNATURE DETECTION: PRIVILEGE ESCALATION
 *
 * Privilege escalation attacks attempt to gain higher privileges via:
 * - Setuid/setgid to root (uid=0)
 * - Setuid/setgid after exploit indicators (rare syscalls, anomalies)
 *
 * INDICATORS:
 * - Setuid/setgid to uid=0 or gid=0
 * - Setuid/setgid after anomaly score > threshold
 *=============================================================================*/

bool edr_detect_privilege_escalation(task_t* task, uint32_t syscall_num) {
    if (!task) return false;

    /* Check if current syscall is privilege-changing */
    if (syscall_num == SYS_SETUID || syscall_num == SYS_SETGID ||
        syscall_num == SYS_SETEUID || syscall_num == SYS_SETEGID) {

        /* If process already has high anomaly score, this is suspicious */
        if (task->edr_state.anomaly_score > 1000) {
            return true;
        }

        /* If process already attempted privilege changes, this is suspicious */
        if (task->edr_state.flags & EDR_FLAG_PRIVILEGE_CHANGE) {
            return true;
        }

        /* Mark that privilege change was attempted */
        task->edr_state.flags |= EDR_FLAG_PRIVILEGE_CHANGE;
    }

    return false;
}

/*=============================================================================
 * SIGNATURE DETECTION: DATA EXFILTRATION
 *
 * Data exfiltration via network:
 * 1. Large read from file/memory
 * 2. Network write (send data out)
 *
 * FUTURE: Implement when network syscalls are added
 *=============================================================================*/

bool edr_detect_data_exfiltration(task_t* task, uint32_t syscall_num) {
    if (!task) return false;

    /* PLACEHOLDER: Implement when network syscalls exist */
    (void)syscall_num;  // Suppress unused parameter warning
    return false;
}

/*=============================================================================
 * SIGNATURE DETECTION: SYSCALL FLOOD
 *
 * Syscall flooding (DoS attack):
 * - Too many syscalls in short time period
 * - Rapid syscall invocations (< 1 tick apart)
 *
 * THRESHOLD: 10+ syscalls in 10 ticks = suspicious
 *=============================================================================*/

bool edr_detect_syscall_flood(task_t* task) {
    if (!task || task->edr_state.history_count < EDR_RAPID_SYSCALL_THRESHOLD) {
        return false;
    }

    /* Look at the oldest and newest of the last EDR_RAPID_SYSCALL_THRESHOLD
     * syscalls. With the threshold == buffer size, this spans the whole
     * window. */
    int index_first = (int)task->edr_state.history_head - EDR_RAPID_SYSCALL_THRESHOLD;
    int index_last = (int)task->edr_state.history_head - 1;
    if (index_first < 0) index_first += EDR_SYSCALL_HISTORY_SIZE;
    if (index_last < 0) index_last += EDR_SYSCALL_HISTORY_SIZE;

    uint32_t first_tick = task->edr_state.history[index_first].timestamp;
    uint32_t last_tick = task->edr_state.history[index_last].timestamp;

    /* Flood = the full window of syscalls all landed in a sub-tick burst.
     * Finite programs exit before sustaining this; only a tight syscall loop
     * keeps the whole window packed this tightly. */
    if ((last_tick - first_tick) < EDR_RAPID_SYSCALL_WINDOW_TICKS) {
        return true;
    }

    return false;
}

/*=============================================================================
 * ALERT SYSTEM
 *=============================================================================*/

void edr_raise_alert(task_t* task, edr_severity_t severity, edr_signature_t signature, const char* message) {
    if (!task) return;

    /* Rate limiting: Don't spam alerts (max 1 per 100 ticks) */
    uint32_t current_tick = pit_get_ticks();
    if (current_tick - task->edr_state.last_alert_tick < 100) {
        return;  /* Too soon since last alert */
    }

    /* Update state */
    task->edr_state.last_alert_tick = current_tick;
    task->edr_state.last_signature = signature;
    task->edr_state.alert_count++;

    /* Log alert */
    kprintf("[EDR %s] PID %d: %s (signature=%s, score=%d, alerts=%d)\n",
            edr_severity_to_string(severity),
            task->pid,
            message,
            edr_signature_to_string(signature),
            task->edr_state.anomaly_score,
            task->edr_state.alert_count);

    /* FUTURE: Take action based on severity */
    /* CRITICAL: Kill process or block syscall */
    /* WARNING: Log and monitor */
    /* INFO: Log only */
}

/*=============================================================================
 * MAIN DETECTION ENTRY POINT
 *
 * Called from syscall_dispatch() for every syscall.
 * Returns true if syscall should be allowed, false if blocked.
 *=============================================================================*/

bool edr_behavioral_check(task_t* task, uint32_t syscall_num, uint32_t arg0) {
    if (!task) return true;

    /* Check if detection is enabled */
    if (!(task->edr_state.flags & EDR_FLAG_DETECTION_ENABLED)) {
        return true;  /* Detection disabled, allow syscall */
    }

    /* Record syscall in history */
    uint32_t current_tick = pit_get_ticks();
    edr_record_syscall(task, syscall_num, current_tick, arg0);

    /* Track behavioral flags */
    /* FUTURE: Set EDR_FLAG_NETWORK_ACTIVITY when network syscalls added */
    if (syscall_num == SYS_SETUID || syscall_num == SYS_SETGID ||
        syscall_num == SYS_SETEUID || syscall_num == SYS_SETEGID) {
        task->edr_state.flags |= EDR_FLAG_PRIVILEGE_CHANGE;
    }

    /* Run detection signatures */
    bool allow_syscall = true;

    /* 1. ROP Chain Detection */
    if (edr_detect_rop_chain(task)) {
        edr_raise_alert(task, EDR_SEVERITY_CRITICAL, EDR_SIG_ROP_CHAIN,
                       "Potential ROP chain detected (rapid rare syscalls)");
        task->edr_state.anomaly_score += 500;  /* High score for ROP */

        /* Phase 4a: Automated Response - Terminate process */
        if (edr_response_should_execute(95)) {  /* 95% threat score */
            edr_response_execute(task, RESPONSE_TERMINATE_PROCESS, "ROP chain detected");
        }
    }

    /* 2. Shellcode Execution Detection */
    if (edr_detect_shellcode(task, syscall_num)) {
        edr_raise_alert(task, EDR_SEVERITY_CRITICAL, EDR_SIG_SHELLCODE_EXEC,
                       "Potential shellcode execution (exec after network read)");
        task->edr_state.anomaly_score += 1000;  /* Very high score */
        allow_syscall = false;  /* Block this syscall */

        /* Phase 4a: Automated Response - Terminate process immediately */
        if (edr_response_should_execute(100)) {  /* 100% threat score - critical */
            edr_response_execute(task, RESPONSE_TERMINATE_PROCESS, "Shellcode execution detected");
        }
    }

    /* 3. Privilege Escalation Detection */
    if (edr_detect_privilege_escalation(task, syscall_num)) {
        edr_raise_alert(task, EDR_SEVERITY_CRITICAL, EDR_SIG_PRIVILEGE_ESCALATION,
                       "Suspicious privilege escalation attempt");
        task->edr_state.anomaly_score += 750;

        /* Phase 4a: Automated Response - Terminate process */
        if (edr_response_should_execute(90)) {  /* 90% threat score */
            edr_response_execute(task, RESPONSE_TERMINATE_PROCESS, "Privilege escalation attempt");
        }
    }

    /* 4. Data Exfiltration Detection */
    if (edr_detect_data_exfiltration(task, syscall_num)) {
        edr_raise_alert(task, EDR_SEVERITY_WARNING, EDR_SIG_DATA_EXFILTRATION,
                       "Potential data exfiltration (large read -> network write)");
        task->edr_state.anomaly_score += 300;
    }

    /* 5. Syscall Flood Detection */
    if (edr_detect_syscall_flood(task)) {
        edr_raise_alert(task, EDR_SEVERITY_WARNING, EDR_SIG_SYSCALL_FLOOD,
                       "Syscall flooding detected (DoS attempt?)");
        task->edr_state.anomaly_score += 200;
    }

    /* 6. Rare Syscall Detection (general anomaly) */
    if (edr_is_rare_syscall(syscall_num)) {
        task->edr_state.anomaly_score += 10;  /* Small score increase */
        if (task->edr_state.anomaly_score > 500) {
            edr_raise_alert(task, EDR_SEVERITY_WARNING, EDR_SIG_ANOMALY,
                           "Anomaly score threshold exceeded (unusual behavior)");
        }
    }

    /*=========================================================================
     * SECURITY FIX (AUDIT 3B): Time-Based Anomaly Score Decay
     *=========================================================================
     *
     * VULNERABILITY: Global Tick-Based Decay Evasion
     *
     * OLD APPROACH (VULNERABLE):
     *   if (current_tick % 1000 == 0) { decay(); }
     *
     * ATTACK SCENARIO:
     * 1. Attacker monitors system tick via timing attacks
     * 2. Waits for (current_tick % 1000 == 0) decay event
     * 3. Immediately performs malicious syscalls
     * 4. Score accumulates, but next decay is 1000 ticks away
     * 5. Malicious activity completes before threshold reached
     *
     * NEW APPROACH (SECURE):
     * - Per-process time tracking (not global tick modulo)
     * - Decay based on elapsed time since last decay
     * - Continuous decay (every 100 ticks) instead of periodic bursts
     * - Proportional decay based on actual elapsed time
     *
     * BENEFITS:
     * - No predictable decay windows for attackers to exploit
     * - Fair decay for all processes regardless of scheduling
     * - More gradual, natural decay curve
     * - Resistant to timing-based evasion
     *=======================================================================*/

    /* Decay anomaly score continuously (every 100 ticks) */
    if (task->edr_state.anomaly_score > 0) {
        uint32_t ticks_since_decay = current_tick - task->edr_state.last_decay_tick;

        /* Decay every 100 ticks (not 1000) for more frequent, gradual decay */
        if (ticks_since_decay >= 100) {
            /* Calculate number of decay periods elapsed */
            uint32_t decay_periods = ticks_since_decay / 100;

            /* Apply proportional decay: 5% per 100 ticks (was 10% per 1000) */
            for (uint32_t i = 0; i < decay_periods && task->edr_state.anomaly_score > 0; i++) {
                task->edr_state.anomaly_score = (task->edr_state.anomaly_score * 95) / 100;
            }

            /* Update last decay timestamp */
            task->edr_state.last_decay_tick = current_tick;

            /* SECURITY: Log significant decay events for forensic analysis */
            if (decay_periods > 10) {  /* More than 1000 ticks elapsed */
                kprintf("[EDR BEHAVIORAL] PID %u: Large decay gap (%u periods, %u ticks)\n",
                        task->pid, decay_periods, ticks_since_decay);
            }
        }
    }

    return allow_syscall;
}

/*=============================================================================
 * HELPER FUNCTIONS
 *=============================================================================*/

void edr_behavioral_set_enabled(task_t* task, bool enabled) {
    if (!task) return;
    if (enabled) {
        task->edr_state.flags |= EDR_FLAG_DETECTION_ENABLED;
    } else {
        task->edr_state.flags &= ~EDR_FLAG_DETECTION_ENABLED;
    }
}

const char* edr_severity_to_string(edr_severity_t severity) {
    switch (severity) {
        case EDR_SEVERITY_INFO: return "INFO";
        case EDR_SEVERITY_WARNING: return "WARNING";
        case EDR_SEVERITY_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

const char* edr_signature_to_string(edr_signature_t signature) {
    switch (signature) {
        case EDR_SIG_NONE: return "NONE";
        case EDR_SIG_ROP_CHAIN: return "ROP_CHAIN";
        case EDR_SIG_SHELLCODE_EXEC: return "SHELLCODE_EXEC";
        case EDR_SIG_PRIVILEGE_ESCALATION: return "PRIVILEGE_ESCALATION";
        case EDR_SIG_DATA_EXFILTRATION: return "DATA_EXFILTRATION";
        case EDR_SIG_FILE_TAMPERING: return "FILE_TAMPERING";
        case EDR_SIG_SYSCALL_FLOOD: return "SYSCALL_FLOOD";
        case EDR_SIG_ANOMALY: return "ANOMALY";
        default: return "UNKNOWN";
    }
}
