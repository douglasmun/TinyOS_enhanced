/*=============================================================================
 * edr_daemon.c - EDR Background Daemon Process
 *=============================================================================
 * A dedicated background process that actively monitors the system for threats.
 *
 * FEATURES:
 * - Continuous process scanning (every 5 seconds)
 * - Hash-based malware detection using Threat Intelligence database
 * - Behavioral anomaly monitoring
 * - Automated threat response coordination
 * - System health reporting
 *
 * DESIGN:
 * - Runs as privileged kernel task (Ring 0)
 * - High priority (PRIORITY_HIGH) for responsive threat detection
 * - Non-blocking scanning using round-robin algorithm
 * - Minimal CPU usage (~2% in idle, ~5% during scan)
 *
 * USAGE:
 *   The daemon is automatically started by kernel_main() during boot.
 *   User can query status via future shell command: "edr status"
 *=============================================================================*/

#include "process.h"
#include "scheduler.h"
#include "kprintf.h"
#include "pit.h"
#include "edr_ml.h"
#include "edr_behavioral.h"
#include "edr_advanced.h"
#include "vfs.h"  /* For CAP_UNKILLABLE */
#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * CONFIGURATION
 *=============================================================================*/
#define EDR_SCAN_INTERVAL_TICKS  500   /* Scan every 5 seconds (100 ticks = 1s) */
#define EDR_STATS_REPORT_TICKS   6000  /* Report stats every 60 seconds */

/*=============================================================================
 * DAEMON STATE
 *=============================================================================*/
static struct {
    uint32_t scans_performed;       /* Total scans completed */
    uint32_t threats_detected;      /* Threats found */
    uint32_t processes_scanned;     /* Total processes scanned */
    uint32_t responses_executed;    /* Automated responses triggered */
    uint32_t last_scan_tick;        /* Timestamp of last scan */
    uint32_t last_scan_duration;    /* Ticks taken by the most recent scan */
    uint32_t daemon_start_tick;     /* Daemon start time */
    bool     daemon_active;         /* Daemon running flag */
} g_edr_daemon_state;

/*=============================================================================
 * HELPER FUNCTIONS
 *=============================================================================*/

/**
 * @brief Calculate simple hash of process name for demonstration
 * @note In real implementation, this would hash the process executable
 */
static uint32_t calculate_process_hash_simple(const char* name) __attribute__((unused));
static uint32_t calculate_process_hash_simple(const char* name) {
    uint32_t hash = 0;
    for (int i = 0; name[i] != '\0'; i++) {
        hash = hash * 31 + (uint32_t)name[i];
    }
    return hash;
}

/**
 * @brief Check if process is suspicious based on multiple criteria
 */
static bool is_process_suspicious(task_t* task) {
    if (!task) return false;

    /* 1. Check behavioral anomaly score */
    if (task->edr_state.anomaly_score > 300) {
        kprintf("[EDR DAEMON] PID %d (%s): High anomaly score %d\n",
                task->pid, task->name, task->edr_state.anomaly_score);
        return true;
    }

    /* 2. Check if process has raised alerts */
    if (task->edr_state.alert_count > 0) {
        kprintf("[EDR DAEMON] PID %d (%s): Has %d alerts\n",
                task->pid, task->name, task->edr_state.alert_count);
        return true;
    }

    /* 3. Check for privilege escalation attempts */
    if (task->edr_state.flags & EDR_FLAG_PRIVILEGE_CHANGE) {
        if (task->uid == 0 || task->euid == 0) {
            kprintf("[EDR DAEMON] PID %d (%s): Privilege escalation to root\n",
                    task->pid, task->name);
            return true;
        }
    }

    /* 4. In real implementation: Check process hash against TI database */
    /* For now, we demonstrate with name-based heuristics */
    if (task->name[0] == 'm' && task->name[1] == 'a' && task->name[2] == 'l') {
        /* Processes starting with "mal" are suspicious (e.g., "malware") */
        kprintf("[EDR DAEMON] PID %d (%s): Suspicious name pattern\n",
                task->pid, task->name);
        return true;
    }

    return false;
}

/**
 * @brief Scan a single process for threats
 */
static void scan_process(task_t* task) {
    if (!task) return;
    if (task->state == TASK_STATE_TERMINATED || task->state == TASK_STATE_ZOMBIE) {
        return;  /* Skip terminated processes */
    }

    g_edr_daemon_state.processes_scanned++;

    /* Check if process is suspicious */
    if (is_process_suspicious(task)) {
        g_edr_daemon_state.threats_detected++;

        kprintf("[EDR DAEMON] THREAT DETECTED: PID %d (%s), anomaly=%d, alerts=%d\n",
                task->pid, task->name,
                task->edr_state.anomaly_score,
                task->edr_state.alert_count);

        /* Calculate threat score based on multiple factors */
        uint8_t threat_score = 0;

        /* Anomaly score contributes 0-50 points */
        if (task->edr_state.anomaly_score > 1000) {
            threat_score += 50;
        } else {
            threat_score += (uint8_t)((task->edr_state.anomaly_score * 50) / 1000);
        }

        /* Alert count contributes 0-30 points */
        if (task->edr_state.alert_count > 5) {
            threat_score += 30;
        } else {
            threat_score += task->edr_state.alert_count * 6;
        }

        /* Privilege escalation adds 20 points */
        if (task->edr_state.flags & EDR_FLAG_PRIVILEGE_CHANGE) {
            threat_score += 20;
        }

        kprintf("[EDR DAEMON] Threat score: %d/100\n", threat_score);

        /* Execute automated response if score exceeds threshold */
        if (edr_response_should_execute(threat_score)) {
            kprintf("[EDR DAEMON] Executing automated response (threshold met)\n");

            /* Choose response based on threat level */
            if (threat_score >= 90) {
                /* Critical threat - terminate immediately */
                edr_response_execute(task, RESPONSE_TERMINATE_PROCESS,
                                    "Critical threat detected by EDR daemon");
                g_edr_daemon_state.responses_executed++;
            } else if (threat_score >= 70) {
                /* High threat - block network and alert */
                edr_response_execute(task, RESPONSE_BLOCK_NETWORK,
                                    "High threat detected by EDR daemon");
                edr_response_execute(task, RESPONSE_ALERT_ADMIN,
                                    "Suspicious process activity");
                g_edr_daemon_state.responses_executed += 2;
            } else {
                /* Medium threat - alert only */
                edr_response_execute(task, RESPONSE_ALERT_ADMIN,
                                    "Potentially suspicious process");
                g_edr_daemon_state.responses_executed++;
            }
        }
    }
}

/**
 * @brief Perform system-wide threat scan
 */
/*
 * The scan runs every EDR_SCAN_INTERVAL_TICKS (5 s) and is SILENT unless it
 * finds something. It used to print three unconditional lines per scan
 * ("Starting threat scan", "Scanning N active processes", "Scan complete"),
 * which is 36 lines a minute on an idle system -- 51 of the 277 lines in a
 * measured boot log, 18%% of all serial output, describing a scan that found
 * nothing every time.
 *
 * That matters beyond tidiness: with the shell at ring 3 the kernel console
 * and the user's own output are the same serial stream (CLAUDE.md), so a
 * periodic three-line burst buries whatever the user just typed. It is the
 * same rule the RX path follows -- count, do not print -- and the counters
 * already exist: scans_performed and processes_scanned are reported by the
 * 60-second summary in report_statistics() and by `secstatus`.
 *
 * What still prints is the THREAT path in scan_process(): a detection, its
 * score, and any automated response. Those are rare by construction and are
 * the only reason to watch this daemon's output at all.
 */
static void perform_threat_scan(void) {
    uint32_t scan_start_tick = pit_get_ticks();

    /* Get all active tasks */
    task_t* task_array[MAX_TASKS];
    int task_count = task_get_all(task_array, MAX_TASKS);

    /* Scan each process */
    for (int i = 0; i < task_count; i++) {
        scan_process(task_array[i]);
    }

    /* Retained rather than printed: the 60-second summary reports it, so the
     * duration is still observable without a line per scan. */
    g_edr_daemon_state.last_scan_duration = pit_get_ticks() - scan_start_tick;
    g_edr_daemon_state.scans_performed++;
    g_edr_daemon_state.last_scan_tick = pit_get_ticks();

}

/**
 * @brief Report daemon statistics
 */
static void report_statistics(void) {
    uint32_t uptime = pit_get_ticks() - g_edr_daemon_state.daemon_start_tick;
    uint32_t uptime_seconds = uptime / 100;  /* 100 ticks = 1 second */

    uint32_t ti_checks, ti_matches;
    uint16_t hash_count, ip_count;
    edr_ti_get_stats(&ti_checks, &ti_matches, &hash_count, &ip_count);

    uint32_t total_responses;
    uint8_t log_count;
    edr_response_get_stats(&total_responses, &log_count);

    /* Print the full block only when something a defender would act on has
     * changed since the last report; otherwise emit one line, and nothing at
     * all if even that is unchanged.
     *
     * The old behaviour was exactly inverted: ten lines every 60 seconds
     * forever, and on an idle system every one of them read zero. That is the
     * status-surface failure in reverse -- a surface so loud when nothing is
     * happening that the report which finally carries a nonzero threat count
     * looks identical to the 60 that preceded it. Scans/processes are progress,
     * not findings, so they do NOT force the block; threats, responses and TI
     * matches do, because those are the counters that mean something happened.
     *
     * Liveness is still observable: the one-line form prints whenever the scan
     * counter moves, so a wedged daemon goes silent rather than continuing to
     * print a reassuring block of zeroes. */
    static uint32_t last_threats = 0;
    static uint32_t last_responses = 0;
    static uint32_t last_ti_matches = 0;
    static uint32_t last_scans = 0;
    static bool reported_once = false;

    bool finding_changed = (g_edr_daemon_state.threats_detected != last_threats) ||
                           (g_edr_daemon_state.responses_executed != last_responses) ||
                           (ti_matches != last_ti_matches);
    bool progress_changed = (g_edr_daemon_state.scans_performed != last_scans);

    last_threats = g_edr_daemon_state.threats_detected;
    last_responses = g_edr_daemon_state.responses_executed;
    last_ti_matches = ti_matches;
    last_scans = g_edr_daemon_state.scans_performed;

    /* The first report always prints in full: it is the daemon's "I am here and
     * these are my baselines" statement, and suppressing it would make an EDR
     * that never started indistinguishable from one running cleanly. */
    if (finding_changed || !reported_once) {
        reported_once = true;
        kprintf("\n[EDR DAEMON] ========== STATUS REPORT ==========\n");
        kprintf("[EDR DAEMON] Uptime: %d seconds\n", uptime_seconds);
        kprintf("[EDR DAEMON] Scans performed: %d (last took %u ticks)\n",
                g_edr_daemon_state.scans_performed,
                g_edr_daemon_state.last_scan_duration);
        kprintf("[EDR DAEMON] Processes scanned: %d\n", g_edr_daemon_state.processes_scanned);
        kprintf("[EDR DAEMON] Threats detected: %d\n", g_edr_daemon_state.threats_detected);
        kprintf("[EDR DAEMON] Responses executed: %d\n", g_edr_daemon_state.responses_executed);
        kprintf("[EDR DAEMON] TI Database: %d hashes, %d IPs, %d checks, %d matches\n",
                hash_count, ip_count, ti_checks, ti_matches);
        kprintf("[EDR DAEMON] Automated Responses: %d total, %d logged\n",
                total_responses, log_count);
        kprintf("[EDR DAEMON] ===================================\n\n");
    } else if (progress_changed) {
        kprintf("[EDR DAEMON] %ds: %d scans, %d procs, %d threats\n",
                uptime_seconds,
                g_edr_daemon_state.scans_performed,
                g_edr_daemon_state.processes_scanned,
                g_edr_daemon_state.threats_detected);
    }
}

/**
 * @brief Main EDR daemon loop
 */
/*
 * NOT static: the supervisor restarts a dead task by calling its entry point,
 * so it needs a void(*)(void) it can store. Exposed via edr_ml.h alongside
 * edr_daemon_start() rather than being called directly by anyone else --
 * kernel.c still starts the daemon through edr_daemon_start().
 */
void edr_daemon_main(void) {
    task_t* self = task_current();
    kprintf("[EDR DAEMON] Starting EDR background daemon (PID %d)\n", self->pid);

    /* Redundant today and kept for intent: task_create_kernel() already grants
     * CAP_ALL (0xFFFFFFFF), which includes CAP_UNKILLABLE, so this OR changes
     * nothing. Deliberately NOT announced -- a log line saying protection was
     * "enabled" here would credit this statement for a property the task
     * already had, which is how a no-op reads as a security step. */
    self->capabilities |= CAP_UNKILLABLE;

    /* Initialize daemon state */
    g_edr_daemon_state.scans_performed = 0;
    g_edr_daemon_state.threats_detected = 0;
    g_edr_daemon_state.processes_scanned = 0;
    g_edr_daemon_state.responses_executed = 0;
    g_edr_daemon_state.last_scan_tick = 0;
    g_edr_daemon_state.last_scan_duration = 0;
    g_edr_daemon_state.daemon_start_tick = pit_get_ticks();
    g_edr_daemon_state.daemon_active = true;

    kprintf("[EDR DAEMON] Configuration: scan_interval=%d ticks (%d seconds)\n",
            EDR_SCAN_INTERVAL_TICKS, EDR_SCAN_INTERVAL_TICKS / 100);

    uint32_t last_report_tick = pit_get_ticks();

    /* Main daemon loop */
    while (g_edr_daemon_state.daemon_active) {
        uint32_t current_tick = pit_get_ticks();

        /* Perform periodic threat scan */
        if (current_tick - g_edr_daemon_state.last_scan_tick >= EDR_SCAN_INTERVAL_TICKS) {
            perform_threat_scan();
        }

        /* Report statistics periodically */
        if (current_tick - last_report_tick >= EDR_STATS_REPORT_TICKS) {
            report_statistics();
            last_report_tick = current_tick;
        }

        /* Sleep to reduce CPU usage */
        task_sleep(100);  /* Sleep for 1 second */
    }

    kprintf("[EDR DAEMON] Shutting down\n");
}

/**
 * @brief Start the EDR daemon process
 *
 * Returns the daemon's pid, or -1 on failure. It MUST return it: PIDs are
 * crypto-random in the range 100-65535 (process.c), so a caller cannot derive
 * this from creation order. kernel.c used to guess `pid_edr = 3` and its
 * task_get(3) therefore returned NULL on every boot that has ever run.
 */
int edr_daemon_start(void) {
    kprintf("[EDR DAEMON] Initializing EDR daemon...\n");

    /* Create EDR daemon as high-priority kernel task */
    int daemon_pid = task_create_kernel(edr_daemon_main, "edr_daemon");

    if (daemon_pid < 0) {
        kprintf("[EDR DAEMON] ERROR: Failed to create daemon process\n");
        return -1;
    }

    /* Get daemon task and set high priority */
    task_t* daemon_task = task_get((uint32_t)daemon_pid);
    if (daemon_task) {
        task_set_priority(daemon_task, PRIORITY_HIGH);
        kprintf("[EDR DAEMON] Created daemon process PID %d with HIGH priority\n", daemon_pid);
    }

    kprintf("[EDR DAEMON] EDR daemon started successfully\n");
    return daemon_pid;
}

/**
 * @brief Stop the EDR daemon process
 */
void edr_daemon_stop(void) {
    g_edr_daemon_state.daemon_active = false;
    kprintf("[EDR DAEMON] Daemon shutdown requested\n");
}

/**
 * @brief Get daemon statistics (for shell commands)
 */
void edr_daemon_get_stats(uint32_t* scans, uint32_t* threats,
                          uint32_t* processes, uint32_t* responses) {
    if (scans) *scans = g_edr_daemon_state.scans_performed;
    if (threats) *threats = g_edr_daemon_state.threats_detected;
    if (processes) *processes = g_edr_daemon_state.processes_scanned;
    if (responses) *responses = g_edr_daemon_state.responses_executed;
}
