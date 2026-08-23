#ifndef SUPERVISOR_H
#define SUPERVISOR_H

#include <stdint.h>
#include <stdbool.h>
#include "process.h"   /* priority_t */

/*=============================================================================
 * SYSTEM TASK SUPERVISOR (doc/NETDAEMON_DESIGN.md item 4, PR D2)
 *
 * Observes registered system tasks and re-creates them when they die.
 *
 * WHY THIS EXISTS AT ALL
 *
 * Nothing in this kernel has ever had to notice a system task dying. A sweep
 * for respawn/restart/watchdog before this file was written returned nothing,
 * and task_knetd() is a while(1) with no exit path. That was survivable while
 * the RX parser ran in ring 0 as an unkillable-in-practice loop; it stops being
 * survivable once the parser moves to ring 3 (PR D1), where the whole premise is
 * that the parser CAN die. A ring-3 parser with no restart turns every parser
 * crash into a permanent loss of networking -- strictly worse than the
 * monolithic arrangement it replaces.
 *
 * Built and proven against knetd BEFORE the ring-3 move, deliberately: a
 * deliberately-killed knetd is a complete test case with no ring-3 code
 * involved, so D1 lands into a kernel that already survives the death of the
 * task it is about to make killable.
 *
 * WHY {pid, generation} AND NOT task_t*
 *
 * task_terminate() fully recycles the slot on death: task_free_resources(),
 * pid = 0, task_free_slot_for_task(). A retained task_t* would alias whatever
 * task lands in that slot next, and a bare PID has the same reuse hazard. This
 * is the exact problem process.h already documents for parent_pid /
 * parent_generation, so the supervisor uses the same value-pair idiom and
 * task_get_validated() rather than inventing a second scheme.
 *
 * RESTART STORMS ARE THE DESIGN PROBLEM, NOT THE RESTART ITSELF
 *
 * Restarting is easy. The hazard is a task that dies on a specific
 * attacker-chosen input: it restarts, re-reads the same input, and dies again,
 * forever, at whatever rate the attacker chooses. So restarts are rate limited
 * (SUPERVISOR_MAX_RESTARTS within SUPERVISOR_WINDOW_MS) and the give-up state is
 * TERMINAL and VISIBLE. A silently dead daemon is precisely the failure that
 * NETWORK_ISOLATION.md item 1's "did it run" flag was reverted for masking.
 *===========================================================================*/

/*
 * Capacity. Was 4 when knetd was the only watched task; now 3 are watched
 * (ktimerd, knetd, edr_daemon) and the header must leave room to add one
 * without a silent "table full" -- supervisor_watch() prints and returns false
 * in that case, which is visible in the boot log but easy to scroll past.
 */
#define SUPERVISOR_MAX_TASKS      8

/*
 * Restart budget. Deliberately small: these are system tasks that should never
 * die at all, so more than a handful of deaths in a short window is a repeating
 * fault, not bad luck, and continuing to restart only burns CPU while hiding it.
 */
#define SUPERVISOR_MAX_RESTARTS   5
#define SUPERVISOR_WINDOW_MS      10000

typedef enum {
    SUPERVISOR_SLOT_FREE = 0,
    SUPERVISOR_SLOT_WATCHING,   /* task is alive, or is about to be restarted */
    SUPERVISOR_SLOT_GAVE_UP     /* terminal: budget exhausted, will not restart */
} supervisor_slot_state_t;

typedef struct {
    supervisor_slot_state_t state;
    const char* name;
    void (*entry)(void);
    uint32_t pid;
    uint32_t generation;
    /*
     * Priority to restore on restart. task_create_kernel() always assigns
     * PRIORITY_NORMAL, so without this a restarted ktimerd or edr_daemon comes
     * back DEMOTED from PRIORITY_HIGH -- it runs, every status surface reports
     * a healthy restart, and the only symptom is worse latency under load.
     * knetd never set a priority, so this was invisible while it was the only
     * watched task.
     */
    priority_t priority;
    uint32_t restarts;           /* total, for the whole uptime */
    uint32_t restarts_in_window;
    uint32_t window_start_ms;
} supervisor_entry_t;

void supervisor_init(void);

/*
 * Register an already-created kernel task. Called after task_create_kernel(),
 * with the pid it returned; the generation is read from the live task so a
 * restart can distinguish "still the task I registered" from "slot reused".
 * Returns false if the table is full or the pid is not live.
 */
bool supervisor_watch(const char* name, void (*entry)(void), uint32_t pid,
                      priority_t priority);

/*
 * One supervision pass: check every watched task and restart the dead ones.
 * Called from the supervisor task. Safe to call when nothing has died (it is a
 * table walk plus a task_get_validated per entry).
 */
void supervisor_run_once(void);

/* The supervisor task itself. */
void task_supervisor(void);

/*
 * Accounting for `ps`/`ifconfig`-style reporting and for the harness. Counters
 * rather than prints: a restart is an event a remote host can drive once the
 * parser is in ring 3, and CLAUDE.md forbids per-event kprintf on paths that
 * reach. (The restart itself DOES print -- it is rare by construction and a
 * silent restart is unreportable. The give-up print is the important one.)
 */
void supervisor_get_stats(uint32_t* watched, uint32_t* total_restarts,
                          uint32_t* gave_up);

#endif /* SUPERVISOR_H */
