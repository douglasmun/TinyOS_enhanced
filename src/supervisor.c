#include "supervisor.h"
#include "process.h"
#include "scheduler.h"
#include "kprintf.h"
#include "kernel.h"    /* get_timer_ticks() */
#include "util.h"      /* memset */

/*=============================================================================
 * SYSTEM TASK SUPERVISOR — see supervisor.h for the design rationale.
 *===========================================================================*/

static supervisor_entry_t supervisor_table[SUPERVISOR_MAX_TASKS];
static uint32_t supervisor_total_restarts = 0;

/*
 * Same conversion tcp_get_time_ms() uses (100 Hz timer). Read through a helper
 * so the window arithmetic below has one definition of "now" rather than two.
 */
static uint32_t supervisor_now_ms(void) {
    return get_timer_ticks() * 10;
}

void supervisor_init(void) {
    memset(supervisor_table, 0, sizeof(supervisor_table));
    supervisor_total_restarts = 0;
}

bool supervisor_watch(const char* name, void (*entry)(void), uint32_t pid) {
    if (!name || !entry || pid == 0) {
        return false;
    }

    /* Read the generation from the live task. Registering a pid that is not
     * live is a caller bug (task_create_kernel failed and was not checked), and
     * silently watching a dead slot would mean the first supervision pass
     * "restarts" a task that never started. */
    task_t* task = task_get(pid);
    if (!task) {
        kprintf("[SUPERVISOR] refusing to watch '%s': PID %u is not live\n",
                name, pid);
        return false;
    }

    for (int i = 0; i < SUPERVISOR_MAX_TASKS; i++) {
        supervisor_entry_t* e = &supervisor_table[i];
        if (e->state != SUPERVISOR_SLOT_FREE) continue;

        e->state = SUPERVISOR_SLOT_WATCHING;
        e->name = name;
        e->entry = entry;
        e->pid = pid;
        e->generation = task->generation;
        e->restarts = 0;
        e->restarts_in_window = 0;
        e->window_start_ms = supervisor_now_ms();
        kprintf("[SUPERVISOR] watching '%s' (PID %u)\n", name, pid);
        return true;
    }

    kprintf("[SUPERVISOR] table full; '%s' is NOT supervised\n", name);
    return false;
}

/*
 * Restart one dead entry. Returns true if the task was re-created.
 *
 * The rate limit is checked HERE rather than at the call site so that every
 * restart path goes through it -- a second caller that skipped the check would
 * reintroduce exactly the storm this exists to prevent.
 */
static bool supervisor_restart(supervisor_entry_t* e) {
    uint32_t now = supervisor_now_ms();

    /* Roll the window forward if the previous one has elapsed. Deaths are
     * counted per-window, so an occasional death years apart never accumulates
     * into a give-up, while a tight loop exhausts the budget immediately. */
    if (now - e->window_start_ms > SUPERVISOR_WINDOW_MS) {
        e->window_start_ms = now;
        e->restarts_in_window = 0;
    }

    if (e->restarts_in_window >= SUPERVISOR_MAX_RESTARTS) {
        /*
         * Terminal, and loud. This is the branch that matters: a daemon dying
         * repeatedly on an attacker-chosen input must stop being restarted, and
         * the operator must be able to see that it has stopped. Printing here
         * does not violate the "no per-packet kprintf" rule -- it fires at most
         * once per entry per boot, because the state change is one-way.
         */
        e->state = SUPERVISOR_SLOT_GAVE_UP;
        kprintf("[SUPERVISOR] GIVING UP on '%s': %u restarts within %u ms.\n",
                e->name, e->restarts_in_window, (uint32_t)SUPERVISOR_WINDOW_MS);
        kprintf("[SUPERVISOR] '%s' will NOT be restarted again. If this is knetd,"
                " inbound packets are no longer being parsed.\n", e->name);
        return false;
    }

    int pid = task_create_kernel(e->entry, e->name);
    if (pid < 0) {
        /* Out of task slots. Not terminal -- the slot may free up -- but it
         * still consumes budget, otherwise a permanently full task table spins
         * here forever. */
        e->restarts_in_window++;
        kprintf("[SUPERVISOR] restart of '%s' FAILED (no task slot)\n", e->name);
        return false;
    }

    task_t* fresh = task_get((uint32_t)pid);
    if (!fresh) {
        e->restarts_in_window++;
        kprintf("[SUPERVISOR] restart of '%s' FAILED (slot vanished)\n", e->name);
        return false;
    }

    /* task_create_kernel() allocates the task but does NOT enqueue it -- kernel.c
     * calls scheduler_add_task() explicitly for every boot task, so the restart
     * path has to as well. Without this the restarted daemon is created, listed
     * by `ps`, and counted as a successful restart while never running a single
     * instruction: the RX counter simply stops advancing. Steps 1 and 2 of
     * verify-supervisor.sh both pass in that state, which is exactly why that
     * harness also asserts frames are parsed AFTER the restart. */
    scheduler_add_task(fresh);

    e->pid = (uint32_t)pid;
    e->generation = fresh->generation;
    e->restarts++;
    e->restarts_in_window++;
    supervisor_total_restarts++;

    kprintf("[SUPERVISOR] restarted '%s' as PID %u (restart #%u)\n",
            e->name, e->pid, e->restarts);
    return true;
}

void supervisor_run_once(void) {
    for (int i = 0; i < SUPERVISOR_MAX_TASKS; i++) {
        supervisor_entry_t* e = &supervisor_table[i];
        if (e->state != SUPERVISOR_SLOT_WATCHING) continue;

        /*
         * task_get_validated(), not task_get(): the slot is recycled on death
         * (task_terminate sets pid = 0 and frees the slot), so a bare PID lookup
         * can match a DIFFERENT task that has since been created in the same
         * slot with the same PID. That would make a dead daemon look alive --
         * the one failure mode this whole subsystem exists to prevent.
         */
        if (task_get_validated(e->pid, e->generation) != NULL) {
            continue;   /* still alive */
        }

        kprintf("[SUPERVISOR] '%s' (PID %u) has died\n", e->name, e->pid);
        supervisor_restart(e);
    }
}

void task_supervisor(void) {
    kprintf("[SUPERVISOR] system task supervisor started [OK]\n");
    while (1) {
        supervisor_run_once();
        scheduler_yield();
    }
}

void supervisor_get_stats(uint32_t* watched, uint32_t* total_restarts,
                          uint32_t* gave_up) {
    uint32_t w = 0, g = 0;
    for (int i = 0; i < SUPERVISOR_MAX_TASKS; i++) {
        if (supervisor_table[i].state == SUPERVISOR_SLOT_WATCHING) w++;
        else if (supervisor_table[i].state == SUPERVISOR_SLOT_GAVE_UP) g++;
    }
    if (watched) *watched = w;
    if (total_restarts) *total_restarts = supervisor_total_restarts;
    if (gave_up) *gave_up = g;
}
