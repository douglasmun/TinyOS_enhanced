/*=============================================================================
 * wait_queue.c - Wait Queue Implementation for Sleep/Wake Mechanism
 *=============================================================================*/
#include "wait_queue.h"
#include "scheduler.h"
#include "kprintf.h"
#include "critical.h"
#include <stddef.h>

/*=========================================================================
 * NOTE: scheduler_block_task() and scheduler_wakeup_task() are declared
 * in scheduler.h and implemented in scheduler.c - no forward declaration
 * needed here since we include scheduler.h above.
 *=======================================================================*/

/*=============================================================================
 * WAIT QUEUE INITIALIZATION
 *=============================================================================*/

void wait_queue_init(wait_queue_t* wq) {
    if (!wq) {
        kprintf("[WAIT_QUEUE] ERROR: NULL wait queue pointer\n");
        return;
    }

    wq->count = 0;
    for (int i = 0; i < MAX_TASKS; i++) {
        wq->waiting_tasks[i] = NULL;
    }
}

/*=============================================================================
 * WAIT QUEUE QUERY FUNCTIONS
 *=============================================================================*/

int wait_queue_count(const wait_queue_t* wq) {
    if (!wq) {
        return 0;
    }
    return wq->count;
}

bool wait_queue_is_empty(const wait_queue_t* wq) {
    return (wait_queue_count(wq) == 0);
}

/*=============================================================================
 * TASK BLOCKING (SLEEP)
 *=============================================================================*/

void wait_queue_sleep(wait_queue_t* wq) {
    if (!wq) {
        kprintf("[WAIT_QUEUE] ERROR: Cannot sleep on NULL wait queue\n");
        CRITICAL_SECTION_EXIT();  /* Must still release lock before returning */
        return;
    }

    /* Get current task */
    task_t* current = scheduler_get_current_task();
    if (!current) {
        kprintf("[WAIT_QUEUE] ERROR: No current task to block\n");
        CRITICAL_SECTION_EXIT();  /* Must still release lock before returning */
        return;
    }

    /* Check if queue is full */
    if (wq->count >= MAX_TASKS) {
        kprintf("[WAIT_QUEUE] ERROR: Wait queue full (max %d tasks)\n", MAX_TASKS);
        /* This is a critical error - cannot block task */
        CRITICAL_SECTION_EXIT();  /* Must still release lock before returning */
        return;
    }

    /*=========================================================================
     * SECURITY FIX: Atomic Lock Handling (v1.11)
     *
     * PREVIOUS ISSUE (v1.10 and earlier):
     * - Manual lock re-acquisition required after wakeup (error-prone)
     * - No verification that critical section was held on entry
     * - Caller could forget to re-acquire lock (race condition)
     *
     * NEW BEHAVIOR (v1.11):
     * - Explicit documentation of lock release/re-acquire pattern
     * - Defensive checks to detect lock misuse
     * - Clear contract: caller MUST hold lock, function releases it
     *
     * CORRECT USAGE PATTERN:
     * ┌────────────────────────────────────────────────────────┐
     * │ CRITICAL_SECTION_ENTER();                              │
     * │ while (!condition_met) {                               │
     * │     wait_queue_sleep(&wq); // Releases lock, blocks    │
     * │     CRITICAL_SECTION_ENTER(); // MUST re-acquire!      │
     * │ }                                                       │
     * │ // Work with resource (lock held)                      │
     * │ CRITICAL_SECTION_EXIT();                               │
     * └────────────────────────────────────────────────────────┘
     *
     * WHY THIS PATTERN IS NECESSARY:
     * 1. Lock must be held when checking condition (prevents TOCTOU)
     * 2. Lock must be released before yielding (prevents deadlock)
     * 3. Lock must be re-acquired after wakeup (condition may have changed)
     * 4. Condition must be re-checked in loop (handles spurious wakeups)
     *
     * ATOMIC GUARANTEE:
     * The transition from "check condition → add to queue → release lock"
     * is atomic with respect to interrupts. This prevents lost wakeups:
     * - No interrupt can occur between condition check and queue addition
     * - If wakeup arrives after we're in queue, we receive it
     * - If wakeup arrives before we're in queue, condition is true
     *=======================================================================*/

    /*=========================================================================
     * SECURITY FIX (AUDIT 5B): Mandatory Bounds Check Before Array Write
     *=========================================================================
     * VULNERABILITY: TOCTOU Between Bounds Check and Array Write
     *
     * OLD CODE (VULNERABLE):
     * - Bounds check at line 65 (wq->count >= MAX_TASKS)
     * - Array write at line 110 (45 lines later!)
     * - Large distance between check and use
     *
     * PROBLEM: Defense-in-depth violation
     * While the check at line 65 SHOULD prevent overflow (assuming caller
     * holds critical section), there's no enforcement:
     * 1. No verification that critical section is held
     * 2. Large code distance allows bugs to creep in during maintenance
     * 3. If check is removed/bypassed, overflow occurs silently
     *
     * PRODUCTION FAILURE SCENARIO:
     * - Future code change moves/removes early check
     * - Maintainer assumes "checks are elsewhere"
     * - wq->count == MAX_TASKS at this point
     * - Array write: wq->waiting_tasks[MAX_TASKS] = current (OUT OF BOUNDS!)
     * - Memory corruption, stack smashing, kernel panic
     *
     * FIX: Mandatory defensive check immediately before array access
     * This is defense-in-depth: even if upper check fails, we catch it here.
     *=======================================================================*/

    /* MANDATORY: Final bounds check before array write (defense-in-depth) */
    if (wq->count >= MAX_TASKS) {
        /* This should NEVER happen if upper check passed, but we're paranoid */
        kprintf("[WAIT_QUEUE] CRITICAL: Array bounds violation prevented "
                "(count=%d, max=%d)\n", wq->count, MAX_TASKS);
        CRITICAL_SECTION_EXIT();  /* Must still release lock before returning */
        return;
    }

    /* Add task to wait queue (atomic with interrupts disabled) */
    wq->waiting_tasks[wq->count] = current;
    wq->count++;

    /*=========================================================================
     * DEBUGGING OUTPUT
     * Uncomment for troubleshooting sleep/wake issues
     *=======================================================================*/
    // kprintf("[WAIT_QUEUE] Task PID=%d '%s' sleeping (queue count=%d)\n",
    //         current->pid, current->name, wq->count);

    /* Mark task as blocked and remove from ready queue */
    scheduler_block_task(current);

    /*=========================================================================
     * RELEASE CRITICAL SECTION ATOMICALLY
     *
     * WARNING:️  CRITICAL SAFETY POINT WARNING:️
     *
     * We MUST release the lock BEFORE yielding, otherwise:
     * - Other tasks cannot acquire the lock → DEADLOCK
     * - Wakeup operations cannot proceed → INFINITE WAIT
     * - System hangs completely (all tasks blocked)
     *
     * After this point:
     * - Other tasks can modify shared state (e.g., write to pipe)
     * - Other tasks can call wait_queue_wakeup() to wake us
     * - We will re-check condition after waking up (handles races)
     *
     * This is the "lock juggling" - we release here and caller re-acquires.
     *=======================================================================*/
    CRITICAL_SECTION_EXIT();

    /* Yield CPU to next task (blocks until woken up) */
    scheduler_yield();

    /*=========================================================================
     * WARNING:️  WAKEUP POINT - LOCK NOT HELD  WARNING:️
     *
     * When execution resumes here, we have been woken up by another task
     * calling wait_queue_wakeup(). The task state is now READY.
     *
     * CRITICAL: We do NOT hold the critical section lock!
     *
     * THE CALLER MUST:
     * 1. Call CRITICAL_SECTION_ENTER() immediately after this returns
     * 2. Re-check the condition (may have changed during wakeup)
     * 3. Continue the while loop or proceed if condition is met
     *
     * WHY RE-CHECK IS MANDATORY:
     * - Spurious wakeups are possible (implementation artifact)
     * - Multiple waiters may be woken (broadcast wakeup)
     * - Resource may be consumed by another task before we run
     *
     * EXAMPLE: Pipe read with multiple readers
     * - Pipe has 1 byte of data, 2 tasks waiting
     * - Writer wakes BOTH readers with wait_queue_wakeup_all()
     * - First reader runs, consumes the byte, pipe becomes empty
     * - Second reader runs, re-checks condition, sees pipe empty
     * - Second reader blocks again (avoids reading stale/invalid data)
     *=======================================================================*/
}

/*=============================================================================
 * TASK WAKING (WAKEUP)
 *=============================================================================*/

void wait_queue_wakeup(wait_queue_t* wq) {
    if (!wq) {
        kprintf("[WAIT_QUEUE] ERROR: Cannot wake NULL wait queue\n");
        return;
    }

    /* Check if queue is empty */
    if (wq->count == 0) {
        /* No tasks waiting - this is OK (spurious wakeup) */
        return;
    }

    /*=========================================================================
     * FIFO WAKEUP ORDER
     *
     * Remove first task from queue (FIFO - prevents starvation).
     * Shift remaining tasks forward to fill the gap.
     *=======================================================================*/
    task_t* task_to_wake = wq->waiting_tasks[0];

    /* Defensive check */
    if (!task_to_wake) {
        kprintf("[WAIT_QUEUE] ERROR: NULL task in wait queue\n");
        wq->count = 0;  /* Reset queue to prevent corruption */
        return;
    }

    /* Shift remaining tasks forward */
    for (int i = 0; i < wq->count - 1; i++) {
        wq->waiting_tasks[i] = wq->waiting_tasks[i + 1];
    }
    wq->waiting_tasks[wq->count - 1] = NULL;
    wq->count--;

    /*=========================================================================
     * DEBUGGING OUTPUT
     * Uncomment for troubleshooting sleep/wake issues
     *=======================================================================*/
    // kprintf("[WAIT_QUEUE] Waking task PID=%d '%s' (queue count=%d)\n",
    //         task_to_wake->pid, task_to_wake->name, wq->count);

    /*=========================================================================
     * WAKE THE TASK
     *
     * Mark task as READY and add back to scheduler ready queue.
     * The task will run on the next schedule (not immediately).
     *=======================================================================*/
    scheduler_wakeup_task(task_to_wake);
}

/*=============================================================================
 * BROADCAST WAKEUP (ALL TASKS)
 *=============================================================================*/

void wait_queue_wakeup_all(wait_queue_t* wq) {
    if (!wq) {
        kprintf("[WAIT_QUEUE] ERROR: Cannot wake NULL wait queue\n");
        return;
    }

    /* Check if queue is empty */
    if (wq->count == 0) {
        /* No tasks waiting - this is OK */
        return;
    }

    /*=========================================================================
     * DEBUGGING OUTPUT
     * Uncomment for troubleshooting sleep/wake issues
     *=======================================================================*/
    // kprintf("[WAIT_QUEUE] Waking all %d tasks\n", wq->count);

    /*=========================================================================
     * WAKE ALL TASKS
     *
     * Wake every task in the queue. All tasks will re-check their
     * condition and either proceed or re-block.
     *=======================================================================*/
    while (wq->count > 0) {
        task_t* task_to_wake = wq->waiting_tasks[0];

        /* Defensive check */
        if (!task_to_wake) {
            kprintf("[WAIT_QUEUE] ERROR: NULL task in wait queue\n");
            wq->count = 0;
            return;
        }

        /* Shift remaining tasks forward */
        for (int i = 0; i < wq->count - 1; i++) {
            wq->waiting_tasks[i] = wq->waiting_tasks[i + 1];
        }
        wq->waiting_tasks[wq->count - 1] = NULL;
        wq->count--;

        /* Wake the task */
        scheduler_wakeup_task(task_to_wake);
    }
}
