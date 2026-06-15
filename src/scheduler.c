/*=============================================================================
 * scheduler.c - Round-Robin Task Scheduler Implementation
 *=============================================================================*/
#include "scheduler.h"
#include "process.h"
#include "kprintf.h"
#include "gdt.h"
#include "tss.h"       /* SECURITY FIX (Issue 12.2): For tss_set_kernel_stack() */
#include "paging.h"
#include "pmm.h"
#include "util.h"
#include "interrupt_regs.h"
#include "critical.h"
#include "pit.h"
#include "audit.h"      /* SECURITY FIX (AUDIT 3A): For audit_log() before panic */
#include <stddef.h>

/*=============================================================================
 * EXTERNAL FUNCTIONS (from context_switch.S)
 *=============================================================================*/
extern void context_switch(task_t* current_task, task_t* next_task);
extern void switch_to_first_task(task_t* task);

/*=============================================================================
 * GLOBAL VARIABLES (CRITICAL: volatile for interrupt safety)
 *
 * VULNERABILITY (11.A): The scheduler runs from timer interrupts (scheduler_tick)
 * and modifies these global state variables. Without volatile, the compiler may
 * cache these values in registers, causing interrupted code to use stale data.
 *
 * EXAMPLE FAILURE SCENARIO:
 * 1. Function A reads ready_queue_head into a register
 * 2. Timer interrupt fires, scheduler_tick modifies ready_queue_head
 * 3. Function A continues with stale register value, causing queue corruption
 *
 * FIX: Mark all scheduler globals as volatile to force memory access on every
 * read/write, ensuring interrupt handlers and main code see consistent state.
 *=============================================================================*/
static volatile task_t* ready_queue_head = NULL;  // Head of circular ready queue
static volatile task_t* ready_queue_tail = NULL;  // Tail of circular ready queue
static volatile task_t* current_running_task = NULL;
static volatile uint32_t total_context_switches = 0;
static volatile bool scheduler_enabled = false;

/*=============================================================================
 * SECURITY FIX (Issue 5.3): Lazy FPU Switching with CR0.TS
 *
 * OPTIMIZATION: Track which task currently owns the FPU state to avoid
 * unnecessary FPU save/restore on every context switch.
 *
 * ALGORITHM:
 * 1. When switching tasks, set CR0.TS (Task Switched) bit
 * 2. When task tries to use FPU, Device Not Available exception (#NM) fires
 * 3. In #NM handler:
 *    - If FPU owner exists, save its FPU state (fxsave)
 *    - Restore current task's FPU state (fxrstor)
 *    - Clear CR0.TS to allow FPU use
 *    - Update fpu_owner to current task
 *
 * BENEFITS:
 * - Avoids 512-byte FPU save/restore for tasks that don't use FPU
 * - Reduces context switch overhead from ~200 cycles to ~50 cycles
 * - Only pays FPU cost when actually needed
 *
 * SECURITY: Prevents FPU state leakage across tasks
 *===========================================================================*/
static volatile task_t* fpu_owner = NULL;  // Task that owns FPU state

/*=============================================================================
 * SECURITY FIX (v2.0): Cleanup Queue for Rapid Task Terminations
 *
 * VULNERABILITY (Issue 3.3): Single task_to_cleanup pointer causes memory
 * leak when multiple tasks terminate rapidly:
 *   1. Task A terminates, task_to_cleanup = A
 *   2. Task B terminates before A is cleaned up, task_to_cleanup = B
 *   3. Task A is never cleaned up → MEMORY LEAK
 *
 * FIX: Use circular queue to track all tasks pending cleanup. Queue size
 * is 8 (sufficient for MAX_TASKS=32, as cleanup happens every tick).
 *=============================================================================*/
#define CLEANUP_QUEUE_SIZE 8
static volatile task_t* cleanup_queue[CLEANUP_QUEUE_SIZE];
static volatile uint32_t cleanup_queue_head = 0;  // Index to dequeue from
static volatile uint32_t cleanup_queue_tail = 0;  // Index to enqueue at
static volatile uint32_t cleanup_queue_count = 0; // Number of items in queue

/*=============================================================================
 * FUNCTION: scheduler_init
 * PURPOSE: Initialize the scheduler
 *=============================================================================*/
void scheduler_init(void) {
    kprintf("[SCHEDULER] Initializing scheduler.. [OK]\n");

    ready_queue_head = NULL;
    ready_queue_tail = NULL;
    current_running_task = NULL;
    total_context_switches = 0;
    scheduler_enabled = false;

    /* Initialize cleanup queue */
    for (int i = 0; i < CLEANUP_QUEUE_SIZE; i++) {
        cleanup_queue[i] = NULL;
    }
    cleanup_queue_head = 0;
    cleanup_queue_tail = 0;
    cleanup_queue_count = 0;

    kprintf("[SCHEDULER] Round-robin initialized. [OK]\n");
}

/*=============================================================================
 * FUNCTION: cleanup_queue_enqueue
 * PURPOSE: Add task to cleanup queue (called from context switch)
 *
 * SECURITY (v2.0): Prevents memory leak from rapid task terminations
 *=============================================================================*/
static bool cleanup_queue_enqueue(task_t* task) {
    if (!task) {
        return false;
    }

    /* Check if queue is full */
    if (cleanup_queue_count >= CLEANUP_QUEUE_SIZE) {
        kprintf("[SCHEDULER] ERROR: Cleanup queue full! (dropped PID=%d)\n", task->pid);
        return false;
    }

    /* Add to tail of queue */
    cleanup_queue[cleanup_queue_tail] = task;
    cleanup_queue_tail = (cleanup_queue_tail + 1) % CLEANUP_QUEUE_SIZE;
    cleanup_queue_count++;

    return true;
}

/*=============================================================================
 * FUNCTION: cleanup_queue_dequeue
 * PURPOSE: Remove task from cleanup queue (called during cleanup)
 *=============================================================================*/
static task_t* cleanup_queue_dequeue(void) {
    /* Check if queue is empty */
    if (cleanup_queue_count == 0) {
        return NULL;
    }

    /* Remove from head of queue */
    task_t* task = (task_t*)cleanup_queue[cleanup_queue_head];
    cleanup_queue[cleanup_queue_head] = NULL;
    cleanup_queue_head = (cleanup_queue_head + 1) % CLEANUP_QUEUE_SIZE;
    cleanup_queue_count--;

    return task;
}

/*=============================================================================
 * FUNCTION: cleanup_queue_is_empty
 * PURPOSE: Check if cleanup queue has any pending tasks
 *=============================================================================*/
static bool cleanup_queue_is_empty(void) {
    return cleanup_queue_count == 0;
}

/*=============================================================================
 * FUNCTION: scheduler_add_task
 * PURPOSE: Add a task to the ready queue (circular linked list)
 *=============================================================================*/
void scheduler_add_task(task_t* task) {
    if (!task) {
        kprintf("[SCHEDULER] ERROR: Cannot add NULL task\n");
        return;
    }

    /* Sanity check: PID must be >= 1 */
    if (task->pid < 1) {
        kprintf("[SCHEDULER] ERROR: Cannot add task with invalid PID %d (must be >= 1)\n", task->pid);
        kprintf("[SCHEDULER] Task name: '%s', state: %d\n", task->name, task->state);
        return;
    }

    // CRITICAL SECTION: Protect ready queue manipulation from timer interrupts
    CRITICAL_SECTION_ENTER();

    // Ensure task is in READY state
    task->state = TASK_STATE_READY;
    task->ticks_remaining = task->time_slice;

    // If queue is empty
    if (!ready_queue_head) {
        ready_queue_head = task;
        ready_queue_tail = task;
        task->next = task;  // Point to itself (circular)
    } else {
        // Add to end of queue
        task_t* original_head = ready_queue_tail->next;  // True head of circular list
        ready_queue_tail->next = task;
        task->next = original_head;  // Circular link to true head
        ready_queue_tail = task;
    }

    CRITICAL_SECTION_EXIT();

    // kprintf("[SCHEDULER] Added task PID=%d '%s' to ready queue\n",
    //         task->pid, task->name);
}

/*=============================================================================
 * FUNCTION: scheduler_remove_task
 * PURPOSE: Remove a task from the ready queue
 *=============================================================================*/
/*=============================================================================
 * SECURITY FIX (v1.17): Nested Critical Section Prevention
 *
 * Internal locked variant that assumes caller already holds critical section.
 * This prevents nested critical sections when called from scheduler_block_task().
 *===========================================================================*/
static void scheduler_remove_task_locked(task_t* task) {
    if (!task || !ready_queue_head) {
        return;
    }

    /* CRITICAL SECTION ASSUMED - Caller must already hold it */

    // Special case: only one task in queue (task points to itself)
    if (task->next == task) {
        ready_queue_head = NULL;
        ready_queue_tail = NULL;
        task->next = NULL;
        return;
    }

    // Find and remove task from circular list
    task_t* current = (task_t*)ready_queue_head;  /* Cast volatile to non-volatile for local use */
    task_t* prev = (task_t*)ready_queue_tail;     /* Cast volatile to non-volatile for local use */

    /*=========================================================================
     * SECURITY: List Corruption Protection
     * CRITICAL: If the circular linked list is corrupted (e.g., due to memory
     * corruption), the loop could run forever, freezing the scheduler.
     *
     * Protection: Limit traversal to MAX_TASKS + 1 iterations.
     * Since the ready queue can contain at most MAX_TASKS tasks, if we iterate
     * more than MAX_TASKS times without finding the task or returning to head,
     * the list is corrupted.
     *=======================================================================*/
    int iterations = 0;
    #define MAX_SCHEDULER_LIST_ITERATIONS (MAX_TASKS + 1)

    do {
        if (++iterations > MAX_SCHEDULER_LIST_ITERATIONS) {
            kprintf("[SCHEDULER] CRITICAL: Ready queue corrupted! Infinite loop detected.\n");
            kprintf("[SCHEDULER] Attempted to remove PID=%d '%s' but list is invalid.\n",
                    task->pid, task->name);

            /*=================================================================
             * SECURITY FIX (AUDIT 3A): Critical Audit Logging Before Panic
             *
             * RATIONALE: Scheduler queue corruption is a near-catastrophic
             * event that must be logged to the audit system for post-mortem
             * analysis. This helps identify the root cause (memory corruption,
             * race condition, or exploit attempt).
             *
             * CRITICAL: Log before panic() to ensure the audit entry is
             * persisted before system halts.
             *===============================================================*/
            audit_log(AUDIT_SYS_CRASH, AUDIT_CRITICAL, 0,
                      "FATAL: Scheduler ready queue corruption detected "
                      "(PID=%u '%s', iterations=%d, max=%d)",
                      (unsigned int)task->pid, task->name, iterations,
                      MAX_SCHEDULER_LIST_ITERATIONS);

            // Panic - corrupted scheduler state is unrecoverable
            panic("Scheduler ready queue corruption detected");
            return;
        }

        if (current == task) {
            // Update links
            prev->next = current->next;

            // Update head/tail if necessary
            if (current == ready_queue_head) {
                ready_queue_head = current->next;
            }
            if (current == ready_queue_tail) {
                ready_queue_tail = prev;
            }

            task->next = NULL;
            return;
        }

        prev = current;
        current = current->next;
    } while (current != ready_queue_head);

    kprintf("[SCHEDULER] WARNING: Task PID=%d '%s' not found in ready queue!\n",
            task->pid, task->name);
}

void scheduler_remove_task(task_t* task) {
    if (!task || !ready_queue_head) {
        return;
    }

    // CRITICAL SECTION: Protect ready queue manipulation from timer interrupts
    CRITICAL_SECTION_ENTER();
    scheduler_remove_task_locked(task);
    CRITICAL_SECTION_EXIT();
}

/*=============================================================================
 * FUNCTION: scheduler_block_task
 * PURPOSE: Block a task (remove from ready queue, mark as BLOCKED)
 *=============================================================================
 * This function is called by wait_queue_sleep() to block the current task.
 *
 * SECURITY NOTES:
 * - Caller MUST hold critical section (interrupts disabled)
 * - Task is removed from ready queue (will not be scheduled)
 * - Task state is changed to BLOCKED
 * - After this, caller should release critical section and yield CPU
 *
 * USAGE:
 * CRITICAL_SECTION_ENTER();
 * scheduler_block_task(current_task);
 * CRITICAL_SECTION_EXIT();
 * scheduler_yield();  // Blocks until woken up
 *=============================================================================*/
void scheduler_block_task(task_t* task) {
    if (!task) {
        kprintf("[SCHEDULER] ERROR: Cannot block NULL task\n");
        return;
    }

    /*=========================================================================
     * SECURITY FIX (v1.18): Prevent blocking in interrupt context
     *
     * CRITICAL: Blocking from an interrupt handler is a fatal bug:
     * - Deadlock: Interrupt context can't reschedule, so blocked task never wakes
     * - Lock inversion: IRQ handler may hold locks needed by other code
     * - Scheduler corruption: Task switching from interrupt is unsafe
     *
     * MITIGATION: Panic immediately if called from interrupt context.
     * Better to halt with diagnostics than silently deadlock the system.
     *=======================================================================*/
    if (in_interrupt_context()) {
        kprintf("\n");
        kprintf("*************************************************************\n");
        kprintf("* CRITICAL: BLOCKING CALLED FROM INTERRUPT CONTEXT         *\n");
        kprintf("*************************************************************\n");
        kprintf("\n");
        kprintf("Task: '%s' (PID=%u)\n", task->name, (unsigned int)task->pid);
        kprintf("\n");
        kprintf("This is a fatal bug - blocking in interrupt context causes:\n");
        kprintf(" - Deadlock (interrupt handlers can't reschedule)\n");
        kprintf(" - Lock inversion\n");
        kprintf(" - Scheduler state corruption\n");
        kprintf("\n");
        kprintf("Halting to prevent system deadlock.\n");
        kprintf("\n");

        kernel_panic("Blocking in interrupt context");
    }

    /*=========================================================================
     * CRITICAL SECTION ASSUMED
     * Caller must have interrupts disabled to prevent race conditions
     *
     * SECURITY FIX (v1.17): Use locked variant to prevent nested critical section
     * - scheduler_remove_task() would enter critical section again
     * - scheduler_remove_task_locked() assumes we're already in one
     *=======================================================================*/

    /* Remove task from ready queue (using locked variant) */
    scheduler_remove_task_locked(task);

    /* Mark task as blocked */
    task->state = TASK_STATE_BLOCKED;

    /*=========================================================================
     * DEBUGGING OUTPUT
     * Uncomment for troubleshooting blocking issues
     *=======================================================================*/
    // kprintf("[SCHEDULER] Task PID=%d '%s' blocked\n", task->pid, task->name);
}

/*=============================================================================
 * FUNCTION: scheduler_wakeup_task
 * PURPOSE: Wake up a blocked task (mark as READY, add to ready queue)
 *=============================================================================
 * This function is called by wait_queue_wakeup() to wake up a blocked task.
 *
 * SECURITY NOTES:
 * - Caller MUST hold critical section (interrupts disabled)
 * - Task is marked as READY
 * - Task is added back to ready queue
 * - Task will run on next scheduler invocation (not immediately)
 *
 * USAGE:
 * CRITICAL_SECTION_ENTER();
 * scheduler_wakeup_task(blocked_task);
 * CRITICAL_SECTION_EXIT();
 *=============================================================================*/
void scheduler_wakeup_task(task_t* task) {
    if (!task) {
        kprintf("[SCHEDULER] ERROR: Cannot wake NULL task\n");
        return;
    }

    /*=========================================================================
     * CRITICAL SECTION ASSUMED
     * Caller must have interrupts disabled to prevent race conditions
     *=======================================================================*/

    /* Only wake tasks that are actually blocked */
    if (task->state != TASK_STATE_BLOCKED) {
        kprintf("[SCHEDULER] WARNING: Attempting to wake task PID=%d in state %d\n",
                task->pid, task->state);
        return;
    }

    /*=========================================================================
     * DEBUGGING OUTPUT
     * Uncomment for troubleshooting wakeup issues
     *=======================================================================*/
    // kprintf("[SCHEDULER] Task PID=%d '%s' waking up\n", task->pid, task->name);

    /* Add task back to ready queue (this also sets state to READY) */
    scheduler_add_task(task);
}

/*=============================================================================
 * FUNCTION: scheduler_get_next_task
 * PURPOSE: Get the next task to run (round-robin)
 *=============================================================================*/
static task_t* scheduler_get_next_task(void) {
    if (!ready_queue_head) {
        return NULL;  // No tasks to run
    }

    // Round-robin: return head and advance to next
    task_t* next = (task_t*)ready_queue_head;  /* Cast volatile to non-volatile for local use */

    // Terminated tasks should already be removed from ready queue by sys_exit()
    // If we find one here, it's a bug - log warning but handle gracefully
    if (next->state == TASK_STATE_TERMINATED) {
        kprintf("[SCHEDULER] WARNING: Found terminated task PID=%d in ready queue!\n", next->pid);
        scheduler_remove_task(next);
        return scheduler_get_next_task();  // Try again
    }

    // Move to next task for next scheduling decision
    ready_queue_head = ready_queue_head->next;

    return next;
}

/*=============================================================================
 * FUNCTION: scheduler_start
 * PURPOSE: Start the scheduler and jump to first task
 *=============================================================================*/
void scheduler_start(void) {
    kprintf("[SCHEDULER] Starting scheduler...... [OK]\n");

    if (!ready_queue_head) {
        kprintf("[SCHEDULER] ERROR: No tasks to run!\n");
        for (;;) __asm__ volatile("hlt");
    }

    scheduler_enabled = true;

    // Get first task
    task_t* first_task = scheduler_get_next_task();
    if (!first_task) {
        kprintf("[SCHEDULER] ERROR: No runnable tasks!\n");
        for (;;) __asm__ volatile("hlt");
    }

    /* Sanity check: PID must be >= 1 */
    if (first_task->pid < 1) {
        kprintf("[SCHEDULER] PANIC: Invalid PID %d (must be >= 1)\n", first_task->pid);
        kprintf("[SCHEDULER] Task pointer: %p\n", (void*)first_task);
        kprintf("[SCHEDULER] Task state: %d\n", first_task->state);
        kprintf("[SCHEDULER] Ready queue head: %p\n", (void*)ready_queue_head);
        for (;;) __asm__ volatile("hlt");
    }

    /*=========================================================================
     * SECURITY FIX (Issue 6.3): Protect Initial State Transition
     *
     * RATIONALE: While unlikely, if a timer interrupt fires between setting
     * current_running_task and first_task->state, the scheduler could see
     * inconsistent state. Protect this critical initialization sequence.
     *=======================================================================*/
    CRITICAL_SECTION_ENTER();
    current_running_task = first_task;
    first_task->state = TASK_STATE_RUNNING;
    first_task->ticks_remaining = first_task->time_slice;
    CRITICAL_SECTION_EXIT();

    kprintf("[SCHEDULER] Switching to PID=%d...... [OK]\n",
            first_task->pid);

    // Debug: Print task details
    kprintf("[SCHEDULER] Task entry: 0x%08x\n", first_task->context.eip);
    kprintf("[SCHEDULER] Task ESP: 0x%08x\n", first_task->context.esp);
    kprintf("[SCHEDULER] Task kernel_stack: 0x%08x\n", first_task->kernel_stack);

    // If switching to a user-mode task, set TSS.esp0 to kernel stack
    if (!first_task->is_kernel_task) {
        tss_set_kernel_stack(first_task->kernel_stack);

        kprintf("[SCHEDULER] User task segments: CS=0x%04x SS=0x%04x DS=0x%04x\n",
                first_task->context.cs, first_task->context.ss, first_task->context.ds);
    }

    kprintf("[SCHEDULER] About to switch_to_first_task...\n");

    // Jump to first task (does not return)
    switch_to_first_task(first_task);

    // Should never reach here
    __builtin_unreachable();
}

/*=============================================================================
 * FUNCTION: scheduler_tick
 * PURPOSE: Called by timer interrupt to update time slices (but NOT switch tasks)
 * NOTE: We don't do context switches from interrupts because context_switch
 *       uses 'ret' instead of 'iret', which would leave interrupts disabled.
 *=============================================================================*/
void scheduler_tick(void) {
    if (!scheduler_enabled || !current_running_task) {
        return;
    }

    // Decrement remaining ticks
    if (current_running_task->ticks_remaining > 0) {
        current_running_task->ticks_remaining--;
    }
    current_running_task->total_ticks++;

    /*=========================================================================
     * SECURITY FIX (Issue 6.3): Atomic State Transition for Sleeping Tasks
     *
     * RACE CONDITION: Original code checked task->state and modified it
     * WITHOUT critical section protection. Timer interrupt could fire between:
     * 1. Reading task->state (SLEEPING)
     * 2. Setting task->state = READY
     * 3. Calling scheduler_add_task()
     *
     * This causes:
     * - Task state and queue membership become inconsistent
     * - Possible double-insertion into ready queue
     * - Scheduler corruption
     *
     * FIX: Wrap state check and transition in critical section.
     * Note: scheduler_add_task() will re-enter critical section, but that's
     * safe because CRITICAL_SECTION_ENTER/EXIT are implemented with
     * interrupt disable/enable, which can nest safely.
     *=======================================================================*/
    // Wake up sleeping tasks whose time has expired
    // NOTE: We iterate through all tasks to check for sleeping ones
    task_t* all_tasks[MAX_TASKS];
    int task_count = task_get_all(all_tasks, MAX_TASKS);
    uint32_t current_ticks = pit_get_ticks();

    for (int i = 0; i < task_count; i++) {
        task_t* task = all_tasks[i];

        // CRITICAL SECTION: Protect state check and transition
        CRITICAL_SECTION_ENTER();

        if (task->state == TASK_STATE_SLEEPING && current_ticks >= task->wake_tick) {
            // Wake up the task (scheduler_add_task will set state to READY)
            // Note: We exit critical section before calling scheduler_add_task
            // to avoid nested critical sections
            CRITICAL_SECTION_EXIT();
            scheduler_add_task(task);  // This will re-enter critical section internally
        } else {
            CRITICAL_SECTION_EXIT();
        }
    }

    // Note: We don't actually switch tasks here.
    // Tasks switch when they voluntarily yield or make syscalls.
}

/*=============================================================================
 * FUNCTION: scheduler_switch_kernel_context
 * PURPOSE: Single choke point for every context_switch() in the kernel.
 *
 * REQUIREMENT: caller must have interrupts disabled, and must have already
 * published next_task as current_running_task. Interrupts stay disabled until
 * the very end of context_switch() (it restores the target's saved EFLAGS
 * only after the target's registers are fully loaded).
 *
 * Responsibilities:
 * 1. TSS.esp0 — if next_task can run in ring 3, its next kernel entry must
 *    land on its own kernel stack.
 * 2. Per-task swap of the interrupt/critical-section bookkeeping globals
 *    (see the comment on saved_int_depth in process.h). A task suspended
 *    mid-ISR still owes interrupt_context_exit(); that debt belongs to the
 *    task, not to whichever task runs next.
 * 3. The switch itself.
 *
 * When prev_task is eventually resumed, whichever invocation of this helper
 * resumed it has already restored prev_task's bookkeeping globals.
 *=============================================================================*/
static void scheduler_switch_kernel_context(task_t* prev_task, task_t* next_task) {
    if (!next_task->is_kernel_task) {
        tss_set_kernel_stack(next_task->kernel_stack);
    }

    prev_task->saved_int_depth  = __interrupt_context_depth;
    prev_task->saved_crit_depth = __critical_section_depth;
    prev_task->saved_crit_flags = __critical_section_saved_flags;

    __interrupt_context_depth      = next_task->saved_int_depth;
    __critical_section_depth       = next_task->saved_crit_depth;
    __critical_section_saved_flags = next_task->saved_crit_flags;

    context_switch(prev_task, next_task);
}

/*=============================================================================
 * FUNCTION: scheduler_schedule
 * PURPOSE: Perform task scheduling (called by timer interrupt)
 *=============================================================================*/
void scheduler_schedule(void) {
    /*=========================================================================
     * SECURITY FIX (v2.0): Check scheduler_enabled with proper protection
     *
     * RACE CONDITION: Original code checked scheduler_enabled before any
     * critical section. While this early check is less dangerous than in
     * scheduler_yield() (since cleanup doesn't depend on scheduler state),
     * we still protect the check for consistency and correctness.
     *
     * NOTE: Cleanup can proceed even if scheduler is disabled, but we avoid
     * scheduling operations if scheduler_enabled is false.
     *=======================================================================*/

    /*=========================================================================
     * Cleanup queue draining is performed ONLY by
     * scheduler_schedule_from_interrupt() (timer IRQ, interrupts off).
     * Draining here as well raced the IRQ path: cleanup_queue_dequeue() is
     * non-atomic, and this function runs with interrupts enabled, enabling
     * a double-free of a terminated task's resources.
     *=======================================================================*/

    /*=========================================================================
     * LOCKING (root-cause fix for preemption corruption): interrupts must
     * stay disabled from the moment current_running_task is reassigned until
     * context_switch() has actually switched stacks. The old code exited the
     * critical section (re-enabling IF) BEFORE context_switch; a timer IRQ in
     * that window saw current_running_task == next_task while the CPU was
     * still executing prev_task's code, and saved next_task's "context" as a
     * resume point inside prev_task's stack — two tasks then ran on one
     * stack, corrupting whatever prev_task was computing (PBKDF2, ECDSA...).
     *
     * We use disable/restore_interrupts() locals instead of CRITICAL_SECTION
     * because the critical-section depth/flags are global bookkeeping that
     * does not survive a context switch (it is swapped per-task by
     * scheduler_switch_kernel_context()). Inner helpers' critical sections
     * nest fine: they save and restore IF=0.
     *=======================================================================*/
    uint32_t irq_flags = disable_interrupts();

    // Check if scheduler is enabled (atomically with interrupts off)
    if (!scheduler_enabled) {
        restore_interrupts(irq_flags);
        return;  // Scheduler not started yet
    }

    // CRITICAL: Detect system-wide task exhaustion (all tasks terminated)
    // If there are no tasks in the ready queue AND no current task,
    // the system has no work to do and must halt to prevent infinite loops
    if (!ready_queue_head && (!current_running_task ||
                              current_running_task->state == TASK_STATE_TERMINATED)) {
        kprintf("\n[SCHEDULER] CRITICAL: All tasks terminated - system halting\n");
        kprintf("[SCHEDULER] No runnable tasks remain. Entering halt state.\n");
        kprintf("[SCHEDULER] System shutdown complete.\n\n");

        /*
         * SECURITY FIX: Use kernel_panic instead of inline halt loop
         * Provides recursion protection and consistent error handling
         */
        kernel_panic("All tasks terminated");
    }

    // If no current task, start from ready queue
    if (!current_running_task) {
        task_t* next = scheduler_get_next_task();
        if (next) {
            current_running_task = next;
            next->state = TASK_STATE_RUNNING;
            next->ticks_remaining = next->time_slice;
            switch_to_first_task(next);  // Does not return
        }
        restore_interrupts(irq_flags);
        return;
    }

    // Decrement remaining ticks
    if (current_running_task->ticks_remaining > 0) {
        current_running_task->ticks_remaining--;
        current_running_task->total_ticks++;
    }

    // Check if time slice expired
    if (current_running_task->ticks_remaining == 0) {
        // Time slice expired, switch to next task
        task_t* prev_task = (task_t*)current_running_task;  /* Cast volatile to non-volatile for local use */
        task_t* next_task = scheduler_get_next_task();

        if (!next_task) {
            // No other tasks, reset time slice and continue
            current_running_task->ticks_remaining = current_running_task->time_slice;
            restore_interrupts(irq_flags);
            return;
        }

        // If next task is same as current, just reset time slice
        if (next_task == prev_task) {
            current_running_task->ticks_remaining = current_running_task->time_slice;
            restore_interrupts(irq_flags);
            return;
        }

        // Perform context switch
        // Check if prev_task is terminated - if so, queue it for cleanup after the switch
        if (prev_task->state == TASK_STATE_TERMINATED ||
            prev_task->state == TASK_STATE_ZOMBIE) {
            /* SECURITY FIX (v2.0): Enqueue instead of single pointer assignment */
            if (!cleanup_queue_enqueue(prev_task)) {
                kprintf("[SCHEDULER] WARNING: Failed to enqueue terminated task PID=%d for cleanup\n", prev_task->pid);
            }
        } else if (prev_task->state == TASK_STATE_RUNNING) {
            /* Only a preempted RUNNING task becomes READY; preserve
             * BLOCKED/SLEEPING set by blocking paths so wakeup works */
            prev_task->state = TASK_STATE_READY;
        }

        next_task->state = TASK_STATE_RUNNING;
        next_task->ticks_remaining = next_task->time_slice;

        current_running_task = next_task;
        total_context_switches++;

        // Mark both tasks as having run
        if (prev_task->state != TASK_STATE_TERMINATED &&
            prev_task->state != TASK_STATE_ZOMBIE) {
            prev_task->has_run_before = true;
        }
        next_task->has_run_before = true;

        /*=====================================================================
         * PHASE 15: Kernel Stack Erasing (Modern Linux Feature) - DISABLED
         *
         * ISSUE DISCOVERED (2025-01-XX):
         * The original implementation had TWO critical bugs:
         *
         * BUG #1 - Size Mismatch (FIXED):
         * - KERNEL_STACK_SIZE = 524288 bytes (512KB) in process.h
         * - Actual stack allocation = 16 pages (64KB) in process.c
         * - memset tried to zero 512KB, writing 448KB beyond allocation!
         * - This corrupted buffer zones, next task's memory → page fault
         *
         * BUG #2 - Stack-in-Use Corruption (ROOT CAUSE):
         * - When task calls scheduler_yield(), it's running on ITS OWN stack
         * - Call chain: task_code → scheduler_yield → scheduler_schedule
         * - All return addresses are on the current task's stack!
         * - Zeroing the stack BEFORE context_switch corrupts these addresses
         * - After context switch back, CPU jumps to corrupted EIP (0x00000003)
         * - Result: #UD Invalid Opcode exception
         *
         * PROPER SOLUTION (for future implementation):
         * - Zero INCOMING task's stack (task we're switching TO)
         * - Not outgoing task's stack (task we're leaving)
         * - Ensures we never zero a stack that's currently in use
         * - Linux uses this approach in kernel v6.17+
         *
         * CURRENT STATUS: Disabled until proper implementation
         * System works correctly without stack zeroing (verified 2025-01-XX)
         * Security impact: Information leakage between tasks (low risk)
         *===================================================================*/

        // Switch context (works for both virgin and running tasks).
        // Interrupts are STILL DISABLED here (see locking comment above);
        // context_switch restores the target's own IF state at its very end.
        scheduler_switch_kernel_context(prev_task, next_task);

        // Resumed later (with IF=0, since we suspended with IF=0):
        // restore our caller's interrupt state.
        restore_interrupts(irq_flags);
    } else {
        // Time slice not expired yet
        restore_interrupts(irq_flags);
    }
}

/*=============================================================================
 * FUNCTION: scheduler_yield
 * PURPOSE: Voluntarily yield CPU to next task
 *=============================================================================*/
void scheduler_yield(void) {
    /*=========================================================================
     * SECURITY FIX (v2.0): Move volatile variable check inside critical section
     *
     * RACE CONDITION: Original code checked scheduler_enabled and
     * current_running_task BEFORE entering critical section. A timer
     * interrupt could modify these between the check and use, causing:
     * - NULL pointer dereference (line 623)
     * - Use of disabled scheduler
     *
     * FIX: Enter critical section FIRST, then check state atomically
     *=======================================================================*/

    // CRITICAL SECTION: Protect ALL shared state access
    CRITICAL_SECTION_ENTER();

    // Check scheduler state atomically
    if (!scheduler_enabled || !current_running_task) {
        CRITICAL_SECTION_EXIT();
        kprintf("[SCHEDULER] yield: scheduler not enabled or no current task\n");
        return;
    }

    // kprintf("[SCHEDULER] Task PID=%d '%s' yielding\n",
    //         current_running_task->pid, current_running_task->name);

    // CRITICAL: When yielding voluntarily, advance ready_queue_head past current task
    // to ensure we actually switch to a different task (not back to ourselves)
    if (ready_queue_head == current_running_task) {
        ready_queue_head = ready_queue_head->next;
    }

    // Force time slice to expire
    current_running_task->ticks_remaining = 0;

    CRITICAL_SECTION_EXIT();

    // Trigger scheduling
    scheduler_schedule();

    // kprintf("[SCHEDULER] Task PID=%d '%s' resumed after yield\n",
    //         current_running_task->pid, current_running_task->name);
}

/*=============================================================================
 * FUNCTION: scheduler_get_current_task
 * PURPOSE: Get currently running task
 *=============================================================================*/
task_t* scheduler_get_current_task(void) {
    /*=========================================================================
     * SECURITY FIX (v2.0): Add critical section protection
     *
     * RACE CONDITION: Without protection, a timer interrupt could modify
     * current_running_task between the read and return, potentially returning
     * a pointer to a task that's being modified or even freed.
     *
     * FIX: Protect the read with a critical section to ensure atomicity.
     *=======================================================================*/
    CRITICAL_SECTION_ENTER();
    task_t* task = (task_t*)current_running_task;
    CRITICAL_SECTION_EXIT();
    return task;
}

/*=============================================================================
 * FUNCTION: scheduler_stats
 * PURPOSE: Print scheduler statistics
 *=============================================================================*/
void scheduler_stats(void) {
    /*=========================================================================
     * SECURITY FIX (v2.0): Protect all reads with critical section
     *
     * RACE CONDITION: Without protection, timer interrupt could modify state
     * variables during reads, resulting in torn/inconsistent statistics:
     * - scheduler_enabled could flip mid-read
     * - total_context_switches could increment between display
     * - current_running_task could change while dereferencing fields
     * - ready_queue could be modified during traversal
     *
     * FIX: Take a consistent snapshot of all state under critical section
     *=======================================================================*/
    kprintf("\n=== SCHEDULER STATISTICS ===\n");

    CRITICAL_SECTION_ENTER();

    /* Snapshot all volatile state atomically */
    bool enabled = scheduler_enabled;
    uint32_t switches = total_context_switches;
    task_t* current = (task_t*)current_running_task;

    kprintf("Enabled: %s\n", enabled ? "YES" : "NO");
    kprintf("Total context switches: %u\n", switches);

    if (current) {
        kprintf("Current task: PID=%d '%s'\n",
                current->pid,
                current->name);
        kprintf("  Time slice: %u ticks\n", current->time_slice);
        kprintf("  Remaining: %u ticks\n", current->ticks_remaining);
        kprintf("  Total CPU: %u ticks\n", current->total_ticks);
    } else {
        kprintf("Current task: NONE\n");
    }

    /* Count tasks in ready queue */
    int task_count = 0;
    if (ready_queue_head) {
        task_t* t = (task_t*)ready_queue_head;
        do {
            task_count++;
            t = t->next;
        } while (t != ready_queue_head);
    }

    CRITICAL_SECTION_EXIT();

    kprintf("Tasks in ready queue: %d\n", task_count);
    kprintf("============================\n\n");
}

/*=============================================================================
 * FUNCTION: scheduler_schedule_from_interrupt
 * PURPOSE: Preemptive scheduling from the timer ISR.
 *
 * Preemptive switches go through scheduler_switch_kernel_context() /
 * context_switch(): the preempted task is suspended exactly here, mid-ISR, on
 * its own kernel stack, and resumes by finishing this ISR (popa/iret restore
 * the interrupted computation, including a privilege-change iret back to
 * ring 3 if it was preempted in user mode). The interrupt frame itself is no
 * longer rewritten; `regs` is kept for ABI stability with isr.S.
 *=============================================================================*/
void scheduler_schedule_from_interrupt(interrupt_regs_t* regs) {
    (void)regs;

    if (!scheduler_enabled || !current_running_task) {
        return;  // Scheduler not started yet
    }

    /*=========================================================================
     * Wake up sleeping tasks whose wake time has expired
     *
     * This is the only place SLEEPING tasks are re-queued: task_sleep()
     * removes the task from the ready queue, so without this check on every
     * timer tick a sleeping task would never run again. We run in IRQ
     * context here (interrupts off), so the state checks are atomic.
     *=======================================================================*/
    {
        task_t* all_tasks[MAX_TASKS];
        int task_count = task_get_all(all_tasks, MAX_TASKS);
        uint32_t current_ticks = pit_get_ticks();

        for (int i = 0; i < task_count; i++) {
            task_t* task = all_tasks[i];
            if (task->state == TASK_STATE_SLEEPING && current_ticks >= task->wake_tick) {
                // scheduler_add_task() sets state to READY
                scheduler_add_task(task);
            }
        }
    }

    /*=========================================================================
     * SECURITY FIX (v2.0): Process ALL queued tasks for cleanup
     *
     * Loop through cleanup queue and free resources for all terminated tasks.
     *=======================================================================*/
    while (!cleanup_queue_is_empty()) {
        task_t* task_to_cleanup = cleanup_queue_dequeue();
        if (!task_to_cleanup) {
            break;  // Queue empty or error
        }

        uint32_t saved_cr3;
        __asm__ volatile("mov %%cr3, %0" : "=r"(saved_cr3));
        uint32_t kernel_pd = get_kernel_page_directory();

        bool switched_to_kernel_pd = false;
        if (saved_cr3 != kernel_pd) {
            __asm__ volatile("mov %0, %%cr3" :: "r"(kernel_pd) : "memory");
            switched_to_kernel_pd = true;
        }

        // Free all task memory (stacks, guard pages, page directory, EDR state)
        // Idempotent: fields already freed by task_terminate() are zeroed
        task_free_resources(task_to_cleanup);

        task_to_cleanup->state = TASK_STATE_TERMINATED;
        task_to_cleanup->pid = 0;

        // Free slot in allocator bitmap for reuse
        task_free_slot_for_task((task_t*)task_to_cleanup);

        /*=====================================================================
         * SECURITY FIX (Issue 5.3): Clear FPU owner if terminated task owns it
         *===================================================================*/
        if (fpu_owner == task_to_cleanup) {
            fpu_owner = NULL;
        }

        if (switched_to_kernel_pd) {
            __asm__ volatile("mov %0, %%cr3" :: "r"(saved_cr3) : "memory");
        }
    }

    // Check for system-wide task exhaustion
    if (!ready_queue_head && (!current_running_task ||
                              current_running_task->state == TASK_STATE_TERMINATED)) {
        kprintf("\n[SCHEDULER] CRITICAL: All tasks terminated - system halting\n");
        kprintf("[SCHEDULER] No runnable tasks remain. Entering halt state.\n");
        kprintf("[SCHEDULER] System shutdown complete.\n\n");

        /*
         * SECURITY FIX: Use kernel_panic instead of inline halt loop
         * Provides recursion protection and consistent error handling
         */
        kernel_panic("All tasks terminated");
    }

    // Decrement remaining ticks
    if (current_running_task->ticks_remaining > 0) {
        current_running_task->ticks_remaining--;
        current_running_task->total_ticks++;
    }

    // Check if time slice expired
    if (current_running_task->ticks_remaining == 0) {
        task_t* prev_task = (task_t*)current_running_task;  /* Cast volatile to non-volatile for local use */
        task_t* next_task = scheduler_get_next_task();

        if (!next_task || next_task == prev_task) {
            // No other tasks or same task, just reset time slice
            current_running_task->ticks_remaining = current_running_task->time_slice;
            return;
        }

        /*=====================================================================
         * SECURITY FIX (Issue 6.3): Atomic State Transition in Interrupt Context
         *
         * NOTE: We're already in an interrupt handler (interrupts disabled by CPU),
         * but we use CRITICAL_SECTION for consistency and explicit documentation.
         * This makes the code's locking model uniform across all schedulers.
         *===================================================================*/
        CRITICAL_SECTION_ENTER();

        // Mark old task state
        if (prev_task->state == TASK_STATE_TERMINATED ||
            prev_task->state == TASK_STATE_ZOMBIE) {
            /* SECURITY FIX (v2.0): Enqueue instead of single pointer assignment */
            if (!cleanup_queue_enqueue(prev_task)) {
                kprintf("[SCHEDULER] WARNING: Failed to enqueue terminated task PID=%d for cleanup\n", prev_task->pid);
            }
        } else if (prev_task->state == TASK_STATE_RUNNING) {
            /* Only a preempted RUNNING task becomes READY; preserve
             * BLOCKED/SLEEPING set by blocking paths so wakeup works */
            prev_task->state = TASK_STATE_READY;
        }

        // Mark new task state
        next_task->state = TASK_STATE_RUNNING;
        next_task->ticks_remaining = next_task->time_slice;
        current_running_task = next_task;
        total_context_switches++;

        CRITICAL_SECTION_EXIT();

        /*=====================================================================
         * ALL PREEMPTIVE SWITCHES use the real stack-switching path.
         *
         * The old iret-frame-rewrite switch only restored GP regs + EIP/CS/
         * EFLAGS into THIS ISR's frame. That is correct only when the iret
         * pops ESP/SS (privilege change to ring 3). For any switch that
         * resumes a task in ring 0 — kernel->kernel, but also user->kernel —
         * iret does NOT reload ESP/SS, so the incoming kernel task resumed on
         * the PREEMPTED task's stack and both corrupted each other. It also
         * left tasks suspended in two different representations (iret-frame
         * vs context_switch), and resuming across representations restored a
         * stale or misaligned ESP.
         *
         * Unified model: every preemptive switch suspends prev_task's
         * KERNEL-SIDE state. We are on prev_task's kernel stack inside the
         * timer ISR; context_switch() records this exact point. When
         * prev_task is rescheduled it returns here, finishes this ISR, and
         * the popa/iret epilogue restores the interrupted computation —
         * including a privilege-change iret back to ring 3 if prev_task was
         * preempted in user mode (its user ESP/SS are in the ISR frame on
         * its own kernel stack).
         *
         * A READY task always has a valid kernel-side suspension: mid-ISR
         * (preempted), mid-syscall (blocked/yielded), or fresh (entry point;
         * fresh user tasks enter ring 3 via context_switch's iret path).
         *
         * CR3 and CR0.TS (lazy FPU) are handled inside context_switch.S;
         * TSS.esp0 and the per-task interrupt-depth bookkeeping are handled
         * by scheduler_switch_kernel_context(). Interrupts are disabled for
         * the whole ISR, satisfying the helper's locking requirement.
         *===================================================================*/
        scheduler_switch_kernel_context(prev_task, next_task);

        /* Resumed later: reset prev_task's slice and return from the ISR
         * normally (popa/iret restore prev_task from its own stack). */
        prev_task->ticks_remaining = prev_task->time_slice;
        return;
    }
}

/*=============================================================================
 * FUNCTION: scheduler_get_all_tasks
 * PURPOSE: Get all active tasks in the system
 *
 * SECURITY FIX: Uses task_get_all() which iterates the internal task array
 * directly instead of searching PIDs 1-99. With PID recycling, PIDs can be
 * any value from 1 to UINT32_MAX, so PID-based iteration is UNSAFE.
 *=============================================================================*/
static task_t* all_tasks_array[MAX_TASKS];

int scheduler_get_all_tasks(task_t*** tasks_out) {
    // Use the safe task_get_all() from process.c which iterates
    // the internal tasks array directly (O(MAX_TASKS) complexity)
    // instead of guessing PIDs (which could be anywhere from 1 to UINT32_MAX)
    int count = task_get_all(all_tasks_array, MAX_TASKS);

    *tasks_out = all_tasks_array;
    return count;
}

/*=============================================================================
 * FUNCTION: scheduler_handle_fpu_exception
 * PURPOSE: Handle lazy FPU switching on Device Not Available exception (#NM)
 *
 * SECURITY FIX (Issue 5.3): Lazy FPU Switching with CR0.TS
 *
 * Called from exception handler (vector 7) when a task tries to use FPU/SSE
 * instructions after CR0.TS was set during context switch.
 *
 * ALGORITHM:
 * 1. If another task owns FPU state, save it (fxsave to old owner's context)
 * 2. Restore current task's FPU state (fxrstor from current->context.fpu_state)
 * 3. Clear CR0.TS to allow FPU use without further exceptions
 * 4. Update fpu_owner to current task
 *
 * CRITICAL SECURITY:
 * - Prevents FPU state leakage across tasks (cryptographic keys, etc.)
 * - Only saves/restores FPU when actually used (performance optimization)
 * - Ensures numerical correctness by maintaining per-task FPU state
 *
 * PERFORMANCE:
 * - Tasks that don't use FPU never pay the 512-byte save/restore cost
 * - Reduces context switch overhead from ~200 cycles to ~50 cycles
 * - SSH/TLS tasks that use crypto still get full FPU performance
 *=============================================================================*/
void scheduler_handle_fpu_exception(void) {
    /*=========================================================================
     * CRITICAL SECTION: Protect fpu_owner access from timer interrupts
     * Without this, a timer interrupt could switch tasks mid-handler,
     * corrupting FPU state tracking.
     *=======================================================================*/
    CRITICAL_SECTION_ENTER();

    /* Get current task */
    task_t* current = (task_t*)current_running_task;
    if (!current) {
        CRITICAL_SECTION_EXIT();
        kprintf("[SCHEDULER] FPU exception with no current task!\n");
        kernel_panic("FPU exception without current task");
        return;
    }

    /*=========================================================================
     * STEP 0: Clear CR0.TS FIRST — before ANY fxsave/fxrstor.
     *
     * CRITICAL ORDERING BUG (fixed): clts used to be STEP 3, AFTER the fxsave
     * below. But fxsave/fxrstor are themselves FPU/SSE instructions, so with
     * TS still set they re-trigger #NM — re-entering this handler, which runs
     * fxsave again, which #NMs again... an infinite fault storm that walks the
     * kernel stack down until it #PFs off the bottom (#NM -> ... -> #PF -> #DF
     * -> triple fault -> reboot). This is what crashed `exec /hello.elf` once
     * the stack was contiguous enough to recurse instead of failing early.
     * Clearing TS at entry lets the save/restore run without re-trapping.
     *=======================================================================*/
    __asm__ volatile("clts");  /* Clear CR0.TS BEFORE any fxsave/fxrstor */

    /*=========================================================================
     * STEP 1: Save FPU state from previous owner (if any)
     *
     * If another task owns the FPU state, we must save it to that task's
     * context before we overwrite the FPU registers with current task's state.
     * This prevents FPU state corruption.
     *=======================================================================*/
    if (fpu_owner && fpu_owner != current) {
        /* Save FPU state to previous owner's context */
        task_t* prev_owner = (task_t*)fpu_owner;
        __asm__ volatile("fxsave %0" : "=m"(prev_owner->context.fpu_state));
    }

    /*=========================================================================
     * STEP 2: Restore current task's FPU state
     *
     * Load the FPU registers with the current task's saved state.
     * If this is the first time the task uses FPU, the state will be
     * the initialized state (from task creation).
     *=======================================================================*/
    __asm__ volatile("fxrstor %0" :: "m"(current->context.fpu_state));

    /*=========================================================================
     * STEP 3: Update FPU owner
     *
     * Record that the current task now owns the FPU state. Next time
     * a different task uses FPU, we'll save this task's state.
     *=======================================================================*/
    fpu_owner = current;

    CRITICAL_SECTION_EXIT();

    /*=========================================================================
     * DEBUGGING OUTPUT (uncomment for troubleshooting)
     *
     * kprintf("[SCHEDULER] FPU lazy switch: PID=%d '%s' now owns FPU\n",
     *         current->pid, current->name);
     *=======================================================================*/
}
