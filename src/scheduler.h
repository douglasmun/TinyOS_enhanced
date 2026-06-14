/*=============================================================================
 * scheduler.h - Task Scheduler Interface
 *=============================================================================*/
#pragma once

#include "process.h"
#include <stdint.h>
#include <stdbool.h>

/* Forward declaration for interrupt-based scheduling */
struct interrupt_regs;

/*=============================================================================
 * FUNCTION PROTOTYPES
 *=============================================================================*/

/**
 * @brief Initialize the scheduler
 */
void scheduler_init(void);

/**
 * @brief Add a task to the ready queue
 * @param task Pointer to task to add
 */
void scheduler_add_task(task_t* task);

/**
 * @brief Remove a task from the ready queue
 * @param task Pointer to task to remove
 */
void scheduler_remove_task(task_t* task);

/**
 * @brief Start the scheduler (begins multitasking)
 * This function does not return - it switches to the first task
 */
void scheduler_start(void) __attribute__((noreturn));

/**
 * @brief Update time slices (called by timer interrupt)
 * This does NOT perform context switches from interrupt context
 */
void scheduler_tick(void);

/**
 * @brief Schedule next task (called by timer interrupt)
 * This performs the actual context switch
 */
void scheduler_schedule(void);

/**
 * @brief Yield CPU to next task
 * Current task gives up its remaining time slice
 */
void scheduler_yield(void);

/**
 * @brief Get the currently running task
 * @return Pointer to current task, or NULL if no task is running
 */
task_t* scheduler_get_current_task(void);

/**
 * @brief Print scheduler statistics
 */
void scheduler_stats(void);

/**
 * @brief Get all tasks in the system
 * @param tasks_out Pointer to receive array of task pointers
 * @return Number of tasks found
 */
int scheduler_get_all_tasks(task_t*** tasks_out);

/**
 * @brief Perform preemptive context switch from interrupt handler
 * This function modifies the interrupt stack frame to switch tasks.
 * When it returns and iret executes, the CPU restores the modified state,
 * effectively switching to a different task. This is true preemptive scheduling.
 *
 * @param regs Pointer to interrupt register state (will be modified)
 */
void scheduler_schedule_from_interrupt(struct interrupt_regs* regs);

/**
 * @brief Block a task (remove from ready queue, mark as BLOCKED)
 * Used by wait queues to put tasks to sleep
 *
 * @param task Task to block
 *
 * SECURITY: Caller MUST hold critical section (interrupts disabled)
 */
void scheduler_block_task(task_t* task);

/**
 * @brief Wake up a blocked task (mark as READY, add to ready queue)
 * Used by wait queues to wake up sleeping tasks
 *
 * @param task Task to wake up
 *
 * SECURITY: Caller MUST hold critical section (interrupts disabled)
 */
void scheduler_wakeup_task(task_t* task);

/**
 * @brief Handle lazy FPU switching on Device Not Available exception (#NM)
 * Called from exception handler when a task tries to use FPU/SSE after CR0.TS was set
 *
 * ALGORITHM:
 * 1. If another task owns FPU, save its state (fxsave)
 * 2. Restore current task's FPU state (fxrstor)
 * 3. Clear CR0.TS to allow FPU use
 * 4. Update FPU owner to current task
 *
 * SECURITY FIX (Issue 5.3): Lazy FPU Switching Optimization
 */
void scheduler_handle_fpu_exception(void);
