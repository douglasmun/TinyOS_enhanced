/*=============================================================================
 * wait_queue.h - Wait Queue Infrastructure for Task Blocking/Waking
 *=============================================================================
 * This module provides the sleep/wake mechanism that allows tasks to block
 * efficiently instead of busy-waiting. Wait queues are used by:
 * - Pipes (waiting for data or space)
 * - Network sockets (waiting for connections or data)
 * - Keyboard input (waiting for user input)
 * - Timers (sleeping for a specific duration)
 *
 * SECURITY BENEFITS:
 * - Eliminates CPU waste from busy-wait loops
 * - Prevents silent data loss in pipes (proper blocking instead of truncation)
 * - Mitigates DoS attacks from resource exhaustion
 * - Improves system responsiveness under load
 *
 * USAGE PATTERN:
 *
 * // In a blocking operation (e.g., reading from empty pipe):
 * CRITICAL_SECTION_ENTER();
 * while (condition_not_met) {
 *     wait_queue_sleep(&queue);  // Blocks current task, releases lock
 *     CRITICAL_SECTION_ENTER();  // Re-acquire lock after wakeup
 * }
 * // Condition is now met, do work
 * CRITICAL_SECTION_EXIT();
 *
 * // In an unblocking operation (e.g., writing data to pipe):
 * CRITICAL_SECTION_ENTER();
 * // Make data available
 * wait_queue_wakeup(&queue);  // Wake one waiting task
 * CRITICAL_SECTION_EXIT();
 *
 *=============================================================================*/
#pragma once

#include "process.h"
#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * WAIT QUEUE DATA STRUCTURE
 *=============================================================================*/

/**
 * @brief Wait queue for blocking/waking tasks
 *
 * A wait queue maintains a list of tasks that are blocked waiting for
 * a specific event or resource. Tasks can be added to the queue when
 * they need to block, and removed when the event occurs.
 *
 * THREAD SAFETY:
 * - All operations must be called with interrupts disabled (CRITICAL_SECTION)
 * - The scheduler ensures atomicity of sleep/wake operations
 *
 * IMPLEMENTATION NOTES:
 * - Fixed-size array for simplicity (no dynamic allocation)
 * - Simple FIFO wakeup order (first blocked task wakes first)
 * - Maximum waiting tasks limited by MAX_TASKS
 */
typedef struct wait_queue {
    task_t* waiting_tasks[MAX_TASKS];  /* Array of task pointers */
    int count;                          /* Number of waiting tasks */
} wait_queue_t;

/*=============================================================================
 * FUNCTION PROTOTYPES
 *=============================================================================*/

/**
 * @brief Initialize a wait queue
 *
 * @param wq Pointer to wait queue to initialize
 *
 * This must be called before using any wait queue.
 * Sets count to 0 and clears the waiting_tasks array.
 */
void wait_queue_init(wait_queue_t* wq);

/**
 * @brief Block current task on a wait queue
 *
 * @param wq Pointer to wait queue
 *
 * This function:
 * 1. Adds current task to the wait queue
 * 2. Marks task as TASK_STATE_BLOCKED
 * 3. Removes task from scheduler ready queue
 * 4. Yields CPU to next task (does not return until woken)
 *
 * CRITICAL SECTION BEHAVIOR:
 * - Caller MUST hold critical section when calling this
 * - This function will RELEASE the critical section before yielding
 * - When task wakes up, critical section is NOT held (caller must re-acquire)
 *
 * USAGE:
 * CRITICAL_SECTION_ENTER();
 * while (!data_available) {
 *     wait_queue_sleep(&queue);
 *     CRITICAL_SECTION_ENTER();  // Must re-acquire after wakeup
 * }
 * // Work with data
 * CRITICAL_SECTION_EXIT();
 *
 * SECURITY NOTE:
 * - Properly releases locks before yielding (prevents deadlocks)
 * - Re-checks condition after wakeup (prevents TOCTOU races)
 */
void wait_queue_sleep(wait_queue_t* wq);

/**
 * @brief Wake up the first task in the wait queue
 *
 * @param wq Pointer to wait queue
 *
 * This function:
 * 1. Removes first task from wait queue (FIFO order)
 * 2. Marks task as TASK_STATE_READY
 * 3. Adds task back to scheduler ready queue
 *
 * If queue is empty, this is a no-op (safe to call spuriously).
 *
 * CRITICAL SECTION BEHAVIOR:
 * - Caller MUST hold critical section when calling this
 * - Woken task will NOT run immediately (runs on next schedule)
 *
 * USAGE:
 * CRITICAL_SECTION_ENTER();
 * // Make resource available
 * wait_queue_wakeup(&queue);  // Wake one waiter
 * CRITICAL_SECTION_EXIT();
 *
 * SECURITY NOTE:
 * - Atomic wakeup prevents lost wakeups
 * - FIFO order prevents starvation
 */
void wait_queue_wakeup(wait_queue_t* wq);

/**
 * @brief Wake up all tasks in the wait queue
 *
 * @param wq Pointer to wait queue
 *
 * This function:
 * 1. Removes ALL tasks from wait queue
 * 2. Marks each as TASK_STATE_READY
 * 3. Adds each back to scheduler ready queue
 *
 * Useful for broadcast events (e.g., signal handlers, condition broadcasts).
 *
 * CRITICAL SECTION BEHAVIOR:
 * - Caller MUST hold critical section when calling this
 * - Woken tasks will NOT run immediately (run on next schedule)
 *
 * USAGE:
 * CRITICAL_SECTION_ENTER();
 * // Broadcast event
 * wait_queue_wakeup_all(&queue);  // Wake all waiters
 * CRITICAL_SECTION_EXIT();
 *
 * SECURITY NOTE:
 * - Prevents indefinite blocking on broadcast events
 * - All waiters re-check condition (prevents spurious wakeups)
 */
void wait_queue_wakeup_all(wait_queue_t* wq);

/**
 * @brief Get number of tasks waiting on queue
 *
 * @param wq Pointer to wait queue
 * @return Number of tasks in wait queue
 *
 * Useful for debugging and monitoring.
 * Caller should hold critical section for accurate count.
 */
int wait_queue_count(const wait_queue_t* wq);

/**
 * @brief Check if wait queue is empty
 *
 * @param wq Pointer to wait queue
 * @return true if no tasks waiting, false otherwise
 *
 * Caller should hold critical section for accurate result.
 */
bool wait_queue_is_empty(const wait_queue_t* wq);

/*=============================================================================
 * SCHEDULER INTEGRATION
 *=============================================================================
 * These functions are declared in scheduler.h but documented here for reference.
 * They are called internally by wait_queue_sleep() and wait_queue_wakeup().
 *
 * void scheduler_block_task(task_t* task);
 * - Remove task from ready queue and mark as BLOCKED
 *
 * void scheduler_wakeup_task(task_t* task);
 * - Add task back to ready queue and mark as READY
 *=============================================================================*/
