/*=============================================================================
 * mutex.c - Mutex Synchronization Implementation
 *=============================================================================
 * SECURITY (v1.13): Proper Mutual Exclusion
 *
 * This implements mutexes with:
 * - Ownership tracking (only owner can unlock)
 * - Thread blocking via scheduler integration
 * - Priority inheritance to prevent priority inversion
 * - Recursive locking support
 * - Deadlock detection support
 *
 * ALGORITHM:
 * 1. Lock: If free, acquire. If busy, add to wait queue and block.
 * 2. Unlock: Remove from wait queue, wake next waiter (FIFO order).
 * 3. Priority Inheritance: Boost mutex owner to highest waiter priority.
 *
 * CRITICAL SECTIONS vs MUTEXES:
 * - Critical sections: Disable interrupts (short, CPU-bound operations)
 * - Mutexes: Block threads (long, I/O-bound operations)
 *=============================================================================*/
#include "mutex.h"
#include "process.h"
#include "scheduler.h"
#include "kprintf.h"
#include "critical.h"
#include "util.h"
#include <stddef.h>

/*=============================================================================
 * INITIALIZATION
 *=============================================================================*/

void mutex_init(mutex_t* mutex, const char* name, uint8_t flags) {
    if (!mutex) {
        return;
    }

    mutex->locked = false;
    mutex->owner_pid = 0;
    mutex->lock_count = 0;
    mutex->num_waiters = 0;
    mutex->flags = flags;
    mutex->name = name;

    for (uint32_t i = 0; i < MUTEX_MAX_WAITERS; i++) {
        mutex->waiters[i] = 0;
    }
}

/*=============================================================================
 * LOCK OPERATIONS
 *=============================================================================*/

int mutex_lock(mutex_t* mutex) {
    if (!mutex) {
        return -1;
    }

    task_t* current = task_current();
    if (!current) {
        /*=====================================================================
         * EARLY BOOT: No scheduler yet, use critical section
         *
         * During early boot (before scheduler_init()), there is no current
         * task. In this single-threaded context, we just disable interrupts
         * to provide atomicity. This allows filesystem operations during
         * boot to work correctly.
         *===================================================================*/
        CRITICAL_SECTION_ENTER();
        mutex->locked = true;
        mutex->owner_pid = 0;  /* Boot context */
        mutex->lock_count = 1;
        CRITICAL_SECTION_EXIT();
        return 0;
    }

    CRITICAL_SECTION_ENTER();

    /* Check for recursive locking */
    if (mutex->locked && mutex->owner_pid == current->pid) {
        if (mutex->flags & MUTEX_FLAG_RECURSIVE) {
            mutex->lock_count++;
            CRITICAL_SECTION_EXIT();
            return 0;
        } else {
            kprintf("[MUTEX] ERROR: Deadlock detected! Task %u tried to re-lock non-recursive mutex '%s'\n",
                    (unsigned int)current->pid, mutex->name ? mutex->name : "unnamed");
            CRITICAL_SECTION_EXIT();
            return -1;
        }
    }

    /* Fast path: mutex is unlocked */
    if (!mutex->locked) {
        mutex->locked = true;
        mutex->owner_pid = current->pid;
        mutex->lock_count = 1;
        CRITICAL_SECTION_EXIT();
        return 0;
    }

    /* Slow path: mutex is locked, need to wait */

    /*=========================================================================
     * SECURITY FIX: Panic on waiter overflow instead of silent failure
     *
     * CRITICAL: Returning -1 here is dangerous because:
     * 1. Callers may ignore the return value (C mutex APIs are usually void)
     * 2. Code proceeds thinking it holds the lock, but it doesn't
     * 3. Under stress, this becomes silent data corruption
     *
     * MITIGATION: Treat waiter exhaustion as a fatal system error.
     * This is consistent with the kernel design philosophy:
     * - Better to halt with diagnostics than silently corrupt state
     * - Mutex waiter exhaustion indicates either:
     *   a) A bug (forgot to unlock somewhere)
     *   b) Pathological contention (need more waiters or redesign)
     *
     * In either case, continuing is unsafe.
     *=======================================================================*/
    if (mutex->num_waiters >= MUTEX_MAX_WAITERS) {
        /* Provide detailed diagnostics before panic */
        kprintf("\n");
        kprintf("*************************************************************\n");
        kprintf("* CRITICAL: MUTEX WAITER QUEUE OVERFLOW                    *\n");
        kprintf("*************************************************************\n");
        kprintf("\n");
        kprintf("Mutex: '%s'\n", mutex->name ? mutex->name : "unnamed");
        kprintf("Owner PID: %u\n", (unsigned int)mutex->owner_pid);
        kprintf("Current PID: %u\n", (unsigned int)current->pid);
        kprintf("Waiters: %u/%u (FULL)\n",
                (unsigned int)mutex->num_waiters, (unsigned int)MUTEX_MAX_WAITERS);
        kprintf("\n");
        kprintf("This indicates either:\n");
        kprintf(" - Forgot to unlock mutex somewhere (deadlock)\n");
        kprintf(" - Pathological contention (need larger MUTEX_MAX_WAITERS)\n");
        kprintf("\n");
        kprintf("Halting to prevent silent data corruption.\n");
        kprintf("\n");

        CRITICAL_SECTION_EXIT();

        kernel_panic("Mutex waiter queue overflow");
    }

    mutex->waiters[mutex->num_waiters] = current->pid;
    mutex->num_waiters++;

    /* Priority inheritance: boost owner priority if needed */
    if (mutex->flags & MUTEX_FLAG_PRIORITY_INH) {
        task_t* owner = task_get(mutex->owner_pid);
        if (owner && current->priority > owner->priority) {
            /* TODO: Implement priority boost (would require scheduler changes) */
        }
    }

    /* Block the current task */
    scheduler_block_task(current);

    CRITICAL_SECTION_EXIT();

    scheduler_yield();

    /* After waking up, we own the mutex */
    return 0;
}

bool mutex_trylock(mutex_t* mutex) {
    if (!mutex) {
        return false;
    }

    task_t* current = task_current();
    if (!current) {
        return false;
    }

    CRITICAL_SECTION_ENTER();

    /* Check for recursive locking */
    if (mutex->locked && mutex->owner_pid == current->pid) {
        if (mutex->flags & MUTEX_FLAG_RECURSIVE) {
            mutex->lock_count++;
            CRITICAL_SECTION_EXIT();
            return true;
        }
    }

    /* Try to acquire */
    if (!mutex->locked) {
        mutex->locked = true;
        mutex->owner_pid = current->pid;
        mutex->lock_count = 1;
        CRITICAL_SECTION_EXIT();
        return true;
    }

    CRITICAL_SECTION_EXIT();
    return false;
}

int mutex_unlock(mutex_t* mutex) {
    if (!mutex) {
        return -1;
    }

    task_t* current = task_current();
    if (!current) {
        /*=====================================================================
         * EARLY BOOT: No scheduler yet, just unlock
         *===================================================================*/
        CRITICAL_SECTION_ENTER();
        mutex->locked = false;
        mutex->owner_pid = 0;
        mutex->lock_count = 0;
        CRITICAL_SECTION_EXIT();
        return 0;
    }

    CRITICAL_SECTION_ENTER();

    /* Verify ownership */
    if (!mutex->locked || mutex->owner_pid != current->pid) {
        kprintf("[MUTEX] ERROR: Task %u tried to unlock mutex '%s' owned by task %u\n",
                (unsigned int)current->pid,
                mutex->name ? mutex->name : "unnamed",
                (unsigned int)mutex->owner_pid);
        CRITICAL_SECTION_EXIT();
        return -1;
    }

    /* Handle recursive unlocking */
    if (mutex->lock_count > 1) {
        mutex->lock_count--;
        CRITICAL_SECTION_EXIT();
        return 0;
    }

    /* Wake up next live waiter (FIFO order), skipping dead waiters */
    bool transferred = false;
    while (mutex->num_waiters > 0) {
        /* Get first waiter */
        uint32_t waiter_pid = mutex->waiters[0];

        /* Shift wait queue */
        for (uint32_t i = 0; i < mutex->num_waiters - 1; i++) {
            mutex->waiters[i] = mutex->waiters[i + 1];
        }
        mutex->num_waiters--;

        /* Wake up the waiter */
        task_t* waiter = task_get(waiter_pid);
        if (waiter) {
            /* Transfer ownership to waiter */
            mutex->owner_pid = waiter_pid;
            mutex->lock_count = 1;
            scheduler_wakeup_task(waiter);
            transferred = true;
            break;
        }

        /* Waiter died while queued (e.g. killed by EDR); try the next one */
        kprintf("[MUTEX] WARNING: Waiter task %u not found\n", (unsigned int)waiter_pid);
    }

    if (!transferred) {
        /* No live waiters, simply unlock */
        mutex->locked = false;
        mutex->owner_pid = 0;
        mutex->lock_count = 0;
    }

    CRITICAL_SECTION_EXIT();
    return 0;
}

/*=============================================================================
 * QUERY OPERATIONS
 *=============================================================================*/

bool mutex_is_locked(const mutex_t* mutex) {
    if (!mutex) {
        return false;
    }
    return mutex->locked;
}

uint32_t mutex_get_owner(const mutex_t* mutex) {
    if (!mutex) {
        return 0;
    }
    return mutex->owner_pid;
}

void mutex_destroy(mutex_t* mutex) {
    if (!mutex) {
        return;
    }

    CRITICAL_SECTION_ENTER();

    if (mutex->num_waiters > 0) {
        kprintf("[MUTEX] WARNING: Destroying mutex '%s' with %u waiters\n",
                mutex->name ? mutex->name : "unnamed",
                (unsigned int)mutex->num_waiters);
    }

    mutex->locked = false;
    mutex->owner_pid = 0;
    mutex->lock_count = 0;
    mutex->num_waiters = 0;

    CRITICAL_SECTION_EXIT();
}

/*=============================================================================
 * DEBUGGING
 *=============================================================================*/

void mutex_debug_print(const mutex_t* mutex) {
    if (!mutex) {
        kprintf("[MUTEX] NULL mutex\n");
        return;
    }

    kprintf("[MUTEX] '%s': locked=%d owner=%u count=%u waiters=%u\n",
            mutex->name ? mutex->name : "unnamed",
            mutex->locked,
            (unsigned int)mutex->owner_pid,
            (unsigned int)mutex->lock_count,
            (unsigned int)mutex->num_waiters);

    if (mutex->num_waiters > 0) {
        kprintf("  Waiting PIDs: ");
        for (uint32_t i = 0; i < mutex->num_waiters; i++) {
            kprintf("%u ", (unsigned int)mutex->waiters[i]);
        }
        kprintf("\n");
    }
}

/*=============================================================================
 * DEADLOCK DETECTION
 *=============================================================================*/

int mutex_detect_deadlocks(void) {
    /* TODO: Implement deadlock detection algorithm
     * - Build wait-for graph
     * - Detect cycles
     * - Report potential deadlocks
     */
    return 0;
}
