/*=============================================================================
 * mutex.h - Mutex Synchronization Primitive
 *=============================================================================
 * STATUS: Production-ready (v1.13)
 *
 * FEATURES:
 * - Mutual exclusion for shared resources
 * - Thread blocking/waking via wait queues
 * - Ownership tracking (only owner can unlock)
 * - Priority inheritance to prevent priority inversion
 * - Deadlock detection support
 * - Recursive mutex support (optional)
 *
 * USAGE:
 *   mutex_t lock;
 *   mutex_init(&lock);
 *   mutex_lock(&lock);
 *   // ... critical section ...
 *   mutex_unlock(&lock);
 *
 * SECURITY CONSIDERATIONS:
 * - Only the owning thread can unlock a mutex
 * - Prevents race conditions on shared resources
 * - Integrates with scheduler for proper blocking
 *=============================================================================*/
#pragma once

#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * CONSTANTS
 *=============================================================================*/

#define MUTEX_MAX_WAITERS   16   /* Maximum threads waiting on one mutex */

/*=============================================================================
 * MUTEX FLAGS
 *=============================================================================*/

#define MUTEX_FLAG_RECURSIVE   0x01  /* Allow same thread to lock multiple times */
#define MUTEX_FLAG_PRIORITY_INH 0x02  /* Enable priority inheritance */

/*=============================================================================
 * DATA STRUCTURES
 *=============================================================================*/

/**
 * Mutex structure
 */
typedef struct {
    volatile bool locked;           /* Is the mutex currently locked? */
    uint32_t owner_pid;             /* PID of the thread that owns the lock */
    uint32_t lock_count;            /* For recursive mutexes */
    uint32_t waiters[MUTEX_MAX_WAITERS]; /* PIDs waiting for this mutex */
    uint32_t num_waiters;           /* Number of waiting threads */
    uint8_t flags;                  /* Mutex flags (recursive, etc.) */
    const char* name;               /* For debugging */
} mutex_t;

/*=============================================================================
 * FUNCTION PROTOTYPES
 *=============================================================================*/

/**
 * @brief Initialize a mutex
 * @param mutex Mutex to initialize
 * @param name Debug name (can be NULL)
 * @param flags Mutex flags (MUTEX_FLAG_*)
 */
void mutex_init(mutex_t* mutex, const char* name, uint8_t flags);

/**
 * @brief Acquire (lock) a mutex
 * @param mutex Mutex to lock
 * @return 0 on success, -1 on error
 *
 * If the mutex is already locked by another thread, the calling thread
 * will be blocked until the mutex becomes available.
 */
int mutex_lock(mutex_t* mutex);

/**
 * @brief Try to acquire a mutex without blocking
 * @param mutex Mutex to try locking
 * @return true if acquired, false if already locked
 */
bool mutex_trylock(mutex_t* mutex);

/**
 * @brief Release (unlock) a mutex
 * @param mutex Mutex to unlock
 * @return 0 on success, -1 on error (not owner)
 *
 * Only the thread that locked the mutex can unlock it.
 */
int mutex_unlock(mutex_t* mutex);

/**
 * @brief Check if a mutex is currently locked
 * @param mutex Mutex to check
 * @return true if locked, false if unlocked
 */
bool mutex_is_locked(const mutex_t* mutex);

/**
 * @brief Get the PID of the mutex owner
 * @param mutex Mutex to query
 * @return Owner PID, or 0 if unlocked
 */
uint32_t mutex_get_owner(const mutex_t* mutex);

/**
 * @brief Destroy a mutex
 * @param mutex Mutex to destroy
 *
 * WARNING: Should only be called when no threads are waiting.
 */
void mutex_destroy(mutex_t* mutex);

/**
 * @brief Print mutex status (for debugging)
 * @param mutex Mutex to print
 */
void mutex_debug_print(const mutex_t* mutex);

/*=============================================================================
 * DEADLOCK DETECTION
 *=============================================================================*/

/**
 * @brief Check for potential deadlocks
 * @return Number of potential deadlocks detected
 */
int mutex_detect_deadlocks(void);
