/*=============================================================================
 * process.c - Process Management Implementation
 *=============================================================================*/
#include "process.h"
#include "kprintf.h"
#include "util.h"
#include "pmm.h"
#include "paging.h"
#include "scheduler.h"
#include "pit.h"
#include "stdio.h"
#include "aslr.h"    /* For stack randomization */
#include "critical.h" /* For CRITICAL_SECTION macros (Issue 5.1) */
#include "wait_queue.h" /* For wait_queue_remove_task() on external kill */
#include "syscall.h"    /* For waitpid_notify_death() on external kill */
#include "vfs.h"     /* For capability flags (CAP_ALL, etc.) - EDR Phase 1 */
#include "errno.h"   /* For -EBADF/-EMFILE from the fd table helpers */
#include "edr_behavioral.h"  /* EDR Phase 2: Behavioral detection */
#include "edr_advanced.h"    /* EDR Phase 3: Advanced detection */
#include "ramfs.h"   /* For ramfs_mkdir() - per-process private /tmp */
#include "crypto.h"  /* For csprng_random_bytes() - crypto-random tmp names */

/*=============================================================================
 * EXTERNAL VARIABLES
 *=============================================================================*/
extern uint32_t* page_directory;  // From paging.c
extern uint16_t user_code_selector;  // From gdt.c
extern uint16_t user_data_selector;  // From gdt.c

/*=============================================================================
 * FORWARD DECLARATIONS
 *=============================================================================*/
/* safe_strcpy is provided by util.h */

/*=============================================================================
 * GLOBAL VARIABLES
 *=============================================================================*/
static task_t tasks[MAX_TASKS];
static task_t* current_task = NULL;
/* PHASE 7: next_pid removed - now using crypto-random PID allocation */

/*=============================================================================
 * PID ALLOCATION OPTIMIZATION: Free Slot Bitmap
 *
 * PERFORMANCE: O(1) free slot finding using bit scan forward (bsf) instruction
 * Each bit represents a task slot: 1 = free, 0 = in use
 * MAX_TASKS = 32, so we use a single uint32_t bitmap
 *=============================================================================*/
static uint32_t free_slot_bitmap = 0xFFFFFFFF;  // All slots initially free

/*=============================================================================
 * SECURITY (v1.12): PID Generation Counters
 *
 * ISSUE: PID reuse vulnerability - when a process exits and its slot is
 * immediately reused, the new process can inherit unintended resources
 * (shared memory, IPC, signals) keyed only by PID.
 *
 * FIX: Each task slot has a generation counter that increments on reuse.
 * Unique process identifier = (PID, Generation) tuple prevents confusion.
 *=============================================================================*/
static uint32_t slot_generations[MAX_TASKS] = {0};  // Generation per slot

/*=============================================================================
 * SECURITY FIX (Issue 4.1): Task Creation Rate Limiting (DoS Prevention)
 *
 * CRITICAL: Without rate limiting, a malicious or buggy process can create
 * tasks in a tight loop (fork bomb), exhausting:
 * - All MAX_TASKS slots → legitimate processes can't fork
 * - All available memory → system OOM
 * - CPU resources → system becomes unresponsive
 *
 * FIX: Token bucket rate limiter - allows burst of tasks but limits sustained
 * creation rate. This is defense-in-depth for future fork() syscall.
 *
 * PARAMETERS:
 * - TASK_RATE_LIMIT_TOKENS: Max burst size (10 tasks)
 * - TASK_RATE_LIMIT_REFILL_PER_SEC: Sustained rate (5 tasks/second)
 * - TASK_RATE_LIMIT_REFILL_INTERVAL: Refill every 100ms (1/10 second)
 *
 * ALGORITHM: Token bucket
 * - Start with full bucket (10 tokens)
 * - Each task creation consumes 1 token
 * - Refill 0.5 tokens every 100ms (5 tokens/second sustained)
 * - If bucket empty, task creation fails with -EAGAIN
 *
 * BYPASS: Boot-time task creation (first 5 seconds) bypasses rate limit
 * to allow kernel to create Shell, SSHServer, Idle tasks during init.
 *=============================================================================*/
#define TASK_RATE_LIMIT_TOKENS 10           // Max burst (initial tokens)
#define TASK_RATE_LIMIT_REFILL_PER_SEC 5    // Sustained rate (tokens/sec)
#define TASK_RATE_LIMIT_REFILL_INTERVAL 100 // Refill every 100ms (ticks)
#define TASK_RATE_LIMIT_BOOT_GRACE_TICKS 500 // 5 seconds grace period (100 ticks/sec)

static uint32_t task_rate_tokens = TASK_RATE_LIMIT_TOKENS;  // Current tokens
static uint32_t task_rate_last_refill = 0;  // Last refill timestamp (ticks)

/*=============================================================================
 * CONCURRENT TASK LIMITS (complements the rate limiter above)
 *
 * The token bucket limits the RATE of task creation, not the QUANTITY of live
 * tasks one user holds. At 5/sec a user fills all MAX_TASKS slots in ~5s and
 * the slots then STAY full -- the bucket refills but the table never drains.
 * `/shell.elf &` in a loop is enough, and the ring-3 shell has no recursion
 * guard (nor should it: nesting a shell is legitimate).
 *
 * The task table is GLOBAL, so exhausting it starves the kernel's own tasks
 * and blocks root from logging in to kill the offender -- recovery needs a
 * reboot. Two limits close that:
 *
 * - USER_MAX_CONCURRENT_TASKS: per-uid ceiling. Bounds the damage regardless
 *   of HOW the tasks were spawned (nesting, `&`, or a program calling spawn in
 *   a loop), which a recursion-depth limit would not -- depth is not the
 *   vector, quantity is.
 *
 * - TASK_ROOT_RESERVED_SLOTS: slots no non-root task may take. This is what
 *   makes the DoS RECOVERABLE rather than terminal: root can still log in and
 *   `kill`. Without it a per-user cap alone still lets several unprivileged
 *   users between them fill the table.
 *
 * Both apply to USER tasks only. Kernel tasks (idle, timer bottom-half, EDR
 * daemon) are created by the kernel itself and must never be refused; they are
 * also what the reserve exists to protect.
 *
 * uid 0 is exempt from the per-user cap: a root fork bomb is not a privilege
 * boundary being crossed, and capping root would be the thing that stops the
 * administrator from cleaning up.
 *===========================================================================*/
#define USER_MAX_CONCURRENT_TASKS 10  // Live tasks one non-root uid may hold
#define TASK_ROOT_RESERVED_SLOTS 4    // Slots reserved for root/kernel use

/*=============================================================================
 * FUNCTION: task_count_live_for_uid
 * PURPOSE: Count live tasks owned by a uid (for the per-user concurrent cap)
 *
 * Counts by REAL uid, not euid: euid can be dropped and raised by a setuid
 * program, so a cap keyed on it could be evaded by lowering euid before each
 * spawn. Real uid is the account that owns the resource.
 *
 * ZOMBIE tasks are counted deliberately -- a zombie still occupies its slot
 * until reaped, so excluding them would let a user hold the table full of
 * unreaped children while appearing to be under the cap.
 *===========================================================================*/
static uint32_t task_count_live_for_uid(uint16_t uid) {
    uint32_t count = 0;

    for (int i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].pid == 0) {
            continue;  // Never-used or fully released slot
        }
        if (tasks[i].state == TASK_STATE_TERMINATED) {
            continue;  // Slot is reusable, not held
        }
        if (tasks[i].uid == uid) {
            count++;
        }
    }

    return count;
}

/*=============================================================================
 * FUNCTION: task_visible_to_current
 * PURPOSE: The one process-visibility predicate (ps, top, SYS_PSINFO)
 *
 * POLICY: an unprivileged user sees ONLY their own processes; root sees all.
 *
 * The alternative -- everyone sees everything, as on a stock Unix -- leaks what
 * root is running to any logged-in user: process NAMES and argv are visible in
 * `ps`, so a root-run recovery or maintenance command becomes an announcement.
 * Own-only is also the conservative direction: it can be relaxed later without
 * breaking anyone, whereas tightening it afterwards would.
 *
 * Matches the kill/waitpid rule (shell_system.c cmd_kill, syscall.c
 * sys_waitpid), so what you can SEE and what you can SIGNAL are the same set --
 * a `ps` listing a process you may not kill, or a `kill` refusing a PID `ps`
 * never showed, are both worse than one consistent rule.
 *
 * euid for the privilege decision, real uid for ownership -- the convention
 * used throughout this kernel. euid is what a setuid program drops to give up
 * authority; real uid is the account that owns the resource.
 *
 * KERNEL TASKS are hidden from unprivileged users along with everything else:
 * they are uid 0. That is deliberate -- the EDR daemon's presence and the idle
 * task's timing are exactly the sort of machine state this policy withholds.
 *
 * Lives in process.c, not shell_monitor.c, because SYS_PSINFO must apply the
 * identical rule and the syscall layer should not depend on a shell module.
 *===========================================================================*/
bool task_visible_to_current(const task_t* task) {
    if (!task) {
        return false;
    }

    task_t* self = scheduler_get_current_task();
    if (!self) {
        return true;  /* No session context: kernel-internal caller, show all */
    }

    if (self->euid == 0) {
        return true;  /* root sees everything */
    }

    return task->uid == self->uid;
}

/*=============================================================================
 * FUNCTION: task_count_free_slots
 * PURPOSE: Count task slots available for allocation
 *===========================================================================*/
static uint32_t task_count_free_slots(void) {
    uint32_t count = 0;

    for (int i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].pid == 0 || tasks[i].state == TASK_STATE_TERMINATED) {
            count++;
        }
    }

    return count;
}

/*=============================================================================
 * FUNCTION: task_rate_limit_check
 * PURPOSE: Check if task creation is allowed (rate limiting)
 * RETURNS: true if allowed (token consumed), false if rate limited
 *=============================================================================*/
static bool task_rate_limit_check(void) {
    uint32_t now = pit_get_ticks();  // Get current tick count

    /*=========================================================================
     * BOOT GRACE PERIOD: Skip rate limiting during early boot
     * Allows kernel to create essential tasks (Shell, SSH, Idle) without
     * hitting rate limits. After 5 seconds, rate limiting activates.
     *=======================================================================*/
    if (now < TASK_RATE_LIMIT_BOOT_GRACE_TICKS) {
        return true;  // Allow during boot grace period
    }

    /*=========================================================================
     * TOKEN REFILL: Replenish tokens based on elapsed time
     * Refill rate: TASK_RATE_LIMIT_REFILL_PER_SEC tokens per second
     *=======================================================================*/
    uint32_t ticks_since_refill = now - task_rate_last_refill;
    if (ticks_since_refill >= TASK_RATE_LIMIT_REFILL_INTERVAL) {
        // Calculate tokens to add (fractional arithmetic to avoid overflow)
        // tokens = (ticks * REFILL_PER_SEC) / (TICKS_PER_SEC)
        // Since TICKS_PER_SEC = 100 and REFILL_INTERVAL = 100:
        // Every 100 ticks (1 second) we add REFILL_PER_SEC tokens
        /* REFILL_INTERVAL is 100 ticks and the PIT runs at 100 Hz, so one
         * "period" is exactly one second and the refill is simply
         * periods * REFILL_PER_SEC.
         *
         * This previously divided that by (1000 / REFILL_INTERVAL) == 10, which
         * made one elapsed second add (1 * 5) / 10 == 0 tokens in integer
         * arithmetic. The bucket therefore refilled ONLY when a single check
         * saw >= 2 seconds elapse, so after an initial burst of 10 the limiter
         * denied task creation far more aggressively than the documented
         * 5/sec -- a correctness bug in the limiter, not in its callers. */
        uint32_t refill_periods = ticks_since_refill / TASK_RATE_LIMIT_REFILL_INTERVAL;
        uint32_t tokens_to_add = refill_periods * TASK_RATE_LIMIT_REFILL_PER_SEC;

        task_rate_tokens += tokens_to_add;
        if (task_rate_tokens > TASK_RATE_LIMIT_TOKENS) {
            task_rate_tokens = TASK_RATE_LIMIT_TOKENS;  // Cap at max
        }

        /* Advance by whole periods only, so the leftover ticks count toward the
         * next refill. Setting this to `now` discarded them and made the
         * effective rate slower than configured. */
        task_rate_last_refill += refill_periods * TASK_RATE_LIMIT_REFILL_INTERVAL;
    }

    /*=========================================================================
     * TOKEN CONSUMPTION: Try to consume 1 token for this task creation
     *=======================================================================*/
    if (task_rate_tokens > 0) {
        task_rate_tokens--;
        return true;  // Allowed - token consumed
    }

    /*=========================================================================
     * RATE LIMITED: No tokens available
     *=======================================================================*/
    kprintf("[PROCESS] RATE LIMIT: Task creation denied (tokens exhausted)\n");
    kprintf("[PROCESS] Sustained limit: %d tasks/sec, burst: %d tasks\n",
            TASK_RATE_LIMIT_REFILL_PER_SEC, TASK_RATE_LIMIT_TOKENS);
    return false;  // Denied - rate limited
}

/*=============================================================================
 * FUNCTION: process_init
 * PURPOSE: Initialize the process management system
 *=============================================================================*/
void process_init(void) {
    kprintf("[PROCESS] Initializing process mgt.. [OK]\n");

    // Clear all task structures
    memset(tasks, 0, sizeof(tasks));

    // Mark all tasks as terminated (available)
    for (int i = 0; i < MAX_TASKS; i++) {
        tasks[i].state = TASK_STATE_TERMINATED;
        tasks[i].pid = 0;
    }

    current_task = NULL;
    /* PHASE 7: next_pid initialization removed - PIDs now crypto-random */

    // kprintf("[PROCESS] Process management initialized (max tasks: %d)\n", MAX_TASKS);
}

/*=============================================================================
 * PHASE 7: Crypto-Random PID Allocation
 *
 * TRADITIONAL UNIX/LINUX WEAKNESS:
 * - PIDs allocated sequentially (1, 2, 3, 4, ...)
 * - Attacker can predict next PID for race condition exploits
 * - Example attacks:
 *   * Create file /tmp/pid.12345, predict next process will be 12346
 *   * Race conditions in PID-based file locking
 *   * Signal injection (kill predictable PID)
 *   * /proc/[pid] race conditions
 *
 * TINYOS INNOVATION:
 * - PIDs allocated randomly using CSPRNG
 * - Range: 100-65535 (avoids low PIDs reserved for system)
 * - Collision detection with retry
 * - Unpredictable PID sequence defeats timing attacks
 *
 * SECURITY BENEFITS:
 * - PID prediction impossible (CSPRNG-based)
 * - No sequential patterns to exploit
 * - Eliminates PID-based race conditions
 * - 65435 possible PIDs provides ample space (MAX_TASKS=32)
 *
 * RETURNS: Valid PID (100-65535) on success, never fails (retries on collision)
 *=============================================================================*/
uint32_t task_alloc_pid(void) {
    /*=========================================================================
     * CRITICAL SECTION: Protect PID allocation from race conditions
     * Must be atomic to prevent two tasks from getting same PID
     * global_csprng is declared in crypto.h (already included at top of file)
     *=======================================================================*/
    CRITICAL_SECTION_ENTER();

    uint32_t pid;
    uint16_t random_val;
    int attempts = 0;
    const int MAX_ATTEMPTS = 1000;  /* Prevent infinite loop (extremely unlikely) */

    /*=========================================================================
     * CRYPTO-RANDOM PID GENERATION WITH COLLISION DETECTION
     * Loop until we find an unused PID (typically succeeds on first try)
     *=======================================================================*/
    do {
        /* Generate 16-bit random number */
        csprng_random_bytes(&global_csprng, (uint8_t*)&random_val, sizeof(random_val));

        /* Map to range 100-65535: pid = 100 + (random_val % 65436) */
        pid = 100 + (random_val % 65436);

        /* Check if PID is already in use */
        bool collision = false;
        for (int i = 0; i < MAX_TASKS; i++) {
            if (tasks[i].pid == pid && tasks[i].state != TASK_STATE_TERMINATED) {
                collision = true;
                break;
            }
        }

        if (!collision) {
            break;  /* Found unused PID */
        }

        attempts++;
        if (attempts >= MAX_ATTEMPTS) {
            /* Extremely unlikely: couldn't find free PID after 1000 attempts
             * Fall back to sequential allocation as safety measure */
            kprintf("[PROCESS] WARNING: PID allocation collision after %d attempts, "
                    "falling back to sequential\n", MAX_ATTEMPTS);

            /* Find first available PID sequentially */
            for (pid = 100; pid < 65536; pid++) {
                bool in_use = false;
                for (int i = 0; i < MAX_TASKS; i++) {
                    if (tasks[i].pid == pid && tasks[i].state != TASK_STATE_TERMINATED) {
                        in_use = true;
                        break;
                    }
                }
                if (!in_use) {
                    break;
                }
            }
            break;
        }
    } while (true);

    CRITICAL_SECTION_EXIT();

    return pid;
}

/*=============================================================================
 * SECURITY FIX (Issue 11.2): Atomic Bitmap Operations for PID Allocation
 *
 * CRITICAL RACE CONDITION: The original implementation had a vulnerable
 * read-modify-write sequence:
 *   1. Read bitmap to find free bit (BSF instruction)
 *   2. [RACE WINDOW] - NMI/IRQ can fire here
 *   3. Clear the bit to mark it used
 *
 * ATTACK SCENARIO:
 *   - Thread A finds slot 5 (reads bitmap)
 *   - [NMI] Thread B also finds slot 5 (reads same bitmap!)
 *   - Thread A clears bit 5
 *   - Thread B also clears bit 5
 *   - RESULT: Both threads allocated same PID → COLLISION
 *
 * SOLUTION: Use x86 LOCK BTS (Bit Test and Set) instruction for atomic
 * read-modify-write. This single instruction atomically:
 *   - Tests if bit is set (free)
 *   - Sets the bit (marks it used)
 *   - Returns original bit value
 * All in ONE atomic operation that cannot be interrupted.
 *
 * FALLBACK: Critical section for architectures without atomic bit ops.
 *=============================================================================*/

/**
 * @brief Atomically test and clear a bit in the bitmap (mark slot as used)
 * @param bitmap Pointer to bitmap
 * @param bit Bit index to test and clear
 * @return true if bit was set (slot was free), false if already clear (used)
 *
 * Uses x86 LOCK BTR (Bit Test and Reset) for atomic read-modify-write
 */
static inline bool atomic_test_and_clear_bit(volatile uint32_t* bitmap, int bit) {
    unsigned char was_set;

    /*=========================================================================
     * x86 LOCK BTR (Bit Test and Reset) - Atomic Read-Modify-Write
     *
     * This instruction atomically:
     * 1. Reads the bit at index 'bit' from memory
     * 2. Stores old bit value in CF (Carry Flag)
     * 3. Clears the bit in memory
     *
     * The LOCK prefix ensures atomicity across cores/interrupts.
     *=======================================================================*/
    __asm__ volatile(
        "lock btrl %2, %0\n\t"   /* Atomic bit test and reset */
        "setc %1"                 /* Store CF (old bit value) in was_set */
        : "+m"(*bitmap),          /* Read-modify-write bitmap */
          "=qm"(was_set)          /* Output: was_set = old bit value */
        : "r"(bit)                /* Input: bit index */
        : "cc", "memory"          /* Clobbers: condition codes, memory barrier */
    );

    return was_set != 0;
}

/**
 * @brief Atomically set a bit in the bitmap (mark slot as free)
 * @param bitmap Pointer to bitmap
 * @param bit Bit index to set
 *
 * Uses x86 LOCK BTS (Bit Test and Set) for atomic write
 */
static inline void atomic_set_bit(volatile uint32_t* bitmap, int bit) {
    /*=========================================================================
     * x86 LOCK BTS (Bit Test and Set) - Atomic Read-Modify-Write
     *
     * This instruction atomically sets the bit in memory. The LOCK prefix
     * ensures atomicity across cores/interrupts, preventing race conditions
     * when freeing a task slot.
     *=======================================================================*/
    __asm__ volatile(
        "lock btsl %1, %0"       /* Atomic bit test and set */
        : "+m"(*bitmap)          /* Read-modify-write bitmap */
        : "r"(bit)               /* Input: bit index */
        : "cc", "memory"         /* Clobbers: condition codes, memory barrier */
    );
}

/*=============================================================================
 * FUNCTION: task_find_free_slot
 * PURPOSE: Find a free task slot using bitmap (O(1) with atomic bit ops)
 * RETURNS: Slot index (0 to MAX_TASKS-1) on success, -1 on failure
 *
 * SECURITY FIX (Issue 11.2): Uses atomic LOCK BTR instruction to prevent
 * race condition where two threads could allocate the same PID slot.
 *=============================================================================*/
static int task_find_free_slot(void) {
    /*=========================================================================
     * ATOMIC SLOT ALLOCATION ALGORITHM:
     *
     * We iterate through all possible slots (0-31), attempting to atomically
     * claim each one. The LOCK BTR instruction ensures that only ONE thread
     * can successfully claim a given slot, even under NMI/IRQ interruption.
     *
     * This is robust against all race conditions:
     * - Thread A tries slot 5, succeeds (bit was 1, now 0)
     * - Thread B tries slot 5, FAILS (bit already 0)
     * - Thread B moves to slot 6 and tries again
     *=======================================================================*/

    for (int slot = 0; slot < MAX_TASKS; slot++) {
        /* Atomically test and clear bit - only succeeds if bit was set (free) */
        if (atomic_test_and_clear_bit(&free_slot_bitmap, slot)) {
            /* SUCCESS: We atomically claimed this slot */
            return slot;
        }
        /* FAIL: Slot already used by another thread, try next slot */
    }

    /* No free slots available */
    return -1;
}

/*=============================================================================
 * FUNCTION: task_free_slot
 * PURPOSE: Mark a task slot as free in the bitmap
 *
 * SECURITY FIX (Issue 11.2): Uses atomic LOCK BTS instruction to prevent
 * race conditions when freeing task slots.
 *
 * SECURITY (v1.12): Increments generation counter to prevent PID reuse attacks
 *=============================================================================*/
static void task_free_slot(int slot) {
    if (slot >= 0 && slot < MAX_TASKS) {
        /*=====================================================================
         * SECURITY FIX (Issue 11.2): Atomic Bitmap Update
         *
         * Use atomic LOCK BTS instruction to set the bit, preventing race
         * condition where:
         * 1. Thread A reads bitmap to check availability
         * 2. [RACE] Thread B frees a slot (sets bit)
         * 3. Thread A overwrites bitmap, losing Thread B's update
         *
         * Atomic operation ensures this cannot happen.
         *===================================================================*/

        // Increment generation counter for this slot (PID reuse defense)
        slot_generations[slot]++;

        // Atomically mark slot as free in bitmap
        atomic_set_bit(&free_slot_bitmap, slot);
    }
}

/*=============================================================================
 * FUNCTION: task_free_slot_for_task
 * PURPOSE: Free a task slot given a task pointer (PUBLIC API for scheduler)
 *=============================================================================*/
void task_free_slot_for_task(task_t* task) {
    if (!task) {
        return;
    }

    // Calculate slot index from task pointer
    // tasks array is static, so we can compute offset
    int slot = (int)(task - tasks);

    // Validate slot is within bounds
    if (slot >= 0 && slot < MAX_TASKS) {
        task_free_slot(slot);
    }
}

/*=============================================================================
 * FUNCTION: task_create_kernel
 * PURPOSE: Create a new kernel-mode task
 *=============================================================================*/
int task_create_kernel(void (*entry)(void), const char* name) {
    /*=========================================================================
     * SECURITY FIX (Issue 4.1): Rate Limiting Check
     * Prevent DoS via rapid task creation (fork bomb defense)
     *=======================================================================*/
    if (!task_rate_limit_check()) {
        kprintf("[PROCESS] ERROR: Task creation rate limited\n");
        return -1;  // Rate limited
    }

    // Find free slot
    int slot = task_find_free_slot();
    if (slot < 0) {
        kprintf("[PROCESS] ERROR: No free task slots\n");
        return -1;
    }

    task_t* task = &tasks[slot];

    // Initialize task structure
    memset(task, 0, sizeof(task_t));

    // Set task identification
    task->pid = task_alloc_pid();
    if (task->pid == 0) {
        kprintf("[PROCESS] ERROR: Failed to allocate PID (PID exhaustion)\n");
        task_free_slot(slot);
        return -1;
    }
    /* SECURITY (v1.12): Assign generation to prevent PID reuse attacks */
    task->generation = slot_generations[slot];
    /* SECURITY (v1.11): Use safe_strcpy with full buffer size */
    safe_strcpy(task->name, name, TASK_NAME_LEN);

    /*=========================================================================
     * SECURITY FEATURE: Stack Guard Pages (Stack Overflow Detection)
     *=========================================================================
     *
     * IMPLEMENTATION:
     * Each task gets:
     * - 1 guard page (4KB) marked NOT PRESENT - lowest address
     * - 4 stack pages (16KB) for actual stack use
     * Total: 5 pages (20KB) per task
     *
     * Memory Layout (addresses grow upward):
     * [Guard Page - NOT PRESENT]  <- guard_page_phys (causes page fault on access)
     * [Stack Page 1]              <- kernel_stack_phys
     * [Stack Page 2]
     * [Stack Page 3]
     * [Stack Page 4]              <- ESP points to top of this page
     *
     * SECURITY BENEFIT:
     * If stack overflows beyond 16KB, it hits the guard page and triggers
     * immediate page fault, preventing:
     * - Silent memory corruption
     * - Heap structure corruption
     * - Privilege escalation via overwritten return addresses
     *
     * DETECTION:
     * Page fault handler checks if fault address is a guard page, terminates
     * task with clear error message instead of silent corruption.
     *=======================================================================*/

    // Allocate guard page (will be marked NOT PRESENT)
    uint32_t guard_page_phys = pmm_alloc();
    if (guard_page_phys == 0) {
        kprintf("[PROCESS] ERROR: Failed to allocate guard page\n");
        task->pid = 0;  // Release PID
        task_free_slot(slot);
        return -1;
    }

    // Allocate KERNEL_TASK_STACK_PAGES for actual kernel stack (128KB usable).
    // The shell runs as a kernel task and the whole exec chain
    // (cmd_exec -> elf_load_process -> ecdsa_verify -> task_create_user ->
    // PAE setup) runs on this stack; 16 pages overflowed under ENFORCE mode.
    // CONTIGUITY FIX: one physically contiguous run (see the user-task path for
    // the full rationale — non-contiguous stack pages triple-fault on the first
    // interrupt push past a page boundary). Kernel tasks happened to dodge this
    // at boot when frames were still contiguous, but the bug was always here.
    uint32_t stack_base = pmm_alloc_contiguous(KERNEL_TASK_STACK_PAGES);
    if (stack_base == 0) {
        kprintf("[PROCESS] ERROR: Failed to allocate contiguous %d-page kernel stack\n",
                KERNEL_TASK_STACK_PAGES);
        pmm_free(guard_page_phys);
        task->pid = 0;  // Release PID
        task_free_slot(slot);
        return -1;
    }
    uint32_t stack_pages[KERNEL_TASK_STACK_PAGES];
    for (int i = 0; i < KERNEL_TASK_STACK_PAGES; i++) {
        stack_pages[i] = stack_base + (uint32_t)i * 4096;
    }

    // CRITICAL FIX: Map guard page and stack pages into page tables
    // The guard page is mapped but marked NOT PRESENT (handled below)
    // Stack pages need to be identity-mapped (virtual == physical) so they can be accessed
    map_page(guard_page_phys, guard_page_phys, PAGE_READWRITE | PAE_NX);  // Will be marked NOT PRESENT below
    for (int i = 0; i < KERNEL_TASK_STACK_PAGES; i++) {
        // Identity-map each stack page (virtual address = physical address)
        map_page(stack_pages[i], stack_pages[i], PAGE_PRESENT | PAGE_READWRITE | PAE_NX);
        // CRITICAL: Flush TLB after mapping so page is immediately accessible
        flush_tlb_single(stack_pages[i]);
    }

    /*=========================================================================
     * SECURITY FIX (Issue 6.3): Zero-Initialize Kernel Stack
     *
     * CRITICAL: New stacks may contain leftover data from previous allocations
     * including the global stack canary value (__stack_chk_guard). If an attacker
     * can read their own uninitialized stack (e.g., via uninitialized local
     * variables), they can leak the canary and defeat stack overflow protection.
     *
     * FIX: Zero the entire kernel stack before first use to prevent:
     * - Stack canary disclosure (primary concern)
     * - Information disclosure from previous kernel data
     * - Uninitialized variable exploits
     *
     * PERFORMANCE: Only done once per task creation (not per context switch),
     * so the overhead is negligible compared to the security benefit.
     *
     * NOTE: TLB must be flushed after mapping (above) before accessing pages.
     *=======================================================================*/
    for (int i = 0; i < KERNEL_TASK_STACK_PAGES; i++) {
        memset((void*)stack_pages[i], 0, 4096);
    }

    // Store physical addresses for cleanup
    task->guard_page_phys = guard_page_phys;
    task->kernel_stack_phys = stack_pages[0];  // First stack page (for compatibility)
    // No user stack for kernel tasks
    task->user_guard_page_phys = 0;
    task->user_guard_page_virt = 0;
    task->user_stack_pages = 0;  // Kernel tasks have no user stack
    for (int i = 0; i < 256; i++) {  // Max 256 pages (1MB)
        task->user_stack_pages_phys[i] = 0;
    }

    // Store all stack page addresses for proper cleanup
    for (int i = 0; i < KERNEL_TASK_STACK_PAGES; i++) {
        task->stack_pages_phys[i] = stack_pages[i];
    }

    // Stack grows downward, so point to the top of the highest stack page.
    // Guard page is at guard_page_phys, stack pages follow contiguously.
    // (The former "3 padding pages" leak here was a workaround for a 12KB
    // over-top write that was itself this exec-chain stack overflow; with a
    // 128KB stack and the NOT-PRESENT guard page below, the padding is
    // unnecessary and is removed.)
    task->kernel_stack = stack_pages[KERNEL_TASK_STACK_PAGES - 1] + 4096;

    // Mark guard page as NOT PRESENT to trigger page fault on access
    // Guard page virtual address is same as physical address (identity mapped)
    /*=========================================================================
     * DANGEROUS INVARIANT: Identity Mapping Assumption
     *
     * This code assumes kernel memory is identity-mapped (virt == phys) for
     * the first 32MB. The guard_page_phys is used directly as a virtual address
     * when calling get_page_table_entry() and flush_tlb_single().
     *
     * BREAKS IF:
     * - Kernel is moved to higher-half (e.g., 0xC0000000+)
     * - PMM allocates pages above 32MB
     * - Identity mapping is removed during refactoring
     *
     * FIX REQUIRED: Use explicit phys-to-virt translation or recursive paging
     *=======================================================================*/

    /*=========================================================================
     * CRITICAL FIX: PAE-Aware Guard Page Setup
     *
     * ISSUE: get_page_table_entry() returns NULL when PAE is active (PTEs are
     * 64-bit in PAE mode, can't be accessed via 32-bit pointer). This caused
     * guard pages to never be marked NOT PRESENT, allowing memory corruption.
     *
     * FIX: Check if PAE is active and use PAE-specific functions
     *=======================================================================*/
    if (pae_is_active()) {
        /* PAE Mode: Use 64-bit PTE functions */
        pae_pte_t* guard_pte = pae_get_pte(guard_page_phys);
        if (guard_pte) {
            /* Clear PAE_PRESENT bit while keeping PAE_READWRITE for debugging */
            *guard_pte = (guard_page_phys & PAE_FRAME_MASK) | PAE_READWRITE;  // Present=0
            flush_tlb_single(guard_page_phys);
        } else {
            kprintf("[PROCESS] WARNING: Could not get PAE PTE for guard page 0x%08x\n", guard_page_phys);
        }
    } else {
        /* Standard 32-bit Mode: Use 32-bit PTE functions */
        uint32_t* guard_pte = get_page_table_entry(guard_page_phys);
        if (guard_pte) {
            // Explicitly clear PAGE_PRESENT bit (bit 0) to make guard page inaccessible
            // Set PAGE_READWRITE to indicate this would be RW if it were present (for debugging)
            *guard_pte = (guard_page_phys & PAGE_FRAME_MASK) | PAGE_READWRITE;  // Present=0 (explicit)
            flush_tlb_single(guard_page_phys);  // Flush TLB for this page

            // Verify first stack page is still mapped after guard page manipulation
            uint32_t* first_stack_pte = get_page_table_entry(stack_pages[0]);
            if (first_stack_pte) {
                // Debug message removed to clean up boot output
                // kprintf("[PROCESS] DEBUG: First stack page PTE after guard clear: 0x%08x (Present=%d)\n",
                //         *first_stack_pte, (*first_stack_pte & 1));
            }
        } else {
            kprintf("[PROCESS] WARNING: Could not get PTE for guard page 0x%08x\n", guard_page_phys);
        }
    }

    // Set up initial CPU context
    task->context.esp = task->kernel_stack - sizeof(uint32_t);  // Leave room for return address
    task->context.ebp = task->context.esp;
    task->context.eip = (uint32_t)entry;
    task->context.eflags = 0x202;  // IF=1 (interrupts enabled), bit 1 always 1

    // Kernel segments (use GRUB's selectors since we copy GRUB's GDT)
    task->context.cs = 0x10;  // Kernel code segment (GRUB's selector)
    task->context.ds = 0x18;  // Kernel data segment
    task->context.es = 0x18;
    task->context.fs = 0x18;
    task->context.gs = 0x18;
    task->context.ss = 0x18;  // Kernel stack segment

    // CRITICAL: Initialize FPU state to clean state
    // This prevents FPU corruption when task first uses floating-point
    __asm__ volatile("fninit");  // Initialize FPU to clean state
    __asm__ volatile("fxsave %0" : "=m"(task->context.fpu_state));

    // This is a kernel task
    task->is_kernel_task = true;

    // User/Group credentials (v1.10) - Kernel tasks run as root
    task->uid = 0;   // Root user
    task->gid = 0;   // Root group
    task->euid = 0;  // Effective UID = root
    task->egid = 0;  // Effective GID = root
    task->ngroups = 0;  // No supplemental groups (v1.12)

    /*=========================================================================
     * SECURITY (EDR Phase 1): Initialize Capabilities and Syscall Filtering
     *
     * DEFAULT POLICY:
     * - Kernel tasks (uid=0): All capabilities, no syscall filtering
     * - User tasks: Default capabilities (CAP_DEFAULT), no syscall filtering by default
     *
     * Process-specific sandboxing can be applied later via edr_security.h functions
     *=======================================================================*/
    /* Kernel tasks get all capabilities (root access) */
    task->capabilities = CAP_ALL;

    /* Syscall filtering disabled by default (backward compatible) */
    task->syscall_filter_enabled = false;

    /* Initialize syscall filter to allow-all (for when filtering is enabled) */
    for (int i = 0; i < SYSCALL_FILTER_SIZE; i++) {
        task->syscall_filter[i] = 0xFFFFFFFF;  // All syscalls allowed initially
    }

    // Use current page directory (kernel space) - MUST use physical address for CR3
    task->page_directory = get_kernel_page_directory();

    // Scheduling parameters
    task->priority = PRIORITY_NORMAL;  // Default priority
    task->base_time_slice = 10;  // 10 timer ticks base
    task->time_slice = task->base_time_slice;  // Will be adjusted by priority
    task->ticks_remaining = task->time_slice;
    task->total_ticks = 0;

    // Sleep management
    task->wake_tick = 0;

    // Exit status
    task->exit_status = 0;
    task->blocked_on_wq = NULL;

    // Initialize per-process stream context (stdin/stdout/stderr)
    streams_init(&task->streams);

    // Initialize the per-process file descriptor table (fds 3+)
    task_fdtable_init(task);

    // Start at the default drive root; sys_spawn overwrites this with the
    // parent's cwd, so a child inherits rather than resetting to "D:/".
    task_cwd_init(task);

    // Initialize FD tracking (v1.11)
    task->open_fd_count = 0;

    /*=========================================================================
     * SECURITY (EDR Phase 2): Initialize Behavioral Detection State
     *
     * Initialize syscall history tracking and anomaly detection for this
     * process. Detection is enabled by default for all processes.
     *=======================================================================*/
    edr_behavioral_init(task);

    /*=========================================================================
     * SECURITY (EDR Phase 3): Initialize Advanced Detection State
     *
     * Allocate and initialize advanced detection modules (memory inspection,
     * network flow analysis, file integrity monitoring, crypto monitoring).
     * Advanced detection is enabled by default for all processes.
     *=======================================================================*/
    task->edr_advanced = (edr_advanced_state_t*)pmm_alloc();  /* Allocate 4KB page */
    if (task->edr_advanced) {
        edr_advanced_init_process(task);
    }

    // Set state to ready
    task->state = TASK_STATE_READY;

    kprintf("[PROCESS] Created task PID=%d '%s'. [OK]\n",
            task->pid, task->name);
    kprintf("[PROCESS]   Stack: 0x%08x (ASLR randomized)\n",
            task->user_stack);

    return task->pid;
}

/*=============================================================================
 * FUNCTION: task_create_user
 * PURPOSE: Create a new user-mode task (Ring 3) with default stack size
 *=============================================================================*/
int task_create_user(uint32_t entry, const char* name) {
    return task_create_user_ex(entry, name, USER_STACK_LARGE);
}

/*=============================================================================
 * FUNCTION: task_create_user_ex
 * PURPOSE: Create a new user-mode task (Ring 3) with configurable stack size
 *
 * Thin wrapper over task_create_user_argv() with an empty argument vector, so
 * a task created this way sees argc == 0 and argv[0] == NULL. Kept as its own
 * entry point because most callers have no arguments to pass.
 *=============================================================================*/
int task_create_user_ex(uint32_t entry, const char* name, uint16_t stack_pages) {
    return task_create_user_argv(entry, name, stack_pages, 0, NULL);
}

/*=============================================================================
 * FUNCTION: task_create_user_argv
 * PURPOSE: Create a new user-mode task (Ring 3) with configurable stack size
 *          and an argc/argv block written onto its user stack
 *=============================================================================*/
int task_create_user_argv(uint32_t entry, const char* name, uint16_t stack_pages,
                          int argc, const char* const* argv) {
    /* Validate the argument vector before anything is allocated, so a bad
     * request fails cheaply rather than half-way through building a task. */
    if (argc < 0 || argc > USER_ARGV_MAX) {
        kprintf("[PROCESS] ERROR: argc %d out of range (max %d)\n", argc, USER_ARGV_MAX);
        return -1;
    }
    if (argc > 0 && !argv) {
        kprintf("[PROCESS] ERROR: argc %d with NULL argv\n", argc);
        return -1;
    }

    /* Total string bytes, NUL terminators included. Computed up front so the
     * whole block is known to fit before the child's stack is touched. */
    size_t argv_bytes = 0;
    for (int i = 0; i < argc; i++) {
        if (!argv[i]) {
            kprintf("[PROCESS] ERROR: argv[%d] is NULL\n", i);
            return -1;
        }
        argv_bytes += strlen(argv[i]) + 1;
        if (argv_bytes > USER_ARGV_MAX_BYTES) {
            kprintf("[PROCESS] ERROR: argv too large (>%d bytes)\n", USER_ARGV_MAX_BYTES);
            return -1;
        }
    }

    // Validate and clamp stack_pages to allowed range
    if (stack_pages < USER_STACK_MIN) {
        kprintf("[PROCESS] WARNING: Stack size %d pages too small, using minimum %d pages\n",
                stack_pages, USER_STACK_MIN);
        stack_pages = USER_STACK_MIN;
    }
    if (stack_pages > USER_STACK_MAX) {
        kprintf("[PROCESS] WARNING: Stack size %d pages too large, using maximum %d pages\n",
                stack_pages, USER_STACK_MAX);
        stack_pages = USER_STACK_MAX;
    }

    /*=========================================================================
     * CONCURRENT LIMITS: bound how many slots one user can hold at once.
     *
     * Keyed on the CREATOR's credentials, not the new task's: task_create_user
     * hardcodes uid 1000 and the caller overwrites it after this function
     * returns (see the credential-inheritance note in launch_login_shell), so
     * the child's own uid is not yet meaningful here. The creator is the
     * account that will own the child in every case that matters -- a shell
     * spawning a program, or a program calling spawn.
     *
     * No current task means early boot with no owner to charge; the rate
     * limiter and its boot grace period already cover that path.
     *
     * CHECKED BEFORE THE RATE LIMITER, deliberately. Being over a standing
     * ownership limit is a more specific and more durable condition than a
     * transient rate spike: it stays true until the user's tasks exit, whereas
     * the bucket refills on its own. Reporting the rate limiter for a user who
     * is ALSO over their concurrent cap tells them to retry, which will keep
     * failing, and hides the real reason. It also makes the two limits
     * separable in testing -- both return -EAGAIN, so whichever runs first is
     * the one that gets observed.
     *=======================================================================*/
    task_t* limit_creator = scheduler_get_current_task();
    if (limit_creator && limit_creator->uid != 0) {
        uint32_t owned = task_count_live_for_uid(limit_creator->uid);
        if (owned >= USER_MAX_CONCURRENT_TASKS) {
            kprintf("[PROCESS] ERROR: uid %u already holds %u tasks (limit %d)\n",
                    limit_creator->uid, owned, USER_MAX_CONCURRENT_TASKS);
            return -EAGAIN;
        }

        /* Root reserve: checked AFTER the per-user cap so the more specific
         * message wins, and applied to non-root only -- the whole point is
         * that root can still get a slot when the table is nearly full. */
        uint32_t free_slots = task_count_free_slots();
        if (free_slots <= TASK_ROOT_RESERVED_SLOTS) {
            kprintf("[PROCESS] ERROR: only %u slots free, %d reserved for root\n",
                    free_slots, TASK_ROOT_RESERVED_SLOTS);
            return -EAGAIN;
        }
    }

    /*=========================================================================
     * SECURITY FIX (Issue 4.1): Rate Limiting Check
     * Prevent DoS via rapid task creation (fork bomb defense)
     *=======================================================================*/
    if (!task_rate_limit_check()) {
        /* -EAGAIN, not -1: this is a "try again later" condition, exactly like
         * the concurrent caps above, and a caller that cannot tell it apart
         * from a malformed binary has no basis for retrying. */
        kprintf("[PROCESS] ERROR: User task creation rate limited\n");
        return -EAGAIN;
    }

    // Find free slot
    int slot = task_find_free_slot();
    if (slot < 0) {
        kprintf("[PROCESS] ERROR: No free task slots\n");
        return -1;
    }

    task_t* task = &tasks[slot];

    // Initialize task structure
    memset(task, 0, sizeof(task_t));

    // Set task identification
    task->pid = task_alloc_pid();
    if (task->pid == 0) {
        kprintf("[PROCESS] ERROR: Failed to allocate PID (PID exhaustion)\n");
        task_free_slot(slot);
        return -1;
    }
    /* SECURITY (v1.12): Assign generation to prevent PID reuse attacks */
    task->generation = slot_generations[slot];
    /* SECURITY (v1.11): Use safe_strcpy with full buffer size */
    safe_strcpy(task->name, name, TASK_NAME_LEN);

    /* Record the creator as parent: whoever is running when a user task is
     * created is the process that started it (the shell, for `exec`). Stored
     * as {pid, generation} so a recycled parent slot can never be mistaken for
     * the real parent. memset above already left these zero (= no parent) for
     * the case where there is no current task (early boot). */
    task_t* creator = scheduler_get_current_task();
    if (creator) {
        task->parent_pid = creator->pid;
        task->parent_generation = creator->generation;
    }

    // Allocate guard page and kernel stack (for syscalls) - same as kernel tasks
    uint32_t guard_page_phys = pmm_alloc();
    if (guard_page_phys == 0) {
        kprintf("[PROCESS] ERROR: Failed to allocate guard page\n");
        task->pid = 0;  // Release PID
        task_free_slot(slot);
        return -1;
    }

    // Allocate 8 pages for kernel stack (32KB usable stack space)
    // CRYPTO FIX: Increased from 4 to 8 pages to support DH/RSA operations
    // CONTIGUITY FIX: must be ONE physically contiguous run — the stack is
    // addressed as a single block (esp = pages[7]+4096, growing down). Eight
    // separate pmm_alloc() calls returned ascending-but-not-contiguous frames
    // once the bitmap had holes, leaving the bytes below the top page
    // unmapped; the first interrupt push past a page boundary then #PF -> #DF
    // -> triple-faulted (this is what crashed `exec /hello.elf`).
    uint32_t kernel_stack_base = pmm_alloc_contiguous(8);
    if (kernel_stack_base == 0) {
        kprintf("[PROCESS] ERROR: Failed to allocate contiguous 8-page kernel stack\n");
        pmm_free(guard_page_phys);
        task->pid = 0;  // Release PID
        task_free_slot(slot);
        return -1;
    }
    uint32_t kernel_stack_pages[8];
    for (int i = 0; i < 8; i++) {
        kernel_stack_pages[i] = kernel_stack_base + (uint32_t)i * 4096;
    }

    // Map kernel stack pages (identity mapping) and flush TLB
    for (int i = 0; i < 8; i++) {
        map_page(kernel_stack_pages[i], kernel_stack_pages[i], PAGE_PRESENT | PAGE_READWRITE | PAE_NX);
        flush_tlb_single(kernel_stack_pages[i]);
    }

    /*=========================================================================
     * SECURITY FIX (Issue 6.3): Zero-Initialize Kernel Stack (User Tasks)
     *
     * CRITICAL: Zero kernel stack for user tasks to prevent stack canary
     * disclosure and information leakage. Even though this is a "user task",
     * it still has a kernel stack for handling syscalls and interrupts.
     *
     * Same rationale as kernel tasks - prevent:
     * - Stack canary leakage to user space
     * - Kernel data disclosure via uninitialized variables
     * - Cross-task information leakage
     *
     * NOTE: Pages must be mapped and TLB flushed (above) before zeroing.
     *=======================================================================*/
    for (int i = 0; i < 8; i++) {
        memset((void*)kernel_stack_pages[i], 0, 4096);
    }

    // Store physical addresses for cleanup
    task->guard_page_phys = guard_page_phys;
    task->kernel_stack_phys = kernel_stack_pages[0];  // First stack page (for compatibility)
    for (int i = 0; i < 8; i++) {
        task->stack_pages_phys[i] = kernel_stack_pages[i];
    }
    task->kernel_stack = kernel_stack_pages[7] + 4096;  // Point to top of 8th stack page

    /* (Formerly: 3 leaked "padding pages" here as a workaround for a supposed
     * 12KB over-top write. That write was the downward exec-chain stack overflow,
     * fixed by the larger kernel-task stack + the NOT-PRESENT guard page below;
     * the padding was removed from the kernel-task path and is dropped here too
     * for symmetry — it leaked 3 frames per user task for no benefit.) */

    // Mark guard page as NOT PRESENT (PAE-aware)
    if (pae_is_active()) {
        pae_pte_t* guard_pte = pae_get_pte(guard_page_phys);
        if (guard_pte) {
            *guard_pte = (guard_page_phys & PAE_FRAME_MASK) | PAE_READWRITE;  // Present=0
            flush_tlb_single(guard_page_phys);
        }
    } else {
        uint32_t* guard_pte = get_page_table_entry(guard_page_phys);
        if (guard_pte) {
            *guard_pte = guard_page_phys | PAGE_READWRITE;  // Present=0
            flush_tlb_single(guard_page_phys);
        }
    }

    // This is a user task
    task->is_kernel_task = false;

    // User/Group credentials (v1.10) - User tasks run as regular user by default
    task->uid = 1000;  // Regular user account
    task->gid = 100;   // Users group
    task->euid = 1000; // Effective UID = regular user
    task->egid = 100;  // Effective GID = users group
    task->ngroups = 0;  // No supplemental groups initially (v1.12)

    // Create a new page directory for process isolation FIRST
    task->page_directory = create_user_page_directory();
    if (task->page_directory == 0) {
        kprintf("[PROCESS] ERROR: Failed to create page directory\n");
        // Cleanup: free guard page and all stack pages
        pmm_free(guard_page_phys);
        for (int i = 0; i < 8; i++) {
            pmm_free(kernel_stack_pages[i]);
        }
        task->pid = 0;  // Release PID on error
        task_free_slot(slot);
        return -1;
    }

    // Allocate guard page for user stack (will be marked NOT PRESENT)
    uint32_t user_guard_page_phys = pmm_alloc();
    if (user_guard_page_phys == 0) {
        kprintf("[PROCESS] ERROR: Failed to allocate user guard page\n");
        free_page_directory(task->page_directory);
        pmm_free(guard_page_phys);
        for (int j = 0; j < 8; j++) {
            pmm_free(kernel_stack_pages[j]);
        }
        task->pid = 0;  // Release PID on error
        task_free_slot(slot);
        return -1;
    }
    task->user_guard_page_phys = user_guard_page_phys;

    // Allocate user stack pages (configurable: 8-256 pages = 32KB-1MB)
    // User stack layout with guard page:
    // [Guard Page - NOT PRESENT] <- guard_virt (causes page fault on access)
    // [Stack Page N-1]            <- bottom of usable stack
    // ...
    // [Stack Page 0]              <- top page, stack grows down from 0xC0000000
    for (int i = 0; i < stack_pages; i++) {
        task->user_stack_pages_phys[i] = pmm_alloc();
        if (task->user_stack_pages_phys[i] == 0) {
            kprintf("[PROCESS] ERROR: Failed to allocate user stack page %d\n", i);
            // Clean up previously allocated user stack pages
            for (int j = 0; j < i; j++) {
                pmm_free(task->user_stack_pages_phys[j]);
            }
            // Clean up other resources
            pmm_free(user_guard_page_phys);
            free_page_directory(task->page_directory);
            pmm_free(guard_page_phys);
            for (int j = 0; j < 8; j++) {
                pmm_free(kernel_stack_pages[j]);
            }
            task->pid = 0;  // Release PID on error
            task_free_slot(slot);
            return -1;
        }
    }

    // Store number of allocated stack pages
    task->user_stack_pages = stack_pages;

    /*=========================================================================
     * SECURITY: ASLR - Randomize user stack location
     *
     * Instead of using a fixed stack address (0xBFFFFFF0), we randomize it.
     * This makes exploitation significantly harder - even if attacker finds
     * a buffer overflow, they don't know where to jump to execute shellcode.
     *
     * ASLR provides 12 bits of entropy (4096 page range = 16MB randomization).
     * This means exploits have only 1/4096 (~0.024%) chance of success.
     *=======================================================================*/
    task->user_stack = aslr_get_random_stack_base(stack_pages);

    // Save current CR3 (kernel page directory)
    uint32_t kernel_cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(kernel_cr3));

    // Switch to user page directory to map stack pages there
    __asm__ volatile("mov %0, %%cr3" :: "r"(task->page_directory) : "memory");

    /*=========================================================================
     * Map user stack with ASLR-randomized base address
     *
     * Stack layout (grows DOWN from randomized base):
     * [Guard Page - NOT PRESENT] <- guard_virt (page fault on underflow)
     * [Stack Page N-1]            <- bottom of usable stack
     * ...
     * [Stack Page 0]              <- top page, ESP points here initially
     *=======================================================================*/

    /* Calculate stack base (align up to page boundary) */
    uint32_t stack_base = (task->user_stack + 0xFFF) & 0xFFFFF000;  /* Round up */

    /* Map user guard page as NOT PRESENT (below the stack).
     *
     * We are running with CR3 = the user PDPT (set above), so the guard page
     * lives at a user-only virtual address whose PD/PT level exists only in
     * THIS PDPT. The old code reached for the PTE directly via pae_get_pte() /
     * get_page_table_entry(), both of which walk the GLOBAL (kernel) page
     * tables and so returned NULL for a user-only address — the guard page was
     * never actually marked not-present (warning logged, guard unarmed).
     *
     * Fix: go through map_page(), which dispatches on the active CR3 to
     * pae_map_page_into(user_pdpt, ...) and auto-allocates the missing PD/PT
     * level — exactly the path the user stack pages below use. First map it
     * present (to force the page-table level into existence in the user PDPT),
     * then re-map the same address with the PRESENT bit cleared. The frame
     * stays recorded so the #PF handler can still recognise a stack-overflow
     * hit on the guard page. */
    uint32_t user_guard_virt = stack_base - ((stack_pages + 1) * 0x1000);
    uint64_t user_stack_flags = PAE_PAGE_STACK;
    map_page(user_guard_virt, user_guard_page_phys, user_stack_flags);
    map_page(user_guard_virt, user_guard_page_phys,
             (user_stack_flags & ~PAGE_PRESENT));  // Present=0
    flush_tlb_single(user_guard_virt);

    /* Record the VIRTUAL address, not just the frame: a ring-3 fault reports
     * CR2 as a user virtual address, and ASLR moves stack_base every exec, so
     * the handler cannot recompute this. Storing only user_guard_page_phys
     * (as before) left the handler with nothing to compare against, which is
     * why user-stack overflow fell through to the generic page-fault path. */
    task->user_guard_page_virt = user_guard_virt;

    /* Map user stack pages into USER page directory (virtual -> physical) */
    for (int i = 0; i < stack_pages; i++) {
        uint32_t virt_addr = stack_base - ((i + 1) * 0x1000);  /* Top-down from stack_base */
        map_page(virt_addr, task->user_stack_pages_phys[i], user_stack_flags);
    }

    /*=========================================================================
     * SECURITY FIX (Issue 6.3): Zero-Initialize User Stack Pages
     *
     * CRITICAL: User stack pages may contain leftover data including:
     * - Stack canary values (if previous user read uninitialized variables)
     * - Sensitive data from previous user processes
     * - Kernel data if pages were previously used by kernel
     *
     * ATTACK SCENARIO:
     * 1. Attacker allocates user stack, gets pages with leftover data
     * 2. Reads uninitialized local variables to scan stack memory
     * 3. Finds stack canary value (__stack_chk_guard) in leftover data
     * 4. Now can reliably exploit stack overflows (canary is known)
     *
     * FIX: Zero all user stack pages while in user page directory context
     * (pages are mapped at virtual addresses, so we can access them directly).
     *
     * NOTE: We're still in user page directory (CR3 = task->page_directory),
     * so we can access the pages via their virtual addresses.
     *=======================================================================*/
    for (int i = 0; i < stack_pages; i++) {
        uint32_t virt_addr = stack_base - ((i + 1) * 0x1000);
        memset((void*)virt_addr, 0, 4096);
    }

    /*=========================================================================
     * Write the argc/argv block onto the child's user stack.
     *
     * This MUST happen here, while CR3 is still the child's PDPT: the stack is
     * mapped only in that address space, so the same virtual addresses are
     * unmapped (or belong to something else entirely) once we switch back.
     *
     * Layout, built downward from the ASLR'd initial ESP:
     *
     *      user_stack ->  [ argv string data      ]  (argv_bytes, then aligned)
     *                     [ argv[argc] == NULL    ]
     *                     [ argv[argc-1] ... argv[0] ]
     *                     [ argv (char**)         ]
     *      new esp    ->  [ argc (int)            ]
     *
     * crt0 pops argc and argv straight into main()'s arguments. With argc == 0
     * this still writes {argc=0, argv=&NULL-terminator}, so a program declaring
     * main(int, char**) sees a valid empty vector rather than garbage.
     *
     * The block lives in the slack below user_stack inside the already-mapped
     * top stack page; USER_ARGV_MAX/USER_ARGV_MAX_BYTES keep it far below a
     * page, and the bounds check below refuses the load rather than writing
     * past the mapping if that ever stops holding.
     *=======================================================================*/
    {
        /* Bytes needed: strings + (argc + 1) pointers + argv + argc + slack
         * for the 16-byte alignment of the final esp (see step 2). */
        size_t block_bytes = argv_bytes + ((size_t)argc + 1) * sizeof(uint32_t)
                             + sizeof(uint32_t) + sizeof(uint32_t) + 15u;
        uint32_t stack_low = stack_base - ((uint32_t)stack_pages * 0x1000);

        if (task->user_stack < stack_low ||
            (size_t)(task->user_stack - stack_low) < block_bytes) {
            /* Cannot happen with the current limits, but writing outside the
             * mapping would corrupt whatever else lives there, so fail loudly
             * instead. Restore CR3 first — we are still on the child's PDPT. */
            __asm__ volatile("mov %0, %%cr3" :: "r"(kernel_cr3) : "memory");
            kprintf("[PROCESS] ERROR: argv block (%u bytes) does not fit on user stack\n",
                    (unsigned)block_bytes);
            task->pid = 0;
            task_free_slot(slot);
            return -1;
        }

        /* 1. Copy the strings, recording where each one landed. */
        uint32_t sp = task->user_stack;
        uint32_t user_argv_ptrs[USER_ARGV_MAX];
        for (int i = 0; i < argc; i++) {
            size_t len = strlen(argv[i]) + 1;
            sp -= len;
            memcpy((void*)sp, argv[i], len);
            user_argv_ptrs[i] = sp;
        }

        /* 2. Align the block so the FINAL esp lands on a 16-byte boundary.
         *
         * This is load-bearing, not cosmetic: switch_to_user_mode in
         * context_switch.S does `and eax, 0xFFFFFFF0` on the user ESP before
         * building the iret frame (SSE wants a 16-aligned stack). That mask
         * silently moves ESP DOWN by up to 15 bytes, so a block whose base is
         * not already 16-aligned is skipped past — crt0 then reads argc from
         * zeroed stack below the block and main() sees argc == 0 with a
         * garbage argv. It looked intermittent because whether sp happened to
         * land on 16 depends on the total length of the argument strings.
         *
         * Steps 3 and 4 push (argc + 1) pointers plus argv plus argc below
         * this point, so bias the alignment by exactly that many bytes. */
        {
            uint32_t below = ((uint32_t)argc + 3u) * sizeof(uint32_t);
            sp = ((sp - below) & ~0xFu) + below;
        }

        /* 3. NULL terminator, then the pointers in reverse so argv[0] ends up
         *    lowest — i.e. the array reads forwards from the final address. */
        sp -= sizeof(uint32_t);
        *(uint32_t*)sp = 0;
        for (int i = argc - 1; i >= 0; i--) {
            sp -= sizeof(uint32_t);
            *(uint32_t*)sp = user_argv_ptrs[i];
        }
        uint32_t user_argv = sp;

        /* 4. argv then argc, so crt0 pops argc first. */
        sp -= sizeof(uint32_t);
        *(uint32_t*)sp = user_argv;
        sp -= sizeof(uint32_t);
        *(uint32_t*)sp = (uint32_t)argc;

        /* ESP starts at the block instead of at the raw ASLR base. */
        task->user_stack = sp;
    }

    // Switch back to kernel page directory
    __asm__ volatile("mov %0, %%cr3" :: "r"(kernel_cr3) : "memory");

    // Set up initial CPU context for user mode
    task->context.esp = task->user_stack;
    task->context.ebp = task->user_stack;
    task->context.eip = entry;
    task->context.eflags = 0x0202;  // IF=1 (interrupts enabled), IOPL=0, bit 1 always 1

    // User segments (Ring 3) - use dynamic selectors + RPL=3
    // Code segment MUST be executable (use user_code_selector)
    // Data/Stack segments MUST be writable (use user_data_selector)
    task->context.cs = user_code_selector | 3;  // User code segment with RPL=3
    // SECURITY FIX: Initialize data segments to USER selectors with RPL=3
    // The context switch code loads these segments before iret to prevent
    // user code from starting with kernel data segments (privilege escalation)
    task->context.ds = user_data_selector | 3;  // User data segment with RPL=3
    task->context.es = user_data_selector | 3;
    task->context.fs = user_data_selector | 3;
    task->context.gs = user_data_selector | 3;
    task->context.ss = user_data_selector | 3;  // User stack segment with RPL=3

    // CRITICAL: Initialize FPU state to clean state
    // This prevents FPU corruption when task first uses floating-point
    __asm__ volatile("fninit");  // Initialize FPU to clean state
    __asm__ volatile("fxsave %0" : "=m"(task->context.fpu_state));

    // Scheduling parameters
    task->priority = PRIORITY_NORMAL;  // Default priority
    task->base_time_slice = 10;  // 10 timer ticks base
    task->time_slice = task->base_time_slice;  // Will be adjusted by priority
    task->ticks_remaining = task->time_slice;
    task->total_ticks = 0;

    // Sleep management
    task->wake_tick = 0;

    // Exit status
    task->exit_status = 0;
    task->blocked_on_wq = NULL;

    // Initialize per-process stream context (stdin/stdout/stderr)
    streams_init(&task->streams);

    // Initialize the per-process file descriptor table (fds 3+)
    task_fdtable_init(task);

    // Start at the default drive root; sys_spawn overwrites this with the
    // parent's cwd, so a child inherits rather than resetting to "D:/".
    task_cwd_init(task);

    // Initialize FD tracking (v1.11)
    task->open_fd_count = 0;

    /*=========================================================================
     * REVOLUTIONARY SECURITY: Create Per-Process Private /tmp Directory
     *
     * TRADITIONAL UNIX/LINUX: Shared world-writable /tmp (50-year-old flaw)
     * TINYOS INNOVATION: Each process gets isolated /tmp namespace
     *
     * Directory name: Crypto-random 40-bit hex (10 characters)
     * Example: /tmp/a3f7c2e4b9/
     *
     * BENEFITS:
     * ✅ Eliminates symlink attacks
     * ✅ Eliminates TOCTOU races
     * ✅ No information leakage between processes
     * ✅ Automatic cleanup on process exit
     * ✅ No DoS via /tmp filling
     *=======================================================================*/
    {
        uint64_t random_bits;
        csprng_random_bytes(&global_csprng, (uint8_t*)&random_bits, 5); // 40 bits

        /* Format: /tmp/XXXXXXXXXX/ where X is hex digit */
        const char* hex = "0123456789abcdef";
        char* p = task->private_tmp_dir;

        *p++ = '/'; *p++ = 't'; *p++ = 'm'; *p++ = 'p'; *p++ = '/';

        /* Convert 40 bits to 10 hex digits */
        for (int i = 9; i >= 0; i--) {
            *p++ = hex[(random_bits >> (i * 4)) & 0xF];
        }
        *p++ = '/';
        *p = '\0';

        /* Create the directory */
        ramfs_mkdir(task->private_tmp_dir);
    }

    /*=========================================================================
     * SECURITY (EDR Phase 2): Initialize Behavioral Detection State
     *
     * Initialize syscall history tracking and anomaly detection for this
     * process. Detection is enabled by default for all processes.
     *=======================================================================*/
    edr_behavioral_init(task);

    /*=========================================================================
     * SECURITY (EDR Phase 3): Initialize Advanced Detection State
     *
     * Allocate and initialize advanced detection modules (memory inspection,
     * network flow analysis, file integrity monitoring, crypto monitoring).
     * Advanced detection is enabled by default for all processes.
     *=======================================================================*/
    task->edr_advanced = (edr_advanced_state_t*)pmm_alloc();  /* Allocate 4KB page */
    if (task->edr_advanced) {
        edr_advanced_init_process(task);
    }

    // Set state to ready
    task->state = TASK_STATE_READY;

    kprintf("[PROCESS] Created user task PID=%d '%s' entry=0x%x\n",
            task->pid, task->name, entry);
    kprintf("[PROCESS]   User stack: 0x%08x (ASLR randomized)\n",
            task->user_stack);
    kprintf("[PROCESS]   Private /tmp: %s\n", task->private_tmp_dir);

    return task->pid;
}

/*=============================================================================
 * FUNCTION: task_get
 * PURPOSE: Get task by PID (without generation validation)
 *
 * SECURITY NOTE (v2.0): This function does NOT validate generation counter!
 * Use task_get_validated() when generation is available to prevent PID reuse
 * attacks. This function is retained for compatibility with code that only
 * has PIDs (e.g., user shell commands, boot initialization).
 *=============================================================================*/
task_t* task_get(uint32_t pid) {
    for (int i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].pid == pid && tasks[i].state != TASK_STATE_TERMINATED) {
            return &tasks[i];
        }
    }
    return NULL;
}

/* Like task_get, but does NOT filter out TERMINATED tasks. Used by the ELF
 * loader immediately after task_create_user: a freshly-created task can be
 * flipped to TERMINATED in the tiny window before lookup (e.g. an EDR periodic
 * check on the timer softirq flags the brand-new task), which made task_get
 * return NULL and aborted exec with "Failed to get task structure". The loader
 * legitimately owns this PID and just needs its slot (for the page directory),
 * so it matches by PID alone. Only the matching slot for a live PID is returned
 * (pid != 0). */
task_t* task_get_any(uint32_t pid) {
    if (pid == 0) return NULL;
    for (int i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].pid == pid) {
            return &tasks[i];
        }
    }
    return NULL;
}

/*=============================================================================
 * FUNCTION: task_get_validated
 * PURPOSE: Get task by PID with generation counter validation
 *
 * SECURITY (v2.0): PID Reuse Attack Prevention
 * ==============================================
 * VULNERABILITY: Without generation validation, a process can:
 * 1. Obtain PID of another process (e.g., waitpid returns PID 5)
 * 2. Process 5 exits, slot is reused for new process 5 (generation++)
 * 3. Original process tries kill(5) and kills WRONG process!
 *
 * FIX: Validate both PID and generation counter. Each time a task slot is
 * reused, generation increments. Old references with stale generation will
 * correctly fail instead of targeting the new process.
 *
 * USAGE: Use this function whenever caller has both PID and generation
 * (e.g., from wait syscall return value, IPC handles, etc.)
 *=============================================================================*/
task_t* task_get_validated(uint32_t pid, uint32_t generation) {
    for (int i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].pid == pid &&
            tasks[i].generation == generation &&
            tasks[i].state != TASK_STATE_TERMINATED) {
            return &tasks[i];
        }
    }
    return NULL;  // PID not found OR generation mismatch (stale reference)
}

/*=============================================================================
 * FUNCTION: task_get_handle
 * PURPOSE: Create a secure PID handle from task (for future syscalls)
 *
 * SECURITY (v2.0): Secure Handle Generation for Syscalls
 * =======================================================
 * USAGE: When syscalls need to return a process reference (e.g., fork(),
 * waitpid()), they should return a pid_handle_t instead of just a PID.
 * This allows the caller to later validate the reference with
 * task_get_validated().
 *
 * Example:
 *   pid_handle_t handle = task_get_handle(child_task);
 *   return handle;  // Syscall returns {pid, generation}
 *
 * Later, when the caller uses the handle:
 *   task_t* task = task_get_validated(handle.pid, handle.generation);
 *   if (!task) {
 *       return -ESRCH;  // Stale reference or process exited
 *   }
 *=============================================================================*/
pid_handle_t task_get_handle(task_t* task) {
    pid_handle_t handle = {0, 0};
    if (task) {
        handle.pid = task->pid;
        handle.generation = task->generation;
    }
    return handle;
}

/*=============================================================================
 * FUNCTION: task_current
 * PURPOSE: Get currently running task
 *=============================================================================*/
task_t* task_current(void) {
    /* The scheduler tracks the running task in its own state; before
     * scheduler_start() this returns NULL, preserving early-boot behavior. */
    return scheduler_get_current_task();
}

/* Validate that `p` actually points at one of the real task slots in the
 * static tasks[] pool (correct element, in bounds, properly aligned). Callers
 * that obtain a task pointer from less-trusted state (e.g. audit logging in IRQ
 * context) use this instead of a bare ">= 1MB" address heuristic, so a stray
 * in-range pointer can't be dereferenced as a task. */
bool task_is_valid_ptr(const void* p) {
    if (p == NULL) return false;
    uintptr_t base = (uintptr_t)&tasks[0];
    uintptr_t end  = (uintptr_t)&tasks[MAX_TASKS];
    uintptr_t addr = (uintptr_t)p;
    if (addr < base || addr >= end) return false;
    /* Must land exactly on a slot boundary, not mid-struct. */
    if (((addr - base) % sizeof(task_t)) != 0) return false;
    return true;
}

/*=============================================================================
 * FUNCTION: task_slot_is_live
 * PURPOSE: True iff `p` points at a live, current-incarnation task slot.
 *
 * Stronger than task_is_valid_ptr: also requires a non-free pid and a
 * generation that still matches the slot. A freed-and-recycled slot bumps
 * slot_generations[slot], so a STALE pointer left dangling in the ready queue
 * (freed slot, or an incarnation that has since been reused) fails the
 * generation compare. The scheduler uses this to refuse switching to a stale
 * ready-queue entry — the read-side complement to deferring the kernel-stack
 * free in task_terminate (a stale entry could otherwise feed a torn-down
 * kernel_stack straight into tss_set_kernel_stack → esp0 panic).
 *=============================================================================*/
bool task_slot_is_live(const task_t* task) {
    if (!task_is_valid_ptr(task)) return false;
    if (task->pid == 0) return false;  /* freed slots zero pid */
    uintptr_t base = (uintptr_t)&tasks[0];
    uint32_t slot = (uint32_t)(((uintptr_t)task - base) / sizeof(task_t));
    if (slot >= MAX_TASKS) return false;
    return task->generation == slot_generations[slot];
}

/*=============================================================================
 * FUNCTION: task_set_current
 * PURPOSE: Set currently running task (used by scheduler)
 *=============================================================================*/
void task_set_current(task_t* task) {
    current_task = task;
    if (task) {
        task->state = TASK_STATE_RUNNING;
    }
}

/*=============================================================================
 * FUNCTION: task_free_resources
 * PURPOSE: Free all memory owned by a task (stacks, guard pages, page
 *          directory, EDR state)
 *
 * Fields are zeroed after freeing so this function is idempotent: it is
 * called from task_terminate() AND from the scheduler cleanup queue, and a
 * task may pass through both paths.
 *=============================================================================*/
void task_free_resources(task_t* task) {
    if (!task) {
        return;
    }

    // Free guard page
    if (task->guard_page_phys != 0) {
        pmm_free(task->guard_page_phys);
        task->guard_page_phys = 0;
    }

    // Free all kernel stack pages (KERNEL_TASK_STACK_PAGES for kernel tasks, 8 for user tasks)
    int num_kernel_stack_pages = task->is_kernel_task ? KERNEL_TASK_STACK_PAGES : 8;
    for (int i = 0; i < num_kernel_stack_pages; i++) {
        if (task->stack_pages_phys[i] != 0) {
            pmm_free(task->stack_pages_phys[i]);
            task->stack_pages_phys[i] = 0;
        }
    }
    task->kernel_stack_phys = 0;  // Alias of stack_pages_phys[0], freed above

    // Free user stack and guard page (if this is a user-mode task)
    if (!task->is_kernel_task) {
        // Free user guard page
        if (task->user_guard_page_phys != 0) {
            pmm_free(task->user_guard_page_phys);
            task->user_guard_page_phys = 0;
        }
        task->user_guard_page_virt = 0;
        // Free all user stack pages (using actual allocated count)
        for (int i = 0; i < task->user_stack_pages; i++) {
            if (task->user_stack_pages_phys[i] != 0) {
                pmm_free(task->user_stack_pages_phys[i]);
                task->user_stack_pages_phys[i] = 0;
            }
        }
        task->user_stack_pages = 0;
    }

    // Free page directory if it's not the kernel page directory
    if (!task->is_kernel_task && task->page_directory != 0) {
        uint32_t kernel_pd = get_kernel_page_directory();
        if (task->page_directory != kernel_pd) {
            free_page_directory(task->page_directory);
        }
        task->page_directory = 0;
    }

    // Free EDR advanced detection state page
    if (task->edr_advanced) {
        pmm_free((uint32_t)task->edr_advanced);
        task->edr_advanced = NULL;
    }
}

/*=============================================================================
 * FUNCTION: task_terminate
 * PURPOSE: Terminate a task
 *=============================================================================*/
void task_terminate(uint32_t pid) {
    task_t* task = task_get(pid);
    if (task) {
        /* SECURITY: Check if process is protected from termination */
        if (task->capabilities & CAP_UNKILLABLE) {
            kprintf("[PROCESS] DENIED: Cannot terminate protected process PID=%d '%s' (CAP_UNKILLABLE)\n",
                    task->pid, task->name);
            return;
        }

        kprintf("[PROCESS] Terminating task PID=%d '%s'\n", task->pid, task->name);

        // A task killed while blocked on a wait queue must be detached from it,
        // or the stale entry consumes a later wakeup / spuriously wakes the
        // slot's next occupant. No-op unless blocked_on_wq is set.
        wait_queue_remove_task(task);

        // An externally killed task never runs sys_exit, so nothing else would
        // record its status or wake anyone blocked in waitpid() on it. Waiters
        // block on a wait queue rather than polling, so skipping this hangs
        // them permanently instead of just delaying them a tick. 0x7F follows
        // the shell convention for "died abnormally"; it is indistinguishable
        // from a deliberate exit(127) until waitpid grows real WIFSIGNALED
        // encoding, which is fine for now — the point is that the waiter is
        // released at all.
        waitpid_notify_death(task->pid, task->generation, 0x7F);

        // Clean up streams (close any open file descriptors)
        streams_cleanup(&task->streams);

        // Release any files the task opened via SYS_OPEN. Safe on the self-exit
        // path too: this only returns entries to the global VFS fd pool and
        // never touches the kernel stack the dying task is still running on.
        task_fdtable_cleanup(task);

        // Same for pipes created via SYS_PIPE. Without this, a shell killed
        // mid-pipeline would strand its slots forever: nothing else knows the
        // owner is gone, and the table is a fixed 8 entries, so repeating it
        // exhausts pipes system-wide. Frees the buffer AND wakes anything still
        // blocked on either end, which matters because the other stage of the
        // pipeline may still be parked in pipe_read waiting for data that can
        // no longer come.
        task_pipes_cleanup(task);

        // A task terminated while not running never reaches the scheduler
        // cleanup queue (it is reaped off the ready queue without freeing its
        // slot), so free its resources and release its slot here. A
        // self-terminating task, by contrast, is STILL EXECUTING ON ITS KERNEL
        // STACK: freeing its resources now would pmm_free the 8 kernel-stack
        // frames it is running on, returning them to the allocator so the next
        // exec's pmm_alloc_contiguous(8) can reclaim them while the dying task
        // still pushes/writes to them — a live use-after-free and free-then-
        // realloc that corrupts the next task's kernel stack (intermittent
        // first-exec-after-login corruption). So for self-exit, defer BOTH the
        // resource-free and the slot-free to the scheduler cleanup path
        // (scheduler.c), which runs task_free_resources + task_free_slot_for_task
        // AFTER the final context switch has moved esp onto the reaper's stack.
        // task_free_resources is idempotent, so the deferred call is the sole
        // freer for self-exiting tasks with no double-free.
        if (task != scheduler_get_current_task()) {
            task_free_resources(task);
            task->state = TASK_STATE_TERMINATED;
            task->pid = 0;  // Mark slot as free
            scheduler_remove_task(task);
            task_free_slot_for_task(task);
        } else {
            // Self-exit: mark terminated so the scheduler queues us for cleanup,
            // but leave resources/slot for the deferred post-switch reaper.
            task->state = TASK_STATE_TERMINATED;
            task->pid = 0;
        }
    }
}

/*=============================================================================
 * FUNCTION: task_exit
 * PURPOSE: Exit current task
 *=============================================================================*/
void task_exit(void) {
    if (current_task) {
        kprintf("[PROCESS] Task PID=%d exiting\n", current_task->pid);
        task_terminate(current_task->pid);

        // Trigger scheduler to switch to next task
        // This will be called by the scheduler
    }
}

/*=============================================================================
 * FUNCTION: task_list
 * PURPOSE: Print all tasks (for debugging)
 *=============================================================================*/
void task_list(void) {
    kprintf("\n=== TASK LIST ===\n");
    kprintf("PID   STATE      NAME                ENTRY      TICKS\n");
    kprintf("----  ---------  ------------------  --------   -----\n");

    for (int i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].pid != 0) {
            const char* state_str = "UNKNOWN";
            switch (tasks[i].state) {
                case TASK_STATE_READY:      state_str = "READY"; break;
                case TASK_STATE_RUNNING:    state_str = "RUNNING"; break;
                case TASK_STATE_BLOCKED:    state_str = "BLOCKED"; break;
                case TASK_STATE_SLEEPING:   state_str = "SLEEPING"; break;
                case TASK_STATE_ZOMBIE:     state_str = "ZOMBIE"; break;
                case TASK_STATE_TERMINATED: state_str = "TERM"; break;
            }

            kprintf("%-4d  %-9s  %-18s  0x%08x  %d\n",
                    tasks[i].pid,
                    state_str,
                    tasks[i].name,
                    tasks[i].context.eip,
                    tasks[i].total_ticks);
        }
    }

    kprintf("=================\n\n");
}

/*=============================================================================
 * SECURITY FIX (v1.11): String Safety
 *
 * Previous unsafe pattern replaced:
 *   OLD: strncpy(task->name, name, TASK_NAME_LEN - 1);
 *        task->name[TASK_NAME_LEN - 1] = '\0';
 *
 *   NEW: safe_strcpy(task->name, name, TASK_NAME_LEN);
 *
 * Benefits:
 * - Uses existing safe_strcpy from util.h
 * - Always null-terminates (guaranteed by safe_strcpy implementation)
 * - Takes full buffer size (no -1 confusion)
 * - Single function call (no manual null termination needed)
 * - Eliminates off-by-one errors
 *=============================================================================*/

/*=============================================================================
 * Get All Active Tasks
 * SECURITY FIX: Replaces inefficient PID-based iteration
 *=============================================================================*/
/**
 * @brief Get all active tasks in the system (for ps command, etc.)
 * @param tasks_out Output array to store pointers to active tasks
 * @param max_tasks Maximum number of tasks to return (size of tasks_out array)
 * @return Number of active tasks found
 *
 * NOTE: Iterates through internal tasks array directly - O(MAX_TASKS) complexity
 * but finds ALL active tasks regardless of PID value.
 *
 * SECURITY: This replaces the previous PID-based iteration (1 to 100) which
 * would miss tasks with PIDs >= 100. With PID recycling, tasks can have any
 * PID value from 1 to UINT32_MAX, so we MUST iterate the array directly.
 */
int task_get_all(task_t** tasks_out, int max_tasks) {
    int count = 0;

    // Iterate through internal tasks array directly
    for (int i = 0; i < MAX_TASKS && count < max_tasks; i++) {
        // Skip empty slots (PID 0) and terminated tasks
        if (tasks[i].pid != 0 && tasks[i].state != TASK_STATE_TERMINATED) {
            tasks_out[count++] = &tasks[i];
        }
    }

    return count;
}

/*=============================================================================
 * FUNCTION: task_get_slot
 * PURPOSE: Return the task in raw slot `slot`, or NULL if it is not live.
 *
 * The STABLE-INDEX counterpart to task_get_all(), which compacts: its output is
 * dense, so if a task exits between two calls every entry after it shifts down
 * and an index-based walk silently skips a process. A caller that cannot hold
 * the lock across its whole loop -- sys_psinfo, which must drop it to
 * copy_to_user without risking a fault under masked interrupts -- needs an
 * index that means the same thing on every iteration. A raw slot does; a
 * position in a compacted list does not.
 *
 * Returns NULL for a free or terminated slot, so callers filter exactly as they
 * would on task_get_all()'s output.
 *===========================================================================*/
task_t* task_get_slot(int slot) {
    if (slot < 0 || slot >= MAX_TASKS) {
        return NULL;
    }
    if (tasks[slot].pid == 0 || tasks[slot].state == TASK_STATE_TERMINATED) {
        return NULL;
    }
    return &tasks[slot];
}

/*=============================================================================
 * TASK STATE MANAGEMENT
 *=============================================================================*/

/**
 * @brief Put current task to sleep for specified ticks
 */
void task_sleep(uint32_t ticks) {
    task_t* task = task_current();
    if (!task) {
        return;
    }

    // State transition and dequeue must be atomic against the timer IRQ:
    // once state is SLEEPING, scheduler_schedule_from_interrupt re-adds any
    // expired sleeper with no ready-queue membership check. A tick landing
    // between the state write and scheduler_remove_task (trivially hit with
    // ticks == 1) would append a task that is still linked in the circular
    // ready queue, corrupting the list.
    CRITICAL_SECTION_ENTER();
    task->wake_tick = pit_get_ticks() + ticks;
    task->state = TASK_STATE_SLEEPING;
    scheduler_remove_task(task);
    CRITICAL_SECTION_EXIT();

    scheduler_yield();
}

/**
 * @brief Block the current task (waiting for I/O or event)
 */
void task_block(void) {
    task_t* task = task_current();
    if (!task) {
        return;
    }

    task->state = TASK_STATE_BLOCKED;

    // Remove from ready queue and yield CPU
    scheduler_remove_task(task);
    scheduler_yield();
}

/**
 * @brief Unblock a task (make it ready to run)
 */
void task_unblock(task_t* task) {
    if (!task || task->state != TASK_STATE_BLOCKED) {
        return;
    }

    task->state = TASK_STATE_READY;
    scheduler_add_task(task);
}

/**
 * @brief Set task priority and adjust time slice accordingly
 *
 * PRIORITY WEIGHTING:
 * - IDLE (0):     1x base time slice (lowest CPU share)
 * - LOW (1):      2x base time slice
 * - NORMAL (2):   3x base time slice (default)
 * - HIGH (3):     5x base time slice
 * - REALTIME (4): 10x base time slice (highest CPU share)
 */
void task_set_priority(task_t* task, priority_t priority) {
    if (!task) {
        return;
    }

    /*=========================================================================
     * SECURITY (v1.13): Robust Array Bounds Check
     *
     * CRITICAL: Use sizeof to check against ACTUAL array size, not PRIORITY_MAX.
     * If PRIORITY_MAX and array size become misaligned during maintenance,
     * out-of-bounds access would occur.
     *
     * VULNERABILITY: Old check was "priority > PRIORITY_MAX" which relies on
     * PRIORITY_MAX being manually kept in sync with array size. If someone:
     *   1. Adds 6th element to array: {1, 2, 3, 5, 10, 15}
     *   2. Forgets to update PRIORITY_MAX from 4 to 5
     *   3. Now priority_multipliers[5] is valid but rejected → feature broken
     *
     * Or vice versa:
     *   1. Changes PRIORITY_MAX to 5
     *   2. Forgets to add 6th element to array
     *   3. Now priority_multipliers[5] is OUT OF BOUNDS → buffer overrun!
     *
     * FIX: Calculate array size at compile time using sizeof. Now impossible
     * for check and array to become misaligned.
     *=======================================================================*/
    static const uint32_t priority_multipliers[] = {1, 2, 3, 5, 10};
    const uint32_t array_size = sizeof(priority_multipliers) / sizeof(priority_multipliers[0]);

    if (priority >= array_size) {
        return;  // Out of bounds - reject
    }

    task->priority = priority;

    // Adjust time slice based on priority (weighted round-robin)
    task->time_slice = task->base_time_slice * priority_multipliers[priority];
    task->ticks_remaining = task->time_slice;
}

/**
 * @brief Get human-readable state name
 */
const char* task_get_state_string(task_state_t state) {
    switch (state) {
        case TASK_STATE_READY:      return "READY";
        case TASK_STATE_RUNNING:    return "RUNNING";
        case TASK_STATE_BLOCKED:    return "BLOCKED";
        case TASK_STATE_SLEEPING:   return "SLEEPING";
        case TASK_STATE_ZOMBIE:     return "ZOMBIE";
        case TASK_STATE_TERMINATED: return "TERMINATED";
        default:                    return "UNKNOWN";
    }
}

/*=============================================================================
 * PER-PROCESS CURRENT WORKING DIRECTORY
 *
 * task->cwd is always absolute and drive-qualified; see the field's comment in
 * process.h. These three functions are its only writers and readers of record.
 *
 * No locking, for the same reason as the fd table below: a task's cwd is only
 * touched by that task's own syscalls.
 *===========================================================================*/

/* task_t sizes cwd independently to avoid a vfs.h <-> process.h include cycle.
 * If VFS_MAX_PATH ever grows, a path the VFS accepts would no longer fit in a
 * cwd, and task_resolve_path would start rejecting valid directories. */
_Static_assert(TASK_CWD_MAX == VFS_MAX_PATH,
               "task cwd must hold any path the VFS accepts");

void task_cwd_init(task_t* task) {
    if (!task) {
        return;
    }
    /* Drive root of the default drive: "D:/". Qualified from the start so the
     * invariant holds even for a task that never calls chdir. */
    task->cwd[0] = VFS_DEFAULT_DRIVE;
    task->cwd[1] = ':';
    task->cwd[2] = '/';
    task->cwd[3] = '\0';
}

int task_resolve_path(task_t* task, const char* path, char* out, size_t out_size) {
    if (!task || !path || !out || out_size == 0) {
        return -EINVAL;
    }

    bool drive_qualified = (path[0] != '\0' && path[1] == ':' &&
                            ((path[0] >= 'A' && path[0] <= 'Z') ||
                             (path[0] >= 'a' && path[0] <= 'z')));

    /* Already absolute in the VFS's own terms: a drive-qualified path names its
     * drive, and a leading '/' is resolved by the VFS against the default
     * drive exactly as before cwd existed. Neither may pick up a cwd prefix. */
    if (drive_qualified || path[0] == '/') {
        if (safe_strcpy(out, path, out_size) >= out_size) {
            return -ENAMETOOLONG;
        }
        return 0;
    }

    /* Relative: join onto the cwd. The cwd invariant (no trailing slash except
     * at a drive root, which ends in '/') is what makes this a single test
     * rather than a general path-normalizing join. */
    size_t cwd_len = strlen(task->cwd);
    bool needs_sep = (cwd_len > 0 && task->cwd[cwd_len - 1] != '/');

    size_t need = cwd_len + (needs_sep ? 1 : 0) + strlen(path) + 1;
    if (need > out_size) {
        return -ENAMETOOLONG;
    }

    size_t pos = safe_strcpy(out, task->cwd, out_size);
    if (needs_sep) {
        out[pos++] = '/';
    }
    safe_strcpy(out + pos, path, out_size - pos);
    return 0;
}

int task_chdir(task_t* task, const char* path) {
    if (!task || !path || path[0] == '\0') {
        return -EINVAL;
    }

    char joined[TASK_CWD_MAX];
    int rc = task_resolve_path(task, path, joined, sizeof(joined));
    if (rc < 0) {
        return rc;
    }

    /* Split the drive prefix off before canonicalizing: vfs_canonicalize_path
     * works on the path part and would treat "D:" as an ordinary component. */
    char drive = VFS_DEFAULT_DRIVE;
    const char* rest = joined;
    if (joined[0] != '\0' && joined[1] == ':') {
        drive = joined[0];
        if (drive >= 'a' && drive <= 'z') {
            drive = drive - 'a' + 'A';
        }
        rest = joined + 2;
    }
    if (rest[0] == '\0') {
        rest = "/";     /* Bare "C:" means that drive's root */
    }

    char canonical[TASK_CWD_MAX];
    if (vfs_canonicalize_path(rest, canonical, sizeof(canonical)) != 0) {
        return -EINVAL;
    }

    /* Rebuild the qualified form that will be stored, and that the existence
     * check below must run against — checking `canonical` alone would test the
     * default drive no matter which drive was named. */
    char resolved[TASK_CWD_MAX];
    size_t canon_len = strlen(canonical);
    if (canon_len + 3 > sizeof(resolved)) {
        return -ENAMETOOLONG;
    }
    resolved[0] = drive;
    resolved[1] = ':';
    safe_strcpy(resolved + 2, canonical, sizeof(resolved) - 2);

    /* Existence, directory-ness and permission in one call. Deliberately not
     * vfs_stat: stat demands read permission, and chdir must only demand
     * search (x) — a process may stand in a directory it cannot list. */
    int err = vfs_access_dir(resolved);
    if (err < 0) {
        return err;
    }

    /* Commit only here: every failure above leaves the old cwd intact. */
    safe_strcpy(task->cwd, resolved, sizeof(task->cwd));
    return 0;
}

/*=============================================================================
 * PER-PROCESS FILE DESCRIPTOR TABLE
 *
 * Userspace fds 3..(TASK_FDTABLE_SIZE+2) map onto the global VFS fd pool.
 * fds 0/1/2 are handled by task->streams and never appear here.
 *
 * No locking: a task's table is only ever touched by that task (from its own
 * syscalls) or by task_terminate() after the task is off the run queue.
 *===========================================================================*/

void task_fdtable_init(task_t* task) {
    if (!task) {
        return;
    }
    for (int i = 0; i < TASK_FDTABLE_SIZE; i++) {
        task->fdtable[i] = -1;
    }
}

void task_fdtable_cleanup(task_t* task) {
    if (!task) {
        return;
    }
    for (int i = 0; i < TASK_FDTABLE_SIZE; i++) {
        if (task->fdtable[i] >= 0) {
            vfs_close(task->fdtable[i]);
            task->fdtable[i] = -1;
        }
    }
}

int task_fd_install(task_t* task, int vfs_fd) {
    if (!task || vfs_fd < 0) {
        return -EBADF;
    }
    for (int i = 0; i < TASK_FDTABLE_SIZE; i++) {
        if (task->fdtable[i] < 0) {
            task->fdtable[i] = vfs_fd;
            return i + TASK_FD_BASE;
        }
    }
    return -EMFILE;
}

int task_fd_lookup(task_t* task, int user_fd) {
    if (!task) {
        return -EBADF;
    }
    int slot = user_fd - TASK_FD_BASE;
    if (slot < 0 || slot >= TASK_FDTABLE_SIZE) {
        return -EBADF;
    }
    if (task->fdtable[slot] < 0) {
        return -EBADF;
    }
    return task->fdtable[slot];
}

int task_fd_remove(task_t* task, int user_fd) {
    if (!task) {
        return -EBADF;
    }
    int slot = user_fd - TASK_FD_BASE;
    if (slot < 0 || slot >= TASK_FDTABLE_SIZE) {
        return -EBADF;
    }
    int vfs_fd = task->fdtable[slot];
    if (vfs_fd < 0) {
        return -EBADF;
    }
    task->fdtable[slot] = -1;
    return vfs_fd;
}
