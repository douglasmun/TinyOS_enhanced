/*=============================================================================
 * process.h - Process Management and Task Control Block
 *=============================================================================
 * PHASE 4: NO /proc FILESYSTEM (Security-by-Design)
 *
 * REVOLUTIONARY SECURITY: TinyOS was designed from the ground up WITHOUT
 * a /proc filesystem. This eliminates information leakage vulnerabilities
 * that plague traditional Unix/Linux systems.
 *
 * TRADITIONAL UNIX/LINUX WEAKNESS:
 * /proc exposes sensitive process information to user space:
 * - /proc/[pid]/maps: Memory layout (defeats ASLR)
 * - /proc/[pid]/mem: Direct memory access
 * - /proc/[pid]/environ: Environment variables (may contain secrets)
 * - /proc/[pid]/cmdline: Command arguments (may contain passwords)
 * - /proc/[pid]/exe: Executable path (information disclosure)
 * - /proc/sys/kernel/: Kernel configuration (reconnaissance)
 *
 * ATTACK VECTORS ENABLED BY /proc:
 * 1. **ASLR Bypass**: Read /proc/self/maps to find library base addresses
 * 2. **Information Disclosure**: Extract credentials from /proc/[pid]/environ
 * 3. **Process Reconnaissance**: Enumerate running processes for targeted attacks
 * 4. **Kernel Parameter Discovery**: Read /proc/sys to find weaknesses
 * 5. **Memory Dumping**: Use /proc/[pid]/mem for process memory extraction
 * 6. **Privilege Escalation**: Combine /proc info with other vulns
 *
 * HISTORICAL EXPLOITS:
 * - ASLR bypass via /proc/self/maps (countless CVEs)
 * - Dirty COW exploit relied on /proc/self/mem
 * - Container escape via /proc/self/exe manipulation
 * - Privilege escalation via /proc/sys/kernel/core_pattern
 *
 * TINYOS APPROACH:
 * - Process information ONLY accessible via kernel syscalls
 * - Syscalls perform privilege checks (only root can inspect other processes)
 * - No file-based process introspection
 * - Memory layout hidden from user space entirely
 * - Process enumeration restricted to privileged operations
 *
 * SECURITY BENEFITS:
 * - ASLR cannot be bypassed (memory layout never exposed)
 * - No information leakage to unprivileged processes
 * - Kernel maintains complete control over process introspection
 * - Attack surface reduced (no /proc parsing vulnerabilities)
 * - Defense in depth (even if file permissions broken, /proc doesn't exist)
 *
 * ALTERNATIVE MECHANISMS:
 * - Kernel syscalls for process status (getpid, getppid, etc.)
 * - Root-only debug syscalls for process inspection
 * - Kernel audit logs for security monitoring
 * - EDR system for behavioral analysis (kernel-level)
 *
 * This is a PERMANENT architectural decision. Adding /proc support in the
 * future would be considered a security regression.
 *===========================================================================*/
#pragma once

#include <stdint.h>
#include <stdbool.h>

/* Include stdio.h for stream_context_t */
#include "stdio.h"

/* Forward declaration for EDR advanced state (defined in edr_advanced.h) */
typedef struct edr_advanced_state edr_advanced_state_t;

/*=============================================================================
 * CONSTANTS
 *=============================================================================*/
#define MAX_TASKS 32
#define TASK_NAME_LEN 32
/*=============================================================================
 * SECURITY FIX: Kernel Stack Overflow Prevention (Stack Size Increase)
 *
 * ROOT CAUSE: The deep call chain VFS → FAT32 → IDE causes kernel stack
 * exhaustion. The corrupted error code (0x0010ce8b) and EIP (0x00000010)
 * in crash dumps indicate severe stack overflow.
 *
 * SYMPTOMS:
 * - Corrupted saved return addresses on kernel stack
 * - Page faults at guard pages (e.g., 0x00301040)
 * - Triple faults during FAT32 read operations
 *
 * MITIGATION: Increase kernel stack from 128KB to 512KB
 * - Provides headroom for VFS → FAT32 → IDE call depth
 * - Accommodates RSA-2048 bigint operations (nested loops up to 2048 iterations)
 * - Safe margin for interrupt handlers during deep call stacks
 * - Trade-off: 384KB additional memory per task (acceptable for security)
 *
 * RECOMMENDATION: Monitor stack usage and implement stack canaries for
 * overflow detection.
 *===========================================================================*/
#define KERNEL_STACK_SIZE 524288  // 512KB kernel stack per task (128 pages)

/* Kernel-task kernel-stack depth, in 4KB pages. The shell runs as a kernel
 * task and the entire exec chain (cmd_exec -> elf_load_process -> ecdsa_verify
 * -> task_create_user -> PAE page-table setup) executes on this stack before
 * the new process is ever scheduled. At 16 pages (64KB) that chain overflowed
 * into the guard page (#PF -> #DF -> triple fault) whenever signature
 * ENFORCE mode put the deep ECDSA verify subtree on the stack underneath the
 * PAE setup. 32 pages (128KB) gives that chain headroom. */
#define KERNEL_TASK_STACK_PAGES 32

/*=============================================================================
 * TASK STATES
 *=============================================================================*/
typedef enum {
    TASK_STATE_READY,       // Ready to run
    TASK_STATE_RUNNING,     // Currently executing
    TASK_STATE_BLOCKED,     // Waiting for I/O or event
    TASK_STATE_SLEEPING,    // Sleeping until wake_tick
    TASK_STATE_ZOMBIE,      // Terminated but not yet cleaned up (for exit status retrieval)
    TASK_STATE_TERMINATED   // Fully cleaned up, slot can be reused
} task_state_t;

/*=============================================================================
 * TASK PRIORITY LEVELS
 *=============================================================================*/
#define PRIORITY_IDLE       0   // Idle task (lowest priority)
#define PRIORITY_LOW        1   // Background tasks
#define PRIORITY_NORMAL     2   // Default priority
#define PRIORITY_HIGH       3   // Interactive tasks
#define PRIORITY_REALTIME   4   // Time-critical tasks (highest priority)
#define PRIORITY_MAX        4   // Maximum priority value

typedef uint8_t priority_t;

/*=============================================================================
 * CPU CONTEXT - Saved during context switch
 *=============================================================================*/
typedef struct {
    // General purpose registers (saved by software)
    uint32_t edi;
    uint32_t esi;
    uint32_t ebp;
    uint32_t esp;  // Stack pointer
    uint32_t ebx;
    uint32_t edx;
    uint32_t ecx;
    uint32_t eax;

    // Segment registers
    uint32_t ds;
    uint32_t es;
    uint32_t fs;
    uint32_t gs;

    // Instruction pointer and flags
    uint32_t eip;     // Instruction pointer
    uint32_t eflags;  // CPU flags

    // Code and stack segments (for ring 3)
    uint32_t cs;
    uint32_t ss;

    // FPU/SSE/AVX state (CRITICAL for numerical stability)
    // FXSAVE/FXRSTOR requires 512 bytes, 16-byte aligned
    // This prevents FPU state corruption across context switches
    //
    // SECURITY FIX (Issue 7.2): FPU Context Save Alignment
    // CRITICAL: fxsave/fxrstor instructions REQUIRE 16-byte alignment.
    // The Intel specification mandates this - misalignment causes #GP fault.
    // We enforce alignment at field level AND verify at compile time below.
    uint8_t fpu_state[512] __attribute__((aligned(16)));
} cpu_context_t;  // NOTE: NO __attribute__((packed)) - would break alignment!

/*=============================================================================
 * COMPILE-TIME ASSERTION: Verify FPU state alignment
 *
 * SECURITY FIX (Issue 7.2): The cpu_context_t structure MUST NOT use
 * __attribute__((packed)) because it would override the 16-byte alignment
 * requirement of fpu_state, causing #GP faults in fxsave/fxrstor.
 *
 * This assertion verifies that the fpu_state field is properly aligned.
 *=============================================================================*/
_Static_assert(
    __builtin_offsetof(cpu_context_t, fpu_state) % 16 == 0,
    "FPU state must be 16-byte aligned for fxsave/fxrstor"
);

/*=============================================================================
 * PROCESS CONTROL BLOCK (PCB) / TASK STRUCTURE
 *=============================================================================*/
typedef struct task {
    // Task identification
    uint32_t pid;                    // Process ID
    uint32_t generation;             // Generation counter (prevents PID reuse attacks)
    char name[TASK_NAME_LEN];        // Task name

    // Task state
    task_state_t state;              // Current state

    // CPU context (saved during context switch)
    cpu_context_t context;

    // Memory management
    uint32_t page_directory;         // Physical address of page directory
    uint32_t kernel_stack;           // Kernel stack pointer (for syscalls)
    uint32_t user_stack;             // User stack pointer
    uint32_t kernel_stack_phys;      // Physical address of kernel stack base (for freeing)
    uint32_t user_stack_pages_phys[256];  // Physical addresses of user stack pages (max 256 pages = 1MB)
    uint16_t user_stack_pages;       // Number of user stack pages actually allocated (configurable: 8-256)
    uint32_t user_guard_page_phys;   // Physical address of user stack guard page (for stack overflow detection)
    uint32_t guard_page_phys;        // Physical address of kernel stack guard page (for stack overflow detection)
    uint32_t stack_pages_phys[KERNEL_TASK_STACK_PAGES];   // Physical addresses of kernel stack pages (KERNEL_TASK_STACK_PAGES for kernel tasks, 8 for user tasks)

    // Privilege level
    bool is_kernel_task;             // true if Ring 0, false if Ring 3

    // User/Group credentials (v1.10)
    uint16_t uid;                    // Real user ID
    uint16_t gid;                    // Real group ID
    uint16_t euid;                   // Effective user ID (for setuid programs)
    uint16_t egid;                   // Effective group ID (for setgid programs)

    /*=========================================================================
     * SECURITY (v1.12): Supplemental Group IDs
     *
     * ISSUE: Without supplemental groups, a process can only have ONE group
     * membership (gid/egid). In real systems, users belong to multiple groups
     * (e.g., "users", "wheel", "docker"). Without this, privilege dropping via
     * setuid/setgid is incomplete - process retains access via supplemental
     * groups even after dropping primary gid.
     *
     * FIX: Track supplemental group list. Permission checks must verify ALL
     * groups (egid + supplemental). setuid must clear supplemental groups
     * when dropping privileges to prevent privilege retention.
     *=======================================================================*/
    #define NGROUPS_MAX 16
    uint16_t groups[NGROUPS_MAX];    // Supplemental group IDs
    uint8_t  ngroups;                // Number of supplemental groups

    /*=========================================================================
     * SECURITY (v1.13): Process Capabilities
     *
     * Capabilities allow fine-grained privilege separation. A process can
     * have specific capabilities (e.g., CAP_SYSTEM_CRITICAL for reserved
     * resource access) without being fully privileged (uid=0).
     *
     * CAP_SYSTEM_CRITICAL: Can access reserved resource pools (FDs, nodes)
     *=======================================================================*/
    uint32_t capabilities;           // Capability flags (see CAP_* in vfs.h)

    /*=========================================================================
     * SECURITY (EDR Phase 1): Syscall Filtering (Seccomp-like)
     *
     * Per-process syscall allow/deny list for attack surface reduction.
     * Blocks exploit payloads from calling dangerous syscalls (exec, module_load, etc.)
     *
     * DESIGN:
     * - syscall_filter[]: Bitmap of allowed syscalls (1 = allowed, 0 = denied)
     * - filter_enabled: Master switch (false = allow all, true = enforce filter)
     * - Default: filter_enabled = false (backward compatible)
     *
     * EXAMPLE USE:
     *   Browser process: Allow read/write/open, deny exec/ptrace/module_load
     *   This prevents ROP chains from calling system("/bin/sh")
     *
     * BITMAP LAYOUT:
     *   Each uint32_t holds 32 syscalls. Array index = syscall_num / 32.
     *   Bit position = syscall_num % 32.
     *   MAX_SYSCALL_NUM is currently 13, so we only need 1 uint32_t (room for 0-31).
     *   We allocate 4 uint32_t (128 syscalls) for future expansion.
     *=======================================================================*/
    #define SYSCALL_FILTER_SIZE 4   // 4 * 32 = 128 syscalls max
    uint32_t syscall_filter[SYSCALL_FILTER_SIZE];  // Allowed syscalls bitmap
    bool syscall_filter_enabled;                   // Master enable switch

    // Timing information
    uint32_t time_slice;             // Time quantum for scheduling
    uint32_t ticks_remaining;        // Ticks left in current time slice
    uint32_t total_ticks;            // Total CPU time used

    // Priority scheduling
    priority_t priority;             // Task priority (0 = lowest, 4 = highest)
    uint32_t base_time_slice;        // Base time slice (time_slice is adjusted by priority)

    // Sleep management
    uint32_t wake_tick;              // Tick count when sleeping task should wake up

    // Exit status (for ZOMBIE state)
    int exit_status;                 // Exit status code for zombies

    // Context switch tracking
    bool has_run_before;             // true if task has been switched to at least once

    // I/O Streams (per-process stdin/stdout/stderr)
    stream_context_t streams;        // Per-process stream context (embedded)

    /*=========================================================================
     * SECURITY (EDR Phase 2): Behavioral Detection State
     *
     * Per-process syscall pattern tracking and anomaly detection for
     * identifying malicious behavior in real-time.
     *
     * FEATURES:
     * - Syscall history tracking (circular buffer of last 32 syscalls)
     * - Behavioral signature matching (ROP, shellcode, privilege escalation)
     * - Anomaly scoring and alert generation
     *
     * SYSCALL HISTORY: Circular buffer storing last 32 syscalls with:
     * - Syscall number (0-127)
     * - Timestamp (tick count)
     * - First argument (for context)
     *
     * ANOMALY SCORING: Cumulative score (0-65535) based on:
     * - Rare syscall usage (potential ROP gadgets)
     * - Rapid syscall changes (syscall flooding)
     * - Suspicious patterns (exec after network activity)
     *
     * DETECTION ENABLED: Master switch (default: true for all processes)
     *=======================================================================*/
    struct {
        /* Syscall history (circular buffer) */
        struct {
            uint32_t syscall_num;   /* Syscall number (0-127) */
            uint32_t timestamp;     /* Tick count when syscall was made */
            uint32_t arg0;          /* First argument (for context) */
        } history[32];              /* Last 32 syscalls */
        uint8_t history_head;       /* Next write position (0-31) */
        uint8_t history_count;      /* Number of entries (0-32) */

        /* Anomaly scoring */
        uint16_t anomaly_score;     /* Cumulative anomaly score (0-65535) */
        uint16_t alert_count;       /* Number of alerts raised */

        /* Behavioral flags */
        uint8_t flags;              /* Behavioral flags (see EDR_FLAG_* below) */
        #define EDR_FLAG_NETWORK_ACTIVITY  0x01  /* Has network activity */
        #define EDR_FLAG_EXEC_INTENT       0x02  /* Has attempted exec */
        #define EDR_FLAG_PRIVILEGE_CHANGE  0x04  /* Has changed privileges */
        #define EDR_FLAG_DETECTION_ENABLED 0x80  /* Detection enabled (default: on) */

        /* Last detection */
        uint8_t last_signature;     /* Last matched signature (edr_signature_t) */
        uint32_t last_alert_tick;   /* Tick of last alert (rate limiting) */
        uint32_t last_decay_tick;   /* Tick of last score decay (SECURITY: prevents timing evasion) */
    } edr_state;

    /*=========================================================================
     * SECURITY (EDR Phase 3): Advanced Detection State
     *
     * Per-process advanced threat detection including memory inspection,
     * network flow analysis, file integrity monitoring, and crypto monitoring.
     *
     * MODULES:
     * - Memory Inspection: Shellcode detection, RWX regions, code injection
     * - Network Flow: C2 beacon detection, connection tracking, exfiltration
     * - File Integrity: Tamper detection for critical files
     * - Crypto Monitoring: Ransomware detection via encryption patterns
     *
     * POINTER DESIGN: Advanced state is large (~2KB), so we use a pointer
     * that is allocated on-demand. NULL means advanced detection not enabled
     * for this process (lightweight processes can skip it).
     *=======================================================================*/
    edr_advanced_state_t* edr_advanced;  /* Advanced detection state (NULL if disabled) */

    /*=========================================================================
     * SECURITY (v1.11): Per-Process FD Limit Tracking
     *
     * ISSUE: Global FD table (RAMFS_MAX_FDS=16) can be exhausted by a single
     * malicious process, preventing other processes from opening files (DoS).
     *
     * FIX: Track FDs per-process and enforce PROCESS_MAX_FDS limit.
     * - open_fd_count: Number of FDs currently open by this process
     * - Limit: PROCESS_MAX_FDS (defined below, e.g., 8 per process)
     * - Prevents one process from monopolizing global FD table
     * - Provides fair resource sharing across processes
     *=======================================================================*/
    uint8_t open_fd_count;           // Number of open file descriptors

    /*=========================================================================
     * REVOLUTIONARY SECURITY: Per-Process Private /tmp Directory
     *
     * TRADITIONAL UNIX/LINUX WEAKNESS:
     * - Shared world-writable /tmp directory (drwxrwxrwt)
     * - Enables attacks:
     *   * Symlink attacks: Replace /tmp/file with symlink to /etc/passwd
     *   * TOCTOU races: Time-of-check-time-of-use between stat() and open()
     *   * Information leakage: Other users can read predictable temp files
     *   * Denial of service: Fill /tmp to crash system
     *   * Privilege escalation: Exploit setuid programs via temp files
     *
     * TINYOS INNOVATION:
     * - Each process gets its own isolated /tmp namespace
     * - Path: /tmp/XXXXX where XXXXX is a crypto-random 40-bit hex string
     * - Example: Process A sees /tmp/a3f7c2e4b9/
     *            Process B sees /tmp/f1d82c3a71/
     * - Automatically created on process spawn
     * - Automatically cleaned up on process exit
     * - No cross-process visibility (isolated namespaces)
     *
     * BENEFITS:
     * ✅ Symlink attacks impossible (isolated namespace)
     * ✅ No TOCTOU races (only owner can modify)
     * ✅ No information leakage (private to process)
     * ✅ Automatic cleanup (no temp file accumulation)
     * ✅ Per-process quotas (DoS prevention)
     * ✅ No predictable filenames (crypto-random directory name)
     *
     * IMPLEMENTATION:
     * - private_tmp_dir: Full path like "/tmp/a3f7c2e4b9/"
     * - Path resolution: /tmp/foo → /tmp/a3f7c2e4b9/foo (transparent)
     * - Created in process_create(), deleted in process_destroy()
     *
     * CONCLUSION:
     * We eliminate an entire attack class that has plagued Unix/Linux
     * for 50+ years. No more symlink attacks, no more TOCTOU races.
     *=======================================================================*/
    char private_tmp_dir[32];        // Per-process private /tmp (e.g., "/tmp/a3f7c2e4b9/")

    // Linked list for scheduling
    struct task* next;               // Next task in queue

    /*=========================================================================
     * Per-task interrupt/critical-section bookkeeping (see critical.h).
     *
     * __interrupt_context_depth / __critical_section_depth /
     * __critical_section_saved_flags are globals, but they describe the
     * EXECUTION CONTEXT (how deep in ISRs / critical sections the CPU
     * currently is) — state that must travel with the task across a
     * context_switch(). A task suspended mid-ISR (preemptive switch) leaves
     * depth=1 pending its epilogue's decrement, while a task suspended via
     * scheduler_yield() was at depth=0; switching between them without
     * swapping these values desynchronizes the counters and breaks
     * critical-section EFLAGS handling system-wide.
     *
     * Saved/restored by scheduler_switch_kernel_context() around every
     * context_switch(). Zero-initialized at task creation (memset).
     *
     * NOTE: fields are intentionally at the END of task_t —
     * context_switch.S hardcodes the offsets of context (48) and
     * page_directory (624).
     *=======================================================================*/
    uint32_t saved_int_depth;        // __interrupt_context_depth at suspension
    uint32_t saved_crit_depth;       // __critical_section_depth at suspension
    uint32_t saved_crit_flags;       // __critical_section_saved_flags at suspension

} task_t;

/* stack_pages_phys[] is dimensioned to KERNEL_TASK_STACK_PAGES (kernel tasks);
 * the user-task path stores only 8 entries into the same array, so the kernel
 * count must dominate. Guards against the two paths drifting apart (silent
 * drift in the kernel-stack page count previously hid a stack overflow). */
_Static_assert(KERNEL_TASK_STACK_PAGES >= 8,
               "stack_pages_phys[] must hold the 8-page user-task kernel stack");

/*=============================================================================
 * SECURITY: Per-Process Resource Limits
 *=============================================================================*/
#define PROCESS_MAX_FDS  8  // Maximum FDs per process (prevents DoS)

/*=============================================================================
 * USER STACK SIZE PRESETS (in pages, 1 page = 4KB)
 *=============================================================================*/
#define USER_STACK_SMALL    8    // 32KB - Minimal tasks (idle, simple utilities)
#define USER_STACK_NORMAL   32   // 128KB - Standard user processes (shell, editors)
#define USER_STACK_LARGE    128  // 512KB - Cryptographic tasks (SSH, TLS)
#define USER_STACK_HUGE     256  // 1MB - Maximum (future expansion, intensive tasks)
#define USER_STACK_MIN      8    // Minimum allowed
#define USER_STACK_MAX      256  // Maximum allowed (1MB)

/*=============================================================================
 * FUNCTION PROTOTYPES
 *=============================================================================*/

/**
 * @brief Initialize the process management system
 */
void process_init(void);

/**
 * @brief Create a new kernel task
 * @param entry Entry point function
 * @param name Task name
 * @return PID of new task, or -1 on error
 */
int task_create_kernel(void (*entry)(void), const char* name);

/**
 * @brief Create a new user task (Ring 3)
 * @param entry Entry point address
 * @param name Task name
 * @return PID of new task, or -1 on error
 */
int task_create_user(uint32_t entry, const char* name);

/**
 * @brief Create a new user task with custom stack size (Ring 3)
 * @param entry Entry point address
 * @param name Task name
 * @param stack_pages Number of stack pages (USER_STACK_MIN to USER_STACK_MAX)
 * @return PID of new task, or -1 on error
 */
int task_create_user_ex(uint32_t entry, const char* name, uint16_t stack_pages);

/**
 * @brief Set currently running task (used by scheduler)
 * @param task Pointer to task structure
 */
void task_set_current(task_t* task);

/*=============================================================================
 * SECURITY (v2.0): PID + Generation Tuple for Syscalls
 *
 * FUTURE SYSCALLS (waitpid, kill, etc.) should use this structure to prevent
 * PID reuse attacks. Instead of returning just a PID, return both:
 * - pid: Process identifier
 * - generation: Generation counter at time of task creation
 *
 * Example usage:
 *   pid_handle_t handle = sys_waitpid(...);  // Returns {pid, generation}
 *   int result = sys_kill(handle);           // Validates both fields
 *
 * This ensures that stale references (after PID reuse) fail validation.
 *=============================================================================*/
typedef struct {
    uint32_t pid;
    uint32_t generation;
} pid_handle_t;

/**
 * @brief Get task by PID (without generation validation - use with caution!)
 * @param pid Process ID
 * @return Pointer to task structure, or NULL if not found
 * @note This function does NOT validate generation! Use task_get_validated()
 *       when generation is available to prevent PID reuse attacks.
 */
task_t* task_get(uint32_t pid);

/* Look up a task by PID WITHOUT filtering out TERMINATED tasks. For the ELF
 * loader, which just created the task and needs its slot even if a concurrent
 * EDR/scheduler action flipped its state in the lookup window. Returns NULL
 * only if no slot holds that (nonzero) PID at all. */
task_t* task_get_any(uint32_t pid);

/**
 * @brief Get task by PID with generation validation (secure)
 * @param pid Process ID
 * @param generation Generation counter (prevents PID reuse attacks)
 * @return Pointer to task structure, or NULL if not found or generation mismatch
 */
task_t* task_get_validated(uint32_t pid, uint32_t generation);

/**
 * @brief Create secure PID handle from task (for future syscalls)
 * @param task Pointer to task structure
 * @return Handle containing {pid, generation} for validated lookups
 */
pid_handle_t task_get_handle(task_t* task);

/**
 * @brief Get currently running task
 * @return Pointer to current task structure
 */
task_t* task_current(void);
bool task_is_valid_ptr(const void* p);  /* true if p points at a real tasks[] slot */

/**
 * @brief Terminate a task
 * @param pid Process ID
 */
void task_terminate(uint32_t pid);

/**
 * @brief Free all memory owned by a task (stacks, guard pages, page directory,
 *        EDR state). Idempotent: fields are zeroed after freeing.
 * @param task Pointer to the task whose resources should be freed
 */
void task_free_resources(task_t* task);

/**
 * @brief Exit current task
 */
void task_exit(void);

/**
 * @brief Print all tasks (for debugging)
 */
void task_list(void);

/**
 * @brief Get next available PID
 */
uint32_t task_alloc_pid(void);

/**
 * @brief Get all active tasks in the system (for ps command, etc.)
 * @param tasks_out Output array to store pointers to active tasks
 * @param max_tasks Maximum number of tasks to return (size of tasks_out array)
 * @return Number of active tasks found
 *
 * NOTE: Iterates through internal tasks array directly - O(MAX_TASKS) complexity
 * but finds ALL active tasks regardless of PID value.
 */
int task_get_all(task_t** tasks_out, int max_tasks);

/**
 * @brief Free a task slot in the allocator bitmap (for scheduler cleanup)
 * @param task Pointer to the task being freed
 *
 * CRITICAL: Must be called when task is terminated to return slot to free pool
 */
void task_free_slot_for_task(task_t* task);

/**
 * @brief Put current task to sleep for specified ticks
 * @param ticks Number of timer ticks to sleep
 */
void task_sleep(uint32_t ticks);

/**
 * @brief Block the current task (waiting for I/O or event)
 */
void task_block(void);

/**
 * @brief Unblock a task (make it ready to run)
 * @param task Task to unblock
 */
void task_unblock(task_t* task);

/**
 * @brief Set task priority
 * @param task Task to modify
 * @param priority New priority level (0-4)
 */
void task_set_priority(task_t* task, priority_t priority);

/**
 * @brief Get human-readable state name
 * @param state Task state
 * @return String representation of state
 */
const char* task_get_state_string(task_state_t state);

/*=============================================================================
 * PHASE 12: NO CORE DUMPS (Security-by-Design)
 *
 * TRADITIONAL UNIX/LINUX WEAKNESS:
 * When a process crashes, Unix/Linux writes a core dump file containing:
 * - Complete process memory (heap, stack, data segments)
 * - All CPU registers and process state
 * - Often written to /tmp, /var/crash, or current directory
 * - Default permissions often world-readable (especially with old umask)
 *
 * SECURITY ISSUES:
 * 1. **Credential Exposure**:
 *    - Passwords in memory (e.g., SSH agent, database connections)
 *    - API keys, OAuth tokens, encryption keys
 *    - Session cookies, authentication tokens
 *
 * 2. **Information Leakage**:
 *    - Business logic revealed in memory structures
 *    - Algorithmic trade secrets in heap data
 *    - Personal information (PII) from user data
 *
 * 3. **Attack Surface**:
 *    - Core dumps aid exploit development (ASLR addresses visible)
 *    - Core parser vulnerabilities (CVE-2016-4998: gdb core parsing RCE)
 *    - Offline analysis reveals vulnerabilities
 *
 * 4. **Storage/Forensics Issues**:
 *    - Core dumps contain sensitive data forever
 *    - Backup systems copy credentials to insecure locations
 *    - Forensic tools can extract passwords from old dumps
 *
 * REAL-WORLD INCIDENTS:
 * - AWS credentials leaked via core dumps in /tmp
 * - Database passwords extracted from Apache core dumps
 * - SSH private keys recovered from application crashes
 * - Healthcare PII exposed via world-readable cores
 *
 * TINYOS INNOVATION:
 * - NO core dump functionality implemented
 * - Crashes print diagnostics to serial console (for debugging)
 * - Crash diagnostics include:
 *   * Unique crash ID (timestamp-based)
 *   * Faulting instruction address
 *   * CPU registers (for debugging)
 *   * No memory contents written to disk
 * - Production builds can disable even crash diagnostics
 *
 * SECURITY BENEFITS:
 * - No credential leakage via core dumps
 * - No offline exploit analysis possible
 * - No PII exposure in crash files
 * - Minimal information disclosure
 * - Defense in depth: Even if attacker crashes process, no data exposure
 *
 * DEBUGGING STRATEGY:
 * - Development: Full crash diagnostics to serial console
 * - Production: Minimal crash ID only (contact support)
 * - Kernel debugger: Available for live debugging (no disk writes)
 *
 * COMPARISON:
 * - Modern Linux: Encrypted core dumps, restricted permissions
 * - TinyOS: No core dumps at all (more secure by default)
 *
 * This is a PERMANENT architectural decision. Core dumps will NEVER
 * be written to disk in TinyOS.
 *===========================================================================*/
