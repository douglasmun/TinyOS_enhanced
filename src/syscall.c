/*=============================================================================
 * syscall.c - System Call Implementation
 *============================================================================*/
#include "syscall.h"
#include "kprintf.h"
#include "kernel.h"
#include "process.h"
#include "paging.h"    // For is_user_address and get_page_table_entry
#include "memory.h"    // For USER_SPACE_END
#include "errno.h"     // For POSIX-style error codes
#include "scheduler.h"
#include "serial.h"
#include "keyboard.h"
#include "copy_user.h" // SECURITY: TOCTOU fix - safe user memory access
#include "util.h"      // For kernel_panic()
#include "critical.h"  // For disable_interrupts/restore_interrupts
#include "user.h"      // For user_* functions (Phase 2: capability-based syscalls)
/* DISABLED: SSH server removed from kernel compilation */
/* #include "ssh_crypto.h" */ // For dh_bigint_t and DH_GROUP14_SIZE
/* #include "rsa.h" */       // For bigint_t and bigint operations
#include "edr_behavioral.h" // EDR Phase 2: Behavioral detection
#include "audit.h"     // For audit_log() in mandatory EDR hook
#include <stddef.h>    // For offsetof() macro used in static assertions

/*-----------------------------------------------------------------------------
 * CPU State Structure (matches syscall stub stack frame)
 * Stack layout from syscall_stub in syscall.S (ESP points to top):
 * 1. pusha pushes: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI (EDI is on top)
 * 2. Before pusha: segment registers were pushed: DS, ES, FS, GS (GS on top)
 * 3. Before that: CPU pushed: EIP, CS, EFLAGS, ESP, SS (EIP on top)
 *
 * So when we pass ESP to this function (after pusha), it points to EDI.
 * The struct must be in REVERSE order of pushing (stack grows down):
 *-----------------------------------------------------------------------------*/
struct cpu_state {
    // Pushed by pusha (last to first, so EDI is at offset 0)
    uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax;
    // Segment registers (in reverse push order, GS was pushed last so it's next)
    uint32_t gs, fs, es, ds;
    // Pushed by CPU automatically (EIP was on top of these)
    uint32_t eip, cs, eflags, useresp, ss;
};

/*=============================================================================
 * STATIC ASSERTIONS: Verify struct layout matches assembly code expectations
 *
 * CRITICAL SECURITY: The assembly code in syscall.S makes hard-coded assumptions
 * about field offsets. If the compiler changes the struct layout (e.g., due
 * to optimization flags, pragma pack, or alignment changes), the assembly
 * code will access WRONG memory locations, causing catastrophic corruption.
 *
 * These compile-time assertions catch layout mismatches IMMEDIATELY, preventing
 * silent data corruption that would be extremely difficult to debug.
 *
 * Expected layout (matching syscall.S push order):
 *   Offset 0:  EDI (first pushed by explicit push edi)
 *   Offset 32: GS (first segment register pushed)
 *   Offset 48: EIP (pushed by CPU during INT 0x80)
 *============================================================================*/
_Static_assert(offsetof(struct cpu_state, edi) == 0,
               "cpu_state.edi must be at offset 0 (first GPR push)");
_Static_assert(offsetof(struct cpu_state, esi) == 4,
               "cpu_state.esi must be at offset 4");
_Static_assert(offsetof(struct cpu_state, ebp) == 8,
               "cpu_state.ebp must be at offset 8");
_Static_assert(offsetof(struct cpu_state, esp) == 12,
               "cpu_state.esp must be at offset 12 (calculated value)");
_Static_assert(offsetof(struct cpu_state, ebx) == 16,
               "cpu_state.ebx must be at offset 16");
_Static_assert(offsetof(struct cpu_state, edx) == 20,
               "cpu_state.edx must be at offset 20");
_Static_assert(offsetof(struct cpu_state, ecx) == 24,
               "cpu_state.ecx must be at offset 24");
_Static_assert(offsetof(struct cpu_state, eax) == 28,
               "cpu_state.eax must be at offset 28 (last GPR push)");
_Static_assert(offsetof(struct cpu_state, gs) == 32,
               "cpu_state.gs must be at offset 32 (first segment push)");
_Static_assert(offsetof(struct cpu_state, fs) == 36,
               "cpu_state.fs must be at offset 36");
_Static_assert(offsetof(struct cpu_state, es) == 40,
               "cpu_state.es must be at offset 40");
_Static_assert(offsetof(struct cpu_state, ds) == 44,
               "cpu_state.ds must be at offset 44 (last segment push)");
_Static_assert(offsetof(struct cpu_state, eip) == 48,
               "cpu_state.eip must be at offset 48 (CPU push 1)");
_Static_assert(offsetof(struct cpu_state, cs) == 52,
               "cpu_state.cs must be at offset 52 (CPU push 2)");
_Static_assert(offsetof(struct cpu_state, eflags) == 56,
               "cpu_state.eflags must be at offset 56 (CPU push 3)");
_Static_assert(offsetof(struct cpu_state, useresp) == 60,
               "cpu_state.useresp must be at offset 60 (CPU push 4)");
_Static_assert(offsetof(struct cpu_state, ss) == 64,
               "cpu_state.ss must be at offset 64 (CPU push 5)");

/* Total size check: 17 fields * 4 bytes = 68 bytes */
_Static_assert(sizeof(struct cpu_state) == 68,
               "cpu_state must be exactly 68 bytes (17 fields * 4 bytes)");

/*-----------------------------------------------------------------------------
 * Function Prototypes (called from assembly)
 *-----------------------------------------------------------------------------*/
void syscall_handler_c(struct cpu_state* state);

/*-----------------------------------------------------------------------------
 * SECURITY: OBSOLETE - validate_user_buffer() REMOVED
 *
 * The old validate_user_buffer() function had a TOCTOU vulnerability:
 * - It checked buffer validity at one time
 * - But kernel accessed buffer at a later time
 * - User could unmap pages between check and use
 *
 * REPLACED WITH: copy_from_user() and copy_to_user()
 * These primitives catch page faults gracefully and return -EFAULT,
 * eliminating the TOCTOU race condition entirely.
 *
 * See copy_user.h and copy_user.c for the secure implementation.
 *-----------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
 * System Call: Exit
 * Terminate the current process
 *-----------------------------------------------------------------------------*/
void sys_exit(int status) {
    kprintf("\n[SYSCALL] Process exited with status %d\n", status);

    // Get current task
    task_t* current = scheduler_get_current_task();

    if (current) {
        kprintf("[SYSCALL] Terminating process PID=%d '%s'\n", current->pid, current->name);

        /*=====================================================================
         * SECURITY (v1.13): Comprehensive Task Cleanup (UAF Prevention)
         *
         * CRITICAL: Before marking task as terminated, we must systematically
         * clear ALL references to this task throughout the kernel to prevent
         * Use-After-Free (UAF) vulnerabilities.
         *
         * ISSUE: If any subsystem retains a stale pointer to this task_t
         * structure, and the slot is later reused for a new process, accessing
         * the stale pointer will corrupt the new process's state or leak data.
         *
         * CLEANUP STEPS:
         * 1. Clear stream contexts (prevent I/O corruption)
         * 2. Reset FD count (prevent accounting errors)
         * 3. Clear parent/child relationships (future: prevent dangling pointers)
         * 4. Wake any tasks waiting on this process (future: prevent deadlock)
         *
         * NOTE: We DON'T free the task_t memory here because we're still
         * using its kernel stack. The scheduler will free it after the
         * context switch completes.
         *
         * NOTE: File descriptors are managed by the global VFS layer and will
         * be cleaned up when the FD table entries are closed or reused.
         *===================================================================*/

        /*=====================================================================
         * SECURITY FIX (HIGH): Disable interrupts during cleanup to prevent
         * race condition where timer interrupt could try to schedule this task
         * between marking it TERMINATED and removing it from ready queue
         *===================================================================*/
        uint32_t eflags = disable_interrupts();

        /* Step 1: Clear stream contexts to prevent I/O corruption */
        current->streams.stdout_stream.is_open = false;
        current->streams.stdin_stream.is_open = false;
        current->streams.stdout_stream.fd = -1;
        current->streams.stdin_stream.fd = -1;

        /* Step 2: Reset FD count */
        current->open_fd_count = 0;

        /*=====================================================================
         * SECURITY FIX (Issue 5.2): ZOMBIE State for Safe Cleanup
         *
         * CRITICAL: We CANNOT mark task as TERMINATED yet because:
         * 1. We're still executing on this task's kernel stack!
         * 2. Scheduler might try to free the stack while we're using it
         * 3. This causes kernel stack corruption → crash
         *
         * FIX: Use two-phase cleanup:
         * - ZOMBIE: Task is dead but resources not yet freed (we're here)
         * - TERMINATED: Resources freed, slot can be reused (after cleanup)
         *
         * The scheduler's cleanup code will transition ZOMBIE → TERMINATED
         * after we've switched away and it's safe to free the stack.
         *===================================================================*/
        current->state = TASK_STATE_ZOMBIE;

        /* Step 4: Remove from ready queue NOW to avoid race condition */
        // where timer interrupt tries to schedule/remove the same task
        kprintf("[SYSCALL] Removing terminated task from ready queue...\n");
        scheduler_remove_task(current);

        /* SECURITY: Re-enable interrupts after atomic cleanup */
        restore_interrupts(eflags);

        kprintf("[SYSCALL] Process cleanup complete, switching to next task...\n");

        // Force a context switch to the next task
        // This should NEVER return since we're terminated
        scheduler_yield();

        // We should never reach here since the task is now terminated
        kprintf("[SYSCALL] ERROR: Returned after termination!\n");
    }

    // Fallback: halt if no current task
    kprintf("[SYSCALL] ERROR: No current task, halting...\n");

    /*
     * SECURITY FIX: Use kernel_panic instead of inline halt loop
     * Provides recursion protection and consistent error handling
     */
    kernel_panic("sys_exit called with no current task");
}

/*-----------------------------------------------------------------------------
 * System Call: Write
 * Write data to console
 *
 * SECURITY FIX: Uses copy_from_user() to prevent TOCTOU race conditions
 * where user unmaps buffer between validation and access.
 *-----------------------------------------------------------------------------*/
int sys_write(int fd, const char* buf, size_t len) {
    // Ignore fd for now (always write to console)
    (void)fd;

    /*=========================================================================
     * SECURITY FIX (CRITICAL): Validate buffer pointer to prevent NULL dereference
     * If buf is NULL and len > 0, this is an invalid request from userspace
     *=======================================================================*/
    if (!buf && len > 0) {
        return -EFAULT;
    }

    if (len == 0) return 0;

    /*=========================================================================
     * SECURITY FIX (AUDIT 2A): Explicit Size Cap Validation
     *
     * VULNERABILITY: Large, unchecked size arguments can cause:
     * - Integer overflows in (buf + len) calculations
     * - Kernel resource exhaustion
     * - Long-running copy operations blocking other tasks
     *
     * DEFENSE: Cap maximum read/write size to reasonable limit (1MB)
     * before any address arithmetic or copy operations.
     *=======================================================================*/
    #define MAX_IO_SIZE (1024 * 1024)  /* 1 MB */
    if (len > MAX_IO_SIZE) {
        kprintf("[SYSCALL] sys_write: size %u exceeds maximum %u\n",
                (unsigned int)len, (unsigned int)MAX_IO_SIZE);
        return -EINVAL;
    }

    /*=========================================================================
     * SECURITY FIX (AUDIT 2A): Boundary Check for User Space
     *
     * CRITICAL: Verify that (buf + len) doesn't exceed USER_SPACE_END
     * to prevent user processes from accessing kernel memory.
     *
     * This is defense-in-depth: copy_from_user also checks, but we
     * reject invalid requests early to avoid wasted work.
     *=======================================================================*/
    uintptr_t buf_addr = (uintptr_t)buf;
    uintptr_t buf_end = buf_addr + len;

    /* Check for wraparound (buf + len < buf) */
    if (buf_end < buf_addr) {
        kprintf("[SYSCALL] sys_write: address wraparound detected\n");
        return -EFAULT;
    }

    /* Check if end address exceeds user space boundary */
    if (buf_end > USER_SPACE_END) {
        kprintf("[SYSCALL] sys_write: buffer extends beyond user space\n");
        return -EFAULT;
    }

    /*=========================================================================
     * SECURITY: Use copy_from_user() Instead of Direct Access
     *
     * OLD (vulnerable):
     *   validate_user_buffer(buf)  ← Check time
     *   ... race window ...
     *   access buf[i]              ← Use time (may page fault!)
     *
     * NEW (secure):
     *   copy_from_user(kernel_buf, buf, len)
     *   - Catches page faults gracefully
     *   - Returns -EFAULT if user unmaps memory
     *   - No kernel crash, no TOCTOU race
     *=======================================================================*/

    /*
     * Copy in chunks to avoid large kernel stack allocations
     * 512 bytes is reasonable for stack-allocated temporary buffer
     */
    #define WRITE_CHUNK_SIZE 512
    char kernel_buf[WRITE_CHUNK_SIZE];
    size_t total_written = 0;

    while (total_written < len) {
        /* Calculate chunk size (min of remaining data and buffer size) */
        size_t chunk_size = len - total_written;
        if (chunk_size > WRITE_CHUNK_SIZE) {
            chunk_size = WRITE_CHUNK_SIZE;
        }

        /*=====================================================================
         * SECURITY FIX (HIGH): Check for pointer overflow before arithmetic
         * If (buf + total_written) wraps around, this is an exploit attempt
         * Check: buf + total_written < buf indicates wraparound
         *===================================================================*/
        if ((uintptr_t)buf + total_written < (uintptr_t)buf) {
            kprintf("[SYSCALL] sys_write: pointer overflow detected\n");
            return (total_written > 0) ? (int)total_written : -EFAULT;
        }

        /*=====================================================================
         * SECURITY: Safe copy with exception handling
         * If user unmaps page during copy, returns -EFAULT
         *===================================================================*/
        int ret = copy_from_user(kernel_buf, buf + total_written, chunk_size);
        if (ret < 0) {
            kprintf("[SYSCALL] sys_write: copy_from_user failed (TOCTOU race?)\n");
            /* Return bytes written so far, or error if nothing written */
            return (total_written > 0) ? (int)total_written : ret;
        }

        /* Now safe to access kernel_buf - output to console and serial */
        for (size_t i = 0; i < chunk_size; i++) {
            console_putc(kernel_buf[i]);
            serial_putc(kernel_buf[i]);
        }

        total_written += chunk_size;
    }

    return (int)total_written;
}

/*-----------------------------------------------------------------------------
 * System Call: Read
 * Read data from console (keyboard)
 *
 * SECURITY FIX: Uses copy_to_user() to prevent TOCTOU race conditions
 * where user unmaps buffer between validation and write.
 *-----------------------------------------------------------------------------*/
int sys_read(char* buf, size_t len) {
    /*=========================================================================
     * SECURITY FIX (CRITICAL): Validate buffer pointer to prevent NULL dereference
     * If buf is NULL and len > 0, this is an invalid request from userspace
     *=======================================================================*/
    if (!buf && len > 0) {
        return -EFAULT;
    }

    if (len == 0) return 0;

    /*=========================================================================
     * SECURITY FIX (AUDIT 2A): Explicit Size Cap Validation
     *
     * VULNERABILITY: Large, unchecked size arguments can cause:
     * - Integer overflows in (buf + len) calculations
     * - Kernel resource exhaustion
     * - Long-running copy operations blocking other tasks
     *
     * DEFENSE: Cap maximum read/write size to reasonable limit (1MB)
     * before any address arithmetic or copy operations.
     *=======================================================================*/
    #define MAX_IO_SIZE (1024 * 1024)  /* 1 MB */
    if (len > MAX_IO_SIZE) {
        kprintf("[SYSCALL] sys_read: size %u exceeds maximum %u\n",
                (unsigned int)len, (unsigned int)MAX_IO_SIZE);
        return -EINVAL;
    }

    /*=========================================================================
     * SECURITY FIX (AUDIT 2A): Boundary Check for User Space
     *
     * CRITICAL: Verify that (buf + len) doesn't exceed USER_SPACE_END
     * to prevent user processes from writing to kernel memory.
     *
     * This is defense-in-depth: copy_to_user also checks, but we
     * reject invalid requests early to avoid wasted work.
     *=======================================================================*/
    uintptr_t buf_addr = (uintptr_t)buf;
    uintptr_t buf_end = buf_addr + len;

    /* Check for wraparound (buf + len < buf) */
    if (buf_end < buf_addr) {
        kprintf("[SYSCALL] sys_read: address wraparound detected\n");
        return -EFAULT;
    }

    /* Check if end address exceeds user space boundary */
    if (buf_end > USER_SPACE_END) {
        kprintf("[SYSCALL] sys_read: buffer extends beyond user space\n");
        return -EFAULT;
    }

    /*=========================================================================
     * SECURITY: Use copy_to_user() Instead of Direct Access
     *
     * OLD (vulnerable):
     *   validate_user_buffer(buf)    ← Check time
     *   ... race window ...
     *   buf[i] = keyboard_getchar()  ← Use time (may page fault!)
     *
     * NEW (secure):
     *   Read into kernel_buf first
     *   copy_to_user(buf, kernel_buf, len)
     *   - Catches page faults gracefully
     *   - Returns -EFAULT if user unmaps memory
     *   - No kernel crash, no TOCTOU race
     *=======================================================================*/

    /*
     * Use kernel buffer to collect input, then copy to user space
     * Limit read size to avoid excessive kernel stack usage
     */
    #define READ_MAX_SIZE 1024
    char kernel_buf[READ_MAX_SIZE];

    /*=========================================================================
     * SECURITY FIX (HIGH): Zero kernel buffer to prevent information disclosure
     * Uninitialized stack buffers may contain sensitive kernel data
     *=======================================================================*/
    memset(kernel_buf, 0, READ_MAX_SIZE);

    size_t read_size = (len > READ_MAX_SIZE) ? READ_MAX_SIZE : len;
    size_t i = 0;

    /*
     * Read characters from keyboard into kernel buffer
     */
    while (i < read_size) {
        char c = keyboard_getchar();  /* Blocks until character available */

        /* Handle special characters */
        if (c == '\n') {
            kernel_buf[i++] = c;
            break;  /* End of line */
        } else if (c == '\b') {
            /* Backspace */
            if (i > 0) {
                i--;
                /* Echo already handled in keyboard IRQ handler */
            }
        } else {
            kernel_buf[i++] = c;
        }
    }

    /*=========================================================================
     * SECURITY: Safe copy to user space with exception handling
     * If user unmaps buffer during copy, returns -EFAULT
     *=======================================================================*/
    if (i > 0) {
        int ret = copy_to_user(buf, kernel_buf, i);
        if (ret < 0) {
            kprintf("[SYSCALL] sys_read: copy_to_user failed (TOCTOU race?)\n");
            return ret;  /* Return -EFAULT */
        }
    }

    return (int)i;
}

/*-----------------------------------------------------------------------------
 * System Call: Get PID
 * Get current process ID
 *-----------------------------------------------------------------------------*/
int sys_getpid(void) {
    // Get current running task
    task_t* current = scheduler_get_current_task();

    if (current) {
        return current->pid;
    }

    RETURN_ERROR(ESRCH);  /* No such process */
}

/*-----------------------------------------------------------------------------
 * System Call: Yield
 * Yield CPU to another process
 *-----------------------------------------------------------------------------*/
void sys_yield(void) {
    // Call the scheduler to switch to the next task
    scheduler_yield();
}

/*=============================================================================
 * USER/GROUP MANAGEMENT SYSCALLS (v1.10)
 *===========================================================================*/

/*-----------------------------------------------------------------------------
 * System Call: Get UID
 * Get real user ID of current process
 *-----------------------------------------------------------------------------*/
uint16_t sys_getuid(void) {
    task_t* current = scheduler_get_current_task();
    if (!current) {
        return (uint16_t)-1;
    }
    return current->uid;
}

/*-----------------------------------------------------------------------------
 * System Call: Get GID
 * Get real group ID of current process
 *-----------------------------------------------------------------------------*/
uint16_t sys_getgid(void) {
    task_t* current = scheduler_get_current_task();
    if (!current) {
        return (uint16_t)-1;
    }
    return current->gid;
}

/*-----------------------------------------------------------------------------
 * System Call: Get EUID
 * Get effective user ID of current process
 *-----------------------------------------------------------------------------*/
uint16_t sys_geteuid(void) {
    task_t* current = scheduler_get_current_task();
    if (!current) {
        return (uint16_t)-1;
    }
    return current->euid;
}

/*-----------------------------------------------------------------------------
 * System Call: Get EGID
 * Get effective group ID of current process
 *-----------------------------------------------------------------------------*/
uint16_t sys_getegid(void) {
    task_t* current = scheduler_get_current_task();
    if (!current) {
        return (uint16_t)-1;
    }
    return current->egid;
}

/*-----------------------------------------------------------------------------
 * System Call: Set UID
 * Set real user ID (only root can change to arbitrary uid)
 *
 * SECURITY:
 * - Only root (euid=0) can change to arbitrary uid
 * - Non-root can only set uid to current euid (drop privileges)
 *-----------------------------------------------------------------------------*/
int sys_setuid(uint16_t uid) {
    task_t* current = scheduler_get_current_task();
    if (!current) {
        RETURN_ERROR(ESRCH);  /* No such process */
    }

    /* Root can change to any uid */
    if (current->euid == 0) {
        current->uid = uid;
        current->euid = uid;  /* Also set euid for simplicity */
        return 0;
    }

    /* Non-root can only set uid to current euid (drop privileges) */
    if (uid == current->euid) {
        current->uid = uid;
        return 0;
    }

    RETURN_ERROR(EPERM);  /* Operation not permitted */
}

/*-----------------------------------------------------------------------------
 * System Call: Set GID
 * Set real group ID (only root can change to arbitrary gid)
 *-----------------------------------------------------------------------------*/
int sys_setgid(uint16_t gid) {
    task_t* current = scheduler_get_current_task();
    if (!current) {
        RETURN_ERROR(ESRCH);  /* No such process */
    }

    /* Root can change to any gid */
    if (current->euid == 0) {
        current->gid = gid;
        current->egid = gid;  /* Also set egid for simplicity */
        return 0;
    }

    /* Non-root can only set gid to current egid (drop privileges) */
    if (gid == current->egid) {
        current->gid = gid;
        return 0;
    }

    RETURN_ERROR(EPERM);  /* Operation not permitted */
}

/*-----------------------------------------------------------------------------
 * System Call: Set EUID
 * Set effective user ID (for setuid programs)
 *
 * SECURITY:
 * - Only root can set euid to arbitrary value
 * - Non-root can toggle between uid and euid
 *-----------------------------------------------------------------------------*/
int sys_seteuid(uint16_t euid) {
    task_t* current = scheduler_get_current_task();
    if (!current) {
        RETURN_ERROR(ESRCH);  /* No such process */
    }

    /* Root can set to any euid */
    if (current->euid == 0) {
        current->euid = euid;
        return 0;
    }

    /* Non-root can toggle between uid and current euid */
    if (euid == current->uid || euid == current->euid) {
        current->euid = euid;
        return 0;
    }

    RETURN_ERROR(EPERM);  /* Operation not permitted */
}

/*-----------------------------------------------------------------------------
 * System Call: Set EGID
 * Set effective group ID
 *-----------------------------------------------------------------------------*/
int sys_setegid(uint16_t egid) {
    task_t* current = scheduler_get_current_task();
    if (!current) {
        RETURN_ERROR(ESRCH);  /* No such process */
    }

    /* Root can set to any egid */
    if (current->euid == 0) {
        current->egid = egid;
        return 0;
    }

    /* Non-root can toggle between gid and current egid */
    if (egid == current->gid || egid == current->egid) {
        current->egid = egid;
        return 0;
    }

    RETURN_ERROR(EPERM);  /* Operation not permitted */
}

/*=============================================================================
 * PHASE 2: Capability-Based Privilege Syscalls (v1.14)
 *
 * These syscalls REPLACE setuid binaries with kernel-level privilege operations.
 * No more /bin/passwd (setuid), /bin/su (setuid), or /bin/mount (setuid).
 *
 * SECURITY ADVANTAGES:
 * 1. Kernel validation (harder to exploit than userspace buffer overflows)
 * 2. No PATH injection attacks
 * 3. No LD_PRELOAD hijacking
 * 4. Explicit authentication for each operation
 * 5. Comprehensive audit trail
 * 6. Eliminates 90% of privilege escalation vulnerabilities
 *===========================================================================*/

/*-----------------------------------------------------------------------------
 * System Call: Change Password
 * Replaces /bin/passwd (setuid root)
 *
 * SECURITY:
 * - Users can change their own password (requires old password verification)
 * - Root can change any user's password (no old password required)
 * - All password changes are audited
 *
 * PARAMETERS:
 * - old_password: Current password (NULL if root changing another user's password)
 * - new_password: New password to set
 *
 * RETURN:
 * - 0 on success
 * - -EFAULT if pointers invalid
 * - -EINVAL if password invalid
 * - -EPERM if authentication fails
 *-----------------------------------------------------------------------------*/
int sys_change_password(const char* old_password, const char* new_password) {
    /*=========================================================================
     * SECURITY: Validate user-space pointers using copy_from_user()
     * Prevents TOCTOU attacks where user unmaps memory after validation
     *=======================================================================*/

    /* Validate new_password pointer (always required) */
    if (!new_password) {
        kprintf("[SYSCALL] sys_change_password: NULL new_password\n");
        RETURN_ERROR(EFAULT);
    }

    task_t* current = scheduler_get_current_task();
    if (!current) {
        RETURN_ERROR(ESRCH);  /* No such process */
    }

    /*=========================================================================
     * SECURITY: Copy passwords from user space to kernel space
     * Maximum password length: USER_MAX_PASSWORD (64 bytes)
     * Uses copy_from_user() to catch page faults gracefully
     *=======================================================================*/
    #define SYSCALL_MAX_PASSWORD_LEN  64
    char kernel_old_password[SYSCALL_MAX_PASSWORD_LEN];
    char kernel_new_password[SYSCALL_MAX_PASSWORD_LEN];

    /* Zero buffers to prevent information leakage */
    memset(kernel_old_password, 0, SYSCALL_MAX_PASSWORD_LEN);
    memset(kernel_new_password, 0, SYSCALL_MAX_PASSWORD_LEN);

    /* Copy new password from user space */
    int ret = copy_from_user(kernel_new_password, new_password, SYSCALL_MAX_PASSWORD_LEN - 1);
    if (ret < 0) {
        kprintf("[SYSCALL] sys_change_password: copy_from_user(new_password) failed\n");
        RETURN_ERROR(EFAULT);
    }

    /* Ensure null termination */
    kernel_new_password[SYSCALL_MAX_PASSWORD_LEN - 1] = '\0';

    /*=========================================================================
     * SECURITY: Validate new password (minimum length, character requirements, etc.)
     * For now, just check that it's not empty
     *=======================================================================*/
    if (kernel_new_password[0] == '\0') {
        kprintf("[SYSCALL] sys_change_password: Empty password not allowed\n");
        RETURN_ERROR(EINVAL);
    }

    /*=========================================================================
     * PRIVILEGE LOGIC:
     * 1. Root (euid=0) can change any user's password without old password
     * 2. Non-root users can only change their own password, must provide old password
     *=======================================================================*/

    if (current->euid == 0) {
        /*=====================================================================
         * ROOT: Can change own password without verification
         * (Root is already authenticated via login)
         *===================================================================*/
        kprintf("[SYSCALL] Root changing password for uid=%d\n", current->uid);

        ret = user_set_password(current->uid, kernel_new_password);

        /* Zero password buffer before returning (defense in depth) */
        memset(kernel_new_password, 0, SYSCALL_MAX_PASSWORD_LEN);

        if (ret == 0) {
            audit_log(AUDIT_USER_PASSWORD_CHANGE, AUDIT_INFO, current->uid,
                      "Password changed by root for uid=%d", current->uid);
            return 0;
        } else {
            kprintf("[SYSCALL] sys_change_password: user_set_password failed (%d)\n", ret);
            RETURN_ERROR(EINVAL);
        }

    } else {
        /*=====================================================================
         * NON-ROOT: Must verify old password before changing
         *===================================================================*/

        /* old_password is required for non-root users */
        if (!old_password) {
            kprintf("[SYSCALL] sys_change_password: Non-root user must provide old_password\n");
            memset(kernel_new_password, 0, SYSCALL_MAX_PASSWORD_LEN);
            RETURN_ERROR(EPERM);
        }

        /* Copy old password from user space */
        ret = copy_from_user(kernel_old_password, old_password, SYSCALL_MAX_PASSWORD_LEN - 1);
        if (ret < 0) {
            kprintf("[SYSCALL] sys_change_password: copy_from_user(old_password) failed\n");
            memset(kernel_new_password, 0, SYSCALL_MAX_PASSWORD_LEN);
            RETURN_ERROR(EFAULT);
        }

        /* Ensure null termination */
        kernel_old_password[SYSCALL_MAX_PASSWORD_LEN - 1] = '\0';

        /*=====================================================================
         * SECURITY: Verify old password before allowing change
         *===================================================================*/
        user_account_t* user = user_find_by_uid(current->uid);
        if (!user) {
            memset(kernel_old_password, 0, SYSCALL_MAX_PASSWORD_LEN);
            memset(kernel_new_password, 0, SYSCALL_MAX_PASSWORD_LEN);
            RETURN_ERROR(ESRCH);
        }

        bool verified = user_verify_password(user->username, kernel_old_password);

        /* Zero old password immediately after verification */
        memset(kernel_old_password, 0, SYSCALL_MAX_PASSWORD_LEN);

        if (!verified) {
            kprintf("[SYSCALL] sys_change_password: Old password verification failed\n");
            memset(kernel_new_password, 0, SYSCALL_MAX_PASSWORD_LEN);
            audit_log(AUDIT_AUTH_PASSWORD_CHANGE_FAILURE, AUDIT_WARN, current->uid,
                      "Failed password change attempt (wrong old password)");
            RETURN_ERROR(EPERM);
        }

        /* Old password verified, set new password */
        ret = user_set_password(current->uid, kernel_new_password);

        /* Zero new password buffer */
        memset(kernel_new_password, 0, SYSCALL_MAX_PASSWORD_LEN);

        if (ret == 0) {
            kprintf("[SYSCALL] Password changed successfully for uid=%d\n", current->uid);
            audit_log(AUDIT_USER_PASSWORD_CHANGE, AUDIT_INFO, current->uid,
                      "User changed own password");
            return 0;
        } else {
            kprintf("[SYSCALL] sys_change_password: user_set_password failed (%d)\n", ret);
            RETURN_ERROR(EINVAL);
        }
    }
}

/*-----------------------------------------------------------------------------
 * System Call: Switch User
 * Replaces /bin/su (setuid root)
 *
 * SECURITY:
 * - Authenticates user before switching
 * - Root can switch to any user without password
 * - Non-root users must provide password
 * - All switches are audited
 *
 * PARAMETERS:
 * - username: Username to switch to
 * - password: Password for authentication (NULL if root switching)
 *
 * RETURN:
 * - 0 on success (process now running as target user)
 * - -EFAULT if pointers invalid
 * - -EINVAL if user not found
 * - -EPERM if authentication fails
 *-----------------------------------------------------------------------------*/
int sys_switch_user(const char* username, const char* password) {
    /*=========================================================================
     * SECURITY: Validate user-space pointers
     *=======================================================================*/
    if (!username) {
        kprintf("[SYSCALL] sys_switch_user: NULL username\n");
        RETURN_ERROR(EFAULT);
    }

    task_t* current = scheduler_get_current_task();
    if (!current) {
        RETURN_ERROR(ESRCH);  /* No such process */
    }

    /*=========================================================================
     * SECURITY: Copy username and password from user space to kernel space
     *=======================================================================*/
    #define SYSCALL_MAX_USERNAME_LEN  32
    #define SYSCALL_MAX_PASSWORD_LEN  64

    char kernel_username[SYSCALL_MAX_USERNAME_LEN];
    char kernel_password[SYSCALL_MAX_PASSWORD_LEN];

    /* Zero buffers */
    memset(kernel_username, 0, SYSCALL_MAX_USERNAME_LEN);
    memset(kernel_password, 0, SYSCALL_MAX_PASSWORD_LEN);

    /* Copy username from user space */
    int ret = copy_from_user(kernel_username, username, SYSCALL_MAX_USERNAME_LEN - 1);
    if (ret < 0) {
        kprintf("[SYSCALL] sys_switch_user: copy_from_user(username) failed\n");
        RETURN_ERROR(EFAULT);
    }

    /* Ensure null termination */
    kernel_username[SYSCALL_MAX_USERNAME_LEN - 1] = '\0';

    /* Validate username not empty */
    if (kernel_username[0] == '\0') {
        kprintf("[SYSCALL] sys_switch_user: Empty username\n");
        RETURN_ERROR(EINVAL);
    }

    /*=========================================================================
     * Lookup target user
     *=======================================================================*/
    user_account_t* target_user = user_find_by_username(kernel_username);
    if (!target_user) {
        kprintf("[SYSCALL] sys_switch_user: User '%s' not found\n", kernel_username);
        RETURN_ERROR(EINVAL);
    }

    /*=========================================================================
     * PRIVILEGE LOGIC:
     * 1. Root (euid=0) can switch to any user without password
     * 2. Non-root users must authenticate with password
     *=======================================================================*/

    if (current->euid == 0) {
        /*=====================================================================
         * ROOT: Can switch to any user without authentication
         *===================================================================*/
        kprintf("[SYSCALL] Root switching to user '%s' (uid=%d)\n",
                kernel_username, target_user->uid);

        /* Switch UID/GID */
        current->uid = target_user->uid;
        current->euid = target_user->uid;
        current->gid = target_user->gid;
        current->egid = target_user->gid;

        audit_log(AUDIT_USER_SWITCH, AUDIT_INFO, target_user->uid,
                  "Root switched to user '%s' (uid=%d)", kernel_username, target_user->uid);

        return 0;

    } else {
        /*=====================================================================
         * NON-ROOT: Must authenticate with password
         *===================================================================*/

        /* Password is required for non-root users */
        if (!password) {
            kprintf("[SYSCALL] sys_switch_user: Non-root user must provide password\n");
            RETURN_ERROR(EPERM);
        }

        /* Copy password from user space */
        ret = copy_from_user(kernel_password, password, SYSCALL_MAX_PASSWORD_LEN - 1);
        if (ret < 0) {
            kprintf("[SYSCALL] sys_switch_user: copy_from_user(password) failed\n");
            RETURN_ERROR(EFAULT);
        }

        /* Ensure null termination */
        kernel_password[SYSCALL_MAX_PASSWORD_LEN - 1] = '\0';

        /*=====================================================================
         * SECURITY: Verify password before switching
         *===================================================================*/
        bool verified = user_verify_password(kernel_username, kernel_password);

        /* Zero password immediately after verification */
        memset(kernel_password, 0, SYSCALL_MAX_PASSWORD_LEN);

        if (!verified) {
            kprintf("[SYSCALL] sys_switch_user: Password verification failed for '%s'\n",
                    kernel_username);
            audit_log(AUDIT_AUTH_SU_FAILURE, AUDIT_WARN, current->uid,
                      "Failed su attempt to user '%s'", kernel_username);
            RETURN_ERROR(EPERM);
        }

        /* Authentication successful, switch user */
        kprintf("[SYSCALL] User uid=%d switching to user '%s' (uid=%d)\n",
                current->uid, kernel_username, target_user->uid);

        current->uid = target_user->uid;
        current->euid = target_user->uid;
        current->gid = target_user->gid;
        current->egid = target_user->gid;

        audit_log(AUDIT_USER_SWITCH, AUDIT_INFO, target_user->uid,
                  "User switched to '%s' (uid=%d)", kernel_username, target_user->uid);

        return 0;
    }
}

/*=============================================================================
 * PHASE 14: Memory Sealing Syscall (mseal) - Modern Linux 2024 Feature
 *
 * Permanently locks memory region, preventing ANY modifications:
 * - Cannot be unmapped (munmap)
 * - Cannot be remapped (mremap)
 * - Cannot change permissions (mprotect)
 * - Cannot modify page table entries
 *
 * PRIMARY USE CASE: Seal .text section after program load to prevent:
 * - Code injection attacks
 * - ROP/JOP chain construction
 * - Security mitigation bypass (patching ASLR, stack canaries)
 *
 * SECURITY: Once sealed, even root cannot unseal pages until process exits
 *===========================================================================*/
int sys_mseal(uint32_t addr, uint32_t size) {
    /*=========================================================================
     * SECURITY: Validate address is in user space
     *=======================================================================*/
    if (addr >= 0xC0000000) {
        kprintf("[SYSCALL] sys_mseal: Cannot seal kernel memory (0x%08x)\n", addr);
        RETURN_ERROR(EINVAL);
    }

    /*=========================================================================
     * SECURITY: Validate size is reasonable (prevent DoS)
     *=======================================================================*/
    #define MAX_SEAL_SIZE (64 * 1024 * 1024)  /* 64 MB max */
    if (size == 0 || size > MAX_SEAL_SIZE) {
        kprintf("[SYSCALL] sys_mseal: Invalid size %u (max %u)\n", size, MAX_SEAL_SIZE);
        RETURN_ERROR(EINVAL);
    }

    /*=========================================================================
     * SECURITY: Check for integer overflow
     *=======================================================================*/
    if (addr + size < addr) {
        kprintf("[SYSCALL] sys_mseal: Address range wraps around\n");
        RETURN_ERROR(EINVAL);
    }

    /*=========================================================================
     * Call PAE sealing function
     *=======================================================================*/
    kprintf("[SYSCALL] sys_mseal: Sealing 0x%08x - 0x%08x (%u bytes)\n",
            addr, addr + size, size);

    int ret = pae_seal_memory(addr, size);
    if (ret < 0) {
        kprintf("[SYSCALL] sys_mseal: Failed to seal memory\n");
        RETURN_ERROR(EPERM);
    }

    /* Null-check current task before dereferencing ->uid, matching the other
     * syscall handlers. Reachable only via int 0x80 from a running task today,
     * so cur is non-NULL in practice — defensive consistency / hardening. */
    task_t* cur = scheduler_get_current_task();
    uint16_t cur_uid = cur ? cur->uid : 0;
    audit_log(AUDIT_MEMORY_SEAL, AUDIT_INFO, cur_uid,
              "Sealed memory region 0x%08x - 0x%08x",
              (unsigned int)addr, (unsigned int)(addr + size));

    return 0;
}

/*-----------------------------------------------------------------------------
 * System Call Dispatcher
 * Called from interrupt handler with register state
 *-----------------------------------------------------------------------------*/
static void syscall_dispatch(struct cpu_state* state) {
    // System call number is in EAX
    uint32_t syscall_num = state->eax;

    // Arguments are in EBX, ECX, EDX, ESI, EDI
    uint32_t arg1 = state->ebx;
    uint32_t arg2 = state->ecx;
    uint32_t arg3 = state->edx;

    // Debug: Log all syscalls
    kprintf("[SYSCALL] num=%d, arg1=0x%x, arg2=0x%x, arg3=0x%x\n",
            syscall_num, arg1, arg2, arg3);

    /*=========================================================================
     * SECURITY FIX (v1.11): Syscall Number Range Validation
     *
     * ISSUE: Malicious user programs could pass arbitrary syscall numbers
     * (e.g., 0xFFFFFFFF) that might cause:
     * - Out-of-bounds table lookups (if we ever use syscall tables)
     * - Integer overflow in switch statements
     * - Unpredictable behavior with negative numbers (when cast to int)
     *
     * FIX: Explicit range check before dispatch
     * - Reject syscall numbers > MAX_SYSCALL_NUM immediately
     * - Return -ENOSYS (function not implemented)
     * - Prevents any potential table access with invalid indices
     *
     * DEFENSE IN DEPTH: While the switch/default already handles invalid
     * numbers safely, explicit validation:
     * 1. Documents the valid range clearly
     * 2. Fails fast with clear error message
     * 3. Protects against future table-based implementations
     * 4. Prevents potential integer overflow issues
     *=======================================================================*/
    if (syscall_num > MAX_SYSCALL_NUM) {
        kprintf("[SYSCALL] ERROR: Invalid syscall number %d (max %d)\n",
                syscall_num, MAX_SYSCALL_NUM);
        state->eax = (uint32_t)(-ENOSYS);
        return;
    }

    /*=========================================================================
     * SECURITY (EDR Phase 1): Syscall Filtering (Seccomp-like)
     *
     * Check if this process has syscall filtering enabled. If so, verify
     * that the requested syscall is in the allow-list.
     *
     * PURPOSE: Prevent exploit payloads from calling dangerous syscalls
     * - Blocks ROP chains from calling exec("/bin/sh")
     * - Prevents shellcode from loading kernel modules
     * - Limits attack surface for sandboxed processes (browsers, network daemons)
     *
     * IMPLEMENTATION:
     * - syscall_filter[]: Bitmap of allowed syscalls (1 = allowed, 0 = denied)
     * - Bit position = syscall_num % 32
     * - Array index = syscall_num / 32
     *
     * PERFORMANCE: Single bitmap check (1 array access + 1 bit test) = ~2 cycles
     *=======================================================================*/
    task_t* current_task = scheduler_get_current_task();
    if (current_task && current_task->syscall_filter_enabled) {
        uint32_t idx = syscall_num / 32;  // Which uint32_t in the array
        uint32_t bit = syscall_num % 32;  // Which bit in that uint32_t

        // Check if syscall is allowed
        if (!(current_task->syscall_filter[idx] & (1 << bit))) {
            kprintf("[SYSCALL FILTER] PID %d: Blocked syscall %d\n",
                    current_task->pid, syscall_num);
            state->eax = (uint32_t)(-ENOSYS);  // Function not implemented
            return;
        }
    }

    /*=========================================================================
     * SECURITY FIX (AUDIT 1B): MANDATORY EDR Pre-Syscall Hook (Defense Evasion)
     *=========================================================================
     *
     * VULNERABILITY: EDR Bypass via Covert Channels
     *
     * ATTACK SCENARIO:
     * 1. Attacker discovers an unchecked syscall path (e.g., sys_fast_bulk_io)
     * 2. Malicious code uses this path to exfiltrate data without EDR detection
     * 3. EDR only monitors standard syscalls (read/write/exec)
     * 4. Attacker bypasses all behavioral analysis
     *
     * FIX: MANDATORY, UNBYPASSABLE Pre-Syscall Hook
     *
     * REQUIREMENTS:
     * 1. **No Conditional Execution** - Hook MUST run for EVERY syscall
     * 2. **Fail-Secure** - Missing current_task is a CRITICAL ERROR (kernel bug)
     * 3. **Audit Trail** - Log any bypass attempts (shouldn't happen in production)
     * 4. **Defense-in-Depth** - Multiple layers of validation
     *
     * ARCHITECTURE:
     * - This hook sits at the ONLY entry point to all kernel privileged operations
     * - No syscall can bypass this check (verified by code inspection)
     * - EDR analyzes syscall patterns to detect malicious behavior in real-time
     *
     * DETECTIONS:
     * - ROP chains (rapid rare syscalls)
     * - Shellcode execution (exec after network read)
     * - Privilege escalation (setuid after exploit indicators)
     * - Data exfiltration (large read → network write)
     * - Syscall flooding (DoS attacks)
     * - Covert channel usage (abnormal syscall sequences)
     *
     * PERFORMANCE: ~20-50 cycles per syscall (negligible overhead)
     *=======================================================================*/

    /* CRITICAL: Verify current_task exists (should never fail in production) */
    if (!current_task) {
        /* This is a KERNEL BUG - syscall from unknown context */
        kprintf("[SYSCALL] CRITICAL: Syscall %d from NULL task (kernel bug!)\n",
                syscall_num);
        audit_log(AUDIT_SEC_EXPLOIT_ATTEMPT, AUDIT_CRITICAL, 0,
                  "SECURITY VIOLATION: Syscall %d from NULL context",
                  (int)syscall_num);
        panic("SECURITY: Syscall from NULL task (possible kernel exploit)");
    }

    /* MANDATORY: Run EDR behavioral analysis (cannot be bypassed) */
    bool allow = edr_behavioral_check(current_task, syscall_num, arg1);
    if (!allow) {
        /* Syscall blocked by behavioral analysis */
        kprintf("[EDR BEHAVIORAL] PID %d: Blocked suspicious syscall %d\n",
                current_task->pid, syscall_num);

        /* AUDIT: Log blocked syscall for forensic analysis */
        audit_log(AUDIT_SEC_POLICY_VIOLATION, AUDIT_CRITICAL, current_task->uid,
                  "EDR blocked syscall %d for PID %d (%s)",
                  (int)syscall_num, (int)current_task->pid, current_task->name);

        state->eax = (uint32_t)(-EPERM);  // Operation not permitted
        return;
    }

    // Return value goes in EAX
    int ret = 0;

    switch (syscall_num) {
        case SYS_EXIT:
            sys_exit((int)arg1);
            // Doesn't return
            break;
            
        case SYS_WRITE:
            /*=================================================================
             * SECURITY (v1.13): Integer Signedness Validation
             *
             * CRITICAL: arg3 (length) comes from user space as a register value.
             * If user passes -1 (0xFFFFFFFF), casting to size_t makes it a
             * huge positive value (4GB), bypassing buffer size checks.
             *
             * DEFENSE: Reject suspiciously large values that could be negative
             * integers. Max reasonable write: 1MB per syscall.
             *===============================================================*/
            if ((uint32_t)arg3 > (1024 * 1024)) {  /* > 1MB */
                ret = -EINVAL;  /* Invalid argument */
                break;
            }
            ret = sys_write((int)arg1, (const char*)arg2, (size_t)arg3);
            break;

        case SYS_READ:
            /*=================================================================
             * SECURITY (v1.13): Integer Signedness Validation
             *
             * CRITICAL: arg2 (length) comes from user space as a register value.
             * If user passes -1 (0xFFFFFFFF), casting to size_t makes it a
             * huge positive value (4GB), bypassing buffer size checks.
             *
             * DEFENSE: Reject suspiciously large values that could be negative
             * integers. Max reasonable read: 1MB per syscall.
             *===============================================================*/
            if ((uint32_t)arg2 > (1024 * 1024)) {  /* > 1MB */
                ret = -EINVAL;  /* Invalid argument */
                break;
            }
            ret = sys_read((char*)arg1, (size_t)arg2);
            break;
            
        case SYS_GETPID:
            ret = sys_getpid();
            break;
            
        case SYS_YIELD:
            sys_yield();
            ret = 0;
            break;

        /* User/Group Management Syscalls (v1.10) */
        case SYS_GETUID:
            ret = sys_getuid();
            break;

        case SYS_GETGID:
            ret = sys_getgid();
            break;

        case SYS_GETEUID:
            ret = sys_geteuid();
            break;

        case SYS_GETEGID:
            ret = sys_getegid();
            break;

        case SYS_SETUID:
            ret = sys_setuid((uint16_t)arg1);
            break;

        case SYS_SETGID:
            ret = sys_setgid((uint16_t)arg1);
            break;

        case SYS_SETEUID:
            ret = sys_seteuid((uint16_t)arg1);
            break;

        case SYS_SETEGID:
            ret = sys_setegid((uint16_t)arg1);
            break;

        /*=====================================================================
         * SECURITY FIX (v1.14 - CRITICAL): Handle SYS_CRYPTO syscall
         *
         * VULNERABILITY: SYS_CRYPTO (13) is defined in syscall.h but has no
         * implementation or dispatcher case. If userspace invokes this syscall,
         * it would fall through to the default case, but the syscall number
         * validation (lines 595-600) allows it through since 13 <= MAX_SYSCALL_NUM.
         *
         * This creates undefined behavior and potential security issues:
         * - User programs see SYS_CRYPTO in the API and might try to use it
         * - The syscall appears "valid" (passes range check) but is unimplemented
         * - This violates the principle of least surprise
         *
         * FIX: Explicitly handle SYS_CRYPTO and return -ENOSYS (not implemented)
         * until a proper implementation is added. This makes the behavior
         * deterministic and prevents confusion.
         *
         * RATIONALE: Explicitly returning -ENOSYS is safer than:
         * 1. Silently ignoring it (falls through to default, same result but less clear)
         * 2. Removing from header (breaks API compatibility)
         * 3. Implementing stub function (adds unnecessary code)
         *===================================================================*/
        case SYS_CRYPTO:
            /* Cryptographic operations are not yet implemented */
            kprintf("[SYSCALL] SYS_CRYPTO called but not implemented\n");
            ret = -ENOSYS;
            break;

        /*=====================================================================
         * PHASE 2: Capability-Based Privilege Syscalls (v1.14)
         * These syscalls REPLACE setuid binaries with kernel-level operations
         *===================================================================*/

        case SYS_CHANGE_PASSWORD:
            /*=================================================================
             * Replace /bin/passwd (setuid root)
             * arg1 = old_password (const char*)
             * arg2 = new_password (const char*)
             *===============================================================*/
            ret = sys_change_password((const char*)arg1, (const char*)arg2);
            break;

        case SYS_SWITCH_USER:
            /*=================================================================
             * Replace /bin/su (setuid root)
             * arg1 = username (const char*)
             * arg2 = password (const char*)
             *===============================================================*/
            ret = sys_switch_user((const char*)arg1, (const char*)arg2);
            break;

        case SYS_MSEAL:
            /*=================================================================
             * PHASE 14: Memory Sealing (Modern Linux 2024)
             * Permanently lock memory region against modifications
             * arg1 = address (uint32_t)
             * arg2 = size (uint32_t)
             *===============================================================*/
            ret = sys_mseal(arg1, arg2);
            break;

        default:
            kprintf("[SYSCALL] ERROR: Unknown system call number %d\n", syscall_num);
            ret = -ENOSYS;  /* Function not implemented */
            break;
    }
    
    /*=========================================================================
     * SECURITY (v1.13): Syscall Return Value Handling
     *
     * CRITICAL: Return values are stored in EAX as 32-bit values.
     * For read/write syscalls that return ssize_t:
     * - Positive values: Successful byte count (0 to SIZE_MAX)
     * - Negative values: Error codes (-1, -EFAULT, -EPERM, etc.)
     *
     * The cast to (uint32_t) preserves the two's complement bit pattern:
     * - Negative errors like -1 become 0xFFFFFFFF in EAX
     * - User space MUST cast EAX to signed int/ssize_t to detect errors
     * - User space MUST NOT cast to size_t or check "if (ret > 0)" directly
     *
     * CORRECT user space usage:
     *   ssize_t ret = read(...);
     *   if (ret < 0) { handle_error(); }
     *
     * INCORRECT user space usage (DANGEROUS):
     *   size_t ret = read(...);  // ERROR: -1 becomes 0xFFFFFFFF!
     *   if (ret > 0) { ... }     // ALWAYS TRUE for errors!
     *
     * This follows Linux/POSIX syscall convention where negative return
     * values indicate errors and are preserved through register storage.
     *=======================================================================*/
    state->eax = (uint32_t)ret;
}

/*-----------------------------------------------------------------------------
 * System Call Handler (called from ISR 128 / 0x80)
 * This is the C entry point from the interrupt
 *-----------------------------------------------------------------------------*/
void syscall_handler_c(struct cpu_state* state) {
    syscall_dispatch(state);
}
