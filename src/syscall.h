/*=============================================================================
 * syscall.h - System Call Interface for User Mode Programs
 *============================================================================*/
#ifndef SYSCALL_H
#define SYSCALL_H

#include <stdint.h>
#include <stddef.h>

/*-----------------------------------------------------------------------------
 * System Call Numbers
 *-----------------------------------------------------------------------------*/
#define SYS_EXIT        0   // Exit process
#define SYS_WRITE       1   // Write to console
#define SYS_READ        2   // Read from console
#define SYS_GETPID      3   // Get process ID
#define SYS_YIELD       4   // Yield CPU

/* User/Group Management (v1.10) */
#define SYS_GETUID      5   // Get real user ID
#define SYS_GETGID      6   // Get real group ID
#define SYS_GETEUID     7   // Get effective user ID
#define SYS_GETEGID     8   // Get effective group ID
#define SYS_SETUID      9   // Set user ID (root only)
#define SYS_SETGID     10   // Set group ID (root only)
#define SYS_SETEUID    11   // Set effective user ID
#define SYS_SETEGID    12   // Set effective group ID

/* Cryptographic Operations (v1.13) */
#define SYS_CRYPTO     13   // Cryptographic operations (DH, RSA, etc.)

/* Blocking primitives (v2.2) */
#define SYS_SLEEP      17   // Sleep for N milliseconds (blocks, timer wake)
#define SYS_WAITPID    18   // Wait for a child process to exit

/*=============================================================================
 * PHASE 2: Capability-Based Privilege Operations (v1.14)
 *
 * REVOLUTIONARY SECURITY: Eliminate setuid binaries entirely
 *
 * TRADITIONAL UNIX/LINUX WEAKNESS:
 * - Privileged operations require setuid binaries (/bin/passwd, /bin/su, /bin/mount)
 * - Setuid bit makes binary run with root privileges regardless of caller
 * - Accounts for 90% of privilege escalation exploits:
 *   * Buffer overflows in setuid binaries = instant root
 *   * Path injection attacks (PATH=/tmp sudo)
 *   * LD_PRELOAD attacks to hijack library functions
 *   * Race conditions in temp file handling
 * - Examples: Dirty COW, Polkit, sudo vulnerabilities
 *
 * TINYOS INNOVATION: Capability-Based Syscalls
 * - NO setuid binaries anywhere in the system
 * - Privileged operations implemented as kernel syscalls with explicit authentication
 * - Each operation validates credentials at the kernel level
 * - Eliminates entire class of vulnerabilities:
 *   * No buffer overflow escalation (kernel validates, not userspace binary)
 *   * No path injection (kernel has no PATH environment variable)
 *   * No LD_PRELOAD attacks (kernel doesn't load libraries)
 *   * No temp file races (kernel operates on kernel data structures)
 *
 * SECURITY BENEFITS:
 * - Attack surface reduced by ~90% (no more vulnerable setuid binaries)
 * - Explicit authentication for each privileged operation
 * - Kernel-level validation (harder to exploit than userspace)
 * - Audit trail for all privilege operations
 * - Principle of least privilege (only grant capability for specific operation)
 *===========================================================================*/
#define SYS_CHANGE_PASSWORD  14  // Change user password (replaces /bin/passwd)
#define SYS_SWITCH_USER      15  // Switch to another user (replaces /bin/su)

/*=============================================================================
 * PHASE 14: Memory Sealing Syscall (Modern Linux 2024 Feature)
 *
 * TRADITIONAL ATTACK VECTOR:
 * - Attacker exploits vulnerability to call mprotect(code_page, PROT_WRITE)
 * - Modifies .text section to inject shellcode or disable mitigations
 * - ROP/JOP attacks by modifying return addresses in code
 *
 * MODERN DEFENSE:
 * - mseal() permanently locks memory region against modifications
 * - Once sealed, NO operation can modify page table entries
 * - Protects against: mprotect, munmap, mremap, madvise
 * - Even root cannot unseal pages
 *
 * USAGE:
 *   mseal(code_start, code_size);  // Seal .text section after program load
 *
 * SECURITY GUARANTEE:
 * - Sealed pages remain immutable until process termination
 * - Prevents code modification attacks
 * - Enables control-flow integrity (CFI)
 *===========================================================================*/
#define SYS_MSEAL            16  // Seal memory region (make immutable)

/* Crypto operation types */
#define CRYPTO_OP_MODEXP  1  // Modular exponentiation for DH

/*-----------------------------------------------------------------------------
 * SECURITY (v1.11): Maximum syscall number for range validation
 * Update this whenever adding new syscalls
 *-----------------------------------------------------------------------------*/
/* Must cover the HIGHEST number defined above, not the highest in this block:
 * SYS_SLEEP (17) and SYS_WAITPID (18) are declared further up and have working
 * dispatcher cases, but this bound stayed at 16 when they were added, so the
 * range check rejected both before dispatch and userspace could never block. */
#define MAX_SYSCALL_NUM  18  // Highest valid syscall number (SYS_WAITPID)

/*=============================================================================
 * PHASE 11: NO chroot() Syscall (Security-by-Omission)
 *
 * TRADITIONAL UNIX/LINUX WEAKNESS:
 * chroot() changes apparent root directory but is fundamentally broken:
 *
 * SECURITY ISSUES:
 * 1. **Double chroot() escape**:
 *    chroot("/jail"); chroot("../../.."); → escapes jail
 *
 * 2. **Doesn't change working directory**:
 *    chdir("/"); chroot("/jail"); fchdir(saved_fd); → still outside jail
 *
 * 3. **Requires root to call**:
 *    If you're root, you can escape anyway (mknod, ptrace, /proc, etc.)
 *
 * 4. **File descriptor leaks**:
 *    Open FDs outside jail remain accessible after chroot
 *
 * 5. **Mount namespace not isolated**:
 *    Can mount new filesystems to escape
 *
 * HISTORICAL EXPLOITS:
 * - BSD chroot escape (1991): Double chroot to parent directory
 * - Linux chroot + pivot_root escape
 * - Schroot privilege escalation (CVE-2017-2616)
 * - Dozens of container escapes via chroot weaknesses
 *
 * TINYOS INNOVATION:
 * - NO chroot() syscall implemented
 * - No false sense of security from weak jails
 * - Future: Implement proper namespaces/containers instead
 *   (separate PID, mount, network, IPC namespaces)
 *
 * SECURITY BENEFITS:
 * - No chroot escape vulnerabilities
 * - Developers can't rely on broken security model
 * - Forces use of proper containerization (when implemented)
 * - Clear distinction: No isolation = no false assumptions
 *
 * ALTERNATIVE APPROACHES (not yet implemented):
 * - Linux-style namespaces (proper isolation)
 * - FreeBSD jails (more secure than chroot)
 * - Capability-based confinement
 *
 * This is a PERMANENT decision. chroot() will NEVER be implemented.
 * Proper containerization will be added via namespaces in the future.
 *===========================================================================*/
/* #define SYS_CHROOT  <NEVER>  -- EXPLICITLY NOT IMPLEMENTED */

/*-----------------------------------------------------------------------------
 * System Call Handler (called from interrupt)
 *-----------------------------------------------------------------------------*/
void syscall_handler(void);

/*-----------------------------------------------------------------------------
 * IDT Setup for System Calls
 *-----------------------------------------------------------------------------*/
void idt_setup_syscall(void);

/*-----------------------------------------------------------------------------
 * Kernel-side System Call Implementations
 *-----------------------------------------------------------------------------*/
void sys_exit(int status);
int sys_write(int fd, const char* buf, size_t len);
int sys_read(char* buf, size_t len);
int sys_getpid(void);
void sys_yield(void);
int sys_sleep(uint32_t ms);
int sys_waitpid(int pid);

/*-----------------------------------------------------------------------------
 * Record a process death and wake every sys_waitpid() waiter.
 *
 * sys_exit calls this on the clean-exit path. task_terminate MUST call it too:
 * a process killed externally (kill, #PF, guard-page hit) never runs sys_exit,
 * and since waiters now BLOCK on a wait queue instead of polling every tick,
 * an unwoken waiter would hang forever rather than merely noticing late.
 *
 * Takes its own critical section (they nest), so callers already inside one —
 * such as sys_exit's cleanup window — can call it directly.
 *---------------------------------------------------------------------------*/
void waitpid_notify_death(uint32_t pid, uint32_t generation, int status);

/* User/Group Management Syscalls (v1.10) */
uint16_t sys_getuid(void);
uint16_t sys_getgid(void);
uint16_t sys_geteuid(void);
uint16_t sys_getegid(void);
int sys_setuid(uint16_t uid);
int sys_setgid(uint16_t gid);
int sys_seteuid(uint16_t euid);
int sys_setegid(uint16_t egid);

/* Cryptographic Syscalls (v1.13) */
int sys_crypto(int op, void* arg1, void* arg2, void* arg3, void* arg4);

/* Capability-Based Privilege Syscalls (v1.14) */
int sys_change_password(const char* old_password, const char* new_password);
int sys_switch_user(const char* username, const char* password);

/* Memory Sealing Syscall (Phase 14) */
int sys_mseal(uint32_t addr, uint32_t size);

/*-----------------------------------------------------------------------------
 * User-space System Call Wrappers (inline for user programs)
 * These should be compiled with user programs, not the kernel
 *-----------------------------------------------------------------------------*/

#ifdef USER_MODE

// Exit the program
static inline void exit(int status) {
    __asm__ volatile (
        "int $0x80"
        :
        : "a"(SYS_EXIT), "b"(status)
    );
    __builtin_unreachable();
}

// Write to console
static inline int write(int fd, const char* buf, size_t len) {
    int ret;
    __asm__ volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(SYS_WRITE), "b"(fd), "c"(buf), "d"(len)
    );
    return ret;
}

// Read from console (placeholder)
static inline int read(char* buf, size_t len) {
    int ret;
    __asm__ volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(SYS_READ), "b"(buf), "c"(len)
    );
    return ret;
}

// Get process ID (placeholder)
static inline int getpid(void) {
    int ret;
    __asm__ volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(SYS_GETPID)
    );
    return ret;
}

// Yield CPU (placeholder)
static inline void yield(void) {
    __asm__ volatile (
        "int $0x80"
        :
        : "a"(SYS_YIELD)
    );
}

// Helper function to write a string
static inline void puts(const char* str) {
    size_t len = 0;
    while (str[len]) len++;
    write(1, str, len);  // fd=1 for stdout
}

#endif // USER_MODE

#endif // SYSCALL_H
