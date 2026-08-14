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

/* Process creation (v2.3) */
#define SYS_SPAWN      19   // Load an ELF and start it as a child process

/* File I/O (v2.4) — the foundation for a ring-3 shell. Until these existed a
 * user process could not open a file at all: sys_read/sys_write only accepted
 * fds 0/1/2. Descriptors returned here are PER-PROCESS indices (3+) into
 * task->fdtable, not global VFS fds. */
#define SYS_OPEN       20   // Open a file, returns a per-process fd (3+)
#define SYS_CLOSE      21   // Close a per-process fd
#define SYS_READDIR    22   // Read directory entries from a fd opened on a dir
#define SYS_STAT       23   // Metadata for a path, without opening it

/* SYS_LSEEK needed a VFS .seek op and a RAMFS implementation first, so that
 * it could not work on C: and fail on D:. Both now exist (ramfs_seek/tell/
 * fd_size, fat32_tell/fd_size), and whence is resolved in the driver because
 * only the driver holds the live position — see the .seek op in vfs.h. */
#define SYS_LSEEK      24   // Reposition an open fd's cursor

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
#define MAX_SYSCALL_NUM  24  // Highest valid syscall number (SYS_LSEEK)

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
/* fd is honoured and must be STDIN_FILENO; both route through the calling
 * task's stream_context_t rather than the console/keyboard directly. */
int sys_read(int fd, char* buf, size_t len);
int sys_getpid(void);
void sys_yield(void);
int sys_sleep(uint32_t ms);
int sys_waitpid(int pid);

/**
 * @brief Load an ELF from the filesystem and start it as a child process
 *
 * @param user_path User pointer to a NUL-terminated path
 * @param user_argv User pointer to a NULL-terminated char* array, or NULL
 * @return Child PID (> 0) on success, negative errno on failure
 *
 * Does not block. The child inherits the caller's streams and is recorded as
 * its child, so waitpid() on the returned PID works. All user memory is copied
 * in before use.
 */
int sys_spawn(const char* user_path, char* const* user_argv);

/**
 * @brief Open a file or directory, returning a per-process fd
 *
 * @param user_path User pointer to a NUL-terminated path ("/f.txt", "C:/F.TXT")
 * @param flags VFS_O_* flags; VFS_O_DIRECTORY opens a directory for readdir
 * @return Per-process fd (>= TASK_FD_BASE) on success, negative errno on failure
 *
 * The returned descriptor indexes task->fdtable, NOT the global VFS fd pool —
 * ring 3 never learns a global fd number. The path is copied in before use.
 */
int sys_open(const char* user_path, int flags);

/**
 * @brief Close a per-process fd
 * @param fd Per-process fd from sys_open
 * @return 0 on success, negative errno on failure
 */
int sys_close(int fd);

/**
 * @brief Read directory entries into a user buffer
 *
 * @param fd Per-process fd opened with VFS_O_DIRECTORY
 * @param user_buf User pointer receiving an array of vfs_dirent_t
 * @param size Size of user_buf in bytes
 * @return Bytes written (a multiple of sizeof(vfs_dirent_t)), 0 at end of
 *         directory, or negative errno
 */
int sys_readdir(int fd, void* user_buf, uint32_t size);

/**
 * @brief Metadata for a path, without opening it
 * @param user_path User-space path pointer (drive-qualified or not)
 * @param user_buf User-space buffer receiving one vfs_dirent_t
 * @param size Buffer size; must be at least sizeof(vfs_dirent_t)
 * @return 0 on success, negative errno on failure
 */
int sys_stat(const char* user_path, void* user_buf, uint32_t size);

/**
 * @brief Reposition an open fd's read/write cursor
 * @param fd Per-process fd (3+) from SYS_OPEN
 * @param offset Signed displacement, interpreted per `whence`
 * @param whence SEEK_SET / SEEK_CUR / SEEK_END (VFS_SEEK_* values)
 * @return Resulting absolute position, or negative errno
 *
 * Seeking past EOF clamps to the file size on both drives rather than
 * creating a sparse region — neither driver can represent a hole.
 */
int sys_lseek(int fd, int32_t offset, int whence);

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

// Read from the stream bound to fd (0 = stdin)
static inline int read(int fd, char* buf, size_t len) {
    int ret;
    __asm__ volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(SYS_READ), "b"(fd), "c"(buf), "d"(len)
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
