/*=============================================================================
 * ramfs.h - Simple RAM Filesystem
 *=============================================================================*/
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* File types */
#define RAMFS_TYPE_FILE    1
#define RAMFS_TYPE_DIR     2
#define RAMFS_TYPE_SYMLINK 3  /* Symlink (reserved for future use) */

/* File flags */
#define RAMFS_FLAG_READ     0x01
#define RAMFS_FLAG_WRITE    0x02
#define RAMFS_FLAG_INHERIT  0x08  /* PHASE 13: Keep FD open across exec (not close-on-exec) */
/*=============================================================================
 * SECURITY (v1.12): O_NOFOLLOW Flag
 *
 * TOCTOU DEFENSE: Prevents following symlinks during path resolution.
 * ISSUE: Without this flag, an attacker can:
 *   1. Create a file /tmp/safe_file
 *   2. Wait for victim process to canonicalize /tmp/safe_file
 *   3. Replace /tmp/safe_file with symlink -> /etc/passwd
 *   4. Victim opens /etc/passwd instead of intended file (TOCTOU race)
 *
 * FIX: When RAMFS_FLAG_NOFOLLOW is set, ramfs_find() will reject paths
 * containing symlinks, preventing the race condition.
 *
 * USAGE: Shell redirection and security-critical opens should use this flag.
 *=============================================================================*/
#define RAMFS_FLAG_NOFOLLOW 0x04

/*=============================================================================
 * PHASE 3: NO SETUID/SGID BITS (Security-by-Design)
 *
 * REVOLUTIONARY SECURITY: TinyOS was designed from the ground up WITHOUT
 * setuid/sgid/sticky bit support. This eliminates a major class of
 * privilege escalation vulnerabilities.
 *
 * TRADITIONAL UNIX/LINUX WEAKNESS:
 * - Setuid bit (04000): Makes executable run with owner's privileges
 * - Sgid bit (02000): Makes executable run with group's privileges
 * - Sticky bit (01000): Restricts deletion in shared directories
 *
 * WHY THESE ARE DANGEROUS:
 * 1. Buffer overflow in setuid binary = instant root (90% of privilege escalation)
 * 2. Path injection attacks (PATH=/tmp; sudo)
 * 3. LD_PRELOAD attacks to hijack library functions
 * 4. Race conditions in temp file handling
 * 5. Environmental variable attacks (LD_LIBRARY_PATH, etc.)
 *
 * HISTORICAL EXPLOITS PREVENTED:
 * - Dirty COW (CVE-2016-5195): setuid binary exploitation
 * - Polkit (CVE-2021-4034): setuid path manipulation
 * - Sudo vulnerabilities: Dozens of CVEs over the years
 *
 * TINYOS APPROACH:
 * - Privilege operations implemented as kernel syscalls (Phase 2)
 * - Explicit authentication required for each operation
 * - No setuid binaries = no privilege escalation via buffer overflow
 * - Capabilities system (CAP_SETUID) replaces setuid binaries
 *
 * SECURITY GUARANTEES:
 * - File mode bits limited to 0777 (owner/group/other rwx only)
 * - Attempting to set bits 04000, 02000, or 01000 has NO EFFECT
 * - Filesystem driver silently masks out high bits (defense in depth)
 * - No code path exists to honor setuid/sgid on exec
 *
 * COMPATIBILITY:
 * - Standard Unix permission model preserved (user/group/other rwx)
 * - chmod() works for normal permissions
 * - ls -l shows standard permission strings (rwxr-xr-x)
 * - Only setuid/sgid/sticky bits are unsupported
 *
 * This is a PERMANENT architectural decision. Adding setuid/sgid support
 * in the future would be considered a security regression.
 *===========================================================================*/

/* Unix-like permissions (NO setuid/sgid/sticky bits - see above) */
#define RAMFS_PERM_OWNER_READ    0400
#define RAMFS_PERM_OWNER_WRITE   0200
#define RAMFS_PERM_OWNER_EXEC    0100
#define RAMFS_PERM_GROUP_READ    0040
#define RAMFS_PERM_GROUP_WRITE   0020
#define RAMFS_PERM_GROUP_EXEC    0010
#define RAMFS_PERM_OTHER_READ    0004
#define RAMFS_PERM_OTHER_WRITE   0002
#define RAMFS_PERM_OTHER_EXEC    0001

/* Permission mask: ONLY allow standard rwx bits, reject setuid/sgid/sticky */
#define RAMFS_PERM_MASK          0777  /* Mask out any setuid/sgid/sticky bits */

/*=============================================================================
 * PHASE 8: Secure Default Permissions (umask 077)
 *
 * TRADITIONAL UNIX/LINUX WEAKNESS:
 * - Default umask 022 creates world-readable files (mode 644 = rw-r--r--)
 * - Sensitive files accidentally exposed to all users
 * - Example: User creates "passwords.txt" → world-readable by default!
 * - Requires users to remember to set restrictive permissions
 *
 * ATTACK SCENARIOS:
 * - Developer writes API key to /tmp/config.json → world-readable
 * - SSH key generated without explicit mode → readable by attacker
 * - Database credentials in .env file → accessible to all users
 * - Core dumps with passwords → world-readable in /var/crash
 *
 * TINYOS INNOVATION:
 * - Default umask 077 = files created as 600 (rw-------)
 * - Directories created as 700 (rwx------)
 * - Principle of least privilege: Start restrictive, grant access explicitly
 * - No accidental information disclosure
 *
 * SECURITY BENEFITS:
 * - Files private by default (user-only access)
 * - Prevents accidental credential leakage
 * - User must explicitly grant group/other access (chmod)
 * - Fail-secure: Forget to set permissions? Still secure.
 *
 * COMPATIBILITY:
 * - Users can still grant access via explicit chmod
 * - Root can access all files (uid 0 bypass)
 * - Standard Unix permission model preserved
 *===========================================================================*/

/* Default permissions (umask 077 - user-only access) */
#define RAMFS_DEFAULT_FILE_MODE  0600  /* rw------- (was 0644) */
#define RAMFS_DEFAULT_DIR_MODE   0700  /* rwx------ (was 0755) */

/* Limits */
#define RAMFS_MAX_FILES 64
#define RAMFS_MAX_NAME  32
#define RAMFS_PAGE_SIZE 4096          // Each file data page is one PMM frame
#define RAMFS_MAX_PAGES 16            // Up to 16 pages per file
#define RAMFS_MAX_DATA  (RAMFS_MAX_PAGES * RAMFS_PAGE_SIZE)  // 64KB per file max
#define RAMFS_MAX_FDS   16            // Max open file descriptors

/*=============================================================================
 * SECURITY (v1.13): Directory Entry Count Limit
 *
 * ISSUE: Without a limit on directory entries, an attacker could:
 * 1. Create thousands of files/subdirs, causing integer overflow on counters
 * 2. Exhaust memory via unbounded pmm_alloc() calls (DoS)
 * 3. Trigger pathological O(n) iteration in ramfs_find() (performance DoS)
 * 4. Corrupt child list leading to infinite loops
 *
 * FIX: Hard limit of 256 entries per directory. Reasonable for embedded OS.
 *===========================================================================*/
#define RAMFS_MAX_CHILDREN_PER_DIR  256

/* File node structure */
typedef struct ramfs_node {
    char name[RAMFS_MAX_NAME];
    uint8_t type;                    // File or directory
    uint32_t size;                   // File size in bytes
    uint16_t mode;                   // Unix-like permissions (e.g., 0644, 0755)
    uint16_t uid;                    // Owner user ID
    uint16_t gid;                    // Owner group ID
    uint16_t child_count;            // Number of children (v1.13: for RAMFS_MAX_CHILDREN_PER_DIR enforcement)
    uint8_t* data;                   // First data page (kept for back-compat / NULL=empty)
    uint8_t* data_pages[RAMFS_MAX_PAGES]; // Page-table backing: one pmm_alloc() frame per slot
    char* symlink_target;            // Symlink target path (NULL for non-symlinks)
    struct ramfs_node* parent;       // Parent directory
    struct ramfs_node* children;     // First child (for directories)
    struct ramfs_node* next;         // Next sibling
} ramfs_node_t;

/*=============================================================================
 * PHASE 13: O_CLOEXEC by Default (Secure FD Inheritance)
 *
 * TRADITIONAL UNIX/LINUX WEAKNESS:
 * - Child processes inherit ALL parent file descriptors by default
 * - Must explicitly set O_CLOEXEC flag to prevent leakage
 * - Easy to forget, leading to sensitive FDs leaking to untrusted children
 *
 * EXAMPLES OF FD LEAKS:
 * - Parent opens database connection, child inherits socket
 * - Parent reads password file, child can access FD
 * - Parent opens network connection, child hijacks communication
 * - CGI scripts inherit web server FDs (security nightmare)
 *
 * TINYOS INNOVATION:
 * - ALL FDs are close-on-exec by default (reversed semantics)
 * - Must explicitly request FD inheritance with RAMFS_FLAG_INHERIT
 * - Secure by default: Forget to set flag? Still secure.
 * - Fail-secure design: No accidental FD leaks
 *===========================================================================*/

/* File descriptor structure */
typedef struct {
    ramfs_node_t* node;
    uint32_t pos;                    // Current position
    uint8_t flags;                   // Read/Write flags
    bool in_use;
    bool close_on_exec;              // PHASE 13: Close this FD on exec (default: true)
} ramfs_fd_t;

/* Initialize the filesystem */
void ramfs_init(void);

/* File operations */
int ramfs_open(const char* path, uint8_t flags);
int ramfs_read(int fd, void* buf, size_t count);
int ramfs_write(int fd, const void* buf, size_t count);
void ramfs_close(int fd);
int ramfs_unlink(const char* path);

/* PHASE 13: Close-on-exec cleanup */
void ramfs_close_on_exec(void);

/*=============================================================================
 * PHASE 6: Crypto-Random Temporary File API
 *
 * REPLACES: Traditional mktemp(), tmpfile(), tempnam() with predictable names
 *
 * TRADITIONAL UNIX/LINUX WEAKNESS:
 * - mktemp() uses PID + counter → predictable filenames (/tmp/file.12345)
 * - Race condition window: mktemp() returns name, then caller opens
 * - Attacker can win race and create file first (symlink attack, data injection)
 * - tmpnam() has same issues (predictable sequence)
 *
 * ATTACK SCENARIO:
 * 1. Victim calls mktemp() → "/tmp/app.12345"
 * 2. Attacker monitors /tmp, sees pattern
 * 3. Attacker predicts next filename → "/tmp/app.12346"
 * 4. Attacker pre-creates symlink: /tmp/app.12346 → /etc/passwd
 * 5. Victim opens "/tmp/app.12346", writes to /etc/passwd (privilege escalation!)
 *
 * TINYOS SECURE APPROACH:
 * - Uses CSPRNG to generate 128-bit random filename (32 hex chars)
 * - Creates file atomically with O_EXCL flag (fails if exists)
 * - Returns open file descriptor (no race window)
 * - Creates in caller's private /tmp directory (Phase 1)
 * - Filename format: /tmp/XXXXXXXXXX/YYYYYYYY.tmp
 *   where X = per-process private dir, Y = crypto-random
 *
 * SECURITY BENEFITS:
 * - Cryptographically unpredictable filenames (2^128 possible values)
 * - No race condition (atomic create + open)
 * - Isolated per-process /tmp (attacker can't access)
 * - Automatic cleanup on process exit
 *
 * USAGE:
 *   int fd = ramfs_mkstemps(filename_buffer, sizeof(filename_buffer));
 *   if (fd < 0) { handle_error(); }
 *   // Use fd for temp file operations
 *   ramfs_close(fd);
 *===========================================================================*/

/**
 * @brief Create crypto-random temporary file (secure mktemp replacement)
 *
 * Creates a temporary file with cryptographically random name in the current
 * process's private /tmp directory. The file is created atomically with
 * exclusive access, preventing race conditions.
 *
 * @param filename_out Buffer to receive full path of created file (min 64 bytes)
 * @param buf_size Size of filename_out buffer
 * @return File descriptor (>=0) on success, negative error code on failure
 *         -1: Buffer too small
 *         -2: Failed to get current task (no process context)
 *         -3: Failed to generate random bytes
 *         -4: Failed to create file (directory doesn't exist or file collision)
 *
 * EXAMPLE:
 *   char tmpfile[64];
 *   int fd = ramfs_mkstemps(tmpfile, sizeof(tmpfile));
 *   if (fd >= 0) {
 *       ramfs_write(fd, "temp data", 9);
 *       ramfs_close(fd);
 *       ramfs_unlink(tmpfile);  // Delete when done
 *   }
 */
int ramfs_mkstemps(char* filename_out, size_t buf_size);

/**
 * @brief Atomic rename/move operation
 * @param old_path Source path
 * @param new_path Destination path
 * @return 0 on success, -1 if source doesn't exist, -2 if destination exists,
 *         -3 if paths invalid, -4 if permission denied
 *
 * SECURITY: Atomic operation - no data copying, just updates the name field
 * This prevents race conditions and data loss in copy-then-delete operations
 */
int ramfs_rename(const char* old_path, const char* new_path);

/* Directory operations */
int ramfs_mkdir(const char* path);
int ramfs_rmdir(const char* path);
ramfs_node_t* ramfs_readdir(const char* path);

/* Debug function: Check RAMFS root integrity */
void ramfs_debug_root(void);

/* Utility functions */
ramfs_node_t* ramfs_find(const char* path);
void ramfs_list(const char* path);
ramfs_node_t* ramfs_get_root(void);

/* Permission operations */
int ramfs_chmod(const char* path, uint16_t mode);
bool ramfs_check_permission(ramfs_node_t* node, uint16_t uid, uint16_t gid, uint8_t access);
void ramfs_format_permissions(uint16_t mode, char* buf);
