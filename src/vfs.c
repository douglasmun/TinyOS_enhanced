/*=============================================================================
 * vfs.c - Virtual File System Implementation
 *=============================================================================
 * STATUS: Foundation implemented (v1.9)
 *
 * IMPLEMENTED:
 * - FD table management
 * - Unified security validation
 * - VFS core functions (open, close, read, write)
 * - Driver registration framework
 *
 * TODO for production:
 * - Implement actual drivers (ramfs_vfs, console_vfs, socket_vfs, pipe_vfs)
 * - Refactor existing code to use VFS
 * - Add path resolution logic
 * - Add per-process FD tables
 *=============================================================================*/
#include "vfs.h"
#include "kprintf.h"
#include "critical.h"
#include "process.h"  /* For task_t and task_current() */
#include "scheduler.h"  /* For scheduler_get_current_task() - EDR Phase 1 */
#include "util.h"
#include <stddef.h>

/*=============================================================================
 * GLOBAL VFS STATE
 *=============================================================================*/

/* Global file descriptor table (simplified - single table for all processes) */
static vfs_file_descriptor_t vfs_fd_table[VFS_MAX_FDS];

/* Driver registry (for future driver registration) */
#define VFS_MAX_DRIVERS 8
typedef struct {
    char name[32];
    const file_operations_t* ops;
    bool registered;
} vfs_driver_t;

/* Mount table for drive letters (A-Z) */
#define VFS_MAX_DRIVES 26
typedef struct {
    char drive_letter;           /* 'A' through 'Z' */
    const file_operations_t* ops; /* Driver ops for this drive */
    bool mounted;                /* Is this drive mounted? */
    char driver_name[32];        /* Name of mounted driver */
} vfs_mount_t;

static vfs_driver_t vfs_drivers[VFS_MAX_DRIVERS];
static vfs_mount_t vfs_mounts[VFS_MAX_DRIVES];
static bool vfs_initialized = false;

/*=============================================================================
 * VFS INITIALIZATION
 *=============================================================================*/

void vfs_init(void) {
    if (vfs_initialized) {
        // kprintf("[VFS] WARNING: Already initialized\n");
        return;
    }

    /* Initialize FD table */
    for (int i = 0; i < VFS_MAX_FDS; i++) {
        vfs_fd_table[i].in_use = false;
        vfs_fd_table[i].flags = 0;
        vfs_fd_table[i].type = VFS_TYPE_NONE;
        vfs_fd_table[i].offset = 0;
        vfs_fd_table[i].private_data = NULL;
        vfs_fd_table[i].ops = NULL;
        vfs_fd_table[i].path[0] = '\0';
    }

    /* Initialize driver registry */
    for (int i = 0; i < VFS_MAX_DRIVERS; i++) {
        vfs_drivers[i].name[0] = '\0';
        vfs_drivers[i].ops = NULL;
        vfs_drivers[i].registered = false;
    }

    /* Initialize mount table */
    for (int i = 0; i < VFS_MAX_DRIVES; i++) {
        vfs_mounts[i].drive_letter = 'A' + i;
        vfs_mounts[i].ops = NULL;
        vfs_mounts[i].mounted = false;
        vfs_mounts[i].driver_name[0] = '\0';
    }

    vfs_initialized = true;
    // kprintf("[VFS] Initialized (max_fds=%d)....... [OK]\n", VFS_MAX_FDS);
}

/*=============================================================================
 * DRIVER REGISTRATION
 *=============================================================================*/

int vfs_register_driver(const char* name, const file_operations_t* ops) {
    if (!vfs_initialized) {
        // kprintf("[VFS] ERROR: Not initialized\n");
        return VFS_EINVAL;
    }

    if (!name || !ops) {
        // kprintf("[VFS] ERROR: NULL driver name or ops\n");
        return VFS_EINVAL;
    }

    /* Find free slot */
    for (int i = 0; i < VFS_MAX_DRIVERS; i++) {
        if (!vfs_drivers[i].registered) {
            safe_strcpy(vfs_drivers[i].name, name, sizeof(vfs_drivers[i].name));
            vfs_drivers[i].ops = ops;
            vfs_drivers[i].registered = true;
            kprintf("[VFS] Registered driver '%s'\n", name);
            return 0;
        }
    }

    // kprintf("[VFS] ERROR: Driver registry full\n");
    return VFS_ENOMEM;
}

/*=============================================================================
 * MOUNT TABLE MANAGEMENT
 *=============================================================================*/

int vfs_mount(char drive_letter, const char* driver_name) {
    if (!vfs_initialized) {
        // kprintf("[VFS] ERROR: Not initialized\n");
        return VFS_EINVAL;
    }

    if (!driver_name) {
        // kprintf("[VFS] ERROR: NULL driver name\n");
        return VFS_EINVAL;
    }

    /* Normalize drive letter to uppercase */
    if (drive_letter >= 'a' && drive_letter <= 'z') {
        drive_letter = drive_letter - 'a' + 'A';
    }

    /* Validate drive letter */
    if (drive_letter < 'A' || drive_letter > 'Z') {
        // kprintf("[VFS] ERROR: Invalid drive letter '%c'\n", drive_letter);
        return VFS_EINVAL;
    }

    /* Find the driver */
    const file_operations_t* driver_ops = NULL;
    for (int i = 0; i < VFS_MAX_DRIVERS; i++) {
        if (vfs_drivers[i].registered &&
            strcmp(vfs_drivers[i].name, driver_name) == 0) {
            driver_ops = vfs_drivers[i].ops;
            break;
        }
    }

    if (!driver_ops) {
        // kprintf("[VFS] ERROR: Driver '%s' not found\n", driver_name);
        return VFS_ENOENT;
    }

    /* Mount the drive */
    int index = drive_letter - 'A';
    vfs_mounts[index].drive_letter = drive_letter;
    vfs_mounts[index].ops = driver_ops;
    vfs_mounts[index].mounted = true;
    safe_strcpy(vfs_mounts[index].driver_name, driver_name,
                sizeof(vfs_mounts[index].driver_name));

    // kprintf("[VFS] Mounted %c: as '%s'\n", drive_letter, driver_name);
    return 0;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: vfs_foreach_mount
 * PURPOSE: Iterate through mounted drives and call callback for each
 *---------------------------------------------------------------------------*/
void vfs_foreach_mount(void (*callback)(char drive_letter, const char* driver_name, void* user_data), void* user_data) {
    if (!callback) {
        return;
    }

    for (int i = 0; i < VFS_MAX_DRIVES; i++) {
        if (vfs_mounts[i].mounted) {
            callback(vfs_mounts[i].drive_letter, vfs_mounts[i].driver_name, user_data);
        }
    }
}

/*=============================================================================
 * FD TABLE MANAGEMENT
 *=============================================================================*/

/*-----------------------------------------------------------------------------
 * FUNCTION: vfs_alloc_fd
 * PURPOSE: Allocate a file descriptor with DoS protection
 *
 * SECURITY (v1.13): Resource Reservation for Critical Processes
 *
 * To prevent DoS via FD exhaustion, we reserve VFS_RESERVED_FDS for
 * critical processes (UID=0 or CAP_SYSTEM_CRITICAL capability).
 *
 * Non-privileged processes can only allocate from FDs 0 to
 * (VFS_MAX_FDS - VFS_RESERVED_FDS - 1).
 *
 * If a critical process needs an FD and primary pool is exhausted, it
 * falls back to the reserved pool (last VFS_RESERVED_FDS entries).
 *
 * If reserved pool is also exhausted for a critical process, we trigger
 * a kernel panic as this indicates catastrophic system failure.
 *---------------------------------------------------------------------------*/
static int vfs_alloc_fd(void) {
    CRITICAL_SECTION_ENTER();

    task_t* current = task_current();
    bool is_privileged = false;

    /* During early boot (before scheduler), allow all allocations */
    if (current != NULL) {
        is_privileged = (current->uid == 0) || (current->capabilities & CAP_SYSTEM_CRITICAL);
    }

    /* Primary pool: available to all processes */
    int primary_limit = VFS_MAX_FDS - VFS_RESERVED_FDS;

    for (int i = 0; i < primary_limit; i++) {
        if (!vfs_fd_table[i].in_use) {
            vfs_fd_table[i].in_use = true;
            CRITICAL_SECTION_EXIT();
            return i;
        }
    }

    /* Primary pool exhausted - non-privileged processes fail here */
    if (!is_privileged) {
        CRITICAL_SECTION_EXIT();
        // kprintf("[VFS] FD exhaustion for non-privileged process (PID=%u)\n",
        //         current ? current->pid : 0);
        return VFS_ENOMEM;
    }

    /* Reserved pool: only for privileged processes */
    for (int i = primary_limit; i < VFS_MAX_FDS; i++) {
        if (!vfs_fd_table[i].in_use) {
            vfs_fd_table[i].in_use = true;
            CRITICAL_SECTION_EXIT();
            kprintf("[VFS] WARNING: Using reserved FD %d for critical process (PID=%u)\n",
                    i, current ? current->pid : 0);
            return i;
        }
    }

    /* CATASTROPHIC: Even reserved pool exhausted for critical process */
    CRITICAL_SECTION_EXIT();
    // kprintf("[VFS] CRITICAL: Reserved FD pool exhausted for PID=%u\n",
    //         current ? current->pid : 0);
    panic("VFS: Critical resource exhaustion - system cannot continue");
    return VFS_ENOMEM;  /* Unreachable, but satisfies compiler */
}

/*=============================================================================
 * SECURITY FIX (AUDIT 4C): Mandatory FD Structure Zeroing on Close
 *=============================================================================
 *
 * VULNERABILITY: Residual State Leakage via FD Reuse
 *
 * OLD BEHAVIOR (VULNERABLE):
 * - Zeroed each field individually: in_use, flags, type, offset, etc.
 * - Only zeroed path[0] (first byte), not entire path array
 * - Padding bytes between struct fields may not be zeroed
 * - Error-prone: adding new fields requires updating this function
 *
 * ATTACK SCENARIO:
 * 1. Process A opens "/etc/shadow" (FD 3), reads sensitive data
 * 2. Process A closes FD 3 - old code only clears field pointers
 * 3. Residual data remains: partial path "/etc/shadow", file offset, flags
 * 4. Process B (attacker) gets FD 3 via open()
 * 5. Process B examines FD structure padding/unzeroed data
 * 6. Result: Information leak revealing Process A's file access patterns
 *
 * PRODUCTION FAILURE:
 * - Process opens file with O_SYNC flag, closes it
 * - Next process gets same FD, inherits stale flags in padding
 * - Experiences performance issues from inherited O_SYNC behavior
 * - Debugging shows "ghost" file metadata from previous owner
 *
 * SECURE ZEROING FIX:
 * - Use memset() to zero ENTIRE structure including padding
 * - Guarantees all bytes (data + padding) are cleared
 * - Future-proof: new fields automatically zeroed
 * - Prevents information leakage through memory forensics
 *
 * PERFORMANCE:
 * - memset() of ~300 bytes (path[256] + 6 fields + padding)
 * - Negligible cost compared to file close I/O operations
 * - Security benefit >> minimal performance impact
 *===========================================================================*/

/* Free a file descriptor */
static void vfs_free_fd(int fd) {
    if (fd < 0 || fd >= VFS_MAX_FDS) {
        return;
    }

    CRITICAL_SECTION_ENTER();

    /* SECURITY: Zero ENTIRE FD structure to prevent information leakage */
    memset(&vfs_fd_table[fd], 0, sizeof(vfs_file_descriptor_t));

    /* Explicit marking as unused (redundant after memset, but defensive) */
    vfs_fd_table[fd].in_use = false;
    vfs_fd_table[fd].type = VFS_TYPE_NONE;

    CRITICAL_SECTION_EXIT();
}

/*=============================================================================
 * PATH CANONICALIZATION - Security Critical
 *=============================================================================*/

/**
 * @brief Canonicalize a path by resolving . and .. components
 *
 * SECURITY FIX: Prevent path traversal attacks like /etc/../etc/passwd
 * or /etc/./passwd from bypassing protected path checks.
 *
 * ALGORITHM:
 * - Split path into components
 * - Skip "." components
 * - For "..", pop the previous component (if not root)
 * - Collapse multiple slashes (//)
 * - Produce absolute, clean path
 *
 * @param path Input path (relative or absolute)
 * @param canonical Output buffer for canonicalized path
 * @param max_len Size of canonical buffer
 * @return 0 on success, negative error code on failure
 */
int vfs_canonicalize_path(const char* path, char* canonical, size_t max_len) {
    if (!path || !canonical || max_len == 0) {
        return VFS_EINVAL;
    }

    /* Stack to store path components (simple array-based stack) */
    #define MAX_PATH_COMPONENTS 32
    const char* components[MAX_PATH_COMPONENTS];
    int component_count = 0;

    /* Working buffer for path processing */
    char work_buf[VFS_MAX_PATH];
    if (strlen(path) >= VFS_MAX_PATH) {
        return VFS_EINVAL;
    }
    safe_strcpy(work_buf, path, VFS_MAX_PATH);

    /* Tokenize path by '/' */
    char* token = work_buf;
    char* next = NULL;

    /* SECURITY: All paths resolve from the filesystem root (drivers strip
     * leading slashes), so always emit an absolute path. A relative result
     * (e.g. "etc/passwd") would bypass the protected-path prefix checks. */
    bool is_absolute = true;

    /* Skip leading slashes */
    while (*token == '/') {
        token++;
    }

    /* Process each component */
    while (token && *token) {
        /* Find next slash */
        next = token;
        while (*next && *next != '/') {
            next++;
        }

        /* Null-terminate current component */
        if (*next == '/') {
            *next = '\0';
            next++;
            /* Skip consecutive slashes */
            while (*next == '/') {
                next++;
            }
        }

        /* Process component */
        if (strcmp(token, ".") == 0) {
            /* Current directory - skip */
        } else if (strcmp(token, "..") == 0) {
            /* Parent directory - pop previous component */
            if (component_count > 0) {
                component_count--;
            }
            /* If already at root, silently ignore .. */
        } else if (*token != '\0') {
            /* Normal component - push to stack */
            if (component_count >= MAX_PATH_COMPONENTS) {
                return VFS_EINVAL;
            }
            components[component_count++] = token;
        }

        token = next;
    }

    /* Build canonicalized path */
    size_t pos = 0;

    if (is_absolute) {
        if (pos + 1 >= max_len) {
            return VFS_EINVAL;
        }
        canonical[pos++] = '/';
    }

    for (int i = 0; i < component_count; i++) {
        size_t comp_len = strlen(components[i]);

        /* Add separator (except for first component if absolute) */
        if (i > 0 || !is_absolute) {
            if (i > 0) {
                if (pos + 1 >= max_len) {
                    return VFS_EINVAL;
                }
                canonical[pos++] = '/';
            }
        }

        /* Add component */
        if (pos + comp_len >= max_len) {
            return VFS_EINVAL;
        }
        memcpy(canonical + pos, components[i], comp_len);
        pos += comp_len;
    }

    /* Null-terminate */
    if (pos >= max_len) {
        return VFS_EINVAL;
    }
    canonical[pos] = '\0';

    /* Handle empty path (root or current directory) */
    if (pos == 0) {
        if (is_absolute) {
            canonical[0] = '/';
            canonical[1] = '\0';
        } else {
            canonical[0] = '.';
            canonical[1] = '\0';
        }
    }

    return 0;
}

/*=============================================================================
 * VFS OPEN - Unified security validation and driver dispatch
 *=============================================================================*/

int vfs_open(const char* path, int flags) {
    /*=========================================================================
     * SECURITY: Unified validation for all I/O types
     *=======================================================================*/
    if (!vfs_initialized) {
        return VFS_EINVAL;
    }

    /* Validate path pointer */
    if (!path) {
        return VFS_EFAULT;
    }

    /* Validate path length */
    size_t path_len = strlen(path);
    if (path_len == 0 || path_len >= VFS_MAX_PATH) {
        return VFS_EINVAL;
    }

    /* Allocate FD */
    int fd = vfs_alloc_fd();
    if (fd < 0) {
        return fd;  /* VFS_ENOMEM */
    }

    /*=========================================================================
     * Path resolution and driver selection
     *
     * Support drive letters (C:, D:, etc.) or fallback to default driver.
     * Format: "C:/path/to/file" or "D:/temp/file"
     *=======================================================================*/

    const file_operations_t* driver_ops = NULL;
    const char* actual_path = path;  /* Path to pass to driver */

    /* Check if path starts with drive letter (e.g., "C:" or "D:") */
    if (path_len >= 2 && path[1] == ':' &&
        ((path[0] >= 'A' && path[0] <= 'Z') ||
         (path[0] >= 'a' && path[0] <= 'z'))) {

        /* Extract and normalize drive letter */
        char drive = path[0];
        if (drive >= 'a' && drive <= 'z') {
            drive = drive - 'a' + 'A';
        }

        /* Look up mount table */
        int mount_idx = drive - 'A';
        if (vfs_mounts[mount_idx].mounted) {
            // kprintf("[VFS DEBUG] Drive %c: mounted as '%s', path='%s'\n",
            //         drive, vfs_mounts[mount_idx].driver_name, path + 2);
            driver_ops = vfs_mounts[mount_idx].ops;
            /* Skip drive letter in path (e.g., "C:/file" -> "/file") */
            actual_path = path + 2;
        } else {
            kprintf("[VFS] ERROR: Drive %c: not mounted (mount_idx=%d)\n", drive, mount_idx);
            vfs_free_fd(fd);
            return VFS_ENOENT;
        }
    } else {
        /* No drive letter - use first registered driver (legacy behavior) */
        for (int i = 0; i < VFS_MAX_DRIVERS; i++) {
            if (vfs_drivers[i].registered) {
                driver_ops = vfs_drivers[i].ops;
                break;
            }
        }
    }

    if (!driver_ops || !driver_ops->open) {
        // kprintf("[VFS] ERROR: No driver available for '%s'\n", path);
        vfs_free_fd(fd);
        return VFS_ENOENT;
    }

    /*=========================================================================
     * SECURITY CRITICAL: Path Canonicalization
     *
     * VULNERABILITY FIX: Canonicalize path BEFORE security checks to prevent
     * path traversal bypass attacks.
     *
     * ATTACK EXAMPLES PREVENTED:
     * - /etc/../etc/passwd  → canonicalizes to /etc/passwd
     * - /etc/./passwd       → canonicalizes to /etc/passwd
     * - /etc///passwd       → canonicalizes to /etc/passwd
     * - /tmp/../etc/passwd  → canonicalizes to /etc/passwd
     *
     * Without canonicalization, these paths would bypass the protected path
     * checks because strncmp() wouldn't match the prefix.
     *=======================================================================*/
    char canonical_path[VFS_MAX_PATH];
    int canon_ret = vfs_canonicalize_path(actual_path, canonical_path, VFS_MAX_PATH);
    if (canon_ret < 0) {
        // kprintf("[VFS] ERROR: Path canonicalization failed for '%s'\n", actual_path);
        vfs_free_fd(fd);
        return canon_ret;
    }

    /* Use canonicalized path for all subsequent checks */
    actual_path = canonical_path;

    /*=========================================================================
     * SECURITY (EDR Phase 1): VFS Write Hooks - Protected Path Check
     *
     * Protect critical system files from unauthorized modification.
     * Only processes with CAP_SYS_ADMIN can write to protected paths.
     *
     * PROTECTED PATHS:
     * - /bin/     : System binaries
     * - /sbin/    : System administration binaries
     * - /etc/     : System configuration files
     * - /boot/    : Boot loader and kernel
     *
     * PURPOSE: Prevent malware from:
     * - Modifying system binaries (backdoors)
     * - Tampering with /etc/passwd or /etc/shadow
     * - Installing bootkits in /boot
     * - Persistence via /etc config files
     *
     * PERFORMANCE: Simple string prefix check (~10 cycles) only on write operations
     *
     * NOTE: Path is now canonicalized, so /etc/../etc/passwd attacks are blocked.
     *=======================================================================*/
    if ((flags & (VFS_O_WRONLY | VFS_O_RDWR))) {
        /* This is a write operation - check if path is protected */
        task_t* current_task = scheduler_get_current_task();

        /* List of protected path prefixes */
        const char* protected_paths[] = {
            "/bin/",
            "/sbin/",
            "/etc/",
            "/boot/",
            "/kernel",
            NULL
        };

        /* Check if canonical actual_path matches any protected prefix */
        bool is_protected = false;
        for (int i = 0; protected_paths[i] != NULL; i++) {
            size_t prefix_len = strlen(protected_paths[i]);
            if (strncmp(actual_path, protected_paths[i], prefix_len) == 0) {
                is_protected = true;
                break;
            }
        }

        /* If protected, verify CAP_SYS_ADMIN capability */
        if (is_protected) {
            if (!current_task || !(current_task->capabilities & CAP_SYS_ADMIN)) {
                kprintf("[VFS SECURITY] PID %d: Denied write to protected path '%s'\n",
                        current_task ? current_task->pid : 0, path);
                vfs_free_fd(fd);
                return VFS_EACCES;  /* Permission denied */
            }
            /* Allowed - log for audit */
            kprintf("[VFS] PID %d: Granted write to protected path '%s' (has CAP_SYS_ADMIN)\n",
                    current_task->pid, path);
        }
    }

    /* Call driver's open function with actual path (drive letter stripped) */
    void* private_data = NULL;
    int ret = driver_ops->open(actual_path, flags, &private_data);
    if (ret < 0) {
        /* Open failed - free FD and return error */
        vfs_free_fd(fd);
        return ret;
    }

    /* Store FD info */
    safe_strcpy(vfs_fd_table[fd].path, path, VFS_MAX_PATH);
    vfs_fd_table[fd].flags = flags;
    vfs_fd_table[fd].type = VFS_TYPE_FILE;
    vfs_fd_table[fd].offset = 0;
    vfs_fd_table[fd].private_data = private_data;
    vfs_fd_table[fd].ops = driver_ops;

    return fd;
}

/*=============================================================================
 * VFS CLOSE - Unified security validation and driver dispatch
 *=============================================================================*/

int vfs_close(int fd) {
    /*=========================================================================
     * SECURITY: Unified FD validation
     *=======================================================================*/
    if (!vfs_initialized) {
        return VFS_EINVAL;
    }

    /* Validate FD range */
    if (fd < 0 || fd >= VFS_MAX_FDS) {
        return VFS_EBADF;
    }

    /* Check FD is allocated */
    if (!vfs_fd_table[fd].in_use) {
        return VFS_EBADF;
    }

    /*=========================================================================
     * Driver dispatch
     *=======================================================================*/
    if (vfs_fd_table[fd].ops && vfs_fd_table[fd].ops->close) {
        int result = vfs_fd_table[fd].ops->close(vfs_fd_table[fd].private_data);
        if (result < 0) {
            return result;
        }
    }

    /* Free FD */
    vfs_free_fd(fd);
    return 0;
}

/*=============================================================================
 * VFS READ - Unified security validation and driver dispatch
 *=============================================================================*/

ssize_t vfs_read(int fd, void* buf, size_t size) {
    /*=========================================================================
     * SECURITY: Unified validation for all I/O types
     *=======================================================================*/
    if (!vfs_initialized) {
        return VFS_EINVAL;
    }

    /* Validate FD range */
    if (fd < 0 || fd >= VFS_MAX_FDS) {
        return VFS_EBADF;
    }

    /* Check FD is allocated */
    if (!vfs_fd_table[fd].in_use) {
        return VFS_EBADF;
    }

    /* Validate buffer pointer */
    if (!buf && size > 0) {
        return VFS_EFAULT;
    }

    /*=========================================================================
     * SECURITY FIX (Issue 6.1): Prevent integer overflow on large I/O
     *
     * PROBLEM: If size > SSIZE_MAX (2GB on 32-bit), driver could return
     * a value that, when cast to int, becomes negative (error code).
     *
     * EXAMPLE:
     *   size = 3GB = 3,000,000,000 bytes
     *   driver returns 3,000,000,000
     *   cast to int = -1,294,967,296 (negative!)
     *   caller thinks error occurred
     *
     * FIX: Reject requests larger than SSIZE_MAX before calling driver.
     *=======================================================================*/
    if (size > (size_t)SSIZE_MAX) {
        // kprintf("[VFS] ERROR: Read size %u exceeds SSIZE_MAX (%d)\n",
        //         (unsigned)size, SSIZE_MAX);
        return VFS_EOVERFLOW;
    }

    /* Handle zero-length read */
    if (size == 0) {
        return 0;
    }

    /*=========================================================================
     * Driver dispatch
     *=======================================================================*/
    if (!vfs_fd_table[fd].ops || !vfs_fd_table[fd].ops->read) {
        // kprintf("[VFS] ERROR: No read operation for FD %d\n", fd);
        return VFS_EINVAL;
    }

    return vfs_fd_table[fd].ops->read(vfs_fd_table[fd].private_data, buf, size);
}

/*=============================================================================
 * VFS WRITE - Unified security validation and driver dispatch
 *=============================================================================*/

ssize_t vfs_write(int fd, const void* buf, size_t size) {
    /*=========================================================================
     * SECURITY: Unified validation for all I/O types
     *=======================================================================*/
    if (!vfs_initialized) {
        return VFS_EINVAL;
    }

    /* Validate FD range */
    if (fd < 0 || fd >= VFS_MAX_FDS) {
        return VFS_EBADF;
    }

    /* Check FD is allocated */
    if (!vfs_fd_table[fd].in_use) {
        return VFS_EBADF;
    }

    /* Validate buffer pointer */
    if (!buf && size > 0) {
        return VFS_EFAULT;
    }

    /*=========================================================================
     * SECURITY FIX (Issue 6.1): Prevent integer overflow on large I/O
     *
     * Same rationale as vfs_read() - reject write requests larger than
     * SSIZE_MAX to prevent return value overflow.
     *=======================================================================*/
    if (size > (size_t)SSIZE_MAX) {
        // kprintf("[VFS] ERROR: Write size %u exceeds SSIZE_MAX (%d)\n",
        //         (unsigned)size, SSIZE_MAX);
        return VFS_EOVERFLOW;
    }

    /* Handle zero-length write */
    if (size == 0) {
        return 0;
    }

    /*=========================================================================
     * Driver dispatch
     *=======================================================================*/
    if (!vfs_fd_table[fd].ops || !vfs_fd_table[fd].ops->write) {
        // kprintf("[VFS] ERROR: No write operation for FD %d\n", fd);
        return VFS_EINVAL;
    }

    return vfs_fd_table[fd].ops->write(vfs_fd_table[fd].private_data, buf, size);
}

/*=============================================================================
 * VFS DIRECTORY OPERATIONS
 *=============================================================================*/

/**
 * @brief Create a directory through VFS layer
 *
 * SECURITY: Validates path, canonicalizes it, checks for protected paths,
 * and delegates to driver's mkdir function.
 */
int vfs_mkdir(const char* path) {
    /*=========================================================================
     * SECURITY: Unified validation
     *=======================================================================*/
    if (!vfs_initialized) {
        return VFS_EINVAL;
    }

    /* Validate path pointer */
    if (!path) {
        return VFS_EFAULT;
    }

    /* Validate path length */
    size_t path_len = strlen(path);
    if (path_len == 0 || path_len >= VFS_MAX_PATH) {
        return VFS_EINVAL;
    }

    /*=========================================================================
     * Path resolution and driver selection
     *=======================================================================*/
    const file_operations_t* driver_ops = NULL;
    const char* actual_path = path;

    /* Check if path starts with drive letter (e.g., "C:" or "D:") */
    if (path_len >= 2 && path[1] == ':' &&
        ((path[0] >= 'A' && path[0] <= 'Z') ||
         (path[0] >= 'a' && path[0] <= 'z'))) {

        /* Extract and normalize drive letter */
        char drive = path[0];
        if (drive >= 'a' && drive <= 'z') {
            drive = drive - 'a' + 'A';
        }

        /* Look up mount table */
        int mount_idx = drive - 'A';
        if (vfs_mounts[mount_idx].mounted) {
            driver_ops = vfs_mounts[mount_idx].ops;
            /* Skip drive letter in path (e.g., "C:/file" -> "/file") */
            actual_path = path + 2;
        } else {
            kprintf("[VFS] ERROR: Drive %c: not mounted\n", drive);
            return VFS_ENOENT;
        }
    } else {
        /* No drive letter - use first registered driver */
        for (int i = 0; i < VFS_MAX_DRIVERS; i++) {
            if (vfs_drivers[i].registered) {
                driver_ops = vfs_drivers[i].ops;
                break;
            }
        }
    }

    if (!driver_ops || !driver_ops->mkdir) {
        // kprintf("[VFS] ERROR: No mkdir operation available for '%s'\n", path);
        return VFS_ENOENT;
    }

    /*=========================================================================
     * SECURITY: Path Canonicalization
     *=======================================================================*/
    char canonical_path[VFS_MAX_PATH];
    int canon_ret = vfs_canonicalize_path(actual_path, canonical_path, VFS_MAX_PATH);
    if (canon_ret < 0) {
        // kprintf("[VFS] ERROR: Path canonicalization failed for '%s'\n", actual_path);
        return canon_ret;
    }

    /* Use canonicalized path for all subsequent checks */
    actual_path = canonical_path;

    /*=========================================================================
     * SECURITY: Protected Path Check
     *
     * Only processes with CAP_SYS_ADMIN can create directories in protected paths
     *=======================================================================*/
    task_t* current_task = scheduler_get_current_task();

    /* List of protected path prefixes */
    const char* protected_paths[] = {
        "/bin/",
        "/sbin/",
        "/etc/",
        "/boot/",
        "/kernel",
        NULL
    };

    /* Check if canonical actual_path matches any protected prefix */
    bool is_protected = false;
    for (int i = 0; protected_paths[i] != NULL; i++) {
        size_t prefix_len = strlen(protected_paths[i]);
        if (strncmp(actual_path, protected_paths[i], prefix_len) == 0) {
            is_protected = true;
            break;
        }
    }

    /* If protected, verify CAP_SYS_ADMIN capability */
    if (is_protected) {
        if (!current_task || !(current_task->capabilities & CAP_SYS_ADMIN)) {
            kprintf("[VFS SECURITY] PID %d: Denied mkdir to protected path '%s'\n",
                    current_task ? current_task->pid : 0, path);
            return VFS_EACCES;
        }
    }

    /* Call driver's mkdir function */
    return driver_ops->mkdir(actual_path);
}

/**
 * @brief Remove a directory through VFS layer
 *
 * SECURITY: Validates path, canonicalizes it, checks for protected paths,
 * and delegates to driver's rmdir function.
 */
int vfs_rmdir(const char* path) {
    /*=========================================================================
     * SECURITY: Unified validation
     *=======================================================================*/
    if (!vfs_initialized) {
        return VFS_EINVAL;
    }

    /* Validate path pointer */
    if (!path) {
        return VFS_EFAULT;
    }

    /* Validate path length */
    size_t path_len = strlen(path);
    if (path_len == 0 || path_len >= VFS_MAX_PATH) {
        return VFS_EINVAL;
    }

    /*=========================================================================
     * Path resolution and driver selection
     *=======================================================================*/
    const file_operations_t* driver_ops = NULL;
    const char* actual_path = path;

    /* Check if path starts with drive letter (e.g., "C:" or "D:") */
    if (path_len >= 2 && path[1] == ':' &&
        ((path[0] >= 'A' && path[0] <= 'Z') ||
         (path[0] >= 'a' && path[0] <= 'z'))) {

        /* Extract and normalize drive letter */
        char drive = path[0];
        if (drive >= 'a' && drive <= 'z') {
            drive = drive - 'a' + 'A';
        }

        /* Look up mount table */
        int mount_idx = drive - 'A';
        if (vfs_mounts[mount_idx].mounted) {
            driver_ops = vfs_mounts[mount_idx].ops;
            /* Skip drive letter in path */
            actual_path = path + 2;
        } else {
            kprintf("[VFS] ERROR: Drive %c: not mounted\n", drive);
            return VFS_ENOENT;
        }
    } else {
        /* No drive letter - use first registered driver */
        for (int i = 0; i < VFS_MAX_DRIVERS; i++) {
            if (vfs_drivers[i].registered) {
                driver_ops = vfs_drivers[i].ops;
                break;
            }
        }
    }

    if (!driver_ops || !driver_ops->rmdir) {
        // kprintf("[VFS] ERROR: No rmdir operation available for '%s'\n", path);
        return VFS_ENOENT;
    }

    /*=========================================================================
     * SECURITY: Path Canonicalization
     *=======================================================================*/
    char canonical_path[VFS_MAX_PATH];
    int canon_ret = vfs_canonicalize_path(actual_path, canonical_path, VFS_MAX_PATH);
    if (canon_ret < 0) {
        // kprintf("[VFS] ERROR: Path canonicalization failed for '%s'\n", actual_path);
        return canon_ret;
    }

    /* Use canonicalized path for all subsequent checks */
    actual_path = canonical_path;

    /*=========================================================================
     * SECURITY: Protected Path Check
     *
     * Only processes with CAP_SYS_ADMIN can remove directories in protected paths
     *=======================================================================*/
    task_t* current_task = scheduler_get_current_task();

    /* List of protected path prefixes */
    const char* protected_paths[] = {
        "/bin/",
        "/sbin/",
        "/etc/",
        "/boot/",
        "/kernel",
        NULL
    };

    /* Check if canonical actual_path matches any protected prefix */
    bool is_protected = false;
    for (int i = 0; protected_paths[i] != NULL; i++) {
        size_t prefix_len = strlen(protected_paths[i]);
        if (strncmp(actual_path, protected_paths[i], prefix_len) == 0) {
            is_protected = true;
            break;
        }
    }

    /* If protected, verify CAP_SYS_ADMIN capability */
    if (is_protected) {
        if (!current_task || !(current_task->capabilities & CAP_SYS_ADMIN)) {
            kprintf("[VFS SECURITY] PID %d: Denied rmdir to protected path '%s'\n",
                    current_task ? current_task->pid : 0, path);
            return VFS_EACCES;
        }
    }

    /* Call driver's rmdir function */
    return driver_ops->rmdir(actual_path);
}

/**
 * @brief Read directory entries through VFS layer
 *
 * SECURITY: Validates FD and buffer, delegates to driver's readdir function.
 */
ssize_t vfs_readdir(int fd, void* buf, size_t size) {
    /*=========================================================================
     * SECURITY: Unified validation
     *=======================================================================*/
    if (!vfs_initialized) {
        return VFS_EINVAL;
    }

    /* Validate FD range */
    if (fd < 0 || fd >= VFS_MAX_FDS) {
        return VFS_EBADF;
    }

    /* Check FD is allocated */
    if (!vfs_fd_table[fd].in_use) {
        return VFS_EBADF;
    }

    /* Validate buffer pointer */
    if (!buf && size > 0) {
        return VFS_EFAULT;
    }

    /* Check for overflow */
    if (size > (size_t)SSIZE_MAX) {
        // kprintf("[VFS] ERROR: readdir size %u exceeds SSIZE_MAX (%d)\n",
        //         (unsigned)size, SSIZE_MAX);
        return VFS_EOVERFLOW;
    }

    /* Handle zero-length read */
    if (size == 0) {
        return 0;
    }

    /*=========================================================================
     * Driver dispatch
     *=======================================================================*/
    if (!vfs_fd_table[fd].ops || !vfs_fd_table[fd].ops->readdir) {
        // kprintf("[VFS] ERROR: No readdir operation for FD %d\n", fd);
        return VFS_EINVAL;
    }

    return vfs_fd_table[fd].ops->readdir(vfs_fd_table[fd].private_data, buf, size);
}

/*=============================================================================
 * VFS DEBUGGING/INFORMATION FUNCTIONS
 *=============================================================================*/

const vfs_file_descriptor_t* vfs_get_fd_info(int fd) {
    if (fd < 0 || fd >= VFS_MAX_FDS) {
        return NULL;
    }

    if (!vfs_fd_table[fd].in_use) {
        return NULL;
    }

    return &vfs_fd_table[fd];
}

void vfs_stats(void) {
    int used_fds = 0;
    int drivers_registered = 0;

    for (int i = 0; i < VFS_MAX_FDS; i++) {
        if (vfs_fd_table[i].in_use) {
            used_fds++;
        }
    }

    for (int i = 0; i < VFS_MAX_DRIVERS; i++) {
        if (vfs_drivers[i].registered) {
            drivers_registered++;
        }
    }

    // kprintf("[VFS] Statistics:\n");
    kprintf("  FDs in use: %d/%d\n", used_fds, VFS_MAX_FDS);
    kprintf("  Drivers registered: %d/%d\n", drivers_registered, VFS_MAX_DRIVERS);
    kprintf("  Initialized: %s\n", vfs_initialized ? "yes" : "no");
}
