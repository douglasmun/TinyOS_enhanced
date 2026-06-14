/*=============================================================================
 * vfs.h - Virtual File System Interface
 *=============================================================================
 * Provides unified I/O abstraction for all I/O types:
 * - Files (RAMFS)
 * - Devices (console, serial)
 * - Sockets (TCP/UDP)
 * - Pipes (IPC)
 *
 * SECURITY BENEFITS (v1.9):
 * - Single point for FD validation (defense-in-depth)
 * - Consistent error handling across all I/O types
 * - Unified buffer validation (prevents TOCTOU)
 * - Easier to audit (one interface vs. many)
 *
 * ARCHITECTURE:
 * Each I/O type implements file_operations_t interface.
 * VFS layer routes operations to appropriate driver.
 * All security checks happen in VFS layer (not drivers).
 *
 * STATUS: Foundation implemented (v1.9)
 * - VFS interface defined
 * - Core VFS functions implemented
 * - FD table management
 * - Security validation layer
 *
 * TODO for full production:
 * - Refactor RAMFS to use VFS (ramfs_vfs.c)
 * - Refactor console to use VFS (console_vfs.c)
 * - Refactor sockets to use VFS (socket_vfs.c)
 * - Refactor pipes to use VFS (pipe_vfs.c)
 * - Update all call sites to use vfs_* functions
 *=============================================================================*/
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*=============================================================================
 * TYPE DEFINITIONS
 *=============================================================================*/

/*
 * SECURITY FIX (Issue 6.1): I/O Size/Error Return Type Mismatch
 *
 * PROBLEM: Using int for read/write return values creates ambiguity:
 * - Positive: bytes transferred (can be up to 2GB on 32-bit system)
 * - Negative: error code
 * - But int max is only 2^31-1 (2,147,483,647 bytes)
 *
 * BUG SCENARIO:
 *   User requests to read 3GB (size_t = 3,000,000,000)
 *   Driver returns (int)3,000,000,000 = -1,294,967,296 (negative!)
 *   Caller thinks error occurred, but operation succeeded
 *
 * FIX: Use ssize_t (signed size_t) which is explicitly designed for this:
 * - ssize_t can represent ALL valid size_t values as signed
 * - Negative values reserved for errors
 * - Positive values = bytes transferred
 * - SSIZE_MAX = maximum positive value (INT32_MAX on 32-bit)
 *
 * POSIX COMPLIANCE: This matches POSIX read()/write() semantics.
 */

#ifndef SSIZE_MAX
typedef int32_t ssize_t;                /* Signed size type for I/O operations */
#define SSIZE_MAX       2147483647      /* Maximum value for ssize_t (2^31 - 1) */
#endif

/*=============================================================================
 * VFS CONSTANTS
 *=============================================================================*/
#define VFS_MAX_FDS         64      /* Maximum file descriptors */
#define VFS_RESERVED_FDS    6       /* Reserved FDs for critical processes (10% of VFS_MAX_FDS) */
#define VFS_MAX_PATH        256     /* Maximum path length */

/*=============================================================================
 * PROCESS CAPABILITY FLAGS (EDR Phase 1)
 *
 * Fine-grained privilege control for processes. Capabilities allow specific
 * privileges without granting full root access.
 *
 * SECURITY DESIGN:
 * - Default processes have NO capabilities (0x00)
 * - Root processes (uid=0) get ALL capabilities by default
 * - Setuid programs can drop capabilities for least privilege
 *=============================================================================*/

/* Resource Management */
#define CAP_SYSTEM_CRITICAL 0x00000001  /* Can access reserved resource pool */

/* Filesystem Operations */
#define CAP_FS_READ         0x00000002  /* Can read from filesystems */
#define CAP_FS_WRITE        0x00000004  /* Can write to filesystems */
#define CAP_SYS_ADMIN       0x00000008  /* Can modify system files (/bin, /etc, /boot) */

/* Network Operations */
#define CAP_NET_RAW         0x00000010  /* Can create raw sockets */
#define CAP_NET_ADMIN       0x00000020  /* Can configure network interfaces */

/* Process Operations */
#define CAP_KILL            0x00000040  /* Can send signals to any process */
#define CAP_SETUID          0x00000080  /* Can change user ID */
#define CAP_SETGID          0x00000100  /* Can change group ID */

/* System Operations */
#define CAP_SYS_MODULE      0x00000200  /* Can load kernel modules */
#define CAP_SYS_RAWIO       0x00000400  /* Can access I/O ports and physical memory */
#define CAP_SYS_BOOT        0x00000800  /* Can reboot system */

/* Protection capabilities */
#define CAP_UNKILLABLE      0x00001000  /* Cannot be terminated by kill() syscall */

/* All capabilities (for root processes) */
#define CAP_ALL             0xFFFFFFFF  /* All capabilities */

/* Default capabilities for new processes */
#define CAP_DEFAULT         (CAP_FS_READ | CAP_FS_WRITE)  /* Read and write files only */

/* File flags (compatible with Unix) */
#define VFS_O_RDONLY        0x0000  /* Read only */
#define VFS_O_WRONLY        0x0001  /* Write only */
#define VFS_O_RDWR          0x0002  /* Read and write */
#define VFS_O_CREAT         0x0100  /* Create if not exists */
#define VFS_O_TRUNC         0x0200  /* Truncate to zero length */
#define VFS_O_APPEND        0x0400  /* Append mode */

/* Error codes (negative values) */
#define VFS_EBADF           -9      /* Bad file descriptor */
#define VFS_EFAULT          -14     /* Bad address */
#define VFS_EINVAL          -22     /* Invalid argument */
#define VFS_ENOMEM          -12     /* Out of memory */
#define VFS_ENOENT          -2      /* No such file or directory */
#define VFS_EACCES          -13     /* Permission denied */
#define VFS_EEXIST          -17     /* File exists */
#define VFS_EOVERFLOW       -75     /* Value too large for defined data type (POSIX) */

/*=============================================================================
 * PHASE 9: No /dev/mem or /dev/kmem (Security-by-Omission)
 *
 * TRADITIONAL UNIX/LINUX WEAKNESS:
 * - /dev/mem: Direct read/write access to ALL physical memory
 * - /dev/kmem: Direct read/write access to kernel virtual memory
 * - Even with root-only permissions (600), these are exploit goldmines
 *
 * ATTACK VECTORS:
 * 1. **Kernel Code Injection**: Write shellcode directly to kernel .text
 * 2. **ASLR Bypass**: Read kernel memory to find addresses
 * 3. **Credential Theft**: Extract passwords, keys from kernel memory
 * 4. **Process Hijacking**: Modify task_struct in kernel memory
 * 5. **Rootkit Installation**: Patch syscall table via /dev/kmem
 * 6. **Secure Boot Bypass**: Modify kernel signatures in memory
 *
 * HISTORICAL EXPLOITS:
 * - Countless rootkits used /dev/kmem to hide processes
 * - Privilege escalation via kernel memory patching
 * - Container escape by reading host memory
 * - Even modern Linux disabled /dev/kmem (removed in 2.6.26)
 *
 * TINYOS INNOVATION:
 * - /dev/mem and /dev/kmem NEVER IMPLEMENTED
 * - No device nodes for physical or kernel memory
 * - Kernel memory completely inaccessible from userspace
 * - No code path exists to create these devices
 *
 * SECURITY BENEFITS:
 * - Kernel memory exploitation impossible
 * - No rootkit installation vector
 * - ASLR cannot be bypassed via memory reading
 * - Complete kernel memory protection
 *
 * COMPATIBILITY:
 * - Modern Linux also removed /dev/kmem (security liability)
 * - /dev/mem access restricted to CONFIG_STRICT_DEVMEM
 * - TinyOS simply never implements these dangerous devices
 *
 * This is a PERMANENT architectural decision. These devices will NEVER
 * be implemented in TinyOS.
 *===========================================================================*/

/* File descriptor types */
typedef enum {
    VFS_TYPE_NONE = 0,
    VFS_TYPE_FILE,      /* Regular file (RAMFS) */
    VFS_TYPE_DEVICE,    /* Character/block device (NOT /dev/mem or /dev/kmem!) */
    VFS_TYPE_SOCKET,    /* Network socket */
    VFS_TYPE_PIPE       /* Named or anonymous pipe */
} vfs_fd_type_t;

/*=============================================================================
 * FILE OPERATIONS INTERFACE
 *=============================================================================
 * Driver interface - each I/O type implements these operations.
 * VFS layer validates parameters and delegates to driver.
 */
typedef struct file_operations {
    /**
     * @brief Open a file/device/socket
     * @param path Path or identifier
     * @param flags Open flags (VFS_O_*)
     * @param private_data Driver-specific data (output)
     * @return 0 on success, negative error code on failure
     */
    int (*open)(const char* path, int flags, void** private_data);

    /**
     * @brief Close a file descriptor
     * @param private_data Driver-specific data
     * @return 0 on success, negative error code on failure
     */
    int (*close)(void* private_data);

    /**
     * @brief Read from file descriptor
     * @param private_data Driver-specific data
     * @param buf Output buffer
     * @param size Number of bytes to read
     * @return Bytes read on success (ssize_t), negative error code on failure
     *
     * SECURITY (Issue 6.1): Returns ssize_t (not int) to prevent overflow
     * when reading large amounts of data (>2GB on 32-bit systems).
     */
    ssize_t (*read)(void* private_data, void* buf, size_t size);

    /**
     * @brief Write to file descriptor
     * @param private_data Driver-specific data
     * @param buf Input buffer
     * @param size Number of bytes to write
     * @return Bytes written on success (ssize_t), negative error code on failure
     *
     * SECURITY (Issue 6.1): Returns ssize_t (not int) to prevent overflow
     * when writing large amounts of data (>2GB on 32-bit systems).
     */
    ssize_t (*write)(void* private_data, const void* buf, size_t size);

    /**
     * @brief I/O control (optional)
     * @param private_data Driver-specific data
     * @param request Request code
     * @param arg Request argument
     * @return 0 on success, negative error code on failure
     */
    int (*ioctl)(void* private_data, unsigned long request, void* arg);

    /**
     * @brief Create a directory
     * @param path Path to directory to create
     * @return 0 on success, negative error code on failure
     */
    int (*mkdir)(const char* path);

    /**
     * @brief Remove a directory
     * @param path Path to directory to remove
     * @return 0 on success, negative error code on failure
     */
    int (*rmdir)(const char* path);

    /**
     * @brief Read directory entries
     * @param private_data Driver-specific data (from open)
     * @param buf Output buffer for directory entries
     * @param size Size of output buffer
     * @return Number of bytes read on success, negative error code on failure
     */
    ssize_t (*readdir)(void* private_data, void* buf, size_t size);

} file_operations_t;

/*=============================================================================
 * FILE DESCRIPTOR TABLE ENTRY
 *=============================================================================*/
typedef struct vfs_file_descriptor {
    bool in_use;                        /* Is this FD allocated? */
    int flags;                          /* Open flags */
    vfs_fd_type_t type;                 /* FD type */
    size_t offset;                      /* Current offset (for seek) */
    void* private_data;                 /* Driver-specific data */
    const file_operations_t* ops;       /* Operations for this FD */
    char path[VFS_MAX_PATH];            /* Path (for debugging) */
} vfs_file_descriptor_t;

/*=============================================================================
 * VFS FUNCTION PROTOTYPES
 *=============================================================================*/

/**
 * @brief Initialize VFS subsystem
 * Must be called before any other VFS functions
 */
void vfs_init(void);

/**
 * @brief Register a file system driver
 * @param name Driver name (e.g., "ramfs", "devfs", "fat32")
 * @param ops File operations for this driver
 * @return 0 on success, negative error on failure
 */
int vfs_register_driver(const char* name, const file_operations_t* ops);

/**
 * @brief Mount a filesystem to a drive letter
 * @param drive_letter Drive letter ('C', 'D', etc.)
 * @param driver_name Name of registered driver to mount
 * @return 0 on success, negative error on failure
 *
 * USAGE:
 *   vfs_mount('C', "fat32");  // Mount FAT32 as C:
 *   vfs_mount('D', "ramfs");  // Mount RAMFS as D:
 */
int vfs_mount(char drive_letter, const char* driver_name);

/**
 * @brief Canonicalize a file path (resolve . and .. components)
 * @param path Input path (relative or absolute)
 * @param canonical Output buffer for canonicalized path
 * @param max_len Size of canonical buffer
 * @return 0 on success, negative error code on failure
 *
 * SECURITY:
 * - Resolves . (current directory) and .. (parent directory)
 * - Collapses // sequences
 * - Prevents path traversal attacks
 * - Produces clean, absolute path
 */
int vfs_canonicalize_path(const char* path, char* canonical, size_t max_len);

/**
 * @brief Open a file/device/socket
 * @param path Path to open
 * @param flags Open flags (VFS_O_*)
 * @return File descriptor (>=0) on success, negative error code on failure
 *
 * SECURITY:
 * - Validates path pointer
 * - Checks path length
 * - Validates flags
 * - Allocates FD from table
 */
int vfs_open(const char* path, int flags);

/**
 * @brief Close a file descriptor
 * @param fd File descriptor to close
 * @return 0 on success, negative error code on failure
 *
 * SECURITY:
 * - Validates FD range
 * - Checks FD is allocated
 * - Prevents double-free
 */
int vfs_close(int fd);

/**
 * @brief Read from file descriptor
 * @param fd File descriptor
 * @param buf Output buffer
 * @param size Number of bytes to read
 * @return Bytes read on success (ssize_t), negative error code on failure
 *
 * SECURITY:
 * - Validates FD range
 * - Validates buffer pointer
 * - Checks FD is allocated
 * - Validates buffer is writable (future: copy_to_user)
 * - Returns VFS_EOVERFLOW if size > SSIZE_MAX (Issue 6.1)
 */
ssize_t vfs_read(int fd, void* buf, size_t size);

/**
 * @brief Write to file descriptor
 * @param fd File descriptor
 * @param buf Input buffer
 * @param size Number of bytes to write
 * @return Bytes written on success (ssize_t), negative error code on failure
 *
 * SECURITY:
 * - Validates FD range
 * - Validates buffer pointer
 * - Checks FD is allocated
 * - Validates buffer is readable (future: copy_from_user)
 * - Returns VFS_EOVERFLOW if size > SSIZE_MAX (Issue 6.1)
 */
ssize_t vfs_write(int fd, const void* buf, size_t size);

/**
 * @brief Get file descriptor information (for debugging)
 * @param fd File descriptor
 * @return Pointer to FD entry, or NULL if invalid
 */
const vfs_file_descriptor_t* vfs_get_fd_info(int fd);

/**
 * @brief Print VFS statistics (for debugging)
 */
void vfs_stats(void);

/**
 * @brief Create a directory
 * @param path Path to directory to create
 * @return 0 on success, negative error code on failure
 *
 * SECURITY:
 * - Validates path pointer and length
 * - Checks for protected paths
 * - Delegates to driver's mkdir function
 */
int vfs_mkdir(const char* path);

/**
 * @brief Remove a directory
 * @param path Path to directory to remove
 * @return 0 on success, negative error code on failure
 *
 * SECURITY:
 * - Validates path pointer and length
 * - Checks for protected paths
 * - Delegates to driver's rmdir function
 */
int vfs_rmdir(const char* path);

/**
 * @brief Read directory entries
 * @param fd File descriptor (from vfs_open on a directory)
 * @param buf Output buffer for directory entries
 * @param size Size of output buffer
 * @return Bytes read on success, negative error code on failure
 *
 * SECURITY:
 * - Validates FD range and allocation
 * - Validates buffer pointer
 * - Delegates to driver's readdir function
 */
ssize_t vfs_readdir(int fd, void* buf, size_t size);

/**
 * @brief Iterate through mounted drives
 * @param callback Function called for each mounted drive
 * @param user_data User data passed to callback
 *
 * Callback signature: void (*callback)(char drive_letter, const char* driver_name, void* user_data)
 */
void vfs_foreach_mount(void (*callback)(char drive_letter, const char* driver_name, void* user_data), void* user_data);
