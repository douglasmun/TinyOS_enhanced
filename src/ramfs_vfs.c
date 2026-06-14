/*=============================================================================
 * ramfs_vfs.c - RAMFS VFS Driver Integration
 *=============================================================================
 * This file implements the VFS file_operations_t interface for RAMFS,
 * allowing RAMFS to be accessed through the unified VFS layer.
 *
 * ARCHITECTURE:
 * - VFS provides security validation and FD management
 * - This driver wraps RAMFS operations to match VFS interface
 * - private_data stores the RAMFS file descriptor
 *
 * SECURITY BENEFITS:
 * - Single validation point (VFS layer)
 * - Consistent error handling
 * - Unified FD table (prevents FD exhaustion attacks)
 *=============================================================================*/
#include "ramfs_vfs.h"
#include "vfs.h"
#include "ramfs.h"
#include "kprintf.h"
#include "util.h"
#include <stddef.h>
#include <stdint.h>

/*=============================================================================
 * PRODUCTION FIX: Type-Safe RAMFS Handles
 *
 * ISSUE: Storing RAMFS file descriptors in private_data using integer casting
 * (void*)(uintptr_t) is not type-safe and could truncate on 64-bit systems.
 *
 * Example of unsafe code:
 *   *private_data = (void*)(uintptr_t)ramfs_fd;  // Loses type information
 *   int fd = (int)(uintptr_t)private_data;       // Unsafe cast back
 *
 * FIX: Use a dedicated structure to hold the RAMFS file descriptor.
 * This provides:
 * - Type safety (compiler catches misuse)
 * - Future extensibility (can add more fields)
 * - Clear intent (structure name documents purpose)
 * - No truncation risk on 64-bit systems
 *
 * NOTE: For 32-bit TinyOS, we use a static pool to avoid dynamic allocation
 * complexity. Each VFS FD maps to one handle from the pool.
 *===========================================================================*/
#define RAMFS_VFS_MAX_HANDLES 64  // Must be >= VFS_MAX_FDS

typedef struct {
    int ramfs_fd;     // RAMFS file descriptor
    bool in_use;      // true if this handle is allocated
} ramfs_fd_handle_t;

// Static pool of handles (avoids malloc/free complexity)
static ramfs_fd_handle_t handle_pool[RAMFS_VFS_MAX_HANDLES];

/*=============================================================================
 * FUNCTION: ramfs_alloc_handle
 * PURPOSE: Allocate a type-safe handle from the pool
 *===========================================================================*/
static ramfs_fd_handle_t* ramfs_alloc_handle(int ramfs_fd) {
    for (int i = 0; i < RAMFS_VFS_MAX_HANDLES; i++) {
        if (!handle_pool[i].in_use) {
            handle_pool[i].ramfs_fd = ramfs_fd;
            handle_pool[i].in_use = true;
            return &handle_pool[i];
        }
    }
    return NULL;  // Pool exhausted
}

/*=============================================================================
 * FUNCTION: ramfs_free_handle
 * PURPOSE: Free a type-safe handle back to the pool
 *===========================================================================*/
static void ramfs_free_handle(ramfs_fd_handle_t* handle) {
    if (handle) {
        handle->in_use = false;
        handle->ramfs_fd = -1;
    }
}

/*=============================================================================
 * RAMFS VFS OPERATIONS
 *=============================================================================*/

/**
 * @brief Open a RAMFS file through VFS
 * @param path File path
 * @param flags VFS open flags
 * @param private_data Output: Type-safe handle pointer
 * @return 0 on success, negative error code on failure
 *
 * PRODUCTION FIX: Now uses type-safe ramfs_fd_handle_t* instead of integer cast
 */
static int ramfs_vfs_open(const char* path, int flags, void** private_data) {
    /* Convert VFS flags to RAMFS flags */
    uint8_t ramfs_flags = 0;

    /*
     * CRITICAL FIX: VFS_O_RDONLY is 0x0000, so "flags & VFS_O_RDONLY" is always false!
     *
     * Correct POSIX semantics:
     * - VFS_O_RDONLY (0x0000) = read-only
     * - VFS_O_WRONLY (0x0001) = write-only
     * - VFS_O_RDWR   (0x0002) = read and write
     *
     * We must check the lower 2 bits to determine access mode.
     */
    int access_mode = flags & 0x3;  /* Extract lower 2 bits */

    if (access_mode == VFS_O_RDONLY || access_mode == VFS_O_RDWR) {
        ramfs_flags |= RAMFS_FLAG_READ;
    }
    if (access_mode == VFS_O_WRONLY || access_mode == VFS_O_RDWR) {
        ramfs_flags |= RAMFS_FLAG_WRITE;
    }

    /* Open file using RAMFS */
    // kprintf("[RAMFS VFS DEBUG] Opening path: '%s', flags=0x%x\n", path, ramfs_flags);
    int ramfs_fd = ramfs_open(path, ramfs_flags);
    if (ramfs_fd < 0) {
        // kprintf("[RAMFS VFS DEBUG] ramfs_open failed, fd=%d\n", ramfs_fd);
        return VFS_ENOENT;  /* File not found or other error */
    }
    // kprintf("[RAMFS VFS DEBUG] ramfs_open succeeded, fd=%d\n", ramfs_fd);

    /* Allocate type-safe handle */
    ramfs_fd_handle_t* handle = ramfs_alloc_handle(ramfs_fd);
    if (!handle) {
        /* Handle pool exhausted - close the RAMFS FD */
        ramfs_close(ramfs_fd);
        return VFS_ENOMEM;
    }

    /* Store handle pointer in private_data */
    *private_data = (void*)handle;

    return 0;
}

/**
 * @brief Close a RAMFS file through VFS
 * @param private_data Type-safe handle pointer
 * @return 0 on success, negative error code on failure
 *
 * PRODUCTION FIX: Now uses type-safe ramfs_fd_handle_t* instead of integer cast
 */
static int ramfs_vfs_close(void* private_data) {
    ramfs_fd_handle_t* handle = (ramfs_fd_handle_t*)private_data;
    if (!handle) {
        return VFS_EINVAL;
    }

    /* Close the RAMFS file */
    ramfs_close(handle->ramfs_fd);

    /* Free the handle back to the pool */
    ramfs_free_handle(handle);

    return 0;
}

/**
 * @brief Read from RAMFS file through VFS
 * @param private_data Type-safe handle pointer
 * @param buf Output buffer
 * @param size Number of bytes to read
 * @return Bytes read on success (ssize_t), negative error code on failure
 *
 * SECURITY (Issue 6.1): Returns ssize_t to match VFS interface
 * PRODUCTION FIX: Now uses type-safe ramfs_fd_handle_t* instead of integer cast
 */
static ssize_t ramfs_vfs_read(void* private_data, void* buf, size_t size) {
    ramfs_fd_handle_t* handle = (ramfs_fd_handle_t*)private_data;
    if (!handle) {
        return VFS_EINVAL;
    }

    int bytes_read = ramfs_read(handle->ramfs_fd, buf, size);

    if (bytes_read < 0) {
        return VFS_EINVAL;  /* Read error */
    }

    return (ssize_t)bytes_read;
}

/**
 * @brief Write to RAMFS file through VFS
 * @param private_data Type-safe handle pointer
 * @param buf Input buffer
 * @param size Number of bytes to write
 * @return Bytes written on success (ssize_t), negative error code on failure
 *
 * SECURITY (Issue 6.1): Returns ssize_t to match VFS interface
 * PRODUCTION FIX: Now uses type-safe ramfs_fd_handle_t* instead of integer cast
 */
static ssize_t ramfs_vfs_write(void* private_data, const void* buf, size_t size) {
    ramfs_fd_handle_t* handle = (ramfs_fd_handle_t*)private_data;
    if (!handle) {
        return VFS_EINVAL;
    }

    int bytes_written = ramfs_write(handle->ramfs_fd, buf, size);

    if (bytes_written < 0) {
        return VFS_EINVAL;  /* Write error */
    }

    return (ssize_t)bytes_written;
}

/*=============================================================================
 * RAMFS DIRECTORY OPERATIONS
 *=============================================================================*/

/**
 * @brief Create a directory in RAMFS through VFS
 * @param path Directory path
 * @return 0 on success, negative error code on failure
 */
static int ramfs_vfs_mkdir(const char* path) {
    /* Delegate directly to RAMFS mkdir */
    int ret = ramfs_mkdir(path);
    if (ret < 0) {
        kprintf("[RAMFS VFS] mkdir failed for '%s': %d\n", path, ret);
        return VFS_ENOENT;  /* Map RAMFS errors to VFS errors */
    }
    return 0;
}

/**
 * @brief Remove a directory in RAMFS through VFS
 * @param path Directory path
 * @return 0 on success, negative error code on failure
 */
static int ramfs_vfs_rmdir(const char* path) {
    /* Delegate directly to RAMFS rmdir */
    int ret = ramfs_rmdir(path);
    if (ret < 0) {
        kprintf("[RAMFS VFS] rmdir failed for '%s': %d\n", path, ret);
        return VFS_ENOENT;  /* Map RAMFS errors to VFS errors */
    }
    return 0;
}

/*=============================================================================
 * NOTE: readdir is not implemented in VFS layer for RAMFS
 *
 * REASON: RAMFS ramfs_readdir() uses a different interface:
 * - RAMFS: ramfs_node_t* ramfs_readdir(const char* path)
 * - VFS:   ssize_t readdir(void* private_data, void* buf, size_t size)
 *
 * These interfaces are incompatible. RAMFS returns a node pointer, while VFS
 * expects a buffer-based interface. To implement VFS readdir, we would need to:
 * 1. Define a directory entry format
 * 2. Serialize ramfs_node_t data into the buffer
 * 3. Implement stateful iteration (remembering position between calls)
 *
 * For now, applications can use ramfs_readdir() directly if needed.
 * The essential operations (mkdir, rmdir) are available through VFS.
 *===========================================================================*/

/*=============================================================================
 * RAMFS FILE OPERATIONS TABLE
 *=============================================================================*/
static const file_operations_t ramfs_file_ops = {
    .open    = ramfs_vfs_open,
    .close   = ramfs_vfs_close,
    .read    = ramfs_vfs_read,
    .write   = ramfs_vfs_write,
    .ioctl   = NULL,  /* Not implemented */
    .mkdir   = ramfs_vfs_mkdir,
    .rmdir   = ramfs_vfs_rmdir,
    .readdir = NULL  /* Incompatible with RAMFS interface - use ramfs_readdir() directly */
};

/*=============================================================================
 * RAMFS VFS DRIVER REGISTRATION
 *=============================================================================*/

/**
 * @brief Register RAMFS as a VFS driver
 * @return 0 on success, negative error code on failure
 */
int ramfs_vfs_init(void) {
    int ret = vfs_register_driver("ramfs", &ramfs_file_ops);
    if (ret < 0) {
        kprintf("[RAMFS_VFS] ERROR: Failed to register driver\n");
        return ret;
    }

    kprintf("[RAMFS_VFS] Registered VFS driver [OK]\n");
    return 0;
}

/**
 * @brief Get RAMFS file operations for VFS
 * @return Pointer to file operations structure
 */
const file_operations_t* ramfs_get_vfs_ops(void) {
    return &ramfs_file_ops;
}
