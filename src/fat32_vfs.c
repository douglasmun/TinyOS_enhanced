/*=============================================================================
 * fat32_vfs.c - FAT32 VFS Driver Integration
 *=============================================================================
 * This file implements the VFS file_operations_t interface for FAT32,
 * allowing FAT32 to be accessed through the unified VFS layer.
 *
 * ARCHITECTURE:
 * - VFS provides security validation and FD management
 * - This driver wraps FAT32 operations to match VFS interface
 * - private_data stores the FAT32 file descriptor
 *
 * SECURITY BENEFITS:
 * - Single validation point (VFS layer)
 * - Consistent error handling
 * - Unified FD table (prevents FD exhaustion attacks)
 *=============================================================================*/
#include "fat32_vfs.h"
#include "vfs.h"
#include "fat32.h"
#include "kprintf.h"
#include "util.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * SECURITY FIX (Issue 8.2): Type-Safe FAT32 Handles
 *
 * ISSUE: Storing FAT32 file descriptors in private_data using integer casting
 * (void*)(uintptr_t) is not type-safe and could truncate on 64-bit systems.
 *
 * Example of unsafe code:
 *   *private_data = (void*)(uintptr_t)fat32_fd;  // Loses type information
 *   int fd = (int)(uintptr_t)private_data;        // Unsafe cast back
 *
 * FIX: Use a dedicated structure to hold the FAT32 file descriptor.
 * This provides:
 * - Type safety (compiler catches misuse)
 * - Future extensibility (can add more fields)
 * - Clear intent (structure name documents purpose)
 * - No truncation risk on 64-bit systems
 * - Matches RAMFS VFS pattern for consistency
 *
 * NOTE: For 32-bit TinyOS, we use a static pool to avoid dynamic allocation
 * complexity. Each VFS FD maps to one handle from the pool.
 *===========================================================================*/
#define FAT32_VFS_MAX_HANDLES 64  // Must be >= VFS_MAX_FDS

typedef struct {
    int fat32_fd;     // FAT32 file descriptor
    bool in_use;      // true if this handle is allocated
} fat32_fd_handle_t;

// Static pool of handles (avoids malloc/free complexity)
static fat32_fd_handle_t handle_pool[FAT32_VFS_MAX_HANDLES];

/*=============================================================================
 * FUNCTION: fat32_alloc_handle
 * PURPOSE: Allocate a type-safe handle from the pool
 *===========================================================================*/
static fat32_fd_handle_t* fat32_alloc_handle(int fat32_fd) {
    for (int i = 0; i < FAT32_VFS_MAX_HANDLES; i++) {
        if (!handle_pool[i].in_use) {
            handle_pool[i].fat32_fd = fat32_fd;
            handle_pool[i].in_use = true;
            return &handle_pool[i];
        }
    }
    return NULL;  // Pool exhausted
}

/*=============================================================================
 * FUNCTION: fat32_free_handle
 * PURPOSE: Free a type-safe handle back to the pool
 *===========================================================================*/
static void fat32_free_handle(fat32_fd_handle_t* handle) {
    if (handle) {
        handle->in_use = false;
        handle->fat32_fd = -1;
    }
}

/*=============================================================================
 * FAT32 VFS OPERATIONS
 *=============================================================================*/

/**
 * @brief Open a FAT32 file through VFS
 * @param path File path
 * @param flags VFS open flags
 * @param private_data Output: Type-safe handle pointer
 * @return 0 on success, negative error code on failure
 *
 * SECURITY FIX (Issue 8.2): Now uses type-safe fat32_fd_handle_t* instead of integer cast
 */
static int fat32_vfs_open(const char* path, int flags, void** private_data) {
    /* FAT32 currently only supports read operations */
    (void)flags;  /* Unused for now */

    /* Open file using FAT32 */
    int fat32_fd = fat32_open(path);
    if (fat32_fd < 0) {
        return VFS_ENOENT;  /* File not found or other error */
    }

    /* Allocate type-safe handle */
    fat32_fd_handle_t* handle = fat32_alloc_handle(fat32_fd);
    if (!handle) {
        /* Handle pool exhausted - close the FAT32 FD */
        fat32_close(fat32_fd);
        return VFS_ENOMEM;
    }

    /* Store handle pointer in private_data */
    *private_data = (void*)handle;

    return 0;
}

/**
 * @brief Close a FAT32 file through VFS
 * @param private_data Type-safe handle pointer
 * @return 0 on success, negative error code on failure
 *
 * SECURITY FIX (Issue 8.2): Now uses type-safe fat32_fd_handle_t* instead of integer cast
 */
static int fat32_vfs_close(void* private_data) {
    fat32_fd_handle_t* handle = (fat32_fd_handle_t*)private_data;
    if (!handle) {
        return VFS_EINVAL;
    }

    /* Close the FAT32 file */
    fat32_close(handle->fat32_fd);

    /* Free the handle back to the pool */
    fat32_free_handle(handle);

    return 0;
}

/**
 * @brief Read from FAT32 file through VFS
 * @param private_data Type-safe handle pointer
 * @param buf Output buffer
 * @param size Number of bytes to read
 * @return Bytes read on success (ssize_t), negative error code on failure
 *
 * SECURITY (Issue 6.1): Returns ssize_t to match VFS interface
 * SECURITY FIX (Issue 8.2): Now uses type-safe fat32_fd_handle_t* instead of integer cast
 */
static ssize_t fat32_vfs_read(void* private_data, void* buf, size_t size) {
    fat32_fd_handle_t* handle = (fat32_fd_handle_t*)private_data;
    if (!handle) {
        return VFS_EINVAL;
    }

    int bytes_read = fat32_read(handle->fat32_fd, buf, (uint32_t)size);

    if (bytes_read < 0) {
        return VFS_EINVAL;  /* Read error */
    }

    return (ssize_t)bytes_read;
}

/**
 * @brief Write to FAT32 file through VFS
 * @param private_data Type-safe handle pointer
 * @param buf Input buffer
 * @param size Number of bytes to write
 * @return Bytes written on success (ssize_t), negative error code on failure
 *
 * SECURITY (Issue 6.1): Returns ssize_t to match VFS interface
 * SECURITY FIX (Issue 8.2): Now uses type-safe fat32_fd_handle_t* instead of integer cast
 */
static ssize_t fat32_vfs_write(void* private_data, const void* buf, size_t size) {
    fat32_fd_handle_t* handle = (fat32_fd_handle_t*)private_data;
    if (!handle) {
        return VFS_EINVAL;
    }

    int bytes_written = fat32_write(handle->fat32_fd, buf, (uint32_t)size);

    if (bytes_written < 0) {
        return VFS_EINVAL;  /* Write error */
    }

    return (ssize_t)bytes_written;
}

/*=============================================================================
 * FAT32 FILE OPERATIONS TABLE
 *=============================================================================*/
static const file_operations_t fat32_file_ops = {
    .open  = fat32_vfs_open,
    .close = fat32_vfs_close,
    .read  = fat32_vfs_read,
    .write = fat32_vfs_write,
    .ioctl = NULL  /* Not implemented */
};

/*=============================================================================
 * FAT32 VFS DRIVER REGISTRATION
 *=============================================================================*/

/**
 * @brief Register FAT32 as a VFS driver
 * @return 0 on success, negative error code on failure
 */
int fat32_vfs_init(void) {
    int ret = vfs_register_driver("fat32", &fat32_file_ops);
    if (ret < 0) {
        kprintf("[FAT32_VFS] ERROR: Failed to register driver\n");
        return ret;
    }

    kprintf("[FAT32_VFS] Registered VFS driver [OK]\n");
    return 0;
}

/**
 * @brief Get FAT32 file operations for VFS
 * @return Pointer to file operations structure
 */
const file_operations_t* fat32_get_vfs_ops(void) {
    return &fat32_file_ops;
}
