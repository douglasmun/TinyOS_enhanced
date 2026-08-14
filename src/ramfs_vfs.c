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
    int ramfs_fd;     // RAMFS file descriptor (-1 for directory handles)
    bool in_use;      // true if this handle is allocated

    /* Directory iteration state (VFS_O_DIRECTORY opens).
     *
     * `dir_node` is the directory being walked and `dir_pos` is how many
     * entries have already been returned. The cursor is an INDEX, not a
     * `ramfs_node_t*` into the sibling list, deliberately: a stashed child
     * pointer would dangle if that child were deleted between two readdir
     * calls. Re-walking from the head each call is O(n^2) over a full
     * listing, which is irrelevant at RAMFS_MAX_CHILDREN_PER_DIR and cannot
     * fault. */
    bool is_dir;
    ramfs_node_t* dir_node;
    uint32_t dir_pos;
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
            handle_pool[i].is_dir = false;
            handle_pool[i].dir_node = NULL;
            handle_pool[i].dir_pos = 0;
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

    /* Directory open: ramfs_open() only accepts regular files (it rejects
     * RAMFS_TYPE_DIR), so a directory handle bypasses it entirely and just
     * pins the node for readdir to walk. */
    if (flags & VFS_O_DIRECTORY) {
        ramfs_node_t* dir = ramfs_find(path);
        if (!dir) {
            return VFS_ENOENT;
        }
        if (dir->type != RAMFS_TYPE_DIR) {
            return VFS_EINVAL;
        }

        /* Bypassing ramfs_open() also bypasses ITS permission check, so do it
         * here: listing a directory is a read of that directory. Without this
         * a ring-3 caller could enumerate a mode-0700 directory it cannot
         * open any file in. */
        uint16_t uid, gid;
        ramfs_get_current_credentials(&uid, &gid);
        if (!ramfs_check_permission(dir, uid, gid, RAMFS_FLAG_READ)) {
            return VFS_EACCES;
        }

        ramfs_fd_handle_t* dir_handle = ramfs_alloc_handle(-1);
        if (!dir_handle) {
            return VFS_ENOMEM;
        }
        dir_handle->is_dir = true;
        dir_handle->dir_node = dir;
        dir_handle->dir_pos = 0;

        *private_data = (void*)dir_handle;
        return 0;
    }

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

    /* Directory handles never went through ramfs_open, so there is no RAMFS
     * fd to release — closing one would pass -1 to ramfs_close(). */
    if (!handle->is_dir) {
        ramfs_close(handle->ramfs_fd);
    }

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
        /* RAMFS returns per-function ad-hoc codes; flattening them all to
         * ENOENT made "permission denied" and "already exists" both read as
         * "no such file", which is actively misleading now that ring 3 sees
         * these errnos. */
        switch (ret) {
            case -2: return VFS_EEXIST;
            case -3: return VFS_ENOTDIR;  /* a path component is a file */
            case -5: return VFS_EACCES;
            case -6:
            case -9: return VFS_ENOSPC;
            case -7: return VFS_EINVAL;   /* path traversal blocked */
            default: return VFS_ENOENT;
        }
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
        switch (ret) {
            case -2: return VFS_ENOTDIR;
            case -3: return VFS_ENOTEMPTY;
            case -5: return VFS_EACCES;
            default: return VFS_ENOENT;
        }
    }
    return 0;
}

/*=============================================================================
 * FUNCTION: ramfs_vfs_unlink
 * PURPOSE: Remove a file (VFS .unlink op)
 *
 * ramfs_unlink already refuses directories and checks write permission on the
 * PARENT directory against the caller's uid/gid, which is what keeps a ring-3
 * task from deleting another user's files.
 *===========================================================================*/
static int ramfs_vfs_unlink(const char* path) {
    int ret = ramfs_unlink(path);
    if (ret < 0) {
        kprintf("[RAMFS VFS] unlink failed for '%s': %d\n", path, ret);
        switch (ret) {
            case -2: return VFS_EISDIR;
            case -4: return VFS_EACCES;
            default: return VFS_ENOENT;
        }
    }
    return 0;
}

/*=============================================================================
 * FUNCTION: ramfs_vfs_readdir
 * PURPOSE: Serialize directory entries into a caller-supplied buffer
 *
 * This is the third piece the old "incompatible interfaces" note called for:
 * the entry format is vfs_dirent_t (vfs.h, a fixed ABI shared with ring 3),
 * and iteration state lives in the handle as an index (see ramfs_fd_handle_t).
 *
 * Fills as many whole vfs_dirent_t records as fit and returns the BYTE count,
 * 0 at end-of-directory. A buffer too small for even one entry is EINVAL
 * rather than a silent 0, which would be indistinguishable from EOF.
 *
 * The buffer is kernel memory: sys_readdir copies it out to userspace.
 *===========================================================================*/
static ssize_t ramfs_vfs_readdir(void* private_data, void* buf, size_t size) {
    ramfs_fd_handle_t* handle = (ramfs_fd_handle_t*)private_data;
    if (!handle || !buf) {
        return VFS_EINVAL;
    }
    if (!handle->is_dir || !handle->dir_node) {
        return VFS_EBADF;   /* Opened as a file, not with VFS_O_DIRECTORY */
    }
    if (size < sizeof(vfs_dirent_t)) {
        return VFS_EINVAL;
    }

    size_t max_entries = size / sizeof(vfs_dirent_t);
    vfs_dirent_t* out = (vfs_dirent_t*)buf;
    size_t produced = 0;

    /* Re-walk from the head and skip dir_pos entries; see the cursor comment
     * on ramfs_fd_handle_t for why this is an index rather than a pointer. */
    ramfs_node_t* child = handle->dir_node->children;
    for (uint32_t skip = 0; skip < handle->dir_pos && child; skip++) {
        child = child->next;
    }

    while (child && produced < max_entries) {
        vfs_dirent_t* de = &out[produced];
        memset(de, 0, sizeof(*de));

        de->size = (child->type == RAMFS_TYPE_DIR) ? 0 : child->size;
        de->mode = child->mode;
        de->type = (child->type == RAMFS_TYPE_DIR) ? VFS_DT_DIR : VFS_DT_REG;
        de->reserved = 0;

        /* Truncate rather than reject: RAMFS_MAX_NAME and VFS_NAME_MAX are
         * independent limits, and a long name must not desync the cursor. */
        safe_strcpy(de->name, child->name, sizeof(de->name));

        produced++;
        handle->dir_pos++;
        child = child->next;
    }

    return (ssize_t)(produced * sizeof(vfs_dirent_t));
}

/**
 * @brief Look up a RAMFS path's metadata without opening it
 * @param path Path (drive letter already stripped by the VFS)
 * @param out Filled in on success
 * @return 0 on success, negative error code on failure
 */
static int ramfs_vfs_stat(const char* path, vfs_dirent_t* out) {
    if (!path || !out) {
        return VFS_EINVAL;
    }

    ramfs_node_t* node = ramfs_find(path);
    if (!node) {
        return VFS_ENOENT;
    }

    /* Reading metadata is a read of the containing directory, which the
     * caller already had to traverse; what ramfs_find does not check is
     * whether THIS node is readable. Require it, so stat cannot be used to
     * probe sizes inside a directory the caller cannot open. */
    uint16_t uid, gid;
    ramfs_get_current_credentials(&uid, &gid);
    if (!ramfs_check_permission(node, uid, gid, RAMFS_FLAG_READ)) {
        return VFS_EACCES;
    }

    out->size = (node->type == RAMFS_TYPE_DIR) ? 0 : node->size;
    out->mode = node->mode;
    out->type = (node->type == RAMFS_TYPE_DIR) ? VFS_DT_DIR : VFS_DT_REG;
    out->reserved = 0;
    return 0;
}

/**
 * @brief Reposition a RAMFS file cursor
 * @param private_data Type-safe handle pointer
 * @param offset Signed displacement, interpreted per `whence`
 * @param whence VFS_SEEK_SET / VFS_SEEK_CUR / VFS_SEEK_END
 * @return Resulting absolute position, or negative error code
 *
 * The whence arithmetic is done here rather than in the VFS layer because
 * only the driver holds the live position and size (see the .seek op in
 * vfs.h). Computed in ssize_t so an offset that would take the result
 * negative is caught before it becomes a huge unsigned position.
 */
static ssize_t ramfs_vfs_seek(void* private_data, ssize_t offset, int whence) {
    ramfs_fd_handle_t* handle = (ramfs_fd_handle_t*)private_data;
    if (!handle) {
        return VFS_EINVAL;
    }
    /* A directory has no read/write cursor; its iteration state is dir_pos,
     * which belongs to readdir alone. Seeking it would desynchronise the
     * walk without any way to express a valid target. */
    if (handle->is_dir) {
        return VFS_EBADF;
    }

    ssize_t base;
    switch (whence) {
        case VFS_SEEK_SET:
            base = 0;
            break;
        case VFS_SEEK_CUR:
            base = (ssize_t)ramfs_tell(handle->ramfs_fd);
            break;
        case VFS_SEEK_END:
            base = (ssize_t)ramfs_fd_size(handle->ramfs_fd);
            break;
        default:
            return VFS_EINVAL;
    }
    if (base < 0) {
        return VFS_EBADF;   /* Stale or never-opened underlying fd */
    }

    ssize_t target = base + offset;
    if (target < 0) {
        return VFS_EINVAL;  /* Before the start of the file */
    }

    int pos = ramfs_seek(handle->ramfs_fd, (uint32_t)target);
    if (pos < 0) {
        return VFS_EBADF;
    }
    return (ssize_t)pos;
}

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
    .unlink  = ramfs_vfs_unlink,
    .readdir = ramfs_vfs_readdir,
    .stat    = ramfs_vfs_stat,
    .seek    = ramfs_vfs_seek
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
