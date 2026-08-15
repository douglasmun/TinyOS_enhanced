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
    int fat32_fd;     // FAT32 file descriptor (-1 for directory handles)
    bool in_use;      // true if this handle is allocated
    bool is_dir;      // true if opened with VFS_O_DIRECTORY (readdir only)
    uint32_t dir_pos; // Directory cursor: entries already returned
    /* Which directory this handle enumerates. Directory handles hold no FAT32
     * fd (the enumerator works by path), so the path is the only thing tying
     * the handle to its directory across readdir calls. Root is "/". */
    char dir_path[VFS_MAX_PATH];
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
            handle_pool[i].is_dir = false;
            handle_pool[i].dir_pos = 0;
            handle_pool[i].dir_path[0] = '\0';
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
    /*=========================================================================
     * Directory open. This used to accept ONLY the root, because the
     * enumerator took no path; it now takes one, so any directory works.
     *
     * The path is validated here rather than at the first readdir: an open
     * that succeeds on a nonexistent directory and then fails on read would
     * report the error in the wrong place, and an open on a FILE with
     * O_DIRECTORY must fail outright rather than enumerate nothing.
     *=======================================================================*/
    if (flags & VFS_O_DIRECTORY) {
        /* vfs_open has already stripped "C:" and canonicalized, so the root
         * arrives as "/" (or "" if the caller passed a bare "C:"). */
        const char* dir_path = (path[0] == '\0') ? "/" : path;

        /* Probe with the real enumerator, which is what readdir will use: a
         * NULL emit callback walks the directory without producing entries,
         * so this validates existence and directory-ness with the same code
         * path that will later list it. */
        int probe = fat32_list_dir_cb(dir_path, 0, 0);
        if (probe == -2) {
            return VFS_ENOTDIR;
        }
        if (probe != 0) {
            return VFS_ENOENT;
        }

        fat32_fd_handle_t* dir_handle = fat32_alloc_handle(-1);
        if (!dir_handle) {
            return VFS_ENOMEM;
        }
        dir_handle->is_dir = true;
        dir_handle->dir_pos = 0;
        if (safe_strcpy(dir_handle->dir_path, dir_path,
                        sizeof(dir_handle->dir_path)) >= sizeof(dir_handle->dir_path)) {
            fat32_free_handle(dir_handle);
            return VFS_EINVAL;
        }

        *private_data = (void*)dir_handle;
        return 0;
    }

    /* Open file using FAT32 */
    int fat32_fd = fat32_open(path);

    /*=========================================================================
     * O_CREAT: create the file, then open it for real.
     *
     * This used to ignore `flags` entirely, so opening a nonexistent file on
     * C: with VFS_O_CREAT just returned ENOENT — there was no way to create a
     * FAT32 file through the VFS at all, which is why the write path was
     * unreachable from the shell even though fat32_write existed.
     *=======================================================================*/
    if (fat32_fd < 0 && (flags & VFS_O_CREAT)) {
        if (fat32_create(path) != 0) {
            return VFS_ENOENT;
        }
        fat32_fd = fat32_open(path);
    }

    if (fat32_fd < 0) {
        return VFS_ENOENT;  /* File not found or other error */
    }

    /* O_TRUNC on an existing file: drop its contents so a rewrite doesn't
     * leave the tail of the previous, longer file behind. */
    if ((flags & VFS_O_TRUNC) && fat32_truncate(fat32_fd) != 0) {
        fat32_close(fat32_fd);
        return VFS_EINVAL;
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

    /* Directory handles never went through fat32_open, so there is no FAT32
     * fd to release — closing one would pass -1 to fat32_close(). */
    if (handle->is_dir) {
        fat32_free_handle(handle);
        return 0;
    }

    /* Close the FAT32 file. The return value matters now that close flushes
     * the directory entry: a failure there means the data is on disk but the
     * dirent still reports the old size, so the file reads back empty. Report
     * it instead of silently claiming success.
     *
     * The handle is freed either way — the FAT32 descriptor is already
     * released, so keeping the pool slot would just leak it. */
    int rc = fat32_close(handle->fat32_fd);

    /* Free the handle back to the pool */
    fat32_free_handle(handle);

    return (rc == 0) ? 0 : VFS_EIO;
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

    if (handle->is_dir) {
        return VFS_EINVAL;  /* Use readdir, not read, on a directory */
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

    if (handle->is_dir) {
        return VFS_EINVAL;  /* Directories are not writable through this path */
    }

    int bytes_written = fat32_write(handle->fat32_fd, buf, (uint32_t)size);

    if (bytes_written < 0) {
        return VFS_EINVAL;  /* Write error */
    }

    return (ssize_t)bytes_written;
}

/*=============================================================================
 * DIRECTORY ENUMERATION
 *
 * fat32_list_dir_cb() is a PUSH enumerator (it walks a whole directory and
 * calls back per entry) while readdir is a PULL cursor. Bridging them here —
 * rather than reimplementing the walk — keeps the LFN-chain, deleted-entry and
 * volume-label handling in one place; duplicating that parsing is where the
 * bugs would come from.
 *
 * Cost: each call re-walks the directory from the start and skips `dir_pos`
 * entries, so listing N entries is O(N^2) in directory reads. Directories here
 * are small and this is not on any hot path; correctness and a single copy of
 * the parser are worth more than the constant factor.
 *===========================================================================*/
typedef struct {
    vfs_dirent_t* out;      /* Caller's buffer */
    uint32_t capacity;      /* Entries it can hold */
    uint32_t filled;        /* Entries written so far */
    uint32_t skip;          /* Entries to skip (the cursor) */
    uint32_t seen;          /* Entries walked past so far */
} fat32_readdir_ctx_t;

static void fat32_readdir_emit(void* ctx, const char* name, uint32_t size, bool is_dir) {
    fat32_readdir_ctx_t* rc = (fat32_readdir_ctx_t*)ctx;

    /* The enumerator has no early exit, so it keeps calling after the buffer
     * is full. Count every entry regardless (the cursor must stay accurate),
     * but only store the ones in this window. */
    uint32_t index = rc->seen++;
    if (index < rc->skip || rc->filled >= rc->capacity) {
        return;
    }

    vfs_dirent_t* de = &rc->out[rc->filled++];
    de->size = is_dir ? 0 : size;
    de->mode = is_dir ? 0755 : 0644;   /* FAT32 has no Unix permissions */
    de->type = is_dir ? VFS_DT_DIR : VFS_DT_REG;
    de->reserved = 0;
    safe_strcpy(de->name, name, sizeof(de->name));
}

/**
 * @brief Read directory entries from a FAT32 directory handle
 * @param private_data Type-safe handle pointer (must be a directory handle)
 * @param buf Output buffer, filled with whole vfs_dirent_t records
 * @param size Buffer size in bytes; must hold at least one entry
 * @return Bytes written, 0 at end of directory, negative error code on failure
 */
static ssize_t fat32_vfs_readdir(void* private_data, void* buf, size_t size) {
    fat32_fd_handle_t* handle = (fat32_fd_handle_t*)private_data;
    if (!handle || !buf) {
        return VFS_EINVAL;
    }
    if (!handle->is_dir) {
        return VFS_EINVAL;  /* Not opened with VFS_O_DIRECTORY */
    }
    if (size < sizeof(vfs_dirent_t)) {
        return VFS_EINVAL;  /* Cannot report a partial entry */
    }

    fat32_readdir_ctx_t ctx;
    ctx.out = (vfs_dirent_t*)buf;
    ctx.capacity = (uint32_t)(size / sizeof(vfs_dirent_t));
    ctx.filled = 0;
    ctx.skip = handle->dir_pos;
    ctx.seen = 0;

    if (fat32_list_dir_cb(handle->dir_path, fat32_readdir_emit, &ctx) != 0) {
        return VFS_EIO;
    }

    handle->dir_pos += ctx.filled;
    return (ssize_t)(ctx.filled * sizeof(vfs_dirent_t));
}

/*=============================================================================
 * STAT
 *
 * fat32.h declares fat32_stat(), but nothing ever implemented it — it is a
 * dead prototype. Rather than add a second directory walk, reuse the same
 * enumerator readdir uses and match on the 8.3 name it produces, so stat and
 * readdir can never disagree about what a file is called or how big it is.
 *
 * Works at any depth: the path is split into parent + leaf and the parent is
 * the directory enumerated.
 *===========================================================================*/
typedef struct {
    const char* want;       /* Name being looked for */
    vfs_dirent_t* out;      /* Filled in on match */
    bool found;
} fat32_stat_ctx_t;

/* FAT32 8.3 names are case-insensitive, and fat32_open() upper-cases what it
 * is given. Comparing case-sensitively here would make stat("persist.txt")
 * fail on a file that open("persist.txt") happily returns. */
static bool fat32_name_eq(const char* a, const char* b) {
    while (*a && *b) {
        char ca = (*a >= 'a' && *a <= 'z') ? (char)(*a - 32) : *a;
        char cb = (*b >= 'a' && *b <= 'z') ? (char)(*b - 32) : *b;
        if (ca != cb) {
            return false;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static void fat32_stat_emit(void* ctx, const char* name, uint32_t size, bool is_dir) {
    fat32_stat_ctx_t* sc = (fat32_stat_ctx_t*)ctx;

    /* The enumerator has no early exit; ignore everything after the match. */
    if (sc->found || !fat32_name_eq(name, sc->want)) {
        return;
    }

    sc->out->size = is_dir ? 0 : size;
    sc->out->mode = is_dir ? 0755 : 0644;   /* FAT32 has no Unix permissions */
    sc->out->type = is_dir ? VFS_DT_DIR : VFS_DT_REG;
    sc->out->reserved = 0;
    sc->found = true;
}

/**
 * @brief Look up a FAT32 path's metadata without opening it
 * @param path Path (drive letter already stripped by the VFS)
 * @param out Filled in on success
 * @return 0 on success, negative error code on failure
 */
static int fat32_vfs_stat(const char* path, vfs_dirent_t* out) {
    if (!path || !out) {
        return VFS_EINVAL;
    }

    /* The root itself: a directory with no entry of its own to look up. */
    if (path[0] == '\0' || (path[0] == '/' && path[1] == '\0')) {
        out->size = 0;
        out->mode = 0755;
        out->type = VFS_DT_DIR;
        out->reserved = 0;
        return 0;
    }

    /*=========================================================================
     * Split the path into the parent directory to enumerate and the leaf name
     * to match. This used to reject any path containing a slash outright,
     * which is what made stat root-only.
     *
     * Matching against the parent's listing (rather than a separate lookup)
     * keeps stat and readdir reporting identical names and sizes — they share
     * one parser, so they cannot disagree.
     *=======================================================================*/
    char parent[VFS_MAX_PATH];
    const char* name = path;

    const char* last_slash = 0;
    for (const char* p = path; *p; p++) {
        if (*p == '/') {
            last_slash = p;
        }
    }

    if (last_slash) {
        name = last_slash + 1;

        /* A trailing slash leaves no leaf name to match. */
        if (*name == '\0') {
            return VFS_EINVAL;
        }

        /* The parent is everything up to the last slash; a leading-slash-only
         * prefix ("/FILE.TXT") means the root. */
        size_t parent_len = (size_t)(last_slash - path);
        if (parent_len == 0) {
            parent[0] = '/';
            parent[1] = '\0';
        } else {
            if (parent_len >= sizeof(parent)) {
                return VFS_EINVAL;
            }
            memcpy(parent, path, parent_len);
            parent[parent_len] = '\0';
        }
    } else {
        parent[0] = '/';
        parent[1] = '\0';
    }

    fat32_stat_ctx_t ctx;
    ctx.want = name;
    ctx.out = out;
    ctx.found = false;

    int rc = fat32_list_dir_cb(parent, fat32_stat_emit, &ctx);
    if (rc == -2) {
        return VFS_ENOTDIR;   /* A path component is a file, not a directory */
    }
    if (rc != 0) {
        return VFS_ENOENT;    /* Parent directory does not exist */
    }

    return ctx.found ? 0 : VFS_ENOENT;
}

/**
 * @brief Check that a FAT32 path names a directory that can be entered
 * @param path Canonical absolute path (drive letter already stripped)
 * @return 0 if it may be entered, negative error code otherwise
 *
 * FAT32 has no ownership or permission model, so there is no permission
 * question to answer — but existence and directory-ness still matter. Without
 * this op the VFS treats a NULL .access_dir as "permitted", which would let
 * chdir succeed on a path that does not exist.
 */
static int fat32_vfs_access_dir(const char* path) {
    if (!path) {
        return VFS_EINVAL;
    }

    const char* dir_path = (path[0] == '\0') ? "/" : path;

    int rc = fat32_list_dir_cb(dir_path, 0, 0);
    if (rc == -2) {
        return VFS_ENOTDIR;
    }
    if (rc != 0) {
        return VFS_ENOENT;
    }
    return 0;
}

/**
 * @brief Reposition a FAT32 file cursor
 * @param private_data Type-safe handle pointer
 * @param offset Signed displacement, interpreted per `whence`
 * @param whence VFS_SEEK_SET / VFS_SEEK_CUR / VFS_SEEK_END
 * @return Resulting absolute position, or negative error code
 *
 * fat32_seek already clamps past-EOF to the file size and returns 0 rather
 * than the new position, so the resulting position is read back explicitly.
 */
static ssize_t fat32_vfs_seek(void* private_data, ssize_t offset, int whence) {
    fat32_fd_handle_t* handle = (fat32_fd_handle_t*)private_data;
    if (!handle) {
        return VFS_EINVAL;
    }
    /* Directory handles never went through fat32_open (fat32_fd is -1) and
     * their cursor is dir_pos, which belongs to readdir alone. */
    if (handle->is_dir) {
        return VFS_EBADF;
    }

    ssize_t base;
    switch (whence) {
        case VFS_SEEK_SET:
            base = 0;
            break;
        case VFS_SEEK_CUR:
            base = (ssize_t)fat32_tell(handle->fat32_fd);
            break;
        case VFS_SEEK_END:
            base = (ssize_t)fat32_fd_size(handle->fat32_fd);
            break;
        default:
            return VFS_EINVAL;
    }
    if (base < 0) {
        return VFS_EBADF;
    }

    ssize_t target = base + offset;
    if (target < 0) {
        return VFS_EINVAL;  /* Before the start of the file */
    }

    if (fat32_seek(handle->fat32_fd, (uint32_t)target) < 0) {
        return VFS_EIO;
    }

    /* fat32_seek clamps to file_size, so the position it actually reached is
     * not necessarily `target`. Report where the cursor really is. */
    int pos = fat32_tell(handle->fat32_fd);
    if (pos < 0) {
        return VFS_EBADF;
    }
    return (ssize_t)pos;
}

/*=============================================================================
 * DIRECTORY / FILE MANAGEMENT OPS
 *
 * These three were unreachable before: the driver implemented them but the ops
 * table below exposed neither mkdir nor rmdir nor unlink, so nothing outside
 * fat32.c ever called them. Wiring them up is what makes SYS_MKDIR/SYS_RMDIR/
 * SYS_UNLINK work on C:.
 *
 * FAT32 has no ownership or permission bits, so unlike RAMFS there is no
 * per-user check here — the protection is vfs_unlink/vfs_rmdir's protected
 * path list plus the driver's own refusals (root dir, non-empty dir, open
 * file).
 *===========================================================================*/
static int fat32_vfs_mkdir(const char* path) {
    int ret = fat32_mkdir(path);
    if (ret < 0) {
        switch (ret) {
            case -2: return VFS_EEXIST;
            /* The driver collapses "disk full", "missing parent directory"
             * and a failed sector access into -1. Out-of-space dominates in
             * practice; directories now grow by allocating clusters, so a
             * full directory is genuinely an out-of-space condition. */
            default: return VFS_ENOSPC;
        }
    }
    return 0;
}

static int fat32_vfs_rmdir(const char* path) {
    int ret = fat32_rmdir(path);
    if (ret < 0) {
        switch (ret) {
            case -2: return VFS_ENOTDIR;
            case -3: return VFS_ENOTEMPTY;
            case -4: return VFS_EBUSY;   /* Directory is currently open */
            default: return VFS_ENOENT;
        }
    }
    return 0;
}

static int fat32_vfs_unlink(const char* path) {
    int ret = fat32_unlink(path);
    if (ret < 0) {
        switch (ret) {
            case -2: return VFS_EISDIR;
            case -3: return VFS_EBUSY;
            default: return VFS_ENOENT;
        }
    }
    return 0;
}

/*=============================================================================
 * FAT32 FILE OPERATIONS TABLE
 *=============================================================================*/
static const file_operations_t fat32_file_ops = {
    .open  = fat32_vfs_open,
    .close = fat32_vfs_close,
    .read  = fat32_vfs_read,
    .write = fat32_vfs_write,
    .readdir = fat32_vfs_readdir,
    .stat = fat32_vfs_stat,
    .seek = fat32_vfs_seek,
    .mkdir = fat32_vfs_mkdir,
    .rmdir = fat32_vfs_rmdir,
    .unlink = fat32_vfs_unlink,
    .access_dir = fat32_vfs_access_dir,
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
