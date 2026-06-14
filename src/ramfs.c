/*=============================================================================
 * ramfs.c - Simple RAM Filesystem Implementation
 *=============================================================================*/
#include "ramfs.h"
#include "kprintf.h"
#include "util.h"
#include "pmm.h"
#include "critical.h"
#include "mutex.h"
#include "process.h"    /* For task_t, PROCESS_MAX_FDS */
#include "scheduler.h"  /* For scheduler_get_current_task() */
#include "errno.h"      /* For EMFILE, ENFILE */
#include "crypto.h"     /* For csprng_random_bytes() - Phase 6: crypto-random temp files */

/*=============================================================================
 * GLOBAL STATE
 *=============================================================================*/
static ramfs_node_t* root = NULL;
static ramfs_fd_t file_descriptors[RAMFS_MAX_FDS];
static uint32_t total_nodes = 0;

/*=============================================================================
 * CONCURRENCY PROTECTION - MUTEX (v1.13 Migration)
 *=============================================================================*/
static mutex_t ramfs_mutex;

/*=========================================================================
 * USER CREDENTIALS (v1.10)
 *
 * SECURITY NOTE: Removed static current_uid/current_gid.
 * All ramfs operations now get credentials from current process via
 * scheduler_get_current_task()->uid/gid.
 *=======================================================================*/

/*=========================================================================
 * CONCURRENCY PROTECTION (v1.11)
 *
 * SECURITY FIX: RAMFS Directory Tree Race Conditions
 *
 * PREVIOUS ISSUE (v1.10 and earlier):
 * - ramfs_find() had no lock protection, could be called concurrently
 * - While one task traversed the directory tree, another could:
 *   - Delete nodes being traversed (use-after-free)
 *   - Modify child/next pointers (corrupted traversal)
 *   - Cause infinite loops or null pointer dereferences
 *
 * NEW BEHAVIOR (v1.11):
 * - All directory tree operations protected by CRITICAL_SECTION
 * - Internal _locked() versions assume caller holds lock
 * - Public wrappers acquire lock for thread-safe access
 * - Prevents corruption of linked list structure
 *
 * IMPLEMENTATION:
 * - TinyOS uses cli/sti (non-nestable) for CRITICAL_SECTION
 * - Internal functions use _locked suffix and skip locking
 * - Public functions acquire lock and call _locked version
 *=======================================================================*/

/*=============================================================================
 * HELPER FUNCTIONS
 *=============================================================================*/

/**
 * Get current process credentials (v1.10)
 * SECURITY: Returns effective UID/GID from current task for permission checking
 *
 * ARCHITECTURAL GUARANTEE: Context Switch Safety
 * ============================================
 * This function is safe against context switches because:
 *
 * 1. **Task Pointer Stability:** scheduler_get_current_task() returns a pointer
 *    to the current task's PCB (Process Control Block). The PCB is stable memory
 *    that does not move or get deallocated while the task is running.
 *
 * 2. **Atomic Credential Reads:** Reading euid and egid are atomic 16-bit reads
 *    on x86 architecture (aligned uint16_t). Even if a context switch occurs
 *    between the two reads, we're still reading from the same PCB.
 *
 * 3. **Credential Caching:** By immediately copying euid/egid to local variables
 *    (uid_out/gid_out), we ensure that subsequent permission checks use a
 *    consistent credential snapshot, even if the task's credentials change
 *    mid-function due to setuid/setgid syscalls.
 *
 * CRITICAL: Callers MUST use get_current_credentials() at function entry to
 * cache credentials locally. Do NOT call scheduler_get_current_task() multiple
 * times within a security-sensitive function - credentials could change between
 * calls if a setuid syscall is executed concurrently.
 */
static void get_current_credentials(uint16_t* uid_out, uint16_t* gid_out) {
    task_t* current = scheduler_get_current_task();
    if (current) {
        /* Use effective UID/GID for permission checks (supports setuid programs) */
        /* CRITICAL: Read both credentials immediately to get consistent snapshot */
        *uid_out = current->euid;
        *gid_out = current->egid;
    } else {
        /* No current task - default to root (for boot initialization) */
        *uid_out = 0;
        *gid_out = 0;
    }
}

/**
 * Allocate a new filesystem node
 */
static ramfs_node_t* alloc_node(const char* name, uint8_t type) {
    if (total_nodes >= RAMFS_MAX_FILES) {
        return NULL;
    }

    ramfs_node_t* node = (ramfs_node_t*)pmm_alloc();
    if (!node) {
        return NULL;
    }

    // kprintf("[RAMFS_DEBUG] Allocated node '%s' at %p\n", name, (void*)node);

    memset(node, 0, sizeof(ramfs_node_t));

    size_t name_len = strlen(name);
    if (name_len >= RAMFS_MAX_NAME) {
        name_len = RAMFS_MAX_NAME - 1;
    }

    for (size_t i = 0; i < name_len; i++) {
        node->name[i] = name[i];
    }
    node->name[name_len] = '\0';

    node->type = type;
    node->size = 0;
    node->data = NULL;
    for (int i = 0; i < RAMFS_MAX_PAGES; i++) node->data_pages[i] = NULL;
    node->parent = NULL;
    node->children = NULL;
    node->next = NULL;

    /* Set default permissions */
    if (type == RAMFS_TYPE_DIR) {
        node->mode = RAMFS_DEFAULT_DIR_MODE;   /* 0755 - rwxr-xr-x */
    } else {
        node->mode = RAMFS_DEFAULT_FILE_MODE;  /* 0644 - rw-r--r-- */
    }
    node->uid = 0;  /* Root user */
    node->gid = 0;  /* Root group */

    total_nodes++;
    return node;
}

/**
 * Free a filesystem node
 */
static void free_node(ramfs_node_t* node) {
    if (!node) return;

    for (int i = 0; i < RAMFS_MAX_PAGES; i++) {
        if (node->data_pages[i]) {
            pmm_free((uint32_t)node->data_pages[i]);
            node->data_pages[i] = NULL;
        }
    }
    node->data = NULL;

    pmm_free((uint32_t)node);
    total_nodes--;
}

/**
 * Split path into components
 */
static int split_path(const char* path, char components[][RAMFS_MAX_NAME], int max_components) {
    int count = 0;
    int comp_idx = 0;

    // Skip leading slashes
    while (*path == '/') path++;

    while (*path && count < max_components) {
        if (*path == '/') {
            components[count][comp_idx] = '\0';

            /*=================================================================
             * SECURITY: Path Traversal Prevention
             * Reject paths containing ".." to prevent directory escape attacks.
             * This protects against attempts to access parent directories or
             * escape the ramfs root boundary.
             *================================================================*/
            if (components[count][0] == '.' && components[count][1] == '.' &&
                components[count][2] == '\0') {
                kprintf("[RAMFS] SECURITY: Path traversal attempt blocked (..)\n");
                return -1;  // Reject path with ".."
            }

            count++;
            comp_idx = 0;
            path++;
        } else {
            if (comp_idx < RAMFS_MAX_NAME - 1) {
                components[count][comp_idx++] = *path;
            }
            path++;
        }
    }

    if (comp_idx > 0) {
        components[count][comp_idx] = '\0';

        // Check the last component for ".." as well
        if (components[count][0] == '.' && components[count][1] == '.' &&
            components[count][2] == '\0') {
            kprintf("[RAMFS] SECURITY: Path traversal attempt blocked (..)\n");
            return -1;  // Reject path with ".."
        }

        count++;
    }

    /*=========================================================================
     * SECURITY: Reject paths with too many components
     * If *path is not '\0' after the loop, we hit max_components limit and
     * silently truncated. This could cause writes to wrong locations.
     * Fail explicitly instead of truncating.
     *========================================================================*/
    if (*path != '\0') {
        kprintf("[RAMFS] SECURITY: Path too deep (>%d components)\n", max_components);
        return -1;  // Path exceeds depth limit
    }

    return count;
}

/*=============================================================================
 * PUBLIC FUNCTIONS
 *=============================================================================*/

/**
 * Initialize the filesystem
 */
void ramfs_init(void) {
    kprintf("[RAM] RAMFS: Initializing........... [OK]\n");

    /* Initialize mutex for filesystem protection */
    mutex_init(&ramfs_mutex, "ramfs", MUTEX_FLAG_RECURSIVE);

    // Create root directory
    root = alloc_node("/", RAMFS_TYPE_DIR);
    if (!root) {
        kprintf("RAMFS: Failed to create root directory\n");
        return;
    }

    // Initialize file descriptors
    for (int i = 0; i < RAMFS_MAX_FDS; i++) {
        file_descriptors[i].in_use = false;
        file_descriptors[i].node = NULL;
        file_descriptors[i].pos = 0;
        file_descriptors[i].flags = 0;
    }

    kprintf("[RAM] RAMFS (max files: %d, fd: %d). [OK]\n",
            RAMFS_MAX_FILES, RAMFS_MAX_FDS);
}

/**
 * INTERNAL: Find a node by path (caller must hold lock)
 *
 * SECURITY (v1.11): This is the internal version that assumes the caller
 * holds CRITICAL_SECTION. Directory tree operations that already hold the
 * lock should call this directly to avoid non-nestable lock issues.
 */
static ramfs_node_t* ramfs_find_locked(const char* path) {
    if (!root || !path) {
        return NULL;
    }

    // Handle root
    if (path[0] == '/' && path[1] == '\0') {
        return root;
    }

    // Split path into components
    char components[16][RAMFS_MAX_NAME];
    int num_components = split_path(path, components, 16);

    if (num_components < 0) {
        return NULL;  // Path traversal or invalid path
    }

    if (num_components == 0) {
        return root;
    }

    // Traverse the tree
    ramfs_node_t* current = root;

    for (int i = 0; i < num_components; i++) {
        if (current->type != RAMFS_TYPE_DIR) {
            return NULL;  // Not a directory
        }

        /*=====================================================================
         * SECURITY: Bounded Child List Traversal (Corruption Protection)
         * CRITICAL: A corrupted 'next' pointer in the child list could cause
         * an infinite loop, freezing the filesystem and requiring reboot.
         * We limit iterations to RAMFS_MAX_FILES to detect corruption.
         *===================================================================*/
        ramfs_node_t* child = current->children;
        bool found = false;
        int iterations = 0;

        while (child) {
            if (++iterations > RAMFS_MAX_FILES) {
                kprintf("[RAMFS] CRITICAL: Child list corrupted in '%s'! Infinite loop detected.\n",
                        current->name);
                return NULL;  // Fail-safe: return not found
            }

            if (strcmp(child->name, components[i]) == 0) {
                /*=============================================================
                 * SECURITY (v1.12): Symlink Detection (Infrastructure)
                 *
                 * When symlinks are fully implemented, this is where we would:
                 * 1. Check if child->type == RAMFS_TYPE_SYMLINK
                 * 2. If yes and not final component, follow the symlink
                 * 3. Track symlink depth to prevent infinite loops
                 *
                 * For now, we just traverse normally since symlinks don't
                 * exist yet. This comment serves as documentation for future
                 * implementation.
                 *===========================================================*/
                current = child;
                found = true;
                break;
            }
            child = child->next;
        }

        if (!found) {
            return NULL;
        }
    }

    return current;
}

/**
 * PUBLIC: Find a node by path (thread-safe)
 *
 * SECURITY (v1.11): This is the public version that acquires CRITICAL_SECTION
 * before traversing the directory tree. External callers should use this to
 * ensure thread-safe access to the filesystem.
 */
ramfs_node_t* ramfs_find(const char* path) {
    mutex_lock(&ramfs_mutex);
    ramfs_node_t* result = ramfs_find_locked(path);
    mutex_unlock(&ramfs_mutex);
    return result;
}

/**
 * Debug function: Check RAMFS root integrity
 */
void ramfs_debug_root(void) {
    // kprintf("[RAMFS_DEBUG] === Root Integrity Check ===\n");
    // kprintf("[RAMFS_DEBUG] Root node: %p\n", (void*)root);
    if (!root) {
        // kprintf("[RAMFS_DEBUG] ERROR: Root is NULL!\n");
        return;
    }

    // kprintf("[RAMFS_DEBUG] Root name: '%s'\n", root->name);
    // kprintf("[RAMFS_DEBUG] Root type: %d (1=DIR)\n", root->type);
    // kprintf("[RAMFS_DEBUG] Root children: %p\n", (void*)root->children);

    if (!root->children) {
        // kprintf("[RAMFS_DEBUG] WARNING: Root has no children!\n");
        return;
    }

    ramfs_node_t* child = root->children;
    int count = 0;
    // kprintf("[RAMFS_DEBUG] Root children list:\n");
    while (child && count < 20) {
        // kprintf("[RAMFS_DEBUG]   [%d] '%s' (type=%d, next=%p)\n",
        //         count, child->name, child->type, (void*)child->next);
        child = child->next;
        count++;

        /* Detect circular reference */
        if (child == root->children) {
            // kprintf("[RAMFS_DEBUG] Circular reference detected at position %d\n", count);
            break;
        }
    }
    if (count >= 20) {
        // kprintf("[RAMFS_DEBUG] WARNING: Stopped at 20 children (possible corruption)\n");
    }
    // kprintf("[RAMFS_DEBUG] Total children found: %d\n", count);
    // kprintf("[RAMFS_DEBUG] ===========================\n");
}

/**
 * Create a directory
 */
int ramfs_mkdir(const char* path) {
    mutex_lock(&ramfs_mutex);  /* SECURITY: Protect filesystem state */

    if (!path || !root) {
        mutex_unlock(&ramfs_mutex);
        return -1;
    }

    /* Get current process credentials (v1.10) */
    uint16_t uid, gid;
    get_current_credentials(&uid, &gid);

    // Check if already exists
    if (ramfs_find_locked(path)) {
        mutex_unlock(&ramfs_mutex);
        return -2;  // Already exists
    }

    // Split path to get parent and name
    char components[16][RAMFS_MAX_NAME];
    int num_components = split_path(path, components, 16);

    if (num_components < 0) {
        mutex_unlock(&ramfs_mutex);
        return -7;  // Path traversal attempt blocked
    }

    if (num_components == 0) {
        mutex_unlock(&ramfs_mutex);
        return -1;
    }

    // Find parent directory
    ramfs_node_t* parent = root;

    for (int i = 0; i < num_components - 1; i++) {
        ramfs_node_t* child = parent->children;
        bool found = false;

        while (child) {
            if (strcmp(child->name, components[i]) == 0) {
                if (child->type != RAMFS_TYPE_DIR) {
                    mutex_unlock(&ramfs_mutex);
                    return -3;  // Parent is not a directory
                }
                parent = child;
                found = true;
                break;
            }
            child = child->next;
        }

        if (!found) {
            mutex_unlock(&ramfs_mutex);
            return -4;  // Parent not found
        }
    }

    /* Check write permission on parent directory */
    if (!ramfs_check_permission(parent, uid, gid, RAMFS_FLAG_WRITE)) {
        mutex_unlock(&ramfs_mutex);
        return -5;  // Permission denied
    }

    /*=========================================================================
     * SECURITY (v1.13): Enforce Directory Entry Limit
     *
     * CRITICAL: Prevent integer overflow and DoS attacks by limiting directory
     * entries. Without this check, attacker could:
     * 1. Create thousands of subdirs, causing integer overflow on child_count
     * 2. Exhaust memory via unbounded pmm_alloc() calls (DoS)
     * 3. Trigger O(n) iteration pathology in ramfs_find() (performance DoS)
     * 4. Cause infinite loops if child list becomes corrupted
     *
     * FIX: Reject mkdir if parent already has RAMFS_MAX_CHILDREN_PER_DIR entries.
     *=======================================================================*/
    if (parent->child_count >= RAMFS_MAX_CHILDREN_PER_DIR) {
        mutex_unlock(&ramfs_mutex);
        return -9;  // Directory full (ENOSPC)
    }

    // Create new directory
    ramfs_node_t* new_dir = alloc_node(components[num_components - 1], RAMFS_TYPE_DIR);
    if (!new_dir) {
        mutex_unlock(&ramfs_mutex);
        return -6;  // Allocation failed
    }

    new_dir->parent = parent;
    new_dir->next = parent->children;
    parent->children = new_dir;
    parent->child_count++;  // Increment counter (v1.13)

    mutex_unlock(&ramfs_mutex);
    return 0;
}

/**
 * Open a file
 */
int ramfs_open(const char* path, uint8_t flags) {
    if (!path || !root) {
        return -1;
    }

    /* Get current process credentials (v1.10) */
    uint16_t uid, gid;
    get_current_credentials(&uid, &gid);

    /*=========================================================================
     * SECURITY FIX (v1.11): Per-Process FD Limit Enforcement
     *
     * ISSUE: Without per-process limits, a single malicious process can
     * exhaust the global FD table (RAMFS_MAX_FDS=16), preventing other
     * processes from opening files (DoS attack).
     *
     * FIX: Check per-process limit before allocating from global table.
     * - Each process limited to PROCESS_MAX_FDS (8 FDs)
     * - Return -EMFILE if process has reached its limit
     * - Fair resource sharing across processes
     *=======================================================================*/
    task_t* current = scheduler_get_current_task();
    if (current && current->open_fd_count >= PROCESS_MAX_FDS) {
        return -EMFILE;  // Too many open files (per-process limit)
    }

    // Find an available file descriptor
    int fd = -1;
    for (int i = 0; i < RAMFS_MAX_FDS; i++) {
        if (!file_descriptors[i].in_use) {
            fd = i;
            break;
        }
    }

    if (fd < 0) {
        return -2;  // No available file descriptors
    }

    /*=========================================================================
     * SECURITY FIX (v1.11): File Creation Race Condition Protection
     *
     * TOCTOU FIX: Check-then-create must be atomic to prevent race conditions.
     * Two threads opening the same non-existent file could both try to create
     * it, corrupting the directory tree. We now hold CRITICAL_SECTION during
     * the entire check-and-create operation.
     *=======================================================================*/

    // Try to find existing file
    ramfs_node_t* node = ramfs_find(path);

    if (!node && (flags & RAMFS_FLAG_WRITE)) {
        /* File doesn't exist and we want to write - create it */
        mutex_lock(&ramfs_mutex);

        /* Re-check after acquiring lock (TOCTOU prevention) */
        node = ramfs_find_locked(path);
        if (node) {
            /* Another thread created it while we waited for lock */
            mutex_unlock(&ramfs_mutex);
            /* Fall through to permission check */
        } else {
            /* Still doesn't exist, create it */
            char components[16][RAMFS_MAX_NAME];
            int num_components = split_path(path, components, 16);

            if (num_components < 0) {
                mutex_unlock(&ramfs_mutex);
                return -8;  // Path traversal attempt blocked
            }

            if (num_components == 0) {
                mutex_unlock(&ramfs_mutex);
                return -1;
            }

            // Find parent directory
            ramfs_node_t* parent = root;

            for (int i = 0; i < num_components - 1; i++) {
                ramfs_node_t* child = parent->children;
                bool found = false;

                while (child) {
                    if (strcmp(child->name, components[i]) == 0) {
                        parent = child;
                        found = true;
                        break;
                    }
                    child = child->next;
                }

                if (!found) {
                    mutex_unlock(&ramfs_mutex);
                    return -4;  // Parent not found
                }
            }

            /*=================================================================
             * SECURITY (v1.13): Enforce Directory Entry Limit (File Creation)
             *
             * CRITICAL: Also enforce limit when creating files, not just dirs.
             * Same DoS risks apply: memory exhaustion, integer overflow, etc.
             *===============================================================*/
            if (parent->child_count >= RAMFS_MAX_CHILDREN_PER_DIR) {
                mutex_unlock(&ramfs_mutex);
                return -9;  // Directory full (ENOSPC)
            }

            // Create new file
            node = alloc_node(components[num_components - 1], RAMFS_TYPE_FILE);
            if (!node) {
                mutex_unlock(&ramfs_mutex);
                return -5;  // Allocation failed
            }

            node->parent = parent;
            node->next = parent->children;
            parent->children = node;
            parent->child_count++;  // Increment counter (v1.13)

            mutex_unlock(&ramfs_mutex);
        }
    }

    if (!node) {
        return -3;  // File not found
    }

    /*=========================================================================
     * SECURITY (v1.12): O_NOFOLLOW Flag Implementation
     *
     * TOCTOU DEFENSE: If RAMFS_FLAG_NOFOLLOW is set and the final component
     * is a symlink, reject the open to prevent TOCTOU race conditions.
     *
     * ATTACK SCENARIO (without NOFOLLOW):
     *   1. Attacker creates /tmp/safe_file (regular file)
     *   2. Shell canonicalizes /tmp/safe_file > sees it's safe
     *   3. Attacker replaces /tmp/safe_file with symlink -> /etc/passwd
     *   4. Shell opens /tmp/safe_file, actually opens /etc/passwd (TOCTOU!)
     *
     * FIX: With NOFOLLOW flag, we reject symlinks at open time atomically.
     *=======================================================================*/
    if ((flags & RAMFS_FLAG_NOFOLLOW) && node->type == RAMFS_TYPE_SYMLINK) {
        return -8;  // Symlink with O_NOFOLLOW (ELOOP)
    }

    if (node->type != RAMFS_TYPE_FILE) {
        return -6;  // Not a file
    }

    /* Check permissions */
    if (!ramfs_check_permission(node, uid, gid, flags)) {
        return -7;  // Permission denied
    }

    /*=========================================================================
     * PHASE 13: Set close-on-exec flag (secure by default)
     * - Default: close_on_exec = true (FD will be closed on exec)
     * - Explicit RAMFS_FLAG_INHERIT: close_on_exec = false (FD survives exec)
     * - Reversed Unix semantics for security
     *=======================================================================*/
    // Setup file descriptor
    file_descriptors[fd].node = node;
    file_descriptors[fd].pos = 0;
    file_descriptors[fd].flags = flags;
    file_descriptors[fd].in_use = true;
    file_descriptors[fd].close_on_exec = !(flags & RAMFS_FLAG_INHERIT);  // PHASE 13

    /* Increment per-process FD count (v1.11) */
    if (current) {
        current->open_fd_count++;
    }

    return fd;
}

/**
 * Read from file
 */
int ramfs_read(int fd, void* buf, size_t count) {
    if (fd < 0 || fd >= RAMFS_MAX_FDS || !file_descriptors[fd].in_use) {
        return -1;
    }

    if (!(file_descriptors[fd].flags & RAMFS_FLAG_READ)) {
        return -2;  // Not opened for reading
    }

    ramfs_node_t* node = file_descriptors[fd].node;
    if (!node) {
        return -3;
    }

    uint32_t pos = file_descriptors[fd].pos;
    if (pos >= node->size) {
        return 0;  // EOF
    }

    size_t available = node->size - pos;
    size_t to_read = (count < available) ? count : available;

    uint8_t* dest = (uint8_t*)buf;
    size_t copied = 0;
    for (size_t i = 0; i < to_read; i++) {
        uint32_t off = pos + i;
        uint32_t page = off / RAMFS_PAGE_SIZE;
        if (page >= RAMFS_MAX_PAGES || !node->data_pages[page]) {
            /* A NULL backing page WITHIN node->size is not a legitimate sparse
             * hole for our use: every page up to node->size should have been
             * committed by ramfs_write. Previously this branch zero-filled the
             * byte and still counted it toward the return value, so a partially-
             * backed file passed the caller's `bytes_read == size` check
             * (cmd_exec, shell_fileops.c) carrying silently-corrupt content —
             * which surfaced as an intermittent ELF signature hash mismatch.
             * Stop here and report a short read (or -EIO if nothing was backed)
             * so the caller sees the truncation instead of bad data. */
            break;
        }
        dest[i] = node->data_pages[page][off % RAMFS_PAGE_SIZE];
        copied++;
    }

    if (copied == 0) {
        return -5;  /* -EIO: requested region within size has no backing page */
    }
    file_descriptors[fd].pos += copied;
    return copied;
}

/**
 * Write to file
 */
int ramfs_write(int fd, const void* buf, size_t count) {
    if (fd < 0 || fd >= RAMFS_MAX_FDS || !file_descriptors[fd].in_use) {
        return -1;
    }

    if (!(file_descriptors[fd].flags & RAMFS_FLAG_WRITE)) {
        return -2;  // Not opened for writing
    }

    ramfs_node_t* node = file_descriptors[fd].node;
    if (!node) {
        return -3;
    }

    uint32_t pos = file_descriptors[fd].pos;

    /*=========================================================================
     * SECURITY: Integer Overflow Prevention in Write Position Calculation
     * CRITICAL: We must validate BEFORE computing needed_size to prevent
     * an attacker from bypassing the RAMFS_MAX_DATA limit via overflow.
     *
     * Attack scenario without this check:
     *   pos = 0xFFFFFF00 (4294967040), count = 0x200 (512)
     *   needed_size = pos + count = 0x100 (256) - OVERFLOWED!
     *   Check: 0x100 < RAMFS_MAX_DATA (4096) - PASSES!
     *   Write occurs at offset 0xFFFFFF00, far beyond buffer bounds
     *
     * This defense ensures we detect overflow conditions before they can
     * be exploited to corrupt kernel memory.
     *=========================================================================*/
    if (pos > RAMFS_MAX_DATA) {
        // Already at or beyond max file size
        return 0;  // No bytes written
    }

    /*=========================================================================
     * SECURITY FIX (v1.18): Log short writes
     *
     * When write is truncated, caller may not check return value and assume
     * all data was written. Log this condition to aid debugging and detect
     * potential data loss issues.
     *=======================================================================*/
    size_t original_count = count;
    if (count > (RAMFS_MAX_DATA - pos)) {
        // Truncate write to fit within max file size
        count = RAMFS_MAX_DATA - pos;
        kprintf("[RAMFS] WARNING: Short write on fd=%d: requested=%u, actual=%u (truncated at max file size)\n",
                fd, (unsigned int)original_count, (unsigned int)count);
    }

    uint32_t needed_size;

    // Write data, allocating backing pages on demand
    const uint8_t* src = (const uint8_t*)buf;
    for (size_t i = 0; i < count; i++) {
        uint32_t off = pos + i;
        uint32_t page = off / RAMFS_PAGE_SIZE;
        if (page >= RAMFS_MAX_PAGES) {
            count = i;  // bounded by RAMFS_MAX_DATA above; defensive
            break;
        }
        if (!node->data_pages[page]) {
            node->data_pages[page] = (uint8_t*)pmm_alloc();
            if (!node->data_pages[page]) {
                count = i;  // out of memory: commit what was written
                break;
            }
            memset(node->data_pages[page], 0, RAMFS_PAGE_SIZE);
            if (page == 0) {
                node->data = node->data_pages[0];  // back-compat alias
            }
        }
        node->data_pages[page][off % RAMFS_PAGE_SIZE] = src[i];
    }

    needed_size = pos + count;
    file_descriptors[fd].pos += count;

    if (needed_size > node->size) {
        node->size = needed_size;
    }

    return count;
}

/**
 * Close file
 */
void ramfs_close(int fd) {
    if (fd >= 0 && fd < RAMFS_MAX_FDS && file_descriptors[fd].in_use) {
        /* Decrement per-process FD count (v1.11) */
        task_t* current = scheduler_get_current_task();
        if (current && current->open_fd_count > 0) {
            current->open_fd_count--;
        }

        file_descriptors[fd].in_use = false;
        file_descriptors[fd].node = NULL;
        file_descriptors[fd].pos = 0;
        file_descriptors[fd].flags = 0;
    }
}

/*=============================================================================
 * PHASE 13: Close-on-Exec Cleanup (Secure FD Inheritance)
 *
 * Called by ELF loader when exec() loads a new program. Closes all file
 * descriptors that have close_on_exec == true (which is the default).
 *
 * TRADITIONAL UNIX/LINUX:
 * - All FDs inherited by default (security nightmare)
 * - Must explicitly set O_CLOEXEC flag to prevent leakage
 * - Easy to forget, leading to FD leaks
 *
 * TINYOS INNOVATION:
 * - All FDs closed on exec by default (close_on_exec = true)
 * - Must explicitly set RAMFS_FLAG_INHERIT to keep FD open
 * - Reversed semantics for security (fail-secure design)
 *
 * SECURITY BENEFITS:
 * - No accidental FD leaks to child processes
 * - Sensitive FDs (database connections, password files) auto-close
 * - Explicit opt-in for FD inheritance (intentional, not accidental)
 *===========================================================================*/
void ramfs_close_on_exec(void) {
    for (int fd = 0; fd < RAMFS_MAX_FDS; fd++) {
        /* Close all FDs marked for close-on-exec */
        if (file_descriptors[fd].in_use && file_descriptors[fd].close_on_exec) {
            ramfs_close(fd);
        }
    }
}

/**
 * Delete a file
 */
int ramfs_unlink(const char* path) {
    mutex_lock(&ramfs_mutex);  /* SECURITY: Protect filesystem state */

    /* Get current process credentials (v1.10) */
    uint16_t uid, gid;
    get_current_credentials(&uid, &gid);

    ramfs_node_t* node = ramfs_find_locked(path);
    if (!node || node == root) {
        mutex_unlock(&ramfs_mutex);
        return -1;
    }

    if (node->type != RAMFS_TYPE_FILE) {
        mutex_unlock(&ramfs_mutex);
        return -2;  // Not a file
    }

    ramfs_node_t* parent = node->parent;
    if (!parent) {
        mutex_unlock(&ramfs_mutex);
        return -3;
    }

    /* Check write permission on parent directory */
    if (!ramfs_check_permission(parent, uid, gid, RAMFS_FLAG_WRITE)) {
        mutex_unlock(&ramfs_mutex);
        return -4;  // Permission denied
    }

    /*=========================================================================
     * SECURITY: Bounded List Traversal for Node Removal (Corruption Safety)
     * Limit iterations when searching parent's children list to prevent
     * infinite loops from corrupted 'next' pointers.
     *=========================================================================*/
    // Remove from parent's children list
    if (parent->children == node) {
        parent->children = node->next;
    } else {
        ramfs_node_t* prev = parent->children;
        int iterations = 0;

        while (prev && prev->next != node) {
            if (++iterations > RAMFS_MAX_FILES) {
                kprintf("[RAMFS] CRITICAL: Parent children list corrupted in unlink! Infinite loop detected.\n");
                mutex_unlock(&ramfs_mutex);
                return -5;  // List corruption detected
            }
            prev = prev->next;
        }
        if (prev) {
            prev->next = node->next;
        }
    }

    parent->child_count--;  // Decrement counter (v1.13)

    free_node(node);
    mutex_unlock(&ramfs_mutex);
    return 0;
}

/**
 * Atomic rename/move operation
 * SECURITY: This is atomic - no data copying, just updates the name field
 * Prevents race conditions and data loss in copy-then-delete operations
 */
int ramfs_rename(const char* old_path, const char* new_path) {
    mutex_lock(&ramfs_mutex);  /* SECURITY: Protect filesystem state */

    /* Get current process credentials (v1.10) */
    uint16_t uid, gid;
    get_current_credentials(&uid, &gid);

    /* Validate inputs */
    if (!old_path || !new_path) {
        mutex_unlock(&ramfs_mutex);
        return -3;  // Invalid paths
    }

    /* Find source node */
    ramfs_node_t* old_node = ramfs_find_locked(old_path);
    if (!old_node || old_node == root) {
        mutex_unlock(&ramfs_mutex);
        return -1;  // Source doesn't exist or is root
    }

    /* Check if destination already exists */
    ramfs_node_t* new_node = ramfs_find_locked(new_path);
    if (new_node) {
        mutex_unlock(&ramfs_mutex);
        return -2;  // Destination already exists
    }

    /* Check write permission on parent directory */
    ramfs_node_t* parent = old_node->parent;
    if (!parent) {
        mutex_unlock(&ramfs_mutex);
        return -3;  // No parent (shouldn't happen except for root)
    }

    if (!ramfs_check_permission(parent, uid, gid, RAMFS_FLAG_WRITE)) {
        mutex_unlock(&ramfs_mutex);
        return -4;  // Permission denied
    }

    /* Extract new name from new_path (just the filename, not the full path)
     * For now, only support rename in same directory (no move across directories)
     * Full path rename would require updating parent pointers
     */
    const char* new_name = new_path;
    const char* last_slash = NULL;

    /* Find last slash to extract filename */
    for (const char* p = new_path; *p != '\0'; p++) {
        if (*p == '/') {
            last_slash = p;
        }
    }

    if (last_slash) {
        new_name = last_slash + 1;
    }

    /* Verify new name fits in buffer */
    size_t new_name_len = 0;
    for (const char* p = new_name; *p != '\0'; p++) {
        new_name_len++;
        if (new_name_len >= RAMFS_MAX_NAME) {
            mutex_unlock(&ramfs_mutex);
            return -3;  // Name too long
        }
    }

    /* ATOMIC OPERATION: Just update the name field */
    for (size_t i = 0; i < RAMFS_MAX_NAME && i <= new_name_len; i++) {
        old_node->name[i] = new_name[i];
    }
    old_node->name[RAMFS_MAX_NAME - 1] = '\0';  // Ensure null termination

    mutex_unlock(&ramfs_mutex);
    return 0;  // Success
}

/**
 * Remove a directory
 */
int ramfs_rmdir(const char* path) {
    mutex_lock(&ramfs_mutex);  /* SECURITY: Protect filesystem state */

    /* Get current process credentials (v1.10) */
    uint16_t uid, gid;
    get_current_credentials(&uid, &gid);

    ramfs_node_t* node = ramfs_find_locked(path);
    if (!node || node == root) {
        mutex_unlock(&ramfs_mutex);
        return -1;  // Not found or cannot remove root
    }

    if (node->type != RAMFS_TYPE_DIR) {
        mutex_unlock(&ramfs_mutex);
        return -2;  // Not a directory
    }

    /* Check if directory is empty */
    if (node->children != NULL) {
        mutex_unlock(&ramfs_mutex);
        return -3;  // Directory not empty
    }

    ramfs_node_t* parent = node->parent;
    if (!parent) {
        mutex_unlock(&ramfs_mutex);
        return -4;  // No parent
    }

    /* Check write permission on parent directory */
    if (!ramfs_check_permission(parent, uid, gid, RAMFS_FLAG_WRITE)) {
        mutex_unlock(&ramfs_mutex);
        return -5;  // Permission denied
    }

    /*=========================================================================
     * SECURITY: Bounded List Traversal for Directory Removal (Corruption Safety)
     * Limit iterations when searching parent's children list to prevent
     * infinite loops from corrupted 'next' pointers.
     *=========================================================================*/
    // Remove from parent's children list
    if (parent->children == node) {
        parent->children = node->next;
    } else {
        ramfs_node_t* prev = parent->children;
        int iterations = 0;

        while (prev && prev->next != node) {
            if (++iterations > RAMFS_MAX_FILES) {
                kprintf("[RAMFS] CRITICAL: Parent children list corrupted in rmdir! Infinite loop detected.\n");
                mutex_unlock(&ramfs_mutex);
                return -6;  // List corruption detected
            }
            prev = prev->next;
        }
        if (prev) {
            prev->next = node->next;
        }
    }

    parent->child_count--;  // Decrement counter (v1.13)

    free_node(node);
    mutex_unlock(&ramfs_mutex);
    return 0;
}

/**
 * List directory contents (with Unix-like permissions)
 */
void ramfs_list(const char* path) {
    ramfs_node_t* node = ramfs_find(path);

    if (!node) {
        kprintf("Not found: %s\n", path);
        return;
    }

    // If it's a file, just display that file's information
    if (node->type == RAMFS_TYPE_FILE) {
        char perm_str[10];
        ramfs_format_permissions(node->mode, perm_str);
        kprintf("  -%s %u:%u %8u %s\n",
                perm_str, node->uid, node->gid, node->size, node->name);
        return;
    }

    // It's a directory, list its contents
    kprintf("Contents of %s:\n", path);

    ramfs_node_t* child = node->children;
    if (!child) {
        kprintf("  (empty)\n");
        return;
    }

    while (child) {
        char perm_str[10];
        ramfs_format_permissions(child->mode, perm_str);

        if (child->type == RAMFS_TYPE_DIR) {
            kprintf("  d%s %u:%u %8s %s/\n",
                    perm_str, child->uid, child->gid, "-", child->name);
        } else {
            kprintf("  -%s %u:%u %8u %s\n",
                    perm_str, child->uid, child->gid, child->size, child->name);
        }
        child = child->next;
    }
}

/**
 * Get directory contents (for iteration)
 */
ramfs_node_t* ramfs_readdir(const char* path) {
    ramfs_node_t* dir = ramfs_find(path);
    if (!dir || dir->type != RAMFS_TYPE_DIR) {
        return NULL;
    }
    return dir->children;
}

/**
 * Get root node
 */
ramfs_node_t* ramfs_get_root(void) {
    return root;
}

/*=============================================================================
 * PERMISSION OPERATIONS
 *=============================================================================*/

/**
 * Change file permissions (chmod)
 */
int ramfs_chmod(const char* path, uint16_t mode) {
    ramfs_node_t* node = ramfs_find(path);
    if (!node) {
        return -1;  /* File not found */
    }

    /*=========================================================================
     * PHASE 3: SECURITY - Enforce NO setuid/sgid/sticky bits
     *
     * DEFENSE IN DEPTH: Mask out ANY high bits to ensure only standard
     * Unix permission bits (owner/group/other rwx) can be set.
     *
     * If a malicious caller tries to set:
     * - chmod 04755 (setuid) → silently becomes 0755 (no setuid)
     * - chmod 02755 (sgid)   → silently becomes 0755 (no sgid)
     * - chmod 01777 (sticky) → silently becomes 0777 (no sticky)
     *
     * This prevents ANY code path from accidentally setting dangerous bits.
     *=======================================================================*/
    mode &= RAMFS_PERM_MASK;  /* Mask out setuid/sgid/sticky bits (keep only 0777) */

    node->mode = mode;
    return 0;
}

/**
 * Check if a user has permission to access a file
 * @param node The file node
 * @param uid User ID performing the access
 * @param gid Group ID of the user
 * @param access Required access (RAMFS_FLAG_READ or RAMFS_FLAG_WRITE)
 * @return true if access is granted, false otherwise
 */
bool ramfs_check_permission(ramfs_node_t* node, uint16_t uid, uint16_t gid, uint8_t access) {
    if (!node) {
        return false;
    }

    /*=========================================================================
     * SECURITY (v1.13): Root Permission Check MUST Be First
     *
     * CRITICAL: The root user (UID 0) check MUST be the very first permission
     * check, immediately after the null check. This ensures root ALWAYS has
     * full access to all files, regardless of permission bits.
     *
     * RATIONALE:
     * - Root must be able to fix broken permissions (chmod 000 file)
     * - Root must be able to access system files for maintenance
     * - Even if a file is set to mode 000, root can still read/write it
     *
     * WARNING: DO NOT move this check below owner/group/other checks!
     * If this check is buried deeper in the logic, a file with mode 000
     * could become inaccessible even to root, breaking system recovery.
     *
     * VERIFICATION: This check must be:
     * 1. After null check only
     * 2. Before any permission bit checking
     * 3. Return true immediately (no fall-through)
     *=======================================================================*/
    if (uid == 0) {
        return true;
    }

    uint16_t required_perms = 0;

    /* Determine which permission set to check */
    if (uid == node->uid) {
        /* Owner permissions */
        if (access & RAMFS_FLAG_READ) {
            required_perms |= RAMFS_PERM_OWNER_READ;
        }
        if (access & RAMFS_FLAG_WRITE) {
            required_perms |= RAMFS_PERM_OWNER_WRITE;
        }
    } else if (gid == node->gid) {
        /* Group permissions (primary group matches) */
        if (access & RAMFS_FLAG_READ) {
            required_perms |= RAMFS_PERM_GROUP_READ;
        }
        if (access & RAMFS_FLAG_WRITE) {
            required_perms |= RAMFS_PERM_GROUP_WRITE;
        }
    } else {
        /*=====================================================================
         * SECURITY (v1.12): Check Supplemental Group IDs
         *
         * CRITICAL: Permission must check ALL groups (egid + supplemental).
         * Without this, processes can retain elevated access via supplemental
         * groups even after dropping primary gid.
         *
         * Example: User in "docker" group drops gid to "users" but retains
         * supplemental "docker" membership - can still access docker files!
         *===================================================================*/
        bool group_match = false;
        task_t* current = scheduler_get_current_task();
        if (current) {
            for (int i = 0; i < current->ngroups; i++) {
                if (current->groups[i] == node->gid) {
                    /* Supplemental group matches - use group permissions */
                    if (access & RAMFS_FLAG_READ) {
                        required_perms |= RAMFS_PERM_GROUP_READ;
                    }
                    if (access & RAMFS_FLAG_WRITE) {
                        required_perms |= RAMFS_PERM_GROUP_WRITE;
                    }
                    group_match = true;
                    break;
                }
            }
        }

        if (group_match) {
            /* Group permission via supplemental group */
        } else {
            /* Others permissions */
            if (access & RAMFS_FLAG_READ) {
                required_perms |= RAMFS_PERM_OTHER_READ;
            }
            if (access & RAMFS_FLAG_WRITE) {
                required_perms |= RAMFS_PERM_OTHER_WRITE;
            }
        }
    }

    /* Check if all required permissions are present */
    return (node->mode & required_perms) == required_perms;
}

/**
 * Format permissions as a Unix-style string (e.g., "rwxr-xr-x")
 * @param mode Permission mode
 * @param buf Buffer to store the formatted string (must be at least 10 bytes)
 */
void ramfs_format_permissions(uint16_t mode, char* buf) {
    /* Owner permissions */
    buf[0] = (mode & RAMFS_PERM_OWNER_READ)  ? 'r' : '-';
    buf[1] = (mode & RAMFS_PERM_OWNER_WRITE) ? 'w' : '-';
    buf[2] = (mode & RAMFS_PERM_OWNER_EXEC)  ? 'x' : '-';

    /* Group permissions */
    buf[3] = (mode & RAMFS_PERM_GROUP_READ)  ? 'r' : '-';
    buf[4] = (mode & RAMFS_PERM_GROUP_WRITE) ? 'w' : '-';
    buf[5] = (mode & RAMFS_PERM_GROUP_EXEC)  ? 'x' : '-';

    /* Other permissions */
    buf[6] = (mode & RAMFS_PERM_OTHER_READ)  ? 'r' : '-';
    buf[7] = (mode & RAMFS_PERM_OTHER_WRITE) ? 'w' : '-';
    buf[8] = (mode & RAMFS_PERM_OTHER_EXEC)  ? 'x' : '-';

    buf[9] = '\0';
}

/*=============================================================================
 * PHASE 6: Crypto-Random Temporary File Creation
 *===========================================================================*/

/**
 * @brief Create crypto-random temporary file (secure mktemp replacement)
 *
 * Creates a temporary file with cryptographically random name in the current
 * process's private /tmp directory. The file is created atomically to prevent
 * race conditions.
 *
 * @param filename_out Buffer to receive full path of created file (min 64 bytes)
 * @param buf_size Size of filename_out buffer
 * @return File descriptor (>=0) on success, negative error code on failure
 */
int ramfs_mkstemps(char* filename_out, size_t buf_size) {
    /*=========================================================================
     * SECURITY VALIDATION
     *=======================================================================*/

    /* Buffer must be large enough for: /tmp/XXXXXXXXXX/YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY.tmp + null
     * where X = 10 hex chars (private dir), Y = 32 hex chars (random) = ~50 bytes min */
    if (buf_size < 64) {
        kprintf("[RAMFS] mkstemps: Buffer too small (need 64 bytes, got %u)\n",
                (unsigned int)buf_size);
        return -1;
    }

    /*=========================================================================
     * GET CURRENT PROCESS CONTEXT
     *=======================================================================*/
    task_t* current = scheduler_get_current_task();
    if (!current) {
        kprintf("[RAMFS] mkstemps: No current task (kernel context?)\n");
        return -2;
    }

    /*=========================================================================
     * GENERATE CRYPTO-RANDOM FILENAME
     * Use 128 bits (16 bytes) of entropy → 32 hex characters
     * global_csprng is declared in crypto.h which is included at top of file
     *=======================================================================*/
    uint8_t random_bytes[16];  /* 128 bits of entropy */

    /* Generate crypto-random bytes (function always succeeds) */
    csprng_random_bytes(&global_csprng, random_bytes, sizeof(random_bytes));

    /* Convert 16 random bytes to 32 hex characters */
    const char* hex = "0123456789abcdef";
    char random_hex[33];  /* 32 hex chars + null terminator */

    for (int i = 0; i < 16; i++) {
        random_hex[i * 2]     = hex[(random_bytes[i] >> 4) & 0xF];  /* High nibble */
        random_hex[i * 2 + 1] = hex[random_bytes[i] & 0xF];         /* Low nibble */
    }
    random_hex[32] = '\0';

    /*=========================================================================
     * BUILD FULL PATH: <private_tmp_dir>/<random>.tmp
     *=======================================================================*/
    char full_path[64];
    int path_len = 0;

    /* Copy private tmp directory path (e.g., "/tmp/a1b2c3d4e5/") */
    const char* tmp_dir = current->private_tmp_dir;
    while (*tmp_dir && path_len < 63) {
        full_path[path_len++] = *tmp_dir++;
    }

    /* Add random filename */
    for (int i = 0; i < 32 && path_len < 63; i++) {
        full_path[path_len++] = random_hex[i];
    }

    /* Add .tmp extension */
    if (path_len < 59) {
        full_path[path_len++] = '.';
        full_path[path_len++] = 't';
        full_path[path_len++] = 'm';
        full_path[path_len++] = 'p';
    }
    full_path[path_len] = '\0';

    /*=========================================================================
     * CREATE FILE ATOMICALLY
     * Try to create the file. If it already exists (unlikely with 128-bit
     * randomness, but theoretically possible), this will fail.
     *=======================================================================*/

    /* First, check if file already exists (should be extremely rare) */
    ramfs_node_t* existing = ramfs_find(full_path);
    if (existing) {
        /* Collision! This should never happen with 128-bit randomness,
         * but if it does, caller should retry */
        kprintf("[RAMFS] mkstemps: Collision on random filename (extremely rare!)\n");
        return -4;
    }

    /* Create the file (this calls create_node which allocates memory) */
    int fd = ramfs_open(full_path, RAMFS_FLAG_READ | RAMFS_FLAG_WRITE);
    if (fd < 0) {
        kprintf("[RAMFS] mkstemps: Failed to create file '%s'\n", full_path);
        return -4;
    }

    /*=========================================================================
     * RETURN FILE DESCRIPTOR AND PATH
     *=======================================================================*/
    /* Copy full path to output buffer */
    for (size_t i = 0; i < buf_size - 1 && i < sizeof(full_path); i++) {
        filename_out[i] = full_path[i];
        if (full_path[i] == '\0') break;
    }
    filename_out[buf_size - 1] = '\0';  /* Ensure null termination */

    kprintf("[RAMFS] mkstemps: Created temp file '%s' (fd=%d)\n", full_path, fd);

    return fd;
}
