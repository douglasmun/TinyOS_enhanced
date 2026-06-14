/*=============================================================================
 * shell_fileops.c - Shell File Operations Implementation
 *=============================================================================*/
#include "shell_fileops.h"
#include "ramfs.h"
#include "fat32.h"
#include "vfs.h"
#include "kernel.h"
#include "kprintf.h"
#include "util.h"
#include "elf.h"
#include "process.h"
#include "scheduler.h"
#include "editor.h"
#include "stdio.h"
#include "critical.h"
#include <stddef.h>
#include <stdint.h>

#define COPY_BUFFER_SIZE 4096

/* Forward declarations */
static const char* resolve_path(const char* path, char* abs_path, size_t abs_path_size);

/*=============================================================================
 * COMMAND: cp - Copy file
 *=============================================================================*/
void cmd_cp(int argc, char** argv) {
    if (argc < 3) {
        kprintf("Usage: cp <source> <destination>\n");
        return;
    }

    const char* src_path = argv[1];
    const char* dst_path = argv[2];

    /*
     * TOCTOU Fix: Open file first, then verify type and size.
     * This prevents race condition between stat and open.
     */

    // Allocate buffer for copy (local, not static - thread-safe)
    uint8_t copy_buffer[COPY_BUFFER_SIZE];

    // Open source file for reading first
    int src_fd = ramfs_open(src_path, RAMFS_FLAG_READ);
    if (src_fd < 0) {
        kprintf("cp: cannot open '%s' for reading\n", src_path);
        return;
    }

    // Now verify the source file after opening
    ramfs_node_t* src_node = ramfs_find(src_path);
    if (!src_node || src_node->type != RAMFS_TYPE_FILE) {
        kprintf("cp: '%s': Not a regular file\n", src_path);
        ramfs_close(src_fd);
        return;
    }

    // Check if destination already exists
    ramfs_node_t* dst_node = ramfs_find(dst_path);
    if (dst_node) {
        kprintf("cp: '%s': File exists (overwrite not implemented)\n", dst_path);
        ramfs_close(src_fd);
        return;
    }

    // Create and open destination file for writing
    int dst_fd = ramfs_open(dst_path, RAMFS_FLAG_WRITE);
    if (dst_fd < 0) {
        kprintf("cp: cannot create '%s'\n", dst_path);
        ramfs_close(src_fd);
        return;
    }

    // Copy file in chunks until EOF (don't rely on pre-checked size)
    uint32_t total_bytes_copied = 0;
    int bytes_read;

    while (1) {
        // Read next chunk (read until EOF)
        bytes_read = ramfs_read(src_fd, copy_buffer, COPY_BUFFER_SIZE);
        if (bytes_read < 0) {
            kprintf("cp: error reading '%s'\n", src_path);
            goto copy_fail;
        }
        if (bytes_read == 0) {
            // EOF reached
            break;
        }

        // Write chunk
        int bytes_written = ramfs_write(dst_fd, copy_buffer, bytes_read);
        if (bytes_written != bytes_read) {
            kprintf("cp: error writing to '%s'\n", dst_path);
            goto copy_fail;
        }

        total_bytes_copied += bytes_read;
    }

    // Success - cleanup and report
    ramfs_close(src_fd);
    ramfs_close(dst_fd);
    kprintf("'%s' -> '%s' (%u bytes)\n", src_path, dst_path, total_bytes_copied);
    return;

copy_fail:
    // Cleanup on failure
    ramfs_close(src_fd);
    ramfs_close(dst_fd);
    // Delete the partially created file
    ramfs_unlink(dst_path);
}

/*=============================================================================
 * COMMAND: mv - Move/rename file
 *=============================================================================*/
void cmd_mv(int argc, char** argv) {
    if (argc < 3) {
        kprintf("Usage: mv <source> <destination>\n");
        return;
    }

    const char* src_path = argv[1];
    const char* dst_path = argv[2];

    /* SECURITY FIX: Use atomic rename operation instead of copy-then-delete
     * This prevents:
     * - Race conditions between copy and delete
     * - Data duplication if system crashes mid-operation
     * - Unnecessary disk I/O and performance overhead
     */
    int result = ramfs_rename(src_path, dst_path);

    if (result == 0) {
        kprintf("'%s' -> '%s'\n", src_path, dst_path);
    } else if (result == -1) {
        kprintf("mv: cannot stat '%s': No such file or directory\n", src_path);
    } else if (result == -2) {
        kprintf("mv: '%s': Destination exists\n", dst_path);
    } else if (result == -3) {
        kprintf("mv: invalid path\n");
    } else if (result == -4) {
        kprintf("mv: permission denied\n");
    } else {
        kprintf("mv: operation failed (error %d)\n", result);
    }
}

/*=============================================================================
 * COMMAND: chmod - Change file permissions
 *=============================================================================*/
void cmd_chmod(int argc, char** argv) {
    if (argc < 3) {
        kprintf("Usage: chmod <mode> <file>\n");
        kprintf("Example: chmod 644 myfile.txt\n");
        kprintf("         chmod 755 mydir\n");
        return;
    }

    const char* mode_str = argv[1];
    char abs_path[MAX_PATH];
    const char* path = resolve_path(argv[2], abs_path, sizeof(abs_path));

    /* SECURITY: Check for path truncation - fail-safe for destructive operations */
    if (!path) {
        kprintf("chmod: path too long (would be truncated) - refusing to operate\n");
        kprintf("chmod: this prevents accidentally changing permissions on wrong file\n");
        return;
    }

    /* Parse octal mode (e.g., "644" -> 0644) */
    uint16_t mode = 0;
    const char* p = mode_str;

    /* Skip leading zeros or '0o' prefix */
    if (*p == '0') {
        p++;
        if (*p == 'o' || *p == 'O') {
            p++;
        }
    }

    /* Parse octal digits */
    while (*p >= '0' && *p <= '7') {
        mode = mode * 8 + (*p - '0');
        p++;
    }

    /* Validate that we parsed something and didn't encounter invalid characters */
    if (p == mode_str || *p != '\0') {
        kprintf("chmod: invalid mode: '%s'\n", mode_str);
        kprintf("Mode must be an octal number (e.g., 644, 755)\n");
        return;
    }

    /* Validate mode range (0-0777) */
    if (mode > 0777) {
        kprintf("chmod: invalid mode: '%s' (must be 0-777)\n", mode_str);
        return;
    }

    /* Change permissions */
    int result = ramfs_chmod(path, mode);
    if (result < 0) {
        if (result == -1) {
            kprintf("chmod: cannot access '%s': No such file or directory\n", path);
        } else if (result == -2) {
            kprintf("chmod: invalid mode\n");
        } else {
            kprintf("chmod: error changing permissions\n");
        }
        return;
    }

    /* Display new permissions */
    ramfs_node_t* node = ramfs_find(path);
    if (node) {
        char perm_str[10];
        ramfs_format_permissions(node->mode, perm_str);
        kprintf("chmod: '%s' -> %s (%03o)\n", path, perm_str, node->mode);
    }
}

/*=============================================================================
 * COMMAND: pwd - Print working directory (Phase 2: With drive letter)
 *=============================================================================*/
static char current_dir[MAX_PATH] = "/";
static char current_drive = 'D';  /* Default to D: (RAMFS) for compatibility */

void cmd_pwd(void) {
    kprintf("%c:%s\n", current_drive, current_dir);
}

/*=============================================================================
 * COMMAND: cd - Change directory (Phase 2: Drive letter support)
 *=============================================================================*/
void cmd_cd(int argc, char* argv[]) {
    if (argc < 2) {
        kprintf("Usage: cd <path>\n");
        kprintf("  cd C:     - Switch to C: drive (FAT32)\n");
        kprintf("  cd D:     - Switch to D: drive (RAMFS)\n");
        kprintf("  cd /path  - Change directory on current drive\n");
        return;
    }

    const char* path = argv[1];
    char new_path[MAX_PATH];
    char target_drive = current_drive;

    /* Check for drive letter (e.g., "C:" or "D:") */
    if ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) {
        if (path[1] == ':') {
            target_drive = path[0];
            if (target_drive >= 'a' && target_drive <= 'z') {
                target_drive = target_drive - 'a' + 'A';  /* Normalize to uppercase */
            }

            /* Check if drive is mounted */
            if (target_drive != 'C' && target_drive != 'D') {
                kprintf("cd: Drive %c: not mounted\n", target_drive);
                return;
            }

            /* If just "C:" or "D:", switch to root of that drive */
            if (path[2] == '\0') {
                current_drive = target_drive;
                current_dir[0] = '/';
                current_dir[1] = '\0';
                return;
            }

            /* Path after drive letter */
            path = path + 2;  /* Skip "C:" or "D:" */
        }
    }

    /* Handle special cases */
    if (strcmp(path, ".") == 0) {
        /* Stay in current directory */
        return;
    } else if (strcmp(path, "..") == 0) {
        /* Go to parent directory */
        if (strcmp(current_dir, "/") == 0) {
            /* Already at root, stay there */
            return;
        }

        /* Find last slash in current_dir */
        int last_slash = -1;
        for (int i = 0; current_dir[i] != '\0'; i++) {
            if (current_dir[i] == '/') {
                last_slash = i;
            }
        }

        if (last_slash == 0) {
            /* Parent is root */
            new_path[0] = '/';
            new_path[1] = '\0';
        } else if (last_slash > 0) {
            /* Copy up to last slash */
            int i;
            for (i = 0; i < last_slash; i++) {
                new_path[i] = current_dir[i];
            }
            new_path[i] = '\0';
        } else {
            /* Shouldn't happen, but default to root */
            new_path[0] = '/';
            new_path[1] = '\0';
        }
        path = new_path;
    } else if (path[0] != '/') {
        /* Relative path - build absolute path */
        if (strcmp(current_dir, "/") == 0) {
            /* In root, just prepend / */
            new_path[0] = '/';
            size_t i;
            for (i = 0; path[i] != '\0' && i < sizeof(new_path) - 2; i++) {
                new_path[i + 1] = path[i];
            }
            new_path[i + 1] = '\0';
        } else {
            /* Append to current directory */
            size_t pos = 0;
            for (size_t i = 0; current_dir[i] != '\0' && pos < sizeof(new_path) - 1; i++) {
                new_path[pos++] = current_dir[i];
            }
            new_path[pos++] = '/';
            for (size_t i = 0; path[i] != '\0' && pos < sizeof(new_path) - 1; i++) {
                new_path[pos++] = path[i];
            }
            new_path[pos] = '\0';
        }
        path = new_path;
    }

    /* Phase 2: FAT32 (C:) only supports root directory for now */
    if (target_drive == 'C') {
        if (strcmp(path, "/") != 0) {
            kprintf("cd: FAT32 (C:) currently only supports root directory\n");
            kprintf("    Use 'cd C:' to go to C:/ root\n");
            return;
        }
        current_drive = 'C';
        current_dir[0] = '/';
        current_dir[1] = '\0';
        return;
    }

    /* RAMFS (D:) - full directory support */
    ramfs_node_t* node = ramfs_find(path);
    if (!node) {
        kprintf("cd: %s: No such directory\n", path);
        return;
    }

    if (node->type != RAMFS_TYPE_DIR) {
        kprintf("cd: %s: Not a directory\n", path);
        return;
    }

    /* Update current drive and directory */
    current_drive = target_drive;
    size_t path_len = strlen(path);
    if (path_len >= sizeof(current_dir)) {
        kprintf("cd: path too long\n");
        return;
    }

    for (size_t i = 0; i < path_len; i++) {
        current_dir[i] = path[i];
    }
    current_dir[path_len] = '\0';

    /* Ensure path ends without trailing slash (except for root) */
    if (path_len > 1 && current_dir[path_len - 1] == '/') {
        current_dir[path_len - 1] = '\0';
    }
}

/*=============================================================================
 * COMMAND: ls - List directory contents
 *=============================================================================*/
/*-----------------------------------------------------------------------------
 * HELPER: Format size in human-readable format (KB, MB, GB)
 * Manual formatting without snprintf (not available in kernel)
 *-----------------------------------------------------------------------------*/
static void format_size_human(uint32_t size, char* buf, size_t buf_size) {
    uint32_t value;
    char suffix;

    if (size < 1024) {
        /* Bytes */
        value = size;
        suffix = 'B';
    } else if (size < 1024 * 1024) {
        /* Kilobytes */
        value = size / 1024;
        suffix = 'K';
    } else if (size < 1024 * 1024 * 1024) {
        /* Megabytes */
        value = size / (1024 * 1024);
        suffix = 'M';
    } else {
        /* Gigabytes */
        value = size / (1024 * 1024 * 1024);
        suffix = 'G';
    }

    /* Convert value to string manually */
    if (value == 0) {
        buf[0] = '0';
        buf[1] = suffix;
        buf[2] = '\0';
        return;
    }

    /* Convert integer to string (reverse order) */
    char temp[16];
    int pos = 0;
    uint32_t v = value;
    while (v > 0 && pos < 15) {
        temp[pos++] = (char)('0' + (v % 10));
        v /= 10;
    }

    /* Reverse into output buffer */
    int i = 0;
    while (pos > 0 && i < (int)buf_size - 2) {
        buf[i++] = temp[--pos];
    }

    /* Add suffix */
    if (i < (int)buf_size - 1) {
        buf[i++] = suffix;
    }
    buf[i] = '\0';
}

/*-----------------------------------------------------------------------------
 * HELPER: Compare two node names for sorting (case-sensitive alphabetical)
 *-----------------------------------------------------------------------------*/
static int node_name_compare(const char* a, const char* b) {
    while (*a && *b) {
        if (*a != *b) {
            return (*a < *b) ? -1 : 1;
        }
        a++;
        b++;
    }
    if (*a) return 1;   /* a is longer */
    if (*b) return -1;  /* b is longer */
    return 0;           /* equal */
}

/*-----------------------------------------------------------------------------
 * HELPER: Sort array of ramfs node pointers alphabetically by name
 * Uses insertion sort (simple and efficient for small lists)
 * Operates on a pointer array so the live sibling chain is never modified.
 *-----------------------------------------------------------------------------*/
static void sort_nodes(ramfs_node_t** list, int count, bool reverse) {
    for (int i = 1; i < count; i++) {
        ramfs_node_t* current = list[i];
        int j = i - 1;
        while (j >= 0 &&
               (reverse ? node_name_compare(current->name, list[j]->name) > 0
                        : node_name_compare(current->name, list[j]->name) < 0)) {
            list[j + 1] = list[j];
            j--;
        }
        list[j + 1] = current;
    }
}

void cmd_ls(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    bool long_format = false;
    bool show_all = false;
    bool human_readable = false;
    bool single_column = false;
    bool reverse_sort = false;
    int path_arg = -1;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            /* Flag */
            for (const char* p = argv[i] + 1; *p; p++) {
                if (*p == 'l') {
                    long_format = true;
                } else if (*p == 'a') {
                    show_all = true;
                } else if (*p == 'h') {
                    human_readable = true;
                } else if (*p == '1') {
                    single_column = true;
                } else if (*p == 'r') {
                    reverse_sort = true;
                } else {
                    stream_printf(ctx, "ls: invalid option -- '%c'\n", *p);
                    stream_printf(ctx, "Usage: ls [-ahl1r] [path]\n");
                    stream_printf(ctx, "  -a  show all files (including hidden)\n");
                    stream_printf(ctx, "  -h  human-readable sizes (K, M, G)\n");
                    stream_printf(ctx, "  -l  long format\n");
                    stream_printf(ctx, "  -1  single column output\n");
                    stream_printf(ctx, "  -r  reverse sort order\n");
                    return;
                }
            }
        } else {
            /* Path argument */
            path_arg = i;
        }
    }

    const char* path = (path_arg >= 0) ? argv[path_arg] : current_dir;
    char target_drive = current_drive;

    /* Parse drive letter if present (e.g., "C:" or "D:") */
    if (path_arg >= 0) {
        const char* arg = argv[path_arg];
        if ((arg[0] >= 'A' && arg[0] <= 'Z') || (arg[0] >= 'a' && arg[0] <= 'z')) {
            if (arg[1] == ':') {
                target_drive = arg[0];
                if (target_drive >= 'a' && target_drive <= 'z') {
                    target_drive = target_drive - 'a' + 'A';
                }
                /* Check if just drive letter or has path */
                if (arg[2] == '\0') {
                    path = "/";  /* Just drive letter, list root */
                } else {
                    path = arg + 2;  /* Skip drive letter */
                }
            }
        }
    }

    /*=========================================================================
     * CROSS-DRIVE ACCESS FIX: Route based on target_drive, not current_drive
     *
     * This allows listing directories on any mounted drive, regardless of
     * the current working directory's drive.
     *
     * Examples:
     *   C:\> ls D:/hello    # Lists D:/hello (routes to RAMFS)
     *   D:\> ls C:/         # Lists C:/ (routes to FAT32)
     *=======================================================================*/
    // kprintf("[LS DEBUG] current_drive='%c', target_drive='%c', path='%s'\n",
    //         current_drive, target_drive, path);

    /* Route to appropriate filesystem based on target_drive */
    if (target_drive == 'C') {
        /* FAT32 filesystem */
        // kprintf("[LS DEBUG] Routing to FAT32 (cmd_fatls)\n");

        /* Build fatls command with options */
        char* fatls_argv[10];
        int fatls_argc = 1;
        fatls_argv[0] = "fatls";

        if (long_format) {
            fatls_argv[fatls_argc++] = "-l";
        }

        cmd_fatls(fatls_argc, fatls_argv);
        return;
    } else if (target_drive == 'D') {
        /* RAMFS filesystem */
        // kprintf("[LS DEBUG] Routing to RAMFS (ramfs_find)\n");
    } else {
        /* Unsupported drive */
        stream_printf(ctx, "ls: drive %c: not supported (only C: and D: are available)\n",
                      target_drive);
        return;
    }

    /* RAMFS (D:) directory listing logic */

    /* DEBUG: Check RAMFS integrity when listing D: root */
    if (path[0] == '/' && path[1] == '\0') {
        ramfs_debug_root();
    }

    /* Find the node */
    ramfs_node_t* node = ramfs_find(path);
    if (!node) {
        stream_printf(ctx, "ls: cannot access '%s': No such file or directory\n", path);
        return;
    }

    /* If it's a file, just display that file */
    if (node->type == RAMFS_TYPE_FILE) {
        if (long_format) {
            char perm_str[10];
            ramfs_format_permissions(node->mode, perm_str);

            if (human_readable) {
                char size_str[16];
                format_size_human(node->size, size_str, sizeof(size_str));
                stream_printf(ctx, "-%s %2u:%-2u %6s %s\n",
                        perm_str, node->uid, node->gid, size_str, node->name);
            } else {
                stream_printf(ctx, "-%s %2u:%-2u %8u %s\n",
                        perm_str, node->uid, node->gid, node->size, node->name);
            }
        } else {
            stream_printf(ctx, "%s\n", node->name);
        }
        return;
    }

    /* It's a directory - list its contents */
    ramfs_node_t* child = node->children;
    if (!child) {
        /* Empty directory */
        if (long_format) {
            stream_printf(ctx, "total 0\n");
        }
        return;
    }

    /* Build array of visible entries (filter hidden if needed);
     * never modify the live sibling chain */
    ramfs_node_t* visible[RAMFS_MAX_CHILDREN_PER_DIR];
    int visible_count = 0;

    while (child) {
        /* Skip hidden files (starting with '.') unless -a specified */
        if (!show_all && child->name[0] == '.') {
            child = child->next;
            continue;
        }

        if (visible_count < RAMFS_MAX_CHILDREN_PER_DIR) {
            visible[visible_count++] = child;
        }
        child = child->next;
    }

    if (visible_count == 0) {
        /* No visible entries */
        if (long_format) {
            stream_printf(ctx, "total 0\n");
        }
        return;
    }

    /* Sort the array alphabetically */
    sort_nodes(visible, visible_count, reverse_sort);

    if (long_format) {
        /* Count total blocks (simplified - just count entries) */
        stream_printf(ctx, "total %d\n", visible_count);

        /* Long format listing */
        for (int v = 0; v < visible_count; v++) {
            ramfs_node_t* entry = visible[v];
            char perm_str[10];
            ramfs_format_permissions(entry->mode, perm_str);

            if (entry->type == RAMFS_TYPE_DIR) {
                stream_printf(ctx, "d%s %2u:%-2u %8s %s/\n",
                        perm_str, entry->uid, entry->gid, "-", entry->name);
            } else {
                if (human_readable) {
                    char size_str[16];
                    format_size_human(entry->size, size_str, sizeof(size_str));
                    stream_printf(ctx, "-%s %2u:%-2u %6s %s\n",
                            perm_str, entry->uid, entry->gid, size_str, entry->name);
                } else {
                    stream_printf(ctx, "-%s %2u:%-2u %8u %s\n",
                            perm_str, entry->uid, entry->gid, entry->size, entry->name);
                }
            }
        }
    } else if (single_column) {
        /* Single column format - one entry per line */
        for (int v = 0; v < visible_count; v++) {
            ramfs_node_t* entry = visible[v];
            if (entry->type == RAMFS_TYPE_DIR) {
                stream_printf(ctx, "%s/\n", entry->name);
            } else {
                stream_printf(ctx, "%s\n", entry->name);
            }
        }
    } else {
        /* Multi-column format - 4 columns */
        int count = 0;
        for (int v = 0; v < visible_count; v++) {
            ramfs_node_t* entry = visible[v];
            if (entry->type == RAMFS_TYPE_DIR) {
                stream_printf(ctx, "%-18s/", entry->name);
            } else {
                stream_printf(ctx, "%-19s", entry->name);
            }

            count++;
            if (count % 4 == 0) {
                stream_printf(ctx, "\n");
            }
        }
        if (count % 4 != 0) {
            stream_printf(ctx, "\n");
        }
    }
}

/*=============================================================================
 * COMMAND: cat - Display file contents
 *=============================================================================*/
void cmd_cat(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    bool number_lines = false;
    int file_arg = 1;
    bool use_stdin = false;

    /* Parse flags */
    if (argc >= 2 && strcmp(argv[1], "-n") == 0) {
        number_lines = true;
        file_arg = 2;
    }

    /* If no file argument, read from stdin */
    if (argc < file_arg + 1) {
        use_stdin = true;
    }

    int fd = -1;
    stream_context_t* streams = NULL;
    char target_drive = current_drive;
    const char* filename = NULL;
    char full_path[256];

    if (use_stdin) {
        /* Read from stdin */
        streams = get_current_streams();
        if (!stdin_is_file(streams)) {
            stream_printf(ctx, "cat: reading from keyboard not supported (use files or redirection)\n");
            return;
        }
    } else {
        /* Parse drive letter from filename if present */
        filename = argv[file_arg];
        if ((filename[0] >= 'A' && filename[0] <= 'Z') ||
            (filename[0] >= 'a' && filename[0] <= 'z')) {
            if (filename[1] == ':') {
                target_drive = filename[0];
                if (target_drive >= 'a' && target_drive <= 'z') {
                    target_drive = target_drive - 'a' + 'A';
                }
                filename = filename + 2;  /* Skip drive letter */
            }
        }

        /*=====================================================================
         * CROSS-DRIVE ACCESS FIX: Always use VFS for proper driver routing
         *
         * ISSUE: Previous code called ramfs_open() directly for D: drive,
         * bypassing VFS. This worked when accessing D: files, but failed
         * when accessing D: from C: drive due to inconsistent routing.
         *
         * FIX: Always construct full path with drive letter and use vfs_open().
         * VFS mount table will route to correct driver (FAT32 or RAMFS).
         *
         * Example:
         *   User types: "cat D:/hello/a.txt" from C: drive
         *   Old code: ramfs_open("/hello/a.txt") - bypassed VFS
         *   New code: vfs_open("D:/hello/a.txt") - proper VFS routing
         *===================================================================*/

        /* Construct full path with drive letter for VFS */
        full_path[0] = target_drive;
        full_path[1] = ':';

        /* Handle relative vs absolute paths */
        size_t offset = 2;
        if (filename[0] != '/' && filename[0] != '\\') {
            /* Relative path - prepend current_dir */
            /* Copy current_dir after drive letter */
            size_t j = 0;
            while (current_dir[j] != '\0' && offset < sizeof(full_path) - 1) {
                full_path[offset++] = current_dir[j++];
            }
            /* Add separator if current_dir doesn't end with one */
            if (offset > 2 && full_path[offset - 1] != '/' && full_path[offset - 1] != '\\') {
                full_path[offset++] = '/';
            }
        }

        /* Append filename */
        size_t i = 0;
        while (filename[i] != '\0' && offset < sizeof(full_path) - 1) {
            full_path[offset++] = filename[i++];
        }
        full_path[offset] = '\0';

        /* Always use VFS for unified cross-drive access */
        // kprintf("[CAT DEBUG] current_drive='%c', target_drive='%c', full_path='%s'\n",
        //         current_drive, target_drive, full_path);
        fd = vfs_open(full_path, VFS_O_RDONLY);
        if (fd < 0) {
            stream_printf(ctx, "cat: %s: No such file or directory\n", argv[file_arg]);
            return;
        }
    }

    char buffer[256];
    int bytes_read;
    int line_num = 1;
    bool at_line_start = true;

    while (1) {
        if (use_stdin) {
            bytes_read = stdin_read(streams, buffer, sizeof(buffer) - 1);
        } else {
            /* Always use VFS for file access (routes to FAT32 or RAMFS) */
            bytes_read = vfs_read(fd, buffer, sizeof(buffer) - 1);
            // kprintf("[CAT DEBUG] vfs_read returned %d bytes\n", bytes_read);
        }

        if (bytes_read <= 0) {
            // if (!use_stdin && bytes_read < 0) {
            //     kprintf("[CAT DEBUG] Read error: %d\n", bytes_read);
            // }
            break;  /* EOF or error */
        }

        for (int i = 0; i < bytes_read; i++) {
            if (number_lines && at_line_start) {
                stream_printf(ctx, "%6d  ", line_num++);
                at_line_start = false;
            }
            stream_printf(ctx, "%c", buffer[i]);
            if (buffer[i] == '\n') {
                at_line_start = true;
            }
        }
    }

    /* Add newline if file doesn't end with one */
    if (!at_line_start) {
        stream_printf(ctx, "\n");
    }

    if (!use_stdin && fd >= 0) {
        /* Always use VFS for file close (routes to correct driver) */
        vfs_close(fd);
    }
}

/*=============================================================================
 * COMMAND: mkdir - Create directory
 *=============================================================================*/
static int mkdir_recursive(const char* path) {
    /* Check if already exists */
    if (ramfs_find(path)) {
        return 0;  /* Already exists, that's ok for -p */
    }

    /* Try to create the directory */
    int result = ramfs_mkdir(path);
    if (result == 0 || result == -2) {
        return 0;  /* Success or already exists */
    }

    if (result == -4) {
        /* Parent doesn't exist, need to create it first */
        char parent_path[MAX_PATH];
        const char* last_slash = NULL;

        /* Find the last slash */
        for (const char* p = path; *p; p++) {
            if (*p == '/') {
                last_slash = p;
            }
        }

        if (!last_slash || last_slash == path) {
            return -1;  /* Can't find parent or at root */
        }

        /* Copy parent path */
        size_t parent_len = last_slash - path;
        if (parent_len == 0) {
            parent_path[0] = '/';
            parent_path[1] = '\0';
        } else {
            for (size_t i = 0; i < parent_len && i < sizeof(parent_path) - 1; i++) {
                parent_path[i] = path[i];
            }
            parent_path[parent_len] = '\0';
        }

        /* Recursively create parent */
        if (mkdir_recursive(parent_path) != 0) {
            return -1;
        }

        /* Now try again to create this directory */
        result = ramfs_mkdir(path);
        if (result == 0 || result == -2) {
            return 0;
        }
    }

    return result;
}

void cmd_mkdir(int argc, char* argv[]) {
    if (argc < 2) {
        kprintf("Usage: mkdir [-p] <path>\n");
        kprintf("  -p  Create parent directories as needed\n");
        return;
    }

    bool create_parents = false;
    int path_arg = 1;

    /* Parse flags */
    if (argc >= 3 && strcmp(argv[1], "-p") == 0) {
        create_parents = true;
        path_arg = 2;
    }

    int result;
    if (create_parents) {
        result = mkdir_recursive(argv[path_arg]);
    } else {
        result = ramfs_mkdir(argv[path_arg]);
    }

    if (result == 0) {
        kprintf("mkdir: created directory '%s'\n", argv[path_arg]);
    } else if (result == -2) {
        kprintf("mkdir: cannot create directory '%s': File exists\n", argv[path_arg]);
    } else if (result == -4) {
        kprintf("mkdir: cannot create directory '%s': No such file or directory\n", argv[path_arg]);
        if (!create_parents) {
            kprintf("mkdir: try using -p to create parent directories\n");
        }
    } else {
        kprintf("mkdir: cannot create directory '%s' (error code: %d)\n", argv[path_arg], result);
    }
}

/*=============================================================================
 * HELPER: Resolve relative path to absolute path
 *=============================================================================*/
static const char* resolve_path(const char* path, char* abs_path, size_t abs_path_size) {
    /* If already absolute, check for truncation and use as-is */
    if (path[0] == '/') {
        size_t path_len = strlen(path);
        if (path_len >= abs_path_size) {
            /* Path too long - return NULL to signal error */
            return NULL;
        }
        return path;
    }

    /* Relative path - make it absolute WITH TRUNCATION DETECTION */
    if (strcmp(current_dir, "/") == 0) {
        /* In root, just prepend / */
        if (abs_path_size < 2) {
            return NULL;  /* Buffer too small */
        }
        abs_path[0] = '/';
        size_t path_len = safe_strcpy(&abs_path[1], path, abs_path_size - 1);
        /* Check for truncation: if path_len >= buffer_size-1, it was truncated */
        if (path_len >= abs_path_size - 1) {
            return NULL;  /* Path truncated */
        }
    } else {
        /* Append to current directory - check lengths first */
        size_t cwd_len = strlen(current_dir);
        size_t path_len = strlen(path);
        /* Need: cwd_len + 1 (for /) + path_len + 1 (for \0) */
        if (cwd_len + 1 + path_len + 1 > abs_path_size) {
            return NULL;  /* Would truncate */
        }

        size_t pos = safe_strcpy(abs_path, current_dir, abs_path_size);
        if (pos >= abs_path_size) {
            return NULL;  /* Truncated */
        }
        abs_path[pos++] = '/';
        size_t copied = safe_strcpy(&abs_path[pos], path, abs_path_size - pos);
        if (copied >= abs_path_size - pos) {
            return NULL;  /* Truncated */
        }
    }
    return abs_path;
}

/*=============================================================================
 * FUNCTION: canonicalize_path
 * PURPOSE: Normalize a path to prevent directory traversal attacks
 * SECURITY: This prevents attacks like:
 *   - /../../../etc/passwd
 *   - /foo//bar///baz (multiple slashes)
 *   - /./foo/././bar (dot components)
 *   - /foo/../bar/../../etc (escaping root)
 *=============================================================================*/
int canonicalize_path(const char* path, char* canonical_out, size_t size) {
    if (!path || !canonical_out || size < 2) {
        return -1;
    }

    /* Buffer for absolute path */
    char working_path[MAX_PATH];

    /* Convert relative path to absolute */
    if (path[0] != '/') {
        size_t pos = 0;
        /* Copy current directory */
        if (strcmp(current_dir, "/") != 0) {
            for (size_t i = 0; current_dir[i] != '\0' && pos < MAX_PATH - 1; i++) {
                working_path[pos++] = current_dir[i];
            }
        }
        /* Add separator if needed */
        if (pos == 0 || working_path[pos - 1] != '/') {
            working_path[pos++] = '/';
        }
        /* Append input path */
        for (size_t i = 0; path[i] != '\0' && pos < MAX_PATH - 1; i++) {
            working_path[pos++] = path[i];
        }
        working_path[pos] = '\0';
        path = working_path;
    }

    /* Stack of component start positions in output buffer */
    #define MAX_DEPTH 32
    size_t comp_starts[MAX_DEPTH];
    int depth = 0;

    /* Build canonical path in output buffer */
    size_t out_pos = 0;
    canonical_out[out_pos++] = '/';  /* Always start with root */

    /* Parse input path component by component */
    const char* p = path;
    if (*p == '/') p++;  /* Skip leading slash */

    while (*p != '\0') {
        /* Find end of component */
        const char* comp_start = p;
        while (*p != '\0' && *p != '/') {
            p++;
        }
        size_t comp_len = (size_t)(p - comp_start);

        /* Process component */
        if (comp_len == 0) {
            /* Empty component (from //) - skip */
        } else if (comp_len == 1 && comp_start[0] == '.') {
            /* Current directory "." - skip */
        } else if (comp_len == 2 && comp_start[0] == '.' && comp_start[1] == '.') {
            /* Parent directory ".." - go up one level */
            if (depth > 0) {
                depth--;
                out_pos = comp_starts[depth];
            }
            /* If depth == 0, we're at root, can't go up - stay at root */
        } else {
            /* Normal component - add to path */
            if (depth >= MAX_DEPTH) {
                return -1;  /* Path too deep */
            }

            /* Record start position of this component */
            comp_starts[depth++] = out_pos;

            /* Copy component to output */
            for (size_t i = 0; i < comp_len; i++) {
                if (out_pos >= size - 1) {
                    return -1;  /* Output buffer too small */
                }
                canonical_out[out_pos++] = comp_start[i];
            }

            /* Add trailing slash (will be removed if this is last component) */
            if (out_pos >= size - 1) {
                return -1;
            }
            canonical_out[out_pos++] = '/';
        }

        /* Skip slashes */
        while (*p == '/') {
            p++;
        }
    }

    /* Remove trailing slash (unless we're at root "/") */
    if (out_pos > 1 && canonical_out[out_pos - 1] == '/') {
        out_pos--;
    }

    canonical_out[out_pos] = '\0';

    return 0;
}

/*=============================================================================
 * COMMAND: touch - Create empty file
 *=============================================================================*/
void cmd_touch(int argc, char* argv[]) {
    if (argc < 2) {
        kprintf("Usage: touch <file>\n");
        return;
    }

    char abs_path[MAX_PATH];
    const char* path = resolve_path(argv[1], abs_path, sizeof(abs_path));

    /*=========================================================================
     * SECURITY FIX (Issue 7.1): Path Resolution Buffer Overflow Protection
     *
     * CRITICAL: Check for path truncation before operating on file. If
     * resolve_path() returns NULL, the path exceeded MAX_PATH and was
     * truncated. Operating on a truncated path could affect the wrong file!
     *
     * EXAMPLE BUG:
     *   User: touch /very/long/path/to/some/file/that/exceeds/buffer/important.txt
     *   Truncated to: /very/long/path/to/some/file/that/exceeds/bu
     *   Result: Creates wrong file with corrupted name!
     *
     * FIX: Reject operation if path is too long.
     *=======================================================================*/
    if (!path) {
        kprintf("touch: path too long (would be truncated) - refusing to operate\n");
        kprintf("touch: this prevents accidentally creating a file with wrong name\n");
        return;
    }

    int fd = ramfs_open(path, RAMFS_FLAG_WRITE);
    if (fd < 0) {
        kprintf("Error: Cannot create file '%s'\n", path);
        return;
    }

    ramfs_close(fd);
    kprintf("File created: %s\n", path);
}

/*=============================================================================
 * COMMAND: write - Write text to file
 *=============================================================================*/
void cmd_write(int argc, char* argv[]) {
    if (argc < 3) {
        kprintf("Usage: write <file> <text>\n");
        return;
    }

    char abs_path[MAX_PATH];
    const char* path = resolve_path(argv[1], abs_path, sizeof(abs_path));

    /* SECURITY: Check for path truncation - fail-safe for destructive operations */
    if (!path) {
        kprintf("write: path too long (would be truncated) - refusing to operate\n");
        kprintf("write: this prevents accidentally writing to wrong file\n");
        return;
    }

    int fd = ramfs_open(path, RAMFS_FLAG_WRITE);
    if (fd < 0) {
        kprintf("Error: Cannot open file '%s'\n", path);
        return;
    }

    /* Write all remaining arguments as text */
    for (int i = 2; i < argc; i++) {
        int len = strlen(argv[i]);
        int written = ramfs_write(fd, argv[i], len);
        if (written < 0) {
            kprintf("Error: Write failed\n");
            ramfs_close(fd);
            return;
        }
        /* Add space between arguments except for last one */
        if (i < argc - 1) {
            ramfs_write(fd, " ", 1);
        }
    }

    ramfs_close(fd);
    kprintf("Written to %s\n", path);
}

/*=============================================================================
 * COMMAND: rm - Remove file or directory
 *=============================================================================*/
static int rm_recursive(const char* path) {
    ramfs_node_t* node = ramfs_find(path);
    if (!node) {
        return -1;
    }

    if (node->type == RAMFS_TYPE_FILE) {
        /* Remove file */
        return ramfs_unlink(path);
    } else {
        /* Directory - recursively remove all children first */
        ramfs_node_t* child = node->children;
        while (child) {
            /* Build child path */
            char child_path[MAX_PATH];
            int pos = 0;

            /* Copy parent path */
            for (const char* p = path; *p && pos < 255; p++) {
                child_path[pos++] = *p;
            }

            /* Add slash if needed */
            if (pos > 0 && child_path[pos - 1] != '/') {
                child_path[pos++] = '/';
            }

            /* Add child name */
            for (const char* p = child->name; *p && pos < 255; p++) {
                child_path[pos++] = *p;
            }
            child_path[pos] = '\0';

            /* Save next sibling before removing current child */
            ramfs_node_t* next = child->next;

            /* Recursively remove child */
            int result = rm_recursive(child_path);
            if (result != 0) {
                return result;
            }

            child = next;
        }

        /* Now remove the empty directory */
        return ramfs_rmdir(path);
    }
}

void cmd_rm(int argc, char* argv[]) {
    if (argc < 2) {
        kprintf("Usage: rm [-r] <file|directory>\n");
        kprintf("  -r  Remove directories and their contents recursively\n");
        return;
    }

    bool recursive = false;
    int path_arg = 1;

    /* Parse flags */
    if (argc >= 3 && (strcmp(argv[1], "-r") == 0 || strcmp(argv[1], "-R") == 0)) {
        recursive = true;
        path_arg = 2;
    }

    char abs_path[MAX_PATH];
    const char* path = resolve_path(argv[path_arg], abs_path, sizeof(abs_path));

    /* SECURITY: Check for path truncation - fail-safe for destructive operations */
    if (!path) {
        kprintf("rm: path too long (would be truncated) - refusing to operate\n");
        kprintf("rm: this prevents accidentally deleting the wrong file\n");
        return;
    }

    /* Check if target exists and what type it is */
    ramfs_node_t* node = ramfs_find(path);
    if (!node) {
        kprintf("rm: cannot remove '%s': No such file or directory\n", path);
        return;
    }

    int result;
    if (node->type == RAMFS_TYPE_FILE) {
        /* Remove file */
        result = ramfs_unlink(path);
        if (result == 0) {
            kprintf("rm: removed '%s'\n", path);
        } else if (result == -4) {
            kprintf("rm: cannot remove '%s': Permission denied\n", path);
        } else {
            kprintf("rm: cannot remove '%s' (error code: %d)\n", path, result);
        }
    } else {
        /* Remove directory */
        if (recursive) {
            result = rm_recursive(path);
            if (result == 0) {
                kprintf("rm: removed directory '%s'\n", path);
            } else if (result == -5) {
                kprintf("rm: cannot remove '%s': Permission denied\n", path);
            } else {
                kprintf("rm: cannot remove '%s' (error code: %d)\n", path, result);
            }
        } else {
            result = ramfs_rmdir(path);
            if (result == 0) {
                kprintf("rm: removed directory '%s'\n", path);
            } else if (result == -3) {
                kprintf("rm: cannot remove '%s': Directory not empty\n", path);
                kprintf("rm: use 'rm -r' to remove directory and its contents\n");
            } else if (result == -5) {
                kprintf("rm: cannot remove '%s': Permission denied\n", path);
            } else {
                kprintf("rm: cannot remove '%s' (error code: %d)\n", path, result);
            }
        }
    }
}

/*=============================================================================
 * COMMAND: exec - Execute ELF binary
 *=============================================================================*/
#define EXEC_BUFFER_SIZE 16384  // 16KB buffer for ELF files
#define EXEC_MAX_FILE_SIZE 65536  // 64KB maximum ELF size (DoS prevention)

void cmd_exec(int argc, char* argv[]) {
    if (argc < 2) {
        kprintf("Usage: exec <file>\n");
        return;
    }

    const char* path = argv[1];
    char abs_path[MAX_PATH];

    /*
     * Static (not stack) buffer: cmd_exec runs on the shell's 64KB task
     * kernel stack, and the ELF verify path (SHA-256 + ECDSA) is deep. A
     * 16KB stack buffer here previously overflowed the task stack and
     * silently corrupted the signature hash computation. cmd_exec is only
     * invoked from the single-threaded shell, so a static buffer is safe.
     */
    static uint8_t exec_buffer[EXEC_BUFFER_SIZE];

    /* Build absolute path if needed */
    if (path[0] != '/') {
        /* Relative path - make it absolute */
        if (strcmp(current_dir, "/") == 0) {
            /* In root, just prepend / */
            abs_path[0] = '/';
            size_t i;
            for (i = 0; path[i] != '\0' && i < sizeof(abs_path) - 2; i++) {
                abs_path[i + 1] = path[i];
            }
            abs_path[i + 1] = '\0';
        } else {
            /* Append to current directory */
            size_t pos = 0;
            for (size_t i = 0; current_dir[i] != '\0' && pos < sizeof(abs_path) - 1; i++) {
                abs_path[pos++] = current_dir[i];
            }
            abs_path[pos++] = '/';
            for (size_t i = 0; path[i] != '\0' && pos < sizeof(abs_path) - 1; i++) {
                abs_path[pos++] = path[i];
            }
            abs_path[pos] = '\0';
        }
        path = abs_path;
    }

    kprintf("[EXEC] Loading '%s'...\n", path);

    // Open the file for reading
    int fd = ramfs_open(path, RAMFS_FLAG_READ);
    if (fd < 0) {
        kprintf("[EXEC] ERROR: Cannot open file '%s'\n", path);
        return;
    }

    // Get file size by reading the file node
    ramfs_node_t* node = ramfs_find(path);
    if (!node || node->type != RAMFS_TYPE_FILE) {
        kprintf("[EXEC] ERROR: '%s' is not a file\n", path);
        ramfs_close(fd);
        return;
    }

    uint32_t file_size = node->size;
    kprintf("[EXEC] File size: %u bytes\n", file_size);

    /* SECURITY FIX: DoS prevention - check file size limits BEFORE allocating/reading
     * This prevents malicious large files from consuming resources
     */
    if (file_size == 0) {
        kprintf("[EXEC] ERROR: File is empty\n");
        ramfs_close(fd);
        return;
    }

    if (file_size > EXEC_MAX_FILE_SIZE) {
        kprintf("[EXEC] ERROR: File too large (max %u bytes for security)\n", EXEC_MAX_FILE_SIZE);
        ramfs_close(fd);
        return;
    }

    if (file_size > EXEC_BUFFER_SIZE) {
        kprintf("[EXEC] ERROR: File exceeds buffer size (max %d bytes)\n", EXEC_BUFFER_SIZE);
        ramfs_close(fd);
        return;
    }

    // Read file contents into local buffer
    int bytes_read = ramfs_read(fd, exec_buffer, file_size);
    ramfs_close(fd);

    if (bytes_read != (int)file_size) {
        kprintf("[EXEC] ERROR: Failed to read file (read %d/%u bytes)\n",
                bytes_read, file_size);
        return;
    }

    kprintf("[EXEC] File loaded successfully\n");
    // Load ELF and create process
    int pid = elf_load_process(exec_buffer, file_size, node->name);

    if (pid < 0) {
        kprintf("[EXEC] ERROR: Failed to load ELF executable\n");
        return;
    }

    kprintf("[EXEC] Process created with PID=%d\n", pid);

    // Add to scheduler
    task_t* task = task_get(pid);
    if (task) {
        scheduler_add_task(task);
        kprintf("[EXEC] Process added to scheduler\n");

        // Wait for child process to terminate
        kprintf("[EXEC] Waiting for process to complete...\n");
        while (1) {
            task_t* child = task_get(pid);
            if (!child || child->state == TASK_STATE_TERMINATED) {
                break;  // Child has finished
            }
            scheduler_yield();  // Give other tasks a chance to run
        }

        /*
         * CRITICAL: Reap the zombie process
         * After the child terminates, we must remove it from the scheduler's
         * ready queue to allow the scheduler to clean up its resources.
         * Without this, terminated tasks accumulate and leak memory.
         *
         * SECURITY FIX: Protect scheduler_remove_task with critical section
         * This operation modifies critical kernel data structures (scheduler's
         * ready queue, task list). If a timer interrupt fires during this
         * operation, it could cause list corruption, double-free, or system crash.
         */
        task_t* terminated_child = task_get(pid);
        if (terminated_child && terminated_child->state == TASK_STATE_TERMINATED) {
            kprintf("[EXEC] Reaping zombie process PID=%d\n", pid);
            CRITICAL_SECTION_ENTER();  /* Protect scheduler state modification */
            scheduler_remove_task(terminated_child);
            CRITICAL_SECTION_EXIT();
        }

        kprintf("[EXEC] Process completed\n");
    } else {
        kprintf("[EXEC] WARNING: Could not find task to add to scheduler\n");
    }
}

/*=============================================================================
 * COMMAND: edit - Text editor
 * WARNING: Stack Overflow Risk
 *
 * The editor runs within the shell task's stack. If editor_run() has deep
 * call stacks (complex editing operations, screen redraws, file I/O), it can
 * overflow the kernel stack. Current shell stack is 256KB (KERNEL_BOOT_STACK_SIZE)
 * which should be sufficient, but for production systems:
 *
 * RECOMMENDATION: Run editor as a separate task/process with its own large stack,
 * or ensure shell task stack is adequately sized and protected with guard pages.
 *=============================================================================*/
void cmd_edit(int argc, char** argv) {
    if (argc < 2) {
        kprintf("Usage: edit <file>\n");
        return;
    }

    char abs_path[MAX_PATH];
    const char* path = resolve_path(argv[1], abs_path, sizeof(abs_path));

    /*=========================================================================
     * SECURITY FIX (Issue 7.1): Path Resolution Buffer Overflow Protection
     *=======================================================================*/
    if (!path) {
        kprintf("edit: path too long (exceeds MAX_PATH=%d characters)\n", MAX_PATH);
        return;
    }

    /* Initialize and run editor */
    editor_init();
    editor_open(path);
    editor_run();
    editor_cleanup();

    /* Restore screen after editor exits */
    console_clear();
    kprintf("Exited editor\n");
}

/*=============================================================================
 * COMMAND: mount - Show mounted drives (dynamically queries VFS)
 *=============================================================================*/
static void mount_callback(char drive_letter, const char* driver_name, void* user_data) {
    (void)user_data;
    kprintf("  %c:  %-8s\n", drive_letter, driver_name);
}

void cmd_mount(int argc, char** argv) {
    (void)argc;
    (void)argv;

    kprintf("Mounted drives:\n");
    vfs_foreach_mount(mount_callback, NULL);
}

/*=============================================================================
 * COMMAND: fatls - List FAT32 root directory (Phase 1: Basic C: access)
 *=============================================================================*/
/* Emit one FAT32 entry to the shell stream (so `ls C:` output actually reaches
 * the user's terminal — the old kprintf-only path went to the kernel console
 * and looked "empty" in the shell). */
static void fatls_stream_emit(void* ctx, const char* name, uint32_t size, bool is_dir) {
    stream_printf((stream_context_t*)ctx, "  %-4s %-12s %u bytes\n",
                  is_dir ? "DIR" : "FILE", name, size);
}

void cmd_fatls(int argc, char** argv) {
    (void)argc;
    (void)argv;

    stream_context_t* ctx = get_current_streams();
    stream_printf(ctx, "Contents of C: drive (FAT32):\n");
    if (fat32_list_root_cb(fatls_stream_emit, ctx) != 0) {
        stream_printf(ctx, "ls: cannot read C: (FAT32 not mounted or read error)\n");
    }
}
