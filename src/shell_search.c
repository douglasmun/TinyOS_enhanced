/*=============================================================================
 * shell_search.c - Shell Search & Filter Implementation
 *=============================================================================*/
#include "shell_search.h"
#include "ramfs.h"
#include "kprintf.h"
#include "util.h"
#include "stdio.h"
#include <stddef.h>

#define SEARCH_BUFFER_SIZE 4096
#define MAX_LINE_LENGTH 1024

/*=============================================================================
 * HELPER: Simple string matching (no regex yet)
 *=============================================================================*/
static bool simple_match(const char* text, const char* pattern) {
    size_t text_len = strlen(text);
    size_t pattern_len = strlen(pattern);

    if (pattern_len == 0) return true;
    if (pattern_len > text_len) return false;

    // Simple substring search
    for (size_t i = 0; i <= text_len - pattern_len; i++) {
        bool match = true;
        for (size_t j = 0; j < pattern_len; j++) {
            if (text[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

/*=============================================================================
 * HELPER: Check if filename matches pattern (supports * wildcard)
 * DoS Protection: Limited iteration count to prevent ReDoS attacks
 *=============================================================================*/
static bool wildcard_match(const char* text, const char* pattern) {
    /*
     * Security: Limit pattern matching iterations to prevent DoS.
     * With pathological patterns like "a*a*a*a*b" against "aaaaaaaaac",
     * unlimited backtracking can cause exponential time complexity.
     * This limit ensures O(n) worst-case behavior.
     */
    #define MAX_PATTERN_ITERATIONS 10000

    const char* t = text;
    const char* p = pattern;
    const char* star = NULL;
    const char* t_backup = NULL;
    int iterations = 0;

    while (*t) {
        /* Safety check: prevent infinite loops from malicious patterns */
        if (++iterations > MAX_PATTERN_ITERATIONS) {
            return false;  /* Pattern too complex, reject match */
        }

        if (*p == '*') {
            star = p++;
            t_backup = t;
        } else if (*p == *t || *p == '?') {
            p++;
            t++;
        } else if (star) {
            p = star + 1;
            t = ++t_backup;
        } else {
            return false;
        }
    }

    while (*p == '*') p++;
    return *p == '\0';

    #undef MAX_PATTERN_ITERATIONS
}

/*=============================================================================
 * COMMAND: grep - Search for pattern in file(s)
 *=============================================================================*/
void cmd_grep(int argc, char** argv) {
    stream_context_t* ctx = get_current_streams();
    if (argc < 2) {
        stream_printf(ctx, "Usage: grep <pattern> [file...]\n");
        stream_printf(ctx, "       grep <pattern>           (searches all files in /)\n");
        return;
    }

    const char* pattern = argv[1];
    /* Use local buffers for thread safety */
    uint8_t buffer[SEARCH_BUFFER_SIZE];
    char line[MAX_LINE_LENGTH];

    // Determine which files to search
    if (argc == 2) {
        // No files specified, search all files in root
        stream_printf(ctx, "grep: Searching all files for '%s'...\n", pattern);

        ramfs_node_t* root = ramfs_get_root();
        if (!root) {
            stream_printf(ctx, "grep: Cannot access root directory\n");
            return;
        }

        // Iterate through all files in root
        ramfs_node_t* current = root->children;
        bool found_any = false;

        while (current) {
            if (current->type == RAMFS_TYPE_FILE) {
                /*=============================================================
                 * SECURITY FIX (v1.18): Use NOFOLLOW to prevent TOCTOU attacks
                 *
                 * Without NOFOLLOW, attacker could:
                 *   1. Create regular file /tmp/data.txt
                 *   2. User runs: grep "pattern" /tmp/data.txt
                 *   3. Attacker replaces with symlink /tmp/data.txt -> /etc/shadow
                 *   4. grep opens and reads /etc/shadow (TOCTOU race!)
                 *
                 * With RAMFS_FLAG_NOFOLLOW, the open will atomically reject
                 * symlinks, preventing the attack.
                 *===========================================================*/
                int fd = ramfs_open(current->name, RAMFS_FLAG_READ | RAMFS_FLAG_NOFOLLOW);
                if (fd < 0) {
                    current = current->next;
                    continue;
                }

                // Read file (reserve 1 byte for null terminator)
                size_t to_read = current->size < (SEARCH_BUFFER_SIZE - 1) ?
                                 current->size : (SEARCH_BUFFER_SIZE - 1);
                int bytes_read = ramfs_read(fd, buffer, to_read);
                ramfs_close(fd);

                if (bytes_read > 0) {
                    /* SECURITY: Safe null termination - buffer[SEARCH_BUFFER_SIZE-1] max */
                    buffer[bytes_read] = '\0';

                    /* SECURITY NOTE: Only first 4095 bytes scanned */
                    if (current->size > (SEARCH_BUFFER_SIZE - 1)) {
                        stream_printf(ctx, "grep: %s: WARNING: Only first %d bytes scanned\n",
                                     current->name, SEARCH_BUFFER_SIZE - 1);
                    }

                    // Search line by line
                    size_t line_start = 0;
                    int line_num = 1;

                    for (int i = 0; i <= bytes_read; i++) {
                        if (i == bytes_read || buffer[i] == '\n') {
                            size_t line_len = i - line_start;
                            if (line_len > 0) {
                                /* Truncate long lines to MAX_LINE_LENGTH - 1 */
                                size_t copy_len = (line_len < MAX_LINE_LENGTH - 1) ?
                                                 line_len : MAX_LINE_LENGTH - 1;
                                memcpy(line, &buffer[line_start], copy_len);
                                line[copy_len] = '\0';

                                if (simple_match(line, pattern)) {
                                    stream_printf(ctx, "%s:%d:%s", current->name, line_num, line);
                                    if (line_len >= MAX_LINE_LENGTH - 1) {
                                        stream_printf(ctx, "... [line truncated]");
                                    }
                                    stream_printf(ctx, "\n");
                                    found_any = true;
                                }
                            }
                            line_start = i + 1;
                            line_num++;
                        }
                    }
                }
            }
            current = current->next;
        }

        if (!found_any) {
            stream_printf(ctx, "grep: No matches found for '%s'\n", pattern);
        }
    } else {
        // Search specified files
        for (int f = 2; f < argc; f++) {
            const char* filepath = argv[f];
            ramfs_node_t* node = ramfs_find(filepath);

            if (!node) {
                stream_printf(ctx, "grep: %s: No such file\n", filepath);
                continue;
            }

            if (node->type != RAMFS_TYPE_FILE) {
                stream_printf(ctx, "grep: %s: Not a regular file\n", filepath);
                continue;
            }

            /*=================================================================
             * SECURITY FIX (v1.18): Use NOFOLLOW to prevent TOCTOU attacks
             *
             * Same TOCTOU protection as above: prevent symlink race conditions
             * by rejecting symlinks atomically at open time.
             *===============================================================*/
            int fd = ramfs_open(filepath, RAMFS_FLAG_READ | RAMFS_FLAG_NOFOLLOW);
            if (fd < 0) {
                stream_printf(ctx, "grep: %s: Cannot open file\n", filepath);
                continue;
            }

            // Read file (reserve 1 byte for null terminator)
            size_t to_read = node->size < (SEARCH_BUFFER_SIZE - 1) ?
                             node->size : (SEARCH_BUFFER_SIZE - 1);
            int bytes_read = ramfs_read(fd, buffer, to_read);
            ramfs_close(fd);

            if (bytes_read <= 0) {
                continue;
            }

            /* SECURITY: Safe null termination - buffer[SEARCH_BUFFER_SIZE-1] max */
            buffer[bytes_read] = '\0';

            /* SECURITY NOTE: Only first 4095 bytes scanned */
            if (node->size > (SEARCH_BUFFER_SIZE - 1)) {
                stream_printf(ctx, "grep: %s: WARNING: Only first %d bytes scanned\n",
                             filepath, SEARCH_BUFFER_SIZE - 1);
            }

            // Search line by line
            size_t line_start = 0;
            int line_num = 1;
            bool found = false;

            for (int i = 0; i <= bytes_read; i++) {
                if (i == bytes_read || buffer[i] == '\n') {
                    size_t line_len = i - line_start;
                    if (line_len > 0) {
                        /* Truncate long lines to MAX_LINE_LENGTH - 1 */
                        size_t copy_len = (line_len < MAX_LINE_LENGTH - 1) ?
                                         line_len : MAX_LINE_LENGTH - 1;
                        memcpy(line, &buffer[line_start], copy_len);
                        line[copy_len] = '\0';

                        if (simple_match(line, pattern)) {
                            if (argc > 3) {
                                // Multiple files - show filename
                                stream_printf(ctx, "%s:%d:%s", filepath, line_num, line);
                            } else {
                                // Single file - just line number
                                stream_printf(ctx, "%d:%s", line_num, line);
                            }
                            if (line_len >= MAX_LINE_LENGTH - 1) {
                                stream_printf(ctx, "... [line truncated]");
                            }
                            stream_printf(ctx, "\n");
                            found = true;
                        }
                    }
                    line_start = i + 1;
                    line_num++;
                }
            }

            if (!found) {
                stream_printf(ctx, "grep: %s: No matches found\n", filepath);
            }
        }
    }
}

/*=============================================================================
 * COMMAND: find - Find files by name pattern
 *=============================================================================*/
void cmd_find(int argc, char** argv) {
    const char* start_dir = "/";
    const char* pattern = "*";

    if (argc == 1) {
        // No arguments - find all files in /
        kprintf("Usage: find [directory] [pattern]\n");
        kprintf("       find              (lists all files in /)\n");
        kprintf("       find <pattern>    (finds files matching pattern)\n");
        kprintf("       find / <pattern>  (finds files in / matching pattern)\n");
        kprintf("\nPattern supports * wildcard (e.g., *.txt, test*)\n\n");
    }

    if (argc >= 2) {
        // Check if first arg looks like a directory or pattern
        if (argv[1][0] == '/' || strcmp(argv[1], ".") == 0) {
            start_dir = argv[1];
            if (argc >= 3) {
                pattern = argv[2];
            }
        } else {
            pattern = argv[1];
        }
    }

    // For now, only support searching in root directory
    if (strcmp(start_dir, "/") != 0 && strcmp(start_dir, ".") != 0) {
        kprintf("find: Only root directory (/) search is supported\n");
        return;
    }

    ramfs_node_t* root = ramfs_get_root();
    if (!root) {
        kprintf("find: Cannot access root directory\n");
        return;
    }

    kprintf("Searching for: %s\n", pattern);

    ramfs_node_t* current = root->children;
    int count = 0;

    while (current) {
        if (wildcard_match(current->name, pattern)) {
            const char* type_str = (current->type == RAMFS_TYPE_FILE) ? "file" : "dir";
            kprintf("./%s  (%s, %u bytes)\n",
                    current->name, type_str, current->size);
            count++;
        }
        current = current->next;
    }

    if (count == 0) {
        kprintf("find: No files matching '%s'\n", pattern);
    } else {
        kprintf("\nFound %d matching item(s)\n", count);
    }
}
