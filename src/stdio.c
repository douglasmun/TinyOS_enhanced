/*=============================================================================
 * stdio.c - Standard I/O Streams Implementation
 *=============================================================================*/
#include "stdio.h"
#include "process.h"
#include "ramfs.h"
#include "kprintf.h"
#include "keyboard.h"
#include "util.h"
#include "scheduler.h"

/*=============================================================================
 * SECURITY FIX: Per-Process Stream Contexts
 *
 * Previously used a single global stream context, which caused:
 * - I/O corruption when multiple processes redirect output
 * - Data leakage between processes
 * - Race conditions in multi-tasking
 *
 * Now each process has its own stream context stored in its task structure.
 *=============================================================================*/

/*=============================================================================
 * Stream Management
 *=============================================================================*/

void streams_init(stream_context_t* ctx) {
    if (!ctx) {
        return;
    }

    /* Initialize stdin to console (keyboard) */
    ctx->stdin_stream.type = STREAM_TYPE_CONSOLE;
    ctx->stdin_stream.fd = -1;
    ctx->stdin_stream.data = NULL;
    ctx->stdin_stream.is_open = true;

    /* Initialize stdout to console (VGA) */
    ctx->stdout_stream.type = STREAM_TYPE_CONSOLE;
    ctx->stdout_stream.fd = -1;
    ctx->stdout_stream.data = NULL;
    ctx->stdout_stream.is_open = true;

    /* Initialize stderr to console (VGA) */
    ctx->stderr_stream.type = STREAM_TYPE_CONSOLE;
    ctx->stderr_stream.fd = -1;
    ctx->stderr_stream.data = NULL;
    ctx->stderr_stream.is_open = true;
}

int stdin_redirect_from_file(stream_context_t* ctx, const char* filename) {
    if (!ctx || !filename) {
        return -1;
    }

    /* SECURITY FIX: Close previous stdin file descriptor to prevent FD leak
     * If a script repeatedly redirects input without cleanup, unclosed FDs
     * accumulate and exhaust the kernel's limited FD pool (DoS).
     *
     * SECURITY FIX: Defensive FD bounds checking (defense-in-depth)
     * While RAMFS validates FDs internally, stdio should defensively check
     * bounds BEFORE passing to ramfs. If FD is corrupted (bug or exploit),
     * out-of-bounds array access could occur in ramfs.
     */
    if (ctx->stdin_stream.is_open &&
        ctx->stdin_stream.type == STREAM_TYPE_FILE &&
        ctx->stdin_stream.fd >= 0 &&
        ctx->stdin_stream.fd < RAMFS_MAX_FDS) {
        ramfs_close(ctx->stdin_stream.fd);
        ctx->stdin_stream.fd = -1;  /* Mark as closed */
    }

    /*=========================================================================
     * SECURITY (v1.12): Use RAMFS_FLAG_NOFOLLOW for Input Redirection
     *
     * TOCTOU DEFENSE: Prevent symlink attacks on stdin redirection.
     * Attack: cmd < /tmp/input where attacker can replace /tmp/input with
     * symlink to /etc/shadow before open.
     *=======================================================================*/
    int fd = ramfs_open(filename, RAMFS_FLAG_READ | RAMFS_FLAG_NOFOLLOW);
    if (fd < 0) {
        /* SECURITY FIX: Restore stdin to console on error
         * If we closed the previous stdin FD but failed to open new file,
         * stdin is now broken. Restore to console for safety.
         */
        ctx->stdin_stream.type = STREAM_TYPE_CONSOLE;
        ctx->stdin_stream.fd = -1;
        ctx->stdin_stream.is_open = true;
        return -1;  /* File doesn't exist or can't be opened */
    }

    /* Set stdin to file */
    ctx->stdin_stream.type = STREAM_TYPE_FILE;
    ctx->stdin_stream.fd = fd;
    ctx->stdin_stream.data = NULL;
    ctx->stdin_stream.is_open = true;

    return 0;
}

int stdout_redirect_to_file(stream_context_t* ctx, const char* filename, bool append) {
    if (!ctx || !filename) {
        return -1;
    }

    /* SECURITY FIX: Close previous stdout file descriptor to prevent FD leak
     * SECURITY FIX: Defensive FD bounds checking (defense-in-depth)
     */
    if (ctx->stdout_stream.is_open &&
        ctx->stdout_stream.type == STREAM_TYPE_FILE &&
        ctx->stdout_stream.fd >= 0 &&
        ctx->stdout_stream.fd < RAMFS_MAX_FDS) {
        ramfs_close(ctx->stdout_stream.fd);
        ctx->stdout_stream.fd = -1;  /* Mark as closed */
    }

    /*=========================================================================
     * SECURITY (v1.12): Use RAMFS_FLAG_NOFOLLOW for Output Redirection
     *
     * TOCTOU DEFENSE: Prevent symlink attacks on stdout redirection.
     *=======================================================================*/
    int fd = ramfs_open(filename, RAMFS_FLAG_WRITE | RAMFS_FLAG_NOFOLLOW);
    if (fd < 0) {
        /* File doesn't exist, try to create it */
        /* Note: RAMFS doesn't have a create-specific flag,
         * so we'd need to use touch or similar */

        /* SECURITY FIX: Restore stdout to console on error
         * If we closed the previous stdout FD but failed to open new file,
         * stdout is now broken. Restore to console so user can still see output.
         * Without this, user's stdout is broken until manually restored.
         */
        ctx->stdout_stream.type = STREAM_TYPE_CONSOLE;
        ctx->stdout_stream.fd = -1;
        ctx->stdout_stream.is_open = true;
        return -1;
    }

    /* TODO: If append mode, seek to end of file */
    (void)append;  /* Suppress unused warning for now */

    /* Set stdout to file */
    ctx->stdout_stream.type = STREAM_TYPE_FILE;
    ctx->stdout_stream.fd = fd;
    ctx->stdout_stream.data = NULL;
    ctx->stdout_stream.is_open = true;

    return 0;
}

void stdin_reset(stream_context_t* ctx) {
    if (!ctx) {
        return;
    }

    /* Close file descriptor if open
     * SECURITY FIX: Defensive FD bounds checking
     */
    if (ctx->stdin_stream.type == STREAM_TYPE_FILE &&
        ctx->stdin_stream.fd >= 0 &&
        ctx->stdin_stream.fd < RAMFS_MAX_FDS) {
        ramfs_close(ctx->stdin_stream.fd);
    }

    /* Reset to console */
    ctx->stdin_stream.type = STREAM_TYPE_CONSOLE;
    ctx->stdin_stream.fd = -1;
    ctx->stdin_stream.data = NULL;
    ctx->stdin_stream.is_open = true;
}

void stdout_reset(stream_context_t* ctx) {
    if (!ctx) {
        return;
    }

    /* Close file descriptor if open
     * SECURITY FIX: Defensive FD bounds checking
     */
    if (ctx->stdout_stream.type == STREAM_TYPE_FILE &&
        ctx->stdout_stream.fd >= 0 &&
        ctx->stdout_stream.fd < RAMFS_MAX_FDS) {
        ramfs_close(ctx->stdout_stream.fd);
    }

    /* Reset to console */
    ctx->stdout_stream.type = STREAM_TYPE_CONSOLE;
    ctx->stdout_stream.fd = -1;
    ctx->stdout_stream.data = NULL;
    ctx->stdout_stream.is_open = true;
}

void stderr_reset(stream_context_t* ctx) {
    if (!ctx) {
        return;
    }

    /* stderr typically stays on console, but support redirection
     * SECURITY FIX: Defensive FD bounds checking
     */
    if (ctx->stderr_stream.type == STREAM_TYPE_FILE &&
        ctx->stderr_stream.fd >= 0 &&
        ctx->stderr_stream.fd < RAMFS_MAX_FDS) {
        ramfs_close(ctx->stderr_stream.fd);
    }

    /* Reset to console */
    ctx->stderr_stream.type = STREAM_TYPE_CONSOLE;
    ctx->stderr_stream.fd = -1;
    ctx->stderr_stream.data = NULL;
    ctx->stderr_stream.is_open = true;
}

void streams_cleanup(stream_context_t* ctx) {
    if (!ctx) {
        return;
    }

    stdin_reset(ctx);
    stdout_reset(ctx);
    stderr_reset(ctx);
}

/*=============================================================================
 * Stream I/O Operations
 *=============================================================================*/

int stdin_read(stream_context_t* ctx, char* buffer, size_t size) {
    if (!ctx || !buffer || size == 0) {
        return -1;
    }

    if (!ctx->stdin_stream.is_open) {
        return -1;
    }

    switch (ctx->stdin_stream.type) {
        case STREAM_TYPE_FILE:
            /* Read from file
             * SECURITY FIX: Defensive FD bounds checking
             */
            if (ctx->stdin_stream.fd >= 0 && ctx->stdin_stream.fd < RAMFS_MAX_FDS) {
                return ramfs_read(ctx->stdin_stream.fd, buffer, size);
            }
            return -1;

        case STREAM_TYPE_PIPE:
            /* TODO: Read from pipe buffer */
            return -1;

        case STREAM_TYPE_CONSOLE:
            /* Read from keyboard - not implemented for raw reads */
            /* This would require keyboard buffer implementation */
            return -1;

        case STREAM_TYPE_NULL:
            /* Reading from /dev/null returns EOF */
            return 0;

        default:
            return -1;
    }
}

int stdin_getline(stream_context_t* ctx, char* buffer, size_t size) {
    if (!ctx || !buffer || size == 0) {
        return -1;
    }

    if (!ctx->stdin_stream.is_open) {
        return -1;
    }

    switch (ctx->stdin_stream.type) {
        case STREAM_TYPE_FILE: {
            /* Read line from file
             * SECURITY FIX: Defensive FD bounds checking
             */
            if (ctx->stdin_stream.fd < 0 || ctx->stdin_stream.fd >= RAMFS_MAX_FDS) {
                return -1;
            }

            size_t pos = 0;
            char c;
            while (pos < size - 1) {
                int n = ramfs_read(ctx->stdin_stream.fd, &c, 1);
                if (n <= 0) {
                    /* EOF or error */
                    break;
                }

                buffer[pos++] = c;
                if (c == '\n') {
                    break;
                }
            }

            buffer[pos] = '\0';
            return (int)pos;
        }

        case STREAM_TYPE_PIPE:
            /* TODO: Read line from pipe buffer */
            return -1;

        case STREAM_TYPE_CONSOLE:
            /* Reading line from keyboard not implemented here */
            /* This is handled by shell's interactive input */
            return -1;

        case STREAM_TYPE_NULL:
            /* Reading from /dev/null returns EOF */
            return 0;

        default:
            return -1;
    }
}

int stdout_write(stream_context_t* ctx, const char* data, size_t size) {
    if (!ctx || !data || size == 0) {
        return -1;
    }

    if (!ctx->stdout_stream.is_open) {
        return -1;
    }

    switch (ctx->stdout_stream.type) {
        case STREAM_TYPE_FILE:
            /* Write to file
             * SECURITY FIX: Defensive FD bounds checking
             */
            if (ctx->stdout_stream.fd >= 0 && ctx->stdout_stream.fd < RAMFS_MAX_FDS) {
                return ramfs_write(ctx->stdout_stream.fd, data, size);
            }
            return -1;

        case STREAM_TYPE_PIPE:
            /* TODO: Write to pipe buffer */
            return -1;

        case STREAM_TYPE_CONSOLE:
            /* Write to console using kprintf */
            for (size_t i = 0; i < size; i++) {
                kprintf("%c", data[i]);
            }
            return (int)size;

        case STREAM_TYPE_NULL:
            /* Writing to /dev/null succeeds but does nothing */
            return (int)size;

        default:
            return -1;
    }
}

int stderr_write(stream_context_t* ctx, const char* data, size_t size) {
    if (!ctx || !data || size == 0) {
        return -1;
    }

    if (!ctx->stderr_stream.is_open) {
        return -1;
    }

    switch (ctx->stderr_stream.type) {
        case STREAM_TYPE_FILE:
            /* Write to file
             * SECURITY FIX: Defensive FD bounds checking
             */
            if (ctx->stderr_stream.fd >= 0 && ctx->stderr_stream.fd < RAMFS_MAX_FDS) {
                return ramfs_write(ctx->stderr_stream.fd, data, size);
            }
            return -1;

        case STREAM_TYPE_PIPE:
            /* stderr typically not piped, but support it */
            return -1;

        case STREAM_TYPE_CONSOLE:
            /* Write to console using kprintf */
            for (size_t i = 0; i < size; i++) {
                kprintf("%c", data[i]);
            }
            return (int)size;

        case STREAM_TYPE_NULL:
            /* Writing to /dev/null succeeds but does nothing */
            return (int)size;

        default:
            return -1;
    }
}

bool stdin_has_data(stream_context_t* ctx) {
    if (!ctx || !ctx->stdin_stream.is_open) {
        return false;
    }

    switch (ctx->stdin_stream.type) {
        case STREAM_TYPE_FILE:
            /* File always has data (until EOF) */
            return true;

        case STREAM_TYPE_PIPE:
            /* TODO: Check pipe buffer */
            return false;

        case STREAM_TYPE_CONSOLE:
            /* Check keyboard buffer */
            return keyboard_has_data();

        case STREAM_TYPE_NULL:
            return false;

        default:
            return false;
    }
}

bool stdin_is_file(stream_context_t* ctx) {
    if (!ctx) {
        return false;
    }
    return ctx->stdin_stream.type == STREAM_TYPE_FILE;
}

/*=============================================================================
 * Helper Functions
 *=============================================================================*/

stream_context_t* get_current_streams(void) {
    /* Get the currently running task */
    task_t* current = task_current();

    if (!current) {
        /*=====================================================================
         * ARCHITECTURE (v1.13): Silent NULL Return
         *
         * Returning NULL is EXPECTED in some scenarios:
         * 1. Shell commands running without stream redirection
         * 2. Early boot before scheduler starts
         * 3. Interrupt context where no task is active
         *
         * Callers (stream_printf, printf_stream) handle NULL gracefully by
         * falling back to kprintf. DO NOT print error message here - it
         * creates noise for normal operations.
         *===================================================================*/
        return NULL;
    }

    /* Return address of this task's embedded stream context */
    return &current->streams;
}

/*=============================================================================
 * Stream-aware printf (use instead of kprintf in shell commands)
 *=============================================================================*/
#include <stdarg.h>

int stream_printf(stream_context_t* ctx, const char* format, ...) {
    va_list args;
    va_start(args, format);

    if (!ctx) {
        /* No context - fall back to kprintf */
        vkprintf(format, args);
        va_end(args);
        return 0;
    }

    /* Check stdout stream type */
    if (ctx->stdout_stream.type == STREAM_TYPE_FILE &&
        ctx->stdout_stream.is_open &&
        ctx->stdout_stream.fd >= 0 &&
        ctx->stdout_stream.fd < RAMFS_MAX_FDS) {
        /* Output redirected to file - format to buffer then write */
        char buffer[1024];
        int len = vsnprintf_impl(buffer, sizeof(buffer), format, args);
        va_end(args);

        /*=====================================================================
         * SECURITY FIX: Clamp buffer length to prevent overflow
         *
         * vsnprintf may return the number of characters that WOULD have been
         * written (not what was actually stored) if output was truncated.
         * Passing this unclamped value to ramfs_write() causes reading beyond
         * the buffer, leading to memory disclosure and UB.
         *
         * Even if vsnprintf_impl currently returns actual bytes written,
         * clamping makes this robust against future changes.
         *===================================================================*/
        if (len <= 0) {
            return -1;
        }

        /* Clamp to actual buffer size - 1 (null terminator not written to file) */
        if ((size_t)len >= sizeof(buffer)) {
            len = (int)(sizeof(buffer) - 1);
        }

        return ramfs_write(ctx->stdout_stream.fd, buffer, len);
    } else {
        /* Console output - use vkprintf */
        vkprintf(format, args);
        va_end(args);
        return 0;
    }
}

/*=============================================================================
 * Simple printf wrapper that auto-detects current stream
 * Use this in shell commands instead of kprintf
 *=============================================================================*/
void printf_stream(const char* str) {
    stream_context_t* ctx = get_current_streams();
    if (!ctx || ctx->stdout_stream.type != STREAM_TYPE_FILE) {
        /* Console output - use kprintf */
        kprintf("%s", str);
    } else if (ctx->stdout_stream.is_open && ctx->stdout_stream.fd >= 0) {
        /* File output */
        ramfs_write(ctx->stdout_stream.fd, str, strlen(str));
    }
}
