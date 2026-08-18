/*=============================================================================
 * stdio.c - Standard I/O Streams Implementation
 *=============================================================================*/
#include "stdio.h"
#include "shell_redir.h"  /* pipe_buffer_t and pipe_read/pipe_write */
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
    ctx->stdin_stream.borrowed = false;

    /* Initialize stdout to console (VGA) */
    ctx->stdout_stream.type = STREAM_TYPE_CONSOLE;
    ctx->stdout_stream.fd = -1;
    ctx->stdout_stream.data = NULL;
    ctx->stdout_stream.is_open = true;
    ctx->stdout_stream.borrowed = false;

    /* Initialize stderr to console (VGA) */
    ctx->stderr_stream.type = STREAM_TYPE_CONSOLE;
    ctx->stderr_stream.fd = -1;
    ctx->stderr_stream.data = NULL;
    ctx->stderr_stream.is_open = true;
    ctx->stderr_stream.borrowed = false;
}

void streams_inherit(stream_context_t* child, const stream_context_t* creator) {
    if (!child || !creator) {
        return;
    }

    /* Shallow copy — see the ownership caveat in stdio.h. Done field-by-field
     * rather than as a struct assignment so that adding a stream later forces
     * a deliberate decision here about whether it should be inherited. */
    child->stdin_stream  = creator->stdin_stream;
    child->stdout_stream = creator->stdout_stream;
    child->stderr_stream = creator->stderr_stream;

    /* The creator keeps ownership of any fd behind these streams. Marking the
     * child's copies borrowed stops stdin_reset/stdout_reset/stderr_reset —
     * and therefore streams_cleanup(), which task_terminate() runs on every
     * dying task — from closing a descriptor the creator is still using. */
    child->stdin_stream.borrowed  = true;
    child->stdout_stream.borrowed = true;
    child->stderr_stream.borrowed = true;
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
    if (!ctx->stdin_stream.borrowed &&
        ctx->stdin_stream.is_open &&
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
    /* RAMFS_FLAG_INHERIT: RAMFS closes every fd on exec by default (see
     * ramfs_close_on_exec), which would leave an exec'd child's inherited stdin
     * pointing at an already-closed descriptor. The opener still owns and closes
     * this fd; INHERIT only exempts it from the exec sweep. */
    int fd = ramfs_open(filename,
                        RAMFS_FLAG_READ | RAMFS_FLAG_NOFOLLOW | RAMFS_FLAG_INHERIT);
    if (fd < 0) {
        /* SECURITY FIX: Restore stdin to console on error
         * If we closed the previous stdin FD but failed to open new file,
         * stdin is now broken. Restore to console for safety.
         */
        ctx->stdin_stream.type = STREAM_TYPE_CONSOLE;
        ctx->stdin_stream.fd = -1;
        ctx->stdin_stream.is_open = true;
        ctx->stdin_stream.borrowed = false;
        return -1;  /* File doesn't exist or can't be opened */
    }

    /* Set stdin to file */
    ctx->stdin_stream.type = STREAM_TYPE_FILE;
    ctx->stdin_stream.fd = fd;
    ctx->stdin_stream.data = NULL;
    ctx->stdin_stream.is_open = true;
    /* This context opened the fd, so it owns it and must close it on reset. */
    ctx->stdin_stream.borrowed = false;

    return 0;
}

int stdout_redirect_to_file(stream_context_t* ctx, const char* filename, bool append) {
    if (!ctx || !filename) {
        return -1;
    }

    /* SECURITY FIX: Close previous stdout file descriptor to prevent FD leak
     * SECURITY FIX: Defensive FD bounds checking (defense-in-depth)
     */
    if (!ctx->stdout_stream.borrowed &&
        ctx->stdout_stream.is_open &&
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
    /* RAMFS_FLAG_INHERIT — same reason as stdin_redirect_from_file above. */
    int fd = ramfs_open(filename,
                        RAMFS_FLAG_WRITE | RAMFS_FLAG_NOFOLLOW | RAMFS_FLAG_INHERIT);
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
        ctx->stdout_stream.borrowed = false;
        return -1;
    }

    /* `>` vs `>>`. This was a TODO for a long time and both halves of it were
     * wrong, not just the append half:
     *
     * ramfs_open does not truncate (there is no flag for it) and ramfs_write
     * only ever GROWS node->size, so a plain `>` onto an existing longer file
     * overwrote from position 0 and left the old tail behind — visible to the
     * very next `cat`. `>` has to actually shorten the file, which is what
     * ramfs_truncate is for.
     *
     * Append is the other direction: the cursor starts at 0 on open, so `>>`
     * without a seek is indistinguishable from `>`, silently destroying the
     * data the user asked to keep. */
    if (append) {
        int end = ramfs_fd_size(fd);
        if (end > 0) {
            ramfs_seek(fd, (uint32_t)end);
        }
    } else {
        ramfs_truncate(fd);
    }

    /* Set stdout to file */
    ctx->stdout_stream.type = STREAM_TYPE_FILE;
    ctx->stdout_stream.fd = fd;
    ctx->stdout_stream.data = NULL;
    ctx->stdout_stream.is_open = true;
    /* This context opened the fd, so it owns it and must close it on reset. */
    ctx->stdout_stream.borrowed = false;

    return 0;
}

void stdin_reset(stream_context_t* ctx) {
    if (!ctx) {
        return;
    }

    /* Close file descriptor if open
     * SECURITY FIX: Defensive FD bounds checking
     */
    if (!ctx->stdin_stream.borrowed &&
        ctx->stdin_stream.type == STREAM_TYPE_FILE &&
        ctx->stdin_stream.fd >= 0 &&
        ctx->stdin_stream.fd < RAMFS_MAX_FDS) {
        ramfs_close(ctx->stdin_stream.fd);
    }

    /* Reset to console */
    ctx->stdin_stream.type = STREAM_TYPE_CONSOLE;
    ctx->stdin_stream.fd = -1;
    ctx->stdin_stream.data = NULL;
    ctx->stdin_stream.is_open = true;
    ctx->stdin_stream.borrowed = false;
}

void stdout_reset(stream_context_t* ctx) {
    if (!ctx) {
        return;
    }

    /* Close file descriptor if open
     * SECURITY FIX: Defensive FD bounds checking
     */
    if (!ctx->stdout_stream.borrowed &&
        ctx->stdout_stream.type == STREAM_TYPE_FILE &&
        ctx->stdout_stream.fd >= 0 &&
        ctx->stdout_stream.fd < RAMFS_MAX_FDS) {
        ramfs_close(ctx->stdout_stream.fd);
    }

    /* Reset to console */
    ctx->stdout_stream.type = STREAM_TYPE_CONSOLE;
    ctx->stdout_stream.fd = -1;
    ctx->stdout_stream.data = NULL;
    ctx->stdout_stream.is_open = true;
    ctx->stdout_stream.borrowed = false;
}

void stderr_reset(stream_context_t* ctx) {
    if (!ctx) {
        return;
    }

    /* stderr typically stays on console, but support redirection
     * SECURITY FIX: Defensive FD bounds checking
     */
    if (!ctx->stderr_stream.borrowed &&
        ctx->stderr_stream.type == STREAM_TYPE_FILE &&
        ctx->stderr_stream.fd >= 0 &&
        ctx->stderr_stream.fd < RAMFS_MAX_FDS) {
        ramfs_close(ctx->stderr_stream.fd);
    }

    /* Reset to console */
    ctx->stderr_stream.type = STREAM_TYPE_CONSOLE;
    ctx->stderr_stream.fd = -1;
    ctx->stderr_stream.data = NULL;
    ctx->stderr_stream.is_open = true;
    ctx->stderr_stream.borrowed = false;
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
            /* Blocks until data arrives, or returns 0 at EOF (all writers
             * closed). data holds the pipe_buffer_t the stream was bound to. */
            if (ctx->stdin_stream.data) {
                return pipe_read((pipe_buffer_t*)ctx->stdin_stream.data,
                                 buffer, size);
            }
            return -1;

        case STREAM_TYPE_CONSOLE: {
            /* Line-oriented keyboard read. This used to return -1 ("not
             * implemented"), with the equivalent loop living inline in
             * sys_read; that made the console the one stdin type a user
             * process could read, and only by bypassing the stream layer.
             * The loop is here now so sys_read can go through stdin_read for
             * every type. keyboard_getchar() BLOCKS, so the first character
             * costs an unbounded wait — same as before, just relocated. */
            size_t i = 0;
            while (i < size) {
                char c = keyboard_getchar();
                if (c == '\n') {
                    buffer[i++] = c;
                    break;          /* deliver the line, newline included */
                } else if (c == '\b') {
                    if (i > 0) {
                        /* Drop the character from the line buffer. NOTHING is
                         * echoed here, and the keyboard IRQ does not echo
                         * either -- keyboard_irq_handler() only calls
                         * buffer_put(), deliberately, so an application can
                         * choose asterisks for a password (see the ARCHITECTURE
                         * note in keyboard.c). This comment used to claim the
                         * IRQ echoed; it never did.
                         *
                         * Consequence: on the ring-3 path the user sees no
                         * per-keystroke feedback. userspace/shell.c echoes the
                         * whole ACCEPTED line after readline() returns, so a
                         * backspace is invisible until then. Fixing that means
                         * a real TTY discipline, not a printf here -- this
                         * function has no stream to write to. */
                        i--;
                    }
                } else {
                    buffer[i++] = c;
                }
            }
            return (int)i;
        }

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

    /* size == 1 leaves room for the terminator and nothing else. Handled here
     * rather than in each case below because every one of them loops on
     * `pos < size - 1` with an unsigned size: at size == 1 that wraps to
     * SIZE_MAX and the loop writes far past a one-byte buffer. Returning the
     * empty string is the honest answer -- zero characters fit -- and it keeps
     * the underflow unreachable no matter which stream type is added later. */
    if (size == 1) {
        buffer[0] = '\0';
        return 0;
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

        case STREAM_TYPE_PIPE: {
            /* One byte at a time: pipe_read has no lookahead, so reading a
             * block would consume bytes past the newline that belong to the
             * NEXT line and there is nowhere to push them back. */
            if (!ctx->stdin_stream.data) {
                return -1;
            }
            pipe_buffer_t* pipe = (pipe_buffer_t*)ctx->stdin_stream.data;
            size_t pos = 0;

            while (pos < size - 1) {
                char c;
                int n = pipe_read(pipe, &c, 1);
                if (n < 0) {
                    return n;        /* Error */
                }
                if (n == 0) {
                    break;           /* EOF: return what we have */
                }
                if (c == '\n') {
                    break;           /* Line complete; newline not stored */
                }
                buffer[pos++] = c;
            }

            buffer[pos] = '\0';
            /* Distinguish "EOF with nothing read" from "empty line". */
            if (pos == 0 && pipe->write_closed && pipe_available(pipe) == 0) {
                return 0;
            }
            return (int)pos;
        }

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
            /* Blocks while the pipe is full; -EPIPE once the read end closes. */
            if (ctx->stdout_stream.data) {
                return pipe_write((pipe_buffer_t*)ctx->stdout_stream.data,
                                  data, size);
            }
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
            /* stderr is not piped by `|` (which redirects stdout only), but a
             * caller can bind it explicitly, so honour it rather than fail. */
            if (ctx->stderr_stream.data) {
                return pipe_write((pipe_buffer_t*)ctx->stderr_stream.data,
                                  data, size);
            }
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
            /* Buffered bytes, or EOF — both make a read return without
             * blocking, which is what callers use this to decide. */
            if (ctx->stdin_stream.data) {
                pipe_buffer_t* pipe = (pipe_buffer_t*)ctx->stdin_stream.data;
                return pipe_available(pipe) > 0 || pipe->write_closed;
            }
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

bool stdin_is_pipe(stream_context_t* ctx) {
    if (!ctx) {
        return false;
    }
    return ctx->stdin_stream.type == STREAM_TYPE_PIPE;
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
