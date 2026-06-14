/*=============================================================================
 * stdio.h - Standard I/O Streams (Unix-like stdin/stdout/stderr)
 *
 * Implements standard file descriptors:
 *   - stdin  (fd 0): Standard input (keyboard by default)
 *   - stdout (fd 1): Standard output (console by default)
 *   - stderr (fd 2): Standard error (console by default)
 *
 * SECURITY FIX: Per-Process Streams
 * Each task now has its own stream context to prevent I/O corruption,
 * data leakage, and race conditions in multi-tasking environments.
 *=============================================================================*/
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Forward declaration to avoid circular dependency with process.h */
struct task;

/*=============================================================================
 * Standard File Descriptors
 *=============================================================================*/
#define STDIN_FILENO    0
#define STDOUT_FILENO   1
#define STDERR_FILENO   2

/*=============================================================================
 * Stream Types
 *=============================================================================*/
typedef enum {
    STREAM_TYPE_CONSOLE,    /* VGA console */
    STREAM_TYPE_FILE,       /* RAMFS file */
    STREAM_TYPE_PIPE,       /* Pipe buffer */
    STREAM_TYPE_NULL,       /* /dev/null equivalent */
} stream_type_t;

/**
 * @brief Stream descriptor
 */
typedef struct {
    stream_type_t type;     /* Stream type */
    int fd;                 /* File descriptor (for files) */
    void* data;             /* Type-specific data pointer */
    bool is_open;           /* Stream is open */
} stream_t;

/**
 * @brief Stream context for shell
 */
typedef struct {
    stream_t stdin_stream;  /* Standard input */
    stream_t stdout_stream; /* Standard output */
    stream_t stderr_stream; /* Standard error */
} stream_context_t;

/*=============================================================================
 * Stream Management
 *=============================================================================*/

/**
 * @brief Initialize standard streams to default (console)
 *
 * @param ctx Stream context to initialize
 */
void streams_init(stream_context_t* ctx);

/**
 * @brief Set stdin to read from a file
 *
 * @param ctx Stream context
 * @param filename File to read from
 * @return 0 on success, -1 on error
 */
int stdin_redirect_from_file(stream_context_t* ctx, const char* filename);

/**
 * @brief Set stdout to write to a file
 *
 * @param ctx Stream context
 * @param filename File to write to
 * @param append True for append mode, false for truncate
 * @return 0 on success, -1 on error
 */
int stdout_redirect_to_file(stream_context_t* ctx, const char* filename, bool append);

/**
 * @brief Reset stdin to default (console/keyboard)
 *
 * @param ctx Stream context
 */
void stdin_reset(stream_context_t* ctx);

/**
 * @brief Reset stdout to default (console)
 *
 * @param ctx Stream context
 */
void stdout_reset(stream_context_t* ctx);

/**
 * @brief Reset stderr to default (console)
 *
 * @param ctx Stream context
 */
void stderr_reset(stream_context_t* ctx);

/**
 * @brief Close all stream file descriptors
 *
 * @param ctx Stream context
 */
void streams_cleanup(stream_context_t* ctx);

/*=============================================================================
 * Stream I/O Operations
 *=============================================================================*/

/**
 * @brief Read a line from stdin
 *
 * @param ctx Stream context
 * @param buffer Output buffer
 * @param size Buffer size
 * @return Number of bytes read, -1 on error
 *
 * This function reads from:
 * - File (if stdin redirected from file)
 * - Pipe buffer (if stdin connected to pipe)
 * - Keyboard (default)
 */
int stdin_getline(stream_context_t* ctx, char* buffer, size_t size);

/**
 * @brief Read data from stdin
 *
 * @param ctx Stream context
 * @param buffer Output buffer
 * @param size Maximum bytes to read
 * @return Number of bytes read, -1 on error
 */
int stdin_read(stream_context_t* ctx, char* buffer, size_t size);

/**
 * @brief Write to stdout
 *
 * @param ctx Stream context
 * @param data Data to write
 * @param size Number of bytes
 * @return Number of bytes written, -1 on error
 */
int stdout_write(stream_context_t* ctx, const char* data, size_t size);

/**
 * @brief Write to stderr
 *
 * @param ctx Stream context
 * @param data Data to write
 * @param size Number of bytes
 * @return Number of bytes written, -1 on error
 */
int stderr_write(stream_context_t* ctx, const char* data, size_t size);

/**
 * @brief Check if stdin has data available
 *
 * @param ctx Stream context
 * @return true if data available, false otherwise
 */
bool stdin_has_data(stream_context_t* ctx);

/**
 * @brief Check if stdin is from a file (not keyboard)
 *
 * @param ctx Stream context
 * @return true if stdin is redirected from file
 */
bool stdin_is_file(stream_context_t* ctx);

/*=============================================================================
 * Helper Functions
 *=============================================================================*/

/**
 * @brief Get global stream context for current shell
 *
 * @return Pointer to global stream context
 *
 * Note: This returns a global context. In a multi-process system,
 * each process would have its own context.
 */
stream_context_t* get_current_streams(void);

/**
 * @brief Print formatted output to stdout
 *
 * @param ctx Stream context
 * @param format Format string (printf-style)
 * @param ... Variable arguments
 * @return Number of bytes written
 *
 * Note: This wraps kprintf() but respects stdout redirection
 */
int stream_printf(stream_context_t* ctx, const char* format, ...);

/**
 * @brief Simple string output to current stdout
 *
 * @param str String to output
 *
 * This automatically detects the current stream context and outputs
 * to either console or redirected file. Use this instead of kprintf()
 * in shell commands to support output redirection.
 *
 * Note: For formatted output, kprintf currently doesn't support
 * redirection. This is a known limitation.
 */
void printf_stream(const char* str);
