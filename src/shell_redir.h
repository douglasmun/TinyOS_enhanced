/*=============================================================================
 * shell_redir.h - Shell I/O Redirection Support
 *
 * Implements bash-like I/O redirection with security:
 * - Output redirection (>, >>)
 * - Input redirection (<)
 * - Pipe support (|)
 *=============================================================================*/
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*=============================================================================
 * Configuration
 *=============================================================================*/
#define MAX_REDIRECTS       4       /* Max redirections per command */
#define MAX_PIPE_STAGES     4       /* Max commands in a pipeline */
#define PIPE_BUFFER_SIZE    4096    /* Pipe buffer size */

/*=============================================================================
 * Redirection Types
 *=============================================================================*/
typedef enum {
    REDIR_NONE = 0,
    REDIR_OUTPUT,          /* > file */
    REDIR_APPEND,          /* >> file */
    REDIR_INPUT,           /* < file */
} redir_type_t;

/**
 * @brief Redirection descriptor
 */
typedef struct {
    redir_type_t type;              /* Redirection type */
    char filename[256];             /* Target filename */
    bool active;                    /* Redirection is active */
} redir_t;

/**
 * @brief Command context with redirections
 */
typedef struct {
    char command[512];              /* Command string */
    redir_t redirects[MAX_REDIRECTS]; /* Array of redirections */
    int redir_count;                /* Number of redirections */
    char input_file[256];           /* Input redirection filename (if any) */
    bool has_input_redir;           /* Has input redirection */
} cmd_context_t;

/**
 * @brief Pipeline context for pipe operator support
 */
typedef struct {
    char commands[MAX_PIPE_STAGES][512];  /* Array of commands in pipeline */
    int cmd_count;                        /* Number of commands */
} pipeline_t;

/*=============================================================================
 * Redirection Parser
 *=============================================================================*/

/**
 * @brief Parse command line for redirections
 *
 * @param cmd_line Input command line
 * @param ctx Output command context
 * @return 0 on success, -1 on error
 *
 * This function:
 * - Extracts redirections from command line
 * - Validates filenames for security
 * - Removes redirection syntax from command
 *
 * Security:
 * - Validates filename paths
 * - Prevents directory traversal attacks
 * - Checks file permissions
 */
int parse_redirections(const char* cmd_line, cmd_context_t* ctx);

/**
 * @brief Validate redirection filename for security
 *
 * @param filename Filename to validate
 * @return true if safe, false if potentially dangerous
 *
 * Security checks:
 * - No absolute paths (must be relative)
 * - No parent directory references (..)
 * - No special characters
 * - Length limits
 */
bool validate_redir_filename(const char* filename);

/*=============================================================================
 * Pipeline Parser
 *=============================================================================*/

/**
 * @brief Parse command line for pipe operators
 *
 * @param cmd_line Input command line
 * @param pipeline Output pipeline context
 * @return 0 on success, -1 on error
 *
 * This function splits a command line on pipe operators (|)
 * Example: "ls | grep txt | wc" -> ["ls", "grep txt", "wc"]
 */
int parse_pipeline(const char* cmd_line, pipeline_t* pipeline);

/*=============================================================================
 * Pipe Support
 *=============================================================================*/

/* Forward declaration for wait queues */
struct wait_queue;

/**
 * @brief Pipe buffer with proper blocking support
 *
 * SECURITY ENHANCEMENT (v1.8):
 * Added wait queues for proper blocking instead of silent data loss.
 * - readers: Tasks waiting for data when pipe is empty
 * - writers: Tasks waiting for space when pipe is full
 */
typedef struct {
    char buffer[PIPE_BUFFER_SIZE];    /* Data buffer */
    size_t write_pos;                 /* Write position */
    size_t read_pos;                  /* Read position */
    size_t data_size;                 /* Amount of data */
    struct wait_queue* readers;       /* Tasks waiting for data (allocated) */
    struct wait_queue* writers;       /* Tasks waiting for space (allocated) */
    bool write_closed;                /* Write end closed (readers get EOF) */
    bool read_closed;                 /* Read end closed (writers get EPIPE) */
} pipe_buffer_t;

/**
 * @brief Initialize pipe buffer
 *
 * @param pipe Pipe buffer to initialize
 */
void pipe_init(pipe_buffer_t* pipe);

/**
 * @brief Write data to pipe
 *
 * @param pipe Pipe buffer
 * @param data Data to write
 * @param size Number of bytes
 * @return Number of bytes written, -1 on error
 */
int pipe_write(pipe_buffer_t* pipe, const char* data, size_t size);

/**
 * @brief Read data from pipe
 *
 * @param pipe Pipe buffer
 * @param data Output buffer
 * @param size Maximum bytes to read
 * @return Number of bytes read, -1 on error
 */
int pipe_read(pipe_buffer_t* pipe, char* data, size_t size);

/**
 * @brief Get available data in pipe
 *
 * @param pipe Pipe buffer
 * @return Number of bytes available
 */
size_t pipe_available(const pipe_buffer_t* pipe);

/**
 * @brief Close write end of pipe (readers will get EOF when empty)
 *
 * @param pipe Pipe buffer
 */
void pipe_close_write(pipe_buffer_t* pipe);

/**
 * @brief Close read end of pipe (writers will get EPIPE)
 *
 * @param pipe Pipe buffer
 */
void pipe_close_read(pipe_buffer_t* pipe);
