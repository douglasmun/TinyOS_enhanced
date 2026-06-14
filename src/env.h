/*=============================================================================
 * env.h - Environment Variable Management
 *
 * Provides bash-like environment variable support for the shell:
 * - set/unset/export/env commands
 * - Variable expansion ($VAR syntax)
 * - PATH variable for command search
 *=============================================================================*/
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*=============================================================================
 * SECURITY FIX (Issue 4.3): Environment Variable Limits (DoS Prevention)
 *
 * CRITICAL: Without strict limits, user can exhaust memory via environment
 * variables, causing DoS. Security review recommends max 4KB total.
 *
 * PREVIOUS: 64 variables * (32+256) = 18.4 KB total
 * NEW:      16 variables * (32+256) = 4.6 KB total (meets 4KB guideline)
 *
 * Rationale: 16 environment variables is sufficient for:
 * - Standard vars (PATH, HOME, USER, SHELL, PWD, TERM, etc.)
 * - Custom user vars (reasonable limit)
 * - Prevents unbounded memory consumption
 *===========================================================================*/
#define ENV_MAX_VARS        16      /* Maximum environment variables (DoS limit) */
#define ENV_MAX_NAME_LEN    32      /* Maximum variable name length */
#define ENV_MAX_VALUE_LEN   256     /* Maximum variable value length */
#define ENV_MAX_EXPAND_LEN  512     /* Maximum length after expansion */
#define ALIAS_MAX_COUNT     16      /* Maximum aliases (reduced from 32) */
#define ALIAS_MAX_NAME_LEN  32      /* Maximum alias name length */
#define ALIAS_MAX_CMD_LEN   256     /* Maximum alias command length */

/*=============================================================================
 * Data Structures
 *=============================================================================*/

/**
 * @brief Environment variable structure
 */
typedef struct {
    char name[ENV_MAX_NAME_LEN];       /* Variable name (e.g., "PATH") */
    char value[ENV_MAX_VALUE_LEN];     /* Variable value */
    bool exported;                      /* Export flag for child processes */
    bool in_use;                        /* Slot is occupied */
} env_var_t;

/*=============================================================================
 * Initialization
 *=============================================================================*/

/**
 * @brief Initialize the environment variable system
 *
 * Sets up the environment with default variables:
 * - PATH=/bin
 * - HOME=/
 * - USER=root
 * - SHELL=/bin/shell
 */
void env_init(void);

/*=============================================================================
 * Variable Management
 *=============================================================================*/

/**
 * @brief Set an environment variable
 *
 * @param name Variable name (alphanumeric + underscore, starts with letter/_)
 * @param value Variable value
 * @return 0 on success, -1 on error (invalid name, table full, etc.)
 */
int env_set(const char* name, const char* value);

/**
 * @brief Get an environment variable's value
 *
 * @param name Variable name
 * @return Pointer to value string, or NULL if not found
 */
const char* env_get(const char* name);

/**
 * @brief Remove an environment variable
 *
 * @param name Variable name
 * @return 0 on success, -1 if not found
 */
int env_unset(const char* name);

/**
 * @brief Mark a variable as exported
 *
 * @param name Variable name
 * @return 0 on success, -1 if not found
 */
int env_export(const char* name);

/**
 * @brief Check if a variable exists
 *
 * @param name Variable name
 * @return true if variable exists, false otherwise
 */
bool env_exists(const char* name);

/*=============================================================================
 * Variable Listing
 *=============================================================================*/

/**
 * @brief Print all environment variables
 *
 * @param exported_only If true, only show exported variables (like 'env')
 *                      If false, show all variables (like 'set')
 */
void env_list(bool exported_only);

/*=============================================================================
 * Variable Expansion
 *=============================================================================*/

/**
 * @brief Expand environment variables in a string
 *
 * Supports:
 * - $VAR or ${VAR} syntax
 * - $$=PID (process ID)
 * - $?=exit status of last command (not implemented yet)
 *
 * @param input Input string with variables to expand
 * @param output Buffer to store expanded string
 * @param output_size Size of output buffer
 * @return 0 on success, -1 on error (buffer overflow, etc.)
 *
 * Example:
 *   input:  "echo $HOME/file"
 *   output: "echo /root/file"
 */
int env_expand(const char* input, char* output, size_t output_size);

/*=============================================================================
 * PATH Variable Support
 *=============================================================================*/

/**
 * @brief Search for a command in PATH
 *
 * @param command Command name (e.g., "ls")
 * @param resolved_path Buffer to store full path
 * @param path_size Size of resolved_path buffer
 * @return 0 on success, -1 if not found
 *
 * Example:
 *   PATH="/bin:/usr/bin"
 *   command="ls"
 *   returns: "/bin/ls"
 */
int env_find_in_path(const char* command, char* resolved_path, size_t path_size);

/*=============================================================================
 * Validation
 *=============================================================================*/

/**
 * @brief Check if a variable name is valid
 *
 * Valid names:
 * - Start with letter or underscore
 * - Contain only letters, digits, underscores
 *
 * @param name Variable name to check
 * @return true if valid, false otherwise
 */
bool env_is_valid_name(const char* name);

/*=============================================================================
 * Alias Support
 *=============================================================================*/

/**
 * @brief Set a command alias
 *
 * @param name Alias name
 * @param command Command to execute
 * @return 0 on success, -1 on error
 *
 * Example:
 *   alias_set("ll", "ls -l")
 */
int alias_set(const char* name, const char* command);

/**
 * @brief Get an alias command
 *
 * @param name Alias name
 * @return Pointer to command string, or NULL if not found
 */
const char* alias_get(const char* name);

/**
 * @brief Remove an alias
 *
 * @param name Alias name
 * @return 0 on success, -1 if not found
 */
int alias_unset(const char* name);

/**
 * @brief List all aliases
 */
void alias_list(void);

/**
 * @brief Check if an alias exists
 *
 * @param name Alias name
 * @return true if alias exists, false otherwise
 */
bool alias_exists(const char* name);
