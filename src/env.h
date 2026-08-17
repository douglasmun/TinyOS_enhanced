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
 * THEN:     16 variables * (32+256) = 4.6 KB total (meets 4KB guideline)
 * NOW:      16 variables * (32+64)  = 1.6 KB, and the same again for aliases
 *
 * The value length dropped 256 -> 64 when storage moved per-task (see
 * env_state_t below). Two reasons, in order of importance:
 *
 * 1. Both tables must fit in ONE 4 KB page, so the per-task allocation is a
 *    plain pmm_alloc() rather than pmm_alloc_contiguous(3). At 256 the pair
 *    came to 9,264 bytes -- 2.26 pages, i.e. three pages with 3 KB wasted per
 *    task. At 64 they total 3,200 bytes with room to spare.
 * 2. 256 was never reachable anyway. SHELL_BUFFER_SIZE is 256 for the ENTIRE
 *    command line, so a single 256-byte value could not expand into it; the
 *    longest default value in the tree is "/bin/shell", at 10 characters.
 *
 * ALIAS_DEFAULT_COUNT is deliberately below ALIAS_MAX_COUNT: filling the table
 * exactly to capacity with built-in aliases leaves a user's own `alias` with
 * nowhere to go, which is what the previous 16-of-16 defaults did.
 *===========================================================================*/
#define ENV_MAX_VARS        16      /* Maximum environment variables (DoS limit) */
#define ENV_MAX_NAME_LEN    32      /* Maximum variable name length */
#define ENV_MAX_VALUE_LEN   64      /* Maximum variable value length */
#define ENV_MAX_EXPAND_LEN  512     /* Maximum length after expansion */
#define ALIAS_MAX_COUNT     16      /* Maximum aliases (reduced from 32) */
#define ALIAS_MAX_NAME_LEN  32      /* Maximum alias name length */
#define ALIAS_MAX_CMD_LEN   64      /* Maximum alias command length */

/* Built-in aliases installed by env_init(). MUST stay below ALIAS_MAX_COUNT,
 * or a user's own `alias` has nowhere to go -- see the list in env.c. */
#define ALIAS_DEFAULT_COUNT 12
_Static_assert(ALIAS_DEFAULT_COUNT < ALIAS_MAX_COUNT,
               "default aliases must leave free slots for the user");

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

/**
 * @brief Command alias structure
 */
typedef struct {
    char name[ALIAS_MAX_NAME_LEN];     /* Alias name */
    char command[ALIAS_MAX_CMD_LEN];   /* Command to execute */
    bool in_use;                        /* Slot is occupied */
} alias_t;

/**
 * @brief Per-task environment and alias storage
 *
 * STORAGE MODEL: one of these per task, allocated on demand.
 *
 * task_t carries a POINTER to this (task->env), not the struct itself. It is
 * NULL until the task first writes a variable or alias, and the whole thing is
 * one pmm_alloc()'d page -- exactly the task->edr_advanced pattern.
 *
 * Embedding it directly in task_t was the obvious alternative and does not
 * work: at MAX_TASKS 32 it would add ~102 KB of .bss unconditionally, charged
 * to every task including the ones that never touch an environment variable.
 * A task that never uses env now costs 4 bytes.
 *
 * The NULL case must read as "empty", never as an error: reads against a task
 * with no table return "not set", which is precisely the behaviour every
 * non-shell task had before this existed.
 *=========================================================================*/
typedef struct env_state {
    env_var_t vars[ENV_MAX_VARS];
    alias_t   aliases[ALIAS_MAX_COUNT];
} env_state_t;

_Static_assert(sizeof(env_state_t) <= 4096,
               "env_state_t must fit in a single pmm_alloc() page; "
               "reduce ENV_MAX_VALUE_LEN/ALIAS_MAX_CMD_LEN or the slot counts");

/*=============================================================================
 * Initialization
 *=============================================================================*/

/**
 * @brief Populate the CURRENT task's environment with the defaults
 *
 * Sets up the environment with default variables:
 * - PATH=/bin
 * - HOME=/
 * - USER=root
 * - SHELL=/bin/shell
 *
 * Called per-shell, not once at boot: storage is per-task, so there is no
 * global table to initialize. Allocates the calling task's env page if it
 * does not exist yet. Safe to call more than once (it clears first).
 */
void env_init(void);

/**
 * @brief Self-test: prove env storage is PER-TASK and that export INHERITS
 *
 * Two halves, reported on two lines, because they are opposite requirements
 * against the same storage: a build that shares one page between tasks passes
 * inheritance trivially and fails isolation, and a build that never copies
 * passes isolation and fails inheritance. Only asserting both pins the design.
 *
 * ISOLATION: spawns a second kernel task, has it set a variable of its own, and
 * checks that the two tasks do not see each other's variables.
 *
 * INHERITANCE: spawns a third, runs env_inherit_exported() over it as sys_spawn
 * and cmd_exec do, and checks that the exported variable crossed while the
 * un-exported one did not. Both clauses are needed -- a copy that ignored the
 * export flag and cloned the whole table looks identical to a correct one if
 * you only look at an exported variable.
 *
 * This exists because per-task isolation is not observable any other way in
 * this build: `su` changes credentials on the SAME task (so it shares the
 * page), and ring 3 has no env syscall yet. A single shell setting and reading
 * its own variable behaves identically under global and per-task storage, so
 * without this the property that motivates the whole design would ship
 * untested.
 *
 * Prints its own result. Returns true if isolation holds.
 */
bool env_pertask_self_test(void);

/**
 * @brief Copy a parent's EXPORTED variables into a freshly-created child
 *
 * Called from sys_spawn, alongside the credential/stream/cwd inheritance, and
 * BEFORE scheduler_add_task() -- the child can run on the next tick, so its
 * environment must be complete before it is made runnable.
 *
 * Only exported variables cross; aliases never do (a spawned binary does not
 * consult the alias table -- substitution happens in the shell). The copy is a
 * SNAPSHOT: later changes on either side are invisible to the other, which is
 * what keeps per-task isolation intact. Inheritance that shared the page would
 * silently undo it.
 *
 * Both arguments are task_t*, declared void* to avoid a circular include.
 * Does nothing if the parent has no table, or if the child's page cannot be
 * allocated (the child then simply starts empty).
 */
void env_inherit_exported(void* parent_task, void* child_task);

/**
 * @brief Release the env page owned by a task
 *
 * Called from task_free_resources(). Idempotent -- nulls the field after
 * freeing, because a task can pass through both the terminate and the
 * scheduler-cleanup paths.
 *
 * Declared void* to avoid a circular include with process.h; the argument is
 * a task_t*.
 */
void env_free_for_task(void* task);

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
 * @brief Copy an environment variable's value into a caller buffer
 *
 * COPY-OUT, NOT A BORROWED POINTER. The previous env_get() returned a pointer
 * INTO the table after releasing the lock, so the caller read a slot another
 * task could rewrite or free underneath it -- harmless while a single kernel
 * shell was the only caller, a genuine use-after-unlock now that storage is
 * per-task and the page can be freed at task exit. Returning a copy made under
 * the lock is the only version that is safe to expose further.
 *
 * @param name Variable name
 * @param out Buffer to receive the value (untouched unless the var exists)
 * @param out_size Size of out; the value is truncated to fit, always
 *                 null-terminated
 * @return true if the variable exists, false otherwise
 */
bool env_get(const char* name, char* out, size_t out_size);

/**
 * @brief Copy an alias's command into a caller buffer
 *
 * Copy-out for the same reason as env_get().
 *
 * @param name Alias name
 * @param out Buffer to receive the command
 * @param out_size Size of out
 * @return true if the alias exists, false otherwise
 */
bool alias_get(const char* name, char* out, size_t out_size);

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
