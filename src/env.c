/*=============================================================================
 * env.c - Environment Variable Management Implementation
 *=============================================================================*/
#include "env.h"
#include "util.h"
#include "kprintf.h"
#include "critical.h"
#include <stddef.h>

/*=============================================================================
 * Global Environment Table
 *=============================================================================*/
static env_var_t env_table[ENV_MAX_VARS];

/*=============================================================================
 * Alias Table
 *=============================================================================*/
typedef struct {
    char name[ALIAS_MAX_NAME_LEN];       /* Alias name */
    char command[ALIAS_MAX_CMD_LEN];     /* Command to execute */
    bool in_use;                         /* Slot is occupied */
} alias_t;

static alias_t alias_table[ALIAS_MAX_COUNT];

/*=============================================================================
 * String Helper Functions
 * SECURITY FIX: Removed unsafe my_strcpy, using safe_strcpy from util.h instead
 *=============================================================================*/

static char* my_strncpy(char* dest, const char* src, size_t n) {
    size_t i;
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0';
    }
    return dest;
}

/*=============================================================================
 * Helper Functions
 *=============================================================================*/

/**
 * @brief Find a variable by name
 * @return Index in env_table, or -1 if not found
 */
static int env_find(const char* name) {
    if (!name) {
        return -1;
    }

    for (int i = 0; i < ENV_MAX_VARS; i++) {
        if (env_table[i].in_use && strcmp(env_table[i].name, name) == 0) {
            return i;
        }
    }

    return -1;
}

/**
 * @brief Find an empty slot in the environment table
 * @return Index of empty slot, or -1 if table is full
 */
static int env_find_empty(void) {
    for (int i = 0; i < ENV_MAX_VARS; i++) {
        if (!env_table[i].in_use) {
            return i;
        }
    }
    return -1;
}

/*=============================================================================
 * Validation
 *=============================================================================*/

bool env_is_valid_name(const char* name) {
    if (!name || !*name) {
        return false;
    }

    /* First character must be letter or underscore */
    char c = name[0];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_')) {
        return false;
    }

    /* Remaining characters must be alphanumeric or underscore */
    for (int i = 1; name[i]; i++) {
        c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_')) {
            return false;
        }
    }

    return true;
}

/*=============================================================================
 * Initialization
 *=============================================================================*/

void env_init(void) {
    /* Clear the environment table */
    for (int i = 0; i < ENV_MAX_VARS; i++) {
        env_table[i].in_use = false;
        env_table[i].exported = false;
        env_table[i].name[0] = '\0';
        env_table[i].value[0] = '\0';
    }

    /* Clear the alias table */
    for (int i = 0; i < ALIAS_MAX_COUNT; i++) {
        alias_table[i].in_use = false;
        alias_table[i].name[0] = '\0';
        alias_table[i].command[0] = '\0';
    }

    /* Set default environment variables */
    env_set("PATH", "/bin");
    env_export("PATH");

    env_set("HOME", "/");
    env_export("HOME");

    env_set("USER", "root");
    env_export("USER");

    env_set("SHELL", "/bin/shell");
    env_export("SHELL");

    env_set("TERM", "vga");
    env_export("TERM");

    env_set("PWD", "/");
    env_export("PWD");

    env_set("OLDPWD", "/");
    env_export("OLDPWD");

    env_set("HOSTNAME", "tinyos");
    env_export("HOSTNAME");

    env_set("EDITOR", "edit");
    env_export("EDITOR");

    env_set("PAGER", "cat");
    env_export("PAGER");

    /* Set up useful default aliases (bash-like) */
    alias_set("ll", "ls -l");
    alias_set("la", "ls -a");
    alias_set("l", "ls");
    alias_set("cls", "clear");
    alias_set("dir", "ls");
    alias_set("copy", "cp");
    alias_set("move", "mv");
    alias_set("del", "rm");
    alias_set("md", "mkdir");
    alias_set("rd", "rm -r");
    alias_set("type", "cat");
    alias_set("..", "cd ..");
    alias_set("...", "cd ../..");
    alias_set("h", "history");
    alias_set("k", "kill");
    alias_set("please", "sudo");  /* Easter egg: sudo isn't implemented but it's fun! */
}

/*=============================================================================
 * Variable Management
 *=============================================================================*/

int env_set(const char* name, const char* value) {
    if (!name || !value) {
        return -1;
    }

    /* Validate name */
    if (!env_is_valid_name(name)) {
        return -1;
    }

    /* Check name length */
    size_t name_len = strlen(name);
    if (name_len >= ENV_MAX_NAME_LEN) {
        return -1;
    }

    /* Check value length */
    size_t value_len = strlen(value);
    if (value_len >= ENV_MAX_VALUE_LEN) {
        return -1;
    }

    CRITICAL_SECTION_ENTER();  /* SECURITY: Protect env table state */

    /* Check if variable already exists */
    int idx = env_find(name);
    if (idx >= 0) {
        /* Update existing variable */
        my_strncpy(env_table[idx].value, value, ENV_MAX_VALUE_LEN - 1);
        env_table[idx].value[ENV_MAX_VALUE_LEN - 1] = '\0';
        CRITICAL_SECTION_EXIT();
        return 0;
    }

    /* Find empty slot */
    idx = env_find_empty();
    if (idx < 0) {
        CRITICAL_SECTION_EXIT();
        return -1;  /* Table full */
    }

    /* Create new variable */
    my_strncpy(env_table[idx].name, name, ENV_MAX_NAME_LEN - 1);
    env_table[idx].name[ENV_MAX_NAME_LEN - 1] = '\0';

    my_strncpy(env_table[idx].value, value, ENV_MAX_VALUE_LEN - 1);
    env_table[idx].value[ENV_MAX_VALUE_LEN - 1] = '\0';

    env_table[idx].exported = false;
    env_table[idx].in_use = true;

    CRITICAL_SECTION_EXIT();
    return 0;
}

const char* env_get(const char* name) {
    CRITICAL_SECTION_ENTER();  /* SECURITY: Protect env table reads */

    int idx = env_find(name);
    const char* result = NULL;
    if (idx >= 0) {
        result = env_table[idx].value;
    }

    CRITICAL_SECTION_EXIT();
    return result;
}

int env_unset(const char* name) {
    CRITICAL_SECTION_ENTER();  /* SECURITY: Protect env table state */

    int idx = env_find(name);
    if (idx < 0) {
        CRITICAL_SECTION_EXIT();
        return -1;
    }

    env_table[idx].in_use = false;
    env_table[idx].exported = false;
    env_table[idx].name[0] = '\0';
    env_table[idx].value[0] = '\0';

    CRITICAL_SECTION_EXIT();
    return 0;
}

int env_export(const char* name) {
    /*=========================================================================
     * SECURITY FIX: Add Critical Section Protection for env_export()
     * CRITICAL: Race condition if thread A calls env_unset() while thread B
     * calls env_export() on the same variable. Without locking:
     *
     * Timeline:
     * T0: Thread B calls env_export("FOO"), env_find() returns idx=5
     * T1: Thread A calls env_unset("FOO"), sets env_table[5].in_use=false
     * T2: Thread B continues, writes env_table[5].exported=true
     * T3: Thread A allocates new var at idx=5, partial state corruption
     *
     * Result: New variable inherits .exported=true from deleted variable.
     * Shell "env" command now leaks internal variables that should be local.
     *
     * This is exactly the "works fine in single-threaded shell, breaks when
     * background jobs + signal handlers run concurrently" issue.
     *
     * All other env_* functions use CRITICAL_SECTION_ENTER/EXIT to protect
     * env_table access. env_export() was the ONLY function missing this.
     *=========================================================================*/
    CRITICAL_SECTION_ENTER();  /* SECURITY: Protect env table state */

    int idx = env_find(name);
    if (idx < 0) {
        CRITICAL_SECTION_EXIT();
        return -1;
    }

    env_table[idx].exported = true;

    CRITICAL_SECTION_EXIT();
    return 0;
}

bool env_exists(const char* name) {
    /*=========================================================================
     * SECURITY FIX: Add Critical Section Protection
     * CRITICAL: env_find() accesses global env_table without locking.
     * Race condition if another thread modifies env_table during lookup.
     *=========================================================================*/
    CRITICAL_SECTION_ENTER();
    bool result = (env_find(name) >= 0);
    CRITICAL_SECTION_EXIT();
    return result;
}

/*=============================================================================
 * Variable Listing
 *=============================================================================*/

void env_list(bool exported_only) {
    /*=========================================================================
     * SECURITY FIX: Add Critical Section Protection
     * CRITICAL: Iterates over global env_table without locking.
     * Race condition if another thread modifies env_table during iteration:
     * - Variables could be added/deleted mid-iteration
     * - Partial reads of multi-word fields (name, value)
     * - TOCTOU: env_table[i].in_use could change between check and use
     *=========================================================================*/
    CRITICAL_SECTION_ENTER();

    int count = 0;

    for (int i = 0; i < ENV_MAX_VARS; i++) {
        if (env_table[i].in_use) {
            if (!exported_only || env_table[i].exported) {
                kprintf("%s=%s\n", env_table[i].name, env_table[i].value);
                count++;
            }
        }
    }

    if (count == 0) {
        kprintf("(no variables)\n");
    }

    CRITICAL_SECTION_EXIT();
}

/*=============================================================================
 * Variable Expansion
 *=============================================================================*/

int env_expand(const char* input, char* output, size_t output_size) {
    if (!input || !output || output_size == 0) {
        return -1;
    }

    const char* src = input;
    char* dst = output;
    size_t remaining = output_size - 1;  /* Reserve space for null terminator */

    while (*src && remaining > 0) {
        if (*src == '$') {
            src++;  /* Skip '$' */

            /* Check for $$ (PID) - not implemented yet, just use 1 */
            if (*src == '$') {
                *dst++ = '1';
                remaining--;
                src++;
                continue;
            }

            /* Extract variable name */
            char var_name[ENV_MAX_NAME_LEN];
            int var_idx = 0;
            bool braces = false;

            /* Check for ${VAR} syntax */
            if (*src == '{') {
                braces = true;
                src++;
            }

            /* Read variable name */
            while (*src && var_idx < ENV_MAX_NAME_LEN - 1) {
                char c = *src;

                if (braces) {
                    /* Inside ${...}, read until '}' */
                    if (c == '}') {
                        src++;
                        break;
                    }
                    var_name[var_idx++] = c;
                    src++;
                } else {
                    /* Without braces, read alphanumeric + underscore */
                    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '_') {
                        var_name[var_idx++] = c;
                        src++;
                    } else {
                        break;
                    }
                }
            }

            var_name[var_idx] = '\0';

            /* Look up variable */
            const char* value = env_get(var_name);
            if (value) {
                /* Copy variable value to output */
                while (*value && remaining > 0) {
                    *dst++ = *value++;
                    remaining--;
                }
            }
            /* If variable not found, expand to empty string */

        } else {
            /* Regular character */
            *dst++ = *src++;
            remaining--;
        }
    }

    *dst = '\0';

    /* Check for buffer overflow */
    if (*src != '\0') {
        return -1;  /* Output buffer too small */
    }

    return 0;
}

/*=============================================================================
 * PATH Variable Support
 *=============================================================================*/

int env_find_in_path(const char* command, char* resolved_path, size_t path_size) {
    if (!command || !resolved_path || path_size == 0) {
        return -1;
    }

    /* If command contains '/', it's already a path */
    if (strchr(command, '/')) {
        my_strncpy(resolved_path, command, path_size - 1);
        resolved_path[path_size - 1] = '\0';
        return 0;
    }

    /* Get PATH variable */
    const char* path = env_get("PATH");
    if (!path) {
        return -1;
    }

    /* PATH is colon-separated list of directories */
    char path_copy[ENV_MAX_VALUE_LEN];
    my_strncpy(path_copy, path, ENV_MAX_VALUE_LEN - 1);
    path_copy[ENV_MAX_VALUE_LEN - 1] = '\0';

    char* dir = path_copy;
    char* next;

    while (dir) {
        /* Find next colon */
        next = strchr(dir, ':');
        if (next) {
            *next = '\0';
            next++;
        }

        /* Build full path: dir/command */
        char full_path[256];
        size_t dir_len = strlen(dir);
        size_t cmd_len = strlen(command);

        if (dir_len + cmd_len + 2 < sizeof(full_path)) {
            /* Copy directory - SECURITY FIX: use safe_strcpy */
            safe_strcpy(full_path, dir, sizeof(full_path));

            /* Add slash if needed */
            if (dir_len > 0 && full_path[dir_len - 1] != '/') {
                full_path[dir_len] = '/';
                full_path[dir_len + 1] = '\0';
            }

            /* Append command - SECURITY FIX: use safe_strcpy with offset */
            size_t current_len = strlen(full_path);
            safe_strcpy(full_path + current_len, command, sizeof(full_path) - current_len);

            /* TODO: Check if file exists (requires filesystem support) */
            /* For now, just return the first candidate */
            my_strncpy(resolved_path, full_path, path_size - 1);
            resolved_path[path_size - 1] = '\0';
            return 0;
        }

        dir = next;
    }

    return -1;  /* Not found in PATH */
}

/*=============================================================================
 * Alias Support
 *=============================================================================*/

/**
 * @brief Find an alias by name
 * @return Index in alias_table, or -1 if not found
 */
/**
 * SECURITY FIX: Use size_t for loop counter to prevent signed/unsigned UB
 * Cast to int only for the return value where -1 indicates failure.
 * This prevents potential wrap-around if a negative index other than -1
 * were to be used for array access (which would convert to huge unsigned).
 */
static int alias_find(const char* name) {
    if (!name) {
        return -1;
    }

    for (size_t i = 0; i < ALIAS_MAX_COUNT; i++) {
        if (alias_table[i].in_use && strcmp(alias_table[i].name, name) == 0) {
            return (int)i;  /* Safe: i is always < ALIAS_MAX_COUNT */
        }
    }

    return -1;
}

/**
 * @brief Find an empty slot in the alias table
 * @return Index of empty slot, or -1 if table is full
 * SECURITY FIX: Use size_t for loop counter (same reasoning as alias_find)
 */
static int alias_find_empty(void) {
    for (size_t i = 0; i < ALIAS_MAX_COUNT; i++) {
        if (!alias_table[i].in_use) {
            return (int)i;  /* Safe: i is always < ALIAS_MAX_COUNT */
        }
    }
    return -1;
}

int alias_set(const char* name, const char* command) {
    if (!name || !command) {
        return -1;
    }

    /* Validate name length */
    size_t name_len = strlen(name);
    if (name_len == 0 || name_len >= ALIAS_MAX_NAME_LEN) {
        return -1;
    }

    /* Validate command length */
    size_t cmd_len = strlen(command);
    if (cmd_len >= ALIAS_MAX_CMD_LEN) {
        return -1;
    }

    CRITICAL_SECTION_ENTER();  /* SECURITY: Protect alias table state */

    /* Check if alias already exists */
    int idx = alias_find(name);
    if (idx >= 0) {
        /* SECURITY FIX: Explicit bounds validation before array access
         * Even though alias_find should never return idx >= ALIAS_MAX_COUNT,
         * this defensive check prevents UB if there's a logic error.
         */
        if ((size_t)idx >= ALIAS_MAX_COUNT) {
            CRITICAL_SECTION_EXIT();
            return -1;  /* Invalid index */
        }
        /* Update existing alias */
        my_strncpy(alias_table[idx].command, command, ALIAS_MAX_CMD_LEN - 1);
        alias_table[idx].command[ALIAS_MAX_CMD_LEN - 1] = '\0';
        CRITICAL_SECTION_EXIT();
        return 0;
    }

    /* Find empty slot */
    idx = alias_find_empty();
    if (idx < 0) {
        CRITICAL_SECTION_EXIT();
        return -1;  /* Table full */
    }

    /* SECURITY FIX: Explicit bounds validation */
    if ((size_t)idx >= ALIAS_MAX_COUNT) {
        CRITICAL_SECTION_EXIT();
        return -1;  /* Invalid index */
    }

    /* Create new alias */
    my_strncpy(alias_table[idx].name, name, ALIAS_MAX_NAME_LEN - 1);
    alias_table[idx].name[ALIAS_MAX_NAME_LEN - 1] = '\0';

    my_strncpy(alias_table[idx].command, command, ALIAS_MAX_CMD_LEN - 1);
    alias_table[idx].command[ALIAS_MAX_CMD_LEN - 1] = '\0';

    alias_table[idx].in_use = true;

    CRITICAL_SECTION_EXIT();
    return 0;
}

const char* alias_get(const char* name) {
    CRITICAL_SECTION_ENTER();  /* SECURITY: Protect alias table reads */

    int idx = alias_find(name);
    const char* result = NULL;
    if (idx >= 0) {
        /* SECURITY FIX: Bounds validation before array access */
        if ((size_t)idx < ALIAS_MAX_COUNT) {
            result = alias_table[idx].command;
        }
    }

    CRITICAL_SECTION_EXIT();
    return result;
}

int alias_unset(const char* name) {
    CRITICAL_SECTION_ENTER();  /* SECURITY: Protect alias table state */

    int idx = alias_find(name);
    if (idx < 0) {
        CRITICAL_SECTION_EXIT();
        return -1;
    }

    /* SECURITY FIX: Bounds validation before array access */
    if ((size_t)idx >= ALIAS_MAX_COUNT) {
        CRITICAL_SECTION_EXIT();
        return -1;
    }

    alias_table[idx].in_use = false;
    alias_table[idx].name[0] = '\0';
    alias_table[idx].command[0] = '\0';

    CRITICAL_SECTION_EXIT();
    return 0;
}

void alias_list(void) {
    /*=========================================================================
     * SECURITY FIX: Add Critical Section Protection
     * CRITICAL: Iterates over global alias_table without locking.
     * Race condition if another thread modifies alias_table during iteration.
     *=========================================================================*/
    CRITICAL_SECTION_ENTER();

    int count = 0;

    /* SECURITY FIX: Use size_t for loop counter (consistent with other loops) */
    for (size_t i = 0; i < ALIAS_MAX_COUNT; i++) {
        if (alias_table[i].in_use) {
            kprintf("alias %s='%s'\n", alias_table[i].name, alias_table[i].command);
            count++;
        }
    }

    if (count == 0) {
        kprintf("(no aliases)\n");
    }

    CRITICAL_SECTION_EXIT();
}

bool alias_exists(const char* name) {
    /*=========================================================================
     * SECURITY FIX: Add Critical Section Protection
     * CRITICAL: alias_find() accesses global alias_table without locking.
     * Race condition if another thread modifies alias_table during lookup.
     *=========================================================================*/
    CRITICAL_SECTION_ENTER();
    bool result = (alias_find(name) >= 0);
    CRITICAL_SECTION_EXIT();
    return result;
}
