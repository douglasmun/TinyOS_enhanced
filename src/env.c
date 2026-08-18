/*=============================================================================
 * env.c - Environment Variable Management Implementation
 *=============================================================================*/
#include "env.h"
#include "util.h"
#include "kprintf.h"
#include "critical.h"
#include "stdio.h"  /* stream_printf / get_current_streams */
#include "process.h"
#include "pmm.h"
#include "scheduler.h"
#include "user.h"   /* user_find_by_uid, for env_refresh_identity */
#include <stddef.h>

/*=============================================================================
 * Per-Task Storage
 *
 * There is no global table any more. Each task owns an env_state_t page,
 * allocated on first write and freed in task_free_resources().
 *
 * env_state() resolves the CALLING task's page. Two cases return NULL and both
 * are normal, not errors:
 *   - no current task (boot-time / interrupt context)
 *   - the task has never written a variable
 * Every reader treats NULL as "empty", so lookups simply miss. Only the
 * writers call env_state_alloc(), which is where the page comes from.
 *=============================================================================*/

static env_state_t* env_state(void) {
    task_t* t = scheduler_get_current_task();
    return t ? t->env : NULL;
}

/**
 * @brief Resolve the current task's env page, allocating it if needed
 * @return The page, or NULL if there is no current task or no free memory
 *
 * The page is NOT zeroed by pmm_alloc(), so it is cleared here. Skipping that
 * leaves in_use holding whatever the previous owner of the frame wrote, which
 * presents as a task booting with a table full of garbage variables.
 */
static env_state_t* env_state_alloc(void) {
    task_t* t = scheduler_get_current_task();
    if (!t) {
        return NULL;
    }
    if (!t->env) {
        env_state_t* s = (env_state_t*)pmm_alloc();
        if (!s) {
            return NULL;
        }
        memset(s, 0, sizeof(env_state_t));
        t->env = s;
    }
    return t->env;
}

/*=============================================================================
 * Per-Task Isolation Self-Test
 *
 * See env_pertask_self_test() in env.h for why this exists rather than a
 * shell-driven check.
 *
 * The helper task sets ENVSELFTEST to its own marker and records what it saw
 * of the PARENT's variable. Communication is via these file-scope flags, not
 * the env tables, which are the thing under test.
 *===========================================================================*/
static volatile bool env_selftest_child_done = false;
static volatile bool env_selftest_child_saw_parent_var = false;
static volatile bool env_selftest_child_set_ok = false;

static volatile bool env_selftest_heir_done = false;
static volatile bool env_selftest_heir_saw_exported = false;
static volatile bool env_selftest_heir_saw_private = false;

/* Second child, used for the INHERITANCE half. It differs from
 * env_selftest_child only in how it is created: the parent runs
 * env_inherit_exported() over it first, exactly as sys_spawn and cmd_exec do.
 * task_create_kernel() itself never inherits, which is precisely why the first
 * child is a clean isolation probe and this one is not. */
static void env_selftest_heir(void) {
    char buf[ENV_MAX_VALUE_LEN];

    /* Must see the EXPORTED variable... */
    env_selftest_heir_saw_exported =
        env_get("ENVEXPORTED", buf, sizeof(buf)) && strcmp(buf, "crossed") == 0;

    /* ...and must NOT see the un-exported one. Without this second clause a
     * copy that ignored the exported flag and cloned the whole table would
     * pass: "inherited everything" and "inherited what was exported" are the
     * same observation when you only look at an exported variable. */
    env_selftest_heir_saw_private = env_get("ENVPRIVATE", buf, sizeof(buf));

    task_t* self = scheduler_get_current_task();
    uint32_t self_pid = self ? self->pid : 0;

    env_selftest_heir_done = true;

    if (self_pid) {
        task_terminate(self_pid);
    }
    for (;;) {
        scheduler_yield();
    }
}

static void env_selftest_child(void) {
    char buf[ENV_MAX_VALUE_LEN];

    /* The parent set ENVSELFTEST=parent before spawning us. Under per-task
     * storage we must NOT see it; under the old global table we would. */
    env_selftest_child_saw_parent_var = env_get("ENVSELFTEST", buf, sizeof(buf));

    /* And we must be able to set our own, which proves this task really got a
     * table of its own rather than failing to allocate one (a task that can
     * see nothing AND set nothing would otherwise pass the check above for
     * entirely the wrong reason). */
    env_selftest_child_set_ok = (env_set("ENVSELFTEST", "child") == 0);

    /* Capture the pid BEFORE signalling done, and terminate via
     * task_terminate(): task_exit() is inert for scheduler-run tasks (it reads
     * process.c's current_task, set only by task_switch_to). */
    task_t* self = scheduler_get_current_task();
    uint32_t self_pid = self ? self->pid : 0;

    env_selftest_child_done = true;

    if (self_pid) {
        task_terminate(self_pid);
    }
    for (;;) {
        scheduler_yield();
    }
}

bool env_pertask_self_test(void) {
    char buf[ENV_MAX_VALUE_LEN];

    env_selftest_child_done = false;
    env_selftest_child_saw_parent_var = false;
    env_selftest_child_set_ok = false;

    if (env_set("ENVSELFTEST", "parent") != 0) {
        kprintf("[ENV] self-test INCONCLUSIVE: parent could not set a variable\n");
        return false;
    }

    int pid = task_create_kernel(env_selftest_child, "envtest");
    if (pid < 0) {
        kprintf("[ENV] self-test INCONCLUSIVE: could not create helper task\n");
        return false;
    }

    /* task_create_kernel() allocates but does NOT enqueue -- without this the
     * helper is listed by ps and never runs one instruction, and the test
     * below would time out reporting a failure that never happened. */
    task_t* child = task_get((uint32_t)pid);
    if (!child) {
        kprintf("[ENV] self-test INCONCLUSIVE: helper task vanished\n");
        return false;
    }
    scheduler_add_task(child);

    /* Bounded wait; the helper is a few instructions of work. */
    for (int spins = 0; spins < 100000 && !env_selftest_child_done; spins++) {
        scheduler_yield();
    }

    if (!env_selftest_child_done) {
        kprintf("[ENV] self-test INCONCLUSIVE: helper task never ran\n");
        return false;
    }

    bool parent_intact = env_get("ENVSELFTEST", buf, sizeof(buf)) &&
                         strcmp(buf, "parent") == 0;

    bool ok = !env_selftest_child_saw_parent_var &&
              env_selftest_child_set_ok &&
              parent_intact;

    kprintf("[ENV] per-task self-test: child saw parent's var: %s | "
            "child set its own: %s | parent's var intact: %s => %s\n",
            env_selftest_child_saw_parent_var ? "YES (BAD)" : "no (good)",
            env_selftest_child_set_ok ? "yes (good)" : "NO (BAD)",
            parent_intact ? "yes (good)" : "NO (BAD)",
            ok ? "PASS" : "FAIL");

    /*=====================================================================
     * Part 2: INHERITANCE. Isolation above and inheritance here are opposite
     * requirements against the same storage -- a build that shares one page
     * passes inheritance trivially and fails isolation, and a build that never
     * copies passes isolation and fails inheritance. Only doing both pins the
     * design. Reported as its own line so which half broke is unambiguous.
     *===================================================================*/
    env_selftest_heir_done = false;
    env_selftest_heir_saw_exported = false;
    env_selftest_heir_saw_private = false;

    bool inherit_ok = false;

    if (env_set("ENVEXPORTED", "crossed") != 0 ||
        env_export("ENVEXPORTED") != 0 ||
        env_set("ENVPRIVATE", "local") != 0) {
        kprintf("[ENV] inheritance self-test INCONCLUSIVE: could not stage variables\n");
        return false;
    }

    int hpid = task_create_kernel(env_selftest_heir, "envheir");
    task_t* heir = (hpid >= 0) ? task_get((uint32_t)hpid) : NULL;
    if (!heir) {
        kprintf("[ENV] inheritance self-test INCONCLUSIVE: could not create heir task\n");
        return false;
    }

    /* The step under test. task_create_kernel() does NOT inherit on its own --
     * that is what makes the first child a clean isolation probe -- so this
     * mirrors what sys_spawn and cmd_exec do, and must happen BEFORE the task
     * is made runnable. */
    task_t* self_task = scheduler_get_current_task();
    env_inherit_exported(self_task, heir);

    scheduler_add_task(heir);

    for (int spins = 0; spins < 100000 && !env_selftest_heir_done; spins++) {
        scheduler_yield();
    }

    if (!env_selftest_heir_done) {
        kprintf("[ENV] inheritance self-test INCONCLUSIVE: heir task never ran\n");
        return false;
    }

    inherit_ok = env_selftest_heir_saw_exported && !env_selftest_heir_saw_private;

    kprintf("[ENV] inheritance self-test: heir got exported var: %s | "
            "heir got un-exported var: %s => %s\n",
            env_selftest_heir_saw_exported ? "yes (good)" : "NO (BAD)",
            env_selftest_heir_saw_private ? "YES (BAD)" : "no (good)",
            inherit_ok ? "PASS" : "FAIL");

    /* Leave the caller's table as we found it. sectest runs from an interactive
     * shell, and three scratch variables surviving in the user's `env` output
     * is a visible side effect of running a test. */
    env_unset("ENVSELFTEST");
    env_unset("ENVEXPORTED");
    env_unset("ENVPRIVATE");

    return ok && inherit_ok;
}

void env_inherit_exported(void* parent_task, void* child_task) {
    task_t* p = (task_t*)parent_task;
    task_t* c = (task_t*)child_task;

    if (!p || !c || !p->env) {
        return;
    }

    /* Allocate the child's page HERE rather than through env_state_alloc(),
     * which resolves scheduler_get_current_task() -- and the current task at
     * this point is the PARENT doing the spawning, not the child being built.
     * Calling it would hand the parent's own page back and copy it onto
     * itself. */
    if (!c->env) {
        env_state_t* s = (env_state_t*)pmm_alloc();
        if (!s) {
            return;                     /* Child simply starts with no variables */
        }
        memset(s, 0, sizeof(env_state_t));
        c->env = s;
    }

    /* Only EXPORTED variables cross, which is the entire point of the flag: a
     * shell-local `set FOO=x` stays local, an `export FOO` reaches children.
     *
     * Aliases are deliberately NOT inherited. They are an interactive
     * convenience of the shell that defined them and have no meaning to a
     * spawned binary, which never consults the alias table -- substitution
     * happens in shell.c before the command is dispatched. bash does not export
     * them either.
     *
     * This is a SNAPSHOT, not a shared page: a later change in either task is
     * invisible to the other. That is both the Unix contract and what keeps the
     * per-task isolation the rest of this file establishes -- inheritance that
     * shared the page would undo it entirely.
     *
     * The bound on j is what makes a full parent table safe: a parent with all
     * ENV_MAX_VARS exported fills the child exactly and stops. */
    CRITICAL_SECTION_ENTER();
    for (int i = 0, j = 0; i < ENV_MAX_VARS && j < ENV_MAX_VARS; i++) {
        if (!p->env->vars[i].in_use || !p->env->vars[i].exported) {
            continue;
        }
        SAFE_STRNCPY(c->env->vars[j].name, p->env->vars[i].name, ENV_MAX_NAME_LEN);
        SAFE_STRNCPY(c->env->vars[j].value, p->env->vars[i].value, ENV_MAX_VALUE_LEN);
        c->env->vars[j].exported = true;
        c->env->vars[j].in_use = true;
        j++;
    }
    CRITICAL_SECTION_EXIT();
}

void env_free_for_task(void* task) {
    task_t* t = (task_t*)task;
    if (t && t->env) {
        pmm_free((uint32_t)t->env);
        t->env = NULL;
    }
}

/*=============================================================================
 * String Helper Functions
 * SECURITY FIX: Removed unsafe my_strcpy/my_strncpy; use SAFE_STRNCPY (strlcpy
 * semantics, always null-terminates) from util.h instead.
 *=============================================================================*/

/*=============================================================================
 * Helper Functions
 *=============================================================================*/

/**
 * @brief Find a variable by name
 * @return Index in env_table, or -1 if not found
 */
static int env_find(env_state_t* s, const char* name) {
    if (!s || !name) {
        return -1;
    }

    for (int i = 0; i < ENV_MAX_VARS; i++) {
        if (s->vars[i].in_use && strcmp(s->vars[i].name, name) == 0) {
            return i;
        }
    }

    return -1;
}

/**
 * @brief Find an empty slot in the environment table
 * @return Index of empty slot, or -1 if table is full
 */
static int env_find_empty(env_state_t* s) {
    if (!s) {
        return -1;
    }
    for (int i = 0; i < ENV_MAX_VARS; i++) {
        if (!s->vars[i].in_use) {
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
    /* Allocate this task's page if it has none, and start from a clean table.
     * Nothing to do if there is no current task or no memory -- every reader
     * below treats an absent table as empty, so the shell degrades to "no
     * variables" rather than faulting. */
    env_state_t* s = env_state_alloc();
    if (!s) {
        return;
    }

    CRITICAL_SECTION_ENTER();
    memset(s, 0, sizeof(env_state_t));
    CRITICAL_SECTION_EXIT();

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

    /* Set up useful default aliases (bash-like).
     *
     * TWELVE of ALIAS_MAX_COUNT (16), deliberately -- see ALIAS_DEFAULT_COUNT
     * in env.h. This list was sixteen, which filled the table exactly to
     * capacity and left a user's own `alias` with nowhere to go: every such
     * command failed with "table full" against a table that looked, to the
     * user, like it held nothing of theirs. Four free slots is the point of
     * the number, so keep the count below the max if you add one here.
     *
     * The four dropped were the redundant ones: `l` (duplicate of `ll`/`la`),
     * `k` (kill is five characters), `...` (`cd ../..`), and `please`, an
     * easter egg aliasing a sudo this kernel does not implement. */
    alias_set("ll", "ls -l");
    alias_set("la", "ls -a");
    alias_set("cls", "clear");
    alias_set("dir", "ls");
    alias_set("copy", "cp");
    alias_set("move", "mv");
    alias_set("del", "rm");
    alias_set("md", "mkdir");
    alias_set("rd", "rm -r");
    alias_set("type", "cat");
    alias_set("..", "cd ..");
    alias_set("h", "history");
}

void env_refresh_identity(void) {
    task_t* self = scheduler_get_current_task();
    if (!self) {
        return;
    }

    user_account_t* acct = user_find_by_uid(self->uid);
    if (!acct) {
        return;
    }

    /* Real uid, not euid: $USER is who you ARE, not what you are momentarily
     * authorized as. self->uid is what su commits via sys_setuid. */
    env_set("USER", acct->username);
    env_export("USER");
    env_set("HOME", acct->uid == 0 ? "/" : "/home");
    env_export("HOME");
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

    /* Allocate outside the critical section: pmm_alloc() must not run with
     * interrupts masked, and this is the first write for a fresh task. */
    env_state_t* s = env_state_alloc();
    if (!s) {
        return -1;
    }

    CRITICAL_SECTION_ENTER();  /* SECURITY: Protect env table state */

    /* Check if variable already exists */
    int idx = env_find(s, name);
    if (idx >= 0) {
        /* Update existing variable */
        SAFE_STRNCPY(s->vars[idx].value, value, ENV_MAX_VALUE_LEN);
        CRITICAL_SECTION_EXIT();
        return 0;
    }

    /* Find empty slot */
    idx = env_find_empty(s);
    if (idx < 0) {
        CRITICAL_SECTION_EXIT();
        return -1;  /* Table full */
    }

    /* Create new variable */
    SAFE_STRNCPY(s->vars[idx].name, name, ENV_MAX_NAME_LEN);
    SAFE_STRNCPY(s->vars[idx].value, value, ENV_MAX_VALUE_LEN);

    s->vars[idx].exported = false;
    s->vars[idx].in_use = true;

    CRITICAL_SECTION_EXIT();
    return 0;
}

bool env_get(const char* name, char* out, size_t out_size) {
    if (!out || out_size == 0) {
        return false;
    }

    env_state_t* s = env_state();

    CRITICAL_SECTION_ENTER();  /* SECURITY: Protect env table reads */

    int idx = env_find(s, name);
    bool found = (idx >= 0);
    if (found) {
        /* Copy INSIDE the lock. The old version returned s->vars[idx].value
         * to the caller after unlocking, leaving them reading a slot another
         * task could rewrite or free. */
        SAFE_STRNCPY(out, s->vars[idx].value, out_size);
    }

    CRITICAL_SECTION_EXIT();
    return found;
}

int env_unset(const char* name) {
    env_state_t* s = env_state();

    CRITICAL_SECTION_ENTER();  /* SECURITY: Protect env table state */

    int idx = env_find(s, name);
    if (idx < 0) {
        CRITICAL_SECTION_EXIT();
        return -1;
    }

    s->vars[idx].in_use = false;
    s->vars[idx].exported = false;
    s->vars[idx].name[0] = '\0';
    s->vars[idx].value[0] = '\0';

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
    env_state_t* s = env_state();

    CRITICAL_SECTION_ENTER();  /* SECURITY: Protect env table state */

    int idx = env_find(s, name);
    if (idx < 0) {
        CRITICAL_SECTION_EXIT();
        return -1;
    }

    s->vars[idx].exported = true;

    CRITICAL_SECTION_EXIT();
    return 0;
}

bool env_exists(const char* name) {
    /*=========================================================================
     * SECURITY FIX: Add Critical Section Protection
     * CRITICAL: env_find() accesses global env_table without locking.
     * Race condition if another thread modifies env_table during lookup.
     *=========================================================================*/
    env_state_t* s = env_state();
    CRITICAL_SECTION_ENTER();
    bool result = (env_find(s, name) >= 0);
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
    /* The lock is taken and dropped once per slot rather than held across the
     * whole listing, because the printing now goes through stream_printf: on a
     * redirected stream that reaches ramfs_write, which is far too much work to
     * run with interrupts masked and can take a mutex of its own. One entry is
     * copied out under the lock and printed after it, so the table is never read
     * unlocked and no I/O happens inside the critical section. The trade is that
     * a variable added mid-listing may or may not appear -- acceptable for a
     * listing, unlike the torn name/value read the lock is actually there for. */
    stream_context_t* ctx = get_current_streams();
    env_state_t* s = env_state();
    env_var_t entry;
    int count = 0;

    for (int i = 0; s && i < ENV_MAX_VARS; i++) {
        bool show;

        CRITICAL_SECTION_ENTER();
        show = s->vars[i].in_use && (!exported_only || s->vars[i].exported);
        if (show) {
            entry = s->vars[i];
        }
        CRITICAL_SECTION_EXIT();

        if (show) {
            stream_printf(ctx, "%s=%s\n", entry.name, entry.value);
            count++;
        }
    }

    if (count == 0) {
        stream_printf(ctx, "(no variables)\n");
    }
}

bool env_get_by_index(size_t index, char* name_out, size_t name_size,
                      char* value_out, size_t value_size, bool* exported_out) {
    if (!name_out || !value_out || !exported_out || index >= ENV_MAX_VARS) {
        return false;
    }

    env_state_t* s = env_state();
    if (!s) {
        return false;
    }

    CRITICAL_SECTION_ENTER();

    bool found = s->vars[index].in_use;
    if (found) {
        /* Copied inside the lock, like env_get(), and for the same reason. */
        SAFE_STRNCPY(name_out, s->vars[index].name, name_size);
        SAFE_STRNCPY(value_out, s->vars[index].value, value_size);
        *exported_out = s->vars[index].exported;
    }

    CRITICAL_SECTION_EXIT();
    return found;
}

bool alias_get_by_index(size_t index, char* name_out, size_t name_size,
                        char* cmd_out, size_t cmd_size) {
    if (!name_out || !cmd_out || index >= ALIAS_MAX_COUNT) {
        return false;
    }

    env_state_t* s = env_state();
    if (!s) {
        return false;
    }

    CRITICAL_SECTION_ENTER();

    bool found = s->aliases[index].in_use;
    if (found) {
        SAFE_STRNCPY(name_out, s->aliases[index].name, name_size);
        SAFE_STRNCPY(cmd_out, s->aliases[index].command, cmd_size);
    }

    CRITICAL_SECTION_EXIT();
    return found;
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
            char value[ENV_MAX_VALUE_LEN];
            if (env_get(var_name, value, sizeof(value))) {
                /* Copy variable value to output */
                const char* v = value;
                while (*v && remaining > 0) {
                    *dst++ = *v++;
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
        SAFE_STRNCPY(resolved_path, command, path_size);
        return 0;
    }

    /* Get PATH variable. PATH is a colon-separated list of directories; the
     * copy-out lands straight in the buffer this function was going to make
     * anyway, so the strtok-style walk below is unchanged. */
    char path_copy[ENV_MAX_VALUE_LEN];
    if (!env_get("PATH", path_copy, sizeof(path_copy))) {
        return -1;
    }

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
            SAFE_STRNCPY(resolved_path, full_path, path_size);
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
static int alias_find(env_state_t* s, const char* name) {
    if (!s || !name) {
        return -1;
    }

    for (size_t i = 0; i < ALIAS_MAX_COUNT; i++) {
        if (s->aliases[i].in_use && strcmp(s->aliases[i].name, name) == 0) {
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
static int alias_find_empty(env_state_t* s) {
    if (!s) {
        return -1;
    }
    for (size_t i = 0; i < ALIAS_MAX_COUNT; i++) {
        if (!s->aliases[i].in_use) {
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

    /* Allocate outside the critical section (see env_set). */
    env_state_t* s = env_state_alloc();
    if (!s) {
        return -1;
    }

    CRITICAL_SECTION_ENTER();  /* SECURITY: Protect alias table state */

    /* Check if alias already exists */
    int idx = alias_find(s, name);
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
        SAFE_STRNCPY(s->aliases[idx].command, command, ALIAS_MAX_CMD_LEN);
        CRITICAL_SECTION_EXIT();
        return 0;
    }

    /* Find empty slot */
    idx = alias_find_empty(s);
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
    SAFE_STRNCPY(s->aliases[idx].name, name, ALIAS_MAX_NAME_LEN);
    SAFE_STRNCPY(s->aliases[idx].command, command, ALIAS_MAX_CMD_LEN);

    s->aliases[idx].in_use = true;

    CRITICAL_SECTION_EXIT();
    return 0;
}

bool alias_get(const char* name, char* out, size_t out_size) {
    if (!out || out_size == 0) {
        return false;
    }

    env_state_t* s = env_state();

    CRITICAL_SECTION_ENTER();  /* SECURITY: Protect alias table reads */

    int idx = alias_find(s, name);
    bool found = false;
    if (idx >= 0) {
        /* SECURITY FIX: Bounds validation before array access */
        if ((size_t)idx < ALIAS_MAX_COUNT) {
            /* Copy inside the lock -- see env_get(). */
            SAFE_STRNCPY(out, s->aliases[idx].command, out_size);
            found = true;
        }
    }

    CRITICAL_SECTION_EXIT();
    return found;
}

int alias_unset(const char* name) {
    env_state_t* s = env_state();

    CRITICAL_SECTION_ENTER();  /* SECURITY: Protect alias table state */

    int idx = alias_find(s, name);
    if (idx < 0) {
        CRITICAL_SECTION_EXIT();
        return -1;
    }

    /* SECURITY FIX: Bounds validation before array access */
    if ((size_t)idx >= ALIAS_MAX_COUNT) {
        CRITICAL_SECTION_EXIT();
        return -1;
    }

    s->aliases[idx].in_use = false;
    s->aliases[idx].name[0] = '\0';
    s->aliases[idx].command[0] = '\0';

    CRITICAL_SECTION_EXIT();
    return 0;
}

void alias_list(void) {
    /*=========================================================================
     * SECURITY FIX: Add Critical Section Protection
     * CRITICAL: Iterates over global alias_table without locking.
     * Race condition if another thread modifies alias_table during iteration.
     *=========================================================================*/
    /* Per-slot locking, printing outside the lock -- same reasoning as
     * env_list() above. */
    stream_context_t* ctx = get_current_streams();
    env_state_t* s = env_state();
    char name[ALIAS_MAX_NAME_LEN];
    char command[ALIAS_MAX_CMD_LEN];
    int count = 0;

    /* SECURITY FIX: Use size_t for loop counter (consistent with other loops) */
    for (size_t i = 0; s && i < ALIAS_MAX_COUNT; i++) {
        bool show;

        CRITICAL_SECTION_ENTER();
        show = s->aliases[i].in_use;
        if (show) {
            memcpy(name, s->aliases[i].name, sizeof(name));
            memcpy(command, s->aliases[i].command, sizeof(command));
        }
        CRITICAL_SECTION_EXIT();

        if (show) {
            stream_printf(ctx, "alias %s='%s'\n", name, command);
            count++;
        }
    }

    if (count == 0) {
        stream_printf(ctx, "(no aliases)\n");
    }
}

bool alias_exists(const char* name) {
    /*=========================================================================
     * SECURITY FIX: Add Critical Section Protection
     * CRITICAL: alias_find() accesses global alias_table without locking.
     * Race condition if another thread modifies alias_table during lookup.
     *=========================================================================*/
    env_state_t* s = env_state();
    CRITICAL_SECTION_ENTER();
    bool result = (alias_find(s, name) >= 0);
    CRITICAL_SECTION_EXIT();
    return result;
}
