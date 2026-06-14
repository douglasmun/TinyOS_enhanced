/*=============================================================================
 * shell.c - Simple Kernel Shell Implementation
 *=============================================================================*/
#include "kernel.h"
#include "kprintf.h"
#include "keyboard.h"
#include "scheduler.h"
#include "util.h"
#include "env.h"
#include "shell_fileops.h"
#include "shell_search.h"
#include "shell_monitor.h"
#include "shell_history.h"
#include "shell_network.h"
#include "shell_system.h"
#include "shell_redir.h"
#include "shell_user.h"  /* User management commands (v1.10) */
#include "ramfs.h"
#include "stdio.h"

#define SHELL_BUFFER_SIZE 256
#define MAX_ARGS 10

/*-----------------------------------------------------------------------------
 * Command table — SINGLE SOURCE OF TRUTH for the help text.
 *
 * Every user-facing command is listed here exactly once with its category and
 * one-line summary. cmd_help() iterates this table, so per-category help and
 * `help all` can never drift from each other again (they used to be three
 * hand-maintained lists, which is how `sshd` lingered in help after removal).
 * The dispatch chain in parse_and_execute() stays explicit (tested control
 * flow), but anything advertised to the user must appear here.
 *---------------------------------------------------------------------------*/
typedef enum {
    CAT_FILE,
    CAT_DRIVE,
    CAT_NET,
    CAT_SYS,
    CAT_SECURITY,
    CAT_USER,
    CAT_SESSION,
} cmd_category_t;

typedef struct {
    const char* name;
    cmd_category_t category;
    const char* usage;     /* short usage shown in per-category help */
    const char* summary;
} shell_command_t;

static const shell_command_t command_table[] = {
    /* File & Directory */
    { "cd",      CAT_FILE, "cd <path>",          "Change current directory" },
    { "pwd",     CAT_FILE, "pwd",                "Print working directory" },
    { "ls",      CAT_FILE, "ls [-l] [path]",     "List directory contents" },
    { "cat",     CAT_FILE, "cat [-n] <file>",    "Display file contents" },
    { "edit",    CAT_FILE, "edit <file>",        "Edit file in text editor" },
    { "mkdir",   CAT_FILE, "mkdir [-p] <path>",  "Create directory" },
    { "touch",   CAT_FILE, "touch <file>",       "Create empty file" },
    { "write",   CAT_FILE, "write <file> <text>","Write text to file" },
    { "rm",      CAT_FILE, "rm [-r] <file>",     "Delete file or directory" },
    { "cp",      CAT_FILE, "cp <src> <dst>",     "Copy file" },
    { "mv",      CAT_FILE, "mv <src> <dst>",     "Move/rename file" },
    { "chmod",   CAT_FILE, "chmod <mode> <file>","Change file permissions" },
    { "grep",    CAT_FILE, "grep <pattern> [files]", "Search for pattern in files" },
    { "find",    CAT_FILE, "find [pattern]",     "Find files by name pattern" },
    { "exec",    CAT_FILE, "exec <file>",        "Execute ELF binary" },

    /* Drive Management */
    { "mount",   CAT_DRIVE, "mount",             "Show mounted drives (C:=FAT32, D:=RAMFS)" },
    { "fatls",   CAT_DRIVE, "fatls",             "List files on C: drive (FAT32)" },

    /* Network */
    { "ifconfig",CAT_NET, "ifconfig",            "Show network configuration" },
    { "ping",    CAT_NET, "ping <host>",         "Send ICMP ping to host" },
    { "dig",     CAT_NET, "dig <hostname>",      "DNS lookup utility" },
    { "dhcp",    CAT_NET, "dhcp [renew]",        "Show DHCP status / renew lease" },
    { "curl",    CAT_NET, "curl <url>",          "Fetch HTTP content (http:// optional)" },

    /* System */
    { "clear",   CAT_SYS, "clear",               "Clear the screen" },
    { "echo",    CAT_SYS, "echo [text]",         "Echo arguments back" },
    { "ps",      CAT_SYS, "ps [-a] [-l]",        "Show task information" },
    { "top",     CAT_SYS, "top",                 "Real-time system monitor (press 'q' to quit)" },
    { "mem",     CAT_SYS, "mem",                 "Show memory usage" },
    { "kill",    CAT_SYS, "kill <pid>",          "Terminate a task" },
    { "history", CAT_SYS, "history [n]",         "Show command history" },
    { "man",     CAT_SYS, "man <cmd>",           "Show manual page for command" },
    { "date",    CAT_SYS, "date [opts]",         "Display or set system date/time" },
    { "env",     CAT_SYS, "env",                 "Display environment variables" },
    { "set",     CAT_SYS, "set [VAR=VAL]",       "Set or display shell variables" },
    { "unset",   CAT_SYS, "unset <VAR>",         "Remove environment variable" },
    { "export",  CAT_SYS, "export <VAR>",        "Mark variable for export" },
    { "alias",   CAT_SYS, "alias [name='cmd']",  "Set or display command aliases" },
    { "unalias", CAT_SYS, "unalias <name>",      "Remove command alias" },
    { "shutdown",CAT_SYS, "shutdown",            "Shutdown the system" },
    { "reboot",  CAT_SYS, "reboot",              "Reboot the system" },

    /* Security */
    { "secstatus",CAT_SECURITY, "secstatus",     "Summary of all security subsystems" },
    { "aslr",    CAT_SECURITY, "aslr",           "Show ASLR statistics" },
    { "pae",     CAT_SECURITY, "pae",            "Show PAE/W^X status" },
    { "wxaudit", CAT_SECURITY, "wxaudit",        "Audit W^X violations" },
    { "auditlog",CAT_SECURITY, "auditlog [opts]","View security audit logs" },
    { "sectest", CAT_SECURITY, "sectest",        "Run security hardening test suite" },

    /* User Management */
    { "whoami",  CAT_USER, "whoami",             "Display current username" },
    { "id",      CAT_USER, "id [username]",      "Display user and group IDs" },
    { "passwd",  CAT_USER, "passwd [username]",  "Change password" },
    { "su",      CAT_USER, "su [username]",      "Switch user (default: root)" },
    { "useradd", CAT_USER, "useradd <username>", "Create new user (root only)" },
    { "userdel", CAT_USER, "userdel <username>", "Delete user (root only)" },
    { "users",   CAT_USER, "users",              "List all users" },

    /* Session */
    { "logout",  CAT_SESSION, "logout",          "Logout and return to login prompt" },
    { "exit",    CAT_SESSION, "exit",            "Alias for logout" },
};

#define COMMAND_COUNT (sizeof(command_table) / sizeof(command_table[0]))

/* Returns the table entry for a command name, or NULL if not a known command. */
static const shell_command_t* command_lookup(const char* name) {
    for (size_t i = 0; i < COMMAND_COUNT; i++) {
        if (strcmp(command_table[i].name, name) == 0) {
            return &command_table[i];
        }
    }
    return NULL;
}

static char input_buffer[SHELL_BUFFER_SIZE];
static int buffer_pos = 0;

/* Logout flag - set by logout command to exit shell loop */
static volatile bool should_logout = false;

/* Function prototype */
void shell_task(void);

/*-----------------------------------------------------------------------------
 * Command Handlers
 *---------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
 * COMMAND: logout - Logout and return to login prompt
 *---------------------------------------------------------------------------*/
static void cmd_logout(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    task_t* current = scheduler_get_current_task();
    if (!current) {
        kprintf("Error: No current task\n");
        return;
    }

    kprintf("\nLogging out user: ");
    shell_cmd_whoami(NULL);
    kprintf("\n");

    /* Set logout flag to exit shell loop */
    should_logout = true;
}

/* Category metadata: keyword used in `help <cat>`, heading, and enum value.
 * Order here is the order categories print in `help all`. */
static const struct {
    cmd_category_t cat;
    const char* keyword;
    const char* heading;
} help_categories[] = {
    { CAT_FILE,     "file",     "File & Directory Commands" },
    { CAT_DRIVE,    "drive",    "Drive Management (FAT32)" },
    { CAT_NET,      "net",      "Network Commands" },
    { CAT_SYS,      "sys",      "System Commands" },
    { CAT_SECURITY, "security", "Security Commands" },
    { CAT_USER,     "user",     "User Management Commands" },
    { CAT_SESSION,  "session",  "Session Commands" },
};
#define HELP_CATEGORY_COUNT (sizeof(help_categories) / sizeof(help_categories[0]))

/* Print one category's commands from the table, left-aligned usage + summary. */
static void help_print_category(cmd_category_t cat, const char* heading) {
    kprintf("\n%s:\n", heading);
    for (size_t i = 0; i < strlen(heading) + 1; i++) kprintf("=");
    kprintf("\n");
    for (size_t i = 0; i < COMMAND_COUNT; i++) {
        if (command_table[i].category != cat) continue;
        kprintf("  %s", command_table[i].usage);
        /* pad usage column to ~20 chars for alignment */
        int pad = 20 - (int)strlen(command_table[i].usage);
        for (int s = 0; s < pad; s++) kprintf(" ");
        kprintf(" - %s\n", command_table[i].summary);
    }
}

static void cmd_help(int argc, char* argv[]) {
    if (argc == 1) {
        /* Main help - show categories (bunny stays!) */
        kprintf("\n");
        kprintf("   (\\_/) Need Help?\n");
        kprintf("   (o.o) I'm here!\n");
        kprintf("   (> <)\n");
        kprintf("\n");
        kprintf("TinyOS Shell - Help Categories\n");
        kprintf("==============================\n");
        kprintf("Usage: help [category]\n\n");
        kprintf("Available categories:\n");
        kprintf("  file           - File and directory operations\n");
        kprintf("  drive          - FAT32 / RAMFS drive management\n");
        kprintf("  net            - Network commands\n");
        kprintf("  sys            - System commands and monitoring\n");
        kprintf("  security       - Security subsystems and auditing\n");
        kprintf("  user           - User management commands\n");
        kprintf("  session        - Logout / exit\n");
        kprintf("  all            - Show all commands\n");
        kprintf("\nAlso: 'man <cmd>' for a command's manual page.\n");
        kprintf("Example: help file\n\n");
        return;
    }

    const char* category = argv[1];

    if (strcmp(category, "all") == 0) {
        kprintf("\nAll Commands:\n");
        kprintf("=============\n");
        for (size_t c = 0; c < HELP_CATEGORY_COUNT; c++) {
            help_print_category(help_categories[c].cat, help_categories[c].heading);
        }
        kprintf("\nUse 'help <category>' to narrow this down.\n\n");
        return;
    }

    for (size_t c = 0; c < HELP_CATEGORY_COUNT; c++) {
        if (strcmp(category, help_categories[c].keyword) == 0) {
            help_print_category(help_categories[c].cat, help_categories[c].heading);
            kprintf("\n");
            return;
        }
    }

    kprintf("Unknown category: %s\n", category);
    kprintf("Use 'help' to see available categories\n");
}

static void cmd_clear(void) {
    console_clear();
}

static void cmd_echo(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        kprintf("%s", argv[i]);
        if (i < argc - 1) {
            kprintf(" ");
        }
    }
    kprintf("\n");
}

/*-----------------------------------------------------------------------------
 * Command Parser
 *---------------------------------------------------------------------------*/

static void parse_and_execute(char* cmd_line) {
    char* argv[MAX_ARGS];
    int argc = 0;

    /*
     * CRITICAL: Make a local copy of the command line to prevent TOCTOU.
     * Without this, if the user types while a command is executing,
     * the input_buffer could be overwritten, corrupting the command's arguments.
     * This is especially dangerous for commands that yield or perform I/O.
     */
    char cmd_copy[SHELL_BUFFER_SIZE];
    size_t cmd_len = 0;
    while (cmd_line[cmd_len] && cmd_len < SHELL_BUFFER_SIZE - 1) {
        cmd_copy[cmd_len] = cmd_line[cmd_len];
        cmd_len++;
    }
    cmd_copy[cmd_len] = '\0';

    /* Check for pipe operators - if found, handle as pipeline */
    bool has_pipe = false;
    for (size_t i = 0; i < cmd_len; i++) {
        if (cmd_copy[i] == '|') {
            has_pipe = true;
            break;
        }
    }

    if (has_pipe) {
        /* Pipes are NOT supported yet — kernel-level output capture between
         * stages isn't implemented. Previously we ran each stage UNPIPED and
         * then printed a "not implemented" note, which produced silently wrong
         * results (the user saw commands "run" and assumed the data flowed).
         * Fail cleanly instead: reject the line without executing anything, so
         * the user is never misled. Still record it in history for recall. */
        history_add(cmd_line);
        kprintf("shell: pipes ('|') are not supported yet\n");
        return;
    }

    /* Check for alias expansion (must be done before variable expansion) */
    char alias_expanded[SHELL_BUFFER_SIZE];
    char* working_cmd = cmd_copy;

    /* Extract the first word to check for alias */
    char first_word[64];
    size_t word_len = 0;
    const char* p = cmd_copy;
    while (*p && *p != ' ' && word_len < sizeof(first_word) - 1) {
        first_word[word_len++] = *p++;
    }
    first_word[word_len] = '\0';

    /* Check if it's an alias */
    const char* alias_cmd = alias_get(first_word);
    if (alias_cmd) {
        /* Expand alias: replace first word with alias command */
        size_t alias_len = strlen(alias_cmd);
        const char* rest = cmd_copy + word_len;

        /* Security check: prevent alias expansion loops and command injection */
        if (alias_len + strlen(rest) < sizeof(alias_expanded) - 1) {
            /* Copy alias command */
            size_t i = 0;
            for (i = 0; alias_cmd[i] && i < alias_len; i++) {
                alias_expanded[i] = alias_cmd[i];
            }
            /* Append rest of command */
            for (size_t j = 0; rest[j]; j++, i++) {
                alias_expanded[i] = rest[j];
            }
            alias_expanded[i] = '\0';
            working_cmd = alias_expanded;
        }
    }

    /* Expand environment variables ($VAR syntax) */
    char expanded_cmd[ENV_MAX_EXPAND_LEN];
    if (env_expand(working_cmd, expanded_cmd, sizeof(expanded_cmd)) < 0) {
        kprintf("shell: command too long after variable expansion\n");
        return;
    }

    /* Parse I/O redirections (>, >>, <) */
    cmd_context_t cmd_ctx;
    if (parse_redirections(expanded_cmd, &cmd_ctx) < 0) {
        kprintf("shell: invalid redirection syntax\n");
        return;
    }

    /* Work with the clean command (redirections removed) */
    char* safe_cmd = cmd_ctx.command;

    /* Skip leading spaces */
    while (*safe_cmd == ' ') safe_cmd++;

    /* Empty command */
    if (*safe_cmd == '\0') {
        return;
    }

    /* Save command to history (using original for history display) */
    history_add(cmd_line);

    /* Handle output redirection if present */
    int redir_fd = -1;
    bool has_output_redir = false;

    for (int i = 0; i < cmd_ctx.redir_count; i++) {
        if (cmd_ctx.redirects[i].active) {
            if (cmd_ctx.redirects[i].type == REDIR_OUTPUT) {
                /*=============================================================
                 * SECURITY (v1.12): Shell Redirection with O_NOFOLLOW
                 *
                 * TOCTOU DEFENSE: Use RAMFS_FLAG_NOFOLLOW to prevent symlink
                 * TOCTOU attacks in shell redirection.
                 *
                 * Without this, attacker could:
                 *   1. Create /tmp/output (regular file)
                 *   2. Shell canonicalizes: cmd > /tmp/output
                 *   3. Attacker replaces /tmp/output -> /etc/passwd
                 *   4. Command output overwrites /etc/passwd!
                 *
                 * With NOFOLLOW, symlink is rejected atomically at open.
                 *===========================================================*/
                /* Close fd from any earlier redirect so it doesn't leak */
                if (redir_fd >= 0) {
                    ramfs_close(redir_fd);
                    redir_fd = -1;
                }
                redir_fd = ramfs_open(cmd_ctx.redirects[i].filename,
                                     RAMFS_FLAG_WRITE | RAMFS_FLAG_NOFOLLOW);
                if (redir_fd < 0) {
                    /* File doesn't exist, create it */
                    int touch_fd = ramfs_open(cmd_ctx.redirects[i].filename,
                                            RAMFS_FLAG_WRITE | RAMFS_FLAG_NOFOLLOW);
                    if (touch_fd >= 0) {
                        ramfs_close(touch_fd);
                        redir_fd = ramfs_open(cmd_ctx.redirects[i].filename,
                                            RAMFS_FLAG_WRITE | RAMFS_FLAG_NOFOLLOW);
                    }
                }
                has_output_redir = (redir_fd >= 0);
                if (!has_output_redir) {
                    kprintf("shell: cannot create %s\n", cmd_ctx.redirects[i].filename);
                    return;
                }
            } else if (cmd_ctx.redirects[i].type == REDIR_APPEND) {
                /* SECURITY (v1.12): Use NOFOLLOW for append redirection too */
                /* Close fd from any earlier redirect so it doesn't leak */
                if (redir_fd >= 0) {
                    ramfs_close(redir_fd);
                    redir_fd = -1;
                }
                redir_fd = ramfs_open(cmd_ctx.redirects[i].filename,
                                     RAMFS_FLAG_WRITE | RAMFS_FLAG_NOFOLLOW);
                if (redir_fd < 0) {
                    /* File doesn't exist, create it */
                    int touch_fd = ramfs_open(cmd_ctx.redirects[i].filename,
                                            RAMFS_FLAG_WRITE | RAMFS_FLAG_NOFOLLOW);
                    if (touch_fd >= 0) {
                        ramfs_close(touch_fd);
                        redir_fd = ramfs_open(cmd_ctx.redirects[i].filename,
                                            RAMFS_FLAG_WRITE | RAMFS_FLAG_NOFOLLOW);
                    }
                }
                has_output_redir = (redir_fd >= 0);
                if (!has_output_redir) {
                    kprintf("shell: cannot create %s\n", cmd_ctx.redirects[i].filename);
                    return;
                }
                /* TODO: Seek to end for append mode */
            }
        }
    }

    /* Note: Output redirection is parsed but command output capture
     * requires deeper integration with kprintf(). For now, redirection
     * files are created but output still goes to console.
     * Full implementation would require a kernel-level output buffer. */

    /*=========================================================================
     * SECURITY (v1.13): Argument Parsing Buffer Overflow Protection
     *
     * CRITICAL: argv[] array has fixed size MAX_ARGS (10 pointers).
     * Without bounds checking, an attacker could:
     * 1. Provide command with >10 arguments (via direct input or expansion)
     * 2. Parser writes past end of argv[] → stack corruption
     * 3. Overwrite return address or function pointers → code execution
     *
     * DEFENSE LAYERS:
     * 1. Loop condition: `argc < MAX_ARGS` prevents overflow
     * 2. Post-increment: `argv[argc++]` writes to argv[0..9], then increments
     * 3. Warning message: Alerts user when arguments are truncated
     *
     * VERIFICATION: When argc=9 (last valid index):
     * - Loop enters because 9 < 10 (TRUE)
     * - Writes to argv[9] (safe), increments argc to 10
     * - Next iteration: 10 < 10 (FALSE), loop exits
     * - No write to argv[10] occurs → no overflow
     *=======================================================================*/
    /* Parse arguments from the safe copy */
    char* token = safe_cmd;
    while (*token && argc < MAX_ARGS) {
        argv[argc++] = token;

        /* Find end of token */
        while (*token && *token != ' ') token++;

        /* Null-terminate token */
        if (*token) {
            *token = '\0';
            token++;

            /* Skip spaces */
            while (*token == ' ') token++;
        }
    }

    /* Check if there are more arguments than MAX_ARGS */
    if (argc >= MAX_ARGS && *token) {
        kprintf("Warning: too many arguments (max %d). Extra arguments ignored.\n", MAX_ARGS);
    }

    if (argc == 0) {
        return;
    }

    /* Handle input redirection: set up stdin stream */
    stream_context_t* streams = NULL;
    if (cmd_ctx.has_input_redir) {
        streams = get_current_streams();
        if (!streams) {
            kprintf("shell: cannot redirect input - no task context\n");
            if (redir_fd >= 0) {
                ramfs_close(redir_fd);
            }
            return;
        }
        /* Redirect stdin to read from file */
        if (stdin_redirect_from_file(streams, cmd_ctx.input_file) < 0) {
            kprintf("shell: %s: cannot open file for reading\n", cmd_ctx.input_file);
            if (redir_fd >= 0) {
                ramfs_close(redir_fd);
            }
            return;
        }
    }

    /* Execute command */
    if (strcmp(argv[0], "help") == 0) {
        cmd_help(argc, argv);
    } else if (strcmp(argv[0], "clear") == 0) {
        cmd_clear();
    } else if (strcmp(argv[0], "echo") == 0) {
        cmd_echo(argc, argv);
    }
    /* System Monitoring Commands */
    else if (strcmp(argv[0], "ps") == 0) {
        cmd_ps_extended(argc, argv);
    } else if (strcmp(argv[0], "top") == 0) {
        cmd_top(argc, argv);
    }
    /* System Commands */
    else if (strcmp(argv[0], "mem") == 0) {
        cmd_mem(argc, argv);

    } else if (strcmp(argv[0], "aslr") == 0) {
        cmd_aslr(argc, argv);

    } else if (strcmp(argv[0], "pae") == 0) {
        cmd_pae(argc, argv);

    } else if (strcmp(argv[0], "wxaudit") == 0) {
        cmd_wxaudit(argc, argv);

    } else if (strcmp(argv[0], "kill") == 0) {
        cmd_kill(argc, argv);
    } else if (strcmp(argv[0], "shutdown") == 0) {
        cmd_shutdown(argc, argv);
    } else if (strcmp(argv[0], "reboot") == 0) {
        cmd_reboot(argc, argv);
    } else if (strcmp(argv[0], "date") == 0) {
        cmd_date(argc, argv);
    } else if (strcmp(argv[0], "auditlog") == 0) {
        cmd_auditlog(argc, argv);
    } else if (strcmp(argv[0], "sectest") == 0) {
        cmd_sectest(argc, argv);
    } else if (strcmp(argv[0], "secstatus") == 0) {
        cmd_secstatus(argc, argv);
    }
    /* Environment Variable Commands */
    else if (strcmp(argv[0], "env") == 0) {
        cmd_env(argc, argv);
    } else if (strcmp(argv[0], "set") == 0) {
        cmd_set(argc, argv);
    } else if (strcmp(argv[0], "unset") == 0) {
        cmd_unset(argc, argv);
    } else if (strcmp(argv[0], "export") == 0) {
        cmd_export(argc, argv);
    } else if (strcmp(argv[0], "alias") == 0) {
        cmd_alias(argc, argv);
    } else if (strcmp(argv[0], "unalias") == 0) {
        cmd_unalias(argc, argv);
    }
    /* User Management Commands (v1.10)
     *
     * These take AT MOST one positional arg (a username); whoami/users take
     * none. They used to be dispatched as `fn(argc>1 ? argv[1] : NULL)`, which
     * silently DROPPED any extra arguments — so `useradd -m bob` or `id -u`
     * looked like it worked but ignored half the line. Reject unexpected args
     * explicitly instead of swallowing them. (No flag support yet; an explicit
     * error is the honest behavior until there is.) */
    else if (strcmp(argv[0], "whoami") == 0) {
        if (argc > 1) { kprintf("whoami: takes no arguments\n"); }
        else shell_cmd_whoami(NULL);
    } else if (strcmp(argv[0], "users") == 0) {
        if (argc > 1) { kprintf("users: takes no arguments\n"); }
        else shell_cmd_users(NULL);
    } else if (strcmp(argv[0], "id") == 0) {
        if (argc > 2) { kprintf("id: too many arguments\nUsage: id [username]\n"); }
        else shell_cmd_id(argc > 1 ? argv[1] : NULL);
    } else if (strcmp(argv[0], "su") == 0) {
        if (argc > 2) { kprintf("su: too many arguments\nUsage: su [username]\n"); }
        else shell_cmd_su(argc > 1 ? argv[1] : NULL);
    } else if (strcmp(argv[0], "passwd") == 0) {
        if (argc > 2) { kprintf("passwd: too many arguments\nUsage: passwd [username]\n"); }
        else shell_cmd_passwd(argc > 1 ? argv[1] : NULL);
    } else if (strcmp(argv[0], "useradd") == 0) {
        if (argc != 2) { kprintf("useradd: expected exactly one username\nUsage: useradd <username>\n"); }
        else shell_cmd_useradd(argv[1]);
    } else if (strcmp(argv[0], "userdel") == 0) {
        if (argc != 2) { kprintf("userdel: expected exactly one username\nUsage: userdel <username>\n"); }
        else shell_cmd_userdel(argv[1]);
    } else if (strcmp(argv[0], "logout") == 0 || strcmp(argv[0], "exit") == 0) {
        cmd_logout(argc, argv);
    }
    /* History Commands */
    else if (strcmp(argv[0], "history") == 0) {
        cmd_history(argc, argv);
    } else if (strcmp(argv[0], "man") == 0) {
        cmd_man(argc, argv);
    }
    /* Network Commands */
    else if (strcmp(argv[0], "ifconfig") == 0) {
        cmd_ifconfig();
    } else if (strcmp(argv[0], "ping") == 0) {
        cmd_ping(argc, argv);
    } else if (strcmp(argv[0], "dig") == 0) {
        cmd_dig(argc, argv);
    } else if (strcmp(argv[0], "dhcp") == 0) {
        cmd_dhcp(argc, argv);
    } else if (strcmp(argv[0], "curl") == 0) {
        cmd_curl(argc, argv);
    }
    /* File Operations Commands */
    else if (strcmp(argv[0], "pwd") == 0) {
        cmd_pwd();
    } else if (strcmp(argv[0], "cd") == 0) {
        cmd_cd(argc, argv);
    } else if (strcmp(argv[0], "ls") == 0) {
        cmd_ls(argc, argv);
    } else if (strcmp(argv[0], "cat") == 0) {
        cmd_cat(argc, argv);
    } else if (strcmp(argv[0], "edit") == 0) {
        cmd_edit(argc, argv);
    } else if (strcmp(argv[0], "mkdir") == 0) {
        cmd_mkdir(argc, argv);
    } else if (strcmp(argv[0], "touch") == 0) {
        cmd_touch(argc, argv);
    } else if (strcmp(argv[0], "write") == 0) {
        cmd_write(argc, argv);
    } else if (strcmp(argv[0], "rm") == 0) {
        cmd_rm(argc, argv);
    } else if (strcmp(argv[0], "cp") == 0) {
        cmd_cp(argc, argv);
    } else if (strcmp(argv[0], "mv") == 0) {
        cmd_mv(argc, argv);
    } else if (strcmp(argv[0], "chmod") == 0) {
        cmd_chmod(argc, argv);
    } else if (strcmp(argv[0], "exec") == 0) {
        cmd_exec(argc, argv);
    }
    /* Search Commands */
    else if (strcmp(argv[0], "grep") == 0) {
        cmd_grep(argc, argv);
    } else if (strcmp(argv[0], "find") == 0) {
        cmd_find(argc, argv);
    }
    /* FAT32/Drive Commands (Phase 1) */
    else if (strcmp(argv[0], "mount") == 0) {
        cmd_mount(argc, argv);
    } else if (strcmp(argv[0], "fatls") == 0) {
        cmd_fatls(argc, argv);
    }
    /* Unknown command */
    else {
        kprintf("Unknown command: %s\n", argv[0]);
        if (command_lookup(argv[0])) {
            /* In the help table but not dispatched — a wiring gap, not a typo. */
            kprintf("(known command not yet wired into the shell — please report)\n");
        } else {
            kprintf("Type 'help' for available commands, or 'man <cmd>' for details.\n");
        }
    }

    /* Clean up redirection file descriptor */
    if (redir_fd >= 0) {
        ramfs_close(redir_fd);
    }

    /* Reset stdin if it was redirected */
    if (cmd_ctx.has_input_redir && streams) {
        stdin_reset(streams);
    }
}

/*-----------------------------------------------------------------------------
 * Shell Main Loop
 *
 * NOTE: Stack protection disabled because it calls shell_login_prompt()
 *       which has deep call chain to password hashing functions with
 *       Re-enabling stack protection to catch overflow
 *---------------------------------------------------------------------------*/

void shell_task(void) {
    kprintf("[SHELL] Shell task started! (ESP check)\n");

    /* Initialize history system */
    history_init();

    /*
     * SECURITY FIX: Streams are now allocated per-process in task_create_*()
     * No need to manually initialize here - each task gets its own stream context
     */

    /*
     * Pause for 1 second (100 ticks at 100Hz) before showing welcome.
     * CRITICAL: Use scheduler_yield() to prevent deadlock if timer fails.
     * Without yielding, this could hang forever if timer interrupts are masked.
     */
    uint32_t start_ticks = get_timer_ticks();
    while (get_timer_ticks() < start_ticks + 100) {
        scheduler_yield();  /* Allow other tasks to run and prevent deadlock */
    }

    /* Main session loop - allows logout and re-login */
    while (1) {
        should_logout = false;  /* Reset logout flag */

        /* The login prompt must run privileged so it can switch to ANY user
         * via sys_setuid/sys_setgid. The previous session left this task with
         * the logged-out user's credentials; reset to root before prompting,
         * otherwise the next login fails with "Unable to set credentials"
         * (a non-root task can only setuid to its own euid). This is kernel
         * code in the login task, so we set the fields directly. */
        {
            task_t* self = scheduler_get_current_task();
            if (self) {
                self->uid = 0;
                self->euid = 0;
                self->gid = 0;
                self->egid = 0;
            }
        }

        /* Interactive login prompt (v1.10) */
        if (shell_login_prompt() != 0) {
            kprintf("\nLogin failed. System halted.\n");
            while (1) {
                scheduler_yield();  /* Halt task - login failed */
            }
        }

        /* Display welcome message with ASCII art */
        kprintf("\n");
        kprintf("   (\\_/) Hearty <3\n");
        kprintf("   (o.o) Thoughts ooO\n");
        kprintf("------------------------\n");
        kprintf("|  Welcome Home!       |\n");
        kprintf("------------------------\n");
        kprintf("\n");
        kprintf("$ ");

        buffer_pos = 0;

        /* Shell command loop */
        while (!should_logout) {
        /* Check for keyboard input */
        if (keyboard_has_data()) {
            char c = keyboard_getchar_nonblock();

            if (c == '\n') {
                /* Execute command */
                kprintf("\n");

                /* SECURITY: Ensure buffer_pos is within bounds before null-terminating */
                if (buffer_pos >= SHELL_BUFFER_SIZE) {
                    buffer_pos = SHELL_BUFFER_SIZE - 1;
                }
                input_buffer[buffer_pos] = '\0';

                if (buffer_pos > 0) {
                    parse_and_execute(input_buffer);
                }

                /* Reset buffer and show prompt */
                buffer_pos = 0;
                kprintf("$ ");
            } else if (c == '\b' || c == 0x7F) {
                /* SECURITY FIX: Explicit backspace handling to prevent display corruption
                 * Previously relied on keyboard driver to echo backspace correctly.
                 * If driver is bugged, disabled, or terminal emulation is non-standard,
                 * the shell's internal state (buffer_pos) becomes decoupled from the
                 * user's visible prompt, leading to confusion and potential mis-parsed commands.
                 *
                 * Now we explicitly control the cursor by sending the full sequence:
                 * \b (move cursor back), space (overwrite char), \b (move cursor back again)
                 *
                 * NOTE (v1.13): Handle both '\b' (0x08) and DEL (0x7F) as different
                 * terminals/keyboards send different codes for the backspace key.
                 */
                if (buffer_pos > 0) {
                    buffer_pos--;
                    kprintf("\b \b");  /* Explicitly erase character from screen */
                }
            } else if (c >= 32 && c < 127) {
                /* Printable character */
                if (buffer_pos < SHELL_BUFFER_SIZE - 1) {
                    input_buffer[buffer_pos++] = c;
                    /* Echo character (v1.13: keyboard driver no longer echoes) */
                    kprintf("%c", c);
                }
            }
        }

        /* Yield to other tasks when no input is available */
        scheduler_yield();
        }  /* End of shell command loop (while !should_logout) */

        /* User logged out - clear screen for security and loop back to login */
        if (should_logout) {
            console_clear();
            kprintf("\n");
        }
    }  /* End of main session loop (while 1) - restarts at login prompt */
}
