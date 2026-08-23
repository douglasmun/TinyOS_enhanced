/*=============================================================================
 * shell.c - Simple Kernel Shell Implementation
 *=============================================================================*/
#include "kernel.h"
#include "kprintf.h"
#include "keyboard.h"
#include "scheduler.h"
#include "util.h"
#include "env.h"
#include "user.h"
#include "editor.h"     /* editor_rowtest, under TINYOS_FAULT_INJECT */
#include "test_tasks.h"   /* knetd_die_now, under TINYOS_FAULT_INJECT */
#include "net.h"          /* net_netd_set_claimed, under TINYOS_FAULT_INJECT */
#include "dns.h"          /* dns_forge_response, under TINYOS_FAULT_INJECT */
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
#include "elf.h"       /* elf_exec_from_path() — launching the ring-3 login shell */
#include "process.h"
#include "syscall.h"   /* sys_waitpid() — the login shell blocks on it */
#include "critical.h"

#ifdef TINYOS_FAULT_INJECT
/* verify-double-fault.sh only. Deliberately recursive, deliberately NOT
 * tail-callable: at -O2 a plain `f(n+1)` tail call becomes a jump that loops
 * forever without growing the stack, so no fault ever occurs and the harness
 * would hang rather than fault. The volatile array forces a real frame per
 * call and using the callee's result keeps it out of tail position. */
/* -Winfinite-recursion is RIGHT: the recursion is unbounded on purpose, since
 * blowing the stack is the whole point. Suppressed here only, not globally. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winfinite-recursion"
__attribute__((noinline))
static uint32_t shell_smash_kernel_stack(uint32_t depth) {
    volatile uint32_t pad[16];
    for (unsigned i = 0; i < 16; i++) pad[i] = depth + i;
    uint32_t deeper = shell_smash_kernel_stack(depth + 1);
    return pad[0] + deeper;
}
#pragma GCC diagnostic pop
#endif

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
    { "exec",    CAT_FILE, "exec <file> [&]",    "Execute ELF binary (& = background)" },

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
    { "jobs",    CAT_SYS, "jobs",                "List background jobs of this shell" },
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
    { "loglevel",CAT_SECURITY, "loglevel [normal|debug]", "Kernel diagnostic verbosity" },
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

/* Exit status by which the ring-3 login shell asks to hand control to the
 * kernel command loop (its `kshell` builtin) rather than log out. It cannot
 * set a kernel flag directly — it is a separate process — so the exit status
 * is the channel. 70 is outside the 0..63 a shell would plausibly return on
 * its own, and sys_waitpid truncates to 0..255, so it round-trips intact. */
#define SHELL_EXIT_WANT_KERNEL_SHELL 70

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

static void parse_and_execute(char* cmd_line);

/*-----------------------------------------------------------------------------
 * Pipeline execution
 *
 * Stages run SEQUENTIALLY, not concurrently: stage N is run to completion with
 * its stdout bound to a pipe, then that pipe becomes stage N+1's stdin. The
 * shell is a single kernel task and its builtins are direct function calls, so
 * there is no second thread of control to run a downstream stage while an
 * upstream one is still producing. Real concurrent pipelines need each stage to
 * be its own process (SYS_SPAWN, already in place) plus fd-level plumbing so a
 * spawned child inherits a pipe end; until then this gives correct DATA FLOW
 * with the caveat below.
 *
 * CONSEQUENCE, stated plainly: a stage that produces more than PIPE_BUFFER_SIZE
 * (4KB) of output would block forever waiting for a reader that cannot run
 * until it finishes. To keep that from becoming a hang, the pipe's read end is
 * closed if a stage overruns, so the writer gets -EPIPE and the line fails
 * loudly instead of wedging the shell. Long outputs are therefore truncated,
 * which is reported.
 *---------------------------------------------------------------------------*/
/*
 * Console-capture sink for a pipeline stage: one character into the stage's
 * stdout pipe.
 *
 * Deliberately NON-BLOCKING.  pipe_write() blocks when the buffer fills, and it
 * is woken by a reader -- but in this sequential pipeline the shell task IS the
 * reader, and it is currently inside the stage call, so nothing would ever
 * drain the pipe and the shell would hang forever.  Dropping the overflow is
 * the survivable choice; run_pipeline reports the truncation to the user by
 * comparing the byte count it collects against what the stage produced.
 */
/* Carries both halves of the sink's state through the callback's single void*,
 * so the drop count lives and dies with the stage it belongs to. It was a
 * file-scope static, which meant a count left over from one stage could be
 * reported against the next. */
typedef struct {
    pipe_buffer_t* pipe;
    size_t dropped;             /* bytes the sink had to discard */
} pipeline_sink_t;

static void pipeline_capture_putc(void* ctx, char c) {
    pipeline_sink_t* sink = (pipeline_sink_t*)ctx;
    if (!sink || !sink->pipe) return;
    if (pipe_available(sink->pipe) >= PIPE_BUFFER_SIZE) {
        sink->dropped++;
        return;
    }
    pipe_write(sink->pipe, &c, 1);
}

static void run_pipeline(const char* cmd_line) {
    /* Static, not stack: pipe_buffer_t is PIPE_BUFFER_SIZE + change (~4KB) and
     * the shell task's kernel stack also carries the whole exec chain. Safe
     * because the shell is single-threaded and one pipeline runs at a time. */
    static pipe_buffer_t stage_pipe;   /* Feeds stage N's stdin */
    static pipe_buffer_t out_pipe;     /* Captures stage N's stdout */
    static char stage_out[PIPE_BUFFER_SIZE];

    pipeline_t pipeline;
    if (parse_pipeline(cmd_line, &pipeline) != 0) {
        kprintf("shell: invalid pipeline (max %d stages)\n", MAX_PIPE_STAGES);
        return;
    }

    if (pipeline.cmd_count < 2) {
        /* A lone '|' with nothing on one side. */
        kprintf("shell: syntax error near '|'\n");
        return;
    }

    stream_context_t* streams = get_current_streams();
    if (!streams) {
        kprintf("shell: cannot run pipeline - no task context\n");
        return;
    }

    /* Carries stage N's output into stage N+1. Empty for the first stage. */
    size_t carry_len = 0;

    /* Which of the two static pipes currently hold an allocated wait-queue
     * page, so the cleanup exit frees exactly those and never double-frees. */
    bool stage_pipe_live = false;
    bool out_pipe_live = false;

    for (int stage = 0; stage < pipeline.cmd_count; stage++) {
        bool is_last = (stage == pipeline.cmd_count - 1);

        /* Fresh per stage, so a previous stage's drop count is never reported
         * against this one. */
        pipeline_sink_t sink = { &out_pipe, 0 };

        /* --- stdin: feed in whatever the previous stage produced. --- */
        if (stage > 0) {
            pipe_init(&stage_pipe);
            stage_pipe_live = true;
            if (carry_len > 0 &&
                pipe_write(&stage_pipe, stage_out, carry_len) < 0) {
                kprintf("shell: pipe write failed\n");
                goto cleanup;
            }
            /* Close the write end BEFORE the stage runs: with no concurrent
             * writer, the data is already complete, and this is what lets the
             * reader see EOF instead of blocking once it drains the buffer. */
            pipe_close_write(&stage_pipe);

            streams->stdin_stream.type = STREAM_TYPE_PIPE;
            streams->stdin_stream.data = &stage_pipe;
            streams->stdin_stream.fd = -1;
            streams->stdin_stream.is_open = true;
            streams->stdin_stream.borrowed = false;
        }

        /* --- stdout: capture into a fresh pipe unless this is the last stage,
         *     which writes to wherever the shell's stdout already points. --- */
        if (!is_last) {
            pipe_init(&out_pipe);
            out_pipe_live = true;
            streams->stdout_stream.type = STREAM_TYPE_PIPE;
            streams->stdout_stream.data = &out_pipe;
            streams->stdout_stream.fd = -1;
            streams->stdout_stream.is_open = true;
            streams->stdout_stream.borrowed = false;
        }

        /* Run the stage. parse_and_execute re-enters this file's dispatch
         * chain; it sees no '|' in a single stage, so this does not recurse. */
        char stage_cmd[512];
        size_t n = 0;
        while (pipeline.commands[stage][n] && n < sizeof(stage_cmd) - 1) {
            stage_cmd[n] = pipeline.commands[stage][n];
            n++;
        }
        stage_cmd[n] = '\0';

        if (!is_last) {
            /* The builtins print with kprintf, straight to the console, so
             * pointing stdout_stream at the pipe is not enough on its own --
             * without this hook `echo hi | cat` would print "hi" to the console
             * and pipe nothing.  Installed only around the stage call and torn
             * down immediately after, so kernel logging outside this window
             * still reaches the console. */
            void* prev_ctx = NULL;
            kprintf_capture_fn prev = kprintf_set_capture(pipeline_capture_putc,
                                                          &sink, &prev_ctx);
            parse_and_execute(stage_cmd);
            kprintf_set_capture(prev, prev_ctx, NULL);
        } else {
            parse_and_execute(stage_cmd);
        }

        /* --- Collect this stage's output for the next one. --- */
        if (!is_last) {
            stdout_reset(streams);

            size_t produced = pipe_available(&out_pipe);
            /* The pipe holds at most PIPE_BUFFER_SIZE and stage_out is exactly
             * that big, so this clamp is a belt-and-braces bound, not the real
             * truncation point -- overflow is dropped by the capture sink,
             * which counts it in sink.dropped. */
            if (produced > sizeof(stage_out)) {
                produced = sizeof(stage_out);
            }

            carry_len = 0;
            if (produced > 0) {
                int got = pipe_read(&out_pipe, stage_out, produced);
                if (got > 0) {
                    carry_len = (size_t)got;
                }
            }

            /* Closing the read end turns any further writes into -EPIPE, so a
             * stage that overran cannot block on a pipe nobody will drain. */
            pipe_close_read(&out_pipe);
            pipe_destroy(&out_pipe);
            out_pipe_live = false;

            if (sink.dropped > 0) {
                kprintf("shell: stage %d output truncated at %u bytes "
                        "(%u dropped)\n",
                        stage + 1, (unsigned)PIPE_BUFFER_SIZE,
                        (unsigned)sink.dropped);
            }
        }

        /* Release this stage's stdin pipe now that the stage has finished. */
        if (stage > 0) {
            stdin_reset(streams);
            pipe_destroy(&stage_pipe);
            stage_pipe_live = false;
        }
    }

cleanup:
    /* Single exit for the mid-loop failure paths. pipe_init() allocates a page
     * per call, so returning straight out of the loop leaked one 4KB wait-queue
     * page per failure -- repeatable on demand, hence a real exhaustion vector.
     * The stream resets matter just as much: stdin/stdout still point at these
     * statics, and leaving them bound to a destroyed pipe would let the next
     * command read or write a torn-down buffer. */
    if (out_pipe_live) {
        stdout_reset(streams);
        pipe_close_read(&out_pipe);
        pipe_destroy(&out_pipe);
    }
    if (stage_pipe_live) {
        stdin_reset(streams);
        pipe_destroy(&stage_pipe);
    }
}

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
        history_add(cmd_line);
        run_pipeline(cmd_copy);
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
    char alias_cmd[ALIAS_MAX_CMD_LEN];
    if (alias_get(first_word, alias_cmd, sizeof(alias_cmd))) {
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
                /* RAMFS_FLAG_INHERIT is required, not optional: RAMFS defaults
                 * every fd to close-on-exec, and elf.c calls
                 * ramfs_close_on_exec() while loading the child. Without the
                 * flag, `exec prog > file` hands the child a stdout bound to an
                 * fd that exec itself just closed, and every write returns -1.
                 * The shell still owns and closes this fd; INHERIT only exempts
                 * it from the exec sweep. */
                redir_fd = ramfs_open(cmd_ctx.redirects[i].filename,
                                     RAMFS_FLAG_WRITE | RAMFS_FLAG_NOFOLLOW |
                                     RAMFS_FLAG_INHERIT);
                if (redir_fd < 0) {
                    /* File doesn't exist, create it */
                    int touch_fd = ramfs_open(cmd_ctx.redirects[i].filename,
                                            RAMFS_FLAG_WRITE | RAMFS_FLAG_NOFOLLOW);
                    if (touch_fd >= 0) {
                        ramfs_close(touch_fd);
                        redir_fd = ramfs_open(cmd_ctx.redirects[i].filename,
                                            RAMFS_FLAG_WRITE | RAMFS_FLAG_NOFOLLOW |
                                            RAMFS_FLAG_INHERIT);
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
                /* RAMFS_FLAG_INHERIT is required, not optional: RAMFS defaults
                 * every fd to close-on-exec, and elf.c calls
                 * ramfs_close_on_exec() while loading the child. Without the
                 * flag, `exec prog > file` hands the child a stdout bound to an
                 * fd that exec itself just closed, and every write returns -1.
                 * The shell still owns and closes this fd; INHERIT only exempts
                 * it from the exec sweep. */
                redir_fd = ramfs_open(cmd_ctx.redirects[i].filename,
                                     RAMFS_FLAG_WRITE | RAMFS_FLAG_NOFOLLOW |
                                     RAMFS_FLAG_INHERIT);
                if (redir_fd < 0) {
                    /* File doesn't exist, create it */
                    int touch_fd = ramfs_open(cmd_ctx.redirects[i].filename,
                                            RAMFS_FLAG_WRITE | RAMFS_FLAG_NOFOLLOW);
                    if (touch_fd >= 0) {
                        ramfs_close(touch_fd);
                        redir_fd = ramfs_open(cmd_ctx.redirects[i].filename,
                                            RAMFS_FLAG_WRITE | RAMFS_FLAG_NOFOLLOW |
                                            RAMFS_FLAG_INHERIT);
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

    /* Bind an output redirection to stdout.
     *
     * `has_output_redir` was previously set and never read: the shell opened
     * the target file, left stdout pointing at the console, and closed the fd
     * again at the end of the command — so `cmd > file` silently printed to
     * the console and wrote nothing. Point stdout_stream at the fd that was
     * already opened above rather than calling stdout_redirect_to_file(),
     * which would open the file a second time and leak this fd.
     *
     * The reset at the end of this function restores the console before
     * ramfs_close(redir_fd), so stdout never references a closed fd. */
    stream_context_t* out_streams = NULL;
    if (has_output_redir) {
        out_streams = get_current_streams();
        if (out_streams) {
            out_streams->stdout_stream.type = STREAM_TYPE_FILE;
            out_streams->stdout_stream.fd = redir_fd;
            out_streams->stdout_stream.data = NULL;
            out_streams->stdout_stream.is_open = true;
            /* The shell opened redir_fd, so it owns it: stdout_reset() below is
             * what actually closes it. A child that inherits this stream gets a
             * borrowed copy instead and leaves the fd alone when it exits. */
            out_streams->stdout_stream.borrowed = false;
        }
    }

    /* Handle input redirection: set up stdin stream */
    stream_context_t* streams = NULL;
    if (cmd_ctx.has_input_redir) {
        streams = get_current_streams();
        if (!streams) {
            kprintf("shell: cannot redirect input - no task context\n");
            /* stdout may already be bound to redir_fd at this point; unbind it
             * first so it isn't left pointing at a descriptor we then close. */
            if (out_streams) {
                stdout_reset(out_streams);
            } else if (redir_fd >= 0) {
                ramfs_close(redir_fd);
            }
            return;
        }
        /* Redirect stdin to read from file */
        if (stdin_redirect_from_file(streams, cmd_ctx.input_file) < 0) {
            kprintf("shell: %s: cannot open file for reading\n", cmd_ctx.input_file);
            if (out_streams) {
                stdout_reset(out_streams);
            } else if (redir_fd >= 0) {
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
    } else if (strcmp(argv[0], "jobs") == 0) {
        cmd_jobs(argc, argv);
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

    } else if (strcmp(argv[0], "loglevel") == 0) {
        cmd_loglevel(argc, argv);

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
    }
#ifdef TINYOS_FAULT_INJECT
    /* verify-editor-rowfail.sh only. Not in the command table, so it never
     * appears in `help`. Drives editor_insert_row()'s allocation-failure path,
     * which real OOM is the only other way to reach. */
    else if (strcmp(argv[0], "rowtest") == 0) {
        editor_rowtest();
    }
    /* verify-double-fault.sh only. Not in the command table, so it never
     * appears in `help`.
     *
     * Exhausts the kernel task stack by unbounded recursion. The overflow runs
     * off the end of the stack into its guard page -> #PF; delivering that #PF
     * needs to push a frame onto the same exhausted stack, which faults again
     * -> #DF. That is the ONE case the old interrupt-gate handler could not
     * survive, because isr_common's pushes hit the dead stack too and the CPU
     * escalated straight to a triple fault (silent reboot, no diagnostics).
     *
     * With the task gate the CPU loads a whole new context from the DF TSS, so
     * the handler runs on its own stack and can print. This command is
     * therefore expected to HALT the machine with a #DF dump -- that is a PASS,
     * not a crash. Nothing resumes afterwards. */
    else if (strcmp(argv[0], "dftest") == 0) {
        kprintf("[FAULT] exhausting kernel stack to force #DF...\n");
        shell_smash_kernel_stack(0);
    }
    /* verify-supervisor.sh only. Not in the command table, so it never appears
     * in `help` -- see the rationale on knetd_die_now in test_tasks.c. */
    else if (strcmp(argv[0], "killknetd") == 0) {
        /* With no argument: one death, the original behaviour steps 1-4 use.
         * With a count: that many deaths back-to-back, each restarted instance
         * dying immediately, to drive the supervisor past SUPERVISOR_MAX_RESTARTS
         * inside SUPERVISOR_WINDOW_MS. The repetition has to happen in the guest
         * rather than as repeated typed commands -- see test_tasks.c. */
        if (argc > 1) {
            int n = 0;
            for (const char* dp = argv[1]; *dp >= '0' && *dp <= '9'; dp++) {
                n = n * 10 + (*dp - '0');
                if (n > 100) break;   /* not a real limit, just no runaway */
            }
            knetd_die_repeat = n;
            kprintf("[FAULT] knetd death requested x%d\n", n);
        } else {
            knetd_die_now = 1;
            kprintf("[FAULT] knetd death requested\n");
        }
    }
    /* verify-netd-arbitration.sh only, and gated for the same reason killknetd
     * is: it exists to drive a state no production path reaches yet.
     *
     * Claiming with no ring-3 daemon running is exactly the interesting case
     * for D1a -- it proves frames stop being parsed in ring 0 and start
     * accumulating on the netd ring, which is the routing switch working. It
     * also, deliberately, breaks ICMP/UDP while claimed: nothing is draining
     * the ring. That is the correct behaviour to observe now, and it is why
     * this is a fault-injection lever rather than a user-facing command. */
    else if (strcmp(argv[0], "netdclaim") == 0) {
        if (argc > 1 && strcmp(argv[1], "off") == 0) {
            net_netd_set_claimed(false);
            kprintf("[FAULT] netd claim released\n");
        } else {
            net_netd_set_claimed(true);
            kprintf("[FAULT] netd claim taken\n");
        }
    }
    /* verify-dns-rx-counters.sh only. Drives handle_dns_response()'s drop
     * branches, which a passing `dig` never reaches -- the counters they feed
     * exist precisely for traffic a friendly network does not produce. */
    else if (strcmp(argv[0], "dnsforge") == 0) {
        dns_forge_response(argc > 1 ? argv[1] : "help");
    }
#endif
    else if (strcmp(argv[0], "ping") == 0) {
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

    /* Clean up the redirection file descriptor.
     *
     * When stdout was bound to it, stdout_reset() closes the fd itself as part
     * of restoring the console, so closing it again here would be a double
     * close (and could later close an unrelated recycled fd). Ownership passes
     * to the stream in that case; only the unbound path closes it directly. */
    if (out_streams) {
        stdout_reset(out_streams);
    } else if (redir_fd >= 0) {
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

/*-----------------------------------------------------------------------------
 * FUNCTION: launch_login_shell
 * PURPOSE: Run /shell.elf as the ring-3 login shell, blocking until it exits
 *
 * Roadmap item 4. The ring-3 shell is the default face of the system, but it
 * is NOT yet a replacement for this one: it has ~13 builtins against this
 * shell's ~70, and everything privileged (users, shutdown, ps/kill, security
 * tooling, networking) plus pipes and redirection still live only here. So
 * this is a launcher with a fallback, not a swap — if /shell.elf is missing,
 * unsigned, or fails to load, we return non-zero and the caller runs the
 * kernel command loop instead. A broken or unsigned shell.elf must never cost
 * the user their login.
 *
 * `exit` in the ring-3 shell therefore means LOGOUT: the process exits, this
 * function returns, and the session loop in shell_task falls back around to
 * the login prompt. That is the whole reason logout works at all without a
 * session syscall — the ring-3 shell cannot return to a login prompt by
 * itself, but its parent can.
 *
 * CREDENTIALS: task_create_user hardcodes uid 1000 for every user task, so a
 * root login would otherwise be silently demoted to a regular user. The child
 * inherits this session's credentials instead, set before it is made runnable
 * for the same reason sys_spawn sets parentage first — after
 * scheduler_add_task the child can run on the very next tick.
 *
 * @return 0 on logout (ring-3 shell ran and exited), 1 if it asked to hand
 *         over to the kernel command loop, negative if it could not be run
 *---------------------------------------------------------------------------*/
static int launch_login_shell(void) {
    const char* path = "/shell.elf";
    const char* name = "shell.elf";
    const char* child_argv[1] = { name };

    const char* err = NULL;
    int pid = elf_exec_from_path(path, name, 1, child_argv, &err);
    if (pid < 0) {
        kprintf("[SHELL] ring-3 shell unavailable (%s); using the kernel shell\n",
                err ? err : "failed to load");
        return -1;
    }

    task_t* task = task_get((uint32_t)pid);
    if (!task) {
        /* Built, then the slot vanished before we could schedule it. Reap
         * rather than leak a fully-constructed process, and fall back. */
        kprintf("[SHELL] ring-3 shell vanished during load; using the kernel shell\n");
        task_terminate((uint32_t)pid);
        return -1;
    }

    /* Run as whoever just logged in, not as the hardcoded uid 1000. */
    task_t* self = scheduler_get_current_task();
    if (self) {
        task->uid  = self->uid;
        task->gid  = self->gid;
        task->euid = self->euid;
        task->egid = self->egid;

        /* Parentage so the child's own waitpid/jobs bookkeeping matches, and
         * streams so its output reaches this session's console. */
        task->parent_pid = self->pid;
        task->parent_generation = self->generation;
        streams_inherit(&task->streams, get_current_streams());

        /* The ring-3 shell starts with this login session's exported variables
         * (USER/HOME/PATH/SHELL). It has no env builtins of its own yet -- that
         * is the follow-up PR -- but the table must already be populated when
         * they arrive, or the first thing a SYS_ENV read returns is nothing. */
        env_inherit_exported(self, task);
    }

    scheduler_add_task(task);

    /* Block on the same wait-queue path userspace waitpid() uses. The return
     * value is the child's exit status (0..255), which is how the ring-3
     * shell's `kshell` asks for the kernel loop. */
    int status = sys_waitpid(pid);

    task_t* child = task_get((uint32_t)pid);
    if (child && child->state == TASK_STATE_TERMINATED) {
        CRITICAL_SECTION_ENTER();
        scheduler_remove_task(child);
        CRITICAL_SECTION_EXIT();
    }

    /* A negative return is a waitpid error, not a status; treat it as a plain
     * exit rather than letting -Exxx be mistaken for a request. */
    if (status == SHELL_EXIT_WANT_KERNEL_SHELL) {
        return 1;
    }
    return 0;
}

void shell_task(void) {
    kprintf("[SHELL] Shell task started! (ESP check)\n");

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

        /* Populate this session's environment and aliases.
         *
         * Per SESSION, not once at boot. Storage is per-task (task->env), so
         * there is no global table a boot-time call could fill; and running it
         * here means a logout/login as a different user starts from the
         * defaults rather than inheriting the previous user's variables.
         * env_init() clears before setting, so the re-run on each login is
         * the reset. */
        env_init();

        /* Same reasoning, and the same reason it belongs HERE rather than
         * once at task start: the history buffer is a single global in this
         * task, so a session that ended at logout left its command lines
         * readable -- with `history` -- by whoever logged in next. Command
         * lines carry arguments, and `passwd`-adjacent typos carry more than
         * that. history_init() clears, so re-running it is the reset. */
        history_init();

        /* USER defaults to "root" in env_init(); correct it to whoever actually
         * logged in. `su` is the OTHER caller of this helper -- see there. */
        env_refresh_identity();

        /* Display welcome message with ASCII art */
        kprintf("\n");
        kprintf("   (\\_/) Hearty <3\n");
        kprintf("   (o.o) Thoughts ooO\n");
        kprintf("------------------------\n");
        kprintf("|  Welcome Home!       |\n");
        kprintf("------------------------\n");
        kprintf("\n");

        /* The ring-3 shell is the default login shell. It blocks until the
         * user exits it, which IS the logout — control lands back here and the
         * session loop restarts at the login prompt.
         *
         * On failure (missing/unsigned/unloadable shell.elf) we fall through
         * to the kernel command loop below, so the system stays usable. The
         * kernel shell is also still reachable on purpose: the ring-3 shell
         * has none of the privileged commands yet, so a user who needs
         * `shutdown` or `useradd` types `kshell` to drop into this loop. */
        if (launch_login_shell() == 0) {
            /* Ring-3 shell exited => logout. Skip the kernel command loop and
             * go straight back to the login prompt. */
            console_clear();
            kprintf("\n");
            continue;
        }
        /* Either the ring-3 shell could not run, or the user typed `kshell`.
         * Both land in the kernel command loop below. */

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
