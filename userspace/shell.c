/*=============================================================================
 * shell.c - TinyOS shell, running in ring 3.
 *
 * The first step of roadmap item 4. This is a REAL shell built entirely on the
 * syscall foundation from PRs #43-#47: every builtin here reaches the
 * filesystem through open/read/readdir/stat/lseek/mkdir/rmdir/unlink/chdir,
 * and external programs run via spawn+waitpid. Nothing touches a kernel
 * structure directly.
 *
 * The kernel shell is untouched and stays the default; reach this one with
 *
 *     exec /shell.elf
 *
 * Deliberately NOT implemented, because the syscalls do not exist yet:
 * pipes and redirection (need pipe/dup2), and the privileged commands
 * (pae, mem, wxaudit, auditlog, useradd, passwd, shutdown, networking).
 * Those stay in the kernel shell until their syscalls land.
 *=============================================================================*/

#include "libc.h"

#define MAX_LINE   256
#define MAX_ARGS   32
#define PATH_MAX   256

/*-----------------------------------------------------------------------------
 * Error reporting
 *
 * The syscalls return negative errno values straight from the VFS. Mapping
 * them to text here keeps every builtin's failure path a single line.
 *---------------------------------------------------------------------------*/
static const char* errstr(int err) {
    switch (err) {
        case -2:  return "no such file or directory";
        case -13: return "permission denied";
        case -17: return "file exists";
        case -20: return "not a directory";
        case -21: return "is a directory";
        case -22: return "invalid argument";
        case -34: return "result too large";
        case -39: return "directory not empty";
        default:  return "operation failed";
    }
}

static void fail(const char* cmd, const char* arg, int err) {
    if (arg) {
        printf("%s: %s: %s\n", cmd, arg, errstr(err));
    } else {
        printf("%s: %s\n", cmd, errstr(err));
    }
}

/*-----------------------------------------------------------------------------
 * Builtins
 *---------------------------------------------------------------------------*/

static void cmd_help(void) {
    print("TinyOS ring-3 shell. Builtins:\n"
          "  help              this message\n"
          "  echo [args...]    print arguments\n"
          "  pwd               print working directory\n"
          "  cd [dir]          change directory (no arg: D:/)\n"
          "  ls [dir]          list a directory (default: .)\n"
          "  cat <file>...     print file contents\n"
          "  stat <path>...    show size and type\n"
          "  mkdir <dir>...    create directories\n"
          "  rmdir <dir>...    remove empty directories\n"
          "  rm <file>...      remove files\n"
          "  write <f> <text>  write text to a file (truncates)\n"
          "  getpid            print this shell's pid\n"
          "  id                print uid and gid\n"
          "  kshell            switch to the kernel shell (see below)\n"
          "  exit / logout     log out and return to the login prompt\n"
          "\n"
          "Anything else is run as a program: a name containing '/' or ending\n"
          "in .elf is spawned, and the shell waits for it unless it ends '&'.\n"
          "\n"
          "This shell runs at ring 3 and reaches the system only through\n"
          "syscalls. It does not yet cover everything: user management,\n"
          "shutdown/reboot, ps/top/kill, the security tooling, networking,\n"
          "pipes and redirection still live in the kernel shell. Type\n"
          "`kshell` to get there.\n");
}

static void cmd_echo(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        if (i > 1) print(" ");
        print(argv[i]);
    }
    print("\n");
}

static void cmd_pwd(void) {
    char buf[PATH_MAX];
    int n = getcwd(buf, sizeof(buf));
    if (n < 0) {
        fail("pwd", 0, n);
        return;
    }
    printf("%s\n", buf);
}

static void cmd_cd(int argc, char** argv) {
    /* Bare `cd` goes to D:/, this system's equivalent of $HOME. */
    const char* target = (argc > 1) ? argv[1] : "D:/";
    int err = chdir(target);
    if (err < 0) {
        fail("cd", target, err);
    }
}

static void cmd_ls(int argc, char** argv) {
    const char* path = (argc > 1) ? argv[1] : ".";

    int fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        fail("ls", path, fd);
        return;
    }

    /* readdir returns whole records, so read a few at a time rather than one
     * syscall per entry. */
    dirent_t ents[8];
    int count = 0;
    for (;;) {
        int n = readdir(fd, ents, sizeof(ents));
        if (n < 0) {
            fail("ls", path, n);
            break;
        }
        if (n == 0) break;

        int have = n / (int)sizeof(dirent_t);
        for (int i = 0; i < have; i++) {
            if (ents[i].type == DT_DIR) {
                printf("%s/\n", ents[i].name);
            } else {
                printf("%s\n", ents[i].name);
            }
            count++;
        }
    }
    close(fd);

    if (count == 0) {
        print("(empty)\n");
    }
}

static void cmd_cat(int argc, char** argv) {
    if (argc < 2) {
        print("usage: cat <file>...\n");
        return;
    }

    for (int i = 1; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY);
        if (fd < 0) {
            fail("cat", argv[i], fd);
            continue;
        }

        char buf[128];
        for (;;) {
            int n = read(fd, buf, sizeof(buf));
            if (n < 0) {
                fail("cat", argv[i], n);
                break;
            }
            if (n == 0) break;
            write(1, buf, (size_t)n);
        }
        close(fd);
    }
}

static void cmd_stat(int argc, char** argv) {
    if (argc < 2) {
        print("usage: stat <path>...\n");
        return;
    }

    for (int i = 1; i < argc; i++) {
        dirent_t st;
        int err = stat(argv[i], &st, sizeof(st));
        if (err < 0) {
            fail("stat", argv[i], err);
            continue;
        }
        printf("%s  size=%u  %s\n", argv[i], st.size,
               st.type == DT_DIR ? "directory" : "file");
    }
}

/* mkdir/rmdir/rm differ only in which syscall they call and what they are
 * called, so one helper covers all three. */
typedef int (*path_op_t)(const char*);

static void cmd_path_op(int argc, char** argv, path_op_t op, const char* name) {
    if (argc < 2) {
        printf("usage: %s <path>...\n", name);
        return;
    }
    for (int i = 1; i < argc; i++) {
        int err = op(argv[i]);
        if (err < 0) {
            fail(name, argv[i], err);
        }
    }
}

static void cmd_write(int argc, char** argv) {
    if (argc < 3) {
        print("usage: write <file> <text...>\n");
        return;
    }

    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) {
        fail("write", argv[1], fd);
        return;
    }

    for (int i = 2; i < argc; i++) {
        if (i > 2) write(fd, " ", 1);
        int len = (int)strlen(argv[i]);
        int n = write(fd, argv[i], (size_t)len);
        if (n < 0) {
            fail("write", argv[1], n);
            close(fd);
            return;
        }
    }
    write(fd, "\n", 1);
    close(fd);
}

static void cmd_id(void) {
    printf("uid=%d gid=%d\n", getuid(), getgid());
}

/*-----------------------------------------------------------------------------
 * External programs
 *
 * spawn() does not block, so a foreground command is spawn + waitpid and a
 * background one is spawn alone. The child inherits stdin/stdout/stderr.
 *---------------------------------------------------------------------------*/
static void run_program(int argc, char** argv, int background) {
    (void)argc;

    /* Copy the path out of argv rather than passing argv[0] itself. The two
     * arguments would otherwise alias the same user string, and the kernel
     * resolves the path against the cwd before reading the vector. */
    char path[PATH_MAX];
    size_t plen = strlen(argv[0]);
    if (plen >= sizeof(path)) {
        printf("%s: path too long\n", argv[0]);
        return;
    }
    memcpy(path, argv[0], plen + 1);

    int pid = spawn(path, argv);
    if (pid < 0) {
        fail(argv[0], 0, pid);
        return;
    }

    if (background) {
        printf("[%d] %s\n", pid, argv[0]);
        return;
    }

    int status = waitpid(pid);
    if (status != 0) {
        printf("%s: exited with status %d\n", argv[0], status);
    }
}

/*-----------------------------------------------------------------------------
 * Parsing
 *
 * Splits on runs of spaces/tabs in place. Quoting is deliberately absent: the
 * kernel shell does not support it either, and adding it here would be a
 * behaviour change smuggled into a migration.
 *---------------------------------------------------------------------------*/
static int split_args(char* line, char** argv, int max) {
    int argc = 0;
    char* p = line;

    while (*p && argc < max - 1) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') break;

        argv[argc++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) {
            *p = '\0';
            p++;
        }
    }
    argv[argc] = 0;
    return argc;
}

/* A trailing '&' backgrounds the command. It may be its own word or stuck to
 * the last one ("sleeper.elf&"); both forms are stripped here so the argv the
 * child sees never contains it. */
static int take_background_flag(int* argc, char** argv) {
    if (*argc == 0) return 0;

    char* last = argv[*argc - 1];
    size_t len = strlen(last);

    if (strcmp(last, "&") == 0) {
        argv[--(*argc)] = 0;
        return 1;
    }
    if (len > 0 && last[len - 1] == '&') {
        last[len - 1] = '\0';
        return 1;
    }
    return 0;
}

/* A word is a program rather than a builtin if it names a path or an ELF. */
static int looks_like_program(const char* word) {
    if (strchr(word, '/') != 0) return 1;

    size_t len = strlen(word);
    return len > 4 && strcmp(word + len - 4, ".elf") == 0;
}

/*-----------------------------------------------------------------------------
 * Dispatch
 *
 * Returns 0 to keep looping, or 1 to exit the shell (with *status set).
 *---------------------------------------------------------------------------*/
static int dispatch(int argc, char** argv, int background, int* status) {
    const char* cmd = argv[0];

    if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "logout") == 0) {
        *status = (argc > 1) ? atoi(argv[1]) : 0;
        return 1;
    }

    /* Hand this session over to the kernel shell, which still owns everything
     * privileged (users, shutdown, ps/kill, security tooling, networking) plus
     * pipes and redirection. We cannot set a flag in the kernel from here, so
     * the request travels as the exit status: the parent recognises 70 and
     * runs its own command loop instead of returning to the login prompt.
     * Keep in sync with SHELL_EXIT_WANT_KERNEL_SHELL in src/shell.c. */
    if (strcmp(cmd, "kshell") == 0) {
        print("Switching to the kernel shell; `logout` there returns to login.\n");
        *status = 70;
        return 1;
    }

    if (strcmp(cmd, "help") == 0)   { cmd_help();               return 0; }
    if (strcmp(cmd, "echo") == 0)   { cmd_echo(argc, argv);     return 0; }
    if (strcmp(cmd, "pwd") == 0)    { cmd_pwd();                return 0; }
    if (strcmp(cmd, "cd") == 0)     { cmd_cd(argc, argv);       return 0; }
    if (strcmp(cmd, "ls") == 0)     { cmd_ls(argc, argv);       return 0; }
    if (strcmp(cmd, "cat") == 0)    { cmd_cat(argc, argv);      return 0; }
    if (strcmp(cmd, "stat") == 0)   { cmd_stat(argc, argv);     return 0; }
    if (strcmp(cmd, "write") == 0)  { cmd_write(argc, argv);    return 0; }
    if (strcmp(cmd, "id") == 0)     { cmd_id();                 return 0; }

    if (strcmp(cmd, "mkdir") == 0) { cmd_path_op(argc, argv, mkdir,  "mkdir"); return 0; }
    if (strcmp(cmd, "rmdir") == 0) { cmd_path_op(argc, argv, rmdir,  "rmdir"); return 0; }
    if (strcmp(cmd, "rm") == 0)    { cmd_path_op(argc, argv, unlink, "rm");    return 0; }

    if (strcmp(cmd, "getpid") == 0) {
        printf("%d\n", getpid());
        return 0;
    }

    if (looks_like_program(cmd)) {
        run_program(argc, argv, background);
        return 0;
    }

    printf("%s: not found (try 'help')\n", cmd);
    return 0;
}

/*-----------------------------------------------------------------------------
 * Main loop
 *---------------------------------------------------------------------------*/
int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    print("\nTinyOS shell (ring 3) - 'help' for builtins, 'kshell' for the "
          "kernel shell, 'exit' to log out\n");

    char line[MAX_LINE];
    char* args[MAX_ARGS];
    int status = 0;

    for (;;) {
        /* The prompt carries the cwd, which is the whole point of having one. */
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) >= 0) {
            printf("%s $ ", cwd);
        } else {
            print("$ ");
        }

        int n = readline(line, sizeof(line));
        if (n < 0) {
            /* stdin is gone; there is no more input to act on. */
            print("\n");
            break;
        }

        /* Echo the accepted line. The kernel echoes keystrokes in the keyboard
         * IRQ, which reaches the VGA console but NOT the serial log, so
         * without this a serial transcript shows output with no commands.
         * readline() has already stripped the newline. */
        printf("%s\n", line);

        if (n == 0) continue;

        int nargs = split_args(line, args, MAX_ARGS);
        if (nargs == 0) continue;

        int background = take_background_flag(&nargs, args);
        if (nargs == 0) continue;

        if (dispatch(nargs, args, background, &status)) {
            break;
        }
    }

    /* "shell: exiting" is load-bearing — verify-usershell.sh greps for it.
     * Keep it byte-identical. */
    print("shell: exiting\n");
    return status;
}
