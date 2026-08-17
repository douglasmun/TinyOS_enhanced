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
 * Redirection, pipelines, the credential commands, and ps/kill/top have since
 * landed. Still kernel-shell only, because their syscalls do not exist:
 * shutdown/reboot, the security tooling (pae, mem, wxaudit, auditlog) and
 * networking.
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
        case -1:  return "operation not permitted";
        case -2:  return "no such file or directory";
        case -11: return "resource limit reached (too many processes)";
        case -13: return "permission denied";
        case -17: return "file exists";
        case -18: return "cannot redirect across drives (D: only)";
        case -20: return "not a directory";
        case -21: return "is a directory";
        case -22: return "invalid argument";
        case -34: return "result too large";
        case -36: return "path too long";
        case -38: return "not supported";
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
          "  cat [file]...     print file contents (no arg: copy stdin)\n"
          "  stat <path>...    show size, mode and type\n"
          "  chmod <mode> <f>  change permission bits (octal; RAM disk only)\n"
          "  mkdir <dir>...    create directories\n"
          "  rmdir <dir>...    remove empty directories\n"
          "  rm <file>...      remove files\n"
          "  write <f> <text>  write text to a file (truncates)\n"
          "  cp <src> <dst>    copy a file\n"
          "  mv <src> <dst>    move a file (copy then remove)\n"
          "  touch <file>...   create a file if it does not exist\n"
          "  getpid            print this shell's pid\n"
          "  id                print uid and gid\n"
          "  date              print the date, time and uptime\n"
          "  env               list environment variables\n"
          "  set [NAME=VALUE]  set a variable (no arg: list)\n"
          "  unset <NAME>      remove a variable\n"
          "  export <NAME>     mark a variable for inheritance by children\n"
          "  alias [n='cmd']   define or list aliases\n"
          "  ps [-l]           list your processes (root: all)\n"
          "  kill <pid>        terminate a process\n"
          "  top               one-shot snapshot of CPU use\n"
          "  passwd [user]     change a password (no arg: your own)\n"
          "  useradd <user>    create a user  (root only)\n"
          "  userdel <user>    delete a user  (root only)\n"
          "  kshell            switch to the kernel shell (see below)\n"
          "  exit / logout     log out and return to the login prompt\n"
          "\n"
          "Anything else is run as a program: a name containing '/' or ending\n"
          "in .elf is spawned, and the shell waits for it unless it ends '&'.\n"
          "\n"
          "Redirection works on builtins and programs alike:\n"
          "  cmd > file        send output to file (truncates)\n"
          "  cmd >> file       append output to file\n"
          "  cmd < file        read input from file\n"
          "Targets must be on D: (the RAM disk); C: is not redirectable.\n"
          "\n"
          "Pipelines run both stages at once, connected by a real pipe:\n"
          "  prog.elf | prog.elf     output of the left feeds the right\n"
          "Both sides must be programs — a builtin runs inside the shell\n"
          "itself, which cannot be both stages at once. `kshell` has\n"
          "pipelines that work with builtins.\n"
          "\n"
          "passwd/useradd/userdel prompt for the password in the KERNEL, not\n"
          "here: this shell never holds one, and cannot leak what it never\n"
          "sees. Permission is the same root check the kernel shell applies.\n"
          "\n"
          "ps shows YOUR processes; root sees every process. kill answers\n"
          "the same way: a pid you cannot see reads as 'no such process',\n"
          "so the two commands agree about what exists. `top` here is a\n"
          "one-shot snapshot -- kshell's is the live, interactive one.\n"
          "\n"
          "This shell runs at ring 3 and reaches the system only through\n"
          "syscalls. It does not yet cover everything: shutdown/reboot,\n"
          "the security tooling and networking still live in the kernel\n"
          "shell. Type `kshell` to get there.\n");
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

/* Output format deliberately matches the kernel shell's cmd_date
 * (shell_system.c): two shells printing the same clock in two formats is a
 * gratuitous difference for anyone comparing them side by side. */
static void cmd_date(void) {
    static const char* const day_names[] = {"Sun", "Mon", "Tue", "Wed",
                                            "Thu", "Fri", "Sat"};
    static const char* const month_names[] = {"", "Jan", "Feb", "Mar", "Apr",
                                              "May", "Jun", "Jul", "Aug",
                                              "Sep", "Oct", "Nov", "Dec"};
    systime_t t;
    int err = systime(&t, sizeof(t));
    if (err < 0) {
        fail("date", 0, err);
        return;
    }

    /* Bound both indices before use. The kernel builds this record from RTC
     * hardware, so a wedged clock reporting month 0xFF would otherwise read
     * off the end of month_names -- cheap to check, and the alternative is a
     * ring-3 crash on a bad battery. */
    const char* dow = (t.weekday < 7) ? day_names[t.weekday] : "???";
    const char* mon = (t.month >= 1 && t.month <= 12) ? month_names[t.month] : "???";

    printf("%s %s %2d %02d:%02d:%02d %04d\n",
           dow, mon, t.day, t.hour, t.minute, t.second, t.year);

    uint32_t up = t.uptime_seconds;
    uint32_t days = up / 86400;
    printf("Uptime: ");
    if (days > 0) {
        printf("%d day%s, ", days, days == 1 ? "" : "s");
    }
    printf("%02d:%02d:%02d\n", (up % 86400) / 3600, (up % 3600) / 60, up % 60);
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

/* Copies an already-open fd to stdout. Shared by `cat <file>` and the no-arg
 * `cat`, which reads fd 0 — the only way `<` is observable from a builtin. */
static void cat_fd(int fd, const char* label) {
    char buf[128];
    for (;;) {
        int n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            fail("cat", label, n);
            return;
        }
        if (n == 0) return;
        write(1, buf, (size_t)n);
    }
}

static void cmd_cat(int argc, char** argv) {
    if (argc < 2) {
        /* No operands: copy stdin. This is what makes `cat < file` mean
         * anything — nothing else in the shell reads fd 0 on demand. With
         * stdin left on the console it reads typed lines instead, the same way
         * the prompt does, which is the conventional behaviour. */
        cat_fd(0, "(stdin)");
        return;
    }

    for (int i = 1; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY);
        if (fd < 0) {
            fail("cat", argv[i], fd);
            continue;
        }

        cat_fd(fd, argv[i]);
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
        /* Printed as three separate digits because this printf has no %o.
         * Adding one would be the tidier fix, but chmod is the only caller
         * that needs octal and a half-used conversion is a maintenance cost;
         * the arithmetic below cannot silently render the wrong base.
         * mode is the ONLY way a ring-3 caller can observe its own chmod --
         * dirent_t carries it, cmd_stat simply used to drop it. */
        unsigned m = st.mode & 0777;
        printf("%s  size=%u  mode=%d%d%d  %s\n", argv[i], st.size,
               (m >> 6) & 7, (m >> 3) & 7, m & 7,
               st.type == DT_DIR ? "directory" : "file");
    }
}

/* Parse an octal mode the way the kernel shell's cmd_chmod does, so "0644",
 * "0o644" and "644" all mean the same thing in both shells. Returns the mode,
 * or -1 if the string is not wholly octal -- checked rather than assumed,
 * because atoi() would read "699" as 699 decimal and hand the kernel a mode
 * the user never typed.
 *
 * The >0777 rejection here makes sys_chmod's identical check unreachable from
 * THIS shell, which does not make the kernel's copy dead: anything can issue
 * int 0x80 with whatever mode it likes, and the kernel is the only side that
 * gets to decide. Don't delete it as redundant. */
static int parse_octal_mode(const char* s) {
    const char* p = s;
    int seen = 0;
    int mode = 0;

    if (*p == '0') {
        /* Consume an "0o"/"0O" prefix. A lone leading '0' is a digit, not a
         * prefix, so only step over it when 'o' follows. */
        if (p[1] == 'o' || p[1] == 'O') {
            p += 2;
        }
    }
    while (*p >= '0' && *p <= '7') {
        mode = mode * 8 + (*p - '0');
        if (mode > 0777) {
            return -1;
        }
        seen = 1;
        p++;
    }
    if (!seen || *p != '\0') {
        return -1;
    }
    return mode;
}

/* The authorization for this lives in ramfs_chmod, not here and not in the
 * syscall -- see the comment at ramfs.c's ownership check (PR #69). This
 * builtin only parses and reports; a refusal it prints was decided three
 * layers down. */
static void cmd_chmod(int argc, char** argv) {
    if (argc < 3) {
        print("usage: chmod <mode> <file>...\n"
              "       mode is octal, e.g. 644 or 755\n");
        return;
    }

    int mode = parse_octal_mode(argv[1]);
    if (mode < 0) {
        printf("chmod: invalid mode: '%s' (octal, 0-777)\n", argv[1]);
        return;
    }

    for (int i = 2; i < argc; i++) {
        int err = chmod(argv[i], (unsigned int)mode);
        if (err == -ELIBC_EXDEV) {
            /* Distinct from the generic errstr text, which describes this
             * errno in terms of redirection. FAT32 has no owner to check. */
            printf("chmod: %s: only files on the RAM disk have permissions\n",
                   argv[i]);
        } else if (err < 0) {
            fail("chmod", argv[i], err);
        }
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

/*-----------------------------------------------------------------------------
 * cp / mv / touch
 *
 * All three are pure userspace: open/read/write/stat/unlink already cross the
 * ring boundary, so nothing here needed a new syscall.
 *---------------------------------------------------------------------------*/

/* Returns 1 if `path` is a directory, 0 if it is not, and 0 if it does not
 * exist (the caller's subsequent open() reports the real error -- deciding
 * "missing" here would duplicate that and get the errno wrong). */
static int is_dir(const char* path) {
    dirent_t st;
    if (stat(path, &st, sizeof(st)) < 0) return 0;
    return st.type == DT_DIR;
}

/* Copies src -> dst, returning 0 or a negative errno.
 *
 * O_TRUNC is load-bearing, not decoration: ramfs_write only ever GROWS a
 * file, so copying a short file over a longer one without truncating leaves
 * the previous tail in place. That flag was silently ignored by the ramfs VFS
 * layer until this change wired it to ramfs_truncate() -- see ramfs_vfs.c. A
 * cp built on the old behaviour would have quietly corrupted its output.
 *
 * The buffer is 128 bytes to match cat_fd(); this runs on the ring-3 stack,
 * so it stays small deliberately. */
static int copy_file(const char* src, const char* dst, const char* who) {
    int in = open(src, O_RDONLY);
    if (in < 0) return in;

    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC);
    if (out < 0) {
        close(in);
        return out;
    }

    char buf[128];
    int rc = 0;
    for (;;) {
        int n = read(in, buf, sizeof(buf));
        if (n < 0) { rc = n; break; }
        if (n == 0) break;

        /* Loop on the write: a short write is not an error, and treating it
         * as completion would truncate the copy silently. cat_fd() ignores
         * this because a short write to the console costs a garbled line;
         * here it would cost file contents. */
        int off = 0;
        int stalled = 0;
        while (off < n) {
            int w = write(out, buf + off, (size_t)(n - off));
            if (w < 0) { rc = w; break; }
            if (w == 0) { stalled = 1; break; }  /* no progress; see below */
            off += w;
        }
        if (rc < 0) break;
        if (stalled) {
            /* write() returned 0 with bytes still pending. Retrying would
             * spin forever, and there is no errno in the userspace headers
             * that honestly describes it, so report it in plain terms rather
             * than borrowing a code that means something else. */
            printf("%s: %s: write stalled with %d byte(s) unwritten\n",
                   who, dst, n - off);
            rc = -1;
            break;
        }
    }

    close(in);
    close(out);
    return rc;
}

static void cmd_cp(int argc, char** argv) {
    if (argc != 3) {
        print("usage: cp <src> <dst>\n");
        return;
    }

    /* Refuse both directory operands rather than half-doing them. There is no
     * readdir-based recursive walk here and no rename syscall, so `cp -r` and
     * "copy into a directory" would each be a different feature; failing
     * clearly beats creating a file whose name happens to be a directory's. */
    if (is_dir(argv[1])) {
        printf("cp: %s: is a directory\n", argv[1]);
        return;
    }
    if (is_dir(argv[2])) {
        printf("cp: %s: is a directory\n", argv[2]);
        return;
    }

    /* Self-copy would otherwise open the same file for read and for write,
     * and the O_TRUNC above would empty it before the first read -- turning
     * `cp f f` into `rm f`. Compared by path string, which is the only
     * identity userspace can see: there is no inode number in dirent_t. That
     * catches the literal case; two different paths naming one file (via a
     * symlink) are not detectable from here and are not claimed to be. */
    if (strcmp(argv[1], argv[2]) == 0) {
        printf("cp: %s and %s are the same file\n", argv[1], argv[2]);
        return;
    }

    int rc = copy_file(argv[1], argv[2], "cp");
    if (rc < 0) fail("cp", argv[1], rc);
}

static void cmd_mv(int argc, char** argv) {
    if (argc != 3) {
        print("usage: mv <src> <dst>\n");
        return;
    }

    if (is_dir(argv[1])) {
        printf("mv: %s: is a directory\n", argv[1]);
        return;
    }
    if (is_dir(argv[2])) {
        printf("mv: %s: is a directory\n", argv[2]);
        return;
    }

    /* `mv f f` is a no-op, and must NOT fall through to copy-then-unlink --
     * that sequence would copy the file onto itself and then delete it. */
    if (strcmp(argv[1], argv[2]) == 0) {
        return;
    }

    /* Copy then unlink, because there is no rename syscall. This is not
     * atomic: an interruption between the two steps leaves both files, which
     * is the recoverable direction. The unlink is deliberately conditional on
     * the copy succeeding -- unlinking first, or unconditionally, would lose
     * the source when the destination could not be written (no space, no
     * permission), and the source is the only copy the user still has. */
    int rc = copy_file(argv[1], argv[2], "mv");
    if (rc < 0) {
        fail("mv", argv[1], rc);
        return;
    }

    rc = unlink(argv[1]);
    if (rc < 0) {
        /* The data is safe in dst; say so rather than reporting a bare
         * failure, because the user's next move depends on which file now
         * holds their content. */
        printf("mv: %s: copied to %s but source not removed: %s\n",
               argv[1], argv[2], errstr(rc));
    }
}

static void cmd_touch(int argc, char** argv) {
    if (argc < 2) {
        print("usage: touch <file>...\n");
        return;
    }

    for (int i = 1; i < argc; i++) {
        /* No O_TRUNC: touch must not destroy an existing file's contents.
         * Opening for write is what creates a missing one -- ramfs_open
         * auto-creates on write, which is why O_CREAT alone is enough and why
         * this cannot be an O_RDONLY open.
         *
         * There is no utime syscall, so this does not update a timestamp on a
         * file that already exists; it is create-if-missing only. Said plainly
         * because a `touch` that silently fails to do the other half of its
         * job is worse than one that never claimed to. */
        int fd = open(argv[i], O_WRONLY | O_CREAT);
        if (fd < 0) {
            fail("touch", argv[i], fd);
            continue;
        }
        close(fd);
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
 * ps / kill / top
 *
 * WHICH processes appear here is the KERNEL's decision, not this shell's: an
 * unprivileged caller gets only its own records back from psinfo(). Nothing is
 * filtered on this side, and nothing needs to be -- a program supplying its own
 * syscall stub would get the same filtered answer. See SYS_PSINFO in
 * src/syscall.h.
 *
 * MAX_PS_RECORDS matches MAX_TASKS in src/process.h: the whole table is the
 * most the kernel can ever return, so one call always suffices and there is no
 * pagination to get wrong. 32 * 64 bytes is 2 KB of the 1 MB user stack.
 *---------------------------------------------------------------------------*/
#define MAX_PS_RECORDS 32

static const char* ps_state_str(uint32_t state) {
    switch (state) {
        case PS_READY:      return "READY";
        case PS_RUNNING:    return "RUN";
        case PS_BLOCKED:    return "BLOCK";
        case PS_SLEEPING:   return "SLEEP";
        case PS_ZOMBIE:     return "ZOMBI";
        case PS_TERMINATED: return "TERM";
        default:            return "UNK";
    }
}

/* Shared by ps and top: fetch the visible table into `buf`, returning the
 * record count, or a negative errno already reported to the user. */
static int ps_fetch(psinfo_t* buf, const char* who) {
    int n = psinfo(buf, sizeof(psinfo_t) * MAX_PS_RECORDS);
    if (n < 0) {
        printf("%s: %s\n", who, errstr(n));
        return n;
    }
    return n / (int)sizeof(psinfo_t);
}

static void cmd_ps(int argc, char** argv) {
    int long_format = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            long_format = 1;
        } else if (strcmp(argv[i], "-h") == 0) {
            print("usage: ps [-l]\n  -l  long format (ppid, priority, ticks)\n");
            return;
        }
    }

    psinfo_t procs[MAX_PS_RECORDS];
    int count = ps_fetch(procs, "ps");
    if (count < 0) {
        return;
    }

    /* PID and PPID are 5 wide, not 3. PIDs here are NOT sequential --
     * task_alloc_pid() draws them from the CSPRNG, so a normal boot shows
     * five-digit values and a 3-wide column overflows on every row, pushing
     * STATE out of alignment with its own header. */
    if (long_format) {
        print("PID    PPID   UID   PRI  STATE  TICKS   NAME\n");
        print("-----  -----  ---   ---  -----  ------  ----\n");
    } else {
        print("PID    STATE  NAME\n");
        print("-----  -----  ----\n");
    }

    for (int i = 0; i < count; i++) {
        psinfo_t* p = &procs[i];
        if (long_format) {
            printf("%-5u  %-5u  %-4u  %-3u  %-5s  %-6u  %s\n",
                   p->pid, p->ppid, p->uid, p->priority,
                   ps_state_str(p->state), p->total_ticks, p->name);
        } else {
            printf("%-5u  %-5s  %s\n", p->pid, ps_state_str(p->state), p->name);
        }
    }

    /* The count is what was PRINTED. The kernel already withheld the rest, and
     * a total larger than the table would restate exactly how many processes
     * are being hidden -- see the same rule in shell_monitor.c. */
    printf("\nTotal: %d process(es)\n", count);
}

static void cmd_kill(int argc, char** argv) {
    if (argc != 2) {
        print("usage: kill <pid>\n");
        return;
    }

    int pid = atoi(argv[1]);
    if (pid <= 0) {
        printf("kill: invalid PID: '%s'\n", argv[1]);
        return;
    }

    int err = kill(pid);
    if (err == 0) {
        printf("kill: terminated %d\n", pid);
        return;
    }

    /* -3 (ESRCH) covers "no such process" AND "not yours", deliberately and
     * identically: telling them apart would confirm the PID is live and let a
     * user enumerate what ps hides. Print the same words for both. */
    if (err == -ELIBC_ESRCH) {
        printf("kill: no such process: %d\n", pid);
    } else if (err == -ELIBC_EPERM) {
        printf("kill: cannot kill protected system process %d\n", pid);
    } else {
        printf("kill: %s\n", errstr(err));
    }
}

/*-----------------------------------------------------------------------------
 * top — a SNAPSHOT, not the kernel shell's interactive display.
 *
 * The kernel-shell `top` loops on keyboard_has_data() until 'q'. This shell
 * cannot do that: read() is line-buffered and blocks, so there is no way to
 * poll for a keypress without stopping the display. Rather than ship a `top`
 * that traps the session until Enter is pressed, this prints one frame and
 * returns -- composable with redirection and pipelines, which the interactive
 * version is not. `kshell` still has the live one.
 *---------------------------------------------------------------------------*/
static void cmd_top(int argc, char** argv) {
    (void)argc;
    (void)argv;

    psinfo_t procs[MAX_PS_RECORDS];
    int count = ps_fetch(procs, "top");
    if (count < 0) {
        return;
    }

    int running = 0, ready = 0, blocked = 0, sleeping = 0, zombie = 0;
    uint32_t total_ticks = 0;

    for (int i = 0; i < count; i++) {
        switch (procs[i].state) {
            case PS_RUNNING:  running++;  break;
            case PS_READY:    ready++;    break;
            case PS_BLOCKED:  blocked++;  break;
            case PS_SLEEPING: sleeping++; break;
            case PS_ZOMBIE:   zombie++;   break;
            default: break;
        }
        total_ticks += procs[i].total_ticks;
    }

    printf("Tasks: %d total (%d run, %d ready, %d block, %d sleep, %d zombie)\n\n",
           count, running, ready, blocked, sleeping, zombie);

    /* 5-wide PID, as in cmd_ps: these are random, not sequential. */
    print("PID    STATE  %CPU  TICKS   NAME\n");
    print("-----  -----  ----  ------  ----\n");

    /* Selection sort by ticks, descending. n is at most 32 and this runs once
     * per invocation, so the O(n^2) is irrelevant and it needs no scratch
     * buffer -- the records are swapped in place. */
    for (int i = 0; i < count; i++) {
        int max = i;
        for (int j = i + 1; j < count; j++) {
            if (procs[j].total_ticks > procs[max].total_ticks) {
                max = j;
            }
        }
        if (max != i) {
            psinfo_t tmp = procs[i];
            procs[i] = procs[max];
            procs[max] = tmp;
        }
    }

    int shown = (count < 10) ? count : 10;
    for (int i = 0; i < shown; i++) {
        psinfo_t* p = &procs[i];

        /* Percent of the ticks in THIS listing. For root that is the whole
         * machine; for an unprivileged user it is a share of their own
         * processes, which is the only denominator they are entitled to.
         * Integer math, no FPU in userspace: scale before dividing. */
        uint32_t pct = (total_ticks > 0)
                     ? (p->total_ticks * 100u) / total_ticks
                     : 0;

        printf("%-5u  %-5s  %-4u  %-6u  %s\n",
               p->pid, ps_state_str(p->state), pct, p->total_ticks, p->name);
    }

    if (count > shown) {
        printf("\n(%d more not shown)\n", count - shown);
    }
}

/*-----------------------------------------------------------------------------
 * Credential commands
 *
 * These are thin on purpose. The shell contributes only the operand: the
 * KERNEL prints the prompts, reads the password, applies the euid checks and
 * prints the result, so there is nothing here to get wrong and no window in
 * which this process holds a plaintext password.
 *
 * `passwd` with no operand means the calling user, which is the one case where
 * a missing argument is not an error. useradd and userdel require a name — the
 * kernel rejects a NULL for them, but catching it here gives a usage line
 * instead of a bare errno.
 *---------------------------------------------------------------------------*/
static int is_cred_cmd(const char* cmd) {
    return strcmp(cmd, "passwd") == 0 ||
           strcmp(cmd, "useradd") == 0 ||
           strcmp(cmd, "userdel") == 0;
}

static void cmd_cred(int argc, char** argv, int op, const char* name) {
    if (argc > 2) {
        printf("usage: %s %s\n", name,
               (op == CRED_PASSWD) ? "[user]" : "<user>");
        return;
    }

    const char* who = (argc > 1) ? argv[1] : 0;
    if (!who && op != CRED_PASSWD) {
        printf("usage: %s <user>\n", name);
        return;
    }

    int rc = cred(op, who);
    if (rc < 0) {
        /* The command already printed why on its own stream; add the errno only
         * so a caller reading a transcript can tell a refusal from a failure. */
        fail(name, who, rc);
    }
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
 *
 * '>' and '<' also END a word, so `echo a>b` splits as `echo` `a` `>b` — the
 * same way the kernel shell tokenises it (shell_redir.c stops a token at those
 * characters). Without this the two shells would disagree about a line that
 * looks identical in both, which is worse than either behaviour on its own.
 *
 * Splitting at an operator cannot be done purely in place: the word before it
 * needs its NUL exactly where the operator byte sits. So the operator and the
 * rest of the line are shifted one byte right, and the NUL goes in the gap.
 * That needs a spare byte, which is why `cap` (the buffer size, not the string
 * length) is a parameter — readline can return a line that fills the buffer
 * completely, and without the bound a line of all-operators would walk off the
 * end. When there is no room the operator is simply left glued to the word,
 * which parses as an ordinary argument: degraded, not corrupt.
 *---------------------------------------------------------------------------*/
static int is_redir_char(char c) {
    return c == '>' || c == '<';
}

static int split_args(char* line, size_t cap, char** argv, int max) {
    int argc = 0;
    char* p = line;
    size_t used = strlen(line) + 1;

    while (*p && argc < max - 1) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') break;

        argv[argc++] = p;

        if (is_redir_char(*p)) {
            /* An operator word: take the operator (two chars for ">>") plus a
             * glued target, stopping at the next operator. */
            if (p[0] == '>' && p[1] == '>') p += 2; else p++;
        }
        while (*p && *p != ' ' && *p != '\t' && !is_redir_char(*p)) p++;

        if (*p == '\0') break;

        if (is_redir_char(*p)) {
            if (used >= cap) break;
            memmove(p + 1, p, used - (size_t)(p - line));
            used++;
        }
        *p = '\0';
        p++;
    }
    argv[argc] = 0;
    return argc;
}

/* Split a line at the FIRST '|', in place: `line` keeps the left stage and the
 * return value points at the right one. Returns 0 when there is no pipe.
 *
 * Done before split_args, not after, because each side is then tokenised —
 * and redirected — entirely on its own. `a < in | b > out` therefore means what
 * it does in a real shell: the `<` belongs to the left stage and the `>` to the
 * right, rather than both being collected into one command's redirections.
 *
 * Unlike the '>' case in split_args this needs no byte shuffling: the '|' byte
 * itself is not part of either side, so it can simply become the left stage's
 * terminator. Only ONE pipe is recognised; see run_pipeline for why more would
 * need a different execution shape, and note that a second '|' is left in the
 * right stage's words rather than silently dropped. */
static char* split_pipeline(char* line) {
    for (char* p = line; *p; p++) {
        if (*p == '|') {
            *p = '\0';
            return p + 1;
        }
    }
    return 0;
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

/*-----------------------------------------------------------------------------
 * Redirection
 *
 * `>`, `>>` and `<` are stripped out of argv here, before dispatch, so every
 * builtin and every program gets them for free without knowing they exist: the
 * shell rebinds its OWN stdin/stdout, runs the command, and restores. Builtins
 * write through write(1, ...) and so land in the file; a spawned child inherits
 * the redirected stream at spawn time (the kernel copies streams into the child
 * in sys_spawn), so it lands there too.
 *
 * The operator may stand alone ("ls > out.txt") or be glued to its target
 * ("ls >out.txt"), matching the kernel shell.
 *---------------------------------------------------------------------------*/
typedef struct {
    const char* out_path;   /* 0 if no > or >>            */
    int         out_append; /* 1 for >>, 0 for >          */
    const char* in_path;    /* 0 if no <                  */
} redir_t;

/* Removes the redirection words from argv (compacting it) and fills `r`.
 * Returns 0 on success, -1 if an operator had no target — in which case the
 * caller must not run the command, since "ls >" would otherwise silently run
 * unredirected. */
static int take_redirections(int* argc, char** argv, redir_t* r) {
    r->out_path = 0;
    r->out_append = 0;
    r->in_path = 0;

    int out = 0;
    for (int i = 0; i < *argc; i++) {
        char* w = argv[i];
        const char** target = 0;
        const char* glued = 0;

        if (w[0] == '>') {
            target = &r->out_path;
            if (w[1] == '>') {
                r->out_append = 1;
                glued = w + 2;
            } else {
                r->out_append = 0;
                glued = w + 1;
            }
        } else if (w[0] == '<') {
            target = &r->in_path;
            glued = w + 1;
        } else {
            argv[out++] = w;
            continue;
        }

        if (*glued != '\0') {
            *target = glued;
        } else if (i + 1 < *argc) {
            *target = argv[++i];
        } else {
            return -1;
        }
    }

    *argc = out;
    argv[out] = 0;
    return 0;
}

/* Applies `r` to this process's own streams. On failure it restores whatever
 * it already changed, so the shell never ends up half-redirected and printing
 * its prompt into a file. Returns 0 or a negative errno. */
static int redir_apply(const redir_t* r) {
    if (r->in_path) {
        int err = redirect(0, r->in_path, REDIR_READ);
        if (err < 0) {
            fail("<", r->in_path, err);
            return err;
        }
    }
    if (r->out_path) {
        int err = redirect(1, r->out_path,
                           r->out_append ? REDIR_APPEND : REDIR_TRUNC);
        if (err < 0) {
            fail(r->out_append ? ">>" : ">", r->out_path, err);
            if (r->in_path) redirect(0, 0, REDIR_RESTORE);
            return err;
        }
    }
    return 0;
}

static void redir_undo(const redir_t* r) {
    if (r->out_path) redirect(1, 0, REDIR_RESTORE);
    if (r->in_path)  redirect(0, 0, REDIR_RESTORE);
}

/* A word is a program rather than a builtin if it names a path or an ELF. */
static int looks_like_program(const char* word) {
    if (strchr(word, '/') != 0) return 1;

    size_t len = strlen(word);
    return len > 4 && strcmp(word + len - 4, ".elf") == 0;
}

/*-----------------------------------------------------------------------------
 * Pipelines
 *
 * `producer | consumer` runs the two stages CONCURRENTLY, connected by a real
 * kernel pipe: both are spawned before either is reaped, so the consumer starts
 * draining while the producer is still writing. That is what makes the data
 * unbounded — the 4 KB buffer is a window, not a cap — and it is the difference
 * from the kernel shell, whose pipeline runs a stage to completion into a
 * buffer before starting the next one (fine there: its stages are function
 * calls, not processes).
 *
 * The shell never touches the data. It binds its OWN stdout to the pipe, spawns
 * the producer (which inherits it), binds its OWN stdin to the same pipe, spawns
 * the consumer, and then restores itself. Exactly the redirection mechanism,
 * used twice — no per-command plumbing, and no need for either program to know
 * it is in a pipeline.
 *
 * BOTH STAGES MUST BE PROGRAMS. A builtin runs inside the shell process itself,
 * and the shell cannot simultaneously be the producer and the consumer, so
 * `echo hi | cat` cannot work the way it does in the kernel shell. Refused with
 * a message that names the reason rather than mis-running it — the kernel shell
 * remains available via `kshell` for builtin pipelines.
 *
 * ORDERING IS LOAD-BEARING, in two places:
 *   - CLOSE_WRITE happens only after the producer is REAPED. Do it earlier and
 *     a still-running producer's writes hit a closed pipe (-EPIPE); never and
 *     the consumer blocks forever once it drains, because more data could
 *     always still arrive. Nothing in task teardown closes it for us: a dying
 *     child's inherited streams are deliberately marked borrowed.
 *   - RESTORE happens before either waitpid. The shell must not still be
 *     holding the pipe on its own stdin while it blocks, or its next readline
 *     would read the pipeline's data instead of the keyboard.
 *
 * PRECONDITION, enforced by the caller: lredir has no out_path and rredir has
 * no in_path. Those are the ends the pipe itself binds, and a stage redirect on
 * one of them would both fight the pipe for the stream AND make the undo below
 * unbind the pipe rather than the file. The caller refuses that line outright,
 * so what reaches here only ever touches the free end of each stage.
 *---------------------------------------------------------------------------*/
static int spawn_stage(int argc, char** argv) {
    (void)argc;

    char path[PATH_MAX];
    size_t plen = strlen(argv[0]);
    if (plen >= sizeof(path)) {
        return -36;  /* ENAMETOOLONG; the errno table above is raw numbers */
    }
    memcpy(path, argv[0], plen + 1);

    /* Silent on failure by design: the producer is spawned while stdout is the
     * pipe, so a message printed here would be fed to the consumer instead of
     * the user. Both callers report the returned errno once stdout is theirs
     * again. */
    return spawn(path, argv);
}

static void run_pipeline(int largc, char** largv, const redir_t* lredir,
                         int rargc, char** rargv, const redir_t* rredir) {
    if (!looks_like_program(largv[0]) || !looks_like_program(rargv[0])) {
        print("shell: pipelines connect two programs; a builtin runs inside "
              "the shell itself, which cannot be both stages at once\n");
        print("shell: use 'kshell' for pipelines involving builtins\n");
        return;
    }

    int id = pipe_op(PIPE_CREATE, 0);
    if (id < 0) {
        fail("pipe", 0, id);
        return;
    }

    /* stdout is the pipe from here until the UNBIND below, so anything printed
     * in that narrow window would be fed to the consumer as if it were the
     * producer's output. Only the producer's spawn happens inside it. */

    /* The producer's `< file`, applied only for as long as it takes to spawn
     * it. PIPE_CREATE already bound stdout, and this binds stdin, so the child
     * inherits both halves at once. */
    int lr = redir_apply(lredir);

    int prod = (lr < 0) ? lr : spawn_stage(largc, largv);

    /* Undo it immediately: the consumer's stdin is about to be bound to the
     * pipe, and leaving the producer's input file there would make the two
     * setups fight over the same stream. */
    redir_undo(lredir);

    /* The producer has its copy, so this stream must come off the write end
     * before the consumer is spawned: a child inherits stdout AS IT IS at spawn
     * time, and a consumer that inherited the write end would write its output
     * into the pipe it is reading instead of to the console. RESTORE is the
     * wrong tool here — it would reset stdin too, and stdin has to stay on the
     * read end across that spawn. */
    pipe_op(PIPE_UNBIND_STDOUT, id);

    if (prod < 0) {
        pipe_op(PIPE_RESTORE, id);
        pipe_op(PIPE_DESTROY, id);
        /* Reported only now: spawn_stage stays silent because at the moment it
         * failed, stdout was the pipe. */
        fail(largv[0], 0, prod);
        return;
    }

    if (pipe_op(PIPE_BIND_STDIN, id) < 0) {
        pipe_op(PIPE_RESTORE, id);
        pipe_op(PIPE_CLOSE_WRITE, id);
        waitpid(prod);
        pipe_op(PIPE_DESTROY, id);
        return;
    }

    /* The consumer's `> file`. Its stdin is the pipe (just bound above) and
     * this rebinds its stdout, which the pipe is not using on this side. */
    int rr = redir_apply(rredir);
    int cons = (rr < 0) ? rr : spawn_stage(rargc, rargv);
    redir_undo(rredir);

    /* Both stages now hold their inherited copies, so the shell's own streams
     * are free to go back to the console — and must, before it blocks. */
    pipe_op(PIPE_RESTORE, id);

    if (cons < 0) {
        /* No reader will ever drain this. Closing the READ end is what turns
         * the producer's writes into -EPIPE so it terminates instead of
         * blocking forever on a full pipe; DESTROY does that as part of
         * releasing the pipe, but the producer must be reaped first. */
        pipe_op(PIPE_CLOSE_WRITE, id);
        waitpid(prod);
        pipe_op(PIPE_DESTROY, id);
        fail(rargv[0], 0, cons);
        return;
    }

    int pstatus = waitpid(prod);
    pipe_op(PIPE_CLOSE_WRITE, id);
    int cstatus = waitpid(cons);

    pipe_op(PIPE_DESTROY, id);

    /* The pipeline's status is the LAST stage's, as in every real shell: it is
     * the one whose output the user actually sees. A failing producer is still
     * worth mentioning, because its output silently vanishing into a pipe is
     * exactly the case that looks like the consumer misbehaving. */
    if (pstatus != 0) {
        printf("%s: exited with status %d\n", largv[0], pstatus);
    }
    if (cstatus != 0) {
        printf("%s: exited with status %d\n", rargv[0], cstatus);
    }
}

/*-----------------------------------------------------------------------------
 * Alias substitution and $VAR expansion
 *
 * The ring-3 counterpart of src/shell.c:542 and :565. Both rewrite `line` in
 * place and are BEST EFFORT: if the result would not fit, the line is left
 * exactly as the user typed it. Half-substituting is the one outcome to avoid
 * -- a command truncated mid-argument can mean something entirely different
 * from what was typed, whereas an unexpanded one merely fails to do what was
 * meant, visibly.
 *---------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------
 * env / set / export / unset / alias
 *
 * All UNGATED: the table is this task's own, so every one of these must work
 * for an unprivileged user. A -ELIBC_EPERM from any of them is a kernel bug,
 * not something to report as a permission problem.
 *
 * The list walks skip empty slots rather than stopping at the first one --
 * env_list() returns 0 for a hole, and the table genuinely has holes once
 * anything has been unset.
 *---------------------------------------------------------------------------*/
static void cmd_env(void) {
    env_record_t rec;
    int shown = 0;

    for (unsigned int i = 0; i < ENV_LIST_MAX_SLOTS; i++) {
        int rc = env_list(i, &rec);
        if (rc < 0) {
            printf("env: %d\n", rc);
            return;
        }
        if (rc == 0) continue;          /* empty slot, not end of table */
        printf("%s=%s\n", rec.name, rec.value);
        shown++;
    }

    if (shown == 0) {
        print("(no variables)\n");
    }
}

static void cmd_set(int argc, char** argv) {
    /* Bare `set` lists, like the kernel shell's. */
    if (argc < 2) {
        cmd_env();
        return;
    }

    /* set NAME=VALUE, or set NAME VALUE. */
    char* eq = strchr(argv[1], '=');
    const char* name;
    const char* value;

    if (eq) {
        *eq = '\0';
        name = argv[1];
        value = eq + 1;
    } else if (argc >= 3) {
        name = argv[1];
        value = argv[2];
    } else {
        print("usage: set NAME=VALUE\n");
        return;
    }

    int rc = env_set_var(name, value);
    if (rc == -ELIBC_EINVAL) {
        printf("set: %s: invalid name (letters, digits, _; not leading digit)\n",
               name);
    } else if (rc < 0) {
        printf("set: %s: no room (table full)\n", name);
    }
}

static void cmd_unset(int argc, char** argv) {
    if (argc < 2) {
        print("usage: unset NAME\n");
        return;
    }
    if (env_unset_var(argv[1]) < 0) {
        printf("unset: %s: not set\n", argv[1]);
    }
}

static void cmd_export(int argc, char** argv) {
    if (argc < 2) {
        print("usage: export NAME  (or export NAME=VALUE)\n");
        return;
    }

    /* export NAME=VALUE sets and exports in one step, as bash does. */
    char* eq = strchr(argv[1], '=');
    if (eq) {
        *eq = '\0';
        int rc = env_set_var(argv[1], eq + 1);
        if (rc < 0) {
            printf("export: %s: could not set\n", argv[1]);
            return;
        }
    }

    if (env_export_var(argv[1]) < 0) {
        printf("export: %s: not set\n", argv[1]);
    }
}

static void cmd_alias(int argc, char** argv) {
    if (argc < 2) {
        env_record_t rec;
        int shown = 0;

        for (unsigned int i = 0; i < ALIAS_LIST_MAX_SLOTS; i++) {
            int rc = alias_list_get(i, &rec);
            if (rc < 0) {
                printf("alias: %d\n", rc);
                return;
            }
            if (rc == 0) continue;
            printf("alias %s='%s'\n", rec.name, rec.value);
            shown++;
        }

        if (shown == 0) {
            print("(no aliases)\n");
        }
        return;
    }

    char* eq = strchr(argv[1], '=');
    if (!eq) {
        /* Show one alias. */
        char cmd[ENV_REC_VALUE_LEN];
        if (alias_get_cmd(argv[1], cmd, sizeof(cmd)) == 0) {
            printf("alias %s='%s'\n", argv[1], cmd);
        } else {
            printf("alias: %s: not found\n", argv[1]);
        }
        return;
    }

    *eq = '\0';
    const char* name = argv[1];
    const char* value = eq + 1;

    /* Strip one layer of surrounding quotes, so `alias ll='ls -l'` stores
     * `ls -l` rather than `'ls`. This is where the KERNEL shell's cmd_alias
     * falls down: it reads argv[1] only, so the tokeniser has already split
     * the value at the first space and the rest is lost silently. Reassembling
     * from the remaining argv here is what makes a multi-word alias usable
     * from ring 3 at all. */
    char joined[ENV_REC_VALUE_LEN];
    size_t jl = 0;
    int quoted = (value[0] == '\'' || value[0] == '"');
    char qc = value[0];

    if (quoted) value++;

    for (size_t k = 0; value[k] && jl < sizeof(joined) - 1; k++) {
        joined[jl++] = value[k];
    }

    /* Append the remaining argv words, which the tokeniser split apart. */
    for (int a = 2; a < argc && jl < sizeof(joined) - 1; a++) {
        joined[jl++] = ' ';
        for (size_t k = 0; argv[a][k] && jl < sizeof(joined) - 1; k++) {
            joined[jl++] = argv[a][k];
        }
    }
    joined[jl] = '\0';

    /* Drop the closing quote if there was an opening one. */
    if (quoted && jl > 0 && joined[jl - 1] == qc) {
        joined[jl - 1] = '\0';
    }

    if (alias_set_cmd(name, joined) < 0) {
        printf("alias: %s: no room (table full)\n", name);
    }
}

/* Local, because userspace has no ctype.h. Matches env_is_valid_name()'s idea
 * of a name character in src/env.c -- a mismatch would have this shell parse a
 * name the kernel then rejects. */
static int isalnum_c(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

static void expand_aliases(char* line, size_t size) {
    /* First word only, like the kernel shell: an alias names a command, and
     * substituting anywhere else would rewrite arguments that merely happen to
     * match an alias name. */
    size_t wlen = 0;
    while (line[wlen] && line[wlen] != ' ' && wlen < ENV_REC_NAME_LEN - 1) {
        wlen++;
    }
    if (wlen == 0 || (line[wlen] && line[wlen] != ' ')) {
        return;  /* empty, or a first word too long to be an alias name */
    }

    char name[ENV_REC_NAME_LEN];
    memcpy(name, line, wlen);
    name[wlen] = '\0';

    char cmd[ENV_REC_VALUE_LEN];
    if (alias_get_cmd(name, cmd, sizeof(cmd)) != 0) {
        return;  /* not an alias; leave the line alone */
    }

    /* NO RECURSION. One pass only, so `alias ls='ls -l'` cannot loop forever.
     * The kernel shell has the same single-pass rule. */
    size_t clen = strlen(cmd);
    size_t rest = strlen(line + wlen);
    if (clen + rest + 1 > size) {
        return;
    }

    char out[MAX_LINE];
    if (clen + rest + 1 > sizeof(out)) {
        return;
    }
    memcpy(out, cmd, clen);
    memcpy(out + clen, line + wlen, rest);
    out[clen + rest] = '\0';

    memcpy(line, out, clen + rest + 1);
}

static void expand_vars(char* line, size_t size) {
    /* Nothing to do is the common case; skip the copy entirely. */
    int has_dollar = 0;
    for (size_t i = 0; line[i]; i++) {
        if (line[i] == '$') { has_dollar = 1; break; }
    }
    if (!has_dollar) {
        return;
    }

    char out[MAX_LINE];
    size_t o = 0;
    size_t i = 0;

    while (line[i]) {
        if (line[i] != '$') {
            if (o + 1 >= sizeof(out)) return;
            out[o++] = line[i++];
            continue;
        }

        /* ${VAR} and $VAR both, as the kernel shell accepts both. */
        i++;
        int braced = (line[i] == '{');
        if (braced) i++;

        char name[ENV_REC_NAME_LEN];
        size_t nlen = 0;
        while (line[i] && nlen < sizeof(name) - 1 &&
               (isalnum_c(line[i]) || line[i] == '_')) {
            name[nlen++] = line[i++];
        }
        name[nlen] = '\0';

        if (braced) {
            if (line[i] != '}') {
                /* Unclosed brace: emit what was consumed literally rather than
                 * guessing where the name ended. */
                if (o + nlen + 2 >= sizeof(out)) return;
                out[o++] = '$';
                out[o++] = '{';
                memcpy(out + o, name, nlen);
                o += nlen;
                continue;
            }
            i++;  /* consume '}' */
        }

        if (nlen == 0) {
            /* A bare '$' is itself, not the start of a name. */
            if (o + 1 >= sizeof(out)) return;
            out[o++] = '$';
            continue;
        }

        /* An UNSET variable expands to nothing, as in every POSIX shell --
         * NOT to its own name. Printing "$FOO" back would make a typo look
         * like a literal, and a script testing for emptiness would see a
         * non-empty string. */
        char value[ENV_REC_VALUE_LEN];
        if (env_get_var(name, value, sizeof(value)) == 0) {
            size_t vlen = strlen(value);
            if (o + vlen >= sizeof(out)) return;
            memcpy(out + o, value, vlen);
            o += vlen;
        }
    }

    if (o + 1 > size) {
        return;
    }
    out[o] = '\0';
    memcpy(line, out, o + 1);
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

    /* Hand this session over to the kernel shell, which still owns the rest of
     * what is privileged (shutdown, ps/kill, security tooling, networking) plus
     * pipelines through builtins. We cannot set a flag in the kernel from here, so
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
    if (strcmp(cmd, "chmod") == 0)  { cmd_chmod(argc, argv);    return 0; }
    if (strcmp(cmd, "write") == 0)  { cmd_write(argc, argv);    return 0; }
    if (strcmp(cmd, "cp") == 0)     { cmd_cp(argc, argv);       return 0; }
    if (strcmp(cmd, "mv") == 0)     { cmd_mv(argc, argv);       return 0; }
    if (strcmp(cmd, "touch") == 0)  { cmd_touch(argc, argv);    return 0; }
    if (strcmp(cmd, "id") == 0)     { cmd_id();                 return 0; }
    if (strcmp(cmd, "date") == 0)   { cmd_date();               return 0; }
    if (strcmp(cmd, "env") == 0)    { cmd_env();                return 0; }
    if (strcmp(cmd, "set") == 0)    { cmd_set(argc, argv);      return 0; }
    if (strcmp(cmd, "unset") == 0)  { cmd_unset(argc, argv);    return 0; }
    if (strcmp(cmd, "export") == 0) { cmd_export(argc, argv);   return 0; }
    if (strcmp(cmd, "alias") == 0)  { cmd_alias(argc, argv);    return 0; }
    if (strcmp(cmd, "ps") == 0)     { cmd_ps(argc, argv);       return 0; }
    if (strcmp(cmd, "kill") == 0)   { cmd_kill(argc, argv);     return 0; }
    if (strcmp(cmd, "top") == 0)    { cmd_top(argc, argv);      return 0; }

    if (strcmp(cmd, "passwd") == 0)  { cmd_cred(argc, argv, CRED_PASSWD,  "passwd");  return 0; }
    if (strcmp(cmd, "useradd") == 0) { cmd_cred(argc, argv, CRED_USERADD, "useradd"); return 0; }
    if (strcmp(cmd, "userdel") == 0) { cmd_cred(argc, argv, CRED_USERDEL, "userdel"); return 0; }

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

        /* Alias substitution and $VAR expansion, in that order -- an alias may
         * itself contain a variable, and bash expands after substituting.
         *
         * These run HERE, in the shell, rather than in the kernel. The kernel
         * shell does its own at src/shell.c:542 and :565, but that code is
         * reached only by kernel-shell input: a ring-3 shell that merely gained
         * the env BUILTINS would still print a literal "$HOME" for `echo $HOME`,
         * because nothing on this path had ever looked at a '$'. Shipping
         * SYS_ENV without this would have been PR A's failure mode again -- a
         * subsystem that appears wired and observably does nothing.
         *
         * Both are best-effort: on overflow the line is left exactly as typed
         * rather than half-substituted, since a truncated command is more
         * dangerous than an unexpanded one. */
        expand_aliases(line, sizeof(line));
        expand_vars(line, sizeof(line));

        /* A pipeline is handled entirely here rather than through dispatch():
         * it is two commands, and dispatch runs exactly one. Split before
         * tokenising so each stage gets its own words and its own redirections
         * (see split_pipeline). The right stage is tokenised into its own argv,
         * since the left stage's is still live while both run. */
        char* rhs = split_pipeline(line);
        if (rhs) {
            char* rargs[MAX_ARGS];

            int lnargs = split_args(line, sizeof(line), args, MAX_ARGS);
            int rnargs = split_args(rhs, sizeof(line) - (size_t)(rhs - line),
                                    rargs, MAX_ARGS);
            if (lnargs == 0 || rnargs == 0) {
                print("shell: a pipeline needs a command on both sides of '|'\n");
                continue;
            }

            redir_t lredir, rredir;
            if (take_redirections(&lnargs, args, &lredir) < 0 ||
                take_redirections(&rnargs, rargs, &rredir) < 0) {
                print("shell: expected a filename after the redirection\n");
                continue;
            }
            if (lnargs == 0 || rnargs == 0) {
                print("shell: a pipeline needs a command on both sides of '|'\n");
                continue;
            }

            /* A stage's own '>' would fight the pipe for the same stream: the
             * shell binds stdout to the pipe for the producer and stdin to it
             * for the consumer, so honouring `a > f | b` would mean the pipe
             * carries nothing while `b` waits on it forever. Refuse rather
             * than pick a winner silently. The OUTER ends are unambiguous and
             * would be worth supporting later; these are the inner ones. */
            if (lredir.out_path || rredir.in_path) {
                print("shell: cannot redirect the piped end of a stage "
                      "(the pipe already binds it)\n");
                continue;
            }

            /* The free ends — `<` into the producer, `>` out of the consumer —
             * are compatible with the pipe, since each rebinds the stream the
             * pipe does not use on that side. They cannot be applied here
             * though: the shell has ONE set of streams and the two stages are
             * bound at different moments, so the producer's `<` would be
             * overwritten by the BIND_STDIN that sets up the consumer. Each is
             * applied inside run_pipeline, in its own stage's window. */
            run_pipeline(lnargs, args, &lredir, rnargs, rargs, &rredir);
            continue;
        }

        int nargs = split_args(line, sizeof(line), args, MAX_ARGS);
        if (nargs == 0) continue;

        int background = take_background_flag(&nargs, args);
        if (nargs == 0) continue;

        redir_t redir;
        if (take_redirections(&nargs, args, &redir) < 0) {
            print("shell: expected a filename after the redirection\n");
            continue;
        }
        if (nargs == 0) continue;

        /* A credential command with a redirection is refused rather than run.
         * Its prompts are printed by the KERNEL into this process's stdout, so
         * `passwd > f` would put "Enter new password:" in the file while the
         * kernel blocked on the keyboard — the user would face a shell that
         * looks hung and would be typing a password blind. `< f` cannot work
         * either: read_password reads the keyboard directly, never stdin, so a
         * redirected stdin is silently ignored rather than supplying anything.
         * Neither is expressible, so say so instead of misbehaving. */
        if (is_cred_cmd(args[0]) && (redir.in_path || redir.out_path)) {
            printf("%s: cannot be redirected; it prompts on the console\n",
                   args[0]);
            continue;
        }

        /* Redirect only around the command itself: the prompt, the echoed line
         * and any error the shell prints about the redirection all belong on
         * the console. A backgrounded child is safe here even though the undo
         * runs immediately — sys_spawn copies the streams into the child, so
         * the child keeps the redirected one after the parent restores. */
        if (redir_apply(&redir) < 0) continue;

        int done = dispatch(nargs, args, background, &status);

        redir_undo(&redir);

        if (done) break;
    }

    /* "shell: exiting" is load-bearing — verify-usershell.sh greps for it.
     * Keep it byte-identical. */
    print("shell: exiting\n");
    return status;
}
