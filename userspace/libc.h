/*=============================================================================
 * libc.h - Minimal freestanding C library for TinyOS user programs
 *
 * Link order: crt0.o <program>.o libc.o (see userspace/Makefile).
 * crt0 sets up the user data segments and calls main(); returning from
 * main() exits with the returned status.
 *=============================================================================*/
#ifndef TINYOS_LIBC_H
#define TINYOS_LIBC_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

/* System call numbers (must match src/syscall.h) */
#define SYS_EXIT   0
#define SYS_WRITE  1
#define SYS_READ   2
#define SYS_GETPID 3
#define SYS_YIELD  4
#define SYS_GETUID 5
#define SYS_GETGID 6
#define SYS_SLEEP  17
#define SYS_WAITPID 18
#define SYS_SPAWN  19
#define SYS_OPEN    20
#define SYS_CLOSE   21
#define SYS_READDIR 22
#define SYS_STAT    23
#define SYS_LSEEK   24
#define SYS_MKDIR   25
#define SYS_RMDIR   26
#define SYS_UNLINK  27
#define SYS_GETCWD  28
#define SYS_CHDIR   29
#define SYS_REDIRECT 30
#define SYS_PIPE     31
#define SYS_CRED     32
#define SYS_PSINFO   33
#define SYS_KILL     34

/* Open flags (must match VFS_O_* in src/vfs.h) */
#define O_RDONLY    0x0000
#define O_WRONLY    0x0001
#define O_RDWR      0x0002
#define O_CREAT     0x0100
#define O_TRUNC     0x0200
#define O_APPEND    0x0400
#define O_DIRECTORY 0x0800

/* Directory entry — the kernel copies this out byte-for-byte, so the layout
 * must stay identical to vfs_dirent_t in src/vfs.h (72 bytes, name at 8). */
#define NAME_MAX    63

#define DT_UNKNOWN  0
#define DT_REG      1
#define DT_DIR      2

typedef struct {
    uint32_t size;
    uint16_t mode;
    uint8_t  type;
    uint8_t  reserved;
    char     name[NAME_MAX + 1];
} dirent_t;

/* Process listing — the kernel copies this out byte-for-byte, so the layout
 * must stay identical to psinfo_t in src/syscall.h.
 *
 * The kernel decides which tasks appear here: an unprivileged process receives
 * only its own, root receives all. That filtering is not advisory and cannot be
 * bypassed by calling SYS_PSINFO directly — see the SYS_PSINFO comment in
 * src/syscall.h. */
#define PSINFO_NAME_LEN 32

/* task_state_t values, as widened into psinfo_t.state */
#define PS_READY      0
#define PS_RUNNING    1
#define PS_BLOCKED    2
#define PS_SLEEPING   3
#define PS_ZOMBIE     4
#define PS_TERMINATED 5

typedef struct {
    uint32_t pid;
    uint32_t ppid;
    uint32_t state;
    uint32_t total_ticks;
    uint32_t time_slice;
    uint32_t capabilities;
    uint16_t uid;
    uint16_t priority;
    uint8_t  is_kernel_task;
    uint8_t  reserved[3];
    char     name[PSINFO_NAME_LEN];
} psinfo_t;

/* Must match psinfo_t in src/syscall.h byte for byte -- the kernel copies
 * records straight into a buffer declared with THIS type. The same assertions
 * are made kernel-side; both must be updated together. */
_Static_assert(sizeof(psinfo_t) == 64, "psinfo_t layout changed: update src/syscall.h to match");
_Static_assert(offsetof(psinfo_t, uid) == 24, "psinfo_t.uid moved: update src/syscall.h to match");
_Static_assert(offsetof(psinfo_t, name) == 32, "psinfo_t.name moved: update src/syscall.h to match");

/* Raw syscall wrappers */
int syscall0(int num);
int syscall1(int num, uint32_t arg1);
int syscall3(int num, uint32_t arg1, uint32_t arg2, uint32_t arg3);

/* Process */
void exit(int status) __attribute__((noreturn));
int  getpid(void);
int  getuid(void);
int  getgid(void);
void yield(void);
int  sleep_ms(uint32_t ms);      /* blocks; timer wakes the task */
int  waitpid(int pid);           /* blocks until pid exits; returns status */

/* Load `path` and start it as a child process. Returns the child PID (> 0) or
 * a negative errno. Does NOT block — waitpid() on the result to wait for it.
 * argv is a NULL-terminated array (argv[0] conventionally the program name);
 * pass NULL for none. The child inherits this process's stdin/stdout/stderr. */
int  spawn(const char* path, char* const* argv);

/* I/O — fd 1 is the console; read is line-buffered and blocks */
int  write(int fd, const void* buf, size_t len);
int  read(int fd, void* buf, size_t len);

/* Files — fds 3.. are per-process and name something this process opened.
 * `path` is drive-qualified ("D:/hello.txt"); O_DIRECTORY opens a directory
 * for readdir() and must be combined only with O_RDONLY. */
int  open(const char* path, int flags);
int  close(int fd);

/* Read whole dirent_t records from a directory fd into `buf`. Returns the
 * number of BYTES written (a multiple of sizeof(dirent_t)), 0 at end of
 * directory, or a negative errno. `size` must fit at least one entry. */
int  readdir(int fd, void* buf, size_t size);

/* Fill one dirent_t for `path` without opening it — the way to learn a file's
 * size before deciding to read it. `size` must be at least sizeof(dirent_t).
 * Returns 0 on success or a negative errno. */
int  stat(const char* path, void* buf, size_t size);

/* Fill `buf` with psinfo_t records for the processes this caller may see.
 * Returns the number of BYTES written (a multiple of sizeof(psinfo_t)) or a
 * negative errno. A buffer too small for every visible process truncates
 * rather than failing, so size it at 32 records to get the whole table. */
int  psinfo(void* buf, size_t size);

/* The two errno values callers actually branch on, named rather than spelled as
 * bare -1/-3 at the use site. Same numbers as src/errno.h; userspace has no
 * errno.h of its own, and a magic number here would silently start meaning
 * something else if the kernel's table were ever renumbered. */
#define ELIBC_EPERM 1   /* Operation not permitted    (src/errno.h EPERM) */
#define ELIBC_ESRCH 3   /* No such process            (src/errno.h ESRCH) */

/* Terminate a process. Returns 0, or a negative errno: -ELIBC_ESRCH if no such
 * process OR one this caller may not see -- the two are deliberately the same
 * answer, so kill cannot be used to discover PIDs psinfo() hides.
 * -ELIBC_EPERM means the target is a protected system process. */
int  kill(int pid);

/* Seek origins — same values as VFS_SEEK_* in src/vfs.h, passed straight
 * through without translation so the two cannot drift apart. */
#define SEEK_SET    0
#define SEEK_CUR    1
#define SEEK_END    2

/* Reposition an open fd's cursor. Returns the resulting absolute position or
 * a negative errno. Seeking past the end clamps to the file size on both
 * drives — neither filesystem can represent a sparse hole, so use write() to
 * grow a file. */
int  lseek(int fd, int offset, int whence);

/* Namespace mutation. All three take a path (drive-qualified or not) and
 * return 0 on success, a negative errno otherwise. rmdir only removes an
 * EMPTY directory; unlink refuses directories and, on C:, open files. */
int  mkdir(const char* path);
int  rmdir(const char* path);
int  unlink(const char* path);

/* Working directory. Relative paths passed to any of the calls above resolve
 * against it, so chdir("D:/scratch") then open("f.txt") opens
 * D:/scratch/f.txt. getcwd returns the length written (excluding the NUL) or
 * -ERANGE if the path does not fit — it never truncates, since a truncated
 * path names a different directory. chdir works at any depth on both drives;
 * it needs only search (x) permission, not read. */
int  getcwd(char* buf, unsigned int size);
int  chdir(const char* path);

/* Redirection modes (must match REDIR_MODE_* in src/syscall.h) */
#define REDIR_TRUNC    0    /* stdout: create or truncate  ('>')  */
#define REDIR_APPEND   1    /* stdout: create or append    ('>>') */
#define REDIR_READ     2    /* stdin:  open an existing file ('<') */
#define REDIR_RESTORE  3    /* put the stream back on the console  */

/* Point stdin or stdout at a file, or restore it to the console.
 *
 * NOT dup2 — there is no fd to duplicate, because fds 0/1/2 are not in the
 * per-process fd table at all; they are the kernel's stream_context_t. This
 * rebinds one of those streams directly.
 *
 * A spawned child INHERITS the redirected stream, so a shell redirects a whole
 * command by redirecting itself, spawning, and restoring afterwards. Only the
 * RAMFS drive (D:) can be a target: -EXDEV for anything else. stderr may be
 * restored but not redirected to a file (-ENOSYS). `path` is ignored for
 * REDIR_RESTORE and may be NULL. Returns 0 or a negative errno. */
int  redirect(int fd, const char* path, int mode);

/* Pipe operations (must match PIPE_OP_* in src/syscall.h) */
#define PIPE_CREATE         0  /* new pipe, bound to my stdout            */
#define PIPE_BIND_STDIN     1  /* bind its read end to my stdin           */
#define PIPE_CLOSE_WRITE    2  /* producer done: readers now see EOF      */
#define PIPE_RESTORE        3  /* my stdin+stdout back to the console     */
#define PIPE_DESTROY        4  /* release the pipe                        */
#define PIPE_UNBIND_STDOUT  5  /* my stdout only, back to the console     */

/* Create a pipe, bind an end to one of my streams, or release it.
 *
 * NOT POSIX pipe(int fd[2]): the ends a shell needs to connect are stdin and
 * stdout, which are not fds at all (same reason redirect() is not dup2). The
 * pipe is named by an opaque ID instead and its buffer stays in the kernel.
 *
 * For `producer | consumer` a shell does:
 *
 *   int id = pipe_op(PIPE_CREATE, 0);      // my stdout -> pipe
 *   int a  = spawn("prod.elf", 0);         // inherits it
 *   pipe_op(PIPE_UNBIND_STDOUT, id);       // my stdout -> console again
 *   pipe_op(PIPE_BIND_STDIN, id);          // my stdin  -> pipe
 *   int b  = spawn("cons.elf", 0);         // inherits pipe stdin, real stdout
 *   pipe_op(PIPE_RESTORE, id);             // my own streams back
 *   waitpid(a);
 *   pipe_op(PIPE_CLOSE_WRITE, id);         // consumer can now see EOF
 *   waitpid(b);
 *   pipe_op(PIPE_DESTROY, id);
 *
 * UNBIND_STDOUT between the spawns is REQUIRED: a child inherits the streams as
 * they are AT SPAWN TIME, so a stdout still on the write end would make the
 * consumer write into the pipe it is reading. RESTORE cannot substitute — it
 * resets stdin too, and stdin must stay on the read end for that spawn.
 *
 * CLOSE_WRITE after reaping the producer is REQUIRED: until it runs, a drained
 * consumer blocks rather than seeing end-of-input, because more data could
 * still arrive.
 *
 * PIPE_CREATE returns a positive ID; the rest return 0. Negative is an errno. */
int  pipe_op(int op, int id);

/* Credential operations (must match CRED_OP_* in src/syscall.h) */
#define CRED_PASSWD   0    /* change a password: own, or another's as root */
#define CRED_USERADD  1    /* create a user  (root only)                   */
#define CRED_USERDEL  2    /* delete a user  (root only, never root)       */

/* Administer user credentials. `user` names the account; pass NULL with
 * CRED_PASSWD to mean the calling user.
 *
 * There is deliberately NO password parameter. The KERNEL prints the prompts
 * and reads the keystrokes into its own buffer, so a plaintext password never
 * enters a user address space, an argv, or a syscall register — a ring-3 shell
 * cannot leak or log what it never holds. The call blocks while the kernel
 * prompts, and the command prints its own diagnostics to this process's stdout.
 *
 * Authorization is the same euid check the kernel shell has always applied, not
 * a second implementation: non-root gets -EPERM for useradd/userdel and for
 * changing someone else's password.
 *
 * Returns 0 on success or a negative errno. */
int  cred(int op, const char* user);

/* Console I/O */
int  putchar(int c);
int  puts(const char* s);            /* appends newline */
void print(const char* s);           /* no newline */
int  getchar(void);
int  readline(char* buf, size_t size);  /* strips newline, NUL-terminates */
int  printf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
int  vprintf(const char* fmt, va_list ap);

/* Strings */
size_t strlen(const char* s);
int    strcmp(const char* a, const char* b);
int    strncmp(const char* a, const char* b, size_t n);
char*  strcpy(char* dst, const char* src);
char*  strncpy(char* dst, const char* src, size_t n);
char*  strchr(const char* s, int c);
void*  memcpy(void* dst, const void* src, size_t n);
void*  memmove(void* dst, const void* src, size_t n);
void*  memset(void* dst, int c, size_t n);
int    memcmp(const void* a, const void* b, size_t n);

/* Conversion */
int atoi(const char* s);

/* Heap — bump allocator over a static arena; free() is a no-op */
void* malloc(size_t size);
void  free(void* ptr);

#endif /* TINYOS_LIBC_H */
