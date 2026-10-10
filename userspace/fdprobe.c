/*=============================================================================
 * fdprobe.c — ring-3 driver for two ways a RAMFS descriptor outlived its
 * owner's hold on it.
 *
 * RAMFS descriptors are one global table. A task names one through its own
 * fdtable (SYS_OPEN) or through a redirected stream; neither copy keeps the
 * slot alive. Once the slot is closed behind the holder's back, the next
 * ramfs_open() anywhere reuses it, and the holder's reads and writes go to
 * that file instead -- whoever opened it.
 *
 * Leg "sweep": every ELF load ran ramfs_close_on_exec(), which closed every
 * close-on-exec descriptor in the SYSTEM, not the loading task's. All SYS_OPEN
 * descriptors are close-on-exec, so any spawn by anyone closed every open file
 * of every process. Here: open A, spawn, open B, write through A.
 *
 *   PROBE sweep a=N b=N     bytes that reached A and B; fixed: 4 and 0
 *
 * Leg "stream": a spawned child inherits a redirected stdout as the bare RAMFS
 * fd. The shell restores (and so closes) it right after spawning a background
 * or pipeline stage, so the child's output went to the next file opened.
 * Here: redirect stdout to OUT, spawn a child that writes later, restore,
 * open VICTIM.
 *
 *   PROBE stream out=N victim=N   fixed: 4 and 0
 *
 * In both legs the first number is the positive control: the bytes must
 * still arrive where they were meant to, not merely stay out of B / VICTIM.
 *
 * Leg "exit": a task that exits normally must give back what it holds.
 * sys_exit released nothing -- only a killed task's teardown did -- so each
 * child that exited with a file open, or with an inherited redirected stdout
 * (which now carries its own reference), kept a slot in the 16-entry RAMFS
 * table for good. A leaked slot still counts against its opener's uid, which
 * may hold RAMFS_USER_MAX_FDS (8). The probe holds 5, leaving 3, then:
 *
 *   PROBE exit stream held=5 spawned=4 open=FD    4 redirected children
 *   PROBE exit files spawned=2 opened=4 open=FD   2 children, 2 files each
 *
 * Fixed: FD >= 0 both times.
 *
 * Leg "cap": one uid may not take the whole table, and the last
 * RAMFS_ROOT_RESERVED_FDS (4) free slots are root's. The per-process cap
 * alone let one user's two processes hold all 16, after which no exec --
 * root's included -- could open its ELF. Needs `/fdprobe.elf roothold &`
 * started by root first, holding ROOT_FIRST slots:
 *
 *   PROBE cap child-held=2
 *   PROBE cap user opened=N refused=RC      fixed: 6, -11 (8 for the uid, less
 *                                           the child's 2; root holds 3)
 *   PROBE cap reserve opened=N refused=RC   fixed: 3, -11 (root now holds 7
 *                                           and the child 2: 7 free, 4 kept)
 *
 * Mode "guard" (run as `/fdprobe.elf guard`): spawn a child, wait for it,
 * create a file -- ROUNDS times. Creating the child marked its kernel guard
 * page not-present in THIS task's page tables, and its exit restored it
 * elsewhere, so the first new file whose ramfs node drew that frame took a
 * kernel #PF and panicked. The sweep leg does the same once.
 *
 *   PROBE guard rounds=N created=N   fixed: both ROUNDS (and no panic)
 *
 * Mode "quiet" (`/fdprobe.elf quiet`): QUIET_EXITS children exit normally,
 * then one is killed. verify-exit-quiet.sh counts what the kernel printed.
 *
 *   PROBE quiet exits=N kill=RC      fixed: QUIET_EXITS, 0
 *===========================================================================*/
#include "libc.h"

#define SELF   "/fdprobe.elf"
#define A      "/scratch/fdprobe.a"
#define B      "/scratch/fdprobe.b"
#define OUT    "/scratch/fdprobe.out"
#define VICTIM "/scratch/fdprobe.victim"

static int file_len(const char* path) {
    char buf[64];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return fd;
    int n = read(fd, buf, sizeof(buf));
    close(fd);
    return n;
}

static int run_child(const char* role) {
    char* const args[] = { SELF, (char*)role, 0 };
    /* Task creation is rate limited (5/s, burst 10). */
    int pid, tries = 0;
    while ((pid = spawn(SELF, args)) == -11 && tries++ < 20) {
        sleep_ms(250);
    }
    return pid;
}

static void leg_sweep(void) {
    int a = open(A, O_WRONLY | O_CREAT | O_TRUNC);
    int pid = run_child("noop");
    if (pid >= 0) waitpid(pid);
    int b = open(B, O_WRONLY | O_CREAT | O_TRUNC);
    int w = write(a, "AAAA", 4);
    close(a);
    close(b);
    printf("PROBE sweep open=%d spawn=%d write=%d\n", a, pid, w);
    printf("PROBE sweep a=%d b=%d\n", file_len(A), file_len(B));
}

static void leg_stream(void) {
    int victim = open(VICTIM, O_WRONLY | O_CREAT | O_TRUNC);
    close(victim);
    int r = redirect(1, OUT, REDIR_TRUNC);
    int pid = run_child("late-write");
    redirect(1, 0, REDIR_RESTORE);
    /* Held open while the child writes, as any other user's file would be. */
    victim = open(VICTIM, O_WRONLY);
    int status = pid >= 0 ? waitpid(pid) : pid;
    close(victim);
    printf("PROBE stream redirect=%d spawn=%d status=%d\n", r, pid, status);
    printf("PROBE stream out=%d victim=%d\n", file_len(OUT), file_len(VICTIM));
}

/* Hold most of this uid's 8 RAMFS slots so a few leaked exits use up the
 * rest: each spawn costs a signature check, ~20 s under TCG. A round needs 2
 * at once (the redirect target and the ELF being loaded), so 5 held leaves
 * room for exactly one round's worth plus one -- a slot leaked per round
 * stops the third spawn. */
#define HELD_SELF  5
#define EXIT_ROUNDS 4

static int hold_files(int* fds, int n, char tag) {
    char path[] = "/scratch/fdprobe.hxA";
    int got = 0;
    path[sizeof(path) - 3] = tag;
    for (int i = 0; i < n; i++) {
        path[sizeof(path) - 2] = (char)('A' + i);
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC);
        if (fd < 0) break;
        fds[got++] = fd;
    }
    return got;
}

static void leg_exit(void) {
    int held[HELD_SELF], nheld, spawned = 0;
    nheld = hold_files(held, HELD_SELF, 'p');
    /* 3 slots left. Children that exit with an inherited stdout reference... */
    for (int i = 0; i < EXIT_ROUNDS; i++) {
        redirect(1, OUT, REDIR_TRUNC);
        int pid = run_child("noop");
        redirect(1, 0, REDIR_RESTORE);
        if (pid >= 0) { waitpid(pid); spawned++; }
    }
    int fd = open(A, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd >= 0) close(fd);
    printf("PROBE exit stream held=%d spawned=%d open=%d\n", nheld, spawned, fd);
    /* ...and children that exit with two files open. */
    int opened = 0;
    spawned = 0;
    for (int i = 0; i < 2; i++) {
        int pid = run_child("open-exit");
        if (pid >= 0) { opened += waitpid(pid); spawned++; }
    }
    fd = open(A, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd >= 0) close(fd);
    printf("PROBE exit files spawned=%d opened=%d open=%d\n", spawned, opened, fd);
    for (int i = 0; i < nheld; i++) close(held[i]);
}

#define ROOT_FIRST 3
#define ROOT_MORE  4
#define CAP_CHILD  2
#define CAP_TRIES  12
#define MORE "/scratch/fdprobe.more"
#define ACK  "/scratch/fdprobe.ack"

static int exists(const char* path) {
    dirent_t st;
    return stat(path, &st, sizeof(st)) == 0;
}

static int wait_for_file(const char* path, int seconds) {
    for (int i = 0; i < seconds * 2; i++) {
        if (exists(path)) return 1;
        sleep_ms(500);
    }
    return 0;
}

static void touch(const char* path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd >= 0) close(fd);
}

/* Open until refused; return how many and store the refusal. */
static int open_until_refused(int* fds, int* refused) {
    char path[] = "/scratch/fdprobe.uA";
    int n = 0;
    *refused = 0;
    while (n < CAP_TRIES) {
        path[sizeof(path) - 2] = (char)('A' + n);
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC);
        if (fd < 0) { *refused = fd; break; }
        fds[n++] = fd;
    }
    return n;
}

/* Run by root, backgrounded, before the unprivileged legs. */
static void mode_roothold(void) {
    int fds[ROOT_FIRST + ROOT_MORE];
    int n = hold_files(fds, ROOT_FIRST, 'r');
    printf("PROBE roothold held=%d\n", n);
    if (!wait_for_file(MORE, 1800)) return;
    n += hold_files(fds + n, ROOT_MORE, 's');
    touch(ACK);
    chmod(ACK, 0644);   /* created 0600; the unprivileged probe stats it */
    printf("PROBE roothold held=%d\n", n);
    sleep_ms(600000);
}

static void leg_cap(void) {
    int fds[CAP_TRIES], refused;
    int child = run_child("cap-hold");
    /* Its second file existing means it holds both. */
    wait_for_file("/scratch/fdprobe.hcB", 120);

    int n = open_until_refused(fds, &refused);
    for (int i = 0; i < n; i++) close(fds[i]);
    printf("PROBE cap user opened=%d refused=%d\n", n, refused);

    touch(MORE);
    int acked = wait_for_file(ACK, 300);
    n = open_until_refused(fds, &refused);
    for (int i = 0; i < n; i++) close(fds[i]);
    printf("PROBE cap reserve acked=%d opened=%d refused=%d\n", acked, n, refused);
    if (child >= 0) kill(child);
}

#define ROUNDS 8

static void mode_guard(void) {
    char path[] = "/scratch/fdprobe.g0";
    int created = 0, rounds = 0;
    for (int i = 0; i < ROUNDS; i++) {
        int pid = run_child("noop");
        if (pid < 0) break;
        waitpid(pid);
        rounds++;
        path[sizeof(path) - 2] = (char)('0' + i);
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC);
        if (fd >= 0 && write(fd, "G", 1) == 1) created++;
        if (fd >= 0) close(fd);
    }
    printf("PROBE guard rounds=%d created=%d\n", rounds, created);
}

#define QUIET_EXITS 4

static void mode_quiet(void) {
    int exits = 0;
    printf("PROBE quiet start\n");
    for (int i = 0; i < QUIET_EXITS; i++) {
        int pid = run_child("noop");
        if (pid >= 0) { waitpid(pid); exits++; }
    }
    int victim = run_child("cap-hold");
    wait_for_file("/scratch/fdprobe.hcB", 120);
    int rc = victim >= 0 ? kill(victim) : victim;
    printf("PROBE quiet exits=%d kill=%d\n", exits, rc);
}

int main(int argc, char** argv) {
    if (argc > 1 && !strcmp(argv[1], "noop")) {
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "count")) {
        /* verify-pipe-fixes.sh: how many RAMFS slots the uid can still open. */
        int fds[CAP_TRIES], refused;
        int n = open_until_refused(fds, &refused);
        for (int i = 0; i < n; i++) close(fds[i]);
        printf("PROBE count opened=%d refused=%d\n", n, refused);
        /* Nonzero so the shell prints "exited with status": the harness
         * waits on that, not on our own line, before typing again. */
        return 3;
    }
    if (argc > 1 && !strcmp(argv[1], "pipebind")) {
        /* verify-pipe-fixes.sh: run as `fdprobe.elf pipebind < f > g`, so both
         * streams own a RAMFS ref, then rebind both to a pipe and back -- the
         * sequence a shell runs for every pipeline. The ref each rebind
         * overwrote must not outlive this process. */
        int id = pipe_op(PIPE_CREATE, 0);
        int b = id > 0 ? pipe_op(PIPE_BIND_STDIN, id) : id;
        if (id > 0) {
            pipe_op(PIPE_RESTORE, id);
            pipe_op(PIPE_CLOSE_WRITE, id);
            pipe_op(PIPE_DESTROY, id);
        }
        printf("PROBE pipebind id=%d bind=%d\n", id > 0 ? 1 : id, b);
        return 3;
    }
    if (argc > 1 && !strcmp(argv[1], "orphan")) {
        /* verify-pipe-fixes.sh: run as a kernel-shell pipeline stage
         * (`exec /fdprobe.elf orphan | cat`). The sleeper inherits this
         * stage's stdout -- the shell's static capture pipe -- and outlives
         * the pipeline, so its second line is written after that pipe is
         * destroyed. The pause lets its first line land inside the pipe. */
        char* sargv[] = { "sleeper.elf", 0 };
        int pid = spawn("/sleeper.elf", sargv);
        sleep_ms(1500);
        printf("PROBE orphan spawn=%d\n", pid > 0 ? 1 : pid);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "cap-hold")) {
        int fds[CAP_CHILD];
        printf("PROBE cap child-held=%d\n", hold_files(fds, CAP_CHILD, 'c'));
        sleep_ms(600000);            /* the parent kills it */
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "roothold")) {
        mode_roothold();
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "open-exit")) {
        /* Exit holding both; the count is the status. */
        return (open(A, O_RDONLY) >= 0) + (open(B, O_RDONLY) >= 0);
    }
    if (argc > 1 && !strcmp(argv[1], "late-write")) {
        sleep_ms(500);
        return write(1, "BBBB", 4);
    }
    if (argc > 1 && !strcmp(argv[1], "quiet")) {
        mode_quiet();
        printf("PROBE done\n");
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "guard")) {
        mode_guard();
        printf("PROBE done\n");
        return 0;
    }
    leg_sweep();
    leg_stream();
    leg_exit();
    leg_cap();
    printf("PROBE done\n");
    return 0;
}
