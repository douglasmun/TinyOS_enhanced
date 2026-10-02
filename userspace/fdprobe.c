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
 * table for good. The parent and a sleeping child hold 6 + 7 slots,
 * leaving 3, then:
 *
 *   PROBE exit child-held=7
 *   PROBE exit stream held=6 spawned=4 open=FD    4 redirected children
 *   PROBE exit files spawned=2 opened=4 open=FD   2 children, 2 files each
 *
 * Fixed: FD >= 0 both times.
 *
 * Mode "guard" (run as `/fdprobe.elf guard`): spawn a child, wait for it,
 * create a file -- ROUNDS times. Creating the child marked its kernel guard
 * page not-present in THIS task's page tables, and its exit restored it
 * elsewhere, so the first new file whose ramfs node drew that frame took a
 * kernel #PF and panicked. The sweep leg does the same once.
 *
 *   PROBE guard rounds=N created=N   fixed: both ROUNDS (and no panic)
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

/* Hold most of the 16-slot RAMFS table so a few leaked exits fill it: each
 * spawn costs a signature check, ~20 s under TCG. A process may hold 8
 * (PROCESS_MAX_FDS) and the parent's spawn and redirect need 2 of its own, so
 * the parent holds 6 and a sleeping child the other 7. */
#define HELD_SELF  6
#define HELD_CHILD 7
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
    int holder = run_child("hold");
    sleep_ms(3000);                  /* let it open its 7 */
    nheld = hold_files(held, HELD_SELF, 'p');
    printf("PROBE exit holder=%d\n", holder);
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

int main(int argc, char** argv) {
    if (argc > 1 && !strcmp(argv[1], "noop")) {
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "hold")) {
        int fds[HELD_CHILD];
        printf("PROBE exit child-held=%d\n", hold_files(fds, HELD_CHILD, 'c'));
        sleep_ms(600000);            /* outlives the leg; the run ends first */
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
    if (argc > 1 && !strcmp(argv[1], "guard")) {
        mode_guard();
        printf("PROBE done\n");
        return 0;
    }
    leg_sweep();
    leg_stream();
    leg_exit();
    printf("PROBE done\n");
    return 0;
}
