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
    return spawn(SELF, args);
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
    printf("PROBE done\n");
    return 0;
}
