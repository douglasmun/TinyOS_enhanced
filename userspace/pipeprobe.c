/*=============================================================================
 * pipeprobe.c — ring-3 driver for the SYS_PIPE use-after-free.
 *
 * THE BUG THIS DRIVES
 *
 * A spawned child inherits its creator's streams by shallow copy, so a child
 * spawned while the creator's stdout is a pipe holds the raw pipe_buffer_t
 * pointer. PIPE_OP_DESTROY (or the owner exiting) pmm_free'd the buffer's
 * frames without asking whether anyone else still named them, and the child's
 * next write went through the stale pointer into whatever the PMM handed the
 * frames to next. No privilege needed: every call here is an ungated syscall.
 *
 * HOW THE PROBE MAKES IT VISIBLE
 *
 * A freed pipe whose frames nobody reuses still says "read end closed", so the
 * child's write would fail with EPIPE on the broken kernel too and the probe
 * would grade nothing. So the parent re-allocates at once: a second
 * PIPE_CREATE asks the PMM for the same number of contiguous frames and gets
 * the ones just freed. On the broken kernel the child's write then lands in
 * that second, unrelated pipe, and the parent reads it back out.
 *
 *   PROBE child-write=N    the child's write() return (via its exit status)
 *   PROBE stray-bytes=N    bytes the parent found in its own, second pipe
 *
 * Fixed kernel: the destroyed pipe stays allocated until the child lets go,
 * the write returns -EPIPE and the second pipe is empty. Broken kernel: the
 * write succeeds and its bytes appear in the second pipe.
 *
 * The control leg runs the same plumbing on a pipe nobody destroys: the
 * child's write must succeed and the parent must read every byte. Without it
 * a probe whose spawn or read path never worked would report "write failed,
 * nothing stray" -- exactly what the fixed kernel reports.
 *
 *   PROBE control-write=N control-bytes=N
 *
 * One binary, two roles: run with no argument it is the parent; the parent
 * spawns it again with "child".
 *===========================================================================*/
#include "libc.h"

#define SELF "/pipeprobe.elf"
static const char MSG[] = "STRAY";

static int child(void) {
    /* Give the parent time to destroy the pipe and re-allocate its frames. */
    sleep_ms(500);
    int rc = write(1, MSG, sizeof(MSG) - 1);
    /* stdout is the pipe, so the result travels back as the exit status:
     * 100 + the byte count on success, else the negated errno. */
    return rc >= 0 ? 100 + rc : -rc;
}

static int child_bytes(int status) {
    return status >= 100 ? status - 100 : -status;
}

/* Control: a live pipe, read back after the child exits. */
static void control(void) {
    char buf[64];
    char* const args[] = { SELF, "child", 0 };
    int id = pipe_op(PIPE_CREATE, 0);
    if (id < 0) {
        printf("PROBE control create rc=%d\n", id);
        return;
    }
    int pid = spawn(SELF, args);
    pipe_op(PIPE_UNBIND_STDOUT, id);
    pipe_op(PIPE_BIND_STDIN, id);
    int status = pid < 0 ? pid : waitpid(pid);
    pipe_op(PIPE_CLOSE_WRITE, id);
    int got = read(0, buf, sizeof(buf));
    pipe_op(PIPE_RESTORE, id);
    pipe_op(PIPE_DESTROY, id);
    printf("PROBE control-write=%d control-bytes=%d\n",
           pid < 0 ? pid : child_bytes(status), got);
}

int main(int argc, char** argv) {
    if (argc > 1 && !strcmp(argv[1], "child")) {
        return child();
    }
    control();

    int id = pipe_op(PIPE_CREATE, 0);
    if (id < 0) {
        printf("PROBE create rc=%d\n", id);
        printf("PROBE done\n");
        return 1;
    }
    char* const args[] = { SELF, "child", 0 };
    int pid = spawn(SELF, args);
    pipe_op(PIPE_RESTORE, id);
    if (pid < 0) {
        pipe_op(PIPE_DESTROY, id);
        printf("PROBE spawn rc=%d\n", pid);
        printf("PROBE done\n");
        return 1;
    }
    int drc = pipe_op(PIPE_DESTROY, id);

    /* The second pipe. CREATE binds it to my stdout; take stdout back at once
     * (nothing may print in between) and read from it instead. */
    int id2 = pipe_op(PIPE_CREATE, 0);
    if (id2 >= 0) {
        pipe_op(PIPE_UNBIND_STDOUT, id2);
        pipe_op(PIPE_BIND_STDIN, id2);
    }

    int status = waitpid(pid);

    int stray = -1;
    if (id2 >= 0) {
        char buf[64];
        pipe_op(PIPE_CLOSE_WRITE, id2);
        stray = read(0, buf, sizeof(buf));
        pipe_op(PIPE_RESTORE, id2);
        pipe_op(PIPE_DESTROY, id2);
    }

    printf("PROBE destroy rc=%d second-pipe=%d\n", drc, id2);
    printf("PROBE child-write=%d\n", child_bytes(status));
    printf("PROBE stray-bytes=%d\n", stray);
    printf("PROBE done\n");
    return 0;
}
