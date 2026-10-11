/*=============================================================================
 * capprobe.c — ring-3 driver for the per-uid shares of the pipe table and the
 * VFS descriptor table.
 *
 * Both tables are system-wide. Without a share, one uid could hold every pipe
 * slot (8), or most of the VFS descriptor pool through directory opens, which
 * no other cap sees, and starve every other user. Run as a NON-ROOT user:
 *
 *   PROBE pipes made=N err=E again=A
 *       PIPE_CREATE until refused (at most 9 tries). Fixed: 4 then -11
 *       (-EAGAIN, PIPE_USER_MAX). Unfixed: 8 then -24 (-EMFILE, table full).
 *       `again` is a create after destroying them all: >0 shows the slots
 *       came back, and that the refused creates leaked none.
 *
 *   PROBE dirs parent=N err=E
 *   PROBE dirs child=N err=E
 *   PROBE dirs again=A
 *       The parent opens D:/scratch as a directory until refused: its own
 *       per-process table (16) stops it either way. It then spawns a same-uid
 *       child that does the same while the parent's descriptors are still
 *       open. Fixed:
 *       the child gets VFS_USER_MAX_FDS (24) minus the parent's, then -11.
 *       Unfixed: the child gets a full 16 again, then -24. `again` is an open
 *       after both have closed everything.
 *
 * One binary, two roles: the parent spawns itself again with "dirchild".
 *===========================================================================*/
#include "libc.h"

#define SELF      "/capprobe.elf"
#define DIR_PATH  "D:/scratch"  /* 0777; D:/ is 0711, no read bit */
#define MAX_TRY   32

static int open_dirs(int* fds, int* err) {
    int n = 0;
    *err = 0;
    while (n < MAX_TRY) {
        int fd = open(DIR_PATH, O_RDONLY | O_DIRECTORY);
        if (fd < 0) {
            *err = fd;
            break;
        }
        fds[n++] = fd;
    }
    return n;
}

static void close_all(const int* fds, int n) {
    for (int i = 0; i < n; i++) {
        close(fds[i]);
    }
}

static void pipes(void) {
    int ids[16];
    int made = 0, err = 0;
    while (made < 9) {
        int id = pipe_op(PIPE_CREATE, 0);
        if (id < 0) {
            err = id;
            break;
        }
        /* CREATE binds my stdout to the pipe; take it back before anything
         * prints. */
        pipe_op(PIPE_UNBIND_STDOUT, id);
        ids[made++] = id;
    }
    for (int i = 0; i < made; i++) {
        pipe_op(PIPE_DESTROY, ids[i]);
    }
    int again = pipe_op(PIPE_CREATE, 0);
    if (again > 0) {
        pipe_op(PIPE_UNBIND_STDOUT, again);
        pipe_op(PIPE_DESTROY, again);
    }
    printf("PROBE pipes made=%d err=%d again=%d\n", made, err, again);
}

static int dirchild(void) {
    int fds[MAX_TRY], err;
    int n = open_dirs(fds, &err);
    printf("PROBE dirs child=%d err=%d\n", n, err);
    close_all(fds, n);
    return 0;
}

static void dirs(void) {
    int fds[MAX_TRY], err;
    int n = open_dirs(fds, &err);
    printf("PROBE dirs parent=%d err=%d\n", n, err);

    char* const args[] = { SELF, "dirchild", 0 };
    int pid = spawn(SELF, args);
    if (pid < 0) {
        printf("PROBE dirs spawn rc=%d\n", pid);
    } else {
        waitpid(pid);
    }
    close_all(fds, n);

    int again = open(DIR_PATH, O_RDONLY | O_DIRECTORY);
    if (again >= 0) {
        close(again);
    }
    printf("PROBE dirs again=%d\n", again);
}

int main(int argc, char** argv) {
    if (argc > 1 && !strcmp(argv[1], "dirchild")) {
        return dirchild();
    }
    pipes();
    dirs();
    printf("PROBE done\n");
    return 0;
}
