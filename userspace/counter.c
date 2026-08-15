/*=============================================================================
 * counter.c - Pipeline consumer half of the SYS_PIPE test
 *
 * Reads stdin to EOF, counts lines and bytes, and reports the totals. Nothing
 * else in userspace reads fd 0 until it ends, which makes this the only thing
 * that can prove the two halves of the pipe contract:
 *
 *   - it BLOCKS while the producer is still writing (rather than seeing a
 *     short read as end-of-input and exiting early), and
 *   - it TERMINATES, which only happens if the shell's PIPE_CLOSE_WRITE
 *     actually reached the pipe after the producer was reaped. Without that
 *     step this program hangs forever on a drained pipe, so the harness timing
 *     out is itself the signal that CLOSE_WRITE regressed.
 *
 * NOTE: the "counter: lines=N bytes=N" line is load-bearing —
 * verify-ring3-pipes.sh greps for it. Keep it byte-identical.
 *===========================================================================*/
#include "libc.h"

int main(int argc, char** argv) {
    (void)argc; (void)argv;

    char buf[512];
    int lines = 0;
    int bytes = 0;

    for (;;) {
        int n = read(0, buf, sizeof(buf));
        if (n <= 0) {
            /* 0 is EOF (the write end closed and the buffer drained); a
             * negative is an error. Either way there is no more input. */
            break;
        }
        bytes += n;
        for (int i = 0; i < n; i++) {
            if (buf[i] == '\n') {
                lines++;
            }
        }
    }

    printf("counter: lines=%d bytes=%d\n", lines, bytes);
    return 0;
}
