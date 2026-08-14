/*=============================================================================
 * sleeper.c - Long-running user program for background-job testing
 *
 * hello.elf exits in milliseconds, so it is useless for proving that a
 * backgrounded process is actually ALIVE and concurrent with the shell: by
 * the time `jobs` runs, it is already reaped. This program stays runnable for
 * several seconds so the shell can be driven interactively while it runs.
 *
 * NOTE: the output strings below are load-bearing — the background-jobs
 * harness greps for "Sleeper started" and "Sleeper done". Keep them
 * byte-identical.
 *=============================================================================*/
#include "libc.h"

int main(void) {
    print("Sleeper started\n");

    /* ~6 seconds total, in blocking 500ms chunks. Blocking (not spinning) is
     * the point: the task sits in SLEEPING state on the timer wait queue, so
     * `ps`/`jobs` observe a real live child while the shell stays responsive. */
    for (int i = 0; i < 12; i++) {
        sleep_ms(500);
    }

    print("Sleeper done\n");
    return 0;
}
