/*=============================================================================
 * callprobe.c — ring-3 driver for the syscall dispatcher's reject counters.
 *
 * The three sites this drives (syscall.c) used to be kprintf:
 *
 *   syscall_num > MAX_SYSCALL_NUM   -> "Invalid syscall number %d"
 *   case SYS_CRYPTO                 -> unimplemented
 *   default                         -> unimplemented
 *
 * The first is the one that mattered. The syscall NUMBER is entirely the
 * caller's own byte -- no privilege, no mapped memory, no setup -- so any
 * ring-3 program printed a kernel console line per call, at whatever rate it
 * chose, into the stream the ring-3 shell shares with the user's own output.
 * The number itself was formatted back out, so the attacker also chose the
 * text. Nothing in the tree drove it: there is no libc wrapper for an invalid
 * syscall and no builtin, the same "no driver, so the sites rot" condition
 * that hid sixteen kprintfs on SYS_MSEAL. Hence this probe.
 *
 * Counts are distinct and none is a multiple of another, so no single
 * miscounting site can produce every expected delta at once.
 *
 * Leg 3 is the POSITIVE CONTROL and is not optional. A dispatcher that
 * refused EVERY call would satisfy legs 1 and 2 perfectly -- both reject
 * counters would read exactly right -- and the surface would report a working
 * mechanism while nothing worked. Leg 3 makes `accepted` move on its own.
 *===========================================================================*/
#include "libc.h"

#define SYS_GETPID  3
#define SYS_CRYPTO 13

/* Above MAX_SYSCALL_NUM (41). Two different out-of-range values, because a
 * range check written with the wrong comparison can admit one and not the
 * other; both must land on the SAME counter. */
#define N_RANGE_LOW    3   /* 42  -- one past the boundary          */
#define N_RANGE_HIGH   5   /* 200 -- far outside                    */
#define N_UNIMPL       7   /* SYS_CRYPTO: in range, no handler      */
#define N_ACCEPTED    11   /* SYS_GETPID: in range, real handler    */

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    int i;
    int rc = 0;

    /* Leg 1a: one past the boundary. Counter: reject_range. */
    for (i = 0; i < N_RANGE_LOW; i++) {
        rc = syscall1(42, 0);
    }
    printf("PROBE range_low n=%d rc=%d\n", N_RANGE_LOW, rc);

    /* Leg 1b: far out of range. Same counter as 1a. */
    for (i = 0; i < N_RANGE_HIGH; i++) {
        rc = syscall1(200, 0);
    }
    printf("PROBE range_high n=%d rc=%d\n", N_RANGE_HIGH, rc);

    /* Leg 2: in range, deliberately unimplemented. Counter: reject_unimpl.
     * Kept apart from leg 1 because it is a different attacker position: the
     * number is valid, so this is reached AFTER the range check and after the
     * seccomp filter, inside the dispatch switch. */
    for (i = 0; i < N_UNIMPL; i++) {
        rc = syscall1(SYS_CRYPTO, 0);
    }
    printf("PROBE unimpl n=%d rc=%d\n", N_UNIMPL, rc);

    /* Leg 3: POSITIVE CONTROL. A real handler, unprivileged, no arguments to
     * get wrong. `accepted` must rise by exactly this many. */
    for (i = 0; i < N_ACCEPTED; i++) {
        rc = syscall0(SYS_GETPID);
    }
    printf("PROBE accepted n=%d rc=%d\n", N_ACCEPTED, rc);

    printf("PROBE done\n");
    return 0;
}
