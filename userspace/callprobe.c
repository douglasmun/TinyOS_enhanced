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

/*-----------------------------------------------------------------------------
 * `io` mode: the sys_read/sys_write argument refusals and the failed-spawn
 * path. Each was a kprintf any caller could fire per call -- outside its own
 * redirection, into the stream every user shares. Now each is counted
 * (secstatus "Syscall arg rejects"), and verify-syscall-io-quiet.sh counts
 * kernel lines between "PROBE io start" and "PROBE io end".
 *
 * Three bad buffers per direction -- over the size cap, wrapping, and ending
 * past user space -- because each is its own refusal site. N_SPAWN_FAIL is
 * odd so the two counters cannot be mistaken for each other.
 *---------------------------------------------------------------------------*/
#define SYS_WRITE 1
#define SYS_READ  2
#define IO_TOO_BIG   (1024u * 1024u + 1u)   /* MAX_IO_SIZE + 1   */
#define IO_WRAP_PTR  0xFFFFFFF0u            /* + 0x20 wraps      */
#define IO_KERN_PTR  0xBFFFFFF0u            /* + 0x20 > USER_SPACE_END */
#define N_SPAWN_FAIL 3

static int io_mode(void) {
    static char buf[16];
    int r[6];
    printf("PROBE io start\n");
    r[0] = syscall3(SYS_WRITE, 1, (uint32_t)buf, IO_TOO_BIG);
    r[1] = syscall3(SYS_WRITE, 1, IO_WRAP_PTR, 0x20);
    r[2] = syscall3(SYS_WRITE, 1, IO_KERN_PTR, 0x20);
    r[3] = syscall3(SYS_READ, 0, (uint32_t)buf, IO_TOO_BIG);
    r[4] = syscall3(SYS_READ, 0, IO_WRAP_PTR, 0x20);
    r[5] = syscall3(SYS_READ, 0, IO_KERN_PTR, 0x20);
    int refused = 0;
    for (int i = 0; i < 6; i++) {
        if (r[i] < 0) refused++;
    }
    int spawn_failed = 0;
    for (int i = 0; i < N_SPAWN_FAIL; i++) {
        char* const args[] = { "/no-such-probe.elf", 0 };
        if (spawn("/no-such-probe.elf", args) < 0) spawn_failed++;
    }
    printf("PROBE io refused=%d spawn_failed=%d\n", refused, spawn_failed);
    printf("PROBE io end\n");
    return 0;
}

int main(int argc, char** argv) {
    if (argc > 1 && !strcmp(argv[1], "io")) {
        return io_mode();
    }
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
