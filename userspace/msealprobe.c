/*=============================================================================
 * msealprobe.c — ring-3 driver for SYS_MSEAL (16).
 *
 * SYS_MSEAL has no libc wrapper and no shell builtin: nothing in userspace
 * can reach it except a program that goes straight to int 0x80. That is the
 * whole point of this probe, and it is also what let sixteen kprintf sites
 * sit on the path unnoticed -- there was no driver to make them fire.
 *
 * Every rejection here is reached with THIS PROGRAM'S OWN arguments, needing
 * no privilege and (for the size legs) no mapped memory at all. Each leg is
 * repeated a DISTINCT number of times so a harness can assert exact deltas:
 * a single counter incremented by everything cannot match all four expected
 * numbers at once.
 *
 * Leg 5 is the POSITIVE CONTROL and is not optional. Without it, a kernel
 * whose sys_mseal rejected every call unconditionally would pass legs 1-4
 * perfectly -- the rejection counters would all be exactly right.
 *===========================================================================*/
#include "libc.h"

#define SYS_MSEAL 16

/* Counts chosen distinct, and none a multiple of another, so no single
 * miscounting site can produce all four expected deltas. */
#define N_BOUNDS_KERNEL   3   /* addr >= KERNEL_BASE                        */
#define N_BOUNDS_HIGH     5   /* addr just under KERNEL_BASE, end above it  */
#define N_BOUNDS_CROSS    7   /* user addr, but end crosses into kernel     */
#define N_SIZE_ZERO      11   /* size == 0   -- rejected above any walk     */
#define N_SIZE_HUGE      13   /* size > 64MB -- rejected above any walk     */
#define N_UNMAPPED        4   /* valid bounds, but the pages are not mapped */

/* A page of our own writable data: the one region we know is mapped and
 * user-accessible, so the positive control can actually succeed. */
static char seal_target[8192];

static int mseal(uint32_t addr, uint32_t size) {
    return syscall3(SYS_MSEAL, addr, size, 0);
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    int i;
    int rc;

    /* Leg 1: kernel address. Counter: bounds. */
    for (i = 0; i < N_BOUNDS_KERNEL; i++) {
        rc = mseal(0xC0100000u, 4096);
    }
    printf("PROBE bounds_kernel n=%d rc=%d\n", N_BOUNDS_KERNEL, rc);

    /* Leg 2: highest user page, one page of size -- end lands exactly ON
     * KERNEL_BASE, which the `end > KERNEL_BASE` test must NOT reject (it is
     * the exclusive upper bound), so this uses the page BELOW it plus enough
     * size to cross. Counter: bounds.
     *
     * NOTE: there is deliberately no wrap-around leg. The integer-overflow
     * check in sys_mseal is UNREACHABLE from ring 3 -- addr < KERNEL_BASE and
     * size <= 64MB together bound addr+size below 0xC4000000, so it can never
     * carry past 2^32. It is correct defence-in-depth against a future caller
     * that relaxes either bound; it is simply not drivable from here, and a
     * leg claiming to exercise it would be measuring the SIZE check instead. */
    for (i = 0; i < N_BOUNDS_HIGH; i++) {
        rc = mseal(0xBFFF0000u, 0x00020000u);
    }
    printf("PROBE bounds_high n=%d rc=%d\n", N_BOUNDS_HIGH, rc);

    /* Leg 3: end crosses into kernel space without wrapping.
     * Kept UNDER the 64MB size cap on purpose -- otherwise the size check
     * fires first and this leg silently lands on the wrong counter. */
    for (i = 0; i < N_BOUNDS_CROSS; i++) {
        rc = mseal(0xBFFFF000u, 0x00100000u);
    }
    printf("PROBE bounds_cross n=%d rc=%d\n", N_BOUNDS_CROSS, rc);

    /* Leg 4a: size 0. The cheapest rejection in the kernel -- no memory, no
     * privilege, rejected above any page walk. This is the flood primitive. */
    for (i = 0; i < N_SIZE_ZERO; i++) {
        rc = mseal((uint32_t)(uintptr_t)seal_target, 0);
    }
    printf("PROBE size_zero n=%d rc=%d\n", N_SIZE_ZERO, rc);

    /* Leg 4b: size over the 64MB cap, likewise rejected before any walk. */
    for (i = 0; i < N_SIZE_HUGE; i++) {
        rc = mseal((uint32_t)(uintptr_t)seal_target, 0x08000000u);
    }
    printf("PROBE size_huge n=%d rc=%d\n", N_SIZE_HUGE, rc);

    /* Leg 4c: valid bounds and valid size, but pointing at unmapped user
     * memory -- this is the pair of counters INSIDE the page-walk loop.
     * Low address, well clear of anything the loader maps. */
    for (i = 0; i < N_UNMAPPED; i++) {
        rc = mseal(0x00010000u, 4096);
    }
    printf("PROBE unmapped n=%d rc=%d\n", N_UNMAPPED, rc);

    /*=========================================================================
     * Leg 5: POSITIVE CONTROL. Seal a page of our own writable data.
     *
     * Without this leg every assertion above is satisfied by a kernel that
     * refuses everything. `seal_target` is 8KB so that a page-aligned 4KB
     * window fits inside it whatever the linker chose for its address.
     *=======================================================================*/
    uint32_t base = ((uint32_t)(uintptr_t)seal_target + 4095u) & ~4095u;
    rc = mseal(base, 4096);
    printf("PROBE seal_own rc=%d\n", rc);

    if (rc == 0) {
        printf("PROBE VERDICT sealed\n");
        return 0;
    }
    printf("PROBE VERDICT refused\n");
    return 1;
}
