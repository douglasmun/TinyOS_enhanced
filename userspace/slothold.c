/*=============================================================================
 * slothold.c - long-lived child for the task-slot cap probe
 *
 * Exists only to OCCUPY A TASK SLOT for far longer than slotbomb.elf needs to
 * fill the table.
 *
 * WHY NOT REUSE sleeper.elf
 *
 * sleeper.elf lives about six seconds, which is plenty for the background-jobs
 * harness but useless here. Every spawn is a full ECDSA signature verification
 * plus an address-space build, which under QEMU/TCG takes tens of seconds --
 * so with sleeper.elf as the child, the early children EXIT AND FREE THEIR
 * SLOTS before the later spawns happen, the live count never climbs, and the
 * cap is never reached. The probe then reports "no refusal" against a kernel
 * whose cap is perfectly correct.
 *
 * That is a harness artifact masquerading as a kernel result, so the child has
 * to outlive the whole loop by a wide margin.
 *
 * It blocks rather than spins: a spinning child would compete with the spawn
 * loop for the CPU under TCG and make an already slow probe far slower. Sitting
 * in SLEEPING state still holds the slot, which is the only thing being tested.
 *===========================================================================*/
#include "libc.h"

/* ~10 minutes. Comfortably longer than the probe's spawn loop under TCG, and
 * the harness kills the VM long before this elapses -- the number just has to
 * be large enough that no child ever exits DURING the measurement. */
#define HOLD_ITERATIONS 1200

int main(void) {
    print("slothold: holding\n");

    for (int i = 0; i < HOLD_ITERATIONS; i++) {
        sleep_ms(500);
    }

    print("slothold: released\n");
    return 0;
}
