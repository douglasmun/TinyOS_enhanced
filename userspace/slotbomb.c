/*=============================================================================
 * slotbomb.c - per-user task-slot cap probe
 *
 * Spawns /sleeper.elf in a loop, as fast as the kernel will accept it, and
 * reports the count at which it was refused and with what errno.
 *
 * WHY THIS IS A PROGRAM AND NOT A SHELL LOOP
 *
 * The cap lives in task_create_user, at the SYSCALL boundary. Driving `&` from
 * the shell tests the shell's parser on the way there and is slow enough under
 * TCG that the rate limiter, not the cap, becomes the thing that stops us --
 * which would make the harness pass against a kernel with no cap at all. This
 * calls spawn() directly, in a tight loop, so the only thing that can refuse it
 * is the kernel's own accounting.
 *
 * WHY IT DOES NOT waitpid()
 *
 * Deliberate: the children must stay ALIVE to hold their slots. Reaping them
 * would free the slots and there would be nothing to hit the cap with.
 *
 * WHY THE CHILD IS slothold.elf AND NOT sleeper.elf
 *
 * Every spawn is a full ECDSA verification plus an address-space build, which
 * under TCG takes tens of seconds. sleeper.elf only lives about six, so with it
 * as the child the early children exit and free their slots before the later
 * spawns happen: the live count never climbs and the cap is never reached. The
 * probe would then report "no refusal" against a kernel whose cap is correct.
 * slothold.elf holds its slot for minutes, so nothing exits mid-measurement.
 *
 * -EAGAIN is the expected refusal and means the cap engaged. Any other errno is
 * a DIFFERENT failure (a missing binary, a bad path, memory exhaustion) and the
 * harness must be able to tell them apart -- "spawn eventually failed" is also
 * true of a kernel with no cap, so the errno is what carries the proof.
 *
 * NOTE: the output strings are load-bearing -- verify-slotcap.sh greps for
 * "slotbomb: refused after N (err=E)" and "slotbomb: no refusal after".
 * Keep them byte-identical.
 *===========================================================================*/
#include "libc.h"

/* Above any sane per-user cap but below the point where a kernel that refuses
 * for an unrelated reason would spin here indefinitely. If we get this far
 * without a refusal the cap is simply absent, which is the interesting result
 * and is reported as such. */
#define MAX_ATTEMPTS 40

int main(int argc, char** argv) {
    (void)argc; (void)argv;

    print("slotbomb: starting\n");

    char* child_argv[] = { "slothold.elf", 0 };

    for (int i = 0; i < MAX_ATTEMPTS; i++) {
        int pid = spawn("/slothold.elf", child_argv);
        if (pid < 0) {
            /* The count is the number that SUCCEEDED, so the harness can check
             * the cap engaged at the right place rather than merely at all. */
            printf("slotbomb: refused after %d (err=%d)\n", i, pid);
            return 0;
        }
    }

    printf("slotbomb: no refusal after %d spawns\n", MAX_ATTEMPTS);
    return 1;
}
