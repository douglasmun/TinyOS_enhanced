/*=============================================================================
 * credprobe.c — ring-3 probe for the DEPRECATED credential syscalls.
 *
 * SYS_CHANGE_PASSWORD (14) and SYS_SWITCH_USER (15) take a PLAINTEXT PASSWORD
 * in a syscall argument register. SYS_CRED (32) supersedes them precisely by
 * never letting a password reach userspace at all, so ring-3 dispatch for the
 * two legacy calls is refused with -ENOSYS unless the kernel is built with
 * -DTINYOS_LEGACY_CRED_SYSCALLS.
 *
 * Nothing in the shell can make these calls, which is exactly why this program
 * exists: the gate lives at the syscall boundary, and only a caller that goes
 * straight to int 0x80 can prove the boundary holds rather than that no shell
 * happens to offer the command. It deliberately calls them with a real username
 * and a real password string, the way an attacker would.
 *
 * Prints one PROBE line per call so a harness can assert on the exact errno.
 *===========================================================================*/
#include "libc.h"

#define SYS_CHANGE_PASSWORD 14
#define SYS_SWITCH_USER     15

#define ENOSYS 38

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    /* Attempt to switch to root with a guessed password. Under the old code
     * this reached user_verify_password() — the bare hash comparison, with no
     * failed_attempts counter — so it was an unlimited password oracle. */
    int su_rc = syscall3(SYS_SWITCH_USER, (uint32_t)(uintptr_t)"root",
                         (uint32_t)(uintptr_t)"guessguess", 0);
    printf("PROBE switch_user rc=%d\n", su_rc);

    /* Attempt to change a password outright. */
    int pw_rc = syscall3(SYS_CHANGE_PASSWORD, (uint32_t)(uintptr_t)"guessguess",
                         (uint32_t)(uintptr_t)"newpassword", 0);
    printf("PROBE change_password rc=%d\n", pw_rc);

    /* Report the identity we ended up with. If either call succeeded in
     * switching us, this is the escalation made visible. */
    printf("PROBE uid=%d euid=%d\n", getuid(), getuid());

    if (su_rc == -ENOSYS && pw_rc == -ENOSYS) {
        printf("PROBE VERDICT refused\n");
        return 0;
    }
    printf("PROBE VERDICT reachable\n");
    return 1;
}
