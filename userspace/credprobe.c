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

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* credprobe -t LABEL USER PASSWORD N: call SYS_SWITCH_USER N times and print
 * each call's rc and cost in units of 1024 TSC cycles. The TSC is readable
 * from ring 3 here, which is what makes a cost difference between refusals
 * an oracle; verify-legacy-su-oracle.sh compares an unknown user, a wrong
 * password and a locked account. */
static int timing_mode(const char* label, const char* user, const char* pass, int n) {
    for (int i = 0; i < n; i++) {
        uint64_t t0 = rdtsc();
        int rc = syscall3(SYS_SWITCH_USER, (uint32_t)(uintptr_t)user,
                          (uint32_t)(uintptr_t)pass, 0);
        uint64_t t1 = rdtsc();
        printf("PROBE t %s rc=%d kc=%u\n", label, rc, (uint32_t)((t1 - t0) >> 10));
    }
    printf("PROBE TIMING DONE %s\n", label);
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 6 && strcmp(argv[1], "-t") == 0) {
        return timing_mode(argv[2], argv[3], argv[4], atoi(argv[5]));
    }

    /* Optional: credprobe [su_user [su_password [old_password]]]. The defaults
     * are the attacker's guesses above; verify-legacy-cred-quiet.sh passes an
     * unknown user and the real password to drive the not-found and success
     * paths of the legacy build. */
    const char* su_user = argc > 1 ? argv[1] : "root";
    const char* su_pass = argc > 2 ? argv[2] : "guessguess";
    const char* old_pass = argc > 3 ? argv[3] : "guessguess";

    /* Attempt to switch to root with a guessed password. Under the old code
     * this reached user_verify_password() — the bare hash comparison, with no
     * failed_attempts counter — so it was an unlimited password oracle. */
    int su_rc = syscall3(SYS_SWITCH_USER, (uint32_t)(uintptr_t)su_user,
                         (uint32_t)(uintptr_t)su_pass, 0);
    printf("PROBE switch_user rc=%d\n", su_rc);

    /* Attempt to change a password outright. */
    int pw_rc = syscall3(SYS_CHANGE_PASSWORD, (uint32_t)(uintptr_t)old_pass,
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
