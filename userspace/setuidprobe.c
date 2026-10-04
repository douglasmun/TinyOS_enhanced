/*=============================================================================
 * setuidprobe.c — ring-3 probe for EDR's privilege-escalation signature.
 *
 * The signature is meant to catch a task reaching for root it does not hold.
 * Nothing in the shell calls setuid/setgid/seteuid/setegid, which is why this
 * program exists: only a caller that goes straight to int 0x80 can show which
 * credential changes EDR lets through and which it kills.
 *
 *   setuidprobe        ordinary credential handling, run as root: drop to
 *                      self, a temporary seteuid drop and its return to root.
 *                      None of it reaches for root the task does not hold, so
 *                      every call must return and "PROBE benign done" print.
 *                      Exits 3 (the esc leg exits 1, or 137 when killed), so
 *                      the shell reports every run's end.
 *   setuidprobe esc    POSITIVE CONTROL: drop root for good, then ask for it
 *                      back. EDR must kill the task inside the second call,
 *                      so "PROBE UNREACHED" never prints.
 *===========================================================================*/
#include "libc.h"

#define SYS_GETEUID 7
#define SYS_SETUID  9
#define SYS_SETGID  10
#define SYS_SETEUID 11
#define SYS_SETEGID 12

static int call(const char* name, int num, int arg) {
    int rc = syscall1(num, (uint32_t)arg);
    printf("PROBE %s(%d) rc=%d\n", name, arg, rc);
    return rc;
}

int main(int argc, char** argv) {
    if (argc > 1 && strcmp(argv[1], "esc") == 0) {
        call("setuid", SYS_SETUID, 1000);
        printf("PROBE dropped uid=%d euid=%d\n", getuid(), syscall0(SYS_GETEUID));
        call("setuid", SYS_SETUID, 0);
        printf("PROBE UNREACHED\n");
        return 1;
    }

    call("setgid", SYS_SETGID, getgid());
    call("setegid", SYS_SETEGID, getgid());
    call("setuid", SYS_SETUID, getuid());
    call("seteuid", SYS_SETEUID, 1000);
    call("seteuid", SYS_SETEUID, 0);
    printf("PROBE benign done uid=%d euid=%d\n", getuid(), syscall0(SYS_GETEUID));
    /* Nonzero so the shell always prints "exited with status", which is the
     * harness's sign that this run is over, killed or not. */
    return 3;
}
