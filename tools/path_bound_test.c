/*=============================================================================
 * path_bound_test.c -- host-side replay of the shell's path-append loops.
 *
 * Built and run by verify-shell-path-overflow.sh with the HOST compiler, not
 * the cross toolchain: the bug is one byte of stack past the end of a local
 * array, and the whole point is to observe that byte directly. Inside QEMU it
 * lands on whatever the compiler happened to place next -- often padding, in
 * which case a boot-based harness sees nothing and reports PASS against the
 * unfixed kernel.
 *
 * Each case replays the loop shape from src/shell_fileops.c verbatim, with the
 * reserve constant as a parameter, and puts a canary immediately after the
 * array. Structure layout is not guaranteed by C, so the canary is read back
 * through the same struct that wrote it and the fixed arm is asserted to leave
 * it intact -- if the compiler inserted padding, BOTH arms come back clean and
 * the harness reports INCONCLUSIVE rather than a false PASS.
 *
 * Exit 0 = the fixed reserve is safe and the old one was not (the fix is
 *          load-bearing and this test can see it).
 * Exit 1 = the fixed reserve still overflows.
 * Exit 2 = neither arm overflows: padding is absorbing the write, so this
 *          test cannot witness the bug on this compiler. INCONCLUSIVE.
 *===========================================================================*/
#include <stdio.h>
#include <string.h>

#define MAX_PATH 256
#define CANARY   0x7E

struct framed {
    char buf[MAX_PATH];
    volatile unsigned char canary;
};

/* The append branch of cmd_cd / cmd_exec: copy cwd, add a separator, copy the
 * argument, terminate. `reserve` is the constant under test. */
static int append_overflows(int reserve, const char* cwd, const char* arg) {
    struct framed f;
    memset(&f, 0, sizeof(f));
    f.canary = CANARY;

    size_t pos = 0;
    for (size_t i = 0; cwd[i] != '\0' && pos < sizeof(f.buf) - (size_t)reserve; i++) {
        f.buf[pos++] = cwd[i];
    }
    f.buf[pos++] = '/';
    for (size_t i = 0; arg[i] != '\0' && pos < sizeof(f.buf) - 1; i++) {
        f.buf[pos++] = arg[i];
    }
    f.buf[pos] = '\0';

    return f.canary != CANARY;
}

int main(void) {
    char cwd[MAX_PATH];
    memset(cwd, 'a', sizeof(cwd) - 1);
    cwd[0] = '/';
    cwd[MAX_PATH - 1] = '\0';        /* a cwd that fills the buffer exactly */

    int old_bad = append_overflows(1, cwd, "x");   /* pre-fix constant  */
    int new_bad = append_overflows(2, cwd, "x");   /* post-fix constant */

    printf("cwd length            : %zu (MAX_PATH %d)\n", strlen(cwd), MAX_PATH);
    printf("reserve -1 (pre-fix)  : canary clobbered = %d\n", old_bad);
    printf("reserve -2 (post-fix) : canary clobbered = %d\n", new_bad);

    if (new_bad) {
        printf("VERDICT: FAIL -- the shipped reserve still writes past the array\n");
        return 1;
    }
    if (!old_bad) {
        printf("VERDICT: INCONCLUSIVE -- neither arm clobbered the canary, so\n");
        printf("         padding is absorbing the write and this test cannot\n");
        printf("         witness the bug on this compiler.\n");
        return 2;
    }
    printf("VERDICT: OK -- pre-fix overflows, post-fix does not\n");
    return 0;
}
