/*=============================================================================
 * protected_path_test.c -- boundary proof for vfs_path_is_protected().
 *
 * The real function is extracted verbatim from src/vfs.c by the harness
 * (verify-protected-path-match.sh) and #included here, so this exercises the
 * SHIPPING logic, not a copy. We then drive the truth table that the match
 * boundary is about:
 *
 *   - the protected directory node itself ("/etc", no trailing slash) must be
 *     protected (the under-match the old bare-strncmp missed);
 *   - contents under it ("/etc/passwd") must stay protected;
 *   - a sibling whose name merely STARTS with a protected name ("/kernelfoo",
 *     "/etcfoo") must NOT be protected (the over-match the old prefix hit);
 *   - unrelated paths must not be protected.
 *
 * A PRE-FIX arm replays the old bare-prefix shape as a negative control: it
 * MUST get the "/etc" (under) and "/kernelfoo" (over) cases wrong, or the test
 * is not actually discriminating and reports INCONCLUSIVE (exit 2) rather than
 * passing -- same discipline as path_bound_test.c.
 *
 * Host-compiled (freestanding kernel strncmp/strlen are just the C library's
 * here), -O0. Exit 0 = fixed arm correct AND pre-fix arm demonstrably wrong;
 * 1 = fixed arm wrong; 2 = inconclusive (pre-fix arm not discriminating).
 *===========================================================================*/
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>

/* Declared here so main() can call it whether the definition is the stand-alone
 * fallback below or the real body the harness appends after this file. */
bool vfs_path_is_protected(const char* canonical);

/* The harness concatenates the extracted vfs_path_is_protected() body AFTER
 * this file before compiling (with PROTECTED_FN_INJECTED defined). The body
 * here is a stand-alone fallback so the file also compiles on its own during
 * development. */
#ifndef PROTECTED_FN_INJECTED
bool vfs_path_is_protected(const char* canonical) {
    static const char* const protected_paths[] = {
        "/bin", "/sbin", "/etc", "/boot", "/kernel", NULL
    };
    for (int i = 0; protected_paths[i] != NULL; i++) {
        size_t len = strlen(protected_paths[i]);
        if (strncmp(canonical, protected_paths[i], len) == 0 &&
            (canonical[len] == '\0' || canonical[len] == '/')) {
            return true;
        }
    }
    return false;
}
#endif

/* The PRE-FIX shape: bare strncmp prefix against slash-suffixed entries.
 * Exactly what shipped before the tightening -- the negative control. */
static bool prefix_shape(const char* canonical) {
    static const char* const old_paths[] = {
        "/bin/", "/sbin/", "/etc/", "/boot/", "/kernel", NULL
    };
    for (int i = 0; old_paths[i] != NULL; i++) {
        if (strncmp(canonical, old_paths[i], strlen(old_paths[i])) == 0) {
            return true;
        }
    }
    return false;
}

struct tc { const char* path; bool want; const char* why; };

int main(void) {
    static const struct tc cases[] = {
        /* the directory node itself -- the under-match */
        { "/etc",        true,  "protected dir node itself" },
        { "/bin",        true,  "protected dir node itself" },
        { "/sbin",       true,  "protected dir node itself" },
        { "/boot",       true,  "protected dir node itself" },
        { "/kernel",     true,  "protected file" },
        /* contents under a protected dir */
        { "/etc/passwd", true,  "content under protected dir" },
        { "/bin/sh",     true,  "content under protected dir" },
        /* the over-match: siblings that merely start with the name */
        { "/etcfoo",     false, "sibling, not under /etc" },
        { "/kernelfoo",  false, "sibling, not /kernel" },
        { "/kernel_bak", false, "sibling, not /kernel" },
        { "/binary",     false, "sibling, not under /bin" },
        /* unrelated */
        { "/",           false, "root is not protected" },
        { "/scratch/x",  false, "unrelated path" },
        { "/home/user",  false, "unrelated path" },
    };
    const int n = (int)(sizeof(cases) / sizeof(cases[0]));

    int fixed_wrong = 0;
    for (int i = 0; i < n; i++) {
        bool got = vfs_path_is_protected(cases[i].path);
        if (got != cases[i].want) {
            printf("FIXED WRONG: %-14s got=%d want=%d (%s)\n",
                   cases[i].path, got, cases[i].want, cases[i].why);
            fixed_wrong++;
        }
    }

    /* The pre-fix shape must disagree with the truth table on at least the two
     * boundary cases it is known to get wrong; otherwise this test is not
     * actually discriminating. */
    bool under = (prefix_shape("/etc")      != false);  /* old missed it => false (wrong) */
    bool over  = (prefix_shape("/kernelfoo") == true);  /* old flagged it => true  (wrong) */
    /* old /etc => prefix "/etc/" (5) vs "/etc\0": strncmp over 5 differs => NOT protected
     * => prefix_shape("/etc") returns false => under-match present. */
    bool prefix_under_bug = (prefix_shape("/etc") == false);
    bool prefix_over_bug  = (prefix_shape("/kernelfoo") == true);
    (void)under; (void)over;

    printf("fixed arm: %d/%d correct\n", n - fixed_wrong, n);
    printf("pre-fix arm under-match bug reproduced: %s\n", prefix_under_bug ? "yes" : "no");
    printf("pre-fix arm over-match bug reproduced:  %s\n", prefix_over_bug ? "yes" : "no");

    if (fixed_wrong != 0) {
        return 1;  /* the shipping function gets a case wrong */
    }
    if (!prefix_under_bug || !prefix_over_bug) {
        return 2;  /* negative control not discriminating */
    }
    return 0;
}
