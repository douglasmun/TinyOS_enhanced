/*=============================================================================
 * ramprobe.c - linked INSIDE the kernel's identity-mapped RAM (0x0C000000)
 *
 * The ELF loader must refuse this image: a user PTE below PMM_MAX_BYTES
 * replaces the kernel's view of a physical frame. If it ever runs, the
 * loader's range check is gone. See verify-user-link-base.sh and
 * doc/DESIGN_USER_LINK_BASE.md.
 *=============================================================================*/
#include "libc.h"

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    print("RAMPROBE ran inside the kernel RAM map\n");
    return 0;
}
