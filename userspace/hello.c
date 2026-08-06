/*=============================================================================
 * hello.c - Simple User Mode Test Program (ELF)
 *
 * Built on the minimal libc (libc.h/libc.c, entry via crt0.S).
 * NOTE: the output strings below are load-bearing — verify-exec.sh and
 * auto-verify-exec.sh grep for "Hello from ELF!". Keep them byte-identical.
 *=============================================================================*/
#include "libc.h"

int main(void) {
    print("Hello from ELF!\n");
    print("This is a user mode program loaded from ELF format.\n");
    print("Yielding...\n");

    for (int i = 0; i < 3; i++) {
        yield();
        print("ELF program resumed!\n");
    }

    print("ELF program exiting.\n");
    return 0;
}
