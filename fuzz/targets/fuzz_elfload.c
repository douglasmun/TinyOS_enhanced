/* Fuzz target: the ELF loader's header and program-header validation in
 * elf_load_process_argv() (src/elf.c) -- everything between the signature
 * gate and task creation.
 *
 * Built as the -DELF_PERMISSIVE_SIGNATURES opt-out, where an unsigned file
 * reaches this code; in the default build only a file the pinned key signed
 * does, so what this finds there is defence in depth, not a pre-auth bug.
 *
 * task_create_user_argv() is stubbed to fail: the input has then passed every
 * check the loader makes before it touches a page table, and the stub notes
 * that so a positive control can show it got there. The input is the file,
 * in an exact-size heap buffer, so ASan flags any read past it. */
#define ELF_PERMISSIVE_SIGNATURES
#include "elf.c"

#include <stdlib.h>
#include "fuzz_common.h"

int task_create_user_argv(uint32_t entry, const char* name, uint16_t stack,
                          int argc, const char* const* argv) {
    (void)entry; (void)name; (void)stack; (void)argc; (void)argv;
    fuzz_note("elfload: validation passed");
    return -1;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len) {
    fuzz_reset();
    uint8_t* f = fuzz_dup(data, len);
    const char* argv[] = { "x", NULL };
    elf_load_process_argv(f, len, "fuzz", 1, argv);
    free(f);
    return 0;
}
