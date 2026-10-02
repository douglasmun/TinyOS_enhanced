/* Fuzz target: elf_verify_signature() in src/elf.c and the P-256 verify under
 * it (src/ecdsa.c), the gate every exec passes before any program header is
 * parsed.
 *
 * Oracle: nothing the fuzzer builds may verify unless it is a genuine
 * signature -- the (hash, r) of one of the shipped signed binaries. s is not
 * compared: s -> n-s is an equally valid signature over the same bytes.
 * Anything else returning true is a forgery and aborts.
 *
 * The fuzzer cannot recompute SHA-256 or guess the pinned key, so byte 0
 * selects which of those the harness fixes up the way a real attacker would
 * (an attacker knows the public key and can hash their own file):
 *   FX_TRAILER  write magic + elf_size so the trailer parses
 *   FX_HASH     store sha256(body) in the trailer
 *   FX_KEY      copy the pinned public key into the trailer
 * which pushes inputs past those checks into ecdsa_verify() with hostile r, s.
 *
 * The pinned key and the genuine (hash, r) pairs come from
 * userspace/*.signed via mk_elfsig_known.py (elfsig_known.h). The positive
 * controls: fuzz/seeds/elfsig/hello is hello.elf.signed untouched behind a
 * zero flag byte; counter_fixups is counter.elf.signed with every fix-up on.
 * Both must print "elfsig: verify=PASS" under FUZZ_VERBOSE=1. */
#include "elf.c"

#include <stdlib.h>
#include "ecdsa.h"
#include "fuzz_common.h"
#include "secure_boot.h"
#include "sha256.h"

#define FX_TRAILER 0x01
#define FX_HASH    0x02
#define FX_KEY     0x04

#include "elfsig_known.h"

void secure_boot_get_config(secure_boot_config_t* config) {
    memcpy(config->public_key, PINNED_KEY, sizeof(PINNED_KEY));
    config->initialized = true;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len) {
    if (len < 1) return 0;
    uint8_t flags = data[0];
    data++; len--;
    fuzz_reset();

    uint8_t* f = fuzz_dup(data, len);
    if (len >= ELF_SIG_SIZE) {
        elf_signature_t* sig = (elf_signature_t*)(f + len - ELF_SIG_SIZE);
        uint32_t body = (uint32_t)(len - ELF_SIG_SIZE);
        if (flags & FX_TRAILER) {
            memcpy(sig->magic, ELF_SIG_MAGIC, 16);
            sig->elf_size = body;
        }
        if (flags & FX_HASH) sha256(f, body, sig->hash);
        if (flags & FX_KEY) memcpy(sig->pub_key_x, PINNED_KEY, 64);
    }

    if (elf_verify_signature(f, len)) {
        uint8_t h[32];
        const elf_signature_t* sig = (const elf_signature_t*)(f + len - ELF_SIG_SIZE);
        sha256(f, sig->elf_size, h);
        bool genuine = false;
        for (size_t i = 0; i < sizeof(KNOWN_SIGS) / sizeof(KNOWN_SIGS[0]); i++) {
            if (memcmp(h, KNOWN_SIGS[i].hash, 32) == 0 &&
                memcmp(sig->signature_r, KNOWN_SIGS[i].r, 32) == 0) genuine = true;
        }
        if (!genuine) abort();
        fuzz_note("elfsig: verify=PASS");
    }
    free(f);
    return 0;
}
