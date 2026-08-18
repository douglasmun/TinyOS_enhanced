/*=============================================================================
 * secure_boot.c - Secure Boot Chain Implementation
 *=============================================================================*/
#include "secure_boot.h"
#include "kprintf.h"
#include "util.h"

/*=============================================================================
 * Global State
 *
 * This subsystem does exactly one job: it holds the pinned ECDSA P-256 public
 * key that elf.c checks every signed binary against, and it refuses to come up
 * with a missing or all-zero key. Signature verification itself lives in
 * elf.c -- see the note above elf_signatures_enforced() for why the gate is
 * there and not here.
 *=============================================================================*/
static secure_boot_config_t boot_config = {0};

/**
 * @brief Check if public key is all zeros (invalid/missing)
 */
static bool is_public_key_zero(const uint8_t* key) {
    for (uint32_t i = 0; i < SECURE_BOOT_PUBKEY_SIZE; i++) {
        if (key[i] != 0) {
            return false;
        }
    }
    return true;
}

void secure_boot_init(const uint8_t* public_key) {
    /*=========================================================================
     * Fail closed on a missing or all-zero key.
     *
     * This is load-bearing, not defensive boilerplate: elf.c refuses every
     * signature when initialized is false, so leaving it false is the safe
     * state. The original code took the opposite path -- memset the key to
     * zeros and continue -- which booted a system where no signature could
     * ever match and the caller was free to treat that as "unenforced".
     *=======================================================================*/

    if (!public_key) {
        kprintf("[SECURE_BOOT] FATAL: No public key provided\n");
        kprintf("[SECURE_BOOT] Secure boot cannot initialize without a valid public key\n");
        kprintf("[SECURE_BOOT] System security compromised - halting\n");
        /* In production, this should halt the system */
        boot_config.initialized = false;
        return;
    }

    memcpy(boot_config.public_key, public_key, SECURE_BOOT_PUBKEY_SIZE);

    /* Validate public key is not all zeros */
    if (is_public_key_zero(boot_config.public_key)) {
        kprintf("[SECURE_BOOT] FATAL: Public key is all zeros (invalid)\n");
        kprintf("[SECURE_BOOT] Check build configuration for embedded public key\n");
        kprintf("[SECURE_BOOT] System security compromised - halting\n");
        boot_config.initialized = false;
        return;
    }

    boot_config.initialized = true;

    /* Report what this subsystem actually establishes: a pinned key. Do NOT
     * reintroduce an "Enforcement:" line here -- whether unsigned binaries are
     * rejected is decided by elf.c's build-mode gate, and a line printed from
     * a policy flag reported ENFORCED even in a permissive build. */
    kprintf("[SECURE_BOOT] Signing key pinned (ECDSA P-256)\n");
}

void secure_boot_get_config(secure_boot_config_t* config) {
    if (config) {
        memcpy(config, &boot_config, sizeof(secure_boot_config_t));
    }
}
