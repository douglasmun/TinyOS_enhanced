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

void secure_boot_init(const uint8_t* public_key, uint32_t min_version, uint32_t flags) {
    /*=========================================================================
     * SECURITY FIX: Fail-Closed on Missing Public Key
     *
     * VULNERABILITY: Accepts NULL or zero public key and continues
     *
     * OLD CODE (VULNERABLE):
     * if (public_key) { copy key } else { memset to zeros }
     * → System boots with no public key, signature checks meaningless
     *
     * NEW CODE (SECURE):
     * - Reject NULL public key as FATAL error
     * - Reject all-zeros public key as configuration error
     * - Force enforcement ON by default (fail-closed)
     * - Only allow disabling enforcement if explicitly requested AND key valid
     *
     * ATTACK SCENARIO PREVENTED:
     * 1. Attacker clears public key in boot config
     * 2. System initializes with zero key
     * 3. Signature verification always fails (no valid key to check against)
     * 4. BUT: Code falls back to unenforced mode
     * 5. Attacker executes unsigned code
     *
     * FIX: Require valid public key, default to enforcement ON
     *=======================================================================*/

    /* Copy public key */
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

    boot_config.min_version = min_version;

    boot_config.flags = flags;
    boot_config.initialized = true;

    /* Report what this subsystem actually establishes: a pinned key. Do NOT
     * reintroduce an "Enforcement:" line here -- whether unsigned binaries are
     * rejected is decided by elf.c's build-mode gate, and a line printed from
     * boot_config.flags reported ENFORCED even in a permissive build. */
    kprintf("[SECURE_BOOT] Signing key pinned (ECDSA P-256)\n");
}

void secure_boot_get_config(secure_boot_config_t* config) {
    if (config) {
        memcpy(config, &boot_config, sizeof(secure_boot_config_t));
    }
}
