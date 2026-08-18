/*=============================================================================
 * secure_boot.h - Pinned code-signing key
 *
 * SCOPE: this subsystem holds the trusted ECDSA P-256 public key and refuses
 * to initialize without a valid one. That is all it does.
 *
 * Signature verification is NOT here -- it lives in elf.c, which owns the
 * on-disk format (a 184-byte trailer produced by tools/sign_elf.py), the
 * interrupt-masking invariant around the P-256 math, and the build-mode gate
 * elf_signatures_enforced().
 *
 * This file once declared a second, incompatible verifier (a prepended
 * secure_boot_header_t), measured-boot PCRs and rollback protection. None of
 * it was ever called: the PCRs stayed zero for the machine's lifetime while
 * the boot log printed "Measured boot: ENABLED". Those declarations were
 * removed rather than wired up -- adding a second signing format to replace a
 * working one is not an improvement. Don't reintroduce them speculatively;
 * with no TPM, PCRs computed by the kernel being measured attest to nothing
 * an attacker already in that kernel cannot forge.
 *=============================================================================*/
#pragma once

#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * Constants
 *=============================================================================*/

/* Pinned key size (ECDSA P-256: x || y) */
#define SECURE_BOOT_PUBKEY_SIZE         64      /* x + y coordinates */

/*=============================================================================
 * Data Structures
 *=============================================================================*/

/**
 * @brief Secure boot configuration
 */
typedef struct {
    uint8_t  public_key[SECURE_BOOT_PUBKEY_SIZE];   /* Trusted public key (x || y) */
    bool     initialized;                           /* Is a valid key pinned? */
} secure_boot_config_t;

/*=============================================================================
 * API Functions
 *=============================================================================*/

/**
 * @brief Pin the trusted code-signing key
 *
 * Takes no policy arguments, deliberately. It used to accept min_version and
 * a flags word, and after the dead verifier was removed nothing read either:
 * they were stored, copied out by get_config, and consulted by nobody, while
 * kernel.c went on passing SECURE_BOOT_FLAG_MEASURED for a measured boot that
 * has no implementation. Accepting policy you cannot enforce is how the
 * "Measured boot: ENABLED" line got written in the first place. If rollback
 * protection is ever wanted, build it where the signature format lives
 * (elf.c) and give it a version field something actually checks.
 *
 * @param public_key Trusted ECDSA P-256 public key (64 bytes: x || y)
 */
void secure_boot_init(const uint8_t* public_key);

/**
 * @brief Get current secure boot configuration
 *
 * @param config Output configuration structure
 */
void secure_boot_get_config(secure_boot_config_t* config);

