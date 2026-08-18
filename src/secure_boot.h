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

/* Boot policy flags */
#define SECURE_BOOT_FLAG_ENFORCE        0x0001  /* Enforce signature checking */
#define SECURE_BOOT_FLAG_MEASURED       0x0002  /* Enable measured boot */
#define SECURE_BOOT_FLAG_ROLLBACK_CHECK 0x0004  /* Check version for rollback */
#define SECURE_BOOT_FLAG_AUDIT_LOG      0x0008  /* Log all verification events */

/*=============================================================================
 * Data Structures
 *=============================================================================*/

/**
 * @brief Secure boot configuration
 */
typedef struct {
    uint8_t  public_key[SECURE_BOOT_PUBKEY_SIZE];   /* Trusted public key (x || y) */
    uint32_t min_version;                           /* Minimum acceptable version */
    uint32_t flags;                                 /* Global boot policy flags */
    bool     initialized;                           /* Is secure boot initialized? */
} secure_boot_config_t;

/*=============================================================================
 * API Functions
 *=============================================================================*/

/**
 * @brief Initialize secure boot subsystem
 *
 * @param public_key Trusted ECDSA P-256 public key (64 bytes: x || y)
 * @param min_version Minimum acceptable binary version
 * @param flags Boot policy flags
 */
void secure_boot_init(const uint8_t* public_key, uint32_t min_version, uint32_t flags);

/**
 * @brief Get current secure boot configuration
 *
 * @param config Output configuration structure
 */
void secure_boot_get_config(secure_boot_config_t* config);

