/*=============================================================================
 * secure_boot.h - Secure Boot Chain (DoD-Grade Code Signing)
 *
 * Implements cryptographic verification of all executables to prevent:
 * - Malware injection
 * - Rootkit persistence
 * - Unauthorized code execution
 * - Downgrade attacks (rollback protection)
 *
 * Features:
 * - ECDSA P-256 signatures on all binaries
 * - Measured boot (hash chain)
 * - Version-based rollback protection
 * - Tamper detection
 *
 * Standards Compliance:
 * - NIST FIPS 186-4 (Digital Signature Standard)
 * - UEFI Secure Boot specification
 * - TCG Trusted Boot
 *
 * Version: 1.0
 * Date: 2025-01-14
 *=============================================================================*/
#pragma once

#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * Constants
 *=============================================================================*/

/* Signature sizes (ECDSA P-256) */
#define SECURE_BOOT_SIGNATURE_SIZE      64      /* r + s (32 bytes each) */
#define SECURE_BOOT_PUBKEY_SIZE         64      /* x + y coordinates */
#define SECURE_BOOT_HASH_SIZE           32      /* SHA-256 hash */

/* Boot policy flags */
#define SECURE_BOOT_FLAG_ENFORCE        0x0001  /* Enforce signature checking */
#define SECURE_BOOT_FLAG_MEASURED       0x0002  /* Enable measured boot */
#define SECURE_BOOT_FLAG_ROLLBACK_CHECK 0x0004  /* Check version for rollback */
#define SECURE_BOOT_FLAG_AUDIT_LOG      0x0008  /* Log all verification events */

/* Maximum version number (prevents overflow) */
#define SECURE_BOOT_MAX_VERSION         0xFFFFFFFF

/*=============================================================================
 * Data Structures
 *=============================================================================*/

/**
 * @brief Boot header embedded in signed binaries
 *
 * This header is prepended to all signed executables (kernel, ELF binaries).
 * The signature covers the entire binary AFTER this header.
 */
typedef struct __attribute__((packed)) {
    uint32_t magic;                                 /* Magic number: 0x5342544E ("SBTN") */
    uint32_t version;                               /* Binary version (for rollback protection) */
    uint32_t flags;                                 /* Boot policy flags */
    uint32_t binary_size;                           /* Size of binary (excluding this header) */
    uint8_t  signature[SECURE_BOOT_SIGNATURE_SIZE]; /* ECDSA P-256 signature (r || s) */
    uint8_t  hash[SECURE_BOOT_HASH_SIZE];           /* SHA-256 hash of binary */
    uint32_t timestamp;                             /* Unix timestamp of signing */
    uint32_t reserved[4];                           /* Reserved for future use */
} secure_boot_header_t;

/**
 * @brief Secure boot configuration
 */
typedef struct {
    uint8_t  public_key[SECURE_BOOT_PUBKEY_SIZE];   /* Trusted public key (x || y) */
    uint32_t min_version;                           /* Minimum acceptable version */
    uint32_t flags;                                 /* Global boot policy flags */
    bool     initialized;                           /* Is secure boot initialized? */
} secure_boot_config_t;

/**
 * @brief Measured boot state (hash chain)
 */
typedef struct {
    uint8_t  pcr[8][SECURE_BOOT_HASH_SIZE];         /* Platform Configuration Registers */
    uint32_t pcr_count[8];                          /* Number of extends per PCR */
    bool     locked;                                /* Is measurement locked? */
} measured_boot_state_t;

/**
 * @brief Verification result
 */
typedef struct {
    bool     signature_valid;                       /* Is ECDSA signature valid? */
    bool     hash_valid;                            /* Does hash match? */
    bool     version_valid;                         /* Passes rollback check? */
    bool     policy_valid;                          /* Meets policy requirements? */
    uint32_t version;                               /* Binary version */
    uint32_t timestamp;                             /* Signing timestamp */
} secure_boot_result_t;

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
 * @brief Verify a signed binary (kernel or ELF)
 *
 * @param binary Pointer to signed binary (including secure_boot_header_t)
 * @param total_size Total size (header + binary)
 * @param result Output verification result (can be NULL)
 * @return 0 on success (signature valid), negative error code on failure
 *
 * Error codes:
 * -1: Invalid header magic
 * -2: Signature verification failed
 * -3: Hash mismatch
 * -4: Version too old (rollback protection)
 * -5: Policy violation
 */
int secure_boot_verify(const void* binary, uint32_t total_size,
                        secure_boot_result_t* result);

/**
 * @brief Verify an ELF binary before execution
 *
 * Convenience wrapper for verifying ELF files loaded from filesystem.
 *
 * @param path Path to ELF binary
 * @return 0 on success, negative error code on failure
 */
int secure_boot_verify_elf(const char* path);

/**
 * @brief Extend a Platform Configuration Register (PCR)
 *
 * Implements measured boot by extending PCR with SHA-256 hash:
 * PCR[n] = SHA-256(PCR[n] || new_value)
 *
 * @param pcr_index PCR index (0-7)
 * @param data Data to measure
 * @param size Size of data
 * @return 0 on success, negative on error
 */
int secure_boot_extend_pcr(uint8_t pcr_index, const void* data, uint32_t size);

/**
 * @brief Get current PCR value
 *
 * @param pcr_index PCR index (0-7)
 * @param pcr_value Output buffer (32 bytes)
 * @return 0 on success, negative on error
 */
int secure_boot_get_pcr(uint8_t pcr_index, uint8_t* pcr_value);

/**
 * @brief Lock measured boot state (prevent further modifications)
 *
 * Once locked, PCR values cannot be extended. This ensures
 * the boot chain cannot be tampered with after verification.
 */
void secure_boot_lock(void);

/**
 * @brief Check if secure boot is enforced
 *
 * @return true if signature checking is enforced, false otherwise
 */
bool secure_boot_is_enforced(void);

/**
 * @brief Get current secure boot configuration
 *
 * @param config Output configuration structure
 */
void secure_boot_get_config(secure_boot_config_t* config);

/**
 * @brief Set minimum acceptable version (rollback protection)
 *
 * @param min_version New minimum version
 */
void secure_boot_set_min_version(uint32_t min_version);

/**
 * @brief Attestation: Get hash of entire boot chain
 *
 * Returns a hash of all PCR values, proving the system
 * booted with specific software. Used for remote attestation.
 *
 * @param attestation_hash Output buffer (32 bytes)
 * @return 0 on success, negative on error
 */
int secure_boot_attest(uint8_t* attestation_hash);

/**
 * @brief Enable/disable secure boot enforcement
 *
 * WARNING: Disabling secure boot removes protection against
 * malware injection. Only use for development/testing.
 *
 * @param enforce true to enforce, false to disable
 */
void secure_boot_set_enforcement(bool enforce);

/*=============================================================================
 * Convenience Macros
 *=============================================================================*/

/* Magic number for secure boot header */
#define SECURE_BOOT_MAGIC   0x5342544E  /* "SBTN" (Secure Boot TinyOS) */

/* PCR assignments (following TCG conventions) */
#define PCR_BOOTLOADER      0           /* Bootloader measurement */
#define PCR_KERNEL          1           /* Kernel measurement */
#define PCR_KERNEL_CMDLINE  2           /* Kernel command line */
#define PCR_INITRAMFS       3           /* Initial RAM filesystem */
#define PCR_USER_BINARIES   4           /* User-space executables */
#define PCR_CONFIGURATION   5           /* System configuration */
#define PCR_CUSTOM_1        6           /* Custom measurements */
#define PCR_CUSTOM_2        7           /* Custom measurements */
