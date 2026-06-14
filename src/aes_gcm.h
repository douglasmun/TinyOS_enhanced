/*=============================================================================
 * aes_gcm.h - AES-GCM (Galois/Counter Mode) AEAD Cipher
 *=============================================================================
 *
 * AES-GCM provides both encryption and authentication in a single operation.
 * It is the mandatory cipher suite for TLS 1.3.
 *
 * Features:
 * - Authenticated Encryption with Associated Data (AEAD)
 * - Combines AES-CTR (encryption) + GHASH (authentication)
 * - Supports AES-128-GCM and AES-256-GCM
 * - Produces authentication tag (96, 104, 112, 120, or 128 bits)
 * - Constant-time implementation (timing attack resistant)
 *
 * Standards:
 * - NIST SP 800-38D (GCM specification)
 * - RFC 5116 (AEAD Interface)
 * - RFC 5288 (AES-GCM for TLS)
 *
 * Version: 1.0
 * Date: 2025-01-14
 *===========================================================================*/
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "crypto.h"

/*=============================================================================
 * Constants
 *===========================================================================*/
#define GCM_IV_SIZE         12      /* 96-bit nonce (recommended) */
#define GCM_TAG_SIZE        16      /* 128-bit authentication tag */
#define GCM_BLOCK_SIZE      16      /* AES block size */
#define GCM_MAX_AAD_SIZE    1024    /* Maximum additional authenticated data */
#define GCM_MAX_CT_SIZE     8192    /* Maximum ciphertext size */

/*=============================================================================
 * Data Structures
 *===========================================================================*/

/**
 * @brief GCM context for encryption/decryption
 * SECURITY FIX (AUDIT 11C): Added alignment attribute for portability
 */
typedef struct {
    aes_ctx_t aes_ctx;                  /* AES context for CTR mode */
    uint8_t H[GCM_BLOCK_SIZE];          /* Hash subkey H = AES_K(0^128) */
    uint8_t J0[GCM_BLOCK_SIZE];         /* Initial counter block */
    uint8_t ghash_state[GCM_BLOCK_SIZE];/* GHASH accumulator */
    uint64_t aad_len;                   /* Length of AAD in bytes */
    uint64_t ct_len;                    /* Length of ciphertext in bytes */
    bool initialized;                   /* Is context initialized? */
} __attribute__((aligned(4))) gcm_ctx_t;

/*=============================================================================
 * AES-GCM API Functions
 *===========================================================================*/

/**
 * @brief Initialize AES-GCM context with key and IV
 *
 * @param ctx GCM context to initialize
 * @param key AES key (16 bytes for AES-128, 32 bytes for AES-256)
 * @param key_len Key length in bytes (16 or 32)
 * @param iv Initialization vector / nonce (12 bytes recommended)
 * @param iv_len IV length in bytes (typically 12)
 */
void gcm_init(gcm_ctx_t* ctx, const uint8_t* key, size_t key_len,
              const uint8_t* iv, size_t iv_len);

/**
 * @brief Add Additional Authenticated Data (AAD)
 *
 * AAD is authenticated but not encrypted (e.g., packet headers).
 * Must be called after gcm_init() and before gcm_encrypt()/gcm_decrypt().
 *
 * @param ctx GCM context
 * @param aad Additional authenticated data
 * @param aad_len Length of AAD in bytes
 */
void gcm_aad(gcm_ctx_t* ctx, const uint8_t* aad, size_t aad_len);

/**
 * @brief Encrypt plaintext with AES-GCM
 *
 * @param ctx GCM context (initialized with gcm_init)
 * @param plaintext Plaintext to encrypt
 * @param ciphertext Output ciphertext buffer (same size as plaintext)
 * @param len Length of plaintext in bytes
 *
 * @note Can be called multiple times to encrypt in chunks
 */
void gcm_encrypt(gcm_ctx_t* ctx, const uint8_t* plaintext,
                 uint8_t* ciphertext, size_t len);

/**
 * @brief Decrypt ciphertext with AES-GCM
 *
 * @param ctx GCM context (initialized with gcm_init)
 * @param ciphertext Ciphertext to decrypt
 * @param plaintext Output plaintext buffer (same size as ciphertext)
 * @param len Length of ciphertext in bytes
 *
 * @note Can be called multiple times to decrypt in chunks
 */
void gcm_decrypt(gcm_ctx_t* ctx, const uint8_t* ciphertext,
                 uint8_t* plaintext, size_t len);

/**
 * @brief Finalize GCM and produce authentication tag
 *
 * @param ctx GCM context
 * @param tag Output authentication tag buffer (16 bytes)
 *
 * @note Must be called after gcm_encrypt() to get the tag
 */
void gcm_finish(gcm_ctx_t* ctx, uint8_t* tag);

/**
 * @brief Verify authentication tag for decryption
 *
 * @param ctx GCM context (after gcm_decrypt)
 * @param tag Authentication tag to verify (16 bytes)
 * @return true if tag is valid, false if authentication failed
 *
 * @note CRITICAL: Always check return value. If false, plaintext is invalid!
 */
bool gcm_verify(gcm_ctx_t* ctx, const uint8_t* tag);

/**
 * @brief Zeroize GCM context (security cleanup)
 *
 * @param ctx GCM context to zeroize
 */
void gcm_destroy(gcm_ctx_t* ctx);

/*=============================================================================
 * One-Shot Convenience Functions
 *===========================================================================*/

/**
 * @brief Encrypt and authenticate in one call
 *
 * @param key AES key (16 or 32 bytes)
 * @param key_len Key length (16 or 32)
 * @param iv Initialization vector (12 bytes recommended)
 * @param iv_len IV length
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len AAD length (0 if no AAD)
 * @param plaintext Plaintext to encrypt
 * @param plaintext_len Plaintext length
 * @param ciphertext Output ciphertext buffer
 * @param tag Output authentication tag (16 bytes)
 */
void gcm_encrypt_oneshot(const uint8_t* key, size_t key_len,
                         const uint8_t* iv, size_t iv_len,
                         const uint8_t* aad, size_t aad_len,
                         const uint8_t* plaintext, size_t plaintext_len,
                         uint8_t* ciphertext, uint8_t* tag);

/**
 * @brief Decrypt and verify in one call
 *
 * @param key AES key (16 or 32 bytes)
 * @param key_len Key length (16 or 32)
 * @param iv Initialization vector (12 bytes recommended)
 * @param iv_len IV length
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len AAD length (0 if no AAD)
 * @param ciphertext Ciphertext to decrypt
 * @param ciphertext_len Ciphertext length
 * @param plaintext Output plaintext buffer
 * @param tag Authentication tag to verify (16 bytes)
 * @return true if authentication succeeded, false otherwise
 *
 * @note If returns false, plaintext is INVALID and must be discarded!
 */
bool gcm_decrypt_oneshot(const uint8_t* key, size_t key_len,
                         const uint8_t* iv, size_t iv_len,
                         const uint8_t* aad, size_t aad_len,
                         const uint8_t* ciphertext, size_t ciphertext_len,
                         uint8_t* plaintext, const uint8_t* tag);

/*=============================================================================
 * GHASH Primitive (Internal, exposed for testing)
 *===========================================================================*/

/**
 * @brief GHASH function: multiply in GF(2^128)
 *
 * GHASH(H, X) = X_1 * H^m ⊕ X_2 * H^(m-1) ⊕ ... ⊕ X_m * H
 *
 * @param output Output hash (16 bytes)
 * @param H Hash subkey (16 bytes)
 * @param input Input data
 * @param len Input length (must be multiple of 16)
 */
void ghash(uint8_t* output, const uint8_t* H, const uint8_t* input, size_t len);

/**
 * @brief GF(2^128) multiplication (for GHASH)
 *
 * @param result Output (16 bytes)
 * @param x First operand (16 bytes)
 * @param y Second operand (16 bytes)
 */
void gf128_mul(uint8_t* result, const uint8_t* x, const uint8_t* y);

/*=============================================================================
 * Test Vectors (NIST SP 800-38D)
 *===========================================================================*/

/**
 * @brief Run AES-GCM test vectors
 *
 * SECURITY: Only available in development builds (-DTINYOS_DEV)
 * Production builds MUST NOT include test code with known key/IV patterns.
 * For production deployment, remove -DTINYOS_DEV from Makefile CFLAGS.
 *
 * @return true if all tests pass, false otherwise
 */
#ifdef TINYOS_DEV
bool gcm_run_tests(void);
#endif
