/*
 * TinyOS Cryptographic Infrastructure
 * Version: 1.0
 * Date: 2025-01-14
 *
 * This module provides production-grade cryptographic primitives:
 * - AES-256 (encryption/decryption)
 * - HMAC-SHA512 (message authentication)
 * - CSPRNG (cryptographically secure random number generator)
 * - PBKDF2 (password-based key derivation)
 *
 * Design Principles:
 * - Constant-time operations (prevent timing attacks)
 * - Secure zeroization (prevent key leakage)
 * - NIST-compliant algorithms
 * - Small footprint (<10 KiB)
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "sha512.h"  /* For SHA-512 context in HMAC */

/*
 * ============================================================================
 * AES-256 (Advanced Encryption Standard)
 * ============================================================================
 * Block cipher with 256-bit keys
 * Block size: 128 bits (16 bytes)
 * Key size: 256 bits (32 bytes)
 * Rounds: 14
 *
 * Modes supported:
 * - ECB (Electronic Codebook) - for testing only, NOT for production
 * - CBC (Cipher Block Chaining) - requires IV
 * - CTR (Counter Mode) - converts block cipher to stream cipher
 */

#define AES_BLOCK_SIZE      16      /* 128 bits */
#define AES_KEY_SIZE        32      /* 256 bits */
#define AES_ROUNDS          14      /* For AES-256 */

/* SECURITY FIX (AUDIT 11C): Added alignment for portability */
typedef struct {
    uint32_t round_keys[4 * (AES_ROUNDS + 1)];  /* Expanded key schedule */
    uint8_t iv[AES_BLOCK_SIZE];                  /* Initialization vector */
    uint32_t num_rounds;                         /* 14 for AES-256 */
} __attribute__((aligned(4))) aes_ctx_t;

/* Initialize AES context with key and IV */
void aes_init(aes_ctx_t* ctx, const uint8_t* key, const uint8_t* iv);

/* Encrypt single block (16 bytes) - ECB mode */
void aes_encrypt_block(aes_ctx_t* ctx, const uint8_t* plaintext, uint8_t* ciphertext);

/* Decrypt single block (16 bytes) - ECB mode */
void aes_decrypt_block(aes_ctx_t* ctx, const uint8_t* ciphertext, uint8_t* plaintext);

/* Encrypt data - CBC mode (requires IV in ctx) */
void aes_cbc_encrypt(aes_ctx_t* ctx, const uint8_t* plaintext, uint8_t* ciphertext, size_t len);

/* Decrypt data - CBC mode (requires IV in ctx) */
void aes_cbc_decrypt(aes_ctx_t* ctx, const uint8_t* ciphertext, uint8_t* plaintext, size_t len);

/* Encrypt data - CTR mode (stream cipher) */
void aes_ctr_encrypt(aes_ctx_t* ctx, const uint8_t* plaintext, uint8_t* ciphertext, size_t len);

/* CTR mode decryption (same as encryption for CTR) */
#define aes_ctr_decrypt aes_ctr_encrypt

/* Zeroize AES context (security cleanup) */
void aes_destroy(aes_ctx_t* ctx);

/*
 * ============================================================================
 * HMAC-SHA512 (Hash-based Message Authentication Code)
 * ============================================================================
 * Provides message authentication and integrity
 * Key size: arbitrary (recommended: 64 bytes)
 * Output size: 64 bytes (512 bits)
 *
 * Use cases:
 * - Verify message hasn't been tampered
 * - Authenticate API requests
 * - Derive session keys
 */

#define HMAC_KEY_SIZE       64      /* Recommended key size */
#define HMAC_OUTPUT_SIZE    64      /* 512 bits */
#define HMAC_BLOCK_SIZE     128     /* SHA-512 block size */

typedef struct {
    uint8_t key[HMAC_BLOCK_SIZE];
    sha512_ctx_t hash_ctx;
} hmac_ctx_t;

/* Initialize HMAC context with key */
void hmac_init(hmac_ctx_t* ctx, const uint8_t* key, size_t key_len);

/* Update HMAC with data */
void hmac_update(hmac_ctx_t* ctx, const uint8_t* data, size_t len);

/* Finalize HMAC and output MAC */
void hmac_final(hmac_ctx_t* ctx, uint8_t* mac);

/* One-shot HMAC computation */
void hmac_sha512(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t* mac);

/* Constant-time MAC comparison (prevent timing attacks) */
bool hmac_verify(const uint8_t* mac1, const uint8_t* mac2, size_t len);

/* Zeroize HMAC context */
void hmac_destroy(hmac_ctx_t* ctx);

/*
 * ============================================================================
 * CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
 * ============================================================================
 * Based on ChaCha20 stream cipher (modern, secure, fast)
 *
 * Seeding sources:
 * 1. Hardware RNG (RDRAND if available)
 * 2. PIT timer entropy
 * 3. Keyboard timing
 * 4. Network packet timing
 * 5. Memory access patterns
 *
 * Security properties:
 * - Backtracking resistance (compromised state doesn't reveal past output)
 * - Prediction resistance (compromised state doesn't reveal future output)
 * - Forward secrecy (periodic reseeding)
 */

#define CSPRNG_SEED_SIZE    32      /* 256 bits */
#define CSPRNG_RESEED_COUNT 1048576 /* Reseed every 1M bytes */

typedef struct {
    uint32_t state[16];             /* ChaCha20 state */
    uint64_t counter;               /* Block counter */
    uint32_t bytes_generated;       /* For periodic reseeding */
    bool initialized;
} csprng_ctx_t;

/* Initialize CSPRNG with seed */
void csprng_init(csprng_ctx_t* ctx, const uint8_t* seed);

/* Generate random bytes */
void csprng_random_bytes(csprng_ctx_t* ctx, uint8_t* output, size_t len);

/* Generate random uint32_t */
uint32_t csprng_random_u32(csprng_ctx_t* ctx);

/* Generate random uint64_t */
uint64_t csprng_random_u64(csprng_ctx_t* ctx);

/* Reseed CSPRNG (periodic or on demand) */
void csprng_reseed(csprng_ctx_t* ctx, const uint8_t* entropy, size_t len);

/* Periodic reseed for global CSPRNG (call from kernel timer/main loop) */
void csprng_periodic_reseed(void);

/* Zeroize CSPRNG context */
void csprng_destroy(csprng_ctx_t* ctx);

/* Global CSPRNG instance (initialized at boot) */
extern csprng_ctx_t global_csprng;

/*
 * ============================================================================
 * PBKDF2 (Password-Based Key Derivation Function 2)
 * ============================================================================
 * Derives cryptographic keys from passwords
 * Uses HMAC-SHA512 as PRF
 *
 * Parameters:
 * - password: User password
 * - salt: Random salt (prevents rainbow tables)
 * - iterations: Number of iterations (10,000+ recommended)
 * - key_len: Desired key length
 */

#define PBKDF2_MIN_ITERATIONS   10000   /* Minimum for security */
#define PBKDF2_SALT_SIZE        16      /* Recommended salt size */

/* Derive key from password using PBKDF2-HMAC-SHA512 */
void pbkdf2_hmac_sha512(const uint8_t* password, size_t password_len,
                        const uint8_t* salt, size_t salt_len,
                        uint32_t iterations,
                        uint8_t* derived_key, size_t key_len);

/*
 * ============================================================================
 * Utility Functions
 * ============================================================================
 */

/* Secure memory zeroization (compiler won't optimize away) */
void crypto_secure_zero(void* ptr, size_t len);

/* Constant-time memory comparison (prevent timing attacks) */
bool crypto_constant_time_compare(const void* a, const void* b, size_t len);

/* Entropy collection from various sources.
 * Returns false if collected entropy fails quality validation (output is
 * left unfilled); caller decides whether to panic (boot) or skip (reseed). */
bool crypto_collect_entropy(uint8_t* output, size_t len);

/*
 * ============================================================================
 * Initialization
 * ============================================================================
 */

/* Initialize cryptographic subsystem (call once at boot) */
void crypto_init(void);

#endif /* CRYPTO_H */
