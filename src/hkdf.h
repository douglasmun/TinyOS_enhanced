/*=============================================================================
 * hkdf.h - HKDF (HMAC-based Key Derivation Function)
 *=============================================================================
 *
 * HKDF is used in TLS 1.3 to derive all session keys from the shared secret.
 *
 * HKDF has two phases:
 * 1. Extract: Extract a fixed-length pseudorandom key (PRK) from input
 *    keying material (IKM) and optional salt:
 *    PRK = HMAC-Hash(salt, IKM)
 *
 * 2. Expand: Expand the PRK into multiple output keying material (OKM)
 *    blocks using optional context information:
 *    OKM = T(1) || T(2) || ... || T(N)
 *    where:
 *      T(0) = empty string
 *      T(i) = HMAC-Hash(PRK, T(i-1) || info || [i])
 *
 * TLS 1.3 Usage:
 * - Derives handshake traffic secrets from ECDHE shared secret
 * - Derives application traffic secrets for record encryption
 * - Derives finished keys for handshake verification
 * - Derives resumption master secret for 0-RTT
 *
 * Standards:
 * - RFC 5869 (HKDF specification)
 * - RFC 8446 (TLS 1.3) - Section 7.1
 * - NIST SP 800-56C (Key Derivation)
 *
 * Hash Functions:
 * - HKDF-SHA-256 (used by TLS 1.3)
 * - HKDF-SHA-512 (for high-security applications)
 *
 * Version: 1.0
 * Date: 2025-01-14
 *===========================================================================*/
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*=============================================================================
 * Constants
 *===========================================================================*/
#define HKDF_SHA256_HASH_LEN    32  /* SHA-256 output size */
#define HKDF_SHA512_HASH_LEN    64  /* SHA-512 output size */

/*=============================================================================
 * SECURITY FIX: HKDF_MAX_INFO_LEN capped at 31 bytes
 * CRITICAL: For SHA-256 HMAC (block size 64 bytes), the input to each HMAC
 * in the expand phase is: T(i-1) || info || counter
 * - T(i-1) = 32 bytes (previous hash output)
 * - counter = 1 byte
 * - info = variable length
 *
 * To guarantee single-block HMAC processing (optimal performance and minimal
 * stack usage): 32 + info_len + 1 ≤ 64 bytes
 * Therefore: info_len ≤ 31 bytes
 *
 * This is sufficient for all TLS 1.3 labels (longest is "c hs traffic" = 13 bytes)
 * and SSH key derivation (typically 1 byte).
 *
 * Previous value of 256 caused:
 * - Wasteful stack allocation: 289 bytes vs 64 bytes
 * - Multi-block HMAC processing (unnecessary overhead)
 *===========================================================================*/
#define HKDF_MAX_INFO_LEN       31  /* Maximum info length (ensures single-block HMAC) */
#define HKDF_MAX_OUTPUT_LEN     8160 /* Maximum OKM length (255 * 32 for SHA-256) */

/*=============================================================================
 * HKDF-SHA256 (for TLS 1.3)
 *===========================================================================*/

/**
 * @brief HKDF-Extract (SHA-256)
 *
 * Extract a pseudorandom key from input keying material.
 *
 * @param prk Output pseudorandom key (32 bytes)
 * @param salt Optional salt value (can be NULL)
 * @param salt_len Length of salt (0 if NULL)
 * @param ikm Input keying material (e.g., ECDHE shared secret)
 * @param ikm_len Length of IKM
 *
 * Notes:
 * - If salt is NULL, a string of HashLen zeros is used
 * - PRK length is always 32 bytes for SHA-256
 */
void hkdf_sha256_extract(uint8_t* prk,
                         const uint8_t* salt, size_t salt_len,
                         const uint8_t* ikm, size_t ikm_len);

/**
 * @brief HKDF-Expand (SHA-256)
 *
 * Expand a pseudorandom key into output keying material.
 *
 * @param okm Output keying material buffer
 * @param okm_len Desired length of OKM (max 8160 bytes = 255 * 32)
 * @param prk Pseudorandom key from HKDF-Extract (32 bytes)
 * @param info Optional context/application specific info (can be NULL)
 * @param info_len Length of info (0 if NULL)
 * @return 0 on success, -1 if okm_len too large
 *
 * Notes:
 * - Maximum okm_len is 255 * HashLen = 8160 bytes for SHA-256
 * - TLS 1.3 typically uses okm_len of 32-48 bytes
 */
int hkdf_sha256_expand(uint8_t* okm, size_t okm_len,
                       const uint8_t* prk,
                       const uint8_t* info, size_t info_len);

/**
 * @brief HKDF (SHA-256) - Combined Extract-and-Expand
 *
 * Convenience function that performs both Extract and Expand.
 *
 * @param okm Output keying material buffer
 * @param okm_len Desired length of OKM
 * @param salt Optional salt (can be NULL)
 * @param salt_len Length of salt
 * @param ikm Input keying material
 * @param ikm_len Length of IKM
 * @param info Optional context info (can be NULL)
 * @param info_len Length of info
 * @return 0 on success, -1 on error
 */
int hkdf_sha256(uint8_t* okm, size_t okm_len,
                const uint8_t* salt, size_t salt_len,
                const uint8_t* ikm, size_t ikm_len,
                const uint8_t* info, size_t info_len);

/*=============================================================================
 * HKDF-SHA512 (for high-security applications)
 *===========================================================================*/

/**
 * @brief HKDF-Extract (SHA-512)
 *
 * @param prk Output pseudorandom key (64 bytes)
 * @param salt Optional salt value (can be NULL)
 * @param salt_len Length of salt
 * @param ikm Input keying material
 * @param ikm_len Length of IKM
 */
void hkdf_sha512_extract(uint8_t* prk,
                         const uint8_t* salt, size_t salt_len,
                         const uint8_t* ikm, size_t ikm_len);

/**
 * @brief HKDF-Expand (SHA-512)
 *
 * @param okm Output keying material buffer
 * @param okm_len Desired length of OKM (max 16320 bytes = 255 * 64)
 * @param prk Pseudorandom key from HKDF-Extract (64 bytes)
 * @param info Optional context info (can be NULL)
 * @param info_len Length of info
 * @return 0 on success, -1 if okm_len too large
 */
int hkdf_sha512_expand(uint8_t* okm, size_t okm_len,
                       const uint8_t* prk,
                       const uint8_t* info, size_t info_len);

/**
 * @brief HKDF (SHA-512) - Combined Extract-and-Expand
 *
 * @param okm Output keying material buffer
 * @param okm_len Desired length of OKM
 * @param salt Optional salt (can be NULL)
 * @param salt_len Length of salt
 * @param ikm Input keying material
 * @param ikm_len Length of IKM
 * @param info Optional context info (can be NULL)
 * @param info_len Length of info
 * @return 0 on success, -1 on error
 */
int hkdf_sha512(uint8_t* okm, size_t okm_len,
                const uint8_t* salt, size_t salt_len,
                const uint8_t* ikm, size_t ikm_len,
                const uint8_t* info, size_t info_len);

/*=============================================================================
 * TLS 1.3 Convenience Functions
 *===========================================================================*/

/**
 * @brief Derive TLS 1.3 key from shared secret
 *
 * TLS 1.3 key schedule uses HKDF-Expand-Label which is HKDF-Expand
 * with a specific label format:
 *
 * HKDF-Expand-Label(Secret, Label, Context, Length) =
 *   HKDF-Expand(Secret, HkdfLabel, Length)
 *
 * where HkdfLabel is:
 *   struct {
 *     uint16 length = Length;
 *     opaque label<7..255> = "tls13 " + Label;
 *     opaque context<0..255> = Context;
 *   } HkdfLabel;
 *
 * @param output Derived key output
 * @param output_len Desired key length
 * @param secret Input secret (PRK from HKDF-Extract)
 * @param label TLS 1.3 label string (without "tls13 " prefix)
 * @param context Optional context data (can be NULL)
 * @param context_len Length of context
 * @return 0 on success, -1 on error
 */
int hkdf_expand_label(uint8_t* output, size_t output_len,
                      const uint8_t* secret,
                      const char* label,
                      const uint8_t* context, size_t context_len);

/*=============================================================================
 * Test Vectors
 *===========================================================================*/

/**
 * @brief Run HKDF test vectors (RFC 5869)
 *
 * @return true if all tests pass, false otherwise
 */
bool hkdf_run_tests(void);
