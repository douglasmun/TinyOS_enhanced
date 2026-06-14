/*=============================================================================
 * ecdhe.h - Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)
 *=============================================================================
 *
 * ECDHE provides Perfect Forward Secrecy for key exchange in TLS 1.3.
 *
 * Key Exchange Protocol:
 * 1. Alice generates ephemeral key pair (a, A = a*G)
 * 2. Bob generates ephemeral key pair (b, B = b*G)
 * 3. Alice sends A to Bob, Bob sends B to Alice
 * 4. Alice computes shared secret: S = a*B = (a*b)*G
 * 5. Bob computes shared secret: S = b*A = (a*b)*G
 * 6. Both derive symmetric keys from S using HKDF
 * 7. Ephemeral keys (a, b) are destroyed immediately
 *
 * Security Properties:
 * - Perfect Forward Secrecy (PFS): Compromise of long-term keys doesn't
 *   reveal past session keys
 * - Ephemeral keys ensure each session has unique encryption keys
 * - Based on ECDLP (Elliptic Curve Discrete Logarithm Problem)
 *
 * Curve: NIST P-256 (secp256r1)
 *
 * Standards:
 * - RFC 4492 (ECC for TLS)
 * - RFC 8446 (TLS 1.3) - Section 4.2.8
 * - NIST SP 800-56A (Key Agreement Using Elliptic Curves)
 *
 * Version: 1.0
 * Date: 2025-01-14
 *===========================================================================*/
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "ecdsa.h"  /* For p256_* types and operations */

/*=============================================================================
 * Data Structures
 *===========================================================================*/

/**
 * @brief ECDHE key pair (ephemeral)
 */
typedef struct {
    p256_int_t private_key;     /* Ephemeral private key (scalar a) */
    p256_point_t public_key;    /* Ephemeral public key (point A = a*G) */
} ecdhe_keypair_t;

/*=============================================================================
 * ECDHE Key Exchange Functions
 *===========================================================================*/

/**
 * @brief Generate ephemeral ECDHE key pair
 *
 * Generates a random private key and derives the public key.
 *
 * @param keypair Output key pair structure
 *
 * @note Private key must be destroyed after deriving shared secret!
 */
void ecdhe_generate_keypair(ecdhe_keypair_t* keypair);

/**
 * @brief Derive shared secret from private key and peer's public key
 *
 * Computes the shared secret point: S = private_key * peer_public_key
 *
 * @param shared_secret Output shared secret (x-coordinate only, 32 bytes)
 * @param private_key Our ephemeral private key
 * @param peer_public_key Peer's ephemeral public key
 * @return 0 on success, -1 if peer's public key is invalid
 *
 * Security:
 * - Validates that peer_public_key is on the curve
 * - Validates that peer_public_key is not point at infinity
 * - Uses only x-coordinate of shared point (per TLS 1.3 spec)
 * - Caller must zeroize shared_secret after deriving session keys
 */
int ecdhe_derive_shared_secret(uint8_t* shared_secret,
                                const p256_int_t* private_key,
                                const p256_point_t* peer_public_key);

/**
 * @brief Destroy ephemeral key pair (zeroize)
 *
 * Securely wipes the private key to prevent leakage.
 * Always call this after deriving the shared secret!
 *
 * @param keypair Key pair to destroy
 */
void ecdhe_destroy_keypair(ecdhe_keypair_t* keypair);

/*=============================================================================
 * Public Key Serialization
 *===========================================================================*/

/**
 * @brief Export public key in TLS 1.3 format
 *
 * TLS 1.3 uses uncompressed point encoding:
 * - 1 byte: 0x04 (uncompressed format marker)
 * - 32 bytes: x-coordinate (big-endian)
 * - 32 bytes: y-coordinate (big-endian)
 * Total: 65 bytes
 *
 * @param output Output buffer (65 bytes)
 * @param public_key Public key to export
 */
void ecdhe_export_public_key_tls(uint8_t* output, const p256_point_t* public_key);

/**
 * @brief Import public key from TLS 1.3 format
 *
 * @param public_key Output public key structure
 * @param input Input buffer (65 bytes: 0x04 + x + y)
 * @return 0 on success, -1 if invalid format or point not on curve
 */
/* SECURITY FIX: Added input_len parameter to prevent out-of-bounds reads */
int ecdhe_import_public_key_tls(p256_point_t* public_key, const uint8_t* input, size_t input_len);

/*=============================================================================
 * Test Vectors
 *===========================================================================*/

/**
 * @brief Run ECDHE test vectors
 *
 * Tests key generation and shared secret derivation using known values.
 *
 * @return true if all tests pass, false otherwise
 */
bool ecdhe_run_tests(void);
