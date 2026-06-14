/*
 * TinyOS ECDSA P-256 Implementation
 * Version: 1.0
 * Date: 2025-01-14
 *
 * Elliptic Curve Digital Signature Algorithm (ECDSA)
 * Curve: NIST P-256 (secp256r1)
 *
 * This implementation provides:
 * - ECDSA signature generation (sign)
 * - ECDSA signature verification (verify)
 * - P-256 elliptic curve point operations
 * - Key pair generation
 *
 * Standards:
 * - FIPS 186-4 (Digital Signature Standard)
 * - SEC 2 (Recommended Elliptic Curve Domain Parameters)
 * - RFC 6979 (Deterministic ECDSA, optional)
 *
 * Security:
 * - 256-bit security level (equivalent to AES-256)
 * - Resistant to timing attacks (constant-time where possible)
 * - Side-channel resistant scalar multiplication
 */

#ifndef ECDSA_H
#define ECDSA_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * ============================================================================
 * P-256 Curve Parameters (NIST secp256r1)
 * ============================================================================
 *
 * The curve equation is: y² = x³ + ax + b (mod p)
 *
 * p = 2^256 - 2^224 + 2^192 + 2^96 - 1 (prime modulus)
 * a = -3 (mod p)
 * b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
 * G = Generator point (base point)
 * n = Order of G (number of points in subgroup)
 * h = Cofactor = 1
 */

#define P256_BYTES      32      /* 256 bits = 32 bytes */
#define P256_WORDS      8       /* 256 bits = 8 x 32-bit words */

/*
 * ============================================================================
 * Data Structures
 * ============================================================================
 */

/* 256-bit big integer (little-endian) */
typedef struct {
    uint32_t d[P256_WORDS];     /* 8 x 32-bit words */
} p256_int_t;

/* Point on elliptic curve (affine coordinates) */
typedef struct {
    p256_int_t x;
    p256_int_t y;
    bool is_infinity;           /* Point at infinity (identity element) */
} p256_point_t;

/* Point on elliptic curve (Jacobian coordinates - for faster computation) */
typedef struct {
    p256_int_t X;
    p256_int_t Y;
    p256_int_t Z;
} p256_jacobian_t;

/* ECDSA key pair */
typedef struct {
    p256_int_t private_key;     /* Private key (scalar, 0 < d < n) */
    p256_point_t public_key;    /* Public key (point Q = d * G) */
} ecdsa_keypair_t;

/* ECDSA signature (r, s) */
typedef struct {
    p256_int_t r;
    p256_int_t s;
} ecdsa_signature_t;

/*
 * ============================================================================
 * P-256 Curve Constants
 * ============================================================================
 */

/* Prime modulus p */
extern const p256_int_t p256_p;

/* Curve parameter a = -3 (mod p) */
extern const p256_int_t p256_a;

/* Curve parameter b */
extern const p256_int_t p256_b;

/* Generator point G */
extern const p256_point_t p256_G;

/* Order of generator (subgroup order) */
extern const p256_int_t p256_n;

/*
 * ============================================================================
 * Big Integer Arithmetic (mod p or mod n)
 * ============================================================================
 */

/* Initialize to zero */
void p256_int_zero(p256_int_t* a);

/* Initialize from bytes (big-endian) */
void p256_int_from_bytes(p256_int_t* a, const uint8_t* bytes);

/* Convert to bytes (big-endian) */
void p256_int_to_bytes(const p256_int_t* a, uint8_t* bytes);

/* Compare: returns -1 if a < b, 0 if a == b, 1 if a > b */
int p256_int_cmp(const p256_int_t* a, const p256_int_t* b);

/* Check if zero */
bool p256_int_is_zero(const p256_int_t* a);

/* Modular addition: c = (a + b) mod m */
void p256_mod_add(p256_int_t* c, const p256_int_t* a, const p256_int_t* b, const p256_int_t* m);

/* Modular subtraction: c = (a - b) mod m */
void p256_mod_sub(p256_int_t* c, const p256_int_t* a, const p256_int_t* b, const p256_int_t* m);

/* Modular multiplication: c = (a * b) mod m */
void p256_mod_mul(p256_int_t* c, const p256_int_t* a, const p256_int_t* b, const p256_int_t* m);

/* Modular inversion: b = a^(-1) mod m (using extended Euclidean algorithm) */
void p256_mod_inv(p256_int_t* b, const p256_int_t* a, const p256_int_t* m);

/*
 * ============================================================================
 * Elliptic Curve Point Operations
 * ============================================================================
 */

/* Initialize point to infinity */
void p256_point_zero(p256_point_t* p);

/* Check if point is at infinity */
bool p256_point_is_infinity(const p256_point_t* p);

/* Check if point is on curve */
bool p256_point_on_curve(const p256_point_t* p);

/* Point addition: R = P + Q */
void p256_point_add(p256_point_t* R, const p256_point_t* P, const p256_point_t* Q);

/* Point doubling: R = 2 * P */
void p256_point_double(p256_point_t* R, const p256_point_t* P);

/* Scalar multiplication: R = k * P (using double-and-add algorithm) */
void p256_point_mul(p256_point_t* R, const p256_int_t* k, const p256_point_t* P);

/* Copy point */
void p256_point_copy(p256_point_t* dst, const p256_point_t* src);

/*
 * ============================================================================
 * ECDSA Key Management
 * ============================================================================
 */

/* Generate random key pair */
void ecdsa_generate_keypair(ecdsa_keypair_t* keypair);

/* Derive public key from private key: Q = d * G */
void ecdsa_derive_public_key(p256_point_t* public_key, const p256_int_t* private_key);

/* Import private key from bytes (32 bytes, big-endian) */
void ecdsa_import_private_key(p256_int_t* private_key, const uint8_t* bytes);

/* Export private key to bytes (32 bytes, big-endian) */
void ecdsa_export_private_key(const p256_int_t* private_key, uint8_t* bytes);

/* Import public key from bytes (64 bytes: 32-byte x + 32-byte y, big-endian) */
void ecdsa_import_public_key(p256_point_t* public_key, const uint8_t* bytes);

/* Export public key to bytes (64 bytes: 32-byte x + 32-byte y, big-endian) */
void ecdsa_export_public_key(const p256_point_t* public_key, uint8_t* bytes);

/*
 * ============================================================================
 * ECDSA Signature Operations
 * ============================================================================
 */

/**
 * Sign a message hash with ECDSA
 *
 * @param signature Output signature (r, s)
 * @param hash Message hash (32 bytes, e.g., from SHA-256)
 * @param private_key Private key (scalar d)
 *
 * Algorithm:
 * 1. Generate random k (0 < k < n)
 * 2. Compute (x, y) = k * G
 * 3. r = x mod n (if r == 0, retry)
 * 4. s = k^(-1) * (hash + r * d) mod n (if s == 0, retry)
 * 5. Return (r, s)
 */
void ecdsa_sign(ecdsa_signature_t* signature,
                const uint8_t* hash,
                const p256_int_t* private_key);

/**
 * Verify an ECDSA signature
 *
 * @param signature Signature to verify (r, s)
 * @param hash Message hash (32 bytes)
 * @param public_key Public key (point Q)
 * @return true if signature is valid, false otherwise
 *
 * Algorithm:
 * 1. Verify 0 < r < n and 0 < s < n
 * 2. w = s^(-1) mod n
 * 3. u1 = hash * w mod n
 * 4. u2 = r * w mod n
 * 5. (x, y) = u1 * G + u2 * Q
 * 6. Return true if r == x mod n
 */
bool ecdsa_verify(const ecdsa_signature_t* signature,
                  const uint8_t* hash,
                  const p256_point_t* public_key);

/**
 * Import signature from bytes (64 bytes: 32-byte r + 32-byte s, big-endian)
 */
void ecdsa_import_signature(ecdsa_signature_t* signature, const uint8_t* bytes);

/**
 * Export signature to bytes (64 bytes: 32-byte r + 32-byte s, big-endian)
 */
void ecdsa_export_signature(const ecdsa_signature_t* signature, uint8_t* bytes);

/*
 * ============================================================================
 * Utility Functions
 * ============================================================================
 */

/* Initialize ECDSA subsystem (verify curve parameters) */
void ecdsa_init(void);

#endif /* ECDSA_H */
