/*=============================================================================
 * ecdhe.c - Elliptic Curve Diffie-Hellman Ephemeral Implementation
 *===========================================================================*/
#include "ecdhe.h"
#include "crypto.h"
#include "kprintf.h"
#include "util.h"  /* For memcpy, memset */

/*=============================================================================
 * Generate Ephemeral Key Pair
 *===========================================================================*/
void ecdhe_generate_keypair(ecdhe_keypair_t* keypair) {
    /* Generate random private key (0 < d < n) */
    do {
        csprng_random_bytes(&global_csprng, (uint8_t*)&keypair->private_key, 32);
    } while (p256_int_is_zero(&keypair->private_key) ||
             p256_int_cmp(&keypair->private_key, &p256_n) >= 0);

    /* Derive public key: Q = d * G */
    ecdsa_derive_public_key(&keypair->public_key, &keypair->private_key);
}

/*=============================================================================
 * Derive Shared Secret
 *===========================================================================*/
int ecdhe_derive_shared_secret(uint8_t* shared_secret,
                                const p256_int_t* private_key,
                                const p256_point_t* peer_public_key) {
    p256_point_t shared_point;

    /* Validate peer's public key */
    if (p256_point_is_infinity(peer_public_key)) {
        kprintf("[ECDHE] ERROR: Peer public key is point at infinity\n");
        return -1;
    }

    if (!p256_point_on_curve(peer_public_key)) {
        kprintf("[ECDHE] ERROR: Peer public key not on curve\n");
        return -1;
    }

    /* Compute shared point: S = private_key * peer_public_key */
    p256_point_mul(&shared_point, private_key, peer_public_key);

    /* Check for point at infinity (should never happen with valid inputs) */
    if (p256_point_is_infinity(&shared_point)) {
        kprintf("[ECDHE] ERROR: Shared secret is point at infinity\n");
        return -1;
    }

    /* Extract x-coordinate as shared secret (per TLS 1.3 spec) */
    p256_int_to_bytes(&shared_point.x, shared_secret);

    /* Zeroize shared point */
    crypto_secure_zero(&shared_point, sizeof(shared_point));

    return 0;
}

/*=============================================================================
 * Destroy Key Pair (Secure Zeroization)
 *===========================================================================*/
void ecdhe_destroy_keypair(ecdhe_keypair_t* keypair) {
    crypto_secure_zero(keypair, sizeof(ecdhe_keypair_t));
}

/*=============================================================================
 * Export Public Key (TLS 1.3 Format)
 *===========================================================================*/
void ecdhe_export_public_key_tls(uint8_t* output, const p256_point_t* public_key) {
    /* Uncompressed point format: 0x04 || x || y */
    output[0] = 0x04;
    p256_int_to_bytes(&public_key->x, output + 1);
    p256_int_to_bytes(&public_key->y, output + 33);
}

/*=============================================================================
 * Import Public Key (TLS 1.3 Format)
 *===========================================================================*/
int ecdhe_import_public_key_tls(p256_point_t* public_key, const uint8_t* input, size_t input_len) {
    /* SECURITY FIX: Validate input buffer length before accessing
     * P-256 uncompressed public key format: 1 byte (0x04) + 32 bytes X + 32 bytes Y = 65 bytes
     * Without this check, a malicious or truncated input could cause out-of-bounds reads
     * when unpacking coordinates at input+1 and input+33. In a privileged context
     * (SSH server, TLS handshake), this could leak sensitive kernel memory or crash. */
    if (input_len < 65) {
        kprintf("[ECDHE] ERROR: Input buffer too short (%zu bytes, need 65)\n", input_len);
        return -1;
    }

    /* Check format marker */
    if (input[0] != 0x04) {
        kprintf("[ECDHE] ERROR: Invalid public key format (expected 0x04, got 0x%02X)\n", input[0]);
        return -1;
    }

    /* Import coordinates - now safe because we validated input_len >= 65 */
    p256_int_from_bytes(&public_key->x, input + 1);
    p256_int_from_bytes(&public_key->y, input + 33);
    public_key->is_infinity = false;

    /* Validate point is on curve */
    if (!p256_point_on_curve(public_key)) {
        kprintf("[ECDHE] ERROR: Imported public key not on curve\n");
        return -1;
    }

    return 0;
}

/*=============================================================================
 * Test Vectors
 *===========================================================================*/
bool ecdhe_run_tests(void) {
    ecdhe_keypair_t alice, bob;
    uint8_t alice_secret[32], bob_secret[32];
    bool test_passed = true;

    kprintf("[ECDHE] Running test vectors...\n");

    /* Test 1: Generate key pairs */
    ecdhe_generate_keypair(&alice);
    ecdhe_generate_keypair(&bob);

    /* Test 2: Derive shared secrets */
    if (ecdhe_derive_shared_secret(alice_secret, &alice.private_key, &bob.public_key) != 0) {
        kprintf("[ECDHE] FAIL: Alice failed to derive shared secret\n");
        test_passed = false;
    }

    if (ecdhe_derive_shared_secret(bob_secret, &bob.private_key, &alice.public_key) != 0) {
        kprintf("[ECDHE] FAIL: Bob failed to derive shared secret\n");
        test_passed = false;
    }

    /* Test 3: Verify both parties computed same shared secret */
    if (memcmp(alice_secret, bob_secret, 32) != 0) {
        kprintf("[ECDHE] FAIL: Shared secrets don't match!\n");
        test_passed = false;
    } else {
        kprintf("[ECDHE] PASS: Shared secrets match\n");
    }

    /* Test 4: Test TLS serialization round-trip */
    uint8_t serialized[65];
    p256_point_t imported;

    ecdhe_export_public_key_tls(serialized, &alice.public_key);
    if (ecdhe_import_public_key_tls(&imported, serialized, 65) != 0) {
        kprintf("[ECDHE] FAIL: Public key serialization round-trip failed\n");
        test_passed = false;
    } else if (p256_int_cmp(&imported.x, &alice.public_key.x) != 0 ||
               p256_int_cmp(&imported.y, &alice.public_key.y) != 0) {
        kprintf("[ECDHE] FAIL: Public key doesn't match after round-trip\n");
        test_passed = false;
    } else {
        kprintf("[ECDHE] PASS: Public key serialization round-trip successful\n");
    }

    /* Test 5: Reject invalid public key (point not on curve) */
    p256_point_t invalid_point;
    p256_int_zero(&invalid_point.x);
    p256_int_zero(&invalid_point.y);
    invalid_point.is_infinity = false;

    ecdhe_export_public_key_tls(serialized, &invalid_point);
    if (ecdhe_import_public_key_tls(&imported, serialized, 65) == 0) {
        kprintf("[ECDHE] FAIL: Accepted invalid public key (not on curve)\n");
        test_passed = false;
    } else {
        kprintf("[ECDHE] PASS: Rejected invalid public key\n");
    }

    /* Cleanup */
    ecdhe_destroy_keypair(&alice);
    ecdhe_destroy_keypair(&bob);
    crypto_secure_zero(alice_secret, 32);
    crypto_secure_zero(bob_secret, 32);

    if (test_passed) {
        kprintf("[ECDHE] All tests PASSED\n");
    } else {
        kprintf("[ECDHE] Some tests FAILED\n");
    }

    return test_passed;
}
