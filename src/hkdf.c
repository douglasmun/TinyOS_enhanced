/*=============================================================================
 * hkdf.c - HKDF (HMAC-based Key Derivation Function) Implementation
 *===========================================================================*/
#include "hkdf.h"
#include "crypto.h"
#include "sha256.h"  /* Real SHA-256 implementation */
#include "sha512.h"
#include "kprintf.h"
#include "util.h"  /* For memcpy, memset */

/*=============================================================================
 * Helper: Safe memcpy (avoids __memcpy_chk)
 * SECURITY: Constant-Time Memory Copy
 *
 * This function is used to copy cryptographic material (keys, HMAC values)
 * and must avoid timing side-channels. We use:
 *
 * 1. volatile pointers: Prevent compiler from optimizing based on data values
 * 2. __attribute__((noinline)): Prevent inlining that could expose timing
 * 3. Memory barrier: Prevent reordering across the copy operation
 *
 * This ensures the loop executes in constant time regardless of data content,
 * preventing cache-timing attacks that could leak secret key material.
 *===========================================================================*/
static void safe_copy(void* dest, const void* src, size_t n)
    __attribute__((noinline));

static void safe_copy(void* dest, const void* src, size_t n) {
    volatile uint8_t* d = (volatile uint8_t*)dest;
    const volatile uint8_t* s = (const volatile uint8_t*)src;

    /* Byte-by-byte copy with volatile to prevent optimization */
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }

    /* Memory barrier: prevent compiler from reordering operations */
    __asm__ volatile("" ::: "memory");
}

/*=============================================================================
 * HMAC-SHA256 Implementation (RFC 2104)
 *
 * CRITICAL FIX: Now uses REAL SHA-256 from sha256.c instead of truncated
 * SHA-512. The previous implementation was non-standard and incompatible
 * with SSH and other protocols.
 *===========================================================================*/
static void hmac_sha256(const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len,
                        uint8_t* mac) {
    uint8_t key_pad[64];
    uint8_t ipad[64], opad[64];
    uint8_t inner_hash[32];

    /* Prepare key: if longer than 64 bytes, hash it first */
    if (key_len > 64) {
        sha256(key, key_len, key_pad);
        memset(key_pad + 32, 0, 32);
    } else {
        memcpy(key_pad, key, key_len);
        memset(key_pad + key_len, 0, 64 - key_len);
    }

    /* Create ipad and opad */
    for (int i = 0; i < 64; i++) {
        ipad[i] = key_pad[i] ^ 0x36;
        opad[i] = key_pad[i] ^ 0x5C;
    }

    /* Inner hash: H(K XOR ipad || message) */
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner_hash);

    /* Outer hash: H(K XOR opad || inner_hash) */
    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, inner_hash, 32);
    sha256_final(&ctx, mac);

    /*=========================================================================
     * SECURITY FIX: Zeroize All Cryptographic Material
     * CRITICAL: Side-channel/key leakage prevention
     *
     * Temporary cryptographic material on the stack can be exploited by an
     * attacker reading memory of later-allocated buffers. Must zeroize ALL
     * buffers containing key material before function returns.
     *
     * Added: inner_hash (previously missing)
     *=========================================================================*/
    crypto_secure_zero(key_pad, sizeof(key_pad));
    crypto_secure_zero(ipad, sizeof(ipad));
    crypto_secure_zero(opad, sizeof(opad));
    crypto_secure_zero(inner_hash, sizeof(inner_hash));
}

/*=============================================================================
 * HKDF-SHA256 Extract
 *===========================================================================*/
void hkdf_sha256_extract(uint8_t* prk,
                         const uint8_t* salt, size_t salt_len,
                         const uint8_t* ikm, size_t ikm_len) {
    uint8_t default_salt[32];

    /* If no salt provided, use zeros */
    if (salt == NULL || salt_len == 0) {
        memset(default_salt, 0, 32);
        salt = default_salt;
        salt_len = 32;
    }

    /* PRK = HMAC-Hash(salt, IKM) */
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

/*=============================================================================
 * HKDF-SHA256 Expand
 *===========================================================================*/
int hkdf_sha256_expand(uint8_t* okm, size_t okm_len,
                       const uint8_t* prk,
                       const uint8_t* info, size_t info_len) {
    uint8_t T[32]; /* Previous T value */
    uint8_t T_len = 0;
    uint8_t counter = 1;
    size_t offset = 0;

    /* Check maximum output length: 255 * HashLen */
    if (okm_len > 255 * 32) {
        return -1;
    }

    if (info == NULL) {
        info_len = 0;
    }

    /* SECURITY FIX: Reject info_len beyond supported maximum to prevent buffer overflow
     * The input buffer is sized as 32 + HKDF_MAX_INFO_LEN + 1, so info_len must not exceed
     * HKDF_MAX_INFO_LEN to prevent writing past the buffer bounds */
    if (info_len > HKDF_MAX_INFO_LEN) {
        return -1;
    }

    /* Generate output blocks */
    while (offset < okm_len) {
        /* Build input: T(i-1) || info || counter */
        uint8_t input[32 + HKDF_MAX_INFO_LEN + 1];
        size_t input_len = 0;

        /* Add previous T (except for first iteration) */
        if (T_len > 0) {
            safe_copy(input + input_len, T, T_len);
            input_len += T_len;
        }

        /* Add info */
        if (info_len > 0) {
            safe_copy(input + input_len, info, info_len);
            input_len += info_len;
        }

        /* Add counter */
        input[input_len] = counter;
        input_len++;

        /* T(i) = HMAC-Hash(PRK, T(i-1) || info || counter) */
        hmac_sha256(prk, 32, input, input_len, T);
        T_len = 32;

        /* Copy to output */
        size_t to_copy = (okm_len - offset < 32) ? (okm_len - offset) : 32;
        memcpy(okm + offset, T, to_copy);
        offset += to_copy;

        counter++;

        /*=====================================================================
         * SECURITY FIX: Zeroize input buffer after each iteration
         * CRITICAL: The input buffer contains previous T value and info which
         * are cryptographic material. Must be zeroized to prevent key leakage.
         *===================================================================*/
        crypto_secure_zero(input, sizeof(input));
    }

    /* Zeroize sensitive data */
    crypto_secure_zero(T, sizeof(T));

    return 0;
}

/*=============================================================================
 * HKDF-SHA256 Combined
 *===========================================================================*/
int hkdf_sha256(uint8_t* okm, size_t okm_len,
                const uint8_t* salt, size_t salt_len,
                const uint8_t* ikm, size_t ikm_len,
                const uint8_t* info, size_t info_len) {
    uint8_t prk[32];

    /* Extract */
    hkdf_sha256_extract(prk, salt, salt_len, ikm, ikm_len);

    /* Expand */
    int result = hkdf_sha256_expand(okm, okm_len, prk, info, info_len);

    /* Zeroize PRK */
    crypto_secure_zero(prk, sizeof(prk));

    return result;
}

/*=============================================================================
 * HKDF-SHA512 Extract
 *===========================================================================*/
void hkdf_sha512_extract(uint8_t* prk,
                         const uint8_t* salt, size_t salt_len,
                         const uint8_t* ikm, size_t ikm_len) {
    uint8_t default_salt[64];

    /* If no salt provided, use zeros */
    if (salt == NULL || salt_len == 0) {
        memset(default_salt, 0, 64);
        salt = default_salt;
        salt_len = 64;
    }

    /* PRK = HMAC-Hash(salt, IKM) */
    hmac_sha512(salt, salt_len, ikm, ikm_len, prk);
}

/*=============================================================================
 * HKDF-SHA512 Expand
 *===========================================================================*/
int hkdf_sha512_expand(uint8_t* okm, size_t okm_len,
                       const uint8_t* prk,
                       const uint8_t* info, size_t info_len) {
    uint8_t T[64];
    uint8_t T_len = 0;
    uint8_t counter = 1;
    size_t offset = 0;

    /* Check maximum output length: 255 * HashLen */
    if (okm_len > 255 * 64) {
        return -1;
    }

    if (info == NULL) {
        info_len = 0;
    }

    /* SECURITY FIX: Reject info_len beyond supported maximum to prevent buffer overflow
     * The input buffer is sized as 64 + HKDF_MAX_INFO_LEN + 1, so info_len must not exceed
     * HKDF_MAX_INFO_LEN to prevent writing past the buffer bounds */
    if (info_len > HKDF_MAX_INFO_LEN) {
        return -1;
    }

    /* Generate output blocks */
    while (offset < okm_len) {
        uint8_t input[64 + HKDF_MAX_INFO_LEN + 1];
        size_t input_len = 0;

        if (T_len > 0) {
            safe_copy(input + input_len, T, T_len);
            input_len += T_len;
        }

        if (info_len > 0) {
            safe_copy(input + input_len, info, info_len);
            input_len += info_len;
        }

        input[input_len] = counter;
        input_len++;

        hmac_sha512(prk, 64, input, input_len, T);
        T_len = 64;

        size_t to_copy = (okm_len - offset < 64) ? (okm_len - offset) : 64;
        safe_copy(okm + offset, T, to_copy);
        offset += to_copy;

        counter++;

        /*=====================================================================
         * SECURITY FIX: Zeroize input buffer after each iteration
         * CRITICAL: The input buffer contains previous T value and info which
         * are cryptographic material. Must be zeroized to prevent key leakage.
         *===================================================================*/
        crypto_secure_zero(input, sizeof(input));
    }

    crypto_secure_zero(T, sizeof(T));
    return 0;
}

/*=============================================================================
 * HKDF-SHA512 Combined
 *===========================================================================*/
int hkdf_sha512(uint8_t* okm, size_t okm_len,
                const uint8_t* salt, size_t salt_len,
                const uint8_t* ikm, size_t ikm_len,
                const uint8_t* info, size_t info_len) {
    uint8_t prk[64];

    hkdf_sha512_extract(prk, salt, salt_len, ikm, ikm_len);
    int result = hkdf_sha512_expand(okm, okm_len, prk, info, info_len);
    crypto_secure_zero(prk, sizeof(prk));

    return result;
}

/*=============================================================================
 * TLS 1.3 HKDF-Expand-Label
 *===========================================================================*/
int hkdf_expand_label(uint8_t* output, size_t output_len,
                      const uint8_t* secret,
                      const char* label,
                      const uint8_t* context, size_t context_len) {
    uint8_t hkdf_label[2 + 1 + 255 + 1 + 255]; /* HkdfLabel structure */
    size_t hkdf_label_len = 0;
    size_t label_len = strlen(label);
    const char* prefix = "tls13 ";
    size_t prefix_len = 6;

    /* Build HkdfLabel:
     *   uint16 length;
     *   opaque label<7..255> = "tls13 " + Label;
     *   opaque context<0..255>;
     */

    /* Length (2 bytes, big-endian) */
    hkdf_label[hkdf_label_len++] = (output_len >> 8) & 0xFF;
    hkdf_label[hkdf_label_len++] = output_len & 0xFF;

    /* Label length (1 byte) */
    uint8_t full_label_len = prefix_len + label_len;
    hkdf_label[hkdf_label_len++] = full_label_len;

    /* Label content: "tls13 " + label */
    safe_copy(hkdf_label + hkdf_label_len, prefix, prefix_len);
    hkdf_label_len += prefix_len;
    safe_copy(hkdf_label + hkdf_label_len, label, label_len);
    hkdf_label_len += label_len;

    /* Context length (1 byte) */
    hkdf_label[hkdf_label_len++] = context_len;

    /* Context content */
    if (context_len > 0 && context != NULL) {
        safe_copy(hkdf_label + hkdf_label_len, context, context_len);
        hkdf_label_len += context_len;
    }

    /* HKDF-Expand */
    return hkdf_sha256_expand(output, output_len, secret, hkdf_label, hkdf_label_len);
}

/*=============================================================================
 * Test Vectors (RFC 5869)
 *===========================================================================*/
bool hkdf_run_tests(void) {
    bool all_passed = true;

    kprintf("[HKDF] Running test vectors (RFC 5869)...\n");

    /* Test Case 1: Basic test with SHA-256 */
    const uint8_t ikm1[] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                             0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                             0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
    const uint8_t salt1[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const uint8_t info1[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                              0xf8, 0xf9 };
    uint8_t okm1[42];

    hkdf_sha256(okm1, 42, salt1, sizeof(salt1), ikm1, sizeof(ikm1), info1, sizeof(info1));

    const uint8_t expected1[] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };

    if (memcmp(okm1, expected1, 42) == 0) {
        kprintf("[HKDF] Test 1 PASSED\n");
    } else {
        kprintf("[HKDF] Test 1 FAILED\n");
        all_passed = false;
    }

    /* Test Case 2: Extract only */
    uint8_t prk2[32];
    hkdf_sha256_extract(prk2, salt1, sizeof(salt1), ikm1, sizeof(ikm1));

    const uint8_t expected_prk2[] = {
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
        0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
    };

    if (memcmp(prk2, expected_prk2, 32) == 0) {
        kprintf("[HKDF] Test 2 (Extract) PASSED\n");
    } else {
        kprintf("[HKDF] Test 2 (Extract) FAILED\n");
        all_passed = false;
    }

    if (all_passed) {
        kprintf("[HKDF] All tests PASSED\n");
    } else {
        kprintf("[HKDF] Some tests FAILED\n");
    }

    return all_passed;
}
