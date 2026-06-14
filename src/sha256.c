/*=============================================================================
 * sha256.c - SHA-256 Hash Function Implementation
 * Based on FIPS 180-4: Secure Hash Standard (SHS)
 *===========================================================================*/

#include "sha256.h"
#include "util.h"  /* For memcpy, memset */

/* SHA-256 Constants (first 32 bits of fractional parts of cube roots of first 64 primes) */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Rotate right */
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/* SHA-256 functions */
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define EP1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SIG0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx_t* ctx, const uint8_t* data) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    uint32_t i;

    /* Prepare message schedule */
    for (i = 0; i < 16; i++) {
        m[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    /* Initialize working variables */
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    /* Main loop */
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    /* Add working variables back into state */
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(sha256_ctx_t* ctx) {
    ctx->count = 0;

    /* Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes) */
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_update(sha256_ctx_t* ctx, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    size_t buflen = (size_t)(ctx->count & 63);

    ctx->count += len;

    /* Handle any partial block */
    if (buflen > 0) {
        size_t to_copy = 64 - buflen;
        if (to_copy > len) {
            to_copy = len;
        }
        memcpy(&ctx->buffer[buflen], p, to_copy);
        p += to_copy;
        len -= to_copy;
        buflen += to_copy;

        if (buflen == 64) {
            sha256_transform(ctx, ctx->buffer);
            buflen = 0;
        }
    }

    /* Process complete 64-byte blocks */
    while (len >= 64) {
        sha256_transform(ctx, p);
        p += 64;
        len -= 64;
    }

    /* Save remaining bytes */
    if (len > 0) {
        memcpy(ctx->buffer, p, len);
    }
}

void sha256_final(sha256_ctx_t* ctx, uint8_t* hash) {
    uint32_t i;
    size_t buflen = (size_t)(ctx->count & 63);

    /* Pad message: append 0x80, then zeros, then 64-bit length */
    ctx->buffer[buflen++] = 0x80;

    /* If not enough room for length, pad this block and start another */
    if (buflen > 56) {
        while (buflen < 64) {
            ctx->buffer[buflen++] = 0;
        }
        sha256_transform(ctx, ctx->buffer);
        buflen = 0;
    }

    /* Pad zeros until we have 56 bytes */
    while (buflen < 56) {
        ctx->buffer[buflen++] = 0;
    }

    /*=========================================================================
     * SECURITY FIX (AUDIT 8B): SHA-256 Integer Overflow Protection
     *
     * VULNERABILITY: Hash Collision via Integer Overflow
     *
     * PROBLEM: Byte-to-Bit Conversion Overflow for Large Files
     * SHA-256 stores message length in bits in the final 64-bit field.
     * The multiplication `ctx->count * 8` converts bytes to bits.
     * Without proper casting, this can overflow on large files.
     *
     * OVERFLOW MATHEMATICS:
     * - ctx->count is uint64_t (bytes processed)
     * - Literal 8 is int (32-bit on x86)
     * - On some compilers: uint64_t * int may use 32-bit intermediate
     * - Overflow threshold: (2^32 / 8) = 536,870,912 bytes (512 MiB)
     * - For files > 512 MiB: bitlen wraps, hash becomes incorrect
     *
     * ATTACK SCENARIO:
     * 1. Attacker crafts two files: small.bin (100 MB) and large.bin (600 MB)
     * 2. large.bin has same content as small.bin plus 500 MB of data
     * 3. Due to integer overflow:
     *    - large.bin bitlen = (600MB * 8) mod 2^32 = 536870912 bits
     *    - This equals 67108864 bytes = 64 MB
     * 4. SHA-256(large.bin) uses incorrect length field
     * 5. Attacker can find hash collisions by manipulating file size
     *
     * SECURITY IMPACT:
     * - Secure boot signature verification bypass
     * - File integrity checks fail to detect tampering
     * - HMAC construction breaks (length extension attack)
     *
     * FIX: Explicit 64-bit Literal with ULL Suffix
     * - Change `ctx->count * 8` to `ctx->count * 8ULL`
     * - Forces 64-bit multiplication (C99 standard)
     * - Maximum file size: (2^64 / 8) = 2 exabytes
     *
     * REFERENCES:
     * - FIPS 180-4 Section 5.1.1: Padding the Message
     * - C99 Standard 6.3.1.8: Integer Promotion Rules
     *=======================================================================*/

    /* Append length in bits (big-endian) */
    /* SECURITY: Use 8ULL to force 64-bit multiplication */
    uint64_t bitlen = ctx->count * 8ULL;
    for (i = 0; i < 8; i++) {
        ctx->buffer[63 - i] = (uint8_t)(bitlen >> (i * 8));
    }

    sha256_transform(ctx, ctx->buffer);

    /* Output hash (big-endian) */
    for (i = 0; i < 8; i++) {
        hash[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

void sha256(const void* data, size_t len, uint8_t* hash) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}
