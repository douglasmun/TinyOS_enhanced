#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

/*=============================================================================
 * SHA-256 Hash Function
 * RFC 6234 - US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)
 *===========================================================================*/

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} sha256_ctx_t;

void sha256_init(sha256_ctx_t* ctx);
void sha256_update(sha256_ctx_t* ctx, const void* data, size_t len);
void sha256_final(sha256_ctx_t* ctx, uint8_t* hash);

/* Convenience function: compute SHA-256 in one call */
void sha256(const void* data, size_t len, uint8_t* hash);

#endif /* SHA256_H */
