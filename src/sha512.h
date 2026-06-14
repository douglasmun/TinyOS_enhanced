/*=============================================================================
 * sha512.h - SHA-512 Cryptographic Hash Interface
 *=============================================================================*/
#pragma once

#include <stdint.h>
#include <stddef.h>

/*-----------------------------------------------------------------------------
 * SHA-512 Context Structure
 *---------------------------------------------------------------------------*/
typedef struct {
    uint64_t state[8];        /* Hash state (8 x 64-bit words) */
    uint64_t bitcount[2];     /* Message length in bits (128-bit counter) */
    uint8_t buffer[128];      /* Input buffer (1024-bit block) */
    uint32_t buflen;          /* Number of bytes in buffer */
} sha512_ctx_t;

/*-----------------------------------------------------------------------------
 * SHA-512 API Functions
 *---------------------------------------------------------------------------*/

/**
 * @brief Initialize SHA-512 context
 * @param ctx Context to initialize
 */
void sha512_init(sha512_ctx_t* ctx);

/**
 * @brief Update hash with new data
 * @param ctx SHA-512 context
 * @param data Data to hash
 * @param len Length of data in bytes
 */
void sha512_update(sha512_ctx_t* ctx, const void* data, size_t len);

/**
 * @brief Finalize hash and output result
 * @param ctx SHA-512 context
 * @param hash Output buffer (must be 64 bytes)
 */
void sha512_final(sha512_ctx_t* ctx, uint8_t* hash);

/**
 * @brief Convenience function: Hash data in one call
 * @param data Data to hash
 * @param len Length of data in bytes
 * @param hash Output buffer (must be 64 bytes)
 */
void sha512(const void* data, size_t len, uint8_t* hash);
