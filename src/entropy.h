/*=============================================================================
 * entropy.h - Hardware Random Number Generation (RDRAND) + Entropy Pool
 *
 * SECURITY (Production-Grade):
 * - Detects and uses Intel RDRAND (true hardware RNG)
 * - Falls back to entropy pool mixing multiple unpredictable sources
 * - Provides cryptographically strong randomness for ASLR, SSP, crypto
 *
 * Author: TinyOS Security Team
 * Version: 2.0 (Production Hardened)
 *===========================================================================*/
#pragma once

#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * Entropy Quality Levels
 *===========================================================================*/
typedef enum {
    ENTROPY_NONE = 0,       /* No entropy available (fatal) */
    ENTROPY_WEAK,           /* TSC-based (predictable, legacy fallback) */
    ENTROPY_MEDIUM,         /* Entropy pool (multiple sources) */
    ENTROPY_STRONG          /* Hardware RNG (RDRAND/RDSEED) */
} entropy_quality_t;

/*=============================================================================
 * Entropy Statistics (for monitoring)
 *===========================================================================*/
typedef struct {
    entropy_quality_t quality;
    bool rdrand_available;
    bool rdseed_available;
    uint32_t rdrand_requests;
    uint32_t rdrand_failures;
    uint32_t pool_stirs;
    uint32_t tsc_samples;
} entropy_stats_t;

/*=============================================================================
 * Public API
 *===========================================================================*/

/**
 * @brief Initialize entropy system
 * Detects RDRAND/RDSEED support and initializes entropy pool
 */
void entropy_init(void);

/**
 * @brief Get 32-bit random value (production-grade)
 * @return Cryptographically strong random number
 *
 * Uses RDRAND if available, otherwise entropy pool
 */
uint32_t entropy_get_random32(void);

/**
 * @brief Get 64-bit random value
 * @return Two calls to entropy_get_random32()
 */
uint64_t entropy_get_random64(void);

/**
 * @brief Fill buffer with random bytes
 * @param buffer Output buffer
 * @param size Number of random bytes to generate
 */
void entropy_get_bytes(void* buffer, uint32_t size);

/**
 * @brief Add entropy to the pool (interrupt timing, network events, etc.)
 * @param sample Entropy sample (e.g., interrupt timestamp)
 */
void entropy_add_sample(uint32_t sample);

/**
 * @brief Get current entropy quality level
 * @return ENTROPY_STRONG if RDRAND available, otherwise pool quality
 */
entropy_quality_t entropy_get_quality(void);

/**
 * @brief Get entropy statistics
 * @return Pointer to entropy stats structure
 */
const entropy_stats_t* entropy_get_stats(void);

/**
 * @brief Check if RDRAND is available
 * @return true if CPU supports RDRAND instruction
 */
bool entropy_has_rdrand(void);

/**
 * @brief Reseed the entropy pool (called periodically)
 * Mixes in TSC, interrupt timing, network events
 */
void entropy_reseed(void);

/**
 * @brief Wait for STRONG quality entropy
 * CRITICAL: Call this before cryptographic key generation
 *
 * @return true if STRONG entropy available, false if only MEDIUM/WEAK
 */
bool entropy_wait_for_strong(void);

/**
 * @brief Require STRONG entropy or block/fail
 * Use this for critical operations that MUST NOT proceed without strong entropy
 *
 * @param operation_name Name of operation for logging (e.g., "SSH key generation")
 * @return true if strong entropy available, false if operation should be blocked
 */
bool entropy_require_strong(const char* operation_name);
