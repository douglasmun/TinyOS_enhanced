/*=============================================================================
 * aslr.h - Address Space Layout Randomization (ASLR)
 *=============================================================================
 *
 * SECURITY: ASLR makes exploitation significantly harder by randomizing
 * memory locations. Even if an attacker finds a buffer overflow, they
 * don't know where to jump to execute their shellcode.
 *
 * EFFECTIVENESS:
 * - Without ASLR: Exploit works 100% of the time (addresses are fixed)
 * - With ASLR: Exploit works 1/N times (where N = entropy bits)
 *   - 16-bit entropy: 1/65536 chance (~0.0015%)
 *   - 20-bit entropy: 1/1048576 chance (~0.0001%)
 *   - 28-bit entropy: 1/268435456 chance (~0.0000004%)
 *
 * IMPLEMENTATION:
 * - User stack randomization (8-28 bits of entropy)
 * - Heap randomization (future)
 * - Kernel base randomization (future, requires bootloader support)
 *
 * ENTROPY SOURCE:
 * - TSC (Time Stamp Counter) - CPU cycles since boot
 * - Boot time variations
 * - Network card MAC address (if available)
 * - Combined using XOR mixing
 *===========================================================================*/
#ifndef ASLR_H
#define ASLR_H

#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * ASLR Configuration
 *===========================================================================*/

/**
 * @brief Stack randomization range (in 4KB pages)
 *
 * SECURITY: Controls how many bits of entropy for stack placement.
 * Larger range = more security, but must fit in available address space.
 *
 * User address space: 0x00000000 - 0xBFFFFFFF (3GB)
 * Kernel address space: 0xC0000000 - 0xFFFFFFFF (1GB)
 *
 * With 256 page range (1MB), we get log2(256) = 8 bits of entropy.
 * With 65536 page range (256MB), we get log2(65536) = 16 bits of entropy.
 */
#define ASLR_STACK_ENTROPY_PAGES    4096    /* 16MB range = 12 bits */

/**
 * @brief Minimum user stack address (leave room for code/heap)
 *
 * User memory layout:
 * 0x00400000 - 0x10000000: Code + Heap (256MB)
 * 0x10000000 - 0xBFFFFFFF: Stack region (~2.75GB)
 * 0xC0000000+: Kernel (1GB)
 */
#define ASLR_STACK_MIN  0x40000000  /* 1GB - plenty of room for code/heap */
#define ASLR_STACK_MAX  0xC0000000  /* 3GB - kernel boundary */

/*=============================================================================
 * ASLR Statistics
 *===========================================================================*/

typedef struct {
    bool enabled;               /* Is ASLR enabled? */
    uint32_t entropy_bits;      /* Bits of entropy for stack */
    uint32_t stacks_randomized; /* Number of stacks randomized */
    uint32_t rng_reseeds;       /* Times RNG was reseeded */
    uint32_t min_stack_addr;    /* Minimum stack address seen */
    uint32_t max_stack_addr;    /* Maximum stack address seen */
} aslr_stats_t;

/*=============================================================================
 * ASLR API
 *===========================================================================*/

/**
 * @brief Initialize ASLR system
 *
 * MUST be called during early boot (after TSC is available).
 * Seeds the RNG with boot-time entropy.
 */
void aslr_init(void);

/**
 * @brief Get randomized stack base address for new user process
 *
 * SECURITY: Returns a randomized virtual address for the user stack.
 * Each call returns a different address (within entropy range).
 *
 * @param stack_size_pages Size of stack in 4KB pages
 * @return Randomized stack base address (16-byte aligned)
 *
 * Example:
 *   uint32_t stack_base = aslr_get_random_stack_base(128); // 512KB stack
 *   // Returns something like: 0x7A3F4FF0 (randomized each boot/process)
 */
uint32_t aslr_get_random_stack_base(uint32_t stack_size_pages);

/**
 * @brief Get ASLR statistics
 *
 * @param stats Output buffer for statistics
 */
void aslr_get_stats(aslr_stats_t* stats);

/**
 * @brief Enable/disable ASLR
 *
 * @param enabled true to enable, false to disable
 *
 * NOTE: Disabling ASLR reduces security but can help with debugging.
 *       When disabled, stack addresses are deterministic.
 */
void aslr_set_enabled(bool enabled);

/**
 * @brief Check if ASLR is enabled
 *
 * @return true if enabled, false otherwise
 */
bool aslr_is_enabled(void);

/*=============================================================================
 * Internal RNG (used by ASLR, not for cryptography)
 *===========================================================================*/

/**
 * @brief Get random 32-bit value
 *
 * SECURITY NOTE: This is NOT cryptographically secure!
 * Uses TSC + simple PRNG for ASLR purposes only.
 * DO NOT use for cryptographic keys or nonces.
 *
 * @return Pseudo-random 32-bit value
 */
uint32_t aslr_random32(void);

/**
 * @brief Reseed the ASLR RNG
 *
 * Mixes in new entropy from TSC.
 * Called periodically to prevent RNG state prediction.
 */
void aslr_reseed(void);

#endif /* ASLR_H */
