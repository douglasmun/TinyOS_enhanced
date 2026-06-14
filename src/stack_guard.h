/*=============================================================================
 * stack_guard.h - Stack Smashing Protection (SSP) for TinyOS
 *=============================================================================
 *
 * SECURITY: Stack Buffer Overflow Protection
 *
 * This implements GCC's stack protector mechanism, which places a "canary"
 * value on the stack before local variables. When the function returns,
 * GCC-generated code checks if the canary was overwritten. If so, it calls
 * __stack_chk_fail() to halt the system before exploitation can occur.
 *
 * ATTACK SCENARIO PREVENTED:
 * 1. Attacker sends malicious input to kernel function
 * 2. Input overflows local buffer on stack
 * 3. Overflow overwrites return address or function pointers
 * 4. Stack canary is ALSO overwritten (it's placed between buffer and metadata)
 * 5. On function return, GCC checks canary → MISMATCH → __stack_chk_fail()
 * 6. System panics BEFORE returning to attacker-controlled address
 *
 * COVERAGE:
 * -fstack-protector-strong protects functions with:
 * - Arrays or buffers > 8 bytes
 * - Calls to alloca()
 * - Local variables with address taken
 * - Array element references
 *
 * This catches ~95% of exploitable stack overflows in kernel code.
 *===========================================================================*/
#ifndef STACK_GUARD_H
#define STACK_GUARD_H

#include <stdint.h>

/*=============================================================================
 * GCC Stack Protector Interface
 *===========================================================================*/

/**
 * @brief Stack canary value (checked by GCC-generated code)
 *
 * SECURITY: This MUST be a global symbol named __stack_chk_guard
 * GCC's -fstack-protector instrumentation expects this exact name.
 *
 * The value should be:
 * - Random (unpredictable to attackers)
 * - Unique per boot (prevents pre-computed exploits)
 * - Non-zero (so strcpy can't easily bypass it)
 * - Contains null byte (prevents string-based attacks)
 */
extern uint32_t __stack_chk_guard;

/**
 * @brief Stack smashing detected handler (called by GCC)
 *
 * CRITICAL: This function is called by GCC-generated code when a stack
 * canary mismatch is detected. It MUST NOT RETURN, as the stack is already
 * corrupted and returning would jump to attacker-controlled address.
 *
 * This function:
 * 1. Prints detailed diagnostics
 * 2. Calls kernel_panic() to halt the system
 * 3. Never returns (marked __attribute__((noreturn)))
 */
void __stack_chk_fail(void) __attribute__((noreturn));

/**
 * @brief Initialize stack protection system
 *
 * MUST be called during early kernel initialization (before enabling
 * stack protection in any code). This:
 *
 * 1. Generates a random canary using TSC (Time Stamp Counter)
 * 2. Ensures canary contains null byte (0x00) in LSB
 * 3. Validates canary is non-zero
 *
 * @note Called from kernel_main() before any protected functions run
 */
void stack_guard_init(void);

/**
 * @brief Test stack protection by intentionally triggering overflow
 *
 * SECURITY TEST: This function intentionally overflows a stack buffer
 * to verify that stack protection is working correctly.
 *
 * Expected behavior:
 * - Buffer overflow corrupts stack canary
 * - GCC-generated epilogue detects canary mismatch
 * - Calls __stack_chk_fail()
 * - System panics with "Stack protection violation"
 *
 * @warning This WILL crash the system! Only call for testing.
 */
void stack_guard_test(void) __attribute__((noinline));

#endif /* STACK_GUARD_H */
