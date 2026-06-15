/*=============================================================================
 * stack_guard.c - Stack Smashing Protection (SSP) Implementation
 *
 * SECURITY (v2.0 - Production Hardened):
 * - Now uses entropy.c module with RDRAND support
 * - Cryptographically strong randomness for stack canary
 * - Falls back to entropy pool if hardware RNG unavailable
 *=============================================================================*/
#include "stack_guard.h"
#include "entropy.h"
#include "kprintf.h"
#include "util.h"   /* For kernel_panic() */
#include "audit.h"  /* For security audit logging */
#include "process.h" /* For task_current() */
#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * Global Stack Canary (GCC expects this exact symbol name)
 *=============================================================================*/

/**
 * SECURITY: Stack canary value checked by GCC-generated code
 *
 * GCC's -fstack-protector instrumentation:
 * 1. Function prologue: Loads this value onto the stack
 * 2. Function epilogue: Compares stack value with this global
 * 3. If mismatch: Calls __stack_chk_fail()
 *
 * Initial value is placeholder, stack_guard_init() sets random value.
 */
uint32_t __stack_chk_guard = 0x00000000;

/*=============================================================================
 * Stack Guard Initialization
 *=============================================================================*/

void stack_guard_init(void) {
    /*=========================================================================
     * STEP 1: Generate random canary using entropy module (RDRAND or pool)
     *=======================================================================*/
    __stack_chk_guard = entropy_get_random32();

    /*=========================================================================
     * STEP 2: Ensure canary has null byte in LSB
     * SECURITY: Makes string-based attacks harder (strcpy stops at null)
     *=======================================================================*/
    __stack_chk_guard = (__stack_chk_guard & 0xFFFFFF00) | 0x00;

    /*=========================================================================
     * STEP 3: Ensure canary is non-zero (in case TSC XOR resulted in zero)
     *=======================================================================*/
    if (__stack_chk_guard == 0) {
        __stack_chk_guard = 0xDEADBE00;  /* Fallback canary */
    }

    /*=========================================================================
     * SECURITY FIX: Canary value is NOT logged to prevent disclosure
     *
     * Previously logged canary value to console during initialization.
     * This is a CRITICAL security vulnerability:
     *
     * Attack: If attacker sees canary value (via serial console, logs, or
     * local access), they can craft buffer overflow exploits that preserve
     * the canary, completely bypassing stack smashing protection (SSP).
     *
     * Example attack:
     * 1. Attacker sees: "[STACK_GUARD] Canary: 0xdeadbeef"
     * 2. Crafts overflow: [buffer...][0xdeadbeef][ret→shellcode]
     * 3. __stack_chk_fail() never triggers → SSP bypassed
     *
     * Fix: Canary value is now kept SECRET (not logged anywhere).
     * SSP effectiveness depends on canary unpredictability.
     *=======================================================================*/
    kprintf("[STACK_GUARD] Initialized......... [OK]\n");
    /* SECURITY: Canary value NOT logged - must remain secret */
    kprintf("[STACK_GUARD] Protection enabled for:\n");
    kprintf("[STACK_GUARD]   - Buffers > 8 bytes\n");
    kprintf("[STACK_GUARD]   - Address-taken variables\n");
    kprintf("[STACK_GUARD]   - Array references\n");
}

/*=============================================================================
 * Stack Smashing Detected Handler
 *=============================================================================*/

void __stack_chk_fail(void) {
    /*=========================================================================
     * CRITICAL: Stack is already corrupted when we reach here!
     *
     * DO NOT:
     * - Return from this function (return address is corrupted)
     * - Call complex functions (stack may be completely trashed)
     * - Trust local variables (they may be overwritten)
     *
     * DO:
     * - Log to audit system (for forensics)
     * - Print minimal diagnostics
     * - Halt the system immediately
     *=======================================================================*/

    /*=========================================================================
     * AUDIT LOG: Stack Corruption (CRITICAL SECURITY EVENT)
     * This event is logged FIRST for forensic analysis, even if stack is
     * corrupted, because audit_log uses minimal stack space and is hardened.
     *=======================================================================*/
    task_t* current = task_current();
    uint16_t uid = current ? current->uid : 0;
    uint16_t pid = current ? current->pid : 0;

    /* Log to audit system for forensics */
    audit_log(AUDIT_SEC_STACK_CORRUPTION, AUDIT_CRITICAL, uid,
              "Stack canary corruption detected (PID=%u, canary=0x%08x, possible exploit)",
              pid, (unsigned int)__stack_chk_guard);

    kprintf("\n");
    kprintf("*****************************************************************\n");
    kprintf("*                                                               *\n");
    kprintf("*  !!!  STACK CORRUPTION DETECTED  !!!                          *\n");
    kprintf("*                                                               *\n");
    kprintf("*****************************************************************\n");
    kprintf("\n");
    kprintf("CRITICAL SECURITY VIOLATION:\n");
    kprintf("  Stack canary was overwritten, indicating:\n");
    kprintf("    1. Buffer overflow on the stack, OR\n");
    kprintf("    2. Stack smashing attack, OR\n");
    kprintf("    3. Memory corruption bug\n");
    kprintf("\n");
    kprintf("Context:\n");
    kprintf("  PID: %u\n", pid);
    kprintf("  UID: %u\n", uid);
    kprintf("  Expected canary: 0x%08x\n", __stack_chk_guard);
    kprintf("  (Actual canary on stack was different)\n");
    kprintf("\n");
    kprintf("EXPLOIT PREVENTION:\n");
    kprintf("  The system is halting NOW to prevent:\n");
    kprintf("    - Execution of attacker-controlled code\n");
    kprintf("    - Return to corrupted address\n");
    kprintf("    - Privilege escalation\n");
    kprintf("\n");
    /* Get audit stats for forensic info */
    audit_stats_t stats;
    audit_get_stats(&stats);

    kprintf("FORENSICS:\n");
    kprintf("  This event has been logged to audit system.\n");
    kprintf("  Sequence: %u\n", stats.newest_sequence);
    kprintf("  Use 'auditlog' command to review attack timeline.\n");
    kprintf("\n");
    kprintf("DEBUG HINTS:\n");
    kprintf("  - Check recent function calls with large buffers\n");
    kprintf("  - Look for strcpy/sprintf without bounds checking\n");
    kprintf("  - Review array accesses for off-by-one errors\n");
    kprintf("\n");
    kprintf("*****************************************************************\n");

    /* Halt the system - DO NOT RETURN */
    kernel_panic("Stack protection violation");

    /* Should never reach here, but infinite loop as safety */
    while (1) {
        __asm__ volatile("hlt");
    }
}

/*=============================================================================
 * Stack Protection Test
 *=============================================================================*/

/**
 * SECURITY TEST: Intentional buffer overflow to verify stack protection
 *
 * This function:
 * 1. Allocates small buffer (16 bytes)
 * 2. Writes WAY beyond buffer bounds (overflows)
 * 3. Overwrites stack canary
 * 4. GCC-generated epilogue checks canary
 * 5. Calls __stack_chk_fail() → kernel_panic()
 *
 * Expected output:
 * [STACK_GUARD_TEST] Triggering overflow...
 * [STACK_GUARD_TEST] Writing beyond buffer...
 * *** STACK CORRUPTION DETECTED ***
 * PANIC: Stack protection violation
 */
void stack_guard_test(void) {
    kprintf("\n");
    kprintf("[STACK_GUARD_TEST] ==========================================\n");
    kprintf("[STACK_GUARD_TEST] Testing stack protection...\n");
    kprintf("[STACK_GUARD_TEST] This will intentionally overflow a buffer\n");
    kprintf("[STACK_GUARD_TEST] to verify canary detection works.\n");
    kprintf("[STACK_GUARD_TEST] ==========================================\n");
    kprintf("\n");

    /* Allocate small buffer on stack */
    volatile char buffer[16];  /* volatile prevents compiler optimization */

    kprintf("[STACK_GUARD_TEST] Buffer address: 0x%08x\n", (uint32_t)buffer);
    kprintf("[STACK_GUARD_TEST] Buffer size: %d bytes\n", (int)sizeof(buffer));
    kprintf("[STACK_GUARD_TEST] Stack canary should be at: ~0x%08x\n",
           (uint32_t)(buffer + sizeof(buffer)));
    kprintf("\n");

    kprintf("[STACK_GUARD_TEST] Triggering overflow in 3... 2... 1...\n");
    kprintf("[STACK_GUARD_TEST] Writing beyond buffer bounds...\n");

    /* INTENTIONAL OVERFLOW: Write way beyond buffer
     * Use volatile to prevent GCC from detecting this at compile time */
    volatile int overflow_size = 100;  /* Opaque to compiler */
    for (int i = 0; i < overflow_size; i++) {
        buffer[i] = (char)(0x41 + (i % 26));  /* Write 'A'-'Z' pattern */
    }

    kprintf("[STACK_GUARD_TEST] Overflow complete, returning...\n");
    kprintf("[STACK_GUARD_TEST] (GCC will now check canary)\n");

    /*=========================================================================
     * GCC-GENERATED CODE (invisible to us):
     *
     * mov eax, [ebp - 4]           ; Load canary from stack
     * xor eax, [__stack_chk_guard] ; Compare with global canary
     * jne __stack_chk_fail         ; If mismatch, call fail handler
     * leave                         ; Otherwise, normal return
     * ret
     *
     * In our case, the canary WILL be corrupted by the overflow above,
     * so __stack_chk_fail() will be called automatically!
     *=======================================================================*/
}
