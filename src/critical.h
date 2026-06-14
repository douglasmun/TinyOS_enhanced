/*=============================================================================
 * critical.h - Re-entrant Critical Section Implementation
 *
 * CRITICAL DESIGN: Nested Critical Section Support
 * =================================================
 * This implementation tracks nesting depth to safely handle nested critical
 * sections. The interrupt flag (IF) is only restored when the outermost
 * critical section exits.
 *
 * Example of nested critical sections:
 *   CRITICAL_SECTION_ENTER();  // depth=1, saves IF, disables interrupts
 *     foo();
 *       CRITICAL_SECTION_ENTER();  // depth=2, interrupts already disabled
 *         bar();
 *       CRITICAL_SECTION_EXIT();   // depth=1, interrupts stay disabled
 *     baz();
 *   CRITICAL_SECTION_EXIT();  // depth=0, restores original IF state
 *
 * SECURITY: Without nesting support, the first EXIT would prematurely
 * re-enable interrupts, causing race conditions inside the outer critical
 * section.
 *=============================================================================*/
#pragma once

#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * GLOBAL STATE: Critical Section Nesting Tracker
 *=============================================================================*/
extern volatile uint32_t __critical_section_depth;
extern volatile uint32_t __critical_section_saved_flags;

/*=============================================================================
 * GLOBAL STATE: Interrupt Context Tracking
 *=============================================================================*/
extern volatile uint32_t __interrupt_context_depth;

/*=============================================================================
 * FUNCTION: critical_section_enter
 * PURPOSE: Enter a critical section (disable interrupts, track nesting)
 *=============================================================================*/
static inline void critical_section_enter(void) {
    uint32_t flags;

    // Save current EFLAGS and disable interrupts atomically
    // OPTIMIZED: pushfl; popl; cli is more efficient than pushfl; cli; popl
    // because it doesn't waste a stack slot temporarily
    __asm__ volatile(
        "pushfl\n"           // Push EFLAGS onto stack
        "popl %0\n"          // Pop saved EFLAGS into flags register
        "cli\n"              // Clear IF (disable interrupts)
        : "=r"(flags)
        :
        : "memory"
    );

    /* Only save flags on first entry (depth 0 -> 1), and ONLY in thread
     * context. In interrupt context IF is already cleared by the gate and is
     * restored by iret on ISR exit; saving/restoring the global
     * __critical_section_saved_flags from an ISR would clobber the value the
     * interrupted thread relies on (the depth/flags state is global and
     * shared between thread and IRQ contexts). Keeping ISR critical sections
     * as pure depth counters avoids corrupting the preempted thread. */
    if (__critical_section_depth == 0 && __interrupt_context_depth == 0) {
        __critical_section_saved_flags = flags;
    }

    /* INVARIANT: depth never approaches UINT32_MAX. A wrap would make EXIT
     * re-enable interrupts inside an outer critical section, but reaching 2^32
     * *outstanding* nestings needs 2^32 live stack frames — the kernel
     * triple-faults on stack overflow after a few thousand, so a wrap is
     * physically unreachable. Documented rather than guarded with a runtime
     * check that could never fire. */
    __critical_section_depth++;
}

/*=============================================================================
 * FUNCTION: critical_section_exit
 * PURPOSE: Exit a critical section (restore interrupts only on final exit)
 *=============================================================================*/
static inline void critical_section_exit(void) {
    // Prevent underflow (programming error detection)
    if (__critical_section_depth == 0) {
        // This is a bug - exiting without entering!
        // In production, this could panic() or log error
        return;
    }

    __critical_section_depth--;

    /* Only restore flags when exiting the outermost critical section
     * (depth 1 -> 0) AND in thread context. In interrupt context, IF must stay
     * cleared until iret restores it; doing popfl here would (a) prematurely
     * re-enable interrupts mid-ISR and (b) write back flags captured/clobbered
     * by ISR-context entries, corrupting the preempted thread. */
    if (__critical_section_depth == 0 && __interrupt_context_depth == 0) {
        __asm__ volatile(
            "pushl %0\n"     // Push saved EFLAGS onto stack
            "popfl\n"        // Pop into EFLAGS (restores IF)
            :
            : "r"(__critical_section_saved_flags)
            : "memory", "cc"
        );
    }
}

/*=============================================================================
 * MACRO: CRITICAL_SECTION_ENTER
 * PURPOSE: Convenient macro wrapper
 *=============================================================================*/
#define CRITICAL_SECTION_ENTER() critical_section_enter()

/*=============================================================================
 * MACRO: CRITICAL_SECTION_EXIT
 * PURPOSE: Convenient macro wrapper
 *=============================================================================*/
#define CRITICAL_SECTION_EXIT() critical_section_exit()

/*=============================================================================
 * FUNCTION: critical_section_is_active
 * PURPOSE: Check if currently inside a critical section (for debugging)
 *=============================================================================*/
static inline bool critical_section_is_active(void) {
    return __critical_section_depth > 0;
}

/*=============================================================================
 * FUNCTION: disable_interrupts
 * PURPOSE: Disable interrupts and return previous EFLAGS state
 * RETURN: Previous EFLAGS register value (for restore_interrupts)
 *
 * NOTE: This is a simpler interface than critical sections - it just saves
 * EFLAGS and disables interrupts without tracking nesting depth. Use this
 * when you need manual control over interrupt state in a single function.
 *=============================================================================*/
static inline uint32_t disable_interrupts(void) {
    uint32_t flags;
    __asm__ volatile(
        "pushfl\n"           // Push EFLAGS onto stack
        "popl %0\n"          // Pop into flags variable
        "cli\n"              // Disable interrupts
        : "=r"(flags)
        :
        : "memory"
    );
    return flags;
}

/*=============================================================================
 * FUNCTION: restore_interrupts
 * PURPOSE: Restore previous interrupt state from saved EFLAGS
 * PARAM: flags - Previously saved EFLAGS from disable_interrupts()
 *
 * NOTE: This restores the full EFLAGS register, including the interrupt flag.
 *=============================================================================*/
static inline void restore_interrupts(uint32_t flags) {
    __asm__ volatile(
        "pushl %0\n"         // Push saved EFLAGS onto stack
        "popfl\n"            // Restore EFLAGS (including IF)
        :
        : "r"(flags)
        : "memory", "cc"
    );
}

/*=============================================================================
 * FUNCTION: interrupt_context_enter
 * PURPOSE: Mark entry into interrupt handler context
 *
 * SECURITY: Call this at the start of isr_common_handler() to track when
 * we're inside an interrupt. This prevents dangerous operations like:
 * - Blocking (scheduler_block_task)
 * - Task switching
 * - Acquiring mutexes that could block
 *=============================================================================*/
static inline void interrupt_context_enter(void) {
    __interrupt_context_depth++;
}

/*=============================================================================
 * FUNCTION: interrupt_context_exit
 * PURPOSE: Mark exit from interrupt handler context
 *=============================================================================*/
static inline void interrupt_context_exit(void) {
    if (__interrupt_context_depth > 0) {
        __interrupt_context_depth--;
    }
}

/*=============================================================================
 * FUNCTION: in_interrupt_context
 * PURPOSE: Check if currently executing in interrupt handler
 * RETURN: true if in interrupt context, false otherwise
 *
 * USAGE: Use this to assert/verify that blocking operations are not called
 * from interrupt handlers.
 *=============================================================================*/
static inline bool in_interrupt_context(void) {
    return __interrupt_context_depth > 0;
}
