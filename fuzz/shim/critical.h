/* Host-build replacement for src/critical.h (fuzzing only).
 * Same API and nesting bookkeeping; the pushfl/cli/popfl asm is dropped
 * because a fuzz target is single-threaded and has no interrupts. */
#pragma once
#include <stdint.h>
#include <stdbool.h>

extern volatile uint32_t __critical_section_depth;
extern volatile uint32_t __critical_section_saved_flags;
extern volatile uint32_t __interrupt_context_depth;

static inline void critical_section_enter(void) { __critical_section_depth++; }
static inline void critical_section_exit(void) {
    if (__critical_section_depth > 0) {
        __critical_section_depth--;
    }
}
#define CRITICAL_SECTION_ENTER() critical_section_enter()
#define CRITICAL_SECTION_EXIT() critical_section_exit()
static inline bool critical_section_is_active(void) { return __critical_section_depth > 0; }
static inline uint32_t disable_interrupts(void) { return 0x200; }
static inline void restore_interrupts(uint32_t flags) { (void)flags; }
static inline void interrupt_context_enter(void) { __interrupt_context_depth++; }
static inline void interrupt_context_exit(void) {
    if (__interrupt_context_depth > 0) {
        __interrupt_context_depth--;
    }
}
static inline bool in_interrupt_context(void) { return __interrupt_context_depth > 0; }
