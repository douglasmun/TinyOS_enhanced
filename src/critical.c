/*=============================================================================
 * critical.c - Re-entrant Critical Section Implementation
 *=============================================================================*/
#include "critical.h"

/*=============================================================================
 * GLOBAL STATE: Critical Section Nesting Tracker
 *
 * CRITICAL: These must be volatile to prevent compiler optimization from
 * caching them in registers, which would break the nesting logic.
 *=============================================================================*/
volatile uint32_t __critical_section_depth = 0;
volatile uint32_t __critical_section_saved_flags = 0;

/*=============================================================================
 * GLOBAL STATE: Interrupt Context Tracking
 *
 * SECURITY (v1.18): Track when we're inside an interrupt handler
 * - Incremented on entry to isr_common_handler
 * - Decremented on exit from isr_common_handler
 * - Used to prevent blocking operations in interrupt context
 *
 * WHY: Blocking in interrupt context is a critical bug:
 * - Can cause deadlocks (interrupt handlers hold locks)
 * - Can prevent other interrupts from being serviced
 * - Can corrupt scheduler state (task switching in interrupt context)
 *=============================================================================*/
volatile uint32_t __interrupt_context_depth = 0;
