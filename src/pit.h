/*=============================================================================
 *  pit.h â€” TinyOS Programmable Interval Timer
 *============================================================================*/
#pragma once
#include <stdint.h>

/**
 * Initialize the Programmable Interval Timer
 * @param hz Desired frequency in Hz (typically 100-1000)
 */
void pit_init(uint32_t hz);

/**
 * Called by IRQ0 handler on each timer tick
 */
void pit_on_tick(void);

/**
 * Get the current tick count
 * @return Number of timer ticks since initialization
 */
uint32_t pit_get_ticks(void);
