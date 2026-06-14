/*=============================================================================
 * keyboard.h - PS/2 Keyboard Driver
 *=============================================================================*/
#pragma once

#include <stdint.h>
#include <stdbool.h>

/*-----------------------------------------------------------------------------
 * PS/2 Keyboard Constants
 *-----------------------------------------------------------------------------*/

/* Keyboard data and status ports */
#define KBD_DATA_PORT    0x60
#define KBD_STATUS_PORT  0x64
#define KBD_COMMAND_PORT 0x64

/* Status register bits */
#define KBD_STAT_OUT_BUF  0x01  /* Output buffer full */
#define KBD_STAT_IN_BUF   0x02  /* Input buffer full */

/* Special scancodes */
#define SC_ESC           0x01
#define SC_BACKSPACE     0x0E
#define SC_TAB           0x0F
#define SC_ENTER         0x1C
#define SC_LCTRL         0x1D
#define SC_LSHIFT        0x2A
#define SC_RSHIFT        0x36
#define SC_LALT          0x38
#define SC_CAPSLOCK      0x3A
#define SC_F1            0x3B
#define SC_F2            0x3C
#define SC_F3            0x3D
#define SC_F4            0x3E
#define SC_F5            0x3F
#define SC_F6            0x40
#define SC_F7            0x41
#define SC_F8            0x42
#define SC_F9            0x43
#define SC_F10           0x44
#define SC_NUMLOCK       0x45
#define SC_SCROLLLOCK    0x46
#define SC_F11           0x57
#define SC_F12           0x58

/* Arrow keys */
#define SC_UP            0x48
#define SC_DOWN          0x50
#define SC_LEFT          0x4B
#define SC_RIGHT         0x4D

/* Special key codes (non-ASCII, sent to buffer) */
#define KEY_UP           0x90
#define KEY_DOWN         0x91
#define KEY_LEFT         0x92
#define KEY_RIGHT        0x93

/* Key release flag (OR'd with scancode) */
#define SC_RELEASED      0x80

/*=============================================================================
 * Input Buffer Configuration with Hysteresis for IRQ Masking
 *=============================================================================*/

/* Input buffer size */
#define KBD_BUFFER_SIZE  256

/*
 * IRQ MASKING THRESHOLDS (Hysteresis for DoS Prevention):
 *
 * FULL_THRESHOLD: Mask IRQ1 when buffer reaches this capacity
 * DRAIN_THRESHOLD: Unmask IRQ1 when buffer drains to this level
 *
 * The gap between these thresholds prevents "thrashing" - constant
 * mask/unmask cycles that would waste CPU and increase latency.
 */
#define KBD_FULL_THRESHOLD   (KBD_BUFFER_SIZE - 1)  /* 255: mask when full */
#define KBD_DRAIN_THRESHOLD  (KBD_BUFFER_SIZE / 2)  /* 128: unmask at 50% */

/*-----------------------------------------------------------------------------
 * Keyboard State
 *-----------------------------------------------------------------------------*/

typedef struct {
    bool shift;
    bool ctrl;
    bool alt;
    bool capslock;
    bool numlock;
    bool scrolllock;
} kbd_state_t;

/*-----------------------------------------------------------------------------
 * Function Prototypes
 *-----------------------------------------------------------------------------*/

/* Initialize keyboard driver (IRQ mode) */
void keyboard_init(void);

/* Enable keyboard IRQ - called by kernel after sti */
void keyboard_enable_irq(void);

/* IRQ1 handler - called from interrupt */
void keyboard_irq_handler(void);

/* Get next character from input buffer (blocking) */
char keyboard_getchar(void);

/* Get next character from input buffer (non-blocking) */
char keyboard_getchar_nonblock(void);

/* Check if input buffer has data */
bool keyboard_has_data(void);

/* Get current keyboard state */
kbd_state_t keyboard_get_state(void);
