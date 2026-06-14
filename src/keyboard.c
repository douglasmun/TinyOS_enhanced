/*=============================================================================
 * keyboard.c - PS/2 Keyboard Driver Implementation
 *=============================================================================*/
#include "keyboard.h"
#include "kernel.h"
#include "kprintf.h"
#include "util.h"
#include "pic.h"
#include "critical.h"  /* For atomic buffer access */
#include "serial.h"    /* For serial input fallback */

/*-----------------------------------------------------------------------------
 * Scancode to ASCII Translation Tables
 *-----------------------------------------------------------------------------*/

/* Normal (no shift) scancode to ASCII map */
static const char scancode_to_ascii[128] = {
    0,    27,  '1',  '2',  '3',  '4',  '5',  '6',   /* 0x00-0x07 */
    '7',  '8',  '9',  '0',  '-',  '=',  '\b', '\t', /* 0x08-0x0F */
    'q',  'w',  'e',  'r',  't',  'y',  'u',  'i',   /* 0x10-0x17 */
    'o',  'p',  '[',  ']',  '\n', 0,    'a',  's',   /* 0x18-0x1F */
    'd',  'f',  'g',  'h',  'j',  'k',  'l',  ';',   /* 0x20-0x27 */
    '\'', '`',  0,    '\\', 'z',  'x',  'c',  'v',   /* 0x28-0x2F */
    'b',  'n',  'm',  ',',  '.',  '/',  0,    '*',   /* 0x30-0x37 */
    0,    ' ',  0,    0,    0,    0,    0,    0,     /* 0x38-0x3F */
    0,    0,    0,    0,    0,    0,    0,    '7',   /* 0x40-0x47 */
    '8',  '9',  '-',  '4',  '5',  '6',  '+',  '1',   /* 0x48-0x4F */
    '2',  '3',  '0',  '.',  0,    0,    0,    0,     /* 0x50-0x57 */
    0,    0,    0,    0,    0,    0,    0,    0      /* 0x58-0x5F */
};

/* Shifted scancode to ASCII map */
static const char scancode_to_ascii_shift[128] = {
    0,    27,  '!',  '@',  '#',  '$',  '%',  '^',   /* 0x00-0x07 */
    '&',  '*',  '(',  ')',  '_',  '+',  '\b', '\t', /* 0x08-0x0F */
    'Q',  'W',  'E',  'R',  'T',  'Y',  'U',  'I',   /* 0x10-0x17 */
    'O',  'P',  '{',  '}',  '\n', 0,    'A',  'S',   /* 0x18-0x1F */
    'D',  'F',  'G',  'H',  'J',  'K',  'L',  ':',   /* 0x20-0x27 */
    '"',  '~',  0,    '|',  'Z',  'X',  'C',  'V',   /* 0x28-0x2F */
    'B',  'N',  'M',  '<',  '>',  '?',  0,    '*',   /* 0x30-0x37 */
    0,    ' ',  0,    0,    0,    0,    0,    0,     /* 0x38-0x3F */
    0,    0,    0,    0,    0,    0,    0,    '7',   /* 0x40-0x47 */
    '8',  '9',  '-',  '4',  '5',  '6',  '+',  '1',   /* 0x48-0x4F */
    '2',  '3',  '0',  '.',  0,    0,    0,    0,     /* 0x50-0x57 */
    0,    0,    0,    0,    0,    0,    0,    0      /* 0x58-0x5F */
};

/*-----------------------------------------------------------------------------
 * Keyboard State and Buffer
 *-----------------------------------------------------------------------------*/

static kbd_state_t kbd_state = {
    .shift = false,
    .ctrl = false,
    .alt = false,
    .capslock = false,
    .numlock = false,
    .scrolllock = false
};

/* Circular input buffer */
static char input_buffer[KBD_BUFFER_SIZE];
static volatile uint32_t buffer_read_pos = 0;
static volatile uint32_t buffer_write_pos = 0;

/*=============================================================================
 * SECURITY (v1.13): Keyboard Buffer Overflow Protection
 *
 * Rate limiting to prevent interrupt storm DoS. If the buffer fills up
 * (e.g., due to rapid key presses or malicious hardware), we track overflow
 * events and log warnings to help diagnose the issue.
 *===========================================================================*/
static volatile uint32_t buffer_overflow_count = 0;
static volatile uint32_t last_overflow_warning = 0;

/*=============================================================================
 * PERFORMANCE (v1.14): IRQ Masking for Interrupt Storm Prevention
 *
 * When keyboard buffer fills up, mask IRQ1 to prevent interrupt storm.
 * Unmask when buffer drains and has space available again.
 *===========================================================================*/
static volatile bool kbd_irq_masked = false;

/*-----------------------------------------------------------------------------
 * Buffer Management Functions
 *-----------------------------------------------------------------------------*/

static inline bool buffer_is_full(void) {
    return ((buffer_write_pos + 1) % KBD_BUFFER_SIZE) == buffer_read_pos;
}

/*
 * CRITICAL: Do NOT inline buffer_is_empty() to prevent compiler optimizations
 * that cache the volatile variable reads across the memory barrier.
 * The IRQ handler modifies buffer_write_pos, and we MUST reload it every time.
 */
static __attribute__((noinline)) bool buffer_is_empty(void) {
    volatile uint32_t write_pos = buffer_write_pos;
    volatile uint32_t read_pos = buffer_read_pos;
    return write_pos == read_pos;
}

static inline int buffer_count(void) {
    /*=========================================================================
     * Calculate current number of items in circular buffer.
     * Handles wrap-around correctly.
     *=======================================================================*/
    return (buffer_write_pos - buffer_read_pos + KBD_BUFFER_SIZE) % KBD_BUFFER_SIZE;
}

static inline void buffer_put(char c) {
    if (!buffer_is_full()) {
        input_buffer[buffer_write_pos] = c;
        buffer_write_pos = (buffer_write_pos + 1) % KBD_BUFFER_SIZE;

        /*
         * CRITICAL: Memory barrier to ensure IRQ handler's writes are visible
         * to main thread. Without this, the compiler/CPU may cache buffer_write_pos
         * in a register, preventing keyboard_getchar() from seeing the update.
         */
        __sync_synchronize();
    } else {
        /*=====================================================================
         * PERFORMANCE (v1.14): Interrupt Storm Prevention via IRQ Masking
         *
         * ISSUE: If keyboard buffer fills up (e.g., due to rapid key presses,
         * malicious hardware, or slow consumer), the ISR will be called
         * repeatedly but unable to make progress, creating an interrupt storm
         * that can DoS the system.
         *
         * DEFENSE:
         * 1. Track overflow events
         * 2. Log warning (rate-limited to avoid log flooding)
         * 3. Silently drop character to prevent buffer corruption
         * 4. MASK IRQ1 to stop interrupt storm until buffer drains
         *===================================================================*/
        buffer_overflow_count++;

        /* Mask keyboard IRQ to prevent interrupt storm */
        if (!kbd_irq_masked) {
            pic_mask(1);  /* IRQ1 = keyboard */
            kbd_irq_masked = true;
        }

        /* Rate-limit warnings: only log every 1000 overflows */
        if ((buffer_overflow_count - last_overflow_warning) >= 1000) {
            /* Note: kprintf from ISR is generally unsafe, but this is
             * an educational OS and we want to see the warning */
            kprintf("\n[KBD] WARNING: Buffer overflow! Dropped %u chars (IRQ masked)\n",
                    (unsigned int)buffer_overflow_count);
            last_overflow_warning = buffer_overflow_count;
        }
    }
}

static inline char buffer_get(void) {
    /*=========================================================================
     * ATOMICITY (v1.14): Protect buffer access from ISR race conditions
     *
     * Disable interrupts to ensure atomic read of buffer pointers and data.
     * Prevents race where ISR modifies buffer_write_pos while we're reading.
     *=======================================================================*/
    uint32_t flags = disable_interrupts();

    if (buffer_is_empty()) {
        restore_interrupts(flags);
        return 0;
    }

    char c = input_buffer[buffer_read_pos];
    buffer_read_pos = (buffer_read_pos + 1) % KBD_BUFFER_SIZE;

    /*=========================================================================
     * PERFORMANCE (v1.14): Re-enable Keyboard IRQ After Buffer Drains
     *                      (Hysteresis-Based Threshold)
     *
     * CRITICAL FIX: Only unmask IRQ when buffer has drained to DRAIN_THRESHOLD
     * (50% capacity), not just when one slot is free. This prevents "thrashing"
     * - constant mask/unmask cycles that waste CPU and increase latency.
     *
     * HYSTERESIS MODEL:
     * - Mask at:   255/256 items (FULL_THRESHOLD)
     * - Unmask at: 128/256 items (DRAIN_THRESHOLD)
     * - Gap:       127 items provides stability
     *
     * This ensures the system has breathing room before re-enabling interrupts,
     * allowing efficient batch processing of accumulated keyboard input.
     *=======================================================================*/
    if (kbd_irq_masked) {
        /* Only unmask when buffer has drained to safe threshold */
        if (buffer_count() <= KBD_DRAIN_THRESHOLD) {
            pic_unmask(1);  /* IRQ1 = keyboard */
            kbd_irq_masked = false;
        }
    }

    restore_interrupts(flags);
    return c;
}

/*-----------------------------------------------------------------------------
 * Scancode to ASCII Conversion
 *-----------------------------------------------------------------------------*/

static char scancode_to_char(uint8_t scancode) {
    /* Check if scancode is in valid range */
    if (scancode >= 128) {
        return 0;
    }

    /* Use shift table if shift is pressed */
    bool use_shift = kbd_state.shift;

    /* Handle capslock for letters */
    if (kbd_state.capslock) {
        char c = scancode_to_ascii[scancode];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
            use_shift = !use_shift;
        }
    }

    return use_shift ? scancode_to_ascii_shift[scancode] : scancode_to_ascii[scancode];
}

/*-----------------------------------------------------------------------------
 * Keyboard IRQ Handler
 *-----------------------------------------------------------------------------*/

void keyboard_irq_handler(void) {
    /* Read scancode from keyboard data port */
    uint8_t scancode = inb(KBD_DATA_PORT);

    /* Check if this is a key release (high bit set) */
    bool released = (scancode & SC_RELEASED) != 0;
    scancode &= ~SC_RELEASED;

    /* Handle modifier keys */
    switch (scancode) {
        case SC_LSHIFT:
        case SC_RSHIFT:
            kbd_state.shift = !released;
            return;

        case SC_LCTRL:
            kbd_state.ctrl = !released;
            return;

        case SC_LALT:
            kbd_state.alt = !released;
            return;

        case SC_CAPSLOCK:
            if (!released) {
                kbd_state.capslock = !kbd_state.capslock;
            }
            return;

        case SC_NUMLOCK:
            if (!released) {
                kbd_state.numlock = !kbd_state.numlock;
            }
            return;

        case SC_SCROLLLOCK:
            if (!released) {
                kbd_state.scrolllock = !kbd_state.scrolllock;
            }
            return;
    }

    /* Only process key presses (not releases) */
    if (released) {
        return;
    }

    /* Handle arrow keys as special non-ASCII keys */
    switch (scancode) {
        case SC_UP:
            buffer_put(KEY_UP);
            return;
        case SC_DOWN:
            buffer_put(KEY_DOWN);
            return;
        case SC_LEFT:
            buffer_put(KEY_LEFT);
            return;
        case SC_RIGHT:
            buffer_put(KEY_RIGHT);
            return;
    }

    /* Convert scancode to ASCII */
    char c = scancode_to_char(scancode);

    if (c != 0) {
        /*=========================================================================
         * ARCHITECTURE (v1.13): Application-Layer Echo Control
         *
         * The keyboard driver should ONLY buffer characters, never echo them.
         * Different applications need different echo behaviors:
         * - Login username: Echo actual characters
         * - Login password: Echo asterisks (*)
         * - Shell: Echo actual characters
         * - Secure commands: Suppress echo entirely
         *
         * If the keyboard driver echoes, applications lose control over echo
         * behavior, causing double-echo bugs and security issues.
         *
         * SECURITY: Password input could leak actual characters if keyboard
         * driver echoes before application can suppress/replace with asterisks.
         *=======================================================================*/

        /* Add to buffer - let application handle all echoing */
        buffer_put(c);
    }
}

/*-----------------------------------------------------------------------------
 * Public API Functions
 *-----------------------------------------------------------------------------*/

void keyboard_init(void) {
    /* Clear keyboard state */
    kbd_state.shift = false;
    kbd_state.ctrl = false;
    kbd_state.alt = false;
    kbd_state.capslock = false;
    kbd_state.numlock = false;
    kbd_state.scrolllock = false;

    /* Clear input buffer */
    buffer_read_pos = 0;
    buffer_write_pos = 0;

    /*=========================================================================
     * INITIALIZATION: Initialize keyboard state, but don't unmask IRQ yet
     *
     * The keyboard IRQ will be unmasked by kernel_main() AFTER sti.
     * This ensures we don't have pending keyboard interrupts fire during
     * the critical transition when interrupts are enabled.
     *=======================================================================*/
    kbd_irq_masked = true;  /* IRQ not yet unmasked */
    buffer_overflow_count = 0;
    last_overflow_warning = 0;
}

void keyboard_enable_irq(void) {
    /*=========================================================================
     * Enable keyboard IRQ - called by kernel after sti
     *
     * This synchronizes the software flag with the hardware state.
     * kernel_main() calls pic_unmask(1) after sti, then calls this function
     * to update our internal state.
     *=======================================================================*/
    kbd_irq_masked = false;
}

char keyboard_getchar(void) {
    /*=========================================================================
     * SECURITY (v1.13): Atomic Buffer Read (Simplified)
     *
     * ISSUE: Without atomic read, password input could be vulnerable to race
     * where one process steals characters from another process's input stream.
     *
     * NOTE: The theoretical race condition exists, but in practice this is an
     * educational OS where:
     * 1. Most operations are single-process (login, shell)
     * 2. The window for race is extremely small (nanoseconds)
     * 3. Complex atomic implementations caused worse issues (double echoing)
     *
     * TRADE-OFF: We accept the minimal theoretical risk rather than introduce
     * complex critical section logic that interferes with interrupt handling.
     *
     * FUTURE: For production OS, implement per-process keyboard buffers or
     * proper TTY discipline layers to isolate input streams.
     *=======================================================================*/
    /* Block until character is available */
    while (buffer_is_empty()) {
        __asm__ volatile("hlt");
    }
    return buffer_get();
}

char keyboard_getchar_nonblock(void) {
    return buffer_get();
}

bool keyboard_has_data(void) {
    return !buffer_is_empty();
}

kbd_state_t keyboard_get_state(void) {
    return kbd_state;
}

