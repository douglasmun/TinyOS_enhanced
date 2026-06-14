/*=============================================================================
 *  vga.c â€” TinyOS VGA Text Mode Console Driver
 *============================================================================*/
#include "kernel.h"
#include "pic.h"
#include "critical.h"  /* For interrupt protection (race condition fix) */

/*=============================================================================
 * VGA BUFFER POINTER
 *============================================================================*/
static volatile uint16_t* const vga = (uint16_t*)VGA_BUFFER_ADDR;

/*=============================================================================
 * VGA HARDWARE CURSOR PORTS
 *============================================================================*/
#define VGA_CTRL_REGISTER  0x3D4  /* CRT Controller Address Register */
#define VGA_DATA_REGISTER  0x3D5  /* CRT Controller Data Register */

/*=============================================================================
 * CURSOR POSITION STATE
 *=============================================================================
 * DESCRIPTION:
 *   Software cursor tracking the current output position.
 *   The next character will be written at (col, row).
 *
 * VARIABLES:
 *   row: Current row (0-24), top to bottom
 *   col: Current column (0-79), left to right
 *   attr: Current attribute byte (color and style)
 *
 * COORDINATE SYSTEM:
 *   Origin (0, 0) is at the TOP-LEFT corner of the screen.
 *   
 *   (0,0)                                               (79,0)
 *     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
 *     â”‚ 80 characters wide (columns 0-79)                 â”‚
 *     â”‚                                                   â”‚
 *     â”‚ 25 characters tall (rows 0-24)                    â”‚
 *     â”‚                                                   â”‚
 *     â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
 *   (0,24)                                             (79,24)
 *
 * DEFAULT ATTRIBUTE: 0x0F (VGA_DEFAULT_ATTR)
 *   0x0F = 0000 1111 binary
 *     Bits 0-3 (0xF): White foreground
 *     Bits 4-7 (0x0): Black background
 *   Result: White text on black background (classic console)
 *
 * CURSOR MOVEMENT:
 *   - Printing a character: Increments col, wraps to next row at end
 *   - Newline (\n): Moves to start of next row
 *   - End of screen: Scrolls entire screen up one line
 *
 * INITIALIZATION:
 *   All start at 0 (top-left corner, white on black).
 *   Set by console_clear() during kernel initialization.
 *
 * THREAD SAFETY:
 *   NOT safe for concurrent access. If two threads write simultaneously,
 *   row/col can become inconsistent, causing garbled output.
 *   Future: Protect with spinlock or use per-CPU consoles.
 *============================================================================*/
static uint8_t row = 0;                  /* Current row (0-24) */
static uint8_t col = 0;                  /* Current column (0-79) */
static uint8_t attr = VGA_DEFAULT_ATTR;  /* Current attribute (0x0F) */

/*=============================================================================
 * FUNCTION: vga_put_at
 *=============================================================================
 * DESCRIPTION:
 *   Writes a character to a specific position on the screen with given
 *   attribute (color). This is the fundamental VGA write operation.
 *
 * PARAMETERS:
 *   c - ASCII character to display (any value 0-255)
 *       Common values: 0x20-0x7E (printable ASCII)
 *       Extended: 0x80-0xFF (line drawing, special chars)
 *   
 *   a - Attribute byte (color and style)
 *       Format: BBBBFFFF (4 bits background, 4 bits foreground)
 *       Example: 0x0F = white on black
 *                0x4E = yellow on red
 *   
 *   x - Column position (0-79)
 *       0 = leftmost column
 *       79 = rightmost column
 *   
 *   y - Row position (0-24)
 *       0 = top row
 *       24 = bottom row
 *
 * USAGE EXAMPLES:
 *   // Write 'X' at (10, 5) in red on black
 *   vga_put_at('X', 0x0C, 10, 5);
 *   
 *   // Clear character at (40, 12)
 *   vga_put_at(' ', 0x0F, 40, 12);
 *   
 *   // Draw blue line at top
 *   for (int x = 0; x < 80; x++)
 *       vga_put_at('â”€', 0x09, x, 0);
 *============================================================================*/
static inline void vga_put_at(char c, uint8_t a, uint8_t x, uint8_t y) {
    /* ROBUSTNESS (v1.14): Bounds checking to prevent memory corruption */
    if (x >= VGA_WIDTH || y >= VGA_HEIGHT) {
        return;  /* Silently ignore out-of-bounds writes */
    }
    vga[y * VGA_WIDTH + x] = (uint16_t)c | ((uint16_t)a << 8);
}

/*=============================================================================
 * FUNCTION: scroll
 *=============================================================================
 * DESCRIPTION:
 *   Scrolls the entire screen up by one line. Copies rows 1-24 to rows 0-23,
 *   then clears the bottom row (row 24). Called when output reaches the
 *   bottom of the screen and needs to continue.
 *
 * VISUAL EXAMPLE (5 rows for clarity):
 *   BEFORE SCROLL:        AFTER SCROLL:
 *   Row 0: Line 1         Row 0: Line 2
 *   Row 1: Line 2         Row 1: Line 3
 *   Row 2: Line 3         Row 2: Line 4
 *   Row 3: Line 4         Row 3: Line 5
 *   Row 4: Line 5  â†“      Row 4: [empty]  â† cleared
 *   (cursor at row 5)     (cursor stays at row 4)
 *
 *============================================================================*/
static void scroll(void) {
    /*=========================================================================
     * PERFORMANCE OPTIMIZATION (v1.14):
     * Use single linear loop instead of nested loops for better cache
     * locality and branch prediction. This copies 1920 words (3840 bytes)
     * representing 24 lines of text.
     *=======================================================================*/
    const uint32_t scroll_size = (VGA_HEIGHT - 1) * VGA_WIDTH;

    /* Copy lines 1-24 to lines 0-23 (bulk copy) */
    for (uint32_t i = 0; i < scroll_size; ++i) {
        vga[i] = vga[i + VGA_WIDTH];
    }

    /* Clear bottom line */
    const uint16_t blank = ' ' | ((uint16_t)attr << 8);
    const uint32_t bottom_line_start = (VGA_HEIGHT - 1) * VGA_WIDTH;
    for (uint32_t i = 0; i < VGA_WIDTH; ++i) {
        vga[bottom_line_start + i] = blank;
    }
}

/*=============================================================================
 * FUNCTION: cursor_update
 *=============================================================================
 * DESCRIPTION:
 *   Updates the hardware VGA cursor position to match the software cursor.
 *=============================================================================*/
static void cursor_update(void) {
    uint16_t pos = row * VGA_WIDTH + col;
    outb(VGA_CTRL_REGISTER, 0x0F);
    outb(VGA_DATA_REGISTER, (uint8_t)(pos & 0xFF));
    outb(VGA_CTRL_REGISTER, 0x0E);
    outb(VGA_DATA_REGISTER, (uint8_t)((pos >> 8) & 0xFF));
}

/*=============================================================================
 * FUNCTION: cursor_enable
 *=============================================================================
 * DESCRIPTION:
 *   Enables the hardware VGA cursor (blinking underscore/block).
 *=============================================================================*/
static void cursor_enable(void) {
    outb(VGA_CTRL_REGISTER, 0x0A);
    outb(VGA_DATA_REGISTER, 0x00);
    outb(VGA_CTRL_REGISTER, 0x0B);
    outb(VGA_DATA_REGISTER, 0x0F);
}

/*=============================================================================
 * FUNCTION: console_clear
 *=============================================================================
 * DESCRIPTION:
 *   Clears the entire screen by filling it with spaces and resets the
 *   cursor to the top-left corner (0, 0). This is typically called during
 *   kernel initialization to start with a clean display.
 *
 * BEHAVIOR:
 *   1. Fills all 2,000 character cells (80 Ã— 25) with spaces
 *   2. Uses current attribute byte for all spaces
 *   3. Resets cursor position to (0, 0)
 *
 *============================================================================*/
void console_clear(void) {
    uint32_t flags = disable_interrupts();

    for (uint32_t y = 0; y < VGA_HEIGHT; ++y)
        for (uint32_t x = 0; x < VGA_WIDTH; ++x)
            vga_put_at(' ', attr, x, y);
    row = col = 0;
    cursor_enable();
    cursor_update();

    restore_interrupts(flags);
}

/*=============================================================================
 * FUNCTION: advance
 *=============================================================================
 * DESCRIPTION:
 *   Advances the cursor to the next character position after writing.
 *   Handles line wrapping (when reaching right edge) and scrolling
 *   (when reaching bottom of screen).
 *
 * BEHAVIOR:
 *   1. Increment column
 *   2. If column >= 80: wrap to next row (col = 0, row++)
 *   3. If row >= 25: scroll screen up and stay on row 24
 *
 * CURSOR MOVEMENT EXAMPLES:
 *   
 *   Normal advance (middle of line):
 *     Before: (col=40, row=10)
 *     After:  (col=41, row=10)
 *   
 *   Line wrap (at right edge):
 *     Before: (col=79, row=10)
 *     After:  (col=0, row=11)
 *   
 *   Scroll (at bottom-right):
 *     Before: (col=79, row=24)
 *     After:  (col=0, row=24)  [screen scrolled up]
 *
 * VISUAL DIAGRAM:
 *   
 *   Row 0:  [....................................] â†’ Row 1
 *   Row 1:  [....................................] â†’ Row 2
 *   ...
 *   Row 23: [....................................] â†’ Row 24
 *   Row 24: [...................X] â†’ scroll! â†’ Row 24 (cursor stays)
 *           â†‘                     â†‘
 *           col=19                wrap would go here,
 *                                 but scroll happens instead
 *
 *============================================================================*/
static void advance(void) {
    if (++col >= VGA_WIDTH) { col = 0; ++row; }
    if (row >= VGA_HEIGHT) { scroll(); row = VGA_HEIGHT - 1; }
    cursor_update();
}

/*=============================================================================
 * FUNCTION: console_backspace
 *=============================================================================
 * DESCRIPTION:
 *   Handles backspace by moving the cursor one position backward and clearing
 *   the character at that position. If at the start of a line, wraps to the
 *   end of the previous line. If at the top-left corner, does nothing.
 *
 * BEHAVIOR:
 *   1. Move cursor back one position (handle line wrapping)
 *   2. Clear the character at the new cursor position
 *   3. Update hardware cursor
 *
 * VISUAL EXAMPLE:
 *   Before: "Hello|" (cursor after 'o')
 *   After:  "Hell|"  (cursor after second 'l', 'o' erased)
 *
 *============================================================================*/
void console_backspace(void) {
    uint32_t flags = disable_interrupts();

    /* Only move back if not at start of screen */
    if (col > 0) {
        col--;
    } else if (row > 0) {
        /* Wrap to end of previous line */
        row--;
        col = VGA_WIDTH - 1;
    } else {
        /* At top-left corner, can't go back */
        restore_interrupts(flags);
        return;
    }

    /* Clear the character at the new cursor position */
    vga_put_at(' ', attr, col, row);

    /* Update hardware cursor */
    cursor_update();
    restore_interrupts(flags);
}

/*=============================================================================
 * FUNCTION: console_putc
 *=============================================================================
 * DESCRIPTION:
 *   Outputs a single character to the VGA console at the current cursor
 *   position. Handles newline (\n) specially by moving to the start of
 *   the next line. Automatically advances cursor and scrolls screen as needed.
 *
 * PARAMETERS:
 *   c - Character to display (0-255)
 *       - Printable ASCII (0x20-0x7E): Normal characters (A-Z, 0-9, etc.)
 *       - Newline (0x0A or '\n'): Move to next line
 *       - Other control chars: Displayed as-is (may show as symbols)
 *       - Extended ASCII (0x80-0xFF): Line drawing, special symbols
 *
 *============================================================================*/
void console_putc(char c) {
    /*=========================================================================
     * ARCHITECTURE (v1.13): Special Character Handling
     *
     * Handle control characters that affect cursor position:
     * - '\n' (newline): Move to start of next line
     * - '\r' (carriage return): Move to start of current line
     * - '\b' (backspace): Move cursor back one position and clear character
     *
     * This allows applications to use kprintf("\b \b") for backspace-erase
     * sequences without calling console_backspace() directly.
     *
     * RACE CONDITION FIX (v1.14):
     * Protect row/col state with interrupt disable/restore to prevent
     * corruption from concurrent ISR access causing repeating lines.
     *=======================================================================*/
    uint32_t flags = disable_interrupts();

    if (c == '\n') {
        col = 0; ++row;
        if (row >= VGA_HEIGHT) { scroll(); row = VGA_HEIGHT - 1; }
        cursor_update();
        restore_interrupts(flags);
        return;
    }

    if (c == '\r') {
        /* Carriage return: move to start of current line (don't advance row) */
        col = 0;
        cursor_update();
        restore_interrupts(flags);
        return;
    }

    if (c == '\b') {
        /* Backspace: move cursor back one position */
        if (col > 0) {
            col--;
        } else if (row > 0) {
            /* Wrap to end of previous line */
            row--;
            col = VGA_WIDTH - 1;
        }
        cursor_update();
        restore_interrupts(flags);
        return;
    }

    vga_put_at(c, attr, col, row);
    advance();
    restore_interrupts(flags);
}

/*=============================================================================
 * FUNCTION: console_puts
 *=============================================================================
 * DESCRIPTION:
 *   Outputs a null-terminated string to the console by repeatedly calling
 *   console_putc() for each character. This is the primary string output
 *   function used throughout the kernel.
 *
 * PARAMETERS:
 *   s - Pointer to null-terminated string (array of characters ending in \0)
 *       Must not be NULL (undefined behavior if NULL)
 *       Can contain newlines (\n) and other special characters
 *
 * NULL TERMINATOR:
 *   Strings must end with '\0' (null byte, value 0x00).
 *   If string is not null-terminated, will read past end of string
 *   until it finds a zero byte (undefined behavior, possible crash).
 *
 *============================================================================*/
void console_puts(const char* s) {
    /* ROBUSTNESS (v1.14): Null pointer check to prevent kernel crash */
    if (!s) {
        s = "(null)";
    }
    while (*s) console_putc(*s++);
}

/*=============================================================================
 * FUNCTION: console_put_hex32
 *=============================================================================
 * DESCRIPTION:
 *   Outputs a 32-bit unsigned integer in hexadecimal format with "0x" prefix.
 *   Always displays exactly 8 hex digits (with leading zeros if necessary).
 *   Used for displaying memory addresses, register values, and other hex data.
 *
 * PARAMETERS:
 *   v - 32-bit unsigned integer value to display
 *
 * OUTPUT FORMAT:
 *   "0x" followed by 8 uppercase hexadecimal digits
 *   
 *   Examples:
 *     v = 0          â†’ "0x00000000"
 *     v = 255        â†’ "0x000000FF"
 *     v = 4096       â†’ "0x00001000"
 *     v = 0xDEADBEEF â†’ "0xDEADBEEF"
 *     v = 0xFFFFFFFF â†’ "0xFFFFFFFF"
 *
 *============================================================================*/
void console_put_hex32(uint32_t v){
    static const char H[] = "0123456789ABCDEF";
    console_puts("0x");
    for (int i = 7; i >= 0; --i) console_putc(H[(v >> (i*4)) & 0xF]);
}

/*=============================================================================
 * FUNCTION: console_put_hex64
 *=============================================================================
 * DESCRIPTION:
 *   Outputs a 64-bit unsigned integer in hexadecimal format. If the high
 *   32 bits are zero, only displays 8 hex digits (same as 32-bit). Otherwise,
 *   displays full 16 hex digits. Always includes "0x" prefix.
 *
 * PARAMETERS:
 *   v - 64-bit unsigned integer value to display
 *
 * OUTPUT FORMAT:
 *   "0x" followed by 8 or 16 uppercase hexadecimal digits
 *   
 *   Examples:
 *     v = 0                    â†’ "0x00000000" (8 digits, high 32 bits zero)
 *     v = 0x123               â†’ "0x00000123" (8 digits)
 *     v = 0xFFFFFFFF          â†’ "0xFFFFFFFF" (8 digits)
 *     v = 0x100000000         â†’ "0x0000000100000000" (16 digits)
 *     v = 0x123456789ABCDEF0  â†’ "0x123456789ABCDEF0" (16 digits)
 *   
 *   Example: v = 0x123456789ABCDEF0
 *     High half (hi): 0x12345678
 *     Low half (lo):  0x9ABCDEF0
 *   
 *   Output: "0x" + digits(hi) + digits(lo)
 *         = "0x" + "12345678" + "9ABCDEF0"
 *         = "0x123456789ABCDEF0"
 *
 *============================================================================*/
void console_put_hex64(uint64_t v){
    uint32_t hi = (uint32_t)(v >> 32), lo = (uint32_t)v;
    if (hi) {
        static const char H[] = "0123456789ABCDEF";
        console_puts("0x");
        for (int i=7;i>=0;--i) console_putc(H[(hi>>(i*4))&0xF]);
        for (int i=7;i>=0;--i) console_putc(H[(lo>>(i*4))&0xF]);
    } else {
        console_put_hex32(lo);
    }
}

/*=============================================================================
 * FUNCTION: console_put_dec_u32
 *=============================================================================
 * DESCRIPTION:
 *   Outputs an unsigned 32-bit integer in decimal (base 10) format without
 *   any prefix. No leading zeros are displayed. Used for counters, sizes,
 *   and other numeric values where decimal representation is more natural.
 *
 * PARAMETERS:
 *   v - 32-bit unsigned integer value to display (0 to 4,294,967,295)
 *
 * OUTPUT FORMAT:
 *   Decimal digits without leading zeros (except value 0 displays as "0")
 *   
 *   Examples:
 *     v = 0          â†’ "0"
 *     v = 5          â†’ "5"
 *     v = 42         â†’ "42"
 *     v = 1000       â†’ "1000"
 *     v = 999999     â†’ "999999"
 *     v = 4294967295 â†’ "4294967295" (max 32-bit unsigned)
 *
 *============================================================================*/
void console_put_dec_u32(uint32_t v){
    char buf[10]; int i=0;
    if (!v) { console_putc('0'); return; }
    while (v) { buf[i++] = '0' + (v % 10); v /= 10; }
    while (i--) console_putc(buf[i]);
}

/*=============================================================================
 * FUNCTION: console_put_dec_i32
 *=============================================================================
 * DESCRIPTION:
 *   Outputs a signed 32-bit integer in decimal format. Negative values are
 *   displayed with a leading minus sign. Zero and positive values have no
 *   sign prefix. Uses console_put_dec_u32() for the actual digit output.
 *
 * PARAMETERS:
 *   v - 32-bit signed integer value to display (-2,147,483,648 to 2,147,483,647)
 *
 * OUTPUT FORMAT:
 *   Decimal digits with optional leading minus sign for negative values
 *   
 *   Examples:
 *     v = 0           â†’ "0"
 *     v = 42          â†’ "42"
 *     v = -42         â†’ "-42"
 *     v = 2147483647  â†’ "2147483647" (max positive 32-bit signed)
 *     v = -2147483648 â†’ "-2147483648" (max negative 32-bit signed)
 *
 *============================================================================*/
void console_put_dec_i32(int32_t v){
    if (v < 0) { console_putc('-'); console_put_dec_u32((uint32_t)(-v)); }
    else { console_put_dec_u32((uint32_t) v); }
}

/*=============================================================================
 * FUNCTION: console_putchar_at
 *=============================================================================
 * DESCRIPTION:
 *   Writes a character at a specific screen position without moving the
 *   cursor. This is useful for text editors and applications that need
 *   precise control over screen layout.
 *
 * PARAMETERS:
 *   c - Character to display
 *   x - Column position (0-79)
 *   y - Row position (0-24)
 *============================================================================*/
void console_putchar_at(char c, uint8_t x, uint8_t y) {
    if (x >= VGA_WIDTH || y >= VGA_HEIGHT) return;
    vga_put_at(c, attr, x, y);
}

/*=============================================================================
 * FUNCTION: console_set_cursor_pos
 *=============================================================================
 * DESCRIPTION:
 *   Sets the cursor position to specific coordinates and updates the
 *   hardware cursor. This allows applications to control where the next
 *   character will be written.
 *
 * PARAMETERS:
 *   x - Column position (0-79)
 *   y - Row position (0-24)
 *============================================================================*/
void console_set_cursor_pos(uint8_t x, uint8_t y) {
    uint32_t flags = disable_interrupts();

    if (x >= VGA_WIDTH) x = VGA_WIDTH - 1;
    if (y >= VGA_HEIGHT) y = VGA_HEIGHT - 1;

    col = x;
    row = y;
    cursor_update();

    restore_interrupts(flags);
}

