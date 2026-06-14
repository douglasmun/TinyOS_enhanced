/*=============================================================================
 *  serial.c â€” Serial Port (UART) Driver for TinyOS
 *=============================================================================*/
#include "kernel.h"
#include "serial.h"

/*=============================================================================
 * SAFE I/O FUNCTIONS WITH MEMORY BARRIERS AND SERIALIZATION
 *=============================================================================
 * SECURITY FIX (AUDIT 5A): I/O Serialization for Serial Port Operations
 *
 * VULNERABILITY: Missing I/O Serialization
 *
 * OLD CODE (VULNERABLE):
 * Simple outb/inb with no barriers or delays. On modern out-of-order CPUs,
 * I/O operations may be reordered, cached, or combined, causing:
 * - UART register writes to arrive out of order
 * - Configuration changes to take effect before data writes
 * - Data corruption, garbled serial output
 * - Intermittent hardware failures (works in QEMU, fails on real hardware)
 *
 * PRODUCTION FAILURE SCENARIO:
 * 1. Kernel writes to UART Line Control Register (LCR)
 * 2. CPU reorders and executes data write BEFORE LCR write
 * 3. UART receives data with wrong configuration (wrong baud, parity)
 * 4. Output is garbled or lost
 * 5. Debugging becomes impossible (serial console broken)
 *
 * FIX: Use same I/O serialization as pic.c (project standard)
 * - Write to port 0x80 after each outb (I/O serialization barrier)
 * - Add delay jumps to ensure operations complete
 * - Memory barrier clobber prevents compiler reordering
 *
 * WHY PORT 0x80:
 * - Port 0x80 is historically the POST diagnostic port (unused on modern PCs)
 * - Writing to it has NO side effects (safe dummy write)
 * - Forces CPU to complete all pending I/O before continuing
 * - Industry-standard technique used by Linux, BSD, etc.
 *===========================================================================*/

/**
 * safe_outb - Write byte to I/O port with serialization barriers
 *
 * PARAMETERS:
 *   port  - I/O port address (0x0000-0xFFFF)
 *   value - Byte value to write
 *
 * GUARANTEES:
 *   - Write completes before function returns
 *   - No reordering with surrounding I/O operations
 *   - Safe for hardware register programming
 */
static inline void safe_outb(uint16_t port, uint8_t value) {
    __asm__ volatile(
        "outb %0, %1\n\t"      /* Output byte to port */
        "jmp 1f\n\t"           /* Delay: jump forward */
        "1: jmp 1f\n\t"        /* Delay: jump forward again */
        "1: outb %%al, $0x80"  /* I/O serialization barrier (port 0x80) */
        :                      /* No output operands */
        : "a"(value),          /* Input: AL register = value */
          "Nd"(port)           /* Input: Port (immediate or DX) */
        : "memory"             /* Clobber: Memory barrier */
    );
}

/**
 * safe_inb - Read byte from I/O port with serialization barriers
 *
 * PARAMETERS:
 *   port - I/O port address (0x0000-0xFFFF)
 *
 * RETURN VALUE:
 *   Byte read from port
 *
 * GUARANTEES:
 *   - Read completes before function returns
 *   - Value reflects hardware state at call time (not cached/speculative)
 *   - Safe for status register polling
 */
static inline uint8_t safe_inb(uint16_t port) {
    uint8_t ret;
    __asm__ volatile(
        "inb %1, %0\n\t"       /* Input byte from port */
        "jmp 1f\n\t"           /* Delay: jump forward */
        "1: jmp 1f\n\t"        /* Delay: jump forward again */
        "1: nop"               /* Delay: no-op */
        : "=a"(ret)            /* Output: AL register → ret */
        : "Nd"(port)           /* Input: Port */
        : "memory"             /* Clobber: Memory barrier */
    );
    return ret;
}

/*=============================================================================
 * CONSTANTS
 *=============================================================================*/

/**
 * COM1 - I/O base address for COM1 serial port
 * 
 * Standard PC I/O addresses:
 *   COM1: 0x3F8 (IRQ4) â† We use this
 *   COM2: 0x2F8 (IRQ3)
 *   COM3: 0x3E8 (IRQ4, shares with COM1)
 *   COM4: 0x2E8 (IRQ3, shares with COM2)
 * 
 * Register offsets from base:
 *   +0: Data register (or divisor latch low)
 *   +1: Interrupt Enable Register (or divisor latch high)
 *   +2: Interrupt ID / FIFO Control Register
 *   +3: Line Control Register
 *   +4: Modem Control Register
 *   +5: Line Status Register
 *   +6: Modem Status Register
 *   +7: Scratch Register
 */
#define COM1 0x3F8


/*=============================================================================
 * FUNCTION: serial_init
 *=============================================================================*/
void serial_init(void) {
    /*
     * STEP 1: DISABLE ALL INTERRUPTS
     */
    safe_outb(COM1 + 1, 0x00);

    /*
     * STEP 2: ENABLE DLAB (Divisor Latch Access Bit)
     */
    safe_outb(COM1 + 3, 0x80);

    /*
     * STEP 3: SET BAUD RATE DIVISOR (LOW BYTE)
     */
    safe_outb(COM1 + 0, 0x01);

    /*
     * STEP 4: SET BAUD RATE DIVISOR (HIGH BYTE)
     */
    safe_outb(COM1 + 1, 0x00);

    /*
     * STEP 5: CONFIGURE LINE (8N1) AND DISABLE DLAB
     */
    safe_outb(COM1 + 3, 0x03);

    /*
     * STEP 6: ENABLE FIFO AND CLEAR BUFFERS
     */
    safe_outb(COM1 + 2, 0xC7);

    /*
     * STEP 7: CONFIGURE MODEM CONTROL
     */
    safe_outb(COM1 + 4, 0x0B);
}

/*=============================================================================
 * FUNCTION: tx_ready
 *=============================================================================*/
static int tx_ready(void) {
    /*
     * Read Line Status Register (COM1+5).
     * 
     * LSR bits:
     *   Bit 0: Data ready (receive buffer has data)
     *   Bit 1: Overrun error
     *   Bit 2: Parity error
     *   Bit 3: Framing error
     *   Bit 4: Break interrupt
     *   Bit 5: Transmitter holding register empty â† THIS ONE!
     *   Bit 6: Transmitter empty (holding and shift registers)
     *   Bit 7: FIFO error
     * 
     * We mask with 0x20 (00100000 binary) to isolate bit 5.
     * 
     * Result:
     *   Non-zero if bit 5 is set (transmitter ready)
     *   Zero if bit 5 is clear (transmitter busy)
     * 
     * Example:
     *   LSR = 0x60 (01100000) â†’ 0x60 & 0x20 = 0x20 (ready!)
     *   LSR = 0x40 (01000000) â†’ 0x40 & 0x20 = 0x00 (busy)
     */
    return safe_inb(COM1 + 5) & 0x20;
}

/*=============================================================================
 * FUNCTION: rx_ready
 *=============================================================================*/
static int rx_ready(void) {
    /*
     * Read Line Status Register (COM1+5) and check bit 0.
     *
     * Bit 0 = Data ready (receive buffer has data)
     *
     * Result:
     *   Non-zero if data is available to read
     *   Zero if no data available
     */
    return safe_inb(COM1 + 5) & 0x01;
}

/*=============================================================================
 * FUNCTION: serial_putc
 *=============================================================================
 *
 * PURPOSE:
 *   Transmit a single character over the serial port.
 *   Automatically converts Unix-style newlines (LF) to CR+LF.
 *
 * EXAMPLE USAGE:
 *   serial_putc('H');   // Send 'H'
 *   serial_putc('\n');  // Send CR+LF (newline)
 */
void serial_putc(char c) {
    /*
     * LINE ENDING CONVERSION
     */
    if (c == '\n') {
        serial_putc('\r');  /* Send CR before LF */
    }

    /*=========================================================================
     * SECURITY FIX (AUDIT 5A): Bounded Timeout for UART Transmit
     *=========================================================================
     * VULNERABILITY: Infinite Spin-Loop Denial of Service
     *
     * OLD CODE (VULNERABLE):
     * while (!tx_ready()) {}
     *
     * PROBLEM: If UART hardware fails or is misconfigured, this spins forever.
     * The CPU is stuck in kernel mode with interrupts disabled (or high
     * priority), making the entire system unresponsive.
     *
     * ATTACK SCENARIO:
     * - Attacker disables serial port in BIOS or via hardware tampering
     * - Kernel tries to write serial debug message
     * - System hangs completely in infinite loop
     * - No watchdog, no timeout, no recovery
     *
     * PRODUCTION FAILURE MODES:
     * 1. Hardware failure: UART chip damaged or disconnected
     * 2. BIOS misconfiguration: Serial port disabled or wrong base address
     * 3. Virtual machine: QEMU/VMware serial device misconfigured
     * 4. Race condition: Serial device removed during runtime (USB-to-serial)
     *
     * FIX: Add bounded timeout (100,000 iterations ≈ 10-100ms on typical CPU)
     * After timeout, silently drop the character and return. Better to lose
     * debug output than hang the entire kernel.
     *
     * TIMEOUT VALUE RATIONALE:
     * - 115200 baud = ~11,520 bytes/sec = ~86 µs per byte
     * - 100,000 iterations ≈ 10-100ms (CPU speed dependent)
     * - Far more than needed for legitimate UART delay
     * - Small enough to detect hardware failure quickly
     *=======================================================================*/

    /*
     * WAIT FOR TRANSMITTER READY (with bounded timeout)
     */
    #define SERIAL_TIMEOUT 100000

    uint32_t timeout = 0;
    while (!tx_ready()) {
        timeout++;
        if (timeout >= SERIAL_TIMEOUT) {
            /* Hardware failure or misconfiguration - drop character and return */
            return;
        }
    }

    /*
     * TRANSMIT BYTE
     * Write character to data register (COM1+0).
     *
     */
    safe_outb(COM1, (uint8_t)c);
}

/*=============================================================================
 * FUNCTION: serial_puts
 *=============================================================================
 * 
 * PURPOSE:
 *   Transmit a null-terminated string over the serial port.
 *   Convenience wrapper around serial_putc().
 * 
 * EXAMPLE USAGE:
 *   serial_puts("Hello, World!\n");
 *   serial_puts("Kernel initializing...\n");
 */
void serial_puts(const char* s) {
    /*
     * ITERATE THROUGH STRING
     */
    while (*s) {
        serial_putc(*s++);
    }
}

/*=============================================================================
 * FUNCTION: serial_getc
 *=============================================================================
 *
 * PURPOSE:
 *   Read a single character from the serial port.
 *   Blocks until data is available.
 *
 * RETURN VALUE:
 *   Character read from serial port
 *
 * EXAMPLE USAGE:
 *   char c = serial_getc();  // Wait for and read one character
 */
char serial_getc(void) {
    /* Wait for data to be available */
    while (!rx_ready()) {
        __asm__ volatile("pause");  /* CPU hint: spin-wait loop */
    }

    /* Read and return the character */
    return safe_inb(COM1);
}

/**
 * serial_has_data - Check if serial data is available for reading
 *
 * RETURN VALUE:
 *   Non-zero if data is available
 *   Zero if no data available
 *
 * EXAMPLE USAGE:
 *   if (serial_has_data()) {
 *       char c = serial_getc();  // Won't block
 *   }
 */
int serial_has_data(void) {
    return rx_ready();
}

