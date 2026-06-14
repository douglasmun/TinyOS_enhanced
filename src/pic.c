/*=============================================================================
 *  pic.c â€” 8259 Programmable Interrupt Controller Driver for TinyOS
 *=============================================================================*/

#include "kernel.h"
#include "pic.h"
#include <stdbool.h>

/*=============================================================================
 * SAFE I/O FUNCTIONS WITH MEMORY BARRIERS AND DELAYS
 * CRITICAL: Port 0x80 write ensures I/O serialization on modern CPUs
 *=============================================================================*/
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
 * safe_inb - Read byte from I/O port with delays and barriers
 * 
 * PARAMETERS:
 *   port - I/O port address
 * 
 * RETURN VALUE:
 *   Byte read from port
 * 
 */
static inline uint8_t safe_inb(uint16_t port) {
    uint8_t ret;
    __asm__ volatile(
        "inb %1, %0\n\t"       /* Input byte from port */
        "jmp 1f\n\t"           /* Delay: jump forward */
        "1: jmp 1f\n\t"        /* Delay: jump forward again */
        "1: nop"               /* Delay: no-op */
        : "=a"(ret)            /* Output: AL register â†’ ret */
        : "Nd"(port)           /* Input: Port */
        : "memory"             /* Clobber: Memory barrier */
    );
    return ret;
}

/*=============================================================================
 * FUNCTION: pic_remap
 *=============================================================================
 * 
 * PURPOSE:
 *   Remap the PIC interrupt vectors from default (0x08-0x0F, 0x70-0x77)
 *   to new locations (0x20-0x2F) to avoid conflict with CPU exceptions.
 * 
 * WHAT IT DOES:
 *   1. Save current interrupt masks
 *   2. Initialize master PIC (IRQ 0-7 â†’ vectors 0x20-0x27)
 *   3. Initialize slave PIC (IRQ 8-15 â†’ vectors 0x28-0x2F)
 *   4. Restore interrupt masks
 * 
 * WHEN TO CALL:
 *   Early in kernel initialization, BEFORE enabling interrupts (STI).
 *   After setting up IDT.
 *   
 *   Typical boot sequence:
 *     idt_init();       // Set up IDT with handlers
 *     pic_remap();      // Remap PIC to avoid conflicts â† HERE!
 *     pic_mask_all();   // Mask all IRQs
 *     pic_unmask(0);    // Enable specific IRQs
 *     sti();            // Enable interrupts
 * 
 */  
void pic_remap(void) {
    uint8_t a1, a2;
    unsigned long flags;

    /*=========================================================================
     * SECURITY FIX (AUDIT 7A): Atomic PIC Reconfiguration
     *
     * VULNERABILITY: Non-Atomic PIC Initialization
     *
     * PROBLEM: Race Condition During Hardware Reconfiguration
     * The PIC reconfiguration involves a multi-step initialization sequence
     * (ICW1-ICW4). If an interrupt occurs mid-sequence, PIC state corrupts.
     *
     * ATTACK SCENARIO:
     * 1. Kernel calls pic_remap() during initialization
     * 2. Timer interrupt (IRQ 0) fires after ICW1 sent but before ICW4
     * 3. PIC has not completed mode setup (8086 vs MCS-80/85)
     * 4. Interrupt acknowledgment reads undefined vector
     * 5. CPU jumps to random memory address → system crash
     *
     * TIMING WINDOW:
     * - PIC reconfiguration: ~10 I/O operations × 1-2 μs = 10-20 μs
     * - Timer interrupt period: 10 ms (100 Hz)
     * - Probability of collision: ~0.2% per boot
     * - Over 1000 reboots: ~86% chance of hitting race at least once
     *
     * FIX: Disable Interrupts During PIC Reconfiguration
     * - Save EFLAGS register (preserves original interrupt state)
     * - Clear IF flag (CLI instruction) → disable maskable interrupts
     * - Perform PIC reconfiguration atomically
     * - Restore original EFLAGS
     *
     * REFERENCES:
     * - Intel 8259A Datasheet: Initialization Command Words
     * - OSDev Wiki: PIC Initialization Sequence
     *=======================================================================*/

    /* SECURITY: Save interrupt state and disable interrupts atomically */
    __asm__ volatile(
        "pushf\n\t"           /* Push EFLAGS onto stack */
        "pop %0\n\t"          /* Pop into flags variable */
        "cli"                 /* Clear IF flag (disable interrupts) */
        : "=r"(flags)         /* Output: flags variable */
        :                     /* No inputs */
        : "memory"            /* Clobber: memory barrier */
    );

    /*
     * STEP 1: SAVE CURRENT INTERRUPT MASKS
     */
    a1 = safe_inb(0x21);  /* Master PIC mask */
    a2 = safe_inb(0xA1);  /* Slave PIC mask */

    /*
     * STEP 2: SEND ICW1 TO BOTH PICS
     */
    safe_outb(0x20, 0x11);  /* Master: ICW1 */
    safe_outb(0xA0, 0x11);  /* Slave: ICW1 */

    /*
     * STEP 3: SEND ICW2 TO BOTH PICS
     */
    safe_outb(0x21, 0x20);  /* Master: Vectors 0x20-0x27 */
    safe_outb(0xA1, 0x28);  /* Slave: Vectors 0x28-0x2F */

    /*
     * STEP 4: SEND ICW3 TO BOTH PICS
     */
    safe_outb(0x21, 0x04);  /* Master: Slave on IR2 */
    safe_outb(0xA1, 0x02);  /* Slave: Cascade identity = 2 */

    /*
     * STEP 5: SEND ICW4 TO BOTH PICS
     */
    safe_outb(0x21, 0x01);  /* Master: 8086 mode */
    safe_outb(0xA1, 0x01);  /* Slave: 8086 mode */

    /*
     * STEP 6: RESTORE INTERRUPT MASKS
     */
    safe_outb(0x21, a1);  /* Master: Restore mask */
    safe_outb(0xA1, a2);  /* Slave: Restore mask */

    /* SECURITY: Restore original interrupt state */
    __asm__ volatile(
        "push %0\n\t"         /* Push saved flags onto stack */
        "popf"                /* Pop into EFLAGS (restores IF if it was set) */
        :                     /* No outputs */
        : "r"(flags)          /* Input: saved flags */
        : "memory", "cc"      /* Clobbers: memory barrier, condition codes */
    );
}

/*=============================================================================
 * FUNCTION: pic_read_isr
 *=============================================================================
 *
 * PURPOSE:
 *   Read the In-Service Register (ISR) from the PIC to detect spurious
 *   interrupts. The ISR shows which IRQs are currently being serviced.
 *
 * PARAMETERS:
 *   irq - IRQ number (0-15)
 *
 * RETURN VALUE:
 *   true if IRQ bit is set in ISR (real interrupt)
 *   false if IRQ bit is NOT set in ISR (spurious interrupt)
 *
 * SPURIOUS INTERRUPT DETECTION:
 *   When the PIC generates a spurious interrupt (typically IRQ 7 or IRQ 15),
 *   the corresponding bit in the ISR will NOT be set. This function checks
 *   the ISR to distinguish real interrupts from spurious ones.
 *
 * MECHANISM:
 *   1. Send OCW3 (0x0B) to PIC command port to request ISR read
 *   2. Read ISR value from the same port
 *   3. Check if the IRQ bit is set
 *
 * WHY THIS MATTERS:
 *   Spurious interrupts must NOT receive EOI commands, as sending EOI
 *   for a spurious interrupt can corrupt the PIC's internal state and
 *   cause system instability or hangs.
 *
 */
bool pic_read_isr(uint8_t irq) {
    uint16_t port;
    uint8_t isr_value;
    uint8_t bit;

    /*
     * DETERMINE WHICH PIC AND BIT TO CHECK
     */
    if (irq < 8) {
        /* Master PIC (IRQ 0-7) */
        port = 0x20;
        bit = irq;
    } else {
        /* Slave PIC (IRQ 8-15) */
        port = 0xA0;
        bit = (uint8_t)(irq - 8);
    }

    /*
     * SEND OCW3 TO REQUEST ISR READ
     * OCW3 = 0x0B (binary: 00001011)
     *   Bit 0-1: 11 = Read ISR on next read
     *   Bit 2:   0  = (not used in this context)
     *   Bit 3:   1  = This is OCW3 (not OCW2)
     *   Bit 4-7: 0  = (reserved)
     */
    safe_outb(port, 0x0B);

    /*
     * READ ISR VALUE FROM SAME PORT
     */
    isr_value = safe_inb(port);

    /*
     * CHECK IF IRQ BIT IS SET
     */
    return (isr_value & (1u << bit)) != 0;
}

/*=============================================================================
 * FUNCTION: pic_eoi
 *=============================================================================
 *
 * PURPOSE:
 *   Send End-Of-Interrupt command to the PIC after handling an IRQ.
 *   This tells the PIC that interrupt handling is complete and it can
 *   accept new interrupts of the same or lower priority.
 *
 * PARAMETERS:
 *   irq - IRQ number (0-15)
 *
 * RETURN VALUE:
 *   None (void function)
 *
 */
void pic_eoi(uint8_t irq) {
    /*
     * CHECK IF SLAVE IRQ (8-15)
     */
    if (irq >= 8) {
        /*
         * SEND EOI TO SLAVE PIC
         */
        safe_outb(0xA0, 0x20);
    }

    /*
     * SEND EOI TO MASTER PIC
     */
    safe_outb(0x20, 0x20);
}

