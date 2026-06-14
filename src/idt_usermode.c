/*=============================================================================
 * idt_usermode.c - Additional IDT setup for user mode system calls
 *
 * This file adds the system call interrupt (0x80) to the existing IDT.
 * Call this after idt_init() to enable system calls.
 *
 * Uses the kernel code segment selector 0x10 (SEG_KCODE in GRUB's layout),
 * matching idt_set_gate() in idt.c. Note 0x08 is SEG_RESERVED here, NOT the
 * "standard" kernel code segment.
 *============================================================================*/
#include "idt.h"  // This should contain struct idt_entry definition
#include "kprintf.h"
#include "syscall.h"


// External functions
extern void syscall_stub(void);    // syscall_stub from syscall.S

/*-----------------------------------------------------------------------------
 * Set IDT Gate with DPL (Descriptor Privilege Level)
 *
 * Uses kernel code segment selector 0x10 (GRUB's non-standard layout):
 * - 0x00: Null descriptor
 * - 0x08: Reserved (SEG_RESERVED, unused)
 * - 0x10: Kernel code segment (SEG_KCODE)
 * - 0x18: Kernel data segment (SEG_KDATA)
 *
 * The DPL (Descriptor Privilege Level) field allows user mode (Ring 3) to
 * invoke this interrupt via INT instruction. Without DPL=3, INT 0x80 from
 * user mode would cause #GP fault.
 *
 * CRITICAL: Selector MUST point to a code segment for interrupt gates.
 *---------------------------------------------------------------------------*/
static void idt_set_gate_dpl(int vec, void (*fn)(void), uint8_t dpl) {
    uint32_t addr = (uint32_t)fn;
    idt[vec].offset_low  = (uint16_t)(addr & 0xFFFF);
    idt[vec].selector    = 0x10;    /* GRUB's kernel code segment (non-standard) */
    idt[vec].zero        = 0;       /* Must be 0 for 32-bit x86 */
    idt[vec].type_attr   = 0x8E | (dpl << 5);  /* Present, DPL set */
    idt[vec].offset_high = (uint16_t)((addr >> 16) & 0xFFFF);
}

/*
// Old version with separate flags parameter (not needed)
static void idt_set_gate_dpl(int vec, void (*fn)(void), uint8_t flags, uint8_t dpl) {
    extern struct idt_entry idt[256];

    uint32_t addr = (uint32_t)fn;
    idt[vec].offset_low  = (uint16_t)(addr & 0xFFFF);
    idt[vec].selector    = 0x10;
    idt[vec].zero        = 0;        // Must be 0 for 32-bit x86
    idt[vec].type_attr   = flags | (dpl << 5);
    idt[vec].offset_high = (uint16_t)((addr >> 16) & 0xFFFF);
}
*/


/*-----------------------------------------------------------------------------
 * Initialize System Call Support
 * Sets up INT 0x80 for system calls with DPL=3 (user mode can call)
 *-----------------------------------------------------------------------------*/
void idt_setup_syscall(void) {
    // kprintf("Setting up system call interrupt (INT 0x80)...\n");
    
    // Set up system call gate with DPL=3 (user accessible)
    idt_set_gate_dpl(0x80, syscall_stub, 3);  // ← FIXED: Only 3 arguments!
    
    // kprintf("System call interrupt installed at vector 0x80\n");
    // kprintf("User mode programs can now make system calls!\n");
}
