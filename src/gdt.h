/*=============================================================================
 * gdt.h - Global Descriptor Table for User Mode Support
 * FIXED: Segment selectors match GRUB's layout
 *============================================================================*/
#ifndef GDT_H
#define GDT_H

#include <stdint.h>

/*-----------------------------------------------------------------------------
 * Segment Selector Definitions
 * CRITICAL: Must match GRUB's GDT layout that IDT already uses!
 *-----------------------------------------------------------------------------*/
#define SEG_NULL        0x00    // Null segment
#define SEG_RESERVED    0x08    // Reserved (unused, maintains GRUB layout)
#define SEG_KCODE       0x10    // Kernel code segment (Ring 0) - matches IDT!
#define SEG_KDATA       0x18    // Kernel data segment (Ring 0)

/*
 * WARNING: User segment selectors are calculated DYNAMICALLY in gdt.c
 * based on GRUB's GDT size! Do NOT use hardcoded values!
 *
 * Instead, use these extern variables from gdt.c:
 */
extern uint16_t user_code_selector;  // Calculated at runtime
extern uint16_t user_data_selector;  // Calculated at runtime
extern uint16_t tss_selector;        // Calculated at runtime

/*-----------------------------------------------------------------------------
 * GDT Entry Structure (8 bytes)
 *-----------------------------------------------------------------------------*/
struct gdt_entry {
    uint16_t limit_low;     // Limit bits 0-15
    uint16_t base_low;      // Base bits 0-15
    uint8_t  base_mid;      // Base bits 16-23
    uint8_t  access;        // Access flags
    uint8_t  granularity;   // Granularity and limit bits 16-19
    uint8_t  base_high;     // Base bits 24-31
} __attribute__((packed));

/*-----------------------------------------------------------------------------
 * GDT Pointer Structure
 *-----------------------------------------------------------------------------*/
struct gdt_ptr {
    uint16_t limit;         // Size of GDT - 1
    uint32_t base;          // Address of first GDT entry
} __attribute__((packed));

/*-----------------------------------------------------------------------------
 * Task State Segment (TSS) Structure
 * Used for privilege level switching (Ring 3 -> Ring 0)
 *-----------------------------------------------------------------------------*/
struct tss_entry {
    uint32_t prev_tss;      // Previous TSS (unused in single-task)
    uint32_t esp0;          // Kernel stack pointer (Ring 0)
    uint32_t ss0;           // Kernel stack segment (Ring 0)
    uint32_t esp1;          // Ring 1 stack (unused)
    uint32_t ss1;           // Ring 1 segment (unused)
    uint32_t esp2;          // Ring 2 stack (unused)
    uint32_t ss2;           // Ring 2 segment (unused)
    uint32_t cr3;           // Page directory base
    uint32_t eip;           // Instruction pointer
    uint32_t eflags;        // Flags register
    uint32_t eax;           // General purpose registers
    uint32_t ecx;
    uint32_t edx;
    uint32_t ebx;
    uint32_t esp;           // User stack pointer
    uint32_t ebp;           // User base pointer
    uint32_t esi;
    uint32_t edi;
    uint32_t es;            // Segment registers
    uint32_t cs;
    uint32_t ss;
    uint32_t ds;
    uint32_t fs;
    uint32_t gs;
    uint32_t ldt;           // LDT selector (unused)
    uint16_t trap;          // Debug trap flag
    uint16_t iomap_base;    // I/O map base address
} __attribute__((packed));

/*-----------------------------------------------------------------------------
 * GDT Access Byte Flags
 *-----------------------------------------------------------------------------*/
#define GDT_ACCESS_PRESENT      0x80    // Present bit
#define GDT_ACCESS_RING0        0x00    // Ring 0 (kernel)
#define GDT_ACCESS_RING3        0x60    // Ring 3 (user)
#define GDT_ACCESS_EXECUTABLE   0x08    // Code segment
#define GDT_ACCESS_RW           0x02    // Readable (code) / Writable (data)
#define GDT_ACCESS_ACCESSED     0x01    // Accessed bit

// Common combinations
#define GDT_KCODE_ACCESS    (GDT_ACCESS_PRESENT | GDT_ACCESS_RING0 | \
                             GDT_ACCESS_EXECUTABLE | GDT_ACCESS_RW)
#define GDT_KDATA_ACCESS    (GDT_ACCESS_PRESENT | GDT_ACCESS_RING0 | \
                             GDT_ACCESS_RW)


// Previously we includes 0x04 for the conforming bit.
// Now, we need ro remove the 0x04 (conforming bit) and
// Change from conforming to non-conforming user code
/*
#define GDT_UCODE_ACCESS    (GDT_ACCESS_PRESENT | GDT_ACCESS_RING3 | \
                             GDT_ACCESS_EXECUTABLE | GDT_ACCESS_RW)
*/

// User mode segments
#define GDT_UCODE_ACCESS 0xFB  // 1111 1011 - Present=1, DPL=3, Code=1, Non-conforming=0, Readable=1
#define GDT_UDATA_ACCESS 0xF3  // 1111 0011 - Present=1, DPL=3, Data=0, Writable=1, Accessed=1

#define GDT_TSS_ACCESS      (GDT_ACCESS_PRESENT | 0x09) // Available 32-bit TSS

/*-----------------------------------------------------------------------------
 * GDT Granularity Byte Flags
 *-----------------------------------------------------------------------------*/
#define GDT_GRAN_4K         0x80    // 4K page granularity
#define GDT_GRAN_32BIT      0x40    // 32-bit protected mode
#define GDT_GRAN_LIMIT_MASK 0x0F    // Upper 4 bits of limit

/*-----------------------------------------------------------------------------
 * Function Prototypes
 *-----------------------------------------------------------------------------*/
void gdt_init(void);
void tss_load(void);
void gdt_set_tss_descriptor(int num, uint32_t base, uint32_t limit);

/*=============================================================================
 * SECURITY FIX (Issue 12.2): TSS Management Centralized in tss.c
 *
 * IMPORTANT: tss_set_kernel_stack() has been REMOVED from gdt.c/gdt.h and
 * moved to tss.c/tss.h for proper encapsulation and validation.
 *
 * Old (buggy) code had TWO separate TSS structures:
 * 1. struct tss_entry tss in gdt.c (UNUSED, but tss_set_kernel_stack modified it!)
 * 2. tss_t tss in tss.c (ACTUAL TSS loaded into CPU)
 *
 * Result: Scheduler called gdt.c:tss_set_kernel_stack(), which updated the
 * WRONG TSS structure! The CPU was still using the old esp0 value from tss.c.
 *
 * Fix: Single source of truth in tss.c with validation.
 * Use: #include "tss.h" and call tss_set_kernel_stack()
 *===========================================================================*/

void verify_gdt_loaded(void);
void verify_gdt_entries(void);

// Your existing GDT functions...
void switch_to_user_mode(uint32_t user_entry, uint32_t user_stack);

void debug_user_switch(uint32_t eip, uint32_t cs, uint32_t ss);
void debug_enter_user_mode(uint32_t func, uint32_t stack, uint16_t code_sel, uint16_t data_sel);
void debug_user_segments(void);

#endif // GDT_H
