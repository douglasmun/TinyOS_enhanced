/*=============================================================================
 *  idt.h â€” TinyOS IDT descriptors and initialization
 *============================================================================*/
#ifndef TINYOS_IDT_H
#define TINYOS_IDT_H
#include "kernel.h"


struct PACKED idt_ptr {
    uint16_t limit;
    uint32_t base;
};

struct idt_entry {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t zero;       // Must be 0 for 32-bit x86 IDT
    uint8_t type_attr;
    uint16_t offset_high;
} __attribute__((packed));


// Interrupt register state
struct regs {
    uint32_t gs, fs, es, ds;
    uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax;
    uint32_t int_no, err_code;
    uint32_t eip, cs, eflags, useresp, ss;
};

void idt_init(void);

/* IDT array (defined in idt.c) */
extern struct idt_entry idt[256];

/* Forward declaration for preemptive scheduling */
struct interrupt_regs;

/* Called by assembly stubs - receives pointer to interrupt stack frame */
void isr_common_handler(struct interrupt_regs* regs);

// Exception handlers
void default_handler(void);
void divide_by_zero_handler(void);
void invalid_opcode_handler(void);
void double_fault_handler(void);
void general_protection_fault_handler(void);
void page_fault_handler_asm(void);
void page_fault_handler(struct regs* r);

#endif
