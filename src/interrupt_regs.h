/*=============================================================================
 * interrupt_regs.h - Interrupt Stack Frame for Preemptive Scheduling
 *
 * This structure represents the complete CPU state saved during an interrupt.
 * Used for preemptive multitasking with iretd-based context switching.
 *============================================================================*/
#pragma once

#include <stdint.h>
#include <stddef.h>  /* For offsetof() macro */

/*=============================================================================
 * INTERRUPT STACK FRAME STRUCTURE
 *
 * This matches the stack layout created by ISR stubs in isr.S:
 * 1. CPU pushes: EIP, CS, EFLAGS, [ESP, SS if privilege change]
 * 2. ISR stub pushes: vector, error_code
 * 3. ISR common pushes: all registers via pusha
 *
 * When we modify this structure and return with iret, the CPU restores
 * the modified state - this is how preemptive scheduling works!
 *============================================================================*/
typedef struct interrupt_regs {
    /* Pushed by pusha (in order) */
    uint32_t edi;
    uint32_t esi;
    uint32_t ebp;
    uint32_t esp_dummy;     /* ESP value before pusha (not used) */
    uint32_t ebx;
    uint32_t edx;
    uint32_t ecx;
    uint32_t eax;

    /* Pushed by isr_common (segment registers) */
    uint32_t gs;
    uint32_t fs;
    uint32_t es;
    uint32_t ds;

    /* Pushed by ISR stub */
    uint32_t vector;        /* Interrupt vector number */
    uint32_t err_code;      /* Error code (0 for most interrupts) */

    /* Pushed by CPU automatically during interrupt */
    uint32_t eip;           /* Instruction pointer */
    uint32_t cs;            /* Code segment */
    uint32_t eflags;        /* CPU flags */

    /* Only pushed by CPU if privilege level changes (ring 3 -> ring 0) */
    uint32_t useresp;       /* User ESP (only if privilege change) */
    uint32_t ss;            /* Stack segment (only if privilege change) */
} __attribute__((packed)) interrupt_regs_t;

/*=============================================================================
 * STATIC ASSERTIONS: Verify struct layout matches assembly code expectations
 *
 * CRITICAL SECURITY: The assembly code in isr.S makes hard-coded assumptions
 * about field offsets. If the compiler changes the struct layout (e.g., due
 * to optimization flags, pragma pack, or alignment changes), the assembly
 * code will access WRONG memory locations, causing catastrophic corruption.
 *
 * These compile-time assertions catch layout mismatches IMMEDIATELY, preventing
 * silent data corruption that would be extremely difficult to debug.
 *
 * Expected layout (matching isr.S pusha, stub pushes, and CPU pushes):
 *   Offset 0:  EDI (first pushed by pusha)
 *   Offset 32: vector (pushed by ISR stub)
 *   Offset 40: EIP (pushed by CPU)
 *============================================================================*/
_Static_assert(offsetof(interrupt_regs_t, edi) == 0,
               "interrupt_regs_t.edi must be at offset 0 (pusha first)");
_Static_assert(offsetof(interrupt_regs_t, esi) == 4,
               "interrupt_regs_t.esi must be at offset 4");
_Static_assert(offsetof(interrupt_regs_t, ebp) == 8,
               "interrupt_regs_t.ebp must be at offset 8");
_Static_assert(offsetof(interrupt_regs_t, esp_dummy) == 12,
               "interrupt_regs_t.esp_dummy must be at offset 12");
_Static_assert(offsetof(interrupt_regs_t, ebx) == 16,
               "interrupt_regs_t.ebx must be at offset 16");
_Static_assert(offsetof(interrupt_regs_t, edx) == 20,
               "interrupt_regs_t.edx must be at offset 20");
_Static_assert(offsetof(interrupt_regs_t, ecx) == 24,
               "interrupt_regs_t.ecx must be at offset 24");
_Static_assert(offsetof(interrupt_regs_t, eax) == 28,
               "interrupt_regs_t.eax must be at offset 28 (pusha last)");
_Static_assert(offsetof(interrupt_regs_t, gs) == 32,
               "interrupt_regs_t.gs must be at offset 32");
_Static_assert(offsetof(interrupt_regs_t, fs) == 36,
               "interrupt_regs_t.fs must be at offset 36");
_Static_assert(offsetof(interrupt_regs_t, es) == 40,
               "interrupt_regs_t.es must be at offset 40");
_Static_assert(offsetof(interrupt_regs_t, ds) == 44,
               "interrupt_regs_t.ds must be at offset 44");
_Static_assert(offsetof(interrupt_regs_t, vector) == 48,
               "interrupt_regs_t.vector must be at offset 48 (stub push 1)");
_Static_assert(offsetof(interrupt_regs_t, err_code) == 52,
               "interrupt_regs_t.err_code must be at offset 52 (stub push 2)");
_Static_assert(offsetof(interrupt_regs_t, eip) == 56,
               "interrupt_regs_t.eip must be at offset 56 (CPU push 1)");
_Static_assert(offsetof(interrupt_regs_t, cs) == 60,
               "interrupt_regs_t.cs must be at offset 60 (CPU push 2)");
_Static_assert(offsetof(interrupt_regs_t, eflags) == 64,
               "interrupt_regs_t.eflags must be at offset 64 (CPU push 3)");
_Static_assert(offsetof(interrupt_regs_t, useresp) == 68,
               "interrupt_regs_t.useresp must be at offset 68 (CPU push 4)");
_Static_assert(offsetof(interrupt_regs_t, ss) == 72,
               "interrupt_regs_t.ss must be at offset 72 (CPU push 5)");

/* Total size check: 19 fields * 4 bytes = 76 bytes */
_Static_assert(sizeof(interrupt_regs_t) == 76,
               "interrupt_regs_t must be exactly 76 bytes (19 fields * 4 bytes)");
