/*=============================================================================
 * tss.h - Task State Segment for x86 Protected Mode
 *=============================================================================
 * Provides IST (Interrupt Stack Table) support for Double Fault handling.
 *
 * SECURITY BENEFITS:
 * - Dedicated stack for Double Fault prevents stack corruption cascades
 * - Enables reliable exception reporting even when main stack is corrupted
 * - Critical for diagnosing kernel bugs and security vulnerabilities
 *
 * x86 ARCHITECTURE NOTE:
 * Modern x86 doesn't use hardware task switching, but TSS is still required
 * for privilege level changes (ring 3 -> ring 0) and dedicated exception stacks.
 *=============================================================================*/
#pragma once

#include <stdint.h>

/*=============================================================================
 * TSS STRUCTURE (x86 32-bit Protected Mode)
 *=============================================================================*/
typedef struct {
    uint32_t prev_tss;      /* Previous TSS selector (unused in modern systems) */
    uint32_t esp0;          /* Stack pointer for ring 0 (kernel) */
    uint32_t ss0;           /* Stack segment for ring 0 */
    uint32_t esp1;          /* Stack pointer for ring 1 (unused) */
    uint32_t ss1;           /* Stack segment for ring 1 */
    uint32_t esp2;          /* Stack pointer for ring 2 (unused) */
    uint32_t ss2;           /* Stack segment for ring 2 */
    uint32_t cr3;           /* Page directory base (for hardware task switching) */
    uint32_t eip;           /* Instruction pointer */
    uint32_t eflags;        /* CPU flags */
    uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi;  /* General registers */
    uint32_t es, cs, ss, ds, fs, gs;  /* Segment registers */
    uint32_t ldt;           /* LDT selector (unused) */
    uint16_t trap;          /* Debug trap flag */
    uint16_t iomap_base;    /* I/O map base address (offset from TSS base) */
} __attribute__((packed)) tss_t;

/*=============================================================================
 * TSS API
 *=============================================================================*/

/**
 * @brief Initialize Task State Segment
 *
 * Sets up TSS with:
 * - Kernel stack (esp0/ss0) for ring 3 -> ring 0 transitions
 * - Double Fault stack (for exception handling)
 */
void tss_init(void);

/**
 * @brief Get current TSS
 * @return Pointer to TSS structure
 */
tss_t* tss_get(void);

/**
 * @brief Get top of dedicated Double Fault stack
 * @return Address of double fault stack top
 */
uint32_t tss_get_double_fault_stack_top(void);

/**
 * @brief Update kernel stack pointer in TSS (for task switching)
 * @param stack_top Top of kernel stack for current task
 *
 * SECURITY FIX (Issue 12.2): Centralized esp0 update with validation
 *
 * CRITICAL: This function is called by the scheduler during context switches
 * to update the TSS esp0 field, which specifies the kernel stack to use when
 * transitioning from ring 3 (user mode) to ring 0 (kernel mode) via interrupts
 * or syscalls.
 *
 * VALIDATION: Performs bounds checking to prevent stack pointer corruption:
 * - Rejects NULL pointers
 * - Rejects obviously invalid addresses (< 1 MB, likely in .text/.data)
 * - Ensures 16-byte alignment (required by x86 ABI)
 *
 * ATTACK PREVENTION:
 * - Corrupted esp0 could cause kernel to use attacker-controlled stack
 * - Invalid esp0 could cause triple fault (unrecoverable crash)
 * - Misaligned esp0 could cause SSE/AVX instruction faults
 */
void tss_set_kernel_stack(uint32_t stack_top);
