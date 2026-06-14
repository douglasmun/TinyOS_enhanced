/*=============================================================================
 * tss.c - Task State Segment Implementation
 *=============================================================================*/
#include "tss.h"
#include "gdt.h"       /* For gdt_set_tss_descriptor() and tss_selector */
#include "kprintf.h"
#include "util.h"      /* For memset */

/*=============================================================================
 * DOUBLE FAULT DEDICATED STACK
 *
 * CRITICAL: This stack is used ONLY by the Double Fault handler.
 * If the main kernel stack is corrupted, this dedicated stack ensures
 * we can still safely handle the exception and print diagnostics.
 *
 * SIZE: 8 KiB should be sufficient for exception handling
 *
 * EXPORTED: The stack array itself is exported for direct access from assembly.
 * This avoids needing to call a function (which uses the stack!) to get the address.
 *=============================================================================*/
#define DOUBLE_FAULT_STACK_SIZE 8192
uint8_t double_fault_stack[DOUBLE_FAULT_STACK_SIZE] __attribute__((aligned(16)));
const uint32_t double_fault_stack_size = DOUBLE_FAULT_STACK_SIZE;

/*=============================================================================
 * TSS INSTANCE
 *
 * SECURITY FIX (Issue 12.2): TSS Hardening
 *
 * CRITICAL: Task State Segment must be properly aligned and sized to prevent:
 * 1. Page-spanning corruption (TSS split across two pages)
 * 2. GDT limit violations (CPU reads garbage beyond TSS)
 * 3. Buffer overflow attacks (corrupting esp0 stack pointer)
 *
 * ALIGNMENT: Page-aligned (4096 bytes) instead of 16-byte aligned
 * - Ensures TSS does not span multiple pages
 * - Simplifies memory protection (entire page can be made read-only if needed)
 * - Prevents partial corruption if adjacent page is unmapped
 *
 * NOTE: TSS cannot be made fully read-only because esp0 field must be updated
 * on every task switch. However, page alignment limits blast radius of any
 * corruption to just the TSS page (4096 bytes) instead of potentially affecting
 * adjacent kernel data structures.
 *
 * SIZE: sizeof(tss_t) = 104 bytes (fits in one page with room to spare)
 *=============================================================================*/
static tss_t tss __attribute__((aligned(4096)));

/*=============================================================================
 * EXTERNAL SYMBOLS
 *=============================================================================*/
extern uint8_t stack_top[];  /* Defined in boot.s */

/*=============================================================================
 * TSS INITIALIZATION
 *=============================================================================*/

void tss_init(void) {
    /*=========================================================================
     * SECURITY FIX (Issue 12.2): TSS Validation Before Setup
     *=======================================================================*/

    /* Verify TSS is page-aligned (critical for security) */
    uint32_t tss_addr = (uint32_t)&tss;
    if (tss_addr % 4096 != 0) {
        kprintf("[TSS] CRITICAL: TSS not page-aligned (addr=0x%08x)\n", tss_addr);
        kernel_panic("TSS alignment violation - cannot continue");
    }

    /* Verify TSS size is reasonable (should be 104 bytes) */
    if (sizeof(tss_t) > 4096) {
        kprintf("[TSS] ERROR: TSS too large (%u bytes, max 4096)\n",
                (uint32_t)sizeof(tss_t));
        kernel_panic("TSS size violation");
    }

    /* Zero-initialize TSS */
    memset(&tss, 0, sizeof(tss_t));

    /* Set up kernel stack (ring 0) */
    /* Note: esp0 will be updated by scheduler when switching tasks */
    tss.esp0 = (uint32_t)stack_top;
    /* ss0 MUST be the kernel DATA selector (SEG_KDATA=0x18), not the code
     * selector. On a ring3->ring0 transition (the first int 0x80 from a user
     * task) the CPU loads SS:=ss0; loading a code selector into SS raises #TS
     * with the bad selector as the error code, which cascades to #DF -> triple
     * fault. This was previously hardcoded to 0x10 (the CODE selector) with a
     * mislabeled "data segment" comment; kernel tasks never hit it because they
     * never do a ring3->ring0 switch. */
    tss.ss0  = SEG_KDATA;

    /* Set up ring 1 and ring 2 (unused but set to sane values) */
    tss.esp1 = 0;
    tss.ss1  = SEG_KDATA;
    tss.esp2 = 0;
    tss.ss2  = SEG_KDATA;

    /* Set I/O map base beyond TSS limit (disable I/O port permission bitmap) */
    tss.iomap_base = sizeof(tss_t);

    /* No LDT used */
    tss.ldt = 0;

    /* No debug trap */
    tss.trap = 0;

    /*=========================================================================
     * SECURITY FIX (Issue 12.2): Use Dynamic TSS Selector
     *
     * CRITICAL: The TSS GDT entry index is calculated dynamically in gdt_init()
     * based on GRUB's GDT size. We CANNOT hardcode selector 0x28 because:
     * - If GRUB has 3 GDT entries: Our TSS is at index 5, selector = 0x28
     * - If GRUB has 4 GDT entries: Our TSS is at index 6, selector = 0x30
     * - If GRUB has 5 GDT entries: Our TSS is at index 7, selector = 0x38
     *
     * Solution: Use the dynamically calculated tss_selector from gdt.c
     *=======================================================================*/

    /* TSS descriptor fields */
    uint32_t tss_base = (uint32_t)&tss;
    uint32_t tss_limit = sizeof(tss_t) - 1;

    /*=========================================================================
     * SECURITY FIX (Issue 12.2): Verify GDT Limit is Exact
     *
     * The limit should be EXACTLY sizeof(tss_t) - 1 (103 bytes for 104-byte TSS).
     * If limit is too large, CPU could read garbage beyond TSS structure.
     * If limit is too small, CPU faults on valid TSS access.
     *=======================================================================*/
    if (tss_limit != 103) {
        kprintf("[TSS] WARNING: Unexpected TSS limit (%u, expected 103)\n", tss_limit);
    }

    /* Calculate TSS GDT index from selector (selector = index * 8) */
    uint32_t tss_index = tss_selector >> 3;

    /* Add TSS descriptor to GDT at the dynamically calculated index */
    gdt_set_tss_descriptor(tss_index, tss_base, tss_limit);

    /* Load TSS using the dynamically calculated selector */
    __asm__ volatile("ltr %0" : : "r"(tss_selector));

    kprintf("[TSS] Initialized at 0x%08x (size=%u, limit=%u) [OK]\n",
            tss_base, (uint32_t)sizeof(tss_t), tss_limit);
    kprintf("[TSS] Selector=0x%04x, GDT index=%u\n", tss_selector, tss_index);
    kprintf("[TSS] Initial esp0=0x%08x, ss0=0x%04x\n", tss.esp0, tss.ss0);
}

/*=============================================================================
 * TSS GETTER
 *=============================================================================*/

tss_t* tss_get(void) {
    return &tss;
}

/*=============================================================================
 * DOUBLE FAULT STACK GETTER
 *
 * Returns pointer to top of double fault stack.
 * Used by IDT to set up IST entry for vector 8 (Double Fault).
 *=============================================================================*/

uint32_t tss_get_double_fault_stack_top(void) {
    return (uint32_t)double_fault_stack + DOUBLE_FAULT_STACK_SIZE;
}

/*=============================================================================
 * TSS KERNEL STACK UPDATE (For Task Switching)
 *
 * SECURITY FIX (Issue 12.2): Centralized esp0 Management with Validation
 *=============================================================================*/

void tss_set_kernel_stack(uint32_t stack_ptr) {
    /*=========================================================================
     * SECURITY FIX (Issue 12.2): Validate Stack Pointer Before Setting
     *
     * CRITICAL: The esp0 field specifies which kernel stack to use when
     * transitioning from ring 3 (user mode) to ring 0 (kernel mode). If this
     * pointer is corrupted, the CPU will use an invalid/attacker-controlled
     * stack, leading to:
     * - Kernel stack corruption
     * - Privilege escalation (if stack is in user-controlled memory)
     * - Triple fault (if stack points to unmapped/invalid memory)
     *
     * VALIDATION CHECKS:
     * 1. NULL pointer check
     * 2. Minimum address check (reject pointers in low memory/code/data)
     * 3. 16-byte alignment check (required by x86 ABI and SSE instructions)
     *
     * ATTACK SCENARIOS PREVENTED:
     * - Corrupted task structure with invalid kernel_stack field
     * - Integer overflow in stack calculation
     * - Heap/stack smashing corrupting scheduler data structures
     *=======================================================================*/

    /* CHECK 1: NULL pointer */
    if (stack_ptr == 0) {
        kprintf("[TSS] ERROR: Attempted to set NULL kernel stack\n");
        kernel_panic("Invalid TSS esp0: NULL pointer");
    }

    /* CHECK 2: Minimum address (reject low memory) */
    /* Kernel stacks should be above 1 MB (0x00100000) */
    if (stack_ptr < 0x00100000) {
        kprintf("[TSS] ERROR: Invalid kernel stack 0x%08x (too low)\n", stack_ptr);
        kernel_panic("Invalid TSS esp0: address in low memory");
    }

    /* CHECK 3: 16-byte alignment (required by x86 ABI) */
    if ((stack_ptr & 0xF) != 0) {
        kprintf("[TSS] ERROR: Kernel stack 0x%08x not 16-byte aligned\n", stack_ptr);
        kernel_panic("Invalid TSS esp0: misaligned pointer");
    }

    /*=========================================================================
     * UPDATE TSS esp0 FIELD
     *
     * NOTE: This is the ONLY place in the entire kernel where tss.esp0 should
     * be modified (except tss_init). Any other code modifying esp0 is a bug
     * and security vulnerability.
     *=======================================================================*/
    tss.esp0 = stack_ptr;
}
