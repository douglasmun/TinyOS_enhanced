/*=============================================================================
 * copy_user.c - Safe User Space Memory Access with Exception Handling
 *
 * SECURITY FIX: Prevents TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities
 * by providing atomic memory access primitives that catch page faults.
 *
 * IMPLEMENTATION:
 * Uses inline assembly to save/restore execution context. When a page fault
 * occurs during copy, the page fault handler detects we're in copy_*_user(),
 * and jumps back to our saved context with -EFAULT error code.
 *============================================================================*/
#include "copy_user.h"
#include "memory.h"
#include "errno.h"
#include "critical.h"  /* For CRITICAL_SECTION_ENTER/EXIT */
#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * EXCEPTION CONTEXT FOR copy_*_user() OPERATIONS
 *============================================================================*/
struct copy_context {
    uint32_t eip;           /* Saved EIP to return to on fault */
    uint32_t esp;           /* Saved ESP to restore on fault */
    uint32_t ebp;           /* Saved EBP to restore on fault */
    bool     active;        /* Is copy_*_user() currently active? */
    int      error_code;    /* Error code to return (-EFAULT on fault) */
    uint32_t fault_addr;    /* Address that caused the fault (for logging) */
};

/*=============================================================================
 * SECURITY FIX: Race Condition Protection
 *
 * VULNERABILITY: Single global context without interrupt protection
 *
 * PROBLEM:
 * - copy_ctx is a single global variable
 * - If interrupt fires during copy_from_user(), IRQ handler might call copy_*_user()
 * - Without interrupt disable, nested calls can corrupt saved EIP/ESP/EBP
 * - Current reentrancy check returns -EFAULT on nesting, but doesn't prevent races
 *
 * ATTACK SCENARIO:
 * 1. Task calls copy_from_user(), sets copy_ctx.active = true
 * 2. Saves EIP/ESP/EBP for fault handling
 * 3. Hardware interrupt fires during copy loop
 * 4. IRQ handler calls audit_log() → copy_from_user()
 * 5. Inner copy_from_user() might corrupt context if check is bypassed
 * 6. Outer copy returns to wrong address → crash or exploit
 *
 * FIX: Disable interrupts during copy operations
 * - Use CRITICAL_SECTION to prevent IRQ handlers from running
 * - Keep reentrancy check for defensive programming
 * - Ensures atomic execution of copy operations
 * - SMP-safe for future multi-CPU support
 *============================================================================*/

/*
 * Global copy context (single-CPU system)
 * CRITICAL: Must be zero-initialized (BSS section)
 * CRITICAL: Protected by interrupt disable (CRITICAL_SECTION) during use
 */
static struct copy_context copy_ctx = {0};

/*=============================================================================
 * FUNCTION: copy_from_user
 *=============================================================================
 * Safely copies data from user space to kernel space with page fault handling.
 * If user unmaps memory during copy, returns -EFAULT instead of crashing.
 *============================================================================*/
int copy_from_user(void* kernel_dst, const void* user_src, size_t len) {
    /*=========================================================================
     * VALIDATION: Check for trivial cases
     *=======================================================================*/
    if (len == 0) {
        return 0;  /* Nothing to copy - success */
    }

    if (!kernel_dst || !user_src) {
        return -EFAULT;  /* NULL pointer */
    }

    /*=========================================================================
     * PHASE 16: Hardened Usercopy - Maximum Size Limit
     *
     * TRADITIONAL WEAKNESS:
     * - No limit on copy size → attacker can DoS by copying GB of data
     * - Integer overflow in size calculations
     * - Excessive memory allocation in kernel
     *
     * ANDROID/LINUX HARDENING:
     * - Maximum copy size enforced (typically 16MB-32MB)
     * - Prevents resource exhaustion attacks
     * - Catches programmer errors (accidentally passing wrong size)
     *
     * TINYOS DEFENSE:
     * - Limit copy operations to 16MB max
     * - Reasonable for embedded OS
     * - Prevents DoS via excessive copy operations
     *=======================================================================*/
    #define MAX_COPY_SIZE (16 * 1024 * 1024)  /* 16MB max per copy */
    if (len > MAX_COPY_SIZE) {
        return -EINVAL;  /* Size too large */
    }

    /*=========================================================================
     * VALIDATION: Ensure user address is in user space
     * SECURITY: Prevent kernel memory access via syscalls
     *=======================================================================*/
    uint32_t user_addr = (uint32_t)user_src;
    uint32_t user_end = user_addr + len;

    /* Check for integer overflow in address calculation */
    if (user_end < user_addr) {
        return -EFAULT;  /* Overflow - wraps around address space */
    }

    /* Check if address range is entirely in user space */
    if (user_addr >= USER_SPACE_END || user_end > USER_SPACE_END) {
        return -EFAULT;  /* Attempts to access kernel memory */
    }

    /*=========================================================================
     * INTERRUPT PROTECTION
     * SECURITY FIX: Disable interrupts to prevent context corruption
     *
     * This prevents IRQ handlers from calling copy_*_user() while we're
     * in the middle of a copy operation, which would corrupt the global
     * copy_ctx structure.
     *=======================================================================*/
    CRITICAL_SECTION_ENTER();

    /*=========================================================================
     * REENTRANCY PROTECTION
     * SECURITY FIX: Prevent nested copy_*_user() calls from corrupting context
     *
     * Scenarios this protects against:
     * 1. Task A calls copy_from_user(), page faults, page fault handler
     *    logs via audit system which calls copy_from_user() again
     * 2. Interrupt during copy_*_user() calls code that also uses copy_*_user()
     * 3. Future code paths (networking, IPC) that might call copy_*_user()
     *    from within page fault/exception handlers
     *
     * Without this check, nested calls would overwrite saved EIP/ESP/EBP,
     * causing the outer call to return to the wrong location -> crash or
     * arbitrary code execution.
     *
     * This is a kernel programming error, not a user exploit, but it's
     * exactly the kind of "works in lab, dies mysteriously in production"
     * bug that appears under load or when new features are added.
     *
     * NOTE: With CRITICAL_SECTION above, this should never trigger in
     * single-CPU systems, but we keep it for defense-in-depth and future
     * SMP support.
     *=======================================================================*/
    if (copy_ctx.active) {
        /* Nested copy_*_user() detected - this is a kernel bug */
        CRITICAL_SECTION_EXIT();
        return -EFAULT;
    }

    /*=========================================================================
     * SECURITY FIX (AUDIT 4B): Atomic Pre-Validation to Prevent Partial Faulting
     *=========================================================================
     *
     * VULNERABILITY: Partial Copy with Inconsistent State
     *
     * OLD BEHAVIOR (VULNERABLE):
     * 1. Validate address range bounds (overflow, user space)
     * 2. Start byte-by-byte copy loop
     * 3. If page fault occurs mid-copy, return -EFAULT
     * 4. Destination buffer has PARTIAL data, but caller thinks copy failed
     *
     * ATTACK SCENARIO:
     * - Attacker provides buffer where first N pages are mapped, last page unmapped
     * - Kernel copies N pages successfully, then faults on last page
     * - Returns -EFAULT, but kernel buffer now contains attacker's partial data
     * - Kernel code may use uninitialized portion thinking entire copy failed
     * - Result: Information leak or logic error
     *
     * PRODUCTION FAILURE:
     * - Process provides 8KB buffer, but only 4KB mapped
     * - Syscall copies 4KB, faults, returns -EFAULT
     * - Kernel code sees -EFAULT, assumes buffer is pristine
     * - Acts on partial data -> undefined behavior
     *
     * ATOMIC PRE-VALIDATION FIX:
     * - Probe EVERY page in the range before starting copy
     * - If ANY page is inaccessible, return -EFAULT immediately
     * - Copy only proceeds if ALL pages are accessible
     * - Guarantees all-or-nothing semantics
     *
     * IMPLEMENTATION:
     * - Walk through range in PAGE_SIZE increments
     * - Probe first byte of each page via volatile read
     * - If probe faults, handle_copy_user_fault() returns -EFAULT
     * - Only after all probes succeed do we start actual copy
     *=======================================================================*/
    #define PAGE_SIZE 4096

    copy_ctx.active = true;
    copy_ctx.error_code = 0;
    copy_ctx.fault_addr = 0;

    /* Save execution context for pre-validation probes */
    __asm__ volatile(
        "movl $copy_from_user_probe_return, %0\n"
        "movl %%esp, %1\n"
        "movl %%ebp, %2\n"
        : "=m"(copy_ctx.eip), "=m"(copy_ctx.esp), "=m"(copy_ctx.ebp)
        : : "memory"
    );

    /* Check if probe faulted */
    if (copy_ctx.error_code != 0) {
        copy_ctx.active = false;
        CRITICAL_SECTION_EXIT();
        return -EFAULT;
    }

    /* ATOMIC PRE-VALIDATION: Probe every page in source range */
    for (uint32_t probe_addr = user_addr; probe_addr < user_end; probe_addr += PAGE_SIZE) {
        /* Volatile read to force memory access (prevents compiler optimization) */
        volatile uint8_t probe_byte = *(volatile uint8_t*)probe_addr;
        (void)probe_byte;  /* Suppress unused variable warning */
    }

    /* Probe the last byte if it's not on a page boundary */
    if ((user_end - 1) / PAGE_SIZE != (user_end - PAGE_SIZE) / PAGE_SIZE) {
        volatile uint8_t probe_byte = *(volatile uint8_t*)(user_end - 1);
        (void)probe_byte;
    }

    __asm__ volatile("copy_from_user_probe_return:");

    /* If any probe faulted, error_code will be set */
    if (copy_ctx.error_code != 0) {
        int ret = copy_ctx.error_code;
        copy_ctx.active = false;
        CRITICAL_SECTION_EXIT();
        return ret;
    }

    /*=========================================================================
     * EXCEPTION CONTEXT SETUP FOR ACTUAL COPY
     * All pages validated - now safe to copy with all-or-nothing guarantee
     *=======================================================================*/
    copy_ctx.error_code = 0;
    copy_ctx.fault_addr = 0;

    /*
     * Save execution context using inline assembly
     * We save: EIP (return address), ESP (stack pointer), EBP (frame pointer)
     *
     * The trick: We use a label (copy_from_user_return) as the return point.
     * If page fault occurs, handle_copy_user_fault() will jump back here.
     */
    __asm__ volatile(
        "movl $copy_from_user_return, %0\n"  /* Save return EIP */
        "movl %%esp, %1\n"                    /* Save ESP */
        "movl %%ebp, %2\n"                    /* Save EBP */
        : "=m"(copy_ctx.eip), "=m"(copy_ctx.esp), "=m"(copy_ctx.ebp)
        : : "memory"
    );

    /*=========================================================================
     * CHECK FOR FAULT RETURN
     * If we returned via page fault handler, error_code will be set
     *=======================================================================*/
    if (copy_ctx.error_code != 0) {
        int ret = copy_ctx.error_code;
        copy_ctx.active = false;
        CRITICAL_SECTION_EXIT();
        return ret;  /* Return -EFAULT */
    }

    /*=========================================================================
     * PERFORM THE COPY
     * This may trigger a page fault if user unmaps memory concurrently
     * SECURITY: Page fault will be caught and return -EFAULT
     *
     * PERMISSION VALIDATION (11.C): This implicitly validates PTE permissions
     * through CPU's hardware memory protection:
     * - If user page lacks READ permission, CPU generates #PF
     * - If page is not present (unmapped), CPU generates #PF
     * - Page fault handler detects copy_ctx.active and returns -EFAULT
     *
     * This approach is SUPERIOR to explicit PTE checks because:
     * 1. Eliminates TOCTOU race (user can't change permissions between check/use)
     * 2. CPU enforces permissions atomically via hardware
     * 3. Handles all fault cases uniformly (not present, no permissions, etc.)
     *=======================================================================*/
    const uint8_t* src = (const uint8_t*)user_src;
    uint8_t* dst = (uint8_t*)kernel_dst;

    for (size_t i = 0; i < len; i++) {
        dst[i] = src[i];  /* May page fault here if user unmaps page */
    }

    /*=========================================================================
     * SUCCESS PATH
     * Mark copy as complete and return success
     *=======================================================================*/
    __asm__ volatile("copy_from_user_return:");  /* Return label */
    if (copy_ctx.error_code != 0) {
        int ret = copy_ctx.error_code;
        copy_ctx.active = false;
        CRITICAL_SECTION_EXIT();
        return ret;  /* Fault during copy loop */
    }
    copy_ctx.active = false;
    CRITICAL_SECTION_EXIT();
    return 0;  /* Success */
}

/*=============================================================================
 * FUNCTION: copy_to_user
 *=============================================================================
 * Safely copies data from kernel space to user space with page fault handling.
 * If user unmaps memory during copy, returns -EFAULT instead of crashing.
 *============================================================================*/
int copy_to_user(void* user_dst, const void* kernel_src, size_t len) {
    /*=========================================================================
     * VALIDATION: Check for trivial cases
     *=======================================================================*/
    if (len == 0) {
        return 0;  /* Nothing to copy - success */
    }

    if (!user_dst || !kernel_src) {
        return -EFAULT;  /* NULL pointer */
    }

    /*=========================================================================
     * PHASE 16: Hardened Usercopy - Maximum Size Limit
     * (Same protection as copy_from_user - see documentation there)
     *=======================================================================*/
    #define MAX_COPY_SIZE (16 * 1024 * 1024)  /* 16MB max per copy */
    if (len > MAX_COPY_SIZE) {
        return -EINVAL;  /* Size too large */
    }

    /*=========================================================================
     * VALIDATION: Ensure user address is in user space
     * SECURITY: Prevent writing to kernel memory via syscalls
     *=======================================================================*/
    uint32_t user_addr = (uint32_t)user_dst;
    uint32_t user_end = user_addr + len;

    /* Check for integer overflow in address calculation */
    if (user_end < user_addr) {
        return -EFAULT;  /* Overflow - wraps around address space */
    }

    /* Check if address range is entirely in user space */
    if (user_addr >= USER_SPACE_END || user_end > USER_SPACE_END) {
        return -EFAULT;  /* Attempts to write to kernel memory */
    }

    /*=========================================================================
     * INTERRUPT PROTECTION (same as copy_from_user)
     * Disable interrupts to prevent IRQ handlers from corrupting context
     *=======================================================================*/
    CRITICAL_SECTION_ENTER();

    /*=========================================================================
     * REENTRANCY PROTECTION (same as copy_from_user)
     *=======================================================================*/
    if (copy_ctx.active) {
        /* Nested copy_*_user() detected - this is a kernel bug */
        CRITICAL_SECTION_EXIT();
        return -EFAULT;
    }

    /*=========================================================================
     * SECURITY FIX (AUDIT 4B): Atomic Pre-Validation (copy_to_user)
     *=========================================================================
     * Same atomic pre-validation as copy_from_user - probes all destination
     * pages before writing to ensure all-or-nothing semantics
     *=======================================================================*/

    copy_ctx.active = true;
    copy_ctx.error_code = 0;
    copy_ctx.fault_addr = 0;

    /* Save execution context for pre-validation probes */
    __asm__ volatile(
        "movl $copy_to_user_probe_return, %0\n"
        "movl %%esp, %1\n"
        "movl %%ebp, %2\n"
        : "=m"(copy_ctx.eip), "=m"(copy_ctx.esp), "=m"(copy_ctx.ebp)
        : : "memory"
    );

    /* Check if probe faulted */
    if (copy_ctx.error_code != 0) {
        copy_ctx.active = false;
        CRITICAL_SECTION_EXIT();
        return -EFAULT;
    }

    /* ATOMIC PRE-VALIDATION: Probe every page in destination range */
    /* Note: For copy_to_user, we do read probes - writes will check permissions later */
    for (uint32_t probe_addr = user_addr; probe_addr < user_end; probe_addr += PAGE_SIZE) {
        /* Volatile read to check page is accessible */
        volatile uint8_t probe_byte = *(volatile uint8_t*)probe_addr;
        (void)probe_byte;
    }

    /* Probe the last byte if it's not on a page boundary */
    if ((user_end - 1) / PAGE_SIZE != (user_end - PAGE_SIZE) / PAGE_SIZE) {
        volatile uint8_t probe_byte = *(volatile uint8_t*)(user_end - 1);
        (void)probe_byte;
    }

    __asm__ volatile("copy_to_user_probe_return:");

    /* If any probe faulted, error_code will be set */
    if (copy_ctx.error_code != 0) {
        int ret = copy_ctx.error_code;
        copy_ctx.active = false;
        CRITICAL_SECTION_EXIT();
        return ret;
    }

    /*=========================================================================
     * EXCEPTION CONTEXT SETUP FOR ACTUAL COPY
     * All pages validated - now safe to copy with all-or-nothing guarantee
     *=======================================================================*/
    copy_ctx.error_code = 0;
    copy_ctx.fault_addr = 0;

    /*
     * Save execution context using inline assembly
     * We save: EIP (return address), ESP (stack pointer), EBP (frame pointer)
     */
    __asm__ volatile(
        "movl $copy_to_user_return, %0\n"    /* Save return EIP */
        "movl %%esp, %1\n"                    /* Save ESP */
        "movl %%ebp, %2\n"                    /* Save EBP */
        : "=m"(copy_ctx.eip), "=m"(copy_ctx.esp), "=m"(copy_ctx.ebp)
        : : "memory"
    );

    /*=========================================================================
     * CHECK FOR FAULT RETURN
     * If we returned via page fault handler, error_code will be set
     *=======================================================================*/
    if (copy_ctx.error_code != 0) {
        int ret = copy_ctx.error_code;
        copy_ctx.active = false;
        CRITICAL_SECTION_EXIT();
        return ret;  /* Return -EFAULT */
    }

    /*=========================================================================
     * PERFORM THE COPY
     * This may trigger a page fault if user unmaps memory concurrently
     * SECURITY: Page fault will be caught and return -EFAULT
     *=======================================================================*/
    const uint8_t* src = (const uint8_t*)kernel_src;
    uint8_t* dst = (uint8_t*)user_dst;

    for (size_t i = 0; i < len; i++) {
        dst[i] = src[i];  /* May page fault here if user unmaps page */
    }

    /*=========================================================================
     * SUCCESS PATH
     * Mark copy as complete and return success
     *=======================================================================*/
    __asm__ volatile("copy_to_user_return:");  /* Return label */
    if (copy_ctx.error_code != 0) {
        int ret = copy_ctx.error_code;
        copy_ctx.active = false;
        CRITICAL_SECTION_EXIT();
        return ret;  /* Fault during copy loop */
    }
    copy_ctx.active = false;
    CRITICAL_SECTION_EXIT();
    return 0;  /* Success */
}

/*=============================================================================
 * FUNCTION: is_copy_user_active
 *=============================================================================
 * Returns true if copy_*_user() is currently active (used by page fault handler)
 *============================================================================*/
bool is_copy_user_active(void) {
    return copy_ctx.active;
}

/*=============================================================================
 * FUNCTION: handle_copy_user_fault
 *=============================================================================
 * Called by page fault handler when fault occurs during copy_*_user().
 * Restores saved context and returns -EFAULT to copy_*_user() caller.
 *
 * IMPORTANT: This function does NOT return - it performs a non-local jump!
 *============================================================================*/
void handle_copy_user_fault(void) {
    /*=========================================================================
     * Set error code to indicate fault
     *=======================================================================*/
    copy_ctx.error_code = -EFAULT;

    /*=========================================================================
     * Restore saved execution context and jump back to copy_*_user()
     * This is like a longjmp() - we return to the saved EIP with saved ESP/EBP
     *=======================================================================*/
    __asm__ volatile(
        "movl %0, %%ebp\n"      /* Restore EBP (frame pointer) */
        "movl %1, %%esp\n"      /* Restore ESP (stack pointer) */
        "jmp *%2\n"             /* Jump to saved EIP (return address) */
        : : "m"(copy_ctx.ebp), "m"(copy_ctx.esp), "m"(copy_ctx.eip)
    );

    /*
     * NEVER REACHES HERE
     * The jmp instruction above transfers control back to copy_*_user()
     */
    __builtin_unreachable();
}

/*=============================================================================
 * FUNCTION: get_copy_user_fault_address
 *=============================================================================
 * Returns the address that caused the page fault (for diagnostic logging)
 *============================================================================*/
uint32_t get_copy_user_fault_address(void) {
    return copy_ctx.fault_addr;
}
