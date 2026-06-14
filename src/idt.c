/*=============================================================================
 *  idt.c – IDT with CORRECT selector (0x08 = Kernel Code Segment)
 *  MODIFIED: Removed 'static' from idt array for user mode support
 *============================================================================*/
#include "idt.h"
#include "kprintf.h"
#include "scheduler.h"
#include "process.h"
#include "copy_user.h"  /* SECURITY: TOCTOU fix - safe user memory access */
#include "util.h"       /* For kernel_panic() */

/* Forward declaration for PAE page table dumping */
extern void pae_dump_tables(uint32_t virt);

/* ISR stubs from isr.S */
extern void isr0(void);  extern void isr1(void);  extern void isr2(void);  extern void isr3(void);
extern void isr4(void);  extern void isr5(void);  extern void isr6(void);  extern void isr7(void);
extern void isr8(void);  extern void isr9(void);  extern void isr10(void); extern void isr11(void);
extern void isr12(void); extern void isr13(void); 

// extern void isr14(void); 

extern void isr15(void);
extern void isr16(void); extern void isr17(void); extern void isr18(void); extern void isr19(void);
extern void isr20(void); extern void isr21(void); extern void isr22(void); extern void isr23(void);
extern void isr24(void); extern void isr25(void); extern void isr26(void); extern void isr27(void);
extern void isr28(void); extern void isr29(void); extern void isr30(void); extern void isr31(void);

/* IRQ stubs from isr.S */
extern void irq32(void); extern void irq33(void); extern void irq34(void); extern void irq35(void);
extern void irq36(void); extern void irq37(void); extern void irq38(void); extern void irq39(void);
extern void irq40(void); extern void irq41(void); extern void irq42(void); extern void irq43(void);
extern void irq44(void); extern void irq45(void); extern void irq46(void); extern void irq47(void);

/* REMOVED 'static' - needed for idt_usermode.c to access */
struct idt_entry idt[256];

static struct idt_ptr idtr;

/*
static void idt_set_gate(int vec, void (*fn)(void), uint8_t flags) {
    // Your existing implementation
    idt[vec].offset_low = ((uint32_t)fn) & 0xFFFF;
    idt[vec].offset_high = (((uint32_t)fn) >> 16) & 0xFFFF;
    idt[vec].selector = 0x08;  // Kernel code segment
    idt[vec].zero = 0;
    idt[vec].type_attr = flags;
}*/

/*-----------------------------------------------------------------------------
 * Set IDT Gate (for exceptions and IRQs)
 *
 * CRITICAL: Must match GRUB's kernel code segment selector
 * This GRUB setup uses a non-standard layout - we need to detect it dynamically
 *---------------------------------------------------------------------------*/
static void idt_set_gate(int vec, void (*fn)(void), uint8_t flags) {
    uint32_t addr = (uint32_t)fn;
    idt[vec].offset_low  = (uint16_t)(addr & 0xFFFF);
    idt[vec].selector    = 0x10;    /* GRUB's kernel code segment (non-standard) */
    idt[vec].zero        = 0;       /* Must be 0 for 32-bit x86 */
    idt[vec].type_attr   = flags;
    idt[vec].offset_high = (uint16_t)((addr >> 16) & 0xFFFF);
} 


// Assembly stub for page fault
void page_fault_handler_asm(void) {
    __asm__ volatile(
        "push $14\n"  // Vector number, so the stack matches struct regs
        "pusha\n"
        "push %%ds\n"
        "push %%es\n"
        "push %%fs\n"
        "push %%gs\n"
        "mov $0x18, %%ax\n"  // SEG_KDATA, matching isr.S/syscall.S
        "mov %%ax, %%ds\n"
        "mov %%ax, %%es\n"
        "mov %%ax, %%fs\n"
        "mov %%ax, %%gs\n"
        "mov %%esp, %%eax\n"
        "push %%eax\n"
        "call page_fault_handler\n"
        "pop %%eax\n"
        "pop %%gs\n"
        "pop %%fs\n"
        "pop %%es\n"
        "pop %%ds\n"
        "popa\n"
        "add $8, %%esp\n"  // Remove vector number and error code
        "iret\n"
        : : : "eax"
    );
}


void idt_init(void) {

    // kprintf("Initializing IDT...\n");

    idtr.limit = (sizeof(struct idt_entry) * 256) - 1;
    idtr.base = (uint32_t)&idt[0];
    
    // Clear IDT
    /*    
    for (int i = 0; i < 256; i++) {
        idt_set_gate(i, default_handler, 0x8E);
    }*/
         
    for (int i = 0; i < 256; ++i) {
        idt[i].offset_low  = 0;
        idt[i].selector    = 0;
        idt[i].zero        = 0;
        idt[i].type_attr   = 0;
        idt[i].offset_high = 0;
    }

    // Set up specific interrupts
    //idt_set_gate(0, divide_by_zero_handler, 0x8E);
    idt_set_gate( 0, isr0,  0x8E);
    idt_set_gate( 1, isr1,  0x8E);
    idt_set_gate( 2, isr2,  0x8E);
    idt_set_gate( 3, isr3,  0x8E);
    idt_set_gate( 4, isr4,  0x8E);
    idt_set_gate( 5, isr5,  0x8E);
    // idt_set_gate(6, invalid_opcode_handler, 0x8E);
    idt_set_gate( 6, isr6,  0x8E);
    idt_set_gate( 7, isr7,  0x8E);
    // idt_set_gate(8, double_fault_handler, 0x8E);
    idt_set_gate( 8, isr8,  0x8E);
    idt_set_gate( 9, isr9,  0x8E);
    idt_set_gate(10, isr10, 0x8E);
    idt_set_gate(11, isr11, 0x8E);
    idt_set_gate(12, isr12, 0x8E);
    // idt_set_gate(13, general_protection_fault_handler, 0x8E);
    idt_set_gate(13, isr13, 0x8E);
    // Set up page fault handler (interrupt 14)
    idt_set_gate(14, page_fault_handler_asm, 0x8E);  // FIXED - 3 arguments only!

    idt_set_gate(15, isr15, 0x8E);
    idt_set_gate(16, isr16, 0x8E);
    idt_set_gate(17, isr17, 0x8E);
    idt_set_gate(18, isr18, 0x8E);
    idt_set_gate(19, isr19, 0x8E);
    idt_set_gate(20, isr20, 0x8E);
    idt_set_gate(21, isr21, 0x8E);
    idt_set_gate(22, isr22, 0x8E);
    idt_set_gate(23, isr23, 0x8E);
    idt_set_gate(24, isr24, 0x8E);
    idt_set_gate(25, isr25, 0x8E);
    idt_set_gate(26, isr26, 0x8E);
    idt_set_gate(27, isr27, 0x8E);
    idt_set_gate(28, isr28, 0x8E);
    idt_set_gate(29, isr29, 0x8E);
    idt_set_gate(30, isr30, 0x8E);
    idt_set_gate(31, isr31, 0x8E);
    idt_set_gate(32, irq32, 0x8E);
    idt_set_gate(33, irq33, 0x8E);
    idt_set_gate(34, irq34, 0x8E);
    idt_set_gate(35, irq35, 0x8E);
    idt_set_gate(36, irq36, 0x8E);
    idt_set_gate(37, irq37, 0x8E);
    idt_set_gate(38, irq38, 0x8E);
    idt_set_gate(39, irq39, 0x8E);
    idt_set_gate(40, irq40, 0x8E);
    idt_set_gate(41, irq41, 0x8E);
    idt_set_gate(42, irq42, 0x8E);
    idt_set_gate(43, irq43, 0x8E);
    idt_set_gate(44, irq44, 0x8E);
    idt_set_gate(45, irq45, 0x8E);
    idt_set_gate(46, irq46, 0x8E);
    idt_set_gate(47, irq47, 0x8E);

    idtr.limit = (uint16_t)(sizeof(idt) - 1);
    idtr.base  = (uint32_t)&idt[0];

    __asm__ volatile ("lidt %0" : : "m"(idtr));

    // CRITICAL: Serialization barrier after LIDT
    // Ensures instruction pipeline is flushed and IDT is globally visible
    __asm__ volatile ("jmp 1f\n1:" : : : "memory");

    // kprintf("IDT installed\n");
}


// Page fault handler function
void page_fault_handler(struct regs* r) {
    uint32_t faulting_address;
    __asm__ volatile("mov %%cr2, %0" : "=r"(faulting_address));

    /*=========================================================================
     * SECURITY: TOCTOU FIX - Handle copy_*_user() Page Faults
     *
     * If page fault occurred during copy_from_user() or copy_to_user(),
     * gracefully return -EFAULT instead of terminating process/system.
     *
     * This prevents TOCTOU race conditions where user unmaps memory after
     * validation but before kernel accesses it.
     *=======================================================================*/
    if (is_copy_user_active()) {
        kprintf("[PAGE FAULT] Caught during copy_*_user() at 0x%08x, returning -EFAULT\n",
                faulting_address);
        handle_copy_user_fault();  /* Does not return - jumps back to copy_*_user() */
    }

    /*=========================================================================
     * SECURITY: STACK GUARD PAGE DETECTION - Stack Overflow Protection
     *
     * Check if page fault occurred on a guard page (stack overflow).
     * If so, terminate the task immediately with clear error message.
     *
     * This prevents silent memory corruption from stack overflows.
     *=======================================================================*/
    task_t* current_task = task_current();
    if (current_task && current_task->kernel_stack_phys != 0) {
        // Kernel-stack overflow detection. The kernel stack is the contiguous run
        // [stack_base, stack_top): stack_base == kernel_stack_phys (page-aligned
        // physical base, identity-mapped) and stack_top == task->kernel_stack
        // (one past the highest stack page). A kernel-stack overflow pushes past
        // stack_base, so the faulting address (CR2) lands just BELOW stack_base.
        //
        // We test "fault in the page directly below stack_base" rather than the
        // guard frame: guard_page_phys is a SEPARATE pmm_alloc() and is generally
        // NOT physically adjacent to the contiguous stack run, so keying off the
        // guard frame (as a prior version did) missed real overflows. We also
        // accept an exact guard-frame hit as a secondary signal when it happens to
        // be adjacent. Catch this BEFORE the heavy kprintf/pae_dump_tables block
        // below, which would run on the already-blown stack and re-fault
        // (#PF -> #DF -> triple fault) — the failure this guard exists to prevent.
        // Keep this branch minimal so it survives a near-empty stack.
        uint32_t fault_page = faulting_address & 0xFFFFF000;
        uint32_t stack_base = current_task->kernel_stack_phys & 0xFFFFF000;
        uint32_t guard_page = current_task->guard_page_phys & 0xFFFFF000;
        // Overflow = a fault in the page immediately below the stack base.
        bool below_stack = (faulting_address < stack_base &&
                            faulting_address >= stack_base - 4096);
        bool on_guard = (current_task->guard_page_phys != 0 &&
                         fault_page == guard_page);
        bool is_stack_overflow = below_stack || on_guard;
        if (is_stack_overflow) {
            kprintf("\n*** STACK OVERFLOW DETECTED ***\n");
            kprintf("Task PID=%d '%s' overflowed its kernel stack\n",
                    current_task->pid, current_task->name);
            kprintf("CR2=0x%08x stack_base=0x%08x guard=0x%08x EIP=0x%08x (err=0x%08x)\n",
                    faulting_address, stack_base, guard_page, r->eip, r->err_code);
            kprintf("Terminating task to prevent memory corruption...\n\n");

            // Terminate the task
            task_terminate(current_task->pid);

            // Yield to scheduler (task is now terminated)
            __asm__ volatile("int $0x20");  // Timer interrupt to trigger scheduler

            // Should not reach here, but halt if we do
            while(1) { __asm__ volatile("hlt"); }
        }
    }

    kprintf("\n*** PAGE FAULT ***\n");
    kprintf("Faulting address: 0x%08x\n", faulting_address);
    kprintf("Error code: 0x%08x\n", r->err_code);
    kprintf("EIP: 0x%08x\n", r->eip);
    kprintf("CS: 0x%04x\n", r->cs);

    // Print current CR3
    uint32_t current_cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(current_cr3));
    kprintf("CR3: 0x%08x\n", current_cr3);

    // Decode error code
    kprintf("Cause: ");
    if (r->err_code & 0x01) kprintf("Present ");
    if (r->err_code & 0x02) kprintf("Write ");
    if (r->err_code & 0x04) kprintf("User ");
    if (r->err_code & 0x08) kprintf("Reserved ");
    if (r->err_code & 0x10) kprintf("Instruction ");
    kprintf("\n");

    /*=========================================================================
     * BUG FIX: Use PAE API instead of recursive mapping
     *
     * CRITICAL: The old code tried to access page tables via recursive mapping
     * at 0xFFFFF000, but PAE initialization never set up recursive mapping!
     * This caused the page fault handler itself to page fault, creating an
     * infinite loop.
     *
     * Fix: Use pae_dump_tables() which safely accesses page tables via the
     * PAE data structures (pdpt and page_directories arrays).
     *=======================================================================*/
    pae_dump_tables(faulting_address);

    // Check if we're in user mode
    if (r->err_code & 0x04) {
        kprintf("Mode: USER (CPL=3)\n");
    } else {
        kprintf("Mode: KERNEL (CPL=0)\n");
    }

    kprintf("*** END PAGE FAULT ***\n\n");

    /*=========================================================================
     * CRITICAL: Production-Quality Fault Handling
     * SECURITY: A single faulty user process must NEVER crash the entire system.
     *
     * User-Mode Fault (CPL=3): Terminate only the offending process and
     * continue system operation with other processes.
     *
     * Kernel-Mode Fault (CPL=0): This indicates a critical kernel bug.
     * The kernel cannot recover safely, so the system must halt.
     *=========================================================================*/
    if (r->err_code & 0x04) {
        /*=====================================================================
         * USER MODE PAGE FAULT - Terminate Process Only
         *
         * A user process has accessed invalid memory. This could be:
         * - Dereferencing NULL pointer
         * - Stack overflow
         * - Accessing freed memory
         * - Invalid pointer arithmetic
         *
         * Production behavior: Kill the faulty process and schedule next task.
         *===================================================================*/
        kprintf("[PAGE FAULT] Terminating faulty user process...\n");

        // Get current task
        task_t* faulty_task = scheduler_get_current_task();

        if (faulty_task) {
            kprintf("[PAGE FAULT] Killing process PID=%d '%s'\n",
                    faulty_task->pid, faulty_task->name);

            // Mark task as terminated
            faulty_task->state = TASK_STATE_TERMINATED;

            // Remove from ready queue to prevent rescheduling
            scheduler_remove_task(faulty_task);

            kprintf("[PAGE FAULT] Process terminated, switching to next task...\n");

            // Force context switch to next available task
            // This should NEVER return since current task is terminated
            scheduler_yield();

            // If we reach here, no other tasks are available
            kprintf("[PAGE FAULT] ERROR: No runnable tasks after process termination\n");
            kprintf("[PAGE FAULT] System shutdown - all tasks exhausted\n");
        } else {
            kprintf("[PAGE FAULT] ERROR: No current task found!\n");
        }

        // Fallback: halt if process termination failed
        kprintf("[PAGE FAULT] CRITICAL: Process termination failed, halting system\n");

        /*
         * SECURITY FIX: Use kernel_panic instead of inline halt loop
         * Provides recursion protection and consistent error handling
         */
        kernel_panic("User mode page fault - process termination failed");

    } else {
        /*=====================================================================
         * KERNEL MODE PAGE FAULT - Critical System Error
         *
         * A page fault in kernel mode indicates a serious bug:
         * - Kernel accessed unmapped memory
         * - Page directory corruption
         * - Stack overflow in kernel
         * - NULL pointer dereference in kernel code
         *
         * The kernel cannot safely recover from this condition.
         * Production behavior: Log diagnostic info and halt system.
         *===================================================================*/
        kprintf("[PAGE FAULT] CRITICAL: Kernel mode page fault detected\n");
        kprintf("[PAGE FAULT] Kernel has accessed invalid memory - this is a BUG\n");
        kprintf("[PAGE FAULT] System must halt to prevent data corruption\n");
        kprintf("[PAGE FAULT] System halted - manual reboot required\n\n");

        /*
         * SECURITY FIX: Use kernel_panic instead of inline halt loop
         * Provides recursion protection and consistent error handling
         */
        kernel_panic("Kernel mode page fault");
    }
}



/*
// Default handler for unhandled interrupts
void default_handler(void) {
    // kprintf("Unhandled interrupt\n");
    for(;;) __asm__ volatile("hlt");
}

// Divide by zero handler
void divide_by_zero_handler(void) {
    // kprintf("Divide by zero exception\n");
    for(;;) __asm__ volatile("hlt");
}

// Invalid opcode handler  
void invalid_opcode_handler(void) {
    // kprintf("Invalid opcode exception\n");
    for(;;) __asm__ volatile("hlt");
}

// Double fault handler
void double_fault_handler(void) {
    // kprintf("Double fault exception\n");
    for(;;) __asm__ volatile("hlt");
}

// General protection fault handler
void general_protection_fault_handler(void) {
    // kprintf("General protection fault\n");
    for(;;) __asm__ volatile("hlt");
}
*/


