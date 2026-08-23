/*=============================================================================
 *  interrupts.c — Working interrupt handler with timer and E1000
 *============================================================================*/
#include "kernel.h"
#include "idt.h"
#include "pic.h"
#include "kprintf.h"
#include "tcp.h"
#include "dhcp.h"
#include "scheduler.h"
#include "keyboard.h"
#include "interrupt_regs.h"
#include "tss.h"  /* For the double-fault TSS and its stack */
#include "util.h"  /* For kernel_panic() */
#include "critical.h"  /* For interrupt context tracking */
#include "audit.h"  /* For security audit logging */
#include "process.h" /* For task_current() */
#include "edr_advanced.h" /* EDR Phase 3: Advanced detection */
#include "crypto.h" /* For csprng_periodic_reseed() */

/*=============================================================================
 * EXTERNAL FUNCTION: e1000_poll_rx
 *============================================================================*/
extern void e1000_poll_rx(void);

/*=============================================================================
 * Function Prototypes
 *============================================================================*/
void double_fault_task_entry(void);

static const char* exc_name[32] = {
    /* Vector 0-7 */
    "#DE Divide Error",           /* Division by zero or overflow */
    "#DB Debug",                  /* Debugger breakpoint or single-step */
    "NMI",                        /* Non-Maskable Interrupt (hardware) */
    "#BP Breakpoint",             /* INT 3 instruction (debugger) */
    "#OF Overflow",               /* INTO instruction with OF=1 */
    "#BR BOUND Range",            /* BOUND instruction out of range */
    "#UD Invalid Opcode",         /* Undefined or illegal instruction */
    "#NM Device Not Available",   /* FPU instruction without FPU */
    
    /* Vector 8-15 */
    "#DF Double Fault",           /* Exception while handling exception */
    "Coprocessor Segment Overrun",/* Legacy, shouldn't happen on modern CPUs */
    "#TS Invalid TSS",            /* Task state segment invalid/not present */
    "#NP Segment Not Present",    /* Segment marked "not present" */
    "#SS Stack Fault",            /* Stack segment fault (limit/not present) */
    "#GP General Protection",     /* Many causes: segment, privilege, etc. */
    "#PF Page Fault",             /* Page not present, protection violation */
    "Reserved",                   /* Intel reserved, shouldn't fire */
    
    /* Vector 16-23 */
    "#MF x87 FP Exception",       /* x87 FPU floating-point error */
    "#AC Alignment Check",        /* Unaligned memory access (if enabled) */
    "#MC Machine Check",          /* Processor or bus error (serious!) */
    "#XF SIMD FP Exception",      /* SSE/AVX floating-point exception */
    "Virtualization",             /* Virtualization exception (EPT, etc.) */
    "Control Protection",         /* Control-flow enforcement (CET) */
    "Reserved",                   /* Intel reserved */
    "Reserved",                   /* Intel reserved */
    
    /* Vector 24-31 */
    "Reserved",                   /* Intel reserved */
    "Reserved",                   /* Intel reserved */
    "Reserved",                   /* Intel reserved */
    "Reserved",                   /* Intel reserved */
    "Reserved",                   /* Intel reserved */
    "Reserved",                   /* Intel reserved */
    "Reserved",                   /* Intel reserved */
    "Reserved"                    /* Intel reserved */
};

static bool exception_can_kill_user_task(uint32_t vector)
{
    switch (vector) {
        case 2:   /* NMI */
        case 8:   /* Double Fault */
        case 18:  /* Machine Check */
            return false;
        default:
            return true;
    }
}

static volatile uint32_t timer_ticks = 0;

/* Bottom-half (softirq) deferral: the timer ISR sets this; timer_softirq_run()
 * drains it in task context. See the IRQ0 handler and timer_softirq_run(). */
volatile uint32_t timer_softirq_pending = 0;

/*=============================================================================
 * FUNCTION: timer_softirq_run
 * PURPOSE: Run deferred timer "bottom half" work in TASK context.
 *
 * Called from the ktimerd kernel task (see kernel.c). Must NOT run in
 * interrupt context — that is the whole point: heavy work here would corrupt
 * interrupted computations. Idempotent and cheap when nothing is pending.
 *=============================================================================*/
void timer_softirq_run(void) {
    /* Snapshot + clear the pending flag atomically w.r.t. the ISR. */
    CRITICAL_SECTION_ENTER();
    uint32_t pending = timer_softirq_pending;
    timer_softirq_pending = 0;
    uint32_t now_ticks = timer_ticks;
    CRITICAL_SECTION_EXIT();

    if (!pending) {
        return;
    }

    /* TCP / DHCP periodic timers (10ms per tick at 100Hz). */
    tcp_tick(now_ticks * 10);
    dhcp_tick(now_ticks * 10);

    /* EDR Phase 3 periodic detection (~1s). */
    if (now_ticks % 100 == 0) {
        edr_advanced_periodic_check();
    }

    /* Periodic CSPRNG reseed (~60s). */
    if (now_ticks % 6000 == 0) {
        csprng_periodic_reseed();
    }
}

/*=============================================================================
 * FUNCTION: get_timer_ticks
 *
 * Returns the value of the timer tick counter.
 * Each tick represents one timer interrupt (10 ms at 100 Hz).
 *=============================================================================
 * SECURITY FIX (AUDIT 5B): Atomic 32-bit Timer Counter Access
 *
 * VULNERABILITY: Non-Atomic 32-bit Read (Data Tearing)
 *
 * OLD CODE (VULNERABLE):
 * return timer_ticks;  // Direct read without protection
 *
 * PROBLEM: Reading 32-bit integer is NOT atomic on 32-bit x86 architecture
 * - Requires TWO 16-bit bus cycles (low 16 bits, then high 16 bits)
 * - If timer interrupt fires BETWEEN the two reads, result is "torn"
 * - Returned value contains half old data, half new data
 *
 * PRODUCTION FAILURE SCENARIO:
 * 1. timer_ticks = 0x00008FFF (36863 ticks)
 * 2. CPU reads low 16 bits: 0x8FFF
 * 3. **INTERRUPT FIRES** → timer_ticks increments to 0x00009000 (36864)
 * 4. CPU reads high 16 bits: 0x0000
 * 5. Result: 0x00008FFF (correct? NO!)
 *    OR worse: if increment crosses 64K boundary:
 *    timer_ticks was 0x0000FFFF (65535), interrupt makes it 0x00010000
 *    CPU reads: low=0xFFFF, **INTERRUPT**, high=0x0001
 *    Result: 0x0001FFFF (131071) instead of 65535 or 65536!
 *
 * SECURITY IMPACT:
 * - Corrupted time measurements (timers expire incorrectly)
 * - Incorrect timeout calculations (delays too short or too long)
 * - Infinite loops in timing logic (while (get_timer_ticks() < target))
 * - Denial of Service: Tasks never wake from sleep
 * - Scheduler starvation: Round-robin timing broken
 *
 * FIX: Atomic Read Using Critical Section
 * - Disable interrupts before reading (CRITICAL_SECTION_ENTER)
 * - Read 32-bit value atomically (no interrupt can split the read)
 * - Re-enable interrupts after reading (CRITICAL_SECTION_EXIT)
 * - Guarantees: Caller receives consistent value (all 32 bits from same instant)
 *
 * WHY THIS IS SAFE:
 * - Critical section duration: ~3 CPU cycles (negligible interrupt latency)
 * - timer_ticks only modified by timer interrupt (no other writers)
 * - Disabling interrupts briefly ensures atomic snapshot
 * - Industry standard pattern (Linux, BSD, RTOS all do this)
 *===========================================================================*/
uint32_t get_timer_ticks(void) {
    uint32_t ticks;
    CRITICAL_SECTION_ENTER();
    ticks = timer_ticks;
    CRITICAL_SECTION_EXIT();
    return ticks;
}

/*=============================================================================
 * FUNCTION: isr_common_handler
 * PURPOSE: Main interrupt dispatcher (called from isr.S)
 *
 * PREEMPTIVE SCHEDULING: This function receives a pointer to the interrupt
 * stack frame. For timer interrupts, we can modify this frame to switch tasks.
 * When we return and iret executes, the modified state is restored!
 *
 * SECURITY (v1.18): Interrupt Context Tracking
 * - We track when we're inside an interrupt handler to prevent dangerous
 *   operations like blocking (scheduler_block_task) from being called.
 * - interrupt_context_enter() increments the nesting counter
 * - interrupt_context_exit() decrements it before returning
 *============================================================================*/
void isr_common_handler(interrupt_regs_t* regs)
{
    /*=========================================================================
     * SECURITY: Mark entry into interrupt context
     * This allows other code to detect if they're being called from an
     * interrupt handler and prevent dangerous operations like blocking.
     *=======================================================================*/
    interrupt_context_enter();

    uint32_t vector = regs->vector;
    uint32_t err = regs->err_code;

    /*=========================================================================
     * EXCEPTION HANDLING (Vectors 0-31)
     *=========================================================================*/
    if (vector < 32) {

        /*=====================================================================
         * SECURITY FIX (Issue 5.3): Lazy FPU Switching - Handle #NM exception
         *
         * Vector 7 (Device Not Available) is triggered when a task tries to
         * use FPU/SSE instructions while CR0.TS bit is set. This is the core
         * of lazy FPU switching optimization.
         *
         * CRITICAL: We must handle this exception BEFORE the generic handler
         * below, otherwise we'd panic on every FPU use!
         *===================================================================*/
        if (vector == 7) {
            /* Call lazy FPU switcher */
            scheduler_handle_fpu_exception();

            /* Return to interrupted code - FPU is now available */
            interrupt_context_exit();
            return;
        }

        if ((regs->cs & 0x3) == 0x3 && exception_can_kill_user_task(vector)) {
            task_t* current = task_current();
            uint16_t uid = current ? current->uid : 0;
            uint16_t pid = current ? current->pid : 0;

            audit_log(AUDIT_SEC_EXPLOIT_ATTEMPT, AUDIT_ERROR, uid,
                      "Contained user exception: PID=%u vector=%u %s eip=0x%08x err=0x%x",
                      pid, (unsigned int)vector, exc_name[vector],
                      (unsigned int)regs->eip, (unsigned int)err);

            kprintf("[EXCEPTION] Containing user exception: PID=%u '%s' %s "
                    "EIP=0x%08x ERR=0x%08x\n",
                    (unsigned int)pid,
                    current ? current->name : "<unknown>",
                    exc_name[vector],
                    (unsigned int)regs->eip,
                    (unsigned int)err);

            interrupt_context_exit();
            scheduler_terminate_current_from_interrupt(regs);
        }

        /*=====================================================================
         * SECURITY FIX (Issue 7.1): Production Secure Panic Mode
         *
         * VULNERABILITY: Detailed register dumps aid attackers in debugging
         * exploits by revealing precise crash state, memory layout, and code
         * structure.
         *
         * SOLUTION: Compile-time flag to control information disclosure:
         * - DEVELOPMENT: Full diagnostics for debugging (default)
         * - PRODUCTION: Minimal output with crash ID only
         *
         * BENEFITS:
         * - Prevents information leakage to attackers
         * - Maintains audit trail for forensics
         * - Preserves debugging capability in development
         *===================================================================*/

        #ifndef PRODUCTION_BUILD
        /* DEVELOPMENT MODE: Full diagnostics for debugging */

        /* Print exception banner */
        kprintf("\n*** CPU EXCEPTION ***\n");

        /* Print vector and exception name */
        kprintf("Vector : %u (%s)\n", vector, exc_name[vector]);

        /* Print error code (interpretation varies by exception type) */
        kprintf("Error  : 0x%08x\n", err);

        /* Print EIP (instruction pointer) to help debug */
        kprintf("EIP    : 0x%08x\n", regs->eip);
        kprintf("CS     : 0x%04x\n", regs->cs);

        /* Print all general-purpose registers for diagnosis */
        kprintf("EAX=0x%08x EBX=0x%08x ECX=0x%08x EDX=0x%08x\n",
                regs->eax, regs->ebx, regs->ecx, regs->edx);
        kprintf("ESI=0x%08x EDI=0x%08x EBP=0x%08x\n",
                regs->esi, regs->edi, regs->ebp);
        kprintf("EFLAGS=0x%08x\n", regs->eflags);

        /* Get current ESP (after interrupt pushes) */
        uint32_t current_esp;
        __asm__ volatile("mov %%esp, %0" : "=r"(current_esp));
        kprintf("Current ESP (in handler)=0x%08x\n", current_esp);

        /* Dump raw stack contents (16 dwords from current stack pointer) */
        kprintf("\nStack dump:\n");
        uint32_t* stack_ptr = (uint32_t*)current_esp;
        for (int i = 0; i < 16; i++) {
            if (i % 4 == 0) kprintf("  [ESP+%02x]: ", i * 4);
            kprintf("0x%08x ", stack_ptr[i]);
            if (i % 4 == 3) kprintf("\n");
        }

        #else
        /* PRODUCTION MODE: Minimal output, no register/stack dumps */

        /* Generate unique crash ID (hash of timestamp + vector + error) */
        uint32_t crash_id = (uint32_t)(timer_ticks ^ ((uint64_t)vector << 24) ^ err);

        kprintf("\n");
        kprintf("*************************************************************\n");
        kprintf("* KERNEL PANIC                                              *\n");
        kprintf("*************************************************************\n");
        kprintf("\n");
        kprintf("Crash ID: 0x%08x\n", crash_id);
        kprintf("\n");
        kprintf("The system has encountered a critical error and must halt.\n");
        kprintf("Please contact technical support with the Crash ID above.\n");
        kprintf("\n");

        /* Suppress detailed output, but keep it for reference if needed */
        (void)regs;  /* Suppress unused warning */

        #endif  /* PRODUCTION_BUILD */

        /*=====================================================================
         * SECURITY AUDIT: Log memory violations before panic
         * NOTE: Audit logging happens in ALL modes (dev + production)
         * Only console output is controlled by PRODUCTION_BUILD flag
         *===================================================================*/
        if (vector == 14) {
            uint32_t cr2;

            /* Read CR2 register (contains faulting linear address) */
            __asm__ volatile ("mov %%cr2,%0" : "=r"(cr2));

            #ifndef PRODUCTION_BUILD
            /* Development: Show CR2 on console for debugging */
            kprintf("CR2=0x%08x\n", (unsigned int)cr2);
            #else
            /* Production: CR2 only in audit logs, not on console */
            (void)cr2;  /* Will be used in audit_log below */
            #endif

            /* AUDIT: Page fault (memory violation) */
            task_t* current = task_current();
            uint16_t uid = current ? current->uid : 0;
            uint16_t pid = current ? current->pid : 0;

            /* Determine violation type from error code */
            bool present = (err & 0x1) != 0;      /* Page present */
            bool write = (err & 0x2) != 0;        /* Write access */
            bool user = (err & 0x4) != 0;         /* User mode */
            /* Reserved bits and instruction fetch not used currently */
            (void)(err); /* Suppress unused warning */

            /* Log to audit system */
            audit_log(AUDIT_SEC_MEMORY_VIOLATION, AUDIT_CRITICAL, uid,
                      "Page fault: PID=%u addr=0x%08x %s %s %s err=0x%x",
                      pid, (unsigned int)cr2,
                      present ? "PROT" : "NOT_PRESENT",
                      write ? "WRITE" : "READ",
                      user ? "USER" : "KERNEL",
                      (unsigned int)err);

            /* Additional logging for potential exploit attempts */
            if (user && !present) {
                /* User mode accessing unmapped memory - potential exploit */
                audit_log(AUDIT_SEC_EXPLOIT_ATTEMPT, AUDIT_CRITICAL, uid,
                          "Possible exploit: user process accessing unmapped memory 0x%08x",
                          (unsigned int)cr2);
            }
        }

        /*=====================================================================
         * SECURITY FIX: Use kernel_panic() instead of inline halt
         *
         * IMPROVEMENTS:
         * 1. Recursion protection - prevents cascading panics if exception
         *    occurs during panic handling
         * 2. Consistent error handling - centralizes panic logic
         * 3. Serial output - ensures error is logged even if VGA fails
         * 4. Future extensibility - easier to add core dumps, stack traces
         * 5. AUDIT LOGGING - all exceptions are now logged for forensics
         *===================================================================*/
        kernel_panic(exc_name[vector]);

        /* UNREACHABLE - kernel_panic() never returns */
    }

    /*=========================================================================
     * HARDWARE IRQ HANDLING (Vectors 32-47)
     *=========================================================================*/
    if (vector >= 32 && vector <= 47) {
        /* Calculate IRQ number from vector */
        uint8_t irq = (uint8_t)(vector - 32);

        /*=====================================================================
         * SECURITY FIX (AUDIT 9F): PIC Spurious Interrupt Detection
         *
         * VULNERABILITY: Spurious Interrupt EOI Corruption
         *
         * PROBLEM: IRQ 7 and IRQ 15 Spurious Interrupt Handling
         * The 8259 PIC can generate spurious interrupts on IRQ 7 (master) and
         * IRQ 15 (slave) under certain conditions:
         * - Interrupt request line de-asserted before CPU acknowledges
         * - Electrical noise on IRQ lines
         * - Race conditions during IRQ masking
         *
         * DETECTION: Read PIC's In-Service Register (ISR)
         * For a genuine interrupt, the IRQ's bit will be SET in the ISR.
         * For a spurious interrupt, the IRQ's bit will be CLEAR in the ISR.
         *
         * CRITICAL HANDLING REQUIREMENTS:
         * 1. IRQ 7 (Master Spurious):
         *    - DO NOT send EOI to master PIC
         *    - Return immediately
         *
         * 2. IRQ 15 (Slave Spurious):
         *    - Send EOI to MASTER PIC only (cascade interrupt must complete)
         *    - DO NOT send EOI to slave PIC
         *    - Return immediately
         *
         * CONSEQUENCES OF INCORRECT HANDLING:
         * - Sending EOI for spurious IRQ 7: Clears wrong ISR bit → IRQ stuck
         * - Not sending EOI for spurious IRQ 15: Master PIC IRQ 2 stuck
         * - System hangs, interrupt storm, or complete lockup
         *
         * REFERENCES:
         * - Intel 8259A Datasheet: Section on Spurious Interrupts
         * - OSDev Wiki: PIC Spurious IRQs
         *===================================================================*/

        /* Check for spurious IRQ 7 (last IRQ on master PIC) */
        if (irq == 7) {
            /* Read ISR to check if this is a real interrupt */
            if (!pic_read_isr(irq)) {
                /* SPURIOUS IRQ 7 DETECTED */
                /* DO NOT send EOI - return immediately */
                interrupt_context_exit();
                return;
            }
        }

        /* Check for spurious IRQ 15 (last IRQ on slave PIC) */
        if (irq == 15) {
            /* Read ISR to check if this is a real interrupt */
            if (!pic_read_isr(irq)) {
                /* SPURIOUS IRQ 15 DETECTED */
                /* Send EOI to MASTER ONLY (cascade must complete) */
                __asm__ volatile(
                    "outb %0, %1"               /* OUT 0x20, AL (AL = 0x20) */
                    :                           /* No outputs */
                    : "a"((uint8_t)0x20),       /* Input: AL = 0x20 (EOI command) */
                      "Nd"((uint16_t)0x20)      /* Input: port = 0x20 (master PIC) */
                    : "memory"                  /* Clobber: has memory side effects */
                );
                __asm__ volatile("outb %%al, $0x80" : : "a"(0) : "memory");

                /* DO NOT send EOI to slave - return immediately */
                interrupt_context_exit();
                return;
            }
        }

        /*=====================================================================
         * NORMAL (NON-SPURIOUS) IRQ HANDLING: Send EOI
         * This allows the PIC to service new interrupts while we process
         * the current one, reducing interrupt latency and preventing PIC lockout
         *===================================================================*/

        /* Slave PIC (IRQ 8-15): Send EOI to both slave and master */
        if (irq >= 8) {
            /* Send EOI to slave PIC (0xA0) */
            __asm__ volatile(
                "outb %0, %1"           /* OUT 0xA0, AL (AL = 0x20) */
                :                       /* No outputs */
                : "a"((uint8_t)0x20),   /* Input: AL = 0x20 (EOI command) */
                  "Nd"((uint16_t)0xA0)  /* Input: port = 0xA0 (slave PIC) */
                : "memory"              /* Clobber: has memory side effects */
            );
            /* CRITICAL: I/O serialization barrier - ensures outb completes before continuing */
            __asm__ volatile("outb %%al, $0x80" : : "a"(0) : "memory");
        }

        /* Master PIC (all IRQs): Always send EOI to master */
        __asm__ volatile(
            "outb %0, %1"               /* OUT 0x20, AL (AL = 0x20) */
            :                           /* No outputs */
            : "a"((uint8_t)0x20),       /* Input: AL = 0x20 (EOI command) */
              "Nd"((uint16_t)0x20)      /* Input: port = 0x20 (master PIC) */
            : "memory"                  /* Clobber: has memory side effects */
        );
        /* CRITICAL: I/O serialization barrier - ensures EOI completes before IRQ handler returns */
        __asm__ volatile("outb %%al, $0x80" : : "a"(0) : "memory");

        /*=====================================================================
         * IRQ0: TIMER - PREEMPTIVE SCHEDULING WITH IRETD
         *===================================================================*/
        if (irq == 0) {
            /* Increment the global timer tick counter */
            timer_ticks++;

            /*=================================================================
             * BOTTOM-HALF DEFERRAL (root-cause fix for interrupt corruption)
             *
             * The timer "bottom half" work — tcp_tick / dhcp_tick /
             * edr_advanced_periodic_check / csprng reseed — used to run HERE,
             * in interrupt context, directly on the interrupted thread's
             * stack. That heavy work (e.g. edr_fim_hash_file has a ~4KB frame)
             * corrupted long-running interrupted computations
             * (PBKDF2/ECDSA/SSH) non-deterministically, breaking password
             * login and signature verification.
             *
             * Fix: the ISR only records that a tick is pending; the actual
             * work runs in TASK context from timer_softirq_run(), called by a
             * dedicated kernel task (ktimerd). This is the standard
             * top-half/bottom-half (softirq) split. See timer_softirq_run().
             *===============================================================*/
            timer_softirq_pending = 1;

            /*=================================================================
             * PREEMPTIVE MULTITASKING WITH IRETD
             *
             * The scheduler may suspend the current task here, mid-ISR, on
             * its own kernel stack via context_switch(). It resumes later by
             * finishing this ISR, so the interrupt frame is NOT rewritten;
             * `regs` is passed only for ABI stability with isr.S.
             *
             * This is true preemptive scheduling - tasks are forcibly
             * switched even if they don't call yield().
             *===============================================================*/
            scheduler_schedule_from_interrupt(regs);
        }

        /*=====================================================================
         * IRQ1: KEYBOARD
         *===================================================================*/
        else if (irq == 1) {
            /* Call keyboard IRQ handler */
            keyboard_irq_handler();
        }

        /*=====================================================================
         * IRQ11: E1000 NETWORK CARD
         *===================================================================*/
        else if (irq == 11) {
            /* Poll E1000 for received packets */
            e1000_poll_rx();
            
            /* Note: E1000 interrupt handling happens here
             * The NIC signals us when:
             * - Packet received (RX descriptor has data)
             * - Packet transmitted (TX descriptor processed)
             * - Link status changed
             * - Errors occurred
             */
        }

        /* EOI already sent at the beginning of IRQ handling for low latency */
        interrupt_context_exit();
        return;
    }

    /* SPURIOUS OR UNHANDLED INTERRUPTS (Vectors 48-255) */
    kprintf("\n[warn] Unhandled vector: %u (err=0x%08x)\n", vector, err);

    /*=========================================================================
     * SECURITY: Mark exit from interrupt context
     * Must be called before every return path from this function
     *=======================================================================*/
    interrupt_context_exit();
}

/*=============================================================================
 * DOUBLE FAULT HANDLER (ABORT-CLASS EXCEPTION)
 *
 * CRITICAL SECURITY AND STABILITY FUNCTION
 *
 * Double Fault (vector 8) is triggered when the CPU encounters an exception
 * while trying to handle a previous exception. This typically indicates:
 * - Stack corruption (most common)
 * - Invalid exception handler
 * - Nested page faults
 * - Corrupt IDT or GDT
 *
 * WHY DEDICATED STACK IS MANDATORY:
 * If the main kernel stack is corrupted, attempting to use it during exception
 * handling will cause a Triple Fault and immediate CPU reset with NO diagnostics.
 * By switching to a dedicated stack BEFORE any stack operations, we ensure:
 * 1. Ability to print crash diagnostics (vital for security analysis)
 * 2. Graceful halt instead of mysterious reboot
 * 3. Forensic evidence preservation
 *
 * PRODUCTION REQUIREMENT:
 * Per industry best practices (Linux, BSD, Windows all use dedicated exception
 * stacks), this handler is CRITICAL for diagnosing kernel bugs and security
 * vulnerabilities in production systems.
 *=============================================================================*/
void double_fault_task_entry(void) {
    /*=========================================================================
     * ENTERED BY A HARDWARE TASK SWITCH, NOT A CALL.
     *
     * There is no return address, no pushed error code and no register frame
     * on this stack -- the CPU saved the interrupted context into the OUTGOING
     * TSS and loaded ours. So this function takes no arguments and MUST NOT
     * return: there is nothing to return to. It halts.
     *
     * The faulting state is read from the main TSS, which is where the CPU
     * just wrote it. df_tss.prev_tss holds the backlink selector confirming
     * which task was interrupted.
     *=======================================================================*/
    tss_t* faulted = tss_get();
    tss_t* self    = tss_get_double_fault_tss();

    #ifndef PRODUCTION_BUILD
    kprintf("\n");
    kprintf("*************************************************************\n");
    kprintf("* CRITICAL SYSTEM FAILURE: DOUBLE FAULT EXCEPTION           *\n");
    kprintf("*************************************************************\n");
    kprintf("\n");
    kprintf("A Double Fault occurred: the CPU hit an exception while trying\n");
    kprintf("to deliver a previous one. Common causes:\n");
    kprintf(" - Kernel stack overflow or corruption\n");
    kprintf(" - Invalid exception handler\n");
    kprintf(" - Nested page faults\n");
    kprintf(" - Corrupt IDT, GDT, or TSS\n");
    kprintf("\n");
    kprintf("Handled via task gate on a dedicated stack (top=0x%08x),\n",
            tss_get_double_fault_stack_top());
    kprintf("so this dump survives even a fully exhausted kernel stack.\n");
    kprintf("\n");
    kprintf("Interrupted task state (read from the outgoing TSS):\n");
    kprintf("  EIP=0x%08x  EFLAGS=0x%08x  CR3=0x%08x\n",
            faulted->eip, faulted->eflags, faulted->cr3);
    kprintf("  EAX=0x%08x  EBX=0x%08x  ECX=0x%08x  EDX=0x%08x\n",
            faulted->eax, faulted->ebx, faulted->ecx, faulted->edx);
    kprintf("  ESI=0x%08x  EDI=0x%08x  EBP=0x%08x  ESP=0x%08x\n",
            faulted->esi, faulted->edi, faulted->ebp, faulted->esp);
    kprintf("  CS=0x%04x  SS=0x%04x  DS=0x%04x  ES=0x%04x  FS=0x%04x  GS=0x%04x\n",
            (uint16_t)faulted->cs, (uint16_t)faulted->ss, (uint16_t)faulted->ds,
            (uint16_t)faulted->es, (uint16_t)faulted->fs, (uint16_t)faulted->gs);
    kprintf("  Ring: %u   esp0=0x%08x ss0=0x%04x\n",
            (uint32_t)(faulted->cs & 3), faulted->esp0, (uint16_t)faulted->ss0);
    kprintf("  Backlink (prev_tss in DF TSS) = 0x%04x\n",
            (uint16_t)self->prev_tss);

    /*=====================================================================
     * Stack-overflow tell: ESP at or below the guard page of the task
     * stack. Naming it matters -- this is the case that used to triple
     * fault silently, so if it is what happened, say so explicitly.
     *
     * The test is DISTANCE FROM esp0, not page equality. esp0 is the TOP
     * of the kernel stack and it grows DOWN, so an exhausted stack puts
     * ESP as far BELOW esp0 as possible -- a same-page test would only
     * ever fire on a stack that is nearly EMPTY, i.e. exactly backwards.
     * Measured on a real dftest run: esp0=0x004d8000, ESP=0x00402ff0,
     * which is 741 KB past the base of a 128 KB stack (it had run through
     * the guard page and kept going).
     *
     * Anything at or below the base is past the guard page by definition.
     * Report the depth either way: a plausible-looking ESP that is already
     * 90% of the way down is worth seeing before it becomes the next #DF.
     *===================================================================*/
    kprintf("\n");
    if (faulted->esp != 0 && faulted->esp0 != 0 && faulted->esp < faulted->esp0) {
        uint32_t stack_bytes = (uint32_t)KERNEL_TASK_STACK_PAGES * 4096u;
        uint32_t stack_base  = faulted->esp0 - stack_bytes;
        uint32_t used        = faulted->esp0 - faulted->esp;

        /* "used" can EXCEED the capacity: once ESP runs past the base it
         * keeps descending, so this is the distance below esp0, not a
         * percentage. A figure larger than the stack size is itself the
         * overflow evidence -- label it so nobody reads it as a quota. */
        kprintf("  Kernel stack: base=0x%08x top=0x%08x (%u KB capacity)\n",
                stack_base, faulted->esp0, stack_bytes / 1024u);
        kprintf("  ESP is %u KB below esp0%s\n", used / 1024u,
                (used > stack_bytes) ? " -- PAST THE BASE" : "");

        if (faulted->esp <= stack_base) {
            kprintf("NOTE: faulting ESP is at or below the base of the kernel\n");
            kprintf("      stack -- it ran through the guard page. Kernel\n");
            kprintf("      stack exhaustion is the cause.\n");
        } else if (used > (stack_bytes - stack_bytes / 8u)) {
            kprintf("NOTE: over 87%% of the kernel stack was consumed --\n");
            kprintf("      stack exhaustion is the likely cause.\n");
        }
    }
    kprintf("The system has been halted to prevent further damage.\n");
    kprintf("\n");
    #else
    uint32_t crash_id = (uint32_t)(timer_ticks ^ (8ULL << 24) ^ faulted->eip);
    kprintf("\n");
    kprintf("*************************************************************\n");
    kprintf("* CRITICAL SYSTEM FAILURE                                   *\n");
    kprintf("*************************************************************\n");
    kprintf("\n");
    kprintf("Crash ID: 0x%08x\n", crash_id);
    kprintf("Error Type: Double Fault (Critical Exception)\n");
    kprintf("\n");
    kprintf("The system has encountered an unrecoverable error.\n");
    kprintf("Please contact technical support with the Crash ID above.\n");
    kprintf("\n");
    (void)self;
    #endif  /* PRODUCTION_BUILD */

    /* ABORT-class: never resume. Returning would IRET into a corrupt task. */
    __asm__ volatile("cli");
    while (1) {
        __asm__ volatile("hlt");
    }
}
