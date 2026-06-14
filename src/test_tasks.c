/*=============================================================================
 * test_tasks.c - Simple Test Tasks for Demonstrating Multitasking
 *
 * This file contains both production tasks (idle) and test tasks.
 * Test tasks are guarded with TINYOS_ENABLE_TESTS.
 *=============================================================================*/
#include "test_tasks.h"
#include "kprintf.h"
#include "scheduler.h"
#include "kernel.h"  /* timer_softirq_run() */

/* get_timer_ticks() / timer_softirq_run() declared in kernel.h */

/*=============================================================================
 * TEST TASKS (only available when TINYOS_ENABLE_TESTS is defined)
 *=============================================================================*/
#ifdef TINYOS_ENABLE_TESTS

/*=============================================================================
 * HELPER FUNCTION: delay
 * PURPOSE: Cooperative delay using scheduler_yield()
 *=============================================================================*/
static void delay(uint32_t ticks) {
    uint32_t start = get_timer_ticks();
    while (get_timer_ticks() - start < ticks) {
        // Yield to other tasks instead of busy-waiting
        scheduler_yield();
    }
}

/*=============================================================================
 * TASK 1: Counter Task A
 * PURPOSE: Count and print 'A' messages
 *=============================================================================*/
void task_counter_a(void) {
    int counter = 0;

    kprintf("[TASK A] Started!\n");

    while (1) {
        counter++;
        kprintf("[TASK A] Count: %d\n", counter);

        // Delay for about 200 ticks (2 seconds at 100 Hz)
        delay(200);

        // After 5 iterations, exit
        if (counter >= 5) {
            kprintf("[TASK A] Exiting after %d iterations\n", counter);
            break;
        }
    }

    // Task finished
    kprintf("[TASK A] Finished\n");

    // Infinite loop (terminated tasks stay here)
    while (1) {
        __asm__ volatile("hlt");
    }
}

/*=============================================================================
 * TASK 2: Counter Task B
 * PURPOSE: Count and print 'B' messages
 *=============================================================================*/
void task_counter_b(void) {
    int counter = 0;

    kprintf("[TASK B] Started!\n");

    while (1) {
        counter++;
        kprintf("[TASK B] Count: %d\n", counter);

        // Delay for about 300 ticks (3 seconds at 100 Hz)
        delay(300);

        // After 5 iterations, exit
        if (counter >= 5) {
            kprintf("[TASK B] Exiting after %d iterations\n", counter);
            break;
        }
    }

    // Task finished
    kprintf("[TASK B] Finished\n");

    // Infinite loop (terminated tasks stay here)
    while (1) {
        __asm__ volatile("hlt");
    }
}

/*=============================================================================
 * TASK 3: Counter Task C
 * PURPOSE: Count and print 'C' messages
 *=============================================================================*/
void task_counter_c(void) {
    int counter = 0;

    kprintf("[TASK C] Started!\n");

    while (1) {
        counter++;
        kprintf("[TASK C] Count: %d\n", counter);

        // Delay for about 150 ticks (1.5 seconds at 100 Hz)
        delay(150);

        // After 5 iterations, exit
        if (counter >= 5) {
            kprintf("[TASK C] Exiting after %d iterations\n", counter);
            break;
        }
    }

    // Task finished
    kprintf("[TASK C] Finished\n");

    // Infinite loop (terminated tasks stay here)
    while (1) {
        __asm__ volatile("hlt");
    }
}

/*=============================================================================
 * TEST TASK: Task that exits immediately (for testing sys_exit)
 * PURPOSE: Test task termination and cleanup
 *=============================================================================*/
void task_exit_test(void) {
    kprintf("[EXIT_TEST] Task started, will exit after 3 seconds...\n");

    // Wait for 3 seconds (300 ticks at 100 Hz)
    delay(300);

    kprintf("[EXIT_TEST] Calling sys_exit(0)...\n");

    // Call sys_exit syscall
    __asm__ volatile(
        "mov $0, %%eax\n"      // SYS_EXIT = 0
        "mov $42, %%ebx\n"     // exit code = 42
        "int $0x80\n"          // syscall interrupt
        : : : "eax", "ebx"
    );

    // Should never reach here
    kprintf("[EXIT_TEST] ERROR: Returned after sys_exit!\n");
    while (1) {
        __asm__ volatile("hlt");
    }
}

#endif /* TINYOS_ENABLE_TESTS */

/*=============================================================================
 * PRODUCTION TASKS (always available)
 *=============================================================================*/

/*=============================================================================
 * IDLE TASK: Runs when no other tasks are ready
 * PURPOSE: Reduce CPU power consumption when idle
 *
 * POWER EFFICIENCY (v1.20):
 * - Uses HLT instruction to halt CPU until next interrupt
 * - Reduces power consumption and thermal output
 * - CPU will wake on timer interrupt (every 10ms) or hardware interrupt
 * - Much more efficient than busy-waiting with scheduler_yield()
 *
 * SECURITY NOTE: HLT is a privileged instruction (ring 0 only)
 * This ensures only kernel code can halt the CPU
 *=============================================================================*/
void task_idle(void) {
    kprintf("[IDLE] Idle task started (power-saving mode) [OK]\n");

    while (1) {
        /*=====================================================================
         * HLT INSTRUCTION - Power-Saving CPU Halt
         *
         * BEHAVIOR:
         * - Halts the CPU until the next interrupt fires
         * - When interrupt occurs, CPU wakes and executes ISR
         * - After ISR completes, execution continues here
         * - Scheduler will switch to a different task if one is ready
         *
         * BENEFITS:
         * - Dramatically reduces CPU power consumption
         * - Lowers thermal output (cooler running)
         * - Battery savings on portable devices
         * - Better for virtualization (QEMU can sleep host CPU)
         *
         * SAFETY:
         * - Interrupts MUST be enabled (sti) before hlt
         * - If interrupts disabled, CPU hangs forever (bad!)
         * - Timer interrupt ensures CPU wakes at least every 10ms
         *===================================================================*/
        __asm__ volatile(
            "sti\n\t"       /* Ensure interrupts are enabled */
            "hlt"           /* Halt CPU until interrupt */
            :               /* No outputs */
            :               /* No inputs */
            : "memory"      /* Clobbers: memory barrier */
        );

        /* CPU woke from interrupt - yield to scheduler */
        /* Scheduler will switch to active task if available */
        scheduler_yield();
    }
}

/*=============================================================================
 * KTIMERD: Timer bottom-half task
 * PURPOSE: Run deferred timer work (tcp_tick/dhcp_tick/EDR/reseed) in TASK
 *          context. The timer ISR only flags pending work (timer_softirq_run);
 *          running it here, off the interrupt path, is the root-cause fix for
 *          the interrupt-corruption bug that broke password login, ECDSA
 *          verification, and the SSH handshake.
 *=============================================================================*/
void task_ktimerd(void) {
    kprintf("[KTIMERD] Timer bottom-half task started [OK]\n");
    while (1) {
        timer_softirq_run();
        /* Yield; we'll be rescheduled on the next tick. timer_softirq_run()
         * is cheap (a flag check) when nothing is pending. */
        scheduler_yield();
    }
}

