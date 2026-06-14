/*=============================================================================
 * usermode_test.c - User Mode Test Program
 * Tests ring 3 execution and system calls
 *
 * SECURITY: Test code guarded with TINYOS_ENABLE_TESTS to prevent inclusion
 * in production builds. Define at compile time to enable test functionality.
 *============================================================================*/
#ifdef TINYOS_ENABLE_TESTS

#include <stdint.h>
#include "kprintf.h"

/*-----------------------------------------------------------------------------
 * Function Prototypes
 *-----------------------------------------------------------------------------*/
void user_main(void);

/*-----------------------------------------------------------------------------
 * System Call Numbers as defined in syscall.h
 *-----------------------------------------------------------------------------*/
#define SYS_EXIT        0   // Exit process
#define SYS_WRITE       1   // Write to console
#define SYS_READ        2   // Read from console (future)
#define SYS_GETPID      3   // Get process ID (future)
#define SYS_YIELD       4   // Yield CPU (future)


/*-----------------------------------------------------------------------------
 * System Call Wrapper
 *-----------------------------------------------------------------------------*/
static inline int syscall1(int num, uint32_t arg1) {
    int ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "b"(arg1)
    );
    return ret;
}

static inline int syscall3(int num, uint32_t arg1, uint32_t arg2, uint32_t arg3) {
    int ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "b"(arg1), "c"(arg2), "d"(arg3)
    );
    return ret;
}

/*-----------------------------------------------------------------------------
 * User Mode Write Function
 *-----------------------------------------------------------------------------*/
static void user_write(const char* str) __attribute__((unused));
static void user_write(const char* str) {
    const char* p = str;
    uint32_t len = 0;
    while (*p++) len++;
    syscall3(SYS_WRITE, 1, (uint32_t)str, len);
}

/*-----------------------------------------------------------------------------
 * User Mode Entry Point
 * This function runs in Ring 3 (user mode)
 *-----------------------------------------------------------------------------*/
// Force 16-byte alignment for memcpy optimization
// Use naked attribute to prevent GCC from adding function prologue/epilogue
// This avoids the push %ebp instruction that requires a working stack
__attribute__((section(".user.text")))
__attribute__((aligned(16)))
__attribute__((naked))
void user_main(void) {
    // FIRST: Set up user-mode data segments
    // This must be the first thing we do after entering user mode via iret
    asm volatile(
        "mov $0x2b, %ax\n"      // Load user data segment selector (0x2b = GDT entry 5, RPL=3)
        "mov %ax, %ds\n"        // Set DS
        "mov %ax, %es\n"        // Set ES
        "mov %ax, %fs\n"        // Set FS
        "mov %ax, %gs\n"        // Set GS
    );

    // Make a simple syscall (EAX will have random value, syscall handler will print "hello world")
    asm volatile("int $0x80");

    // Yield back to the scheduler so other tasks can run
    // SYS_YIELD = 4
    asm volatile(
        "mov $4, %%eax\n"    // SYS_YIELD syscall number
        "int $0x80\n"         // Make the syscall
        : : : "eax"
    );

    // After yielding, loop forever but keep yielding
    while(1) {
        // Yield again so we don't hog the CPU
        asm volatile(
            "mov $4, %%eax\n"
            "int $0x80\n"
            : : : "eax"
        );
    }
}

#endif /* TINYOS_ENABLE_TESTS */

