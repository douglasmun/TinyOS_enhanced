/*=============================================================================
 * hello.c - Simple User Mode Test Program (ELF)
 *=============================================================================*/

// System call numbers
#define SYS_EXIT  0
#define SYS_WRITE 1
#define SYS_YIELD 4

/*-----------------------------------------------------------------------------
 * System Call Wrappers
 *-----------------------------------------------------------------------------*/
static inline int syscall1(int num, unsigned int arg1) {
    int ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "b"(arg1)
    );
    return ret;
}

static inline int syscall3(int num, unsigned int arg1, unsigned int arg2, unsigned int arg3) {
    int ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "b"(arg1), "c"(arg2), "d"(arg3)
    );
    return ret;
}

/*-----------------------------------------------------------------------------
 * Helper Functions
 *-----------------------------------------------------------------------------*/
static int strlen(const char* str) {
    int len = 0;
    while (str[len]) len++;
    return len;
}

static void write(int fd, const char* str, int len) {
    syscall3(SYS_WRITE, fd, (unsigned int)str, len);
}

static void puts(const char* str) {
    write(1, str, strlen(str));
}

static void yield(void) {
    syscall1(SYS_YIELD, 0);
}

static void exit(int status) {
    syscall1(SYS_EXIT, status);
    while(1);  // Should never reach here
}

/*-----------------------------------------------------------------------------
 * Main Entry Point
 *-----------------------------------------------------------------------------*/
void _start(void) {
    // Set up user-mode data segments
    __asm__ volatile(
        "mov $0x2b, %ax\n"
        "mov %ax, %ds\n"
        "mov %ax, %es\n"
        "mov %ax, %fs\n"
        "mov %ax, %gs\n"
    );

    // Main program
    puts("Hello from ELF!\n");
    puts("This is a user mode program loaded from ELF format.\n");
    puts("Yielding...\n");

    // Yield a few times to show cooperative multitasking
    for (int i = 0; i < 3; i++) {
        yield();
        puts("ELF program resumed!\n");
    }

    puts("ELF program exiting.\n");
    exit(0);
}
