/*=============================================================================
 * shell.c - TinyOS Interactive Shell
 *=============================================================================*/

#define USER_MODE
#include "../src/syscall.h"

/*-----------------------------------------------------------------------------
 * String Utilities
 *-----------------------------------------------------------------------------*/

// String length
static int strlen(const char* str) {
    int len = 0;
    while (str[len]) len++;
    return len;
}

// String compare
static int strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

// String compare (n characters)
static int strncmp(const char* s1, const char* s2, int n) {
    while (n && *s1 && (*s1 == *s2)) {
        s1++;
        s2++;
        n--;
    }
    if (n == 0) return 0;
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

// Memory set
static void memset(void* dest, int val, int len) {
    unsigned char* d = (unsigned char*)dest;
    while (len--) {
        *d++ = (unsigned char)val;
    }
}

/*-----------------------------------------------------------------------------
 * Shell Commands
 *-----------------------------------------------------------------------------*/

static void cmd_help(void) {
    puts("TinyOS Shell - Available Commands:\n");
    puts("  help   - Show this help message\n");
    puts("  clear  - Clear the screen\n");
    puts("  ps     - List running processes\n");
    puts("  exit   - Exit the shell\n");
    puts("\n");
}

static void cmd_clear(void) {
    // VGA text mode: 80x25
    // Clear by writing spaces
    puts("\x1B[2J\x1B[H");  // ANSI escape codes (if supported)
    // For now, just print newlines
    for (int i = 0; i < 25; i++) {
        puts("\n");
    }
}

static void cmd_ps(void) {
    puts("PID   NAME\n");
    puts("---   ----\n");

    // For now, just show current process
    int pid = getpid();

    write("", 0);  // Placeholder - kernel would need to expose process list
    write("Currently running in PID: ", 26);

    // Convert PID to string
    char pid_str[12];
    int i = 0;
    int temp_pid = pid;

    if (temp_pid == 0) {
        pid_str[i++] = '0';
    } else {
        // Convert to string (reversed)
        int digits = 0;
        while (temp_pid > 0) {
            pid_str[digits++] = '0' + (temp_pid % 10);
            temp_pid /= 10;
        }
        // Reverse
        for (int j = 0; j < digits / 2; j++) {
            char tmp = pid_str[j];
            pid_str[j] = pid_str[digits - 1 - j];
            pid_str[digits - 1 - j] = tmp;
        }
        i = digits;
    }
    pid_str[i] = '\0';

    puts(pid_str);
    puts("\n\n");
    puts("Note: Full process listing not yet implemented\n");
}

static void cmd_exit(void) {
    puts("Exiting shell...\n");
    exit(0);
}

/*-----------------------------------------------------------------------------
 * Command Parser
 *-----------------------------------------------------------------------------*/

static void parse_command(const char* cmd) {
    // Trim leading spaces
    while (*cmd == ' ') cmd++;

    // Empty command
    if (*cmd == '\0' || *cmd == '\n') {
        return;
    }

    // Match commands
    if (strcmp(cmd, "help\n") == 0 || strcmp(cmd, "help") == 0) {
        cmd_help();
    }
    else if (strcmp(cmd, "clear\n") == 0 || strcmp(cmd, "clear") == 0) {
        cmd_clear();
    }
    else if (strcmp(cmd, "ps\n") == 0 || strcmp(cmd, "ps") == 0) {
        cmd_ps();
    }
    else if (strcmp(cmd, "exit\n") == 0 || strcmp(cmd, "exit") == 0) {
        cmd_exit();
    }
    else {
        puts("Unknown command: ");
        write(cmd, strlen(cmd));
        puts("Type 'help' for available commands\n");
    }
}

/*-----------------------------------------------------------------------------
 * Main Shell Loop
 *-----------------------------------------------------------------------------*/

void _start(void) {
    // Set up user-mode data segments
    // Use 0x23 (GDT entry 4, ring 3) not 0x2b (LDT entry 5, ring 3)
    __asm__ volatile(
        "mov $0x2b, %ax\n"
        "mov %ax, %ds\n"
        "mov %ax, %es\n"
        "mov %ax, %fs\n"
        "mov %ax, %gs\n"
    );

    // Welcome message
    puts("\n");
    puts("================================\n");
    puts("  TinyOS Interactive Shell v1.0\n");
    puts("================================\n");
    puts("\n");
    puts("Type 'help' for available commands\n");
    puts("\n");

    // Command buffer
    char cmd_buffer[256];

    // Main shell loop
    while (1) {
        // Print prompt
        puts("tiny$ ");

        // Read command
        memset(cmd_buffer, 0, sizeof(cmd_buffer));
        int bytes_read = read(cmd_buffer, sizeof(cmd_buffer) - 1);

        if (bytes_read > 0) {
            // Null-terminate
            cmd_buffer[bytes_read] = '\0';

            // Parse and execute command
            parse_command(cmd_buffer);
        }
    }

    // Should never reach here
    exit(0);
}
