/*=============================================================================
 *  util.c â€” Freestanding C Library and Kernel Utilities for TinyOS
 *=============================================================================
 * 
 * PURPOSE:
 *   This file provides fundamental utility functions that a kernel needs to
 *   operate in a FREESTANDING environment (no standard C library). It
 *   implements essential string/memory operations and critical error handling.
 *
 */
#include <stddef.h>
#include <stdint.h>
#include "kernel.h"
#include "serial.h"  // For serial output in panic
#include "util.h"

/*=============================================================================
 * FUNCTION: strlen
 *============================================================================*/
/**
 * @brief Computes the length of the string s.
 * @param s Pointer to the null-terminated string.
 * @return size_t The number of characters in the string.
 */
size_t strlen(const char* s) {
    size_t len = 0;
    while (s[len] != '\0') {
        len++;
    }
    return len;
}

/*=============================================================================
 * FUNCTION: strcmp
 *============================================================================*/
/**
 * @brief Compares two strings.
 * @param s1 Pointer to the first null-terminated string.
 * @param s2 Pointer to the second null-terminated string.
 * @return int 0 if equal, < 0 if s1 is less than s2, > 0 if s1 is greater than s2.
 */
int strcmp(const char* s1, const char* s2) {
    while (*s1 != '\0' && *s2 != '\0') {
        if (*s1 != *s2) {
            return (unsigned char)*s1 - (unsigned char)*s2;
        }
        s1++;
        s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

/*=============================================================================
 * FUNCTION: strcasecmp
 *============================================================================*/
/**
 * @brief Compares two strings (case-insensitive).
 * @param s1 Pointer to the first null-terminated string.
 * @param s2 Pointer to the second null-terminated string.
 * @return int 0 if equal (ignoring case), < 0 if s1 < s2, > 0 if s1 > s2.
 */
int strcasecmp(const char* s1, const char* s2) {
    while (*s1 != '\0' && *s2 != '\0') {
        unsigned char c1 = (unsigned char)*s1;
        unsigned char c2 = (unsigned char)*s2;

        // Convert to lowercase
        if (c1 >= 'A' && c1 <= 'Z') {
            c1 += 32;  // 'a' - 'A' = 32
        }
        if (c2 >= 'A' && c2 <= 'Z') {
            c2 += 32;
        }

        if (c1 != c2) {
            return c1 - c2;
        }

        s1++;
        s2++;
    }

    // Handle case where one string is a prefix of the other
    unsigned char c1 = (unsigned char)*s1;
    unsigned char c2 = (unsigned char)*s2;
    if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
    if (c2 >= 'A' && c2 <= 'Z') c2 += 32;

    return c1 - c2;
}

/*=============================================================================
 * FUNCTION: strncmp
 *============================================================================*/
/**
 * @brief Compares up to n characters of two strings.
 * @param s1 Pointer to the first null-terminated string.
 * @param s2 Pointer to the second null-terminated string.
 * @param n Maximum number of characters to compare.
 * @return int 0 if equal (up to n chars), < 0 if s1 < s2, > 0 if s1 > s2.
 */
int strncmp(const char* s1, const char* s2, size_t n) {
    if (n == 0) {
        return 0;
    }
    while (n > 0 && *s1 != '\0' && *s2 != '\0') {
        if (*s1 != *s2) {
            return (unsigned char)*s1 - (unsigned char)*s2;
        }
        s1++;
        s2++;
        n--;
    }
    if (n == 0) {
        return 0;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

/*=============================================================================
 * FUNCTION: strstr
 *============================================================================*/
/**
 * @brief Finds the first occurrence of substring in string.
 * @param haystack The string to search in.
 * @param needle The substring to search for.
 * @return char* Pointer to first occurrence of needle in haystack, or NULL if not found.
 */
char* strstr(const char* haystack, const char* needle) {
    if (!haystack || !needle) {
        return NULL;
    }

    if (*needle == '\0') {
        return (char*)haystack;
    }

    size_t needle_len = strlen(needle);

    for (const char* h = haystack; *h != '\0'; h++) {
        if (*h == *needle) {
            // Check if rest of needle matches
            size_t i;
            for (i = 0; i < needle_len && h[i] != '\0'; i++) {
                if (h[i] != needle[i]) {
                    break;
                }
            }
            if (i == needle_len) {
                return (char*)h;
            }
        }
    }

    return NULL;
}

/*=============================================================================
 * FUNCTION: strchr
 *============================================================================*/
/**
 * @brief Finds the first occurrence of character in string.
 * @param s The string to search in.
 * @param c The character to search for.
 * @return char* Pointer to first occurrence of c in s, or NULL if not found.
 */
char* strchr(const char* s, int c) {
    if (!s) {
        return NULL;
    }

    while (*s != '\0') {
        if (*s == (char)c) {
            return (char*)s;
        }
        s++;
    }

    // Check if c is the null terminator
    if ((char)c == '\0') {
        return (char*)s;
    }

    return NULL;
}

/*=============================================================================
 * FUNCTION: safe_strcpy
 *============================================================================*/
/**
 * @brief Safe string copy with bounds checking (like strlcpy)
 * @param dst Destination buffer
 * @param src Source string
 * @param size Size of destination buffer
 * @return Length of src (for truncation detection)
 *
 * SECURITY: Always null-terminates dst (unless size == 0)
 * If src length >= size, dst will be truncated
 */
size_t safe_strcpy(char* dst, const char* src, size_t size) {
    if (!dst || !src || size == 0) {
        return src ? strlen(src) : 0;
    }

    size_t src_len = 0;
    size_t i;

    /* Copy up to size-1 characters */
    for (i = 0; i < size - 1 && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }

    /* Always null-terminate */
    dst[i] = '\0';

    /* Calculate full source length (for truncation detection) */
    if (src[i] != '\0') {
        /* We stopped early, continue counting */
        src_len = i;
        while (src[src_len] != '\0') {
            src_len++;
        }
    } else {
        src_len = i;
    }

    return src_len;
}

/*=============================================================================
 * FUNCTION: memcmp
 *============================================================================*/
/**
 * @brief Compares two blocks of memory.
 * @param s1 Pointer to block 1.
 * @param s2 Pointer to block 2.
 * @param n Number of bytes to compare.
 * @return int 0 if equal, < 0 if s1 is less than s2, > 0 if s1 is greater than s2.
 */
int memcmp(const void* s1, const void* s2, size_t n) {
    const uint8_t* p1 = (const uint8_t*)s1;
    const uint8_t* p2 = (const uint8_t*)s2;

    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }
    return 0;
}

/*=============================================================================
 * FUNCTION: memset
 *=============================================================================*/
void* memset(void* dst, int val, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    for (size_t i = 0; i < n; ++i) {
        d[i] = (unsigned char)val;
    }
    return dst;
}

/*=============================================================================
 * FUNCTION: memcpy
 *============================================================================= */
void* memcpy(void* dst, const void* src, size_t n) {
    /*
     * Step 1: Convert void pointers to byte pointers
     */
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;

    /*
     * Step 2: Copy bytes one at a time
     */
    for (size_t i = 0; i < n; ++i) {
        d[i] = s[i];
    }

    /*
     * Step 3: Return original destination pointer
     */
    return dst;
}

/*
 * memmove: like memcpy but SAFE for overlapping regions. memcpy here is a
 * forward byte copy, so an overlapping copy where dst > src (shifting data
 * upward) would clobber not-yet-read source bytes (UB per the C standard).
 * Route any in-place / possibly-overlapping shift through memmove instead.
 */
void* memmove(void* dst, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;

    if (d == s || n == 0) {
        return dst;
    }
    if (d < s) {
        /* Non-overlapping or dst below src: forward copy is safe. */
        for (size_t i = 0; i < n; ++i) {
            d[i] = s[i];
        }
    } else {
        /* dst above src and possibly overlapping: copy backward. */
        for (size_t i = n; i > 0; --i) {
            d[i - 1] = s[i - 1];
        }
    }
    return dst;
}

/*=============================================================================
 * FUNCTION: secure_memzero
 *=============================================================================
 *
 * PURPOSE:
 *   Securely zero memory in a way that cannot be optimized away by the compiler.
 *   Use this for sensitive data like passwords, keys, etc.
 *
 * SECURITY:
 *   Standard memset() can be optimized away by aggressive compilers if they
 *   determine the memory is never read again. Using volatile forces the
 *   compiler to actually perform the write operations.
 *
 * SIGNATURE:
 *   void secure_memzero(void* v, size_t n);
 *
 * PARAMETERS:
 *   v - Pointer to memory region to zero
 *   n - Number of bytes to zero
 *
 */
void secure_memzero(void* v, size_t n) {
    volatile unsigned char* p = (volatile unsigned char*)v;
    while (n--) {
        *p++ = 0;
    }
}

/*=============================================================================
 * FUNCTION: panic
 *=============================================================================
 *
 * PURPOSE:
 *   Handle unrecoverable kernel errors by displaying an error message
 *   and halting the system. This is the "emergency stop" function.
 *
 * SIGNATURE:
 *   NORETURN void panic(const char* msg);
 *
 * OUTPUT FORMAT:
 *
 *   *** KERNEL PANIC ***
 *   Out of physical memory
 *   System halted.
 *
 */
NORETURN void panic(const char* msg) {
    /*
     * STEP 1: DISABLE INTERRUPTS IMMEDIATELY
     */
    __asm__ volatile("cli" ::: "memory");

    /*
     * STEP 2: OUTPUT TO VGA CONSOLE
     */

    /* Clear screen for visibility */
    console_clear();

    /* Display header (universally recognized format) */
    console_puts("*** KERNEL PANIC ***\n");

    /* Display error message (or "<null>" if msg is NULL) */
    console_puts(msg ? msg : "<null>");

    /* Display footer (tells user system is halted) */
    console_puts("\nSystem halted.\n");

    /*
     * STEP 3: OUTPUT TO SERIAL PORT
     */

    /* Newline for separation (in case previous output was in progress) */
    serial_puts("\n*** KERNEL PANIC ***\n");

    /* Same message as VGA */
    serial_puts(msg ? msg : "<null>");

    /* Same footer as VGA */
    serial_puts("\nSystem halted.\n");

    /*
     * STEP 4: HALT FOREVER
     */
    for(;;) {
        __asm__ volatile("hlt");
    }
}

/*=============================================================================
 * FUNCTION: kernel_panic
 *=============================================================================
 *
 * PURPOSE:
 *   Enhanced panic handler with RECURSION PROTECTION. This function prevents
 *   cascading panics (panic-within-panic) that could corrupt state or create
 *   infinite loops.
 *
 * SECURITY RATIONALE:
 *   - If panic() calls a function that triggers an exception (e.g., page fault
 *     in console_puts), we could enter an infinite panic loop.
 *   - Malicious code could intentionally trigger cascading panics to cause DoS
 *     or exploit race conditions in the panic handler.
 *   - Unhandled exceptions (division by zero, page faults) need centralized
 *     handling to prevent system instability.
 *
 * IMPLEMENTATION:
 *   Uses a static flag to detect re-entry. On recursive panic:
 *   - Disable interrupts immediately
 *   - Output minimal error message directly to I/O ports (bypass higher-level
 *     functions that might trigger more exceptions)
 *   - Halt immediately without complex cleanup
 *
 * USAGE:
 *   Exception handlers (interrupts.c) should call kernel_panic() instead of
 *   implementing inline halt logic.
 *
 * SIGNATURE:
 *   NORETURN void kernel_panic(const char* msg);
 *
 */
NORETURN void kernel_panic(const char* msg) {
    /*=========================================================================
     * RECURSION DETECTION: Static flag to track panic state
     *
     * CRITICAL: This must be static (not on stack) because:
     * 1. Stack might be corrupted (stack overflow exception)
     * 2. We need persistent state across function calls
     * 3. Must survive across different call contexts
     *
     * NOTE: Not volatile because we always access it with interrupts disabled
     *=======================================================================*/
    static int in_panic = 0;

    /*=========================================================================
     * STEP 1: DISABLE INTERRUPTS ATOMICALLY BEFORE CHECKING FLAG
     *
     * CRITICAL: Must disable interrupts BEFORE checking in_panic to prevent
     * race condition where:
     * 1. Thread A checks in_panic (0), gets interrupted
     * 2. Thread B enters panic, sets in_panic=1
     * 3. Thread A resumes, also enters panic (thinks it's first)
     *
     * By disabling interrupts first, we make check-and-set atomic.
     *=======================================================================*/
    __asm__ volatile("cli" ::: "memory");

    /*=========================================================================
     * STEP 2: CHECK FOR RECURSIVE PANIC (panic-within-panic)
     *=======================================================================*/
    if (in_panic) {
        /*=====================================================================
         * RECURSIVE PANIC DETECTED - MINIMAL RECOVERY PATH
         *
         * We're already in a panic and panic was called again (probably due
         * to exception in panic handler itself). Do NOT call any complex
         * functions - just halt immediately.
         *
         * Use serial_putc (low-level) instead of serial_puts to minimize
         * risk of triggering more exceptions.
         *===================================================================*/

        /* Output minimal message to serial port (byte-by-byte) */
        const char* recursive_msg = "\n*** RECURSIVE PANIC - HALTING ***\n";
        for (const char* p = recursive_msg; *p; p++) {
            serial_putc(*p);
        }

        /* Halt immediately - no cleanup, no further function calls */
        for(;;) {
            __asm__ volatile("hlt");
        }
    }

    /*=========================================================================
     * STEP 3: MARK AS IN-PANIC (first panic)
     *=======================================================================*/
    in_panic = 1;

    /*=========================================================================
     * STEP 4: DELEGATE TO NORMAL PANIC HANDLER
     *
     * Since this is the first panic, we can safely call the normal panic()
     * function which will do proper cleanup and output formatting.
     *=======================================================================*/
    panic(msg);

    /* UNREACHABLE - panic() never returns */
}

/*=============================================================================
 * FUNCTION: system_halt
 *=============================================================================
 *
 * PURPOSE:
 *   Clean system shutdown without displaying "KERNEL PANIC" message.
 *   Used for intentional shutdowns (shutdown command, ACPI poweroff, etc.)
 *
 * IMPLEMENTATION:
 *   1. Disable interrupts to prevent any further execution
 *   2. Halt CPU indefinitely
 *
 * USAGE:
 *   - shutdown command
 *   - ACPI poweroff sequences
 *   - Any clean system termination
 *
 * SIGNATURE:
 *   NORETURN void system_halt(void);
 *
 */
NORETURN void system_halt(void) {
    /*=========================================================================
     * CLEAN SHUTDOWN: Disable interrupts and halt forever
     *
     * Unlike kernel_panic(), this function does NOT print error messages.
     * It's for intentional, clean system shutdowns where the user/system
     * has already been informed (e.g., "Shutting down..." message already
     * displayed by the shutdown command).
     *=======================================================================*/
    __asm__ volatile("cli" ::: "memory");

    for(;;) {
        __asm__ volatile("hlt");
    }

    /* UNREACHABLE */
}


/* I/O port access functions (16-bit and 32-bit) */
/* Note: 8-bit outb/inb are defined as inline in pic.h */

void outw(uint16_t port, uint16_t val) {
    __asm__ volatile ("outw %0, %1" : : "a"(val), "Nd"(port));
}

uint16_t inw(uint16_t port) {
    uint16_t ret;
    __asm__ volatile ("inw %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

void outl(uint16_t port, uint32_t val) {
    __asm__ volatile ("outl %0, %1" : : "a"(val), "Nd"(port));
}

uint32_t inl(uint16_t port) {
    uint32_t ret;
    __asm__ volatile ("inl %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}
