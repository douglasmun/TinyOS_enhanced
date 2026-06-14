/*=============================================================================
 *  kprintf.c â€" TinyOS unified printf (VGA + serial) with flags & width
 *============================================================================*/
#include "kernel.h"
#include "kprintf.h"
#include "serial.h"
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

/* ---------- low-level unified sink ---------- */
static inline void kputc(char c) {          /* mirror to both sinks */
    console_putc(c);
    serial_putc(c);
}
/*=============================================================================
 * OUTPUT SINK
 * buf == NULL: emit to console/serial via kputc.
 * buf != NULL: store into buf (truncating at size-1); pos always counts the
 * characters that would have been written (vsnprintf-style semantics).
 *=============================================================================*/
typedef struct {
    char* buf;
    size_t size;
    size_t pos;
} fmt_sink_t;

static void sink_putc(fmt_sink_t* sk, char c) {
    if (!sk->buf) {
        kputc(c);
    } else if (sk->size > 0 && sk->pos < sk->size - 1) {
        sk->buf[sk->pos] = c;
    }
    sk->pos++;
}

static void sink_puts(fmt_sink_t* sk, const char* s) {
    while (*s) sink_putc(sk, *s++);
}

/*=============================================================================
 * NUMBER-TO-STRING CONVERSION HELPERS
 *
 * SECURITY FIX: Buffer size increased to prevent overflow for base-2 conversion
 * MAX_NUM_BUF must accommodate:
 * - Binary (base 2): 64 digits for uint64_t
 * - Plus null terminator: 1 byte
 * - Total: 65 bytes minimum
 *
 * Previous value of 32 was UNSAFE and could cause kernel stack buffer overflow
 * if binary formatting was ever implemented or used.
 *=============================================================================*/
#define MAX_NUM_BUF 65  /* 64 digits for base-2 uint64_t + null terminator */

static int u64_to_str(uint64_t v, unsigned base, bool upper, char* out_rev) {
    /* writes digits into out_rev backwards; returns count */
    static const char L[] = "0123456789abcdef";
    static const char U[] = "0123456789ABCDEF";
    const char* D = upper ? U : L;

    /*=========================================================================
     * SECURITY: Bounds Checking to Prevent Buffer Overflow
     * Max digits for uint64_t:
     * - Binary (base 2): 64 digits (NOW SAFE with 65-byte buffer)
     * - Octal (base 8): 22 digits
     * - Decimal (base 10): 20 digits
     * - Hex (base 16): 16 digits
     *
     * SECURITY FIX: Buffer increased from 32 to 65 bytes to support all bases
     * including binary. Bounds checking still in place for defense in depth.
     *=======================================================================*/
    int n = 0;
    if (v == 0) { out_rev[n++] = '0'; return n; }
    while (v && n < MAX_NUM_BUF) {  /* BOUNDS CHECK: Prevent overflow */
        out_rev[n++] = D[v % base];
        v /= base;
    }
    return n;
}

/* emit_pad - Output padding characters */
static void emit_pad(fmt_sink_t* sk, int count, char ch) {
    while (count-- > 0) {
        sink_putc(sk, ch);
    }
}

/*=============================================================================
 * CORE PRINT FUNCTIONS
 *=============================================================================*/
static void print_signed(fmt_sink_t* sk, long long val, unsigned base,
                         bool upper, int width, bool left, bool zero) {
    char buf[MAX_NUM_BUF];  /* SECURITY: Use MAX_NUM_BUF (65) instead of hardcoded 32 */
    bool neg = (val < 0);
    uint64_t u = neg ? (uint64_t)(-(long long)val) : (uint64_t)val;

    int nd = u64_to_str(u, base, upper, buf);       /* digits reversed */
    int len = nd + (neg ? 1 : 0);                   /* include '-' if needed */

    int pads = (width > len) ? (width - len) : 0;
    if (!left) emit_pad(sk, pads, zero ? '0' : ' ');
    if (neg) sink_putc(sk, '-');
    for (int i = nd - 1; i >= 0; --i) sink_putc(sk, buf[i]);
    if (left) emit_pad(sk, pads, ' ');
}

static void print_unsigned(fmt_sink_t* sk, uint64_t u, unsigned base,
                           bool upper, int width, bool left, bool zero,
                           const char* prefix) {
    char buf[MAX_NUM_BUF];  /* SECURITY: Use MAX_NUM_BUF (65) instead of hardcoded 32 */
    int nd = u64_to_str(u, base, upper, buf);       /* digits reversed */

    int prefix_len = 0;
    if (prefix) while (prefix[prefix_len]) prefix_len++;

    int len = prefix_len + nd;
    int pads = (width > len) ? (width - len) : 0;

    if (!left) emit_pad(sk, pads, zero ? '0' : ' ');
    if (prefix) sink_puts(sk, prefix);
    for (int i = nd - 1; i >= 0; --i) sink_putc(sk, buf[i]);
    if (left) emit_pad(sk, pads, ' ');
}

/*=============================================================================
 * FUNCTION: vformat - core printf engine with %, width, flags -,0 and
 * length l/ll, emitting through a sink (console or buffer).
 * Returns the number of characters produced (vsnprintf-style count).
 *=============================================================================*/
static int vformat(fmt_sink_t* sk, const char* fmt, va_list ap) {
    /* Loop through format string */
    for (const char* p = fmt; *p; ++p) {
        /* Check for format specifier */
        if (*p != '%') {
            /* Literal character: output directly */
            sink_putc(sk, *p);
            continue;
        }

        /* STEP 1: PARSE FLAGS (-, 0) */
        bool left = false;  /* - flag: Left-justify */
        bool zero = false;  /* 0 flag: Zero-padding */
        bool parsing = true;

        while (parsing) {
            switch (*++p) {
                case '-':
                    left = true;
                    break;
                case '0':
                    zero = true;
                    break;
                default:
                    parsing = false;
                    break;
            }
            if (parsing == false) break;
        }

        if (left) zero = false;

        /* STEP 2: PARSE WIDTH */
        int width = 0;
        const int MAX_WIDTH = 256;  /* DoS PREVENTION: Limit to reasonable console width */

        while (*p >= '0' && *p <= '9') {
            int digit = (*p - '0');
            if (width > (MAX_WIDTH / 10)) {
                width = MAX_WIDTH;
                while (*++p >= '0' && *p <= '9');
                break;
            }
            width = width * 10 + digit;
            if (width > MAX_WIDTH) {
                width = MAX_WIDTH;
                while (*++p >= '0' && *p <= '9');
                break;
            }
            ++p;
        }

        /* STEP 3: PARSE LENGTH MODIFIER */
        enum { LEN_DEF, LEN_L, LEN_LL } len = LEN_DEF;
        if (*p == 'l') {
            if (*(p+1) == 'l') {
                len = LEN_LL;
                p += 2;
            } else {
                len = LEN_L;
                ++p;
            }
        }

        /* End of format string reached while parsing a specifier
         * (e.g. fmt ends with '%', '%-', '%0' or '%l'): stop here so the
         * outer loop's ++p cannot walk past the NUL terminator. */
        if (*p == '\0') break;

        /* STEP 4: PROCESS CONVERSION SPECIFIER */
        char c = *p;
        switch (c) {
            case 'c': {
                int ch = va_arg(ap, int);
                int pads = (width > 1) ? (width - 1) : 0;
                if (!left) emit_pad(sk, pads, ' ');
                sink_putc(sk, (char)ch);
                if (left) emit_pad(sk, pads, ' ');
            } break;

            case 's': {
                const char* s = va_arg(ap, const char*);
                if (!s) s = "(null)";
                int n = 0;
                while (s[n]) n++;
                int pads = (width > n) ? (width - n) : 0;
                if (!left) emit_pad(sk, pads, ' ');
                sink_puts(sk, s);
                if (left) emit_pad(sk, pads, ' ');
            } break;

            case 'd':
            case 'i': {
                long long v = (len == LEN_LL) ? va_arg(ap, long long)
                              : (len == LEN_L)  ? (long long)va_arg(ap, long)
                                                : (long long)va_arg(ap, int);
                print_signed(sk, v, 10, false, width, left, zero);
            } break;

            case 'u': {
                unsigned long long v = (len == LEN_LL) ? va_arg(ap, unsigned long long)
                                        : (len == LEN_L)  ? (unsigned long long)va_arg(ap, unsigned long)
                                                          : (unsigned long long)va_arg(ap, unsigned int);
                print_unsigned(sk, v, 10, false, width, left, zero, NULL);
            } break;

            case 'x':
            case 'X': {
                bool upper = (c == 'X');
                unsigned long long v = (len == LEN_LL) ? va_arg(ap, unsigned long long)
                                        : (len == LEN_L)  ? (unsigned long long)va_arg(ap, unsigned long)
                                                          : (unsigned long long)va_arg(ap, unsigned int);
                print_unsigned(sk, v, 16, upper, width, left, zero, NULL);
            } break;

            case 'p': {
                uintptr_t v = (uintptr_t)va_arg(ap, void*);
                int w = (width > 0) ? width : 8;
                print_unsigned(sk, (uint64_t)v, 16, false, w + 2, left, zero, "0x");
            } break;

            case '%':
                sink_putc(sk, '%');
                break;

            default:
                sink_putc(sk, '%');
                sink_putc(sk, c);
                break;
        }
    }

    return (int)sk->pos;
}

/*=============================================================================
 * FUNCTION: kprintf - printf with %, width, flags -,0 and length l/ll
 *=============================================================================*/
void kprintf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vkprintf(fmt, ap);
    va_end(ap);
}

/*=============================================================================
 * FUNCTION: vkprintf - Variadic version of kprintf that takes va_list
 *
 * This function is used by stream_printf() and other functions that need
 * to pass variadic arguments to kprintf-style formatting.
 *=============================================================================*/
int vkprintf(const char* fmt, va_list ap) {
    fmt_sink_t sk = { NULL, 0, 0 };
    return vformat(&sk, fmt, ap);
}

/*=============================================================================
 * FUNCTION: vsnprintf_impl - Format to buffer (like vsnprintf)
 *=============================================================================*/
int vsnprintf_impl(char* buffer, size_t size, const char* format, va_list ap) {
    if (!buffer || size == 0) {
        return 0;
    }

    fmt_sink_t sk = { buffer, size, 0 };
    vformat(&sk, format, ap);

    size_t end = (sk.pos < size - 1) ? sk.pos : size - 1;
    buffer[end] = '\0';
    return (int)sk.pos;
}

/*=============================================================================
 * SECURITY FIX: Format String Attack Prevention
 *=============================================================================
 *
 * FUNCTION: kputs_safe - Safely print untrusted strings
 *
 * PURPOSE:
 * This function provides a format-string-proof way to print untrusted text.
 * It treats ALL characters as literal text, never as format specifiers.
 *
 * SECURITY RATIONALE:
 * -------------------
 * kprintf() is a powerful function that interprets format specifiers like:
 * - %x (read stack values)
 * - %s (read memory at address)
 * - %n (WRITE to memory at address!)
 *
 * If user input containing these characters is passed as the format string,
 * an attacker can:
 * 1. Leak kernel memory (info disclosure)
 * 2. Crash the system (DoS)
 * 3. Achieve arbitrary code execution (RCE)
 *
 * IMPLEMENTATION:
 * ---------------
 * Instead of calling kprintf(user_string), this function uses kprintf("%c")
 * to print each character individually. This ensures user input is NEVER
 * interpreted as a format string.
 *
 * USAGE:
 * ------
 * Use this function when printing:
 * - User input (command arguments, typed text)
 * - Filenames (can contain %x, %s, etc.)
 * - Network data (untrusted remote input)
 * - Any string not under kernel control
 *
 * EXAMPLE:
 * --------
 * char filename[] = "malicious%x%x%s%n.txt";  // User-provided
 * kputs_safe(filename);  // Safely prints: malicious%x%x%s%n.txt
 *
 * NOT this:
 * kprintf(filename);  // DANGEROUS! Would interpret %x, %s, %n
 *=============================================================================*/
void kputs_safe(const char* str) {
    if (!str) {
        /* NULL safety: print indicator instead of crashing */
        kprintf("(null)");
        return;
    }

    /* Print character-by-character to prevent format string interpretation
     * This is the ONLY safe way to print untrusted strings.
     */
    while (*str) {
        kprintf("%c", *str);
        str++;
    }
}
