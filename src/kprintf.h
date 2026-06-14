#ifdef NO_DEBUG_LOGGING
#define kprintf(...) ((void)0)
#else
/*=============================================================================
 *  kprintf.h â€” TinyOS unified kernel printf (VGA + serial)
 *============================================================================*/
#pragma once
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

void kprintf(const char* fmt, ...);

/**
 * @brief Variadic version of kprintf that takes va_list
 * @param fmt Format string
 * @param ap Variable argument list
 * @return 0 (return value not used currently)
 *
 * This function enables other variadic functions to pass their va_list
 * to kprintf-style formatting. Used by stream_printf() to support
 * formatted output to redirected streams.
 */
int vkprintf(const char* fmt, va_list ap);

/**
 * @brief Format to buffer (like vsnprintf)
 * @param buffer Output buffer
 * @param size Buffer size (includes null terminator)
 * @param format Format string
 * @param args Variable argument list
 * @return Number of characters written (excluding null terminator)
 *
 * This function formats output to a buffer instead of console.
 * Used by stream_printf() to format output before writing to files.
 */
int vsnprintf_impl(char* buffer, size_t size, const char* format, va_list args);

/*=============================================================================
 * SECURITY: Format String Vulnerability Protection
 *=============================================================================
 *
 * CRITICAL SECURITY POLICY:
 * -------------------------
 * NEVER pass user-controlled strings as the format argument to kprintf():
 *
 *   UNSAFE:  kprintf(user_string);              // VULNERABLE!
 *   UNSAFE:  kprintf(filename);                 // VULNERABLE!
 *   SAFE:    kprintf("%s", user_string);        // Correct
 *   SAFE:    kputs_safe(user_string);           // Correct
 *
 * WHY THIS MATTERS:
 * -----------------
 * If a malicious user provides input like "%x%x%x%s%n" as a filename or
 * command argument, and this is passed directly as a format string:
 *
 * 1. %x reads values from the stack (INFORMATION DISCLOSURE)
 * 2. %s can read arbitrary memory addresses (KERNEL MEMORY LEAK)
 * 3. %n can WRITE to arbitrary memory addresses (ARBITRARY CODE EXECUTION)
 *
 * ATTACK EXAMPLE:
 * ---------------
 * $ touch "myfile%x%x%x.txt"
 * $ cat myfile%x%x%x.txt
 *
 * If cat uses: kprintf(filename) instead of kprintf("%s", filename)
 * Output would be: "cat: myfile12345678abcdef9a.txt: not found"
 *                            ^^^^^^^^^^^^^^^^^ leaked stack values!
 *
 * CORRECT USAGE:
 * --------------
 * For untrusted strings (filenames, user input, network data):
 *   - Use: kprintf("%s", untrusted_string);
 *   - Or:  kputs_safe(untrusted_string);
 *
 * For trusted format strings (string literals only):
 *   - Use: kprintf("Error: file not found\n");
 *   - Use: kprintf("PID %d terminated\n", pid);
 *
 * DEFENSIVE WRAPPER:
 * ------------------
 * kputs_safe() provides a format-string-proof way to print untrusted text.
 * It prints character-by-character, treating ALL input as literal text.
 *=============================================================================*/

/**
 * @brief Safely print untrusted string (format-string attack proof)
 * @param str String to print (may contain %x, %s, etc. - treated as literal)
 *
 * This function is immune to format string attacks. It prints the string
 * character-by-character, treating all characters as literal text.
 * Use this for printing user input, filenames, or any untrusted data.
 *
 * Example:
 *   char filename[] = "evil%x%x%x.txt";  // User-provided filename
 *   kputs_safe(filename);  // Safely prints: evil%x%x%x.txt
 *
 * SECURITY: This function makes format string attacks impossible because
 * it never calls kprintf() with user data as the format string.
 */
void kputs_safe(const char* str);

/**
 * @brief Safely print untrusted string with length limit and truncation marker
 * @param str String to print (may contain %x, %s, etc. - treated as literal)
 * @param max_len Maximum number of characters to print
 *
 * SECURITY (v1.13): Audit Log Evasion Prevention
 *
 * This function prevents audit log evasion attacks by:
 * 1. Limiting printed string length to prevent log flooding
 * 2. Adding explicit "[...TRUNCATED_N_BYTES]" marker when truncated
 * 3. Ensuring auditors see the BEGINNING of suspicious strings
 *
 * Attack scenario this prevents:
 * - Attacker creates file "/../../etc/passwd[512 spaces]benign.txt"
 * - Without truncation marker, log shows: "/../../etc/passwd" (cut off)
 * - Auditor doesn't know if this is the full path or truncated
 * - WITH marker, log shows: "/../../etc/passwd[...TRUNCATED_512_BYTES]"
 * - Auditor knows the log is incomplete and investigates further
 *
 * Example:
 *   kprintf("ERROR: Cannot open file: ");
 *   kputs_safe_limited(untrusted_filename, 128);
 *   kprintf("\n");
 */
void kputs_safe_limited(const char* str, size_t max_len);

#endif
