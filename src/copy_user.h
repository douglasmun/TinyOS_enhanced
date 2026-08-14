/*=============================================================================
 * copy_user.h - Safe User Space Memory Access Primitives
 *
 * SECURITY: Prevents TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities
 * in system calls by providing atomic memory copy operations with exception
 * handling. If a page fault occurs during copy, returns -EFAULT instead of
 * crashing the kernel.
 *============================================================================*/
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*=============================================================================
 * FUNCTION: copy_from_user
 *============================================================================*/
/**
 * Safely copies data from user space to kernel space with exception handling.
 *
 * SECURITY:
 * - Validates user address is in user space (< USER_SPACE_END)
 * - Catches page faults if user unmaps memory during copy
 * - Returns -EFAULT on fault instead of panicking kernel
 * - Prevents TOCTOU race conditions
 *
 * @param kernel_dst  Destination buffer in kernel space (must be valid)
 * @param user_src    Source buffer in user space (may be invalid/unmapped)
 * @param len         Number of bytes to copy
 *
 * @return 0 on success, -EFAULT if user address is invalid or page fault occurs
 *
 * USAGE:
 *   char kernel_buf[512];
 *   if (copy_from_user(kernel_buf, user_ptr, 512) < 0) {
 *       return -EFAULT;  // User pointer was invalid
 *   }
 *   // Safe to use kernel_buf now
 */
int copy_from_user(void* kernel_dst, const void* user_src, size_t len);

/*=============================================================================
 * FUNCTION: copy_to_user
 *============================================================================*/
/**
 * Safely copies data from kernel space to user space with exception handling.
 *
 * SECURITY:
 * - Validates user address is in user space (< USER_SPACE_END)
 * - Catches page faults if user unmaps memory during copy
 * - Returns -EFAULT on fault instead of panicking kernel
 * - Prevents TOCTOU race conditions
 *
 * @param user_dst    Destination buffer in user space (may be invalid/unmapped)
 * @param kernel_src  Source buffer in kernel space (must be valid)
 * @param len         Number of bytes to copy
 *
 * @return 0 on success, -EFAULT if user address is invalid or page fault occurs
 *
 * USAGE:
 *   if (copy_to_user(user_buf, kernel_data, size) < 0) {
 *       return -EFAULT;  // User buffer was invalid
 *   }
 */
int copy_to_user(void* user_dst, const void* kernel_src, size_t len);

/*=============================================================================
 * FUNCTION: copy_string_from_user
 *============================================================================*/
/**
 * Safely copies a NUL-terminated string from user space into a kernel buffer.
 *
 * copy_from_user() cannot express this: the length is not known until the
 * terminator is found, and guessing a length would either read past the end of
 * a short string (faulting on the next, possibly unmapped, page even though the
 * string itself was entirely valid) or truncate a long one.
 *
 * Bytes are therefore fetched one at a time through copy_from_user(), which
 * keeps every per-byte user-space and page-fault check in exactly one place.
 *
 * SECURITY:
 * - Never reads past the terminator, so a string ending just before an
 *   unmapped page still copies successfully
 * - Always NUL-terminates on success, so callers can treat the result as a
 *   C string without re-checking
 * - Refuses rather than truncates when the string does not fit, so a caller
 *   cannot be handed a silently shortened path or argument
 *
 * @param kernel_dst  Destination buffer in kernel space
 * @param user_src    Source string in user space (may be invalid/unmapped)
 * @param max_len     Size of kernel_dst, terminator included
 *
 * @return Length of the copied string (excluding the terminator) on success,
 *         -EFAULT if the user address is invalid or faults,
 *         -EINVAL on a bad argument,
 *         -ENAMETOOLONG if the string does not fit in max_len
 */
int copy_string_from_user(char* kernel_dst, const char* user_src, size_t max_len);

/*=============================================================================
 * INTERNAL FUNCTIONS (called from page fault handler)
 *============================================================================*/

/**
 * Check if a copy_*_user() operation is currently active.
 * Called by page fault handler to detect faults during safe copy.
 *
 * @return true if copy_*_user() is active, false otherwise
 */
bool is_copy_user_active(void);

/**
 * Handle page fault that occurred during copy_*_user() operation.
 * Restores saved context and returns -EFAULT to caller.
 *
 * IMPORTANT: This function does NOT return normally - it performs
 * a non-local jump back to the copy_*_user() function.
 */
void handle_copy_user_fault(void) __attribute__((noreturn));

/**
 * Get the faulting address from the copy_*_user() operation.
 * Used for diagnostic logging in page fault handler.
 *
 * @return The user address that caused the fault
 */
uint32_t get_copy_user_fault_address(void);
