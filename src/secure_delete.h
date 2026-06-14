/*=============================================================================
 * secure_delete.h - Secure File Deletion (DoD 5220.22-M Standard)
 *
 * Implements multi-pass overwriting to prevent data recovery.
 * Complies with:
 * - DoD 5220.22-M (3-pass overwrite)
 * - NIST 800-88 (media sanitization guidelines)
 *
 * Version: 1.0
 * Date: 2025-01-14
 *=============================================================================*/
#pragma once

#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * Constants
 *=============================================================================*/

/* Overwrite patterns */
#define SECURE_DELETE_PASSES    3       /* DoD 5220.22-M requires 3 passes */

/* Overwrite methods */
typedef enum {
    SECURE_DELETE_DOD_3PASS,            /* DoD 5220.22-M (3 passes: random, complement, random) */
    SECURE_DELETE_NIST_CLEAR,           /* NIST Clear (1 pass: zeros or random) */
    SECURE_DELETE_GUTMANN,              /* Gutmann 35-pass (overkill for modern drives) */
    SECURE_DELETE_ZERO,                 /* Simple zero-fill (1 pass) */
} secure_delete_method_t;

/* Options for secure deletion */
typedef struct {
    secure_delete_method_t method;      /* Deletion method */
    bool verify_overwrite;              /* Verify each pass was successful */
    bool sync_after_each_pass;          /* Sync to disk after each pass */
    bool remove_after;                  /* Unlink file after overwriting */
    bool audit_log;                     /* Log to audit system */
} secure_delete_opts_t;

/* Statistics for secure deletion */
typedef struct {
    uint32_t total_bytes;               /* Total bytes overwritten */
    uint32_t passes_completed;          /* Number of passes completed */
    uint32_t verification_failures;     /* Number of verification failures */
    bool success;                       /* Overall success status */
} secure_delete_stats_t;

/*=============================================================================
 * API Functions
 *=============================================================================*/

/**
 * @brief Initialize secure deletion subsystem
 */
void secure_delete_init(void);

/**
 * @brief Securely delete a file (DoD 3-pass by default)
 *
 * @param path File path to securely delete
 * @return 0 on success, negative on error
 *
 * Default behavior:
 * - 3-pass DoD 5220.22-M overwrite
 * - Verification enabled
 * - Sync after each pass
 * - Unlink after overwrite
 * - Audit logging enabled
 */
int secure_delete_file(const char* path);

/**
 * @brief Securely delete a file with custom options
 *
 * @param path File path to securely delete
 * @param opts Custom deletion options
 * @param stats Output statistics (can be NULL)
 * @return 0 on success, negative on error
 */
int secure_delete_file_ex(const char* path, const secure_delete_opts_t* opts,
                           secure_delete_stats_t* stats);

/**
 * @brief Overwrite file data with pattern (internal use)
 *
 * @param fd File descriptor
 * @param size File size in bytes
 * @param pattern_type Pattern to use (0=random, 1=zeros, 2=ones, 3=complement)
 * @param prev_pattern Previous pattern for complement mode
 * @return 0 on success, negative on error
 */
int secure_delete_overwrite_pass(int fd, uint32_t size, int pattern_type,
                                   const uint8_t* prev_pattern);

/**
 * @brief Verify that overwrite was successful
 *
 * @param fd File descriptor
 * @param size File size in bytes
 * @param expected_pattern Expected pattern
 * @return true if verification passed, false otherwise
 */
bool secure_delete_verify_pass(int fd, uint32_t size, const uint8_t* expected_pattern);

/**
 * @brief Get default secure deletion options
 *
 * @return Default options structure
 */
secure_delete_opts_t secure_delete_get_default_opts(void);

/**
 * @brief Get secure deletion statistics
 *
 * @param stats Output statistics structure
 */
void secure_delete_get_stats(secure_delete_stats_t* stats);

/**
 * @brief Test secure deletion functionality
 *
 * Creates a test file, securely deletes it, and verifies removal.
 * Prints test results to kernel log.
 */
void secure_delete_test(void);

/*=============================================================================
 * Convenience Macros
 *=============================================================================*/

/* Quick secure delete with defaults */
#define SECURE_DELETE(path) secure_delete_file(path)

/* Zero-fill delete (faster, less secure) */
#define QUICK_DELETE(path) \
    secure_delete_file_ex(path, &(secure_delete_opts_t){ \
        .method = SECURE_DELETE_ZERO, \
        .verify_overwrite = false, \
        .sync_after_each_pass = false, \
        .remove_after = true, \
        .audit_log = false \
    }, NULL)
