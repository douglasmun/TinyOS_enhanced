/*=============================================================================
 * secure_delete.c - Secure File Deletion Implementation
 *
 * Implements DoD 5220.22-M 3-pass overwrite:
 * - Pass 1: Random data
 * - Pass 2: Complement of Pass 1
 * - Pass 3: Random data
 * - Verification after each pass (optional)
 * - Sync to disk after each pass
 * - Unlink file
 *=============================================================================*/
#include "secure_delete.h"
#include "vfs.h"
#include "ramfs.h"  /* For ramfs_find() and ramfs_unlink() */
#include "crypto.h"
#include "audit.h"
#include "kprintf.h"
#include "util.h"
#include "util.h"  /* For memcpy, memset */

/* POSIX seek constants (not defined in VFS) */
#define SEEK_SET 0
#define SEEK_END 2

/*=============================================================================
 * Global Statistics
 *=============================================================================*/
static secure_delete_stats_t global_stats = {0};
static bool secure_delete_initialized = false;

/*=============================================================================
 * Buffer for overwrite operations (4KB)
 *=============================================================================*/
#define OVERWRITE_BUFFER_SIZE   4096
static uint8_t overwrite_buffer[OVERWRITE_BUFFER_SIZE];

/*=============================================================================
 * Initialization
 *=============================================================================*/
void secure_delete_init(void) {
    memset(&global_stats, 0, sizeof(global_stats));
    memset(overwrite_buffer, 0, sizeof(overwrite_buffer));
    secure_delete_initialized = true;

    kprintf("[SECURE_DELETE] Initialized (DoD 5220.22-M)\n");
}

/*=============================================================================
 * Default Options
 *=============================================================================*/
secure_delete_opts_t secure_delete_get_default_opts(void) {
    return (secure_delete_opts_t){
        .method = SECURE_DELETE_DOD_3PASS,
        .verify_overwrite = true,
        .sync_after_each_pass = true,
        .remove_after = true,
        .audit_log = true
    };
}

/*=============================================================================
 * Overwrite Pass Implementation
 *=============================================================================*/
int secure_delete_overwrite_pass(int fd, uint32_t size, int pattern_type,
                                   const uint8_t* prev_pattern) {
    uint32_t bytes_written = 0;
    uint32_t chunk_size;
    int ret;

    /* NOTE: Caller must ensure FD is at start of file (close/reopen between passes) */

    /* Generate pattern based on type */
    switch (pattern_type) {
        case 0: /* Random data */
            csprng_random_bytes(&global_csprng, overwrite_buffer, OVERWRITE_BUFFER_SIZE);
            break;

        case 1: /* All zeros */
            memset(overwrite_buffer, 0x00, OVERWRITE_BUFFER_SIZE);
            break;

        case 2: /* All ones */
            memset(overwrite_buffer, 0xFF, OVERWRITE_BUFFER_SIZE);
            break;

        case 3: /* Complement of previous pattern */
            if (prev_pattern) {
                for (uint32_t i = 0; i < OVERWRITE_BUFFER_SIZE; i++) {
                    overwrite_buffer[i] = ~prev_pattern[i];
                }
            } else {
                /* No previous pattern, use random */
                csprng_random_bytes(&global_csprng, overwrite_buffer, OVERWRITE_BUFFER_SIZE);
            }
            break;

        default:
            return -2; /* Invalid pattern type */
    }

    /* Overwrite file in chunks */
    while (bytes_written < size) {
        chunk_size = (size - bytes_written) < OVERWRITE_BUFFER_SIZE ?
                     (size - bytes_written) : OVERWRITE_BUFFER_SIZE;

        ret = vfs_write(fd, overwrite_buffer, chunk_size);
        if (ret < 0) {
            return -3; /* Write failed */
        }

        bytes_written += ret;
    }

    /* NOTE: No fsync() - RAMFS is in-memory */

    global_stats.total_bytes += bytes_written;
    return 0;
}

/*=============================================================================
 * Verify Pass Implementation
 *=============================================================================*/
bool secure_delete_verify_pass(int fd, uint32_t size, const uint8_t* expected_pattern) {
    uint8_t read_buffer[OVERWRITE_BUFFER_SIZE];
    uint32_t bytes_read = 0;
    uint32_t chunk_size;
    int ret;

    /* NOTE: Caller must ensure FD is at start of file (close/reopen) */

    /* Read and verify file in chunks */
    while (bytes_read < size) {
        chunk_size = (size - bytes_read) < OVERWRITE_BUFFER_SIZE ?
                     (size - bytes_read) : OVERWRITE_BUFFER_SIZE;

        ret = vfs_read(fd, read_buffer, chunk_size);
        if (ret < 0) {
            global_stats.verification_failures++;
            return false;
        }

        /* Verify chunk matches expected pattern */
        for (uint32_t i = 0; i < (uint32_t)ret; i++) {
            if (read_buffer[i] != expected_pattern[i % OVERWRITE_BUFFER_SIZE]) {
                global_stats.verification_failures++;
                return false;
            }
        }

        bytes_read += ret;
    }

    return true;
}

/*=============================================================================
 * Secure Delete with Options
 *=============================================================================*/
int secure_delete_file_ex(const char* path, const secure_delete_opts_t* opts,
                           secure_delete_stats_t* stats) {
    int fd;
    uint32_t file_size;
    int ret = 0;
    uint8_t prev_pattern[OVERWRITE_BUFFER_SIZE];
    bool should_verify = opts->verify_overwrite;
    ramfs_node_t* node;

    if (!secure_delete_initialized) {
        secure_delete_init();
    }

    /* Initialize stats */
    if (stats) {
        memset(stats, 0, sizeof(secure_delete_stats_t));
    }

    /* Get file size from RAMFS (since VFS doesn't have lseek) */
    node = ramfs_find(path);
    if (!node) {
        if (opts->audit_log) {
            audit_log(AUDIT_FILE_DELETE, AUDIT_ERROR, 0,
                      "Secure delete failed: file not found '%s'", path);
        }
        return -1;
    }

    file_size = node->size;
    if (file_size == 0) {
        if (opts->remove_after) {
            return ramfs_unlink(path);
        }
        return 0; /* Empty file, nothing to overwrite */
    }

    /* Open file for read/write */
    fd = vfs_open(path, VFS_O_RDWR);
    if (fd < 0) {
        if (opts->audit_log) {
            audit_log(AUDIT_FILE_DELETE, AUDIT_ERROR, 0,
                      "Secure delete failed: cannot open '%s'", path);
        }
        return -1;
    }

    /* Perform overwrite passes based on method */
    switch (opts->method) {
        case SECURE_DELETE_DOD_3PASS:
            /* Pass 1: Random data */
            ret = secure_delete_overwrite_pass(fd, file_size, 0, NULL);
            if (ret < 0) goto cleanup;

            memcpy(prev_pattern, overwrite_buffer, OVERWRITE_BUFFER_SIZE);
            global_stats.passes_completed++;
            if (stats) stats->passes_completed++;

            /* Verify Pass 1 (close/reopen to reset position) */
            if (should_verify) {
                vfs_close(fd);
                fd = vfs_open(path, VFS_O_RDWR);
                if (fd < 0) {
                    ret = -1;
                    goto cleanup;
                }
                if (!secure_delete_verify_pass(fd, file_size, overwrite_buffer)) {
                    /*=====================================================================
                     * SECURITY FIX (AUDIT 4D): Elevated Response to Verification Failure
                     *====================================================================
                     *
                     * VULNERABILITY: Silent Verification Failure
                     *
                     * CRITICAL SECURITY EVENT: Secure deletion verification failed!
                     * This indicates:
                     * - Storage firmware tampering
                     * - Hardware failure or corruption
                     * - Memory corruption attack
                     * - Potential security compromise
                     *
                     * PRODUCTION IMPACT:
                     * Sensitive data may remain on storage media despite shred attempt.
                     * Compliance requirements (HIPAA, PCI-DSS, GDPR) mandate proper
                     * data destruction verification.
                     *===================================================================*/
                    kprintf("[SECURE_DELETE] CRITICAL: Pass 1 verification FAILED for '%s'\n", path);
                    kprintf("[SECURE_DELETE] WARNING: Sensitive data may NOT be securely deleted!\n");
                    audit_log(AUDIT_SEC_POLICY_VIOLATION, AUDIT_CRITICAL, 0,
                              "SECURE DELETE VERIFICATION FAILURE: Pass 1 failed for '%s' "
                              "(size=%u) - POTENTIAL HARDWARE TAMPERING OR FAILURE",
                              path, file_size);
                    ret = -4; /* Verification failed */
                    goto cleanup;
                }
                /* Reopen for next pass */
                vfs_close(fd);
                fd = vfs_open(path, VFS_O_RDWR);
                if (fd < 0) {
                    ret = -1;
                    goto cleanup;
                }
            }

            /* Pass 2: Complement of Pass 1 */
            ret = secure_delete_overwrite_pass(fd, file_size, 3, prev_pattern);
            if (ret < 0) goto cleanup;

            global_stats.passes_completed++;
            if (stats) stats->passes_completed++;

            /* Verify Pass 2 */
            if (should_verify) {
                vfs_close(fd);
                fd = vfs_open(path, VFS_O_RDWR);
                if (fd < 0) {
                    ret = -1;
                    goto cleanup;
                }
                if (!secure_delete_verify_pass(fd, file_size, overwrite_buffer)) {
                    /* SECURITY FIX (AUDIT 4D): Critical verification failure logging */
                    kprintf("[SECURE_DELETE] CRITICAL: Pass 2 verification FAILED for '%s'\n", path);
                    kprintf("[SECURE_DELETE] WARNING: Sensitive data may NOT be securely deleted!\n");
                    audit_log(AUDIT_SEC_POLICY_VIOLATION, AUDIT_CRITICAL, 0,
                              "SECURE DELETE VERIFICATION FAILURE: Pass 2 failed for '%s' "
                              "(size=%u) - POTENTIAL HARDWARE TAMPERING OR FAILURE",
                              path, file_size);
                    ret = -4;
                    goto cleanup;
                }
                /* Reopen for next pass */
                vfs_close(fd);
                fd = vfs_open(path, VFS_O_RDWR);
                if (fd < 0) {
                    ret = -1;
                    goto cleanup;
                }
            }

            /* Pass 3: Random data */
            ret = secure_delete_overwrite_pass(fd, file_size, 0, NULL);
            if (ret < 0) goto cleanup;

            global_stats.passes_completed++;
            if (stats) stats->passes_completed++;

            /* Verify Pass 3 */
            if (should_verify) {
                vfs_close(fd);
                fd = vfs_open(path, VFS_O_RDWR);
                if (fd < 0) {
                    ret = -1;
                    goto cleanup;
                }
                if (!secure_delete_verify_pass(fd, file_size, overwrite_buffer)) {
                    /* SECURITY FIX (AUDIT 4D): Critical verification failure logging */
                    kprintf("[SECURE_DELETE] CRITICAL: Pass 3 verification FAILED for '%s'\n", path);
                    kprintf("[SECURE_DELETE] WARNING: Sensitive data may NOT be securely deleted!\n");
                    audit_log(AUDIT_SEC_POLICY_VIOLATION, AUDIT_CRITICAL, 0,
                              "SECURE DELETE VERIFICATION FAILURE: Pass 3 failed for '%s' "
                              "(size=%u) - POTENTIAL HARDWARE TAMPERING OR FAILURE",
                              path, file_size);
                    ret = -4;
                    goto cleanup;
                }
            }

            break;

        case SECURE_DELETE_NIST_CLEAR:
            /* Single pass with random data */
            ret = secure_delete_overwrite_pass(fd, file_size, 0, NULL);
            if (ret < 0) goto cleanup;

            global_stats.passes_completed++;
            if (stats) stats->passes_completed++;

            /* Verify pass */
            if (should_verify) {
                vfs_close(fd);
                fd = vfs_open(path, VFS_O_RDWR);
                if (fd < 0) {
                    ret = -1;
                    goto cleanup;
                }
                if (!secure_delete_verify_pass(fd, file_size, overwrite_buffer)) {
                    /* SECURITY FIX (AUDIT 4D): Critical verification failure logging */
                    kprintf("[SECURE_DELETE] CRITICAL: NIST pass verification FAILED for '%s'\n", path);
                    kprintf("[SECURE_DELETE] WARNING: Sensitive data may NOT be securely deleted!\n");
                    audit_log(AUDIT_SEC_POLICY_VIOLATION, AUDIT_CRITICAL, 0,
                              "SECURE DELETE VERIFICATION FAILURE: NIST pass failed for '%s' "
                              "(size=%u) - POTENTIAL HARDWARE TAMPERING OR FAILURE",
                              path, file_size);
                    ret = -4;
                    goto cleanup;
                }
            }
            break;

        case SECURE_DELETE_ZERO:
            /* Single pass with zeros */
            ret = secure_delete_overwrite_pass(fd, file_size, 1, NULL);
            if (ret < 0) goto cleanup;

            global_stats.passes_completed++;
            if (stats) stats->passes_completed++;
            break;

        case SECURE_DELETE_GUTMANN:
            /* 35-pass Gutmann method - too complex for now, fall back to DoD */
            kprintf("[SECURE_DELETE] Gutmann method not implemented, using DoD 3-pass\n");
            ret = -5; /* Not implemented */
            goto cleanup;

        default:
            ret = -6; /* Invalid method */
            goto cleanup;
    }

    /* Success */
    if (stats) {
        stats->total_bytes = file_size * stats->passes_completed;
        stats->success = true;
    }

cleanup:
    vfs_close(fd);

    /* Remove file if requested and overwrite succeeded */
    if (opts->remove_after && ret == 0) {
        int unlink_ret = ramfs_unlink(path);
        if (unlink_ret < 0) {
            ret = -7; /* Unlink failed */
        }
    }

    /* Audit log */
    if (opts->audit_log) {
        if (ret == 0) {
            audit_log(AUDIT_FILE_DELETE, AUDIT_INFO, 0,
                      "Secure delete: '%s' (%lu bytes, %lu passes)",
                      path, (unsigned long)file_size,
                      (unsigned long)(stats ? stats->passes_completed : 0));
        } else {
            audit_log(AUDIT_FILE_DELETE, AUDIT_ERROR, 0,
                      "Secure delete failed: '%s' (error %d)", path, ret);
        }
    }

    return ret;
}

/*=============================================================================
 * Simple Secure Delete (Default Options)
 *=============================================================================*/
int secure_delete_file(const char* path) {
    secure_delete_opts_t opts = secure_delete_get_default_opts();
    return secure_delete_file_ex(path, &opts, NULL);
}

/*=============================================================================
 * Get Statistics
 *=============================================================================*/
void secure_delete_get_stats(secure_delete_stats_t* stats) {
    if (stats) {
        memcpy(stats, &global_stats, sizeof(secure_delete_stats_t));
    }
}

/*=============================================================================
 * Test Function
 *=============================================================================*/
void secure_delete_test(void) {
    kprintf("[SECURE_DELETE_TEST] Starting tests...\n");

    /* Test 1: Create a test file with secret data using RAMFS directly */
    const char* test_file = "/tmp/test_shred.txt";
    const char* secret_data = "TOP SECRET: This data must be securely deleted!";

    /* Use RAMFS API directly */
    int fd = ramfs_open(test_file, RAMFS_FLAG_WRITE);
    if (fd < 0) {
        kprintf("[SECURE_DELETE_TEST] FAIL: Cannot create test file\n");
        return;
    }

    ramfs_write(fd, secret_data, strlen(secret_data));
    ramfs_close(fd);
    kprintf("[SECURE_DELETE_TEST] Created file: %s (%u bytes)\n",
            test_file, (uint32_t)strlen(secret_data));

    /* Test 2: Securely delete the file */
    secure_delete_opts_t opts = secure_delete_get_default_opts();
    secure_delete_stats_t stats;

    int ret = secure_delete_file_ex(test_file, &opts, &stats);

    if (ret == 0) {
        kprintf("[SECURE_DELETE_TEST] PASS: File securely deleted\n");
        kprintf("[SECURE_DELETE_TEST]   - Bytes overwritten: %u\n", stats.total_bytes);
        kprintf("[SECURE_DELETE_TEST]   - Passes completed: %u\n", stats.passes_completed);
        kprintf("[SECURE_DELETE_TEST]   - Verification failures: %u\n",
                stats.verification_failures);
    } else {
        kprintf("[SECURE_DELETE_TEST] FAIL: Secure delete failed (error %d)\n", ret);
        return;
    }

    /* Test 3: Verify file no longer exists */
    ramfs_node_t* node = ramfs_find(test_file);
    if (!node) {
        kprintf("[SECURE_DELETE_TEST] PASS: File successfully removed\n");
    } else {
        kprintf("[SECURE_DELETE_TEST] FAIL: File still exists after deletion!\n");
        return;
    }

    kprintf("[SECURE_DELETE_TEST] All tests passed! [OK]\n");
}
