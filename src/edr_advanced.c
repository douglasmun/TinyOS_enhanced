/*=============================================================================
 * edr_advanced.c - EDR Advanced Detection Engine Implementation (Phase 3)
 *=============================================================================*/
#include "edr_advanced.h"
#include "process.h"
#include "kprintf.h"
#include "pit.h"
#include "util.h"
#include "paging.h"
#include "sha256.h"
#include "scheduler.h"
#include "vfs.h"
#include "edr_ml.h"  /* Phase 4a: Automated Response */

/* Task iteration uses task_get_all() from process.h */

/*=============================================================================
 * GLOBAL STATE
 *=============================================================================*/

/* File Integrity Monitoring database */
static fim_database_t g_fim_db;

/* Shellcode signature patterns */
static const shellcode_signature_t shellcode_signatures[] = {
    /* NOP sled (0x90 repeated) */
    {"NOP_sled", (const uint8_t*)"\x90\x90\x90\x90\x90\x90\x90\x90", 8, 8},

    /* x86 syscall instruction (int 0x80) */
    {"INT_80h", (const uint8_t*)"\xCD\x80", 2, 7},

    /* Common shellcode prologue (push/pop registers) */
    {"PUSH_POP", (const uint8_t*)"\x60\x61", 2, 5},

    /* JMP/CALL shellcode pattern */
    {"JMP_CALL", (const uint8_t*)"\xEB\x1F\x5E\x89\x76", 5, 6},
};
static const int shellcode_signatures_count = sizeof(shellcode_signatures) / sizeof(shellcode_signatures[0]);

/*=============================================================================
 * MODULE 1: MEMORY INSPECTION
 *=============================================================================*/

/**
 * @brief Detect shellcode patterns in memory buffer
 */
uint8_t edr_memory_detect_shellcode(const uint8_t* buffer, size_t size) {
    if (!buffer || size < 8) return 0;

    uint16_t total_weight = 0;

    /* Scan buffer for known shellcode signatures */
    for (int sig_idx = 0; sig_idx < shellcode_signatures_count; sig_idx++) {
        const shellcode_signature_t* sig = &shellcode_signatures[sig_idx];

        /* Search for pattern in buffer */
        for (size_t i = 0; i <= size - sig->pattern_len; i++) {
            bool match = true;
            for (size_t j = 0; j < sig->pattern_len; j++) {
                if (buffer[i + j] != sig->pattern[j]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                total_weight += sig->weight;
                break;  /* Don't count same signature multiple times */
            }
        }
    }

    /* Convert weight to 0-100 score */
    if (total_weight > 100) total_weight = 100;
    return (uint8_t)total_weight;
}

/**
 * @brief Check for RWX (read-write-execute) memory regions
 *
 * DISABLED — returns 0. The previous implementation was broken and unsafe on
 * this kernel:
 *
 *  1. WRONG FORMAT. It walked task->page_directory as a legacy 32-bit paging
 *     structure (uint32_t*, 1024-entry tables, `pde & 0xFFFFF000`). This kernel
 *     runs PAE: 64-bit entries, 512-entry tables, a 4-entry PDPT. Reinterpreting
 *     the 32-byte PDPT as uint32_t[1024] reads the two 32-bit halves of each
 *     64-bit entry and then runs ~1016 entries off the end of the structure into
 *     adjacent .bss, treating arbitrary bytes as page-table pointers.
 *  2. WRONG BITS. It tested Present+Write+User only and never the execute/NX
 *     bit, so it labelled every normal R+W+NX data page "RWX".
 *  3. REDUNDANT. PAE W^X is enforced via the NX bit (pae_apply_kernel_wx) and
 *     pae_verify_kernel_layout() PANICS on any W^X page, so a genuine RWX page
 *     cannot legitimately exist here — a correct scan would always return 0.
 *
 * Net effect was one false "CODE_INJECTION" alert per task on every boot, plus
 * an unsafe dereference of misinterpreted entries as page-table pointers (only
 * avoided faulting by the <32MB guard + low-RAM identity mapping). If genuine
 * per-process RWX telemetry for USER ELF tasks is ever wanted, reimplement this
 * as a proper PAE walk (pae_pdpte_t over 4/512/512 entries, testing
 * PAE_PRESENT && PAE_READWRITE && !(pte & PAE_NX)); until then, W^X verification
 * already provides the guarantee this tried to check.
 */
uint16_t edr_memory_check_rwx_regions(task_t* task) {
    (void)task;
    return 0;
}

/**
 * @brief Scan process memory for suspicious patterns
 */
bool edr_memory_inspect(task_t* task) {
    if (!task || !task->edr_advanced) return false;

    edr_memory_state_t* mem_state = &task->edr_advanced->memory;

    /* Rate limiting: Only scan once per 100 ticks */
    uint32_t current_tick = pit_get_ticks();
    if (current_tick - mem_state->last_scan_tick < 100) {
        return false;  /* Too soon */
    }
    mem_state->last_scan_tick = current_tick;

    /* FUTURE: Implement incremental scanning
     * For now, we'll do a basic check for RWX regions
     */
    uint16_t rwx_count = edr_memory_check_rwx_regions(task);
    if (rwx_count > 0) {
        mem_state->rwx_region_count = rwx_count;
        mem_state->has_suspicious_memory = true;
        return true;  /* Suspicious */
    }

    return false;
}

/*=============================================================================
 * MODULE 2: NETWORK FLOW ANALYSIS
 *=============================================================================*/

/**
 * @brief Track new network connection
 *
 * USAGE: Network-related syscalls should call this function when:
 * - TCP/UDP socket connects to remote host (SYS_CONNECT)
 * - TCP connection accepted (SYS_ACCEPT)
 * - UDP datagram sent (SYS_SENDTO)
 *
 * Example integration in syscall.c:
 *   case SYS_CONNECT:
 *       edr_network_track_connection(current_task, remote_ip, remote_port, local_port);
 *       break;
 */
void edr_network_track_connection(task_t* task, uint32_t remote_ip,
                                   uint16_t remote_port, uint16_t local_port) {
    if (!task || !task->edr_advanced) return;

    edr_network_state_t* net_state = &task->edr_advanced->network;

    /* Find free slot or reuse oldest */
    int slot = -1;
    for (int i = 0; i < EDR_MAX_CONNECTIONS; i++) {
        if (net_state->connections[i].remote_ip == 0) {
            slot = i;
            break;
        }
    }

    /* If no free slot, reuse oldest */
    if (slot == -1) {
        uint32_t oldest_tick = 0xFFFFFFFF;
        for (int i = 0; i < EDR_MAX_CONNECTIONS; i++) {
            if (net_state->connections[i].established_tick < oldest_tick) {
                oldest_tick = net_state->connections[i].established_tick;
                slot = i;
            }
        }
    }

    /* Add connection */
    if (slot >= 0) {
        network_connection_t* conn = &net_state->connections[slot];
        conn->remote_ip = remote_ip;
        conn->remote_port = remote_port;
        conn->local_port = local_port;
        conn->established_tick = pit_get_ticks();
        conn->last_activity_tick = conn->established_tick;
        conn->bytes_sent = 0;
        conn->bytes_received = 0;
        conn->beacon_count = 0;

        net_state->connection_count++;
        net_state->has_network_activity = true;
    }
}

/**
 * @brief Detect Command & Control (C2) beaconing patterns
 */
bool edr_network_detect_c2_beacon(task_t* task) {
    if (!task || !task->edr_advanced) return false;

    edr_network_state_t* net_state = &task->edr_advanced->network;

    /* Look for connections with high beacon count */
    for (int i = 0; i < EDR_MAX_CONNECTIONS; i++) {
        network_connection_t* conn = &net_state->connections[i];
        if (conn->remote_ip == 0) continue;  /* Empty slot */

        if (conn->beacon_count >= EDR_C2_BEACON_THRESHOLD) {
            return true;  /* C2 beaconing detected */
        }
    }

    return false;
}

/**
 * @brief Analyze network traffic patterns
 */
bool edr_network_analyze(task_t* task) {
    if (!task || !task->edr_advanced) return false;

    /* Check for C2 beaconing */
    if (edr_network_detect_c2_beacon(task)) {
        return true;  /* Suspicious */
    }

    /* FUTURE: Add more network analysis
     * - Port scanning detection (many connections to sequential ports)
     * - Data exfiltration (large outbound transfer)
     */

    return false;
}

/*=============================================================================
 * MODULE 3: FILE INTEGRITY MONITORING (FIM)
 *=============================================================================*/

/**
 * @brief Compute SHA-256 hash of file
 */
bool edr_fim_hash_file(const char* path, uint8_t* hash_out) {
    if (!path || !hash_out) return false;

    /* Open file for reading */
    int fd = vfs_open(path, 0);  /* 0 = O_RDONLY */
    if (fd < 0) {
        /* File doesn't exist or can't be opened - return dummy hash */
        for (int i = 0; i < EDR_FIM_HASH_SIZE; i++) {
            hash_out[i] = 0x00;
        }
        return false;
    }

    /* Initialize SHA-256 context */
    sha256_ctx_t ctx;
    sha256_init(&ctx);

    /* Read file in 4KB chunks and hash */
    uint8_t buffer[4096];
    ssize_t bytes_read;

    while ((bytes_read = vfs_read(fd, buffer, sizeof(buffer))) > 0) {
        sha256_update(&ctx, buffer, (size_t)bytes_read);
    }

    /* Finalize hash */
    sha256_final(&ctx, hash_out);

    /* Close file */
    vfs_close(fd);

    return (bytes_read >= 0);  /* Return true if no errors */
}

/**
 * @brief Add file to FIM monitoring
 */
bool edr_fim_add_file(const char* path) {
    if (!path) return false;
    if (g_fim_db.file_count >= EDR_FIM_MAX_FILES) return false;

    /* Find free slot */
    fim_entry_t* entry = &g_fim_db.files[g_fim_db.file_count];

    /* Copy path */
    size_t len = 0;
    while (path[len] && len < 63) {
        entry->path[len] = path[len];
        len++;
    }
    entry->path[len] = '\0';

    /* Compute baseline hash */
    if (!edr_fim_hash_file(path, entry->hash)) {
        return false;
    }

    entry->last_check_tick = pit_get_ticks();
    entry->is_monitored = true;
    entry->tampered = false;

    g_fim_db.file_count++;
    return true;
}

/**
 * @brief Check file integrity against baseline
 */
bool edr_fim_check_integrity(const char* path) {
    if (!path) return false;

    /* Find entry in database */
    fim_entry_t* entry = NULL;
    for (int i = 0; i < g_fim_db.file_count; i++) {
        if (strcmp(g_fim_db.files[i].path, path) == 0) {
            entry = &g_fim_db.files[i];
            break;
        }
    }

    if (!entry || !entry->is_monitored) return false;

    /* Compute current hash */
    uint8_t current_hash[EDR_FIM_HASH_SIZE];
    if (!edr_fim_hash_file(path, current_hash)) {
        return false;
    }

    /* Compare hashes */
    bool tampered = false;
    for (int i = 0; i < EDR_FIM_HASH_SIZE; i++) {
        if (current_hash[i] != entry->hash[i]) {
            tampered = true;
            break;
        }
    }

    if (tampered) {
        entry->tampered = true;
        g_fim_db.tamper_count++;
    }

    entry->last_check_tick = pit_get_ticks();
    return tampered;
}

/**
 * @brief Perform periodic integrity scan of all monitored files
 */
uint16_t edr_fim_scan_all(void) {
    uint16_t tampered_count = 0;

    for (int i = 0; i < g_fim_db.file_count; i++) {
        fim_entry_t* entry = &g_fim_db.files[i];
        if (!entry->is_monitored) continue;

        if (edr_fim_check_integrity(entry->path)) {
            tampered_count++;
        }
    }

    g_fim_db.last_full_scan_tick = pit_get_ticks();
    return tampered_count;
}

/**
 * @brief Initialize File Integrity Monitoring
 */
void edr_fim_init(void) {
    /* Clear database */
    for (int i = 0; i < EDR_FIM_MAX_FILES; i++) {
        g_fim_db.files[i].path[0] = '\0';
        g_fim_db.files[i].is_monitored = false;
        g_fim_db.files[i].tampered = false;
    }
    g_fim_db.file_count = 0;
    g_fim_db.last_full_scan_tick = 0;
    g_fim_db.tamper_count = 0;

    /* Add critical system files to monitoring
     * FUTURE: Add actual file paths when filesystem is mounted
     */
    /* edr_fim_add_file("/bin/init"); */
    /* edr_fim_add_file("/etc/passwd"); */
    /* edr_fim_add_file("/boot/kernel.elf"); */

    kprintf("[EDR FIM] Initialized (monitoring %d files)\n", g_fim_db.file_count);
}

/*=============================================================================
 * MODULE 4: CRYPTOGRAPHIC OPERATIONS MONITORING
 *=============================================================================*/

/**
 * @brief Track cryptographic operation
 *
 * USAGE: Cryptographic functions should call this to track encryption/decryption:
 * - AES encryption/decryption (aes_encrypt, aes_decrypt)
 * - SHA hashing operations (sha256_update, sha512_update)
 * - RSA operations (rsa_encrypt, rsa_decrypt)
 *
 * Example integration in crypto.c:
 *   void aes_encrypt(task_t* task, uint8_t* data, size_t len) {
 *       edr_crypto_track_operation(task, CRYPTO_OP_ENCRYPT, len);
 *       // ... actual encryption ...
 *   }
 */
void edr_crypto_track_operation(task_t* task, crypto_op_type_t op_type, uint32_t bytes) {
    if (!task || !task->edr_advanced) return;

    edr_crypto_state_t* crypto_state = &task->edr_advanced->crypto;

    /* Get current second index (circular buffer) */
    uint8_t head = crypto_state->history_head;
    crypto_activity_t* activity = &crypto_state->history[head];

    /* Update counters */
    if (op_type == CRYPTO_OP_ENCRYPT) {
        activity->encrypt_count++;
        activity->bytes_encrypted += bytes;
        crypto_state->total_encrypt_ops++;
    } else if (op_type == CRYPTO_OP_DECRYPT) {
        activity->decrypt_count++;
        activity->bytes_decrypted += bytes;
        crypto_state->total_decrypt_ops++;
    }

    crypto_state->has_crypto_activity = true;
}

/**
 * @brief Detect ransomware encryption patterns
 */
bool edr_crypto_detect_ransomware(task_t* task) {
    if (!task || !task->edr_advanced) return false;

    edr_crypto_state_t* crypto_state = &task->edr_advanced->crypto;

    /* Count total encryptions in last 10 seconds */
    uint32_t total_encryptions = 0;
    for (int i = 0; i < EDR_CRYPTO_HISTORY_SIZE; i++) {
        total_encryptions += crypto_state->history[i].encrypt_count;
    }

    /* Ransomware detected if > threshold encryptions in 10 seconds */
    if (total_encryptions > EDR_CRYPTO_THRESHOLD) {
        return true;
    }

    return false;
}

/**
 * @brief Analyze crypto activity for suspicious patterns
 */
bool edr_crypto_analyze(task_t* task) {
    if (!task || !task->edr_advanced) return false;

    /* Check for ransomware pattern */
    if (edr_crypto_detect_ransomware(task)) {
        return true;  /* Suspicious */
    }

    /* FUTURE: Add more crypto analysis
     * - Cryptocurrency mining detection (high keygen activity)
     * - Unusual decryption patterns
     */

    return false;
}

/*=============================================================================
 * CORE FUNCTIONS
 *=============================================================================*/

/**
 * @brief Initialize advanced detection system (global)
 */
void edr_advanced_init(void) {
    /* Initialize File Integrity Monitoring */
    edr_fim_init();

    kprintf("[EDR ADVANCED] Initialized (Phase 3: Memory, Network, FIM, Crypto)\n");
}

/**
 * @brief Initialize advanced detection state for a process
 */
void edr_advanced_init_process(task_t* task) {
    if (!task || !task->edr_advanced) return;

    edr_advanced_state_t* state = task->edr_advanced;

    /* Clear memory state */
    state->memory.last_scan_tick = 0;
    state->memory.next_scan_addr = 0;
    state->memory.rwx_region_count = 0;
    state->memory.shellcode_detections = 0;
    state->memory.has_suspicious_memory = false;

    /* Clear network state */
    for (int i = 0; i < EDR_MAX_CONNECTIONS; i++) {
        state->network.connections[i].remote_ip = 0;
    }
    state->network.connection_count = 0;
    state->network.total_bytes_sent = 0;
    state->network.total_bytes_received = 0;
    state->network.c2_score = 0;
    state->network.has_network_activity = false;

    /* Clear crypto state */
    for (int i = 0; i < EDR_CRYPTO_HISTORY_SIZE; i++) {
        state->crypto.history[i].encrypt_count = 0;
        state->crypto.history[i].decrypt_count = 0;
        state->crypto.history[i].bytes_encrypted = 0;
        state->crypto.history[i].bytes_decrypted = 0;
    }
    state->crypto.history_head = 0;
    state->crypto.total_encrypt_ops = 0;
    state->crypto.total_decrypt_ops = 0;
    state->crypto.ransomware_score = 0;
    state->crypto.has_crypto_activity = false;

    /* Enable advanced detection by default */
    state->advanced_detection_enabled = true;
    state->advanced_alert_count = 0;
}

/*=============================================================================
 * ALERT GENERATION AND RESPONSE
 *=============================================================================*/

/* Rate limiting state */
static uint32_t last_alert_tick = 0;
static uint32_t total_advanced_alerts = 0;

/**
 * @brief Raise an advanced threat alert
 */
static void edr_advanced_raise_alert(task_t* task, edr_advanced_signature_t signature,
                                      const char* message, bool terminate) {
    if (!task || !task->edr_advanced) return;

    /* Rate limiting: Max 1 alert per 50 ticks globally */
    uint32_t current_tick = pit_get_ticks();
    if (current_tick - last_alert_tick < 50) {
        return;
    }
    last_alert_tick = current_tick;

    /* Update stats */
    task->edr_advanced->advanced_alert_count++;
    total_advanced_alerts++;

    /* Log alert */
    kprintf("[EDR ADVANCED] PID %d: %s (sig=%s, terminate=%d)\n",
            task->pid, message,
            edr_advanced_signature_to_string(signature),
            terminate);

    /* Terminate process on critical threats */
    if (terminate) {
        kprintf("[EDR ADVANCED] TERMINATING PID %d due to critical threat!\n", task->pid);
        /* Mark for termination - scheduler will clean up */
        task->state = TASK_STATE_TERMINATED;
        task->exit_status = 128 + 9;  /* Exit code 137 (SIGKILL) */
    }
}

/**
 * @brief Periodic check for advanced threats (called from timer interrupt)
 */
void edr_advanced_periodic_check(void) {
    static uint32_t process_scan_index = 0;  /* Round-robin for memory scans */
    static uint32_t file_scan_index = 0;     /* Round-robin for FIM scans */

    /* Get task list using task_get_all() */
    task_t* task_array[MAX_TASKS];  /* Array of task pointers */
    int task_count = task_get_all(task_array, MAX_TASKS);

    if (task_count == 0) return;

    /* 1. Memory inspection - scan one process per call (round-robin) */
    for (int i = 0; i < task_count; i++) {
        int idx = (process_scan_index + i) % task_count;
        task_t* task = task_array[idx];

        /* Only scan tasks that have actually executed. A task that was just
         * created but has never been switched to (has_run_before == false) has
         * done nothing suspicious by definition; scanning/terminating it is pure
         * false-positive surface and races exec's task setup (the brief
         * window where a fresh task could be flipped to TERMINATED before
         * elf_load_process finishes mapping it). */
        if ((task->state == TASK_STATE_RUNNING || task->state == TASK_STATE_READY) &&
            task->has_run_before) {
            if (task->edr_advanced && task->edr_advanced->advanced_detection_enabled) {
                /* Raise the alert only on the first detection per process.
                 * edr_memory_inspect() sets has_suspicious_memory; without this
                 * guard a process with a (benign) RWX region re-alerts on every
                 * scan, flooding the console. */
                bool was_flagged = task->edr_advanced->memory.has_suspicious_memory;
                if (edr_memory_inspect(task) && !was_flagged) {
                    edr_advanced_raise_alert(task, EDR_SIG_ADV_CODE_INJECTION,
                                            "Suspicious memory detected", false);
                }
                process_scan_index = (idx + 1) % task_count;
                break;  /* Only scan one process per tick */
            }
        }
    }

    /* 2. Network flow analysis - check all processes */
    for (int i = 0; i < task_count; i++) {
        task_t* task = task_array[i];
        /* Only scan tasks that have actually executed. A task that was just
         * created but has never been switched to (has_run_before == false) has
         * done nothing suspicious by definition; scanning/terminating it is pure
         * false-positive surface and races exec's task setup (the brief
         * window where a fresh task could be flipped to TERMINATED before
         * elf_load_process finishes mapping it). */
        if ((task->state == TASK_STATE_RUNNING || task->state == TASK_STATE_READY) &&
            task->has_run_before) {
            if (task->edr_advanced && task->edr_advanced->advanced_detection_enabled) {
                if (edr_network_analyze(task)) {
                    edr_advanced_raise_alert(task, EDR_SIG_ADV_C2_BEACON,
                                            "C2 beaconing detected", false);

                    /* Phase 4a: Automated Response - Block network and terminate */
                    if (edr_response_should_execute(85)) {  /* 85% threat score */
                        edr_response_execute(task, RESPONSE_BLOCK_NETWORK, "C2 beaconing detected");
                        edr_response_execute(task, RESPONSE_TERMINATE_PROCESS, "C2 communication");
                    }
                }
            }
        }
    }

    /* 3. Cryptographic operations - check all processes */
    for (int i = 0; i < task_count; i++) {
        task_t* task = task_array[i];
        /* Only scan tasks that have actually executed. A task that was just
         * created but has never been switched to (has_run_before == false) has
         * done nothing suspicious by definition; scanning/terminating it is pure
         * false-positive surface and races exec's task setup (the brief
         * window where a fresh task could be flipped to TERMINATED before
         * elf_load_process finishes mapping it). */
        if ((task->state == TASK_STATE_RUNNING || task->state == TASK_STATE_READY) &&
            task->has_run_before) {
            if (task->edr_advanced && task->edr_advanced->advanced_detection_enabled) {
                if (edr_crypto_analyze(task)) {
                    /* Ransomware is CRITICAL - terminate immediately */
                    edr_advanced_raise_alert(task, EDR_SIG_ADV_RANSOMWARE,
                                            "Ransomware activity detected!", true);

                    /* Phase 4a: Automated Response - Terminate process immediately */
                    if (edr_response_should_execute(100)) {  /* 100% threat score - CRITICAL */
                        edr_response_execute(task, RESPONSE_TERMINATE_PROCESS, "Ransomware detected");
                    }
                }
            }
        }
    }

    /* 4. File Integrity Monitoring - scan one file per call (round-robin) */
    if (g_fim_db.file_count > 0) {
        file_scan_index = file_scan_index % g_fim_db.file_count;
        fim_entry_t* entry = &g_fim_db.files[file_scan_index];

        if (entry->is_monitored) {
            if (edr_fim_check_integrity(entry->path)) {
                /* File tampering detected - find which process might have done it */
                kprintf("[EDR ADVANCED] File tampering detected: %s\n", entry->path);
            }
        }
        file_scan_index = (file_scan_index + 1) % g_fim_db.file_count;
    }
}

/**
 * @brief Enable/disable advanced detection for a process
 */
void edr_advanced_set_enabled(task_t* task, bool enabled) {
    if (!task || !task->edr_advanced) return;
    task->edr_advanced->advanced_detection_enabled = enabled;
}

/**
 * @brief Get signature name as string
 */
const char* edr_advanced_signature_to_string(edr_advanced_signature_t signature) {
    switch (signature) {
        case EDR_SIG_ADV_CODE_INJECTION: return "CODE_INJECTION";
        case EDR_SIG_ADV_RWX_MEMORY: return "RWX_MEMORY";
        case EDR_SIG_ADV_MEMORY_CORRUPTION: return "MEMORY_CORRUPTION";
        case EDR_SIG_ADV_C2_BEACON: return "C2_BEACON";
        case EDR_SIG_ADV_PORT_SCAN: return "PORT_SCAN";
        case EDR_SIG_ADV_DATA_EXFIL_NET: return "DATA_EXFIL_NET";
        case EDR_SIG_ADV_ROOTKIT: return "ROOTKIT";
        case EDR_SIG_ADV_CONFIG_TAMPER: return "CONFIG_TAMPER";
        case EDR_SIG_ADV_BOOTKIT: return "BOOTKIT";
        case EDR_SIG_ADV_RANSOMWARE: return "RANSOMWARE";
        case EDR_SIG_ADV_CRYPTO_MINING: return "CRYPTO_MINING";
        default: return "UNKNOWN";
    }
}
