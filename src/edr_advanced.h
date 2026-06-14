/*=============================================================================
 * edr_advanced.h - EDR Advanced Detection Module (Phase 3)
 *=============================================================================
 * Advanced threat detection capabilities for sophisticated attacks.
 *
 * MODULES:
 * 1. Memory Inspection - Detect code injection, shellcode, RWX regions
 * 2. Network Flow Analysis - Track connections, detect C2 patterns
 * 3. File Integrity Monitoring (FIM) - Hash critical files, detect tampering
 * 4. Cryptographic Operations Monitoring - Detect ransomware encryption
 *
 * ATTACK PATTERNS DETECTED:
 * - Code injection (shellcode in heap/stack)
 * - Command & Control (C2) beaconing
 * - Rootkit installation (system file tampering)
 * - Ransomware encryption activity
 * - Memory corruption exploits
 * - Persistence mechanisms
 *
 * USAGE:
 *   edr_advanced_init();  // Initialize FIM database
 *   edr_advanced_periodic_check();  // Called from timer interrupt
 *=============================================================================*/
#ifndef EDR_ADVANCED_H
#define EDR_ADVANCED_H

#include <stdint.h>
#include <stdbool.h>
#include "process.h"

/*=============================================================================
 * CONFIGURATION
 *=============================================================================*/

/* Memory inspection */
#define EDR_MEM_SCAN_PAGES 16         /* Scan 16 pages (64KB) per check */
#define EDR_SHELLCODE_THRESHOLD 5     /* Min suspicious patterns for alert */

/* Network flow analysis */
#define EDR_MAX_CONNECTIONS 16        /* Track up to 16 connections per process */
#define EDR_C2_BEACON_THRESHOLD 10    /* 10 periodic connections = C2? */

/* File integrity monitoring */
#define EDR_FIM_MAX_FILES 32          /* Monitor up to 32 critical files */
#define EDR_FIM_HASH_SIZE 32          /* SHA-256 hash (32 bytes) */

/* Cryptographic operations monitoring */
#define EDR_CRYPTO_THRESHOLD 100      /* 100 crypto ops/sec = ransomware? */
#define EDR_CRYPTO_HISTORY_SIZE 10    /* Track last 10 seconds of crypto activity */

/*=============================================================================
 * ADVANCED SIGNATURES (extends Phase 2)
 *=============================================================================*/
typedef enum {
    /* Memory-based attacks */
    EDR_SIG_ADV_CODE_INJECTION = 100,      /* Shellcode in heap/stack */
    EDR_SIG_ADV_RWX_MEMORY = 101,          /* Suspicious RWX memory regions */
    EDR_SIG_ADV_MEMORY_CORRUPTION = 102,   /* Stack/heap overflow detected */

    /* Network-based attacks */
    EDR_SIG_ADV_C2_BEACON = 200,           /* Command & Control beaconing */
    EDR_SIG_ADV_PORT_SCAN = 201,           /* Port scanning activity */
    EDR_SIG_ADV_DATA_EXFIL_NET = 202,      /* Large network data transfer */

    /* File-based attacks */
    EDR_SIG_ADV_ROOTKIT = 300,             /* System file tampering (rootkit) */
    EDR_SIG_ADV_CONFIG_TAMPER = 301,       /* Configuration file modification */
    EDR_SIG_ADV_BOOTKIT = 302,             /* Boot sector modification */

    /* Cryptographic attacks */
    EDR_SIG_ADV_RANSOMWARE = 400,          /* Rapid file encryption (ransomware) */
    EDR_SIG_ADV_CRYPTO_MINING = 401        /* Cryptocurrency mining activity */
} edr_advanced_signature_t;

/*=============================================================================
 * MODULE 1: MEMORY INSPECTION
 *=============================================================================*/

/**
 * @brief Shellcode signature patterns (NOP sleds, syscall instructions, etc.)
 */
typedef struct {
    const char* name;
    const uint8_t* pattern;
    size_t pattern_len;
    uint8_t weight;  /* How suspicious (1-10) */
} shellcode_signature_t;

/**
 * @brief Memory region information
 */
typedef struct {
    uint32_t start_addr;
    uint32_t end_addr;
    bool readable;
    bool writable;
    bool executable;
    uint8_t suspicious_score;  /* 0-100 */
} memory_region_t;

/**
 * @brief Per-process memory inspection state
 */
typedef struct {
    uint32_t last_scan_tick;         /* Last time we scanned this process */
    uint32_t next_scan_addr;         /* Next address to scan (for incremental scanning) */
    uint16_t rwx_region_count;       /* Number of RWX regions detected */
    uint16_t shellcode_detections;   /* Number of shellcode patterns found */
    bool has_suspicious_memory;      /* Flag for quick checks */
} edr_memory_state_t;

/**
 * @brief Scan process memory for suspicious patterns
 * @param task Process to scan
 * @return true if suspicious activity detected
 */
bool edr_memory_inspect(task_t* task);

/**
 * @brief Detect shellcode patterns in memory buffer
 * @param buffer Memory buffer to scan
 * @param size Buffer size
 * @return Suspicion score (0-100)
 */
uint8_t edr_memory_detect_shellcode(const uint8_t* buffer, size_t size);

/**
 * @brief Check for RWX (read-write-execute) memory regions
 * @param task Process to check
 * @return Number of suspicious RWX regions
 */
uint16_t edr_memory_check_rwx_regions(task_t* task);

/*=============================================================================
 * MODULE 2: NETWORK FLOW ANALYSIS
 *=============================================================================*/

/**
 * @brief Network connection tracking entry
 */
typedef struct {
    uint32_t remote_ip;              /* Remote IP address */
    uint16_t remote_port;            /* Remote port */
    uint16_t local_port;             /* Local port */
    uint32_t established_tick;       /* When connection was established */
    uint32_t last_activity_tick;     /* Last packet sent/received */
    uint32_t bytes_sent;             /* Total bytes sent */
    uint32_t bytes_received;         /* Total bytes received */
    uint8_t beacon_count;            /* Periodic connection counter (C2 detection) */
} network_connection_t;

/**
 * @brief Per-process network flow state
 */
typedef struct {
    network_connection_t connections[EDR_MAX_CONNECTIONS];
    uint8_t connection_count;        /* Number of active connections */
    uint32_t total_bytes_sent;       /* Lifetime bytes sent */
    uint32_t total_bytes_received;   /* Lifetime bytes received */
    uint16_t c2_score;               /* Command & Control suspicion score */
    bool has_network_activity;       /* Quick flag */
} edr_network_state_t;

/**
 * @brief Analyze network traffic patterns
 * @param task Process to analyze
 * @return true if suspicious network activity detected
 */
bool edr_network_analyze(task_t* task);

/**
 * @brief Track new network connection
 * @param task Process making connection
 * @param remote_ip Remote IP address
 * @param remote_port Remote port
 * @param local_port Local port
 */
void edr_network_track_connection(task_t* task, uint32_t remote_ip,
                                   uint16_t remote_port, uint16_t local_port);

/**
 * @brief Detect Command & Control (C2) beaconing patterns
 * @param task Process to check
 * @return true if C2 beaconing detected
 */
bool edr_network_detect_c2_beacon(task_t* task);

/*=============================================================================
 * MODULE 3: FILE INTEGRITY MONITORING (FIM)
 *=============================================================================*/

/**
 * @brief File integrity entry (hash database)
 */
typedef struct {
    char path[64];                   /* File path (e.g., "/bin/init") */
    uint8_t hash[EDR_FIM_HASH_SIZE]; /* SHA-256 hash */
    uint32_t last_check_tick;        /* Last integrity check */
    bool is_monitored;               /* Currently monitored */
    bool tampered;                   /* Integrity violation detected */
} fim_entry_t;

/**
 * @brief Global FIM database
 */
typedef struct {
    fim_entry_t files[EDR_FIM_MAX_FILES];
    uint8_t file_count;
    uint32_t last_full_scan_tick;
    uint16_t tamper_count;           /* Number of tampered files */
} fim_database_t;

/**
 * @brief Initialize File Integrity Monitoring
 *
 * Computes baseline hashes for critical system files:
 * - /bin/ directory (system binaries)
 * - /etc/ directory (configuration files)
 * - /boot/ directory (bootloader)
 */
void edr_fim_init(void);

/**
 * @brief Add file to FIM monitoring
 * @param path File path to monitor
 * @return true if successfully added
 */
bool edr_fim_add_file(const char* path);

/**
 * @brief Check file integrity against baseline
 * @param path File path to check
 * @return true if file has been tampered with
 */
bool edr_fim_check_integrity(const char* path);

/**
 * @brief Perform periodic integrity scan of all monitored files
 * @return Number of tampered files detected
 */
uint16_t edr_fim_scan_all(void);

/**
 * @brief Compute SHA-256 hash of file
 * @param path File path
 * @param hash_out Output buffer (32 bytes)
 * @return true if successful
 */
bool edr_fim_hash_file(const char* path, uint8_t* hash_out);

/*=============================================================================
 * MODULE 4: CRYPTOGRAPHIC OPERATIONS MONITORING
 *=============================================================================*/

/**
 * @brief Crypto operation types
 */
typedef enum {
    CRYPTO_OP_ENCRYPT = 0,
    CRYPTO_OP_DECRYPT = 1,
    CRYPTO_OP_HASH = 2,
    CRYPTO_OP_KEYGEN = 3
} crypto_op_type_t;

/**
 * @brief Crypto activity snapshot (per second)
 */
typedef struct {
    uint16_t encrypt_count;          /* Encryption operations */
    uint16_t decrypt_count;          /* Decryption operations */
    uint32_t bytes_encrypted;        /* Bytes encrypted */
    uint32_t bytes_decrypted;        /* Bytes decrypted */
} crypto_activity_t;

/**
 * @brief Per-process cryptographic monitoring state
 */
typedef struct {
    crypto_activity_t history[EDR_CRYPTO_HISTORY_SIZE];  /* Last 10 seconds */
    uint8_t history_head;            /* Circular buffer head */
    uint32_t total_encrypt_ops;      /* Lifetime encryption operations */
    uint32_t total_decrypt_ops;      /* Lifetime decryption operations */
    uint16_t ransomware_score;       /* Ransomware suspicion score */
    bool has_crypto_activity;        /* Quick flag */
} edr_crypto_state_t;

/**
 * @brief Track cryptographic operation
 * @param task Process performing crypto
 * @param op_type Type of operation (encrypt/decrypt/hash/keygen)
 * @param bytes Number of bytes processed
 */
void edr_crypto_track_operation(task_t* task, crypto_op_type_t op_type, uint32_t bytes);

/**
 * @brief Detect ransomware encryption patterns
 * @param task Process to check
 * @return true if ransomware activity detected
 */
bool edr_crypto_detect_ransomware(task_t* task);

/**
 * @brief Analyze crypto activity for suspicious patterns
 * @param task Process to analyze
 * @return true if suspicious crypto activity detected
 */
bool edr_crypto_analyze(task_t* task);

/*=============================================================================
 * ADVANCED DETECTION STATE (embedded in task_t)
 *=============================================================================*/

/**
 * @brief Per-process advanced detection state
 *
 * This structure is embedded in task_t to track advanced detection metrics.
 */
typedef struct edr_advanced_state {
    edr_memory_state_t memory;       /* Memory inspection state */
    edr_network_state_t network;     /* Network flow analysis state */
    edr_crypto_state_t crypto;       /* Cryptographic monitoring state */

    /* Global flags */
    bool advanced_detection_enabled; /* Master switch (default: true) */
    uint16_t advanced_alert_count;   /* Number of advanced alerts */
} edr_advanced_state_t;

/*=============================================================================
 * CORE FUNCTIONS
 *=============================================================================*/

/**
 * @brief Initialize advanced detection system
 *
 * Sets up FIM database, loads signatures, initializes global state.
 * Should be called once during kernel initialization.
 */
void edr_advanced_init(void);

/**
 * @brief Initialize advanced detection state for a process
 * @param task Process to initialize
 */
void edr_advanced_init_process(task_t* task);

/**
 * @brief Periodic check for advanced threats (called from timer interrupt)
 *
 * Performs incremental scanning:
 * - Memory inspection (1 process per tick)
 * - Network flow analysis (all processes)
 * - File integrity check (1 file per tick)
 * - Crypto activity analysis (all processes)
 */
void edr_advanced_periodic_check(void);

/**
 * @brief Enable/disable advanced detection for a process
 * @param task Process to configure
 * @param enabled true to enable, false to disable
 */
void edr_advanced_set_enabled(task_t* task, bool enabled);

/**
 * @brief Get signature name as string
 * @param signature Advanced signature type
 * @return String representation
 */
const char* edr_advanced_signature_to_string(edr_advanced_signature_t signature);

#endif /* EDR_ADVANCED_H */
