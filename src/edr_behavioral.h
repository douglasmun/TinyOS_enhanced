/*=============================================================================
 * edr_behavioral.h - EDR Behavioral Detection Engine (Phase 2)
 *=============================================================================
 * Syscall pattern analysis and anomaly detection to identify malicious
 * behavior in real-time.
 *
 * FEATURES:
 * - Syscall sequence tracking (circular buffer per process)
 * - Behavioral signature matching (ROP, shellcode, privilege escalation)
 * - Anomaly detection (frequency analysis, unusual patterns)
 * - Alert system with severity levels
 *
 * ATTACK PATTERNS DETECTED:
 * 1. ROP Chains: Rapid syscall changes, unusual sequences
 * 2. Shellcode Execution: exec after network read
 * 3. Privilege Escalation: setuid/setgid after exploit indicators
 * 4. Data Exfiltration: Large reads followed by network writes
 * 5. File Tampering: Writes to sensitive system files
 *
 * USAGE:
 *   // Called automatically from syscall_dispatch()
 *   edr_behavioral_check(current_task, syscall_num);
 *=============================================================================*/
#ifndef EDR_BEHAVIORAL_H
#define EDR_BEHAVIORAL_H

#include <stdint.h>
#include <stdbool.h>
#include "process.h"

/*=============================================================================
 * CONFIGURATION
 *=============================================================================*/

/* Syscall history buffer size (circular buffer) */
#define EDR_SYSCALL_HISTORY_SIZE 32

/* Detection thresholds */
#define EDR_ROP_CHAIN_THRESHOLD 5      /* Consecutive rare syscalls = ROP? */
/* Syscall-flood (DoS) detection. The old "10 syscalls in 10 ticks" tripped on
 * EVERY normal program: at 100 Hz a tick is 10ms, and any process doing ~10
 * back-to-back syscalls (e.g. a hello-world's write() calls, which finish in
 * microseconds — far under one tick) looked like a flood. A burst is normal;
 * a DoS flood is SUSTAINED. Require the full 32-entry history window packed
 * into a sub-tick span, so a finite program (which exits long before issuing
 * 32 syscalls that fast) never trips, while a tight infinite syscall loop
 * does. */
#define EDR_RAPID_SYSCALL_THRESHOLD EDR_SYSCALL_HISTORY_SIZE /* full window (32) */
#define EDR_RAPID_SYSCALL_WINDOW_TICKS 2 /* 32 syscalls in <2 ticks (<20ms) = flood */
#define EDR_EXFIL_SIZE_THRESHOLD 65536 /* 64KB read+write = data exfiltration? */

/*=============================================================================
 * ALERT SEVERITY LEVELS
 *=============================================================================*/
typedef enum {
    EDR_SEVERITY_INFO = 0,      /* Informational (baseline establishment) */
    EDR_SEVERITY_WARNING = 1,   /* Suspicious behavior (log and monitor) */
    EDR_SEVERITY_CRITICAL = 2   /* Confirmed attack (kill process or block) */
} edr_severity_t;

/*=============================================================================
 * BEHAVIORAL SIGNATURES
 *=============================================================================*/
typedef enum {
    EDR_SIG_NONE = 0,
    EDR_SIG_ROP_CHAIN = 1,          /* Rapid syscall changes (ROP gadgets) */
    EDR_SIG_SHELLCODE_EXEC = 2,     /* exec after network read (reverse shell) */
    EDR_SIG_PRIVILEGE_ESCALATION = 3, /* setuid/setgid after exploit */
    EDR_SIG_DATA_EXFILTRATION = 4,  /* Large read → network write */
    EDR_SIG_FILE_TAMPERING = 5,     /* Write to /etc/passwd, /etc/shadow */
    EDR_SIG_SYSCALL_FLOOD = 6,      /* Too many syscalls in short time (DoS) */
    EDR_SIG_ANOMALY = 7             /* Generic anomaly (unusual pattern) */
} edr_signature_t;

/*=============================================================================
 * SYSCALL HISTORY ENTRY
 *=============================================================================*/
typedef struct {
    uint32_t syscall_num;   /* Syscall number (0-127) */
    uint32_t timestamp;     /* Tick count when syscall was made */
    uint32_t arg0;          /* First argument (for context) */
} edr_syscall_entry_t;

/*=============================================================================
 * PER-PROCESS BEHAVIORAL STATE
 *
 * This structure is embedded in task_t (process.h) to track behavioral
 * patterns for each process.
 *=============================================================================*/
typedef struct {
    /* Syscall history (circular buffer) */
    edr_syscall_entry_t history[EDR_SYSCALL_HISTORY_SIZE];
    uint8_t history_head;       /* Next write position (0-31) */
    uint8_t history_count;      /* Number of entries (0-32) */

    /* Anomaly scoring */
    uint16_t anomaly_score;     /* Cumulative anomaly score (0-65535) */
    uint16_t alert_count;       /* Number of alerts raised for this process */

    /* Behavioral flags */
    bool has_network_activity;  /* Has made network-related syscalls */
    bool has_exec_intent;       /* Has attempted exec/execve */
    bool has_privilege_change;  /* Has attempted setuid/setgid */

    /* Last detection */
    edr_signature_t last_signature; /* Last matched signature */
    uint32_t last_alert_tick;       /* Tick of last alert (for rate limiting) */

    /* Detection enabled/disabled */
    bool detection_enabled;     /* Master switch (default: true) */
} edr_behavioral_state_t;

/*=============================================================================
 * ALERT STRUCTURE
 *=============================================================================*/
typedef struct {
    uint32_t pid;               /* Process ID */
    uint32_t timestamp;         /* Tick count */
    edr_severity_t severity;    /* Alert severity */
    edr_signature_t signature;  /* Matched signature */
    char message[128];          /* Human-readable description */
} edr_alert_t;

/*=============================================================================
 * CORE DETECTION FUNCTIONS
 *=============================================================================*/

/**
 * @brief Initialize behavioral detection for a process
 * @param task Process to initialize
 */
void edr_behavioral_init(task_t* task);

/**
 * @brief Check syscall for suspicious patterns (called from syscall_dispatch)
 * @param task Current process
 * @param syscall_num Syscall number being executed
 * @param arg0 First syscall argument (for context)
 * @return true if syscall should be allowed, false if blocked
 */
bool edr_behavioral_check(task_t* task, uint32_t syscall_num, uint32_t arg0);

/**
 * @brief Record syscall in history buffer
 * @param task Process to update
 * @param syscall_num Syscall number
 * @param timestamp Current tick count
 * @param arg0 First syscall argument
 */
void edr_record_syscall(task_t* task, uint32_t syscall_num, uint32_t timestamp, uint32_t arg0);

/**
 * @brief Raise an alert for suspicious behavior
 * @param task Process that triggered the alert
 * @param severity Alert severity level
 * @param signature Matched behavioral signature
 * @param message Human-readable description
 */
void edr_raise_alert(task_t* task, edr_severity_t severity, edr_signature_t signature, const char* message);

/*=============================================================================
 * SIGNATURE DETECTION FUNCTIONS
 *=============================================================================*/

/**
 * @brief Detect ROP chain patterns
 * @param task Process to analyze
 * @return true if ROP chain detected
 */
bool edr_detect_rop_chain(task_t* task);

/**
 * @brief Detect shellcode execution patterns
 * @param task Process to analyze
 * @param syscall_num Current syscall
 * @return true if shellcode pattern detected
 */
bool edr_detect_shellcode(task_t* task, uint32_t syscall_num);

/**
 * @brief Detect privilege escalation attempts
 * @param task Process to analyze
 * @param syscall_num Current syscall
 * @return true if privilege escalation detected
 */
bool edr_detect_privilege_escalation(task_t* task, uint32_t syscall_num);

/**
 * @brief Detect data exfiltration patterns
 * @param task Process to analyze
 * @param syscall_num Current syscall
 * @return true if exfiltration detected
 */
bool edr_detect_data_exfiltration(task_t* task, uint32_t syscall_num);

/**
 * @brief Detect syscall flooding (DoS)
 * @param task Process to analyze
 * @return true if syscall flood detected
 */
bool edr_detect_syscall_flood(task_t* task);

/*=============================================================================
 * HELPER FUNCTIONS
 *=============================================================================*/

/**
 * @brief Get syscall from history (0 = most recent, 1 = previous, etc.)
 * @param task Process to query
 * @param offset History offset (0-31)
 * @return Syscall number, or 0xFFFFFFFF if not available
 */
uint32_t edr_get_history_syscall(task_t* task, uint8_t offset);

/**
 * @brief Check if syscall is "rare" (potential ROP gadget)
 * @param syscall_num Syscall number
 * @return true if syscall is rare/unusual
 */
bool edr_is_rare_syscall(uint32_t syscall_num);

/**
 * @brief Enable/disable behavioral detection for a process
 * @param task Process to configure
 * @param enabled true to enable, false to disable
 */
void edr_behavioral_set_enabled(task_t* task, bool enabled);

/**
 * @brief Get severity level as string
 * @param severity Severity level
 * @return String representation
 */
const char* edr_severity_to_string(edr_severity_t severity);

/**
 * @brief Get signature name as string
 * @param signature Signature type
 * @return String representation
 */
const char* edr_signature_to_string(edr_signature_t signature);

#endif /* EDR_BEHAVIORAL_H */
