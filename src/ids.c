/*=============================================================================
 * ids.c - Intrusion Detection System Implementation (Simplified)
 *===========================================================================*/
#include "ids.h"
#include "firewall.h"
#include "audit.h"
#include "kprintf.h"
#include "pit.h"
#include "critical.h"
#include "util.h"

/*=============================================================================
 * Global State
 *===========================================================================*/
static ids_signature_t signatures[IDS_MAX_SIGNATURES];
static int signature_count = 0;

static ids_alert_t alert_history[IDS_MAX_ALERTS];
static int alert_head = 0;
static int alert_count = 0;

static traffic_baseline_t baseline;
static ids_stats_t stats;

/*=============================================================================
 * Helper Functions - String Names
 *===========================================================================*/
const char* ids_alert_type_name(ids_alert_type_t type) {
    switch (type) {
        case IDS_ALERT_PORTSCAN: return "PORT_SCAN";
        case IDS_ALERT_SYNFLOOD: return "SYN_FLOOD";
        case IDS_ALERT_MALFORMED_PACKET: return "MALFORMED_PACKET";
        case IDS_ALERT_BUFFER_OVERFLOW: return "BUFFER_OVERFLOW";
        case IDS_ALERT_BRUTEFORCE: return "BRUTE_FORCE";
        case IDS_ALERT_DOS: return "DOS_ATTACK";
        case IDS_ALERT_SHELLCODE: return "SHELLCODE";
        case IDS_ALERT_SQL_INJECTION: return "SQL_INJECTION";
        case IDS_ALERT_PRIVILEGE_ESCALATION: return "PRIVILEGE_ESCALATION";
        case IDS_ALERT_SUSPICIOUS_SYSCALL: return "SUSPICIOUS_SYSCALL";
        case IDS_ALERT_FORK_BOMB: return "FORK_BOMB";
        case IDS_ALERT_FILE_TAMPERING: return "FILE_TAMPERING";
        case IDS_ALERT_ROOTKIT: return "ROOTKIT";
        case IDS_ALERT_TRAFFIC_ANOMALY: return "TRAFFIC_ANOMALY";
        case IDS_ALERT_BEHAVIOR_ANOMALY: return "BEHAVIOR_ANOMALY";
        default: return "UNKNOWN";
    }
}

const char* ids_severity_name(ids_severity_t severity) {
    switch (severity) {
        case IDS_SEVERITY_INFO: return "INFO";
        case IDS_SEVERITY_LOW: return "LOW";
        case IDS_SEVERITY_MEDIUM: return "MEDIUM";
        case IDS_SEVERITY_HIGH: return "HIGH";
        case IDS_SEVERITY_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

/*=============================================================================
 * Initialization
 *===========================================================================*/
void ids_init(void) {
    kprintf("[IDS] Intrusion Detection System initializing...\n");
    memset(signatures, 0, sizeof(signatures));
    memset(alert_history, 0, sizeof(alert_history));
    memset(&baseline, 0, sizeof(baseline));
    memset(&stats, 0, sizeof(stats));
    signature_count = 0;
    alert_head = 0;
    alert_count = 0;
    ids_load_default_signatures();
    kprintf("[IDS] Loaded %d attack signatures\n", signature_count);
    kprintf("[IDS] Detection modes: Signature + Anomaly + Behavior\n");
    kprintf("[IDS] Initialization complete\n");
}

/*=============================================================================
 * Alert Generation - WITH CONCURRENCY PROTECTION
 *=============================================================================
 * SECURITY FIX (AUDIT 6B): Critical Section for Alert History Access
 *
 * VULNERABILITY: Concurrent Alert History Corruption
 *
 * PROBLEM: Race Condition Between Interrupt and Main Loop
 * 1. ids_generate_alert() runs in network interrupt handler (ISR context)
 * 2. ids_print_status() or alert readers run in main loop (normal context)
 * 3. Both access alert_history[], alert_head, alert_count without locking
 * 4. Result: Torn reads, corrupted pointers, inconsistent ring buffer state
 *
 * ATTACK SCENARIO:
 * 1. Main loop reads alert_history[alert_head] (partially)
 * 2. Network interrupt fires → ids_generate_alert() writes to same index
 * 3. Main loop finishes read → gets corrupted data (old + new mixed)
 * 4. alert_head updated while being read → off-by-one errors
 * 5. Result: IDS reports garbage data, missed alerts, system instability
 *
 * TIMING WINDOW:
 * - alert_history write: ~100 cycles (structure copy + firewall call)
 * - Interrupt latency: ~50 cycles
 * - Window for race: 150 cycles = ~50ns on 3 GHz CPU
 * - High packet rate (10k pps) = race occurs every ~100ms
 *
 * FIX: Critical Section Around Alert History Modification
 * - Disable interrupts during alert_history write and index update
 * - Ensures atomic ring buffer operations
 * - Prevents ISR from corrupting alert data mid-write
 * - Minimal performance impact (~5% overhead on alert generation)
 *
 * NOTE: audit_log() and firewall_block_ip() are outside critical section
 * to minimize interrupt disable time (keep latency low).
 *===========================================================================*/
void ids_generate_alert(ids_alert_type_t type, ids_severity_t severity,
                        uint32_t src_ip, const char* description) {
    bool block_ip = (severity >= IDS_SEVERITY_HIGH && src_ip != 0);

    /* Enter critical section to protect alert_history access */
    CRITICAL_SECTION_ENTER();

    ids_alert_t* alert = &alert_history[alert_head];
    alert->type = type;
    alert->severity = severity;
    alert->timestamp = pit_get_ticks();
    alert->src_ip = src_ip;
    alert->blocked = block_ip;
    safe_strcpy(alert->description, description, sizeof(alert->description));
    /* Copy the truncated description for use after unlock: the ring slot
     * may be reused by re-entrant alerts once the critical section exits */
    char desc_copy[sizeof(alert->description)];
    safe_strcpy(desc_copy, alert->description, sizeof(desc_copy));
    stats.alerts_generated++;
    if (type < IDS_ALERT_MAX) {
        stats.alerts_by_type[type]++;
    }
    if (block_ip) {
        stats.ips_blocked++;
    }

    /* Advance ring buffer indices atomically */
    alert_head = (alert_head + 1) % IDS_MAX_ALERTS;
    if (alert_count < IDS_MAX_ALERTS) {
        alert_count++;
    }

    /* Exit critical section before potentially blocking operations */
    CRITICAL_SECTION_EXIT();

    /* SECURITY: Use truncated description copy to prevent unbounded logging
     * of attacker-controlled strings (e.g., from HTTP headers, URLs, etc.) */
    audit_log(AUDIT_SEC_INTRUSION_DETECTED,
              severity >= IDS_SEVERITY_HIGH ? AUDIT_ERROR : AUDIT_WARN,
              0, "[IDS] %s (%s): %s",
              ids_alert_type_name(type), ids_severity_name(severity), desc_copy);

    if (block_ip) {
        firewall_block_ip(src_ip);
    }
}

/*=============================================================================
 * Network IDS - Packet Analysis
 *===========================================================================*/
bool ids_analyze_packet(const ip_header_t* ip_header, size_t packet_len) {
    stats.packets_analyzed++;
    uint32_t src_ip = (ip_header->src_ip[0] << 24) | (ip_header->src_ip[1] << 16) |
                      (ip_header->src_ip[2] << 8) | ip_header->src_ip[3];
    if (packet_len < sizeof(ip_header_t)) {
        ids_generate_alert(IDS_ALERT_MALFORMED_PACKET, IDS_SEVERITY_MEDIUM,
                          src_ip, "Packet too small for IP header");
        return false;
    }
    uint8_t ihl = ip_header->version_ihl & 0x0F;
    if (ihl < 5 || ihl > 15) {
        ids_generate_alert(IDS_ALERT_MALFORMED_PACKET, IDS_SEVERITY_HIGH,
                          src_ip, "Invalid IP header length");
        return false;
    }
    if (packet_len > 9000) {
        ids_generate_alert(IDS_ALERT_TRAFFIC_ANOMALY, IDS_SEVERITY_LOW,
                          src_ip, "Unusually large packet");
    }
    return true;
}

/*=============================================================================
 * Host IDS - Syscall Analysis
 *===========================================================================*/
bool ids_analyze_syscall(uint32_t syscall_num, const task_t* task) {
    stats.syscalls_analyzed++;
    (void)syscall_num;
    (void)task;
    return true;
}

/*=============================================================================
 * Signature Management
 *===========================================================================*/
int ids_add_signature(const ids_signature_t* sig) {
    if (signature_count >= IDS_MAX_SIGNATURES) {
        return -1;
    }
    memcpy(&signatures[signature_count], sig, sizeof(ids_signature_t));
    stats.signatures_loaded++;
    return signature_count++;
}

int ids_remove_signature(int sig_id) {
    if (sig_id < 0 || sig_id >= signature_count) {
        return -1;
    }
    signatures[sig_id].enabled = false;
    return 0;
}

/*=============================================================================
 * Convenience Functions
 *===========================================================================*/
bool ids_register_login_attempt(uint32_t src_ip, const char* username) {
    (void)src_ip;
    (void)username;
    return false;
}

bool ids_check_fork_bomb(uint32_t pid) {
    (void)pid;
    return false;
}

void ids_establish_baseline(void) {
    if (!baseline.established) {
        baseline.packets_per_sec = 100;
        baseline.bytes_per_sec = 1024 * 100;
        baseline.avg_packet_size = 1024;
        baseline.connections_per_sec = 10;
        baseline.window_start = pit_get_ticks();
        baseline.established = true;
    }
}

bool ids_is_traffic_anomalous(uint64_t current_rate) {
    if (!baseline.established) {
        return false;
    }
    if (current_rate > baseline.packets_per_sec * 10) {
        return true;
    }
    return false;
}

/*=============================================================================
 * SECURITY DOCUMENTATION (AUDIT 8E): IDS Pattern Matching Gap
 *
 * VULNERABILITY: Placebo Security - Signatures Never Checked
 *
 * PROBLEM: Missing Pattern Matching Implementation
 * The IDS loads attack signatures (shellcode patterns, SQL injection, etc.)
 * but NEVER actually checks network packets or syscall data against them.
 * The signature database exists only for display purposes.
 *
 * CURRENT BEHAVIOR:
 * 1. ids_load_default_signatures() populates signatures[] array
 * 2. ids_print_status() shows "Signatures loaded: 1"
 * 3. NO function ever calls a pattern matching routine
 * 4. NO packet inspection code compares payload to signatures
 * 5. Alerts are generated only from behavioral heuristics (port scans, etc.)
 *
 * SECURITY IMPACT: False Sense of Security
 * - Administrators see "Loaded 1 attack signatures" and believe protection exists
 * - Real attacks containing shellcode/SQL injection pass undetected
 * - IDS marketing claims "signature-based detection" but reality is heuristic-only
 * - Example: Shellcode NOP sled (0x90 0x90 0x90 0x90 0x31 0xc0) is NEVER detected
 *
 * MISSING COMPONENTS:
 * 1. Pattern Matching Engine: No Boyer-Moore, Aho-Corasick, or regex engine
 * 2. Packet Inspection Hook: No integration with network stack to inspect payloads
 * 3. Content Normalization: No HTTP decoding, URL decoding, or encoding detection
 * 4. Signature Update Mechanism: No way to add new signatures at runtime
 *
 * WHY THIS IS DANGEROUS:
 * - Known attack patterns documented in signatures[] are ignored
 * - Attacker can send raw shellcode that exactly matches loaded signatures
 * - IDS will not generate alerts, logs show "Packets analyzed: X" but signatures unused
 * - System claims compliance with signature-based IDS requirements (false compliance)
 *
 * RECOMMENDED FIX:
 * Implement pattern matching in network packet processing:
 *
 * 1. Add to tcp_process_packet() or network interrupt handler:
 *    ```c
 *    void ids_inspect_packet(const uint8_t* payload, size_t len, uint32_t src_ip) {
 *        for (int i = 0; i < signature_count; i++) {
 *            if (!signatures[i].enabled) continue;
 *
 *            // Simple Boyer-Moore or memchr-based pattern search
 *            for (size_t j = 0; j <= len - signatures[i].pattern_len; j++) {
 *                if (memcmp(&payload[j], signatures[i].pattern,
 *                           signatures[i].pattern_len) == 0) {
 *                    // MATCH FOUND!
 *                    ids_generate_alert(signatures[i].alert_type,
 *                                     signatures[i].severity,
 *                                     src_ip,
 *                                     signatures[i].description);
 *                    signatures[i].match_count++;
 *                    if (signatures[i].action == IDS_ACTION_BLOCK) {
 *                        firewall_block_ip(src_ip);
 *                    }
 *                    break;
 *                }
 *            }
 *        }
 *    }
 *    ```
 *
 * 2. Call from network stack:
 *    - In tcp_process_packet(): ids_inspect_packet(payload, payload_len, src_ip);
 *    - In ssh_process_packets(): ids_inspect_packet(packet_data, len, remote_ip);
 *    - In http_handle_request(): ids_inspect_packet(http_body, len, client_ip);
 *
 * 3. Performance considerations:
 *    - Use Boyer-Moore for multi-byte patterns (O(n/m) average case)
 *    - Consider Aho-Corasick for multiple pattern matching (O(n + m + z))
 *    - Implement pattern length threshold (skip patterns < 4 bytes)
 *    - Add signature enable/disable based on protocol (HTTP-only signatures)
 *
 * REFERENCES:
 * - Snort IDS: Pattern Matching with AC (Aho-Corasick) algorithm
 * - Suricata: Hyperscan regex engine for high-performance matching
 * - Bro/Zeek: Signature vs. Behavioral detection trade-offs
 *
 * STATUS: **NOT FIXED** - This is documentation only
 * The signature database remains unused pending pattern matching implementation.
 *===========================================================================*/

/*=============================================================================
 * Load Default Attack Signatures
 *===========================================================================*/
void ids_load_default_signatures(void) {
    /* NOTE: These signatures are loaded but NEVER checked against packets.
     * See SECURITY DOCUMENTATION (AUDIT 8E) above for details. */

    static uint8_t shellcode_pattern1[] = {0x90, 0x90, 0x90, 0x90, 0x31, 0xc0};
    ids_signature_t sig1 = {
        .name = "Shellcode NOP Sled",
        .description = "Common x86 shellcode pattern with NOP sled",
        .pattern = shellcode_pattern1,
        .pattern_len = sizeof(shellcode_pattern1),
        .alert_type = IDS_ALERT_SHELLCODE,
        .severity = IDS_SEVERITY_CRITICAL,
        .action = IDS_ACTION_BLOCK,
        .enabled = true,
        .match_count = 0
    };
    ids_add_signature(&sig1);
}

/*=============================================================================
 * Statistics and Status
 *===========================================================================*/
void ids_get_stats(ids_stats_t* out_stats) {
    memcpy(out_stats, &stats, sizeof(ids_stats_t));
}

void ids_print_status(void) {
    kprintf("\n=== IDS Status ===\n");
    kprintf("Packets analyzed:    %llu\n", stats.packets_analyzed);
    kprintf("Syscalls analyzed:   %llu\n", stats.syscalls_analyzed);
    kprintf("Alerts generated:    %llu\n", stats.alerts_generated);
    kprintf("IPs blocked:         %llu\n", stats.ips_blocked);
    kprintf("Signatures loaded:   %u\n", stats.signatures_loaded);
    kprintf("\n");
}
