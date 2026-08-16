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
 * FUNCTION: ids_inspect_payload
 * PURPOSE: Match a packet payload against the loaded signature database.
 *
 * This closes AUDIT-8E. The signatures were loaded, counted, and displayed by
 * `secstatus` while nothing ever compared a byte against them -- the worst kind
 * of gap, because the status line read as protection.
 *
 * Returns false if a BLOCK-action signature matched, so the caller drops the
 * packet; ALERT-only matches still return true.
 *
 * BOUNDS. The obvious loop, `for (j = 0; j <= len - pattern_len; j++)`, is
 * WRONG here, and is exactly what the AUDIT-8E fix sketch in this file used to
 * recommend: `len` and `pattern_len` are both size_t, so when the payload is
 * shorter than the
 * pattern the subtraction WRAPS to a huge positive number and the scan reads
 * far off the end of the packet buffer. A short packet is entirely
 * attacker-controlled, which makes that an out-of-bounds read reachable from
 * the network -- exactly the class of bug this function exists to catch. The
 * length is compared BEFORE any subtraction.
 *
 * A zero-length pattern would match everywhere and alert on every packet, so
 * it is skipped rather than trusted; ids_add_signature does not check it.
 *===========================================================================*/
static bool ids_inspect_payload(const uint8_t* payload, size_t len, uint32_t src_ip) {
    bool allow = true;

    for (int i = 0; i < signature_count; i++) {
        ids_signature_t* sig = &signatures[i];

        if (!sig->enabled || sig->pattern == NULL) {
            continue;
        }
        /* Guard BEFORE the subtraction below -- see the BOUNDS note above. */
        if (sig->pattern_len == 0 || sig->pattern_len > len) {
            continue;
        }

        size_t last = len - sig->pattern_len;
        for (size_t j = 0; j <= last; j++) {
            if (memcmp(&payload[j], sig->pattern, sig->pattern_len) != 0) {
                continue;
            }

            sig->match_count++;
            stats.signature_matches++;

            /* ids_generate_alert blocks the source itself for HIGH and above;
             * calling firewall_block_ip here as well would double-block. The
             * return value is what stops THIS packet. */
            ids_generate_alert(sig->alert_type, sig->severity, src_ip,
                               sig->description);

            if (sig->action == IDS_ACTION_BLOCK) {
                allow = false;
            }
            break;  /* One alert per signature per packet, not per offset. */
        }
    }

    return allow;
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

    /* Signature matching over the L4 payload (AUDIT-8E).
     *
     * ihl is validated above, but ihl*4 can still EXCEED packet_len -- a header
     * length longer than the packet is malformed and, left unchecked, would
     * make the payload length underflow. Both bounds are re-derived here rather
     * than assumed from the caller: net.c computes the same offset, but this
     * function is exported and must hold on its own.
     *
     * The scan covers the payload only. Running it over the header as well
     * would let ordinary address and checksum bytes trip a short signature. */
    size_t hdr_len = (size_t)ihl * 4u;
    if (hdr_len >= packet_len) {
        return true;   /* No payload to inspect; header checks already passed. */
    }

    const uint8_t* payload = (const uint8_t*)ip_header + hdr_len;
    return ids_inspect_payload(payload, packet_len - hdr_len, src_ip);
}

/*=============================================================================
 * Host IDS - Syscall Analysis
 *===========================================================================*/
/* STUB -- detects nothing, and has no callers. Kept because the header
 * advertises it and removing it would change the public API, but note that
 * wiring it into the syscall dispatcher as it stands would be worse than
 * leaving it out: it would cost a call on every syscall, raise
 * "Syscalls analyzed" off zero, and still return true for every input. That
 * misleading counter is the same shape of bug AUDIT-8E named. Give it a real
 * body before giving it a call site. */
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
/* STUB -- no callers, no state, always "not a brute force". The login path
 * does its own throttling; this would need a per-source-IP attempt table with
 * a decay window before it is worth calling. See ids_analyze_syscall(). */
bool ids_register_login_attempt(uint32_t src_ip, const char* username) {
    (void)src_ip;
    (void)username;
    return false;
}

/* STUB -- no callers, always false. Note the actual defence against task-slot
 * exhaustion is the per-uid live-task cap in task_create_user_argv(), which is
 * enforced, tested, and does not depend on this. */
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
 * SECURITY DOCUMENTATION (AUDIT 8E): IDS Pattern Matching Gap -- FIXED
 *
 * WAS: Placebo Security - Signatures Never Checked
 *
 * ids_load_default_signatures() populated signatures[] and ids_print_status()
 * reported "Signatures loaded: 1", but nothing ever compared a byte of network
 * traffic against them. A packet carrying the exact NOP sled in signatures[0]
 * produced no alert. The status line was the whole problem: a loaded count with
 * no match count reads identically whether the matcher is running or absent.
 *
 * FIX: ids_inspect_payload() (above ids_analyze_packet) walks every enabled
 * signature over the IP payload and calls ids_generate_alert() on a hit.
 * ids_analyze_packet() calls it as its last step, so the existing hook in
 * net.c:ip_receive is the only call site -- there is no second one to get wrong
 * or to leave out of a future protocol handler.
 *
 * Two properties worth keeping if this is ever rewritten:
 *
 * 1. BOUNDS. The obvious loop bound `j <= len - pattern_len` is a size_t
 *    underflow when the payload is shorter than the pattern: it wraps to ~4e9
 *    and memcmp() walks off the end of the packet buffer. Since the payload is
 *    attacker-controlled and this runs in the receive path, that is a remotely
 *    triggerable OOB read. ids_inspect_payload() rejects pattern_len == 0 and
 *    pattern_len > len BEFORE the subtraction. (An earlier revision of this
 *    comment recommended exactly the underflowing loop -- do not restore it.)
 *
 * 2. ONE ALERT PER SIGNATURE PER PACKET. The inner loop breaks on first match.
 *    A NOP sled matches at every offset; alerting per offset would let one
 *    packet flood the alert ring and evict real alerts.
 *
 * stats.signature_matches counts hits so the status line can distinguish a
 * quiet network from a dead matcher. That is the assertion verify-ids.sh keys
 * on, and the negative control is a packet that matches nothing.
 *
 * STILL HEURISTIC-ONLY, deliberately: this is a naive O(n*m) memcmp scan, not
 * Aho-Corasick, and there is no content normalization (no URL/HTTP decoding),
 * so an attacker who encodes the payload evades it. That is acceptable for one
 * six-byte signature on a teaching kernel; it would not be with a real ruleset.
 *
 * NOT covered by this fix -- the host-based detectors remain empty stubs:
 * ids_analyze_syscall(), ids_register_login_attempt(), ids_check_fork_bomb().
 * They count and return; they detect nothing. See ids_analyze_syscall().
 *===========================================================================*/

/*=============================================================================
 * Load Default Attack Signatures
 *===========================================================================*/
void ids_load_default_signatures(void) {
    /* Every enabled entry here is scanned against each inbound IP payload by
     * ids_inspect_payload(). Adding one costs a memcmp pass per packet. */

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
    kprintf("Signature matches:   %llu\n", stats.signature_matches);
    kprintf("\n");
}
