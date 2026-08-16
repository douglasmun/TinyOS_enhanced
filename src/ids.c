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
#include "time.h"
#include "user.h"
#include <stdarg.h>

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

/* Bounded format into an alert description. There is no ksnprintf in this
 * tree -- kprintf.h exposes only vsnprintf_impl -- and alert descriptions can
 * carry attacker-controlled substrings, so every formatted alert goes through
 * this rather than through any unbounded string building. */
static void ids_format_desc(char* buf, size_t size, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf_impl(buf, size, fmt, args);
    va_end(args);
}

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
 * Host IDS - Syscall Analysis: REMOVED, not unimplemented
 *=============================================================================
 * ids_analyze_syscall() used to live here as a stub that incremented
 * "Syscalls analyzed" and returned true for every input. It is gone rather
 * than implemented, because the detector it promised already exists and is
 * enforcing: edr_behavioral_check() (edr_behavioral.c) occupies the exact call
 * site this would have used -- syscall.c's dispatcher, mandatory and
 * unbypassable -- and implements the whole advertised list with real per-task
 * state: edr_detect_rop_chain(), edr_detect_syscall_flood(),
 * edr_detect_privilege_escalation(), edr_detect_shellcode(),
 * edr_detect_data_exfiltration(), plus a decaying anomaly score and automated
 * termination.
 *
 * A second detector on that hook would not be defence in depth. It would be a
 * competing score and a competing alert ring for the same event, and it would
 * add per-syscall work and output to a path ring 3 reaches on every keystroke
 * -- which this tree bans outright. IDS_SYSCALL_ANOMALY_THRESHOLD would be
 * recomputing what EDR_RAPID_SYSCALL_THRESHOLD already computes.
 *
 * The "Syscalls analyzed" status line went with it. Nothing else incremented
 * that counter, so keeping the line would have printed a hardcoded 0 forever
 * -- a status field that cannot move is the AUDIT-8E failure shape again, just
 * inverted. Syscall-level detection is reported by the EDR status commands,
 * which is where it actually happens.
 *===========================================================================*/

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
 * Host IDS - Horizontal Credential Attack Detection
 *=============================================================================
 * WHAT THIS COVERS THAT user.c DOES NOT.
 *
 * user.c already locks an account after USER_MAX_LOGIN_ATTEMPTS (3) failures
 * within USER_LOCKOUT_DURATION (60s), audit-logged, enforced. That guard is
 * keyed on the ACCOUNT: it counts into user->failed_attempts. It is a complete
 * answer to a vertical attack -- many passwords against one username.
 *
 * It is structurally blind to the horizontal one. An attacker spraying a single
 * likely password ("password123") across fifty usernames leaves every account
 * at 1/3 failures, so nothing ever reaches the lockout threshold and nothing is
 * ever logged as an attack. Each individual event looks like an ordinary typo.
 * The attack is only visible in the aggregate across DIFFERENT accounts, which
 * is a place no per-account counter can see by construction.
 *
 * Worse, user_authenticate_for() returns -2 for an unknown username before any
 * counter exists at all -- a spray against guessed names touches no
 * failed_attempts field anywhere. That branch is the least observed path in the
 * whole auth system and it is the one a spray spends most of its time in.
 *
 * So this detector keys on USERNAME DIVERSITY, not attempt count: how many
 * DISTINCT usernames have failed inside one decay window. Counting raw failures
 * instead would just duplicate user.c and fire on one user fat-fingering their
 * password four times.
 *
 * WHY NOT src_ip. The old stub took a uint32_t src_ip. Every login path in this
 * kernel is local -- console login, su, and the ring-3 credential syscalls;
 * SSH is excluded from the build and there is no telnet -- so every caller
 * would have passed 0, and a per-source-IP table keyed on 0 collapses to a
 * single global bucket while presenting itself as per-source attribution. That
 * is precisely the AUDIT-8E shape: a field that reads as evidence and is not.
 * The parameter is gone rather than passed a placeholder.
 *
 * WINDOW SIZING. The window is deliberately LONGER than USER_LOCKOUT_DURATION.
 * A spray is slow by design -- staying under the per-account threshold is the
 * whole point of it -- so a window shorter than the lockout period would let an
 * attacker evade this by pacing just slowly enough, while still being fast
 * enough to matter.
 *
 * SEVERITY is MEDIUM, not HIGH, on purpose: ids_generate_alert() blocks the
 * source IP at HIGH, and with src_ip 0 (local, as all logins here are) there is
 * nothing meaningful to block. Raising it to HIGH would only ever produce a
 * no-op block attempt against address 0.
 *
 * NOT A LOCKOUT. This alerts and audits; it does not deny. Denying on username
 * diversity is a self-inflicted DoS -- one attacker could lock the console for
 * everyone by failing five names. The enforcement answer to credential attacks
 * stays where it is, per-account in user.c.
 *===========================================================================*/
#define IDS_SPRAY_WINDOW_SECONDS  300u   /* 5 min; > USER_LOCKOUT_DURATION (60) */
#define IDS_SPRAY_MAX_TRACKED     16u    /* Distinct usernames remembered */

/* THRESHOLD: distinct usernames in one window before alerting.
 *
 * Deliberately NOT IDS_BRUTEFORCE_THRESHOLD (5), which is the network-side
 * constant. shell_login_prompt() allows max_attempts = 3 and then halts the
 * system outright, so a console spray can produce at most THREE distinct failed
 * usernames per boot. A threshold of 5 would be unreachable from the only path
 * that calls this -- a detector that cannot fire, which is the exact placebo
 * this file's AUDIT-8E note exists to prevent.
 *
 * 3 is therefore both the ceiling of what the login path can produce and the
 * point at which a spray is distinguishable from a typo: user.c's own lockout
 * fires at 3 failures against ONE account, so 3 failures against three
 * DIFFERENT accounts is the same amount of evidence pointed at the pattern
 * per-account counting cannot see. Raise this if a remote login path is ever
 * added, since that would lift the max_attempts ceiling. */
#define IDS_SPRAY_THRESHOLD       3u

typedef struct {
    char username[USER_MAX_USERNAME];
    uint32_t last_seen;              /* Uptime seconds of most recent failure */
} ids_failed_login_t;

static ids_failed_login_t spray_table[IDS_SPRAY_MAX_TRACKED];
static uint32_t spray_window_start = 0;
static bool spray_alerted = false;

bool ids_register_login_failure(const char* username) {
    if (!username || username[0] == '\0') {
        return false;
    }

    uint32_t now = time_get_uptime_seconds();
    bool threshold_crossed = false;
    uint32_t distinct = 0;

    /* The table is touched from the login path, which is task context, but the
     * alert ring this may feed is also written from the network ISR. Keep the
     * table update itself atomic and do the alerting outside, matching
     * ids_generate_alert()'s own discipline of not holding interrupts across
     * audit_log(). */
    CRITICAL_SECTION_ENTER();

    /* Expire the whole window at once rather than per entry. A spray is judged
     * on how many distinct names failed TOGETHER; sliding each entry
     * independently would let an attacker hold a rolling set of 4 names alive
     * indefinitely and never assemble a 5th inside one window. */
    if (spray_window_start == 0 || (now - spray_window_start) > IDS_SPRAY_WINDOW_SECONDS) {
        memset(spray_table, 0, sizeof(spray_table));
        spray_window_start = now;
        spray_alerted = false;
    }

    int free_slot = -1;
    bool already_known = false;

    for (uint32_t i = 0; i < IDS_SPRAY_MAX_TRACKED; i++) {
        if (spray_table[i].username[0] == '\0') {
            if (free_slot < 0) {
                free_slot = (int)i;
            }
            continue;
        }
        distinct++;
        if (strcmp(spray_table[i].username, username) == 0) {
            spray_table[i].last_seen = now;
            already_known = true;
        }
    }

    if (!already_known) {
        if (free_slot >= 0) {
            safe_strcpy(spray_table[free_slot].username, username,
                        sizeof(spray_table[free_slot].username));
            spray_table[free_slot].last_seen = now;
            distinct++;
        } else {
            /* Table full. Every slot full already means distinct >=
             * IDS_SPRAY_MAX_TRACKED, which is far past the threshold, so the
             * alert has fired; dropping the name loses nothing. Deliberately
             * NOT evicting: eviction would let a spray of more than 16 names
             * recycle slots and keep `distinct` pinned just under the cap. */
            distinct = IDS_SPRAY_MAX_TRACKED;
        }
    }

    /* One alert per window. Without this, every subsequent failure past the
     * threshold generates another alert and one spray floods the ring, evicting
     * the earlier alerts that identify it -- the same "break on first match"
     * lesson ids_inspect_payload() records. */
    if (distinct >= IDS_SPRAY_THRESHOLD && !spray_alerted) {
        spray_alerted = true;
        threshold_crossed = true;
    }

    CRITICAL_SECTION_EXIT();

    if (threshold_crossed) {
        /* The username is attacker-controlled, so it goes through a bounded
         * format into a fixed buffer; ids_generate_alert() truncates again into
         * the alert slot. */
        char desc[128];
        ids_format_desc(desc, sizeof(desc),
                        "Credential spray: %u distinct usernames failed login "
                        "within %us (most recent '%s')",
                        (unsigned)distinct,
                        (unsigned)IDS_SPRAY_WINDOW_SECONDS, username);
        ids_generate_alert(IDS_ALERT_BRUTEFORCE, IDS_SEVERITY_MEDIUM, 0, desc);

        /* Surfaced on the console explicitly.
         *
         * ids_generate_alert() routes to audit_log() at AUDIT_WARN for anything
         * below IDS_SEVERITY_HIGH, and audit_log_raw() only echoes >= AUDIT_ERROR
         * to serial -- so without this line the detection would be recorded in
         * the audit ring and visible to nobody watching the machine. A detector
         * whose output never surfaces is the same class of bug as one that never
         * runs.
         *
         * Raising the alert to HIGH would surface it but also trip
         * firewall_block_ip() on src_ip 0, which is meaningless for a local
         * login and would put a junk entry in the block list.
         *
         * kprintf is correct here and does not violate the no-chatter rule: this
         * is a once-per-window security event on the login path, not a
         * per-operation print on a path ring 3 reaches. */
        kprintf("[IDS] %s\n", desc);
    }

    return threshold_crossed;
}

/*=============================================================================
 * ids_check_fork_bomb(): REMOVED, not unimplemented
 *=============================================================================
 * This was a stub that always returned false. It is deleted rather than given a
 * body because the defence it names is already enforced at the only point where
 * enforcement is possible: the per-uid live-task cap (USER_MAX_CONCURRENT_TASKS)
 * plus the root slot reserve in task_create_user_argv(), which REFUSES the
 * allocation and returns -EAGAIN.
 *
 * A detector here could only observe after the fact, and after the fact there is
 * nothing left to decide -- the cap already denied the task. Its only effect
 * would be a second opinion about an event that was already prevented, and a
 * FORK_BOMB counter that moves when nothing got through.
 *===========================================================================*/

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
 * The host-based side, which this fix did NOT cover, has since been resolved --
 * by subtraction as much as by addition. ids_register_login_failure() detects a
 * horizontal credential spray (see its block comment above);
 * ids_analyze_syscall() and ids_check_fork_bomb() were DELETED rather than
 * implemented, because edr_behavioral_check() and the per-uid live-task cap
 * already own those and enforce rather than merely observe. Deleting a stub is
 * a legitimate answer to this class of gap: the bug AUDIT-8E named is a claim
 * of protection that nothing backs, and an honest absence makes no claim.
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
    kprintf("Alerts generated:    %llu\n", stats.alerts_generated);
    kprintf("IPs blocked:         %llu\n", stats.ips_blocked);
    kprintf("Signatures loaded:   %u\n", stats.signatures_loaded);
    kprintf("Signature matches:   %llu\n", stats.signature_matches);
    kprintf("\n");
}
