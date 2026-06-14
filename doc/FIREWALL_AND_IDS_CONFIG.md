# Configuring the Firewall and IDS

How to configure TinyOS Enhanced's packet **firewall** and **intrusion-detection
system (IDS)**. Read this together with [`SECURITY_HARDENING.md`](SECURITY_HARDENING.md)
(memory protections) and [`EDR_QUICK_REFERENCE.md`](EDR_QUICK_REFERENCE.md) (the
behavioral EDR subsystem).

> **Important — configuration is compile-time, not runtime.** TinyOS has **no
> shell command** to add, remove, or edit firewall rules or IDS signatures while
> running. Rules are defined in C source and applied at boot. To change them you
> edit the source and **rebuild the kernel**. The shell only *views* security
> state (`secstatus`, `auditlog`) — it does not configure it. This matches the
> project's educational scope; a runtime rule-management CLI is not implemented.

---

## 1. Firewall

The firewall is a stateful, whitelist (default-deny) packet filter. Source:
`src/firewall.c` / `src/firewall.h`.

### Where the default rules are set

At boot, `src/kernel.c` initialises the firewall and installs the default policy:

```c
/* src/kernel.c */
firewall_init();
firewall_allow_outgoing();      /* allow all outbound connections      */
firewall_allow_established();   /* allow replies on established conns   */
firewall_allow_icmp();          /* allow ICMP (ping)                    */
```

The default inbound policy is **DENY ALL** — only traffic matching an explicit
allow rule (or an established connection) is accepted.

### The rule structure

A rule is a 5-tuple match plus an action (`src/firewall.h`):

```c
typedef struct {
    uint32_t src_ip,  src_ip_mask;   /* 0 = any */
    uint32_t dst_ip,  dst_ip_mask;   /* 0 = any */
    uint16_t src_port;               /* 0 = any */
    uint16_t dst_port;               /* 0 = any */
    uint8_t  protocol;               /* IPPROTO_TCP/UDP/ICMP, 0 = any */
    firewall_action_t action;        /* see below */
    bool enabled;
    bool bidirectional;
    uint32_t packet_count, byte_count;   /* stats, filled at runtime */
    char description[64];
    uint32_t priority;               /* lower value = evaluated first */
} firewall_rule_t;
```

Actions (`firewall_action_t`):

| Action | Effect |
|--------|--------|
| `FW_ACTION_ACCEPT`   | allow the packet |
| `FW_ACTION_DROP`     | silently drop |
| `FW_ACTION_REJECT`   | drop and send ICMP unreachable |
| `FW_ACTION_LOG`      | log, then accept |
| `FW_ACTION_LOG_DROP` | log, then drop |

### How to add or change a rule

Edit the firewall setup in `src/kernel.c` (next to the `firewall_allow_*` calls)
and rebuild. Two ways:

**a) Convenience helpers** (simplest):

```c
firewall_allow_port(22, IPPROTO_TCP, "SSH inbound");  /* open a port   */
firewall_block_ip(0x0A000005);                        /* block 10.0.0.5 */
```

**b) A full rule** via `firewall_add_rule()` — returns a rule ID (or -1):

```c
firewall_rule_t r = {
    .dst_port = 8080,
    .protocol = IPPROTO_TCP,
    .action   = FW_ACTION_ACCEPT,
    .enabled  = true,
    .priority = 100,
    .description = "Allow inbound HTTP-alt",
};
int id = firewall_add_rule(&r);
```

Other C API (callable from kernel code, not the shell):
`firewall_remove_rule(id)`, `firewall_set_rule_enabled(id, bool)`,
`firewall_get_stats(&stats)`.

After editing, rebuild: `make -j8 kernel.elf` (then rebuild the ISO if you boot
from one — see the README).

### Viewing firewall state at runtime

From the shell, `secstatus` shows a firewall summary (packets processed,
dropped, and rejected, plus SYN-flood / port-scan counts). There is no command
to edit rules live.

---

## 2. IDS (Intrusion Detection System)

Signature- and anomaly-oriented IDS. Source: `src/ids.c` / `src/ids.h`.

### Where signatures are defined

Signatures are loaded at boot in `ids_load_default_signatures()` (`src/ids.c`),
called from `ids_init()`. They are hardcoded — there is no signature file or
shell command:

```c
/* src/ids.c — ids_load_default_signatures() */
static uint8_t shellcode_pattern1[] = {0x90,0x90,0x90,0x90,0x31,0xc0};
ids_signature_t sig1 = {
    .name        = "Shellcode NOP Sled",
    .description = "Common x86 shellcode pattern with NOP sled",
    .pattern     = shellcode_pattern1,
    .pattern_len = sizeof(shellcode_pattern1),
    .alert_type  = IDS_ALERT_SHELLCODE,
    .severity    = IDS_SEVERITY_CRITICAL,
    .action      = IDS_ACTION_BLOCK,
    .enabled     = true,
};
ids_add_signature(&sig1);
```

The signature structure (`ids_signature_t`, `src/ids.h`) matches a raw **byte
pattern** (`pattern` / `pattern_len`) and carries an alert type, severity, and
response action:

- **Alert types** (`ids_alert_type_t`): `PORTSCAN`, `SYNFLOOD`,
  `MALFORMED_PACKET`, `BUFFER_OVERFLOW`, `BRUTEFORCE`, `DOS`, `SHELLCODE`,
  `SQL_INJECTION`, `PRIVILEGE_ESCALATION`, `SUSPICIOUS_SYSCALL`, `FORK_BOMB`,
  `FILE_TAMPERING`, `ROOTKIT`, `TRAFFIC_ANOMALY`, `BEHAVIOR_ANOMALY`.
- **Severity** (`ids_severity_t`): `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- **Action** (`ids_action_t`): `LOG`, `ALERT`, `BLOCK`, `QUARANTINE`, `FAILSAFE`.

### How to add a signature

Add another `ids_signature_t` and `ids_add_signature(&sig)` call inside
`ids_load_default_signatures()` in `src/ids.c`, then rebuild. C API:
`ids_add_signature(&sig)`, `ids_remove_signature(id)`, `ids_get_stats(&stats)`.

### ⚠️ Known limitation — signatures are not matched against traffic

The signature **database loads** at boot (you'll see `[IDS] Loaded N attack
signatures`), but TinyOS does **not** currently run a packet-inspection engine
that tests those byte patterns against live traffic. The signature table is
effectively informational. This gap is documented in the source
(`src/ids.c`, "AUDIT 8E: IDS Pattern Matching Gap") and in the security audit
([`MULTI_AGENT_SECURITY_AUDIT_2026.md`](MULTI_AGENT_SECURITY_AUDIT_2026.md)).
Anomaly/behavioral detection lives in the EDR subsystem, not here. Treat the IDS
as a teaching scaffold, not an operational detector.

### Viewing IDS state

`secstatus` shows the loaded signature count and IDS stats; `auditlog` shows
recorded security events (it supports `-n`, `--warn`, `--error`, `--critical`,
`-v`). No command edits signatures live.

---

## 3. Related: EDR

The behavioral **EDR** subsystem (memory / network / crypto / file-integrity
monitoring) is also configured in C and viewed via `secstatus`. Its policy,
whitelist/blacklist, and detector toggles are compile-time C API. See
[`EDR_QUICK_REFERENCE.md`](EDR_QUICK_REFERENCE.md).

---

## Summary

| Component | Configured in | Runtime shell config? | View with |
|-----------|---------------|-----------------------|-----------|
| Firewall  | `src/kernel.c` + `firewall.c/.h` API | No | `secstatus` |
| IDS       | `ids_load_default_signatures()` in `src/ids.c` | No | `secstatus`, `auditlog` |
| EDR       | C API (`edr_*`) | No (`secstatus` view only) | `secstatus` |

To change firewall or IDS behavior: **edit the source, rebuild the kernel,
re-make the ISO.** There is no live reconfiguration interface — by design, for an
educational kernel.

---

## Future enhancements (not yet implemented)

The compile-time-only model is a deliberate starting point, but the C APIs
already exist to support runtime management. Natural near-term improvements:

- **`firewall` shell command** — `firewall list / add / del / enable / disable`,
  wrapping the existing `firewall_add_rule()` / `firewall_remove_rule()` /
  `firewall_set_rule_enabled()` / `firewall_get_stats()` API so rules can be
  managed live without a rebuild. (A good first contribution — the kernel side is
  already done; it only needs a shell front-end.)
- **Wire up the IDS pattern-matching engine** — close the AUDIT 8E gap so loaded
  signatures are actually tested against packet payloads (and the
  port-scan / SYN-flood / brute-force detectors are fed real traffic), turning the
  signature table from informational into operational.
- **An `ids` shell command** — list/enable/disable signatures and show recent
  alerts at runtime.
- **Persistent rules** — load firewall rules / IDS signatures from a file on the
  FAT32 `C:` drive at boot, so config survives without recompiling.

These are tracked here as documentation, not commitments.
