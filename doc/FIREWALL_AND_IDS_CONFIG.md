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

### Signature matching (AUDIT 8E — fixed)

Signatures **are** matched against live traffic. `ids_inspect_payload()` scans the
payload of every inbound IP packet against each enabled signature; a hit raises an
alert, and a `IDS_ACTION_BLOCK` signature also drops the packet. The hook is
`ids_analyze_packet()` in `handle_ip()` (`src/net.c`), which runs before L4
demultiplexing — so a packet is inspected whether or not anything is listening on
its port.

`secstatus` reports the match count next to the signature count:

```
IDS ................. 1 signatures, 0 matches, 0 alerts, 0 IPs blocked
```

Both numbers matter. For as long as only the *loaded* count was displayed, an IDS
that never compared a byte was indistinguishable from one on a quiet network — that
was AUDIT 8E, and it is why the match count is now on the same line.

**What this is not.** The scan is a naive O(n·m) `memcmp` walk, not Aho-Corasick, and
there is **no content normalization** — no URL or HTTP decoding — so an attacker who
encodes the payload evades it. It is also only as good as the one six-byte signature
loaded by default. Anomaly and behavioral detection live in the EDR subsystem, not
here. Treat the IDS as a teaching scaffold that now genuinely detects the cases it
claims to, not as an operational detector.

Regression harness: `verify-ids-signature.sh` (sends a matching and a non-matching
datagram, asserts the counter moves for exactly one of them).

## Host-based detection: credential spray

`ids_register_login_failure()` is the IDS's one host-based detector, called from
`user_authenticate_for()` on **both** failure branches.

It exists because `user.c`'s lockout is keyed on the **account**
(`user->failed_attempts`, 3 failures / 60s). That is a complete answer to a
*vertical* attack — many passwords against one username — and structurally blind to
the *horizontal* one: spraying a single likely password across many usernames leaves
every account at 1/3 and trips nothing. The "user not found" branch is worse still —
it returns before any counter exists, so a spray against guessed names touches
nothing at all.

So this detector keys on **username diversity**, not attempt count: how many distinct
usernames failed inside one window (`IDS_SPRAY_WINDOW_SECONDS`, 300s). Counting raw
failures instead would just duplicate `user.c` and fire on one user mistyping their
password.

Two things not to undo:

- **The threshold is `IDS_SPRAY_THRESHOLD` (3), not the network-side
  `IDS_BRUTEFORCE_THRESHOLD` (5).** `shell_login_prompt()` allows `max_attempts = 3`
  and then halts the machine, so a console spray can produce at most three distinct
  failed usernames per boot. A threshold of 5 would be **unreachable from the only
  path that calls this** — a detector that cannot fire.
- **It alerts; it does not deny.** Denying on username diversity is a self-inflicted
  DoS: one attacker could lock the console for everyone by failing three names.
  Enforcement stays per-account in `user.c`.

It also prints its alert with `kprintf`, deliberately: `ids_generate_alert()` logs at
`AUDIT_WARN` for anything below `IDS_SEVERITY_HIGH`, and `audit_log_raw()` only echoes
`>= AUDIT_ERROR` to serial — so without that line the detection would reach nobody
watching the machine. Raising it to HIGH instead would trip `firewall_block_ip()` on
`src_ip` 0, which is meaningless for a local login.

Regression harness: `verify-ids-spray.sh` (3 failures across 3 distinct usernames must
alert exactly once; 3 failures against **one** username must not alert at all — that
negative is the half that separates this from a duplicate of `user.c`).

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
- ~~Give the host-based detectors a body~~ — **done, and two of the three were
  deleted rather than implemented.** `ids_register_login_failure()` (above) replaced
  `ids_register_login_attempt()`, whose `src_ip` parameter had no source: every login
  path here is local, so every caller would have passed 0 and a per-source-IP table
  keyed on 0 collapses to one global bucket presenting itself as per-source
  attribution. `ids_analyze_syscall()` and `ids_check_fork_bomb()` were removed
  because the detectors they promised already exist and enforce —
  `edr_behavioral_check()` on the syscall dispatcher, and the per-uid live-task cap
  in `task_create_user_argv()` respectively. A second opinion about an event that
  was already denied is not defence in depth. See the block comments in `ids.c`.
- **Improve the matcher** — Aho-Corasick instead of the current O(n·m) scan, and
  content normalization (URL/HTTP decoding), without which encoded payloads evade it.
- **An `ids` shell command** — list/enable/disable signatures and show recent
  alerts at runtime.
- **Persistent rules** — load firewall rules / IDS signatures from a file on the
  FAT32 `C:` drive at boot, so config survives without recompiling.

These are tracked here as documentation, not commitments.
