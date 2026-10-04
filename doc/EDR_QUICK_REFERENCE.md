# TinyOS EDR: Quick Reference

What the endpoint detection and response (EDR) code in `src/` actually does, as of
v2.9 (reviewed 2026-10). Everything is configured at compile time; there is no EDR
shell command. `secstatus` is the only runtime view.

---

## Files

| File | Role |
|---|---|
| `src/edr_behavioral.[ch]` | Per-task syscall history and signatures, run on every syscall |
| `src/edr_advanced.[ch]` | Periodic checks: file integrity (FIM), C2 beaconing, ransomware rate |
| `src/edr_response.c` | Response actions (terminate, alert); policy threshold |
| `src/edr_threat_intel.c` | IoC tables (file hashes, IPv4), CSV loader |
| `src/edr_daemon.c` | Background scanner task (`edr_daemon`) |
| `src/edr_ml.h` | Shared types: response actions, policy, prototypes |
| `src/edr_security.h` | Inline capability / syscall-filter helpers (no callers in the tree) |

There is no `edr.c`, `edr.h` or `edr_policy.h`. Most `edr_ml_*`, `edr_cluster_*`,
`edr_forensics_*` and `edr_correlate_*` prototypes in `edr_ml.h` have no definition:
the ML phase was never built.

---

## Where it hooks in

| Hook | Location | When |
|---|---|---|
| `edr_advanced_init()`, `edr_ti_init()`, `edr_response_init()` | `kernel.c` | Boot |
| `edr_daemon_start()` | `kernel.c` | Boot; then `supervisor_watch("edr_daemon", ...)`, task granted `CAP_UNKILLABLE` |
| `edr_behavioral_init()`, `edr_advanced_init_process()` | `process.c` | Every task creation |
| `edr_behavioral_check(current_task, syscall_num, arg1)` | `syscall_dispatch()`, `syscall.c` | Every syscall, after the per-task syscall filter |
| `edr_advanced_periodic_check()` | timer softirq, `interrupts.c` | Every 100 ticks (~1 s) |

In the dispatcher: if the check returns false the call is refused, counted in
`syscall_block_edr`, and audited once per task (`EDR blocked syscall %d for PID %d
(%s)`). If a response marked the calling task (`edr_kill_pending`), the dispatcher
exits it with `sys_exit(EDR_KILL_STATUS)` (137) before the syscall body runs.

---

## Behavioral signatures (`edr_behavioral.c`)

Rare syscalls: `SYS_SETUID`, `SYS_SETGID`, `SYS_SETEUID`, `SYS_SETEGID`.

| Signature | Trigger | Severity | Score | Response |
|---|---|---|---|---|
| `ROP_CHAIN` | >= 5 rare syscalls among the last 10, spanning < 10 ticks | CRITICAL | +500 | terminate (95) |
| `PRIVILEGE_ESCALATION` | setuid-family call while `EDR_FLAG_PRIVILEGE_CHANGE` is set or score > 1000 | CRITICAL | +750 | terminate (90) |
| `SYSCALL_FLOOD` | the whole 32-entry history inside < 2 ticks | WARNING | +200 | none |
| `ANOMALY` | each rare syscall +10; alert once score > 500 | WARNING | +10 | none |
| `SHELLCODE_EXEC` | placeholder, always false | — | — | — |
| `DATA_EXFILTRATION` | placeholder, always false | — | — | — |

The number in parentheses is the threat score passed to
`edr_response_should_execute()`; the response runs when it is >= the policy
threshold (80). Scores decay 5% per 100 ticks, per task.

Alert line: `[EDR %s] PID %d: %s (signature=%s, score=%d, alerts=%d)`. The console
line is rate-limited to one per task per 100 ticks (a higher severity always
prints); every alert is still counted.

Thresholds (`edr_behavioral.h`): `EDR_SYSCALL_HISTORY_SIZE 32`,
`EDR_ROP_CHAIN_THRESHOLD 5`, `EDR_RAPID_SYSCALL_THRESHOLD 32`,
`EDR_RAPID_SYSCALL_WINDOW_TICKS 2`, `EDR_EXFIL_SIZE_THRESHOLD 65536`.

---

## Advanced checks (`edr_advanced.c`)

| Check | State |
|---|---|
| File integrity (FIM) | SHA-256 baseline via `vfs_open`, one file re-hashed per periodic tick. The default list is empty (the `edr_fim_add_file()` calls are commented out), so boot prints `monitoring 0 files`. Tamper line: `[EDR ADVANCED] File tampering detected: %s` |
| RWX memory scan | Disabled (`edr_memory_check_rwx_regions()` returns 0); W^X is enforced by PAE/NX instead |
| C2 beaconing | `beacon_count >= EDR_C2_BEACON_THRESHOLD` (10) → block network, then terminate (85). Fed by `edr_network_track_connection()`, which has no callers |
| Ransomware | > `EDR_CRYPTO_THRESHOLD` (100) encryptions in `EDR_CRYPTO_HISTORY_SIZE` (10) s → terminate. Fed by `edr_crypto_track_operation()`, which has no callers |

Alert line: `[EDR ADVANCED] PID %d: %s (sig=%s, terminate=%d)`, rate-limited per task
at 50 ticks.

Thresholds (`edr_advanced.h`): `EDR_MEM_SCAN_PAGES 16`, `EDR_SHELLCODE_THRESHOLD 5`,
`EDR_MAX_CONNECTIONS 16`, `EDR_C2_BEACON_THRESHOLD 10`, `EDR_FIM_MAX_FILES 32`,
`EDR_CRYPTO_THRESHOLD 100`, `EDR_CRYPTO_HISTORY_SIZE 10`.

---

## Responses (`edr_response.c`)

Default policy: `auto_terminate=1`, `auto_quarantine=1`, `auto_block_network=1`,
`response_threshold=80`.

| Action | Behaviour |
|---|---|
| `RESPONSE_TERMINATE_PROCESS` | Validates `{pid, generation}` first; refuses `CAP_UNKILLABLE` targets (counted, not printed). The current task is only marked (`edr_kill_pending`); any other goes through `task_terminate_status()` with status 137, the same teardown as `kill` |
| `RESPONSE_ALERT_ADMIN` | Console line plus an audit record |
| `RESPONSE_BLOCK_NETWORK` | Stub: logs and audits, closes nothing |
| `RESPONSE_QUARANTINE_FILE` | `edr_response_quarantine_file()` canonicalizes and confines the target to `/quarantine`, but the mkdir/rename/chmod calls are stubs |
| `SUSPEND`, `ISOLATE`, `ROLLBACK`, `COLLECT_EVIDENCE` | Not implemented; return false |

Refusals are readable with `edr_response_get_refusals(&unkillable, &gone)`.

---

## Daemon (`edr_daemon.c`)

Kernel task at `PRIORITY_HIGH`, supervised, `CAP_UNKILLABLE`. Wakes every second,
scans all tasks every 500 ticks (5 s). A task is suspicious when its anomaly score is
> 300, it has raised any alert, it changed privilege to uid/euid 0, or its name starts
with `mal` (a demonstration heuristic). The threat score (0-100) is built from
anomaly score (<= 50), alert count (<= 30) and privilege change (20); at >= 80 the
daemon terminates (>= 90) or blocks network and alerts (>= 70).

The scan is silent unless it finds something. The 60 s report prints a full block
only when threats, responses or TI matches changed (and on the first report), one
line when only the scan count moved, and nothing otherwise.

---

## Threat intelligence (`edr_threat_intel.c`)

Tables of up to 256 SHA-256 hashes, 128 IPv4 addresses, 64 domains, all empty at
boot. `edr_ti_load_csv()`, `edr_ti_check_ip()` and `edr_ti_check_file_hash()` exist
but nothing calls them; the daemon only reads `edr_ti_get_stats()` for its report.

---

## Boot lines

```
[EDR FIM] Initialized (monitoring 0 files)
[EDR ADVANCED] Initialized (Phase 3: Memory, Network, FIM, Crypto)
[EDR TI] Initialized (max: 256 hashes, 128 IPs, 64 domains)
[EDR RESPONSE] Initialized
[EDR RESPONSE] Policy: terminate=1, quarantine=1, block_network=1, threshold=80
[EDR DAEMON] Initializing EDR daemon...
[EDR DAEMON] Created daemon process PID <n> with HIGH priority
[EDR DAEMON] EDR daemon started successfully
```

---

## Viewing state

`secstatus` (kernel shell, via `kshell`):

```
  Endpoint detection (EDR)
    Scans / threats ..... <n> scans, <n> threats, <n> responses
    Alerts .............. <n> behavioral (<n> unprinted), <n> advanced (<n> unprinted)
```

EDR audit records appear in `auditlog` (root, kernel shell).

---

## Changing behaviour

Edit the `#define`s in `edr_behavioral.h` / `edr_advanced.h`, the
`g_response_policy` initializer in `edr_response.c`, or `EDR_SCAN_INTERVAL_TICKS` in
`edr_daemon.c`, then rebuild. `edr_response_set_policy()` and
`edr_behavioral_set_enabled()` exist as kernel C API; nothing calls them.

---

## Harnesses

- `verify/verify-edr-alert-record.sh` — every alert is counted although the console
  line is rate-limited (`TINYOS_FAULT_INJECT`, `edr_alert_selftest()`).
- `verify/verify-edr-kill-reap.sh` — a task EDR kills while not running is reaped.
- `verify/verify-edr-pid.sh` — the daemon is found by pid and granted `CAP_UNKILLABLE`.
- `verify/verify-dispatch-block-quiet.sh` — a blocked task is audited once, not per call.
