# verify/ — harness rules

Every rule here was paid for by a harness that reported FAIL on a correct kernel, or PASS on
a broken one. Full reasoning: `doc/RULES_THAT_BITE.md` and `doc/RING3_MIGRATION.md`.

## Serial and typing

- **No log pattern may be anchored on the shell prompt alone.** The EDR daemon's periodic
  multi-line burst tears the `D:/ $ ` line (no trailing newline) at an arbitrary character.
  Filters that drop the echo and guards that require it both fail *deterministically* on a
  correct kernel. Use `verify/edr-rejoin.sh` (tested by `verify/edr-rejoin-test.sh`) — never a
  hand-rolled splice; all five earlier copies had defects. Filter EDR spam with `grep -v Suspicious`.
- **Don't echo-verify each character.** The ring-3 shell echoes the whole line *after*
  `readline()` returns (`src/stdio.c:336`, `userspace/shell.c:2035`); a per-char wait blocks
  and a resend loop types `kkkkshell`. Only the kernel shell echoes per keystroke. The typist
  is not flaky — ~45 boots, zero dropped keystrokes; every failure was a harness defect.
- **A harness must not delete its own evidence.** Never `rm -rf` a `mktemp -d` holding
  `SERIAL` from an EXIT trap — it fires on failure too. Use `verify/preserve-serial.sh`
  (tests: `verify/preserve-serial-test.sh`), keyed on **exit status, not a parsed verdict**.
  Capture `rc=$?` as the trap's **first** action; any earlier command resets `$?`.

## Running

- `verify/run-all.sh` is the batch runner (~2.7 h serially — nightly/manual, not a PR gate).
- Harnesses needing `-DTINYOS_FAULT_INJECT` must `make clean` on exit — the flag isn't in the
  dependency graph, so its objects break the other harnesses at link time.
- **A harness never run end to end reports PASS and proves nothing** — run new ones against
  the **unfixed** tree.

## Designing assertions

- **Every exclusion needs a positive control.** A mechanism that refuses everything, or a
  counter that increments on every frame, satisfies the rejection half alone.
- **Counter harnesses need a selectivity leg** — a well-formed frame matching no connection
  must land on `no-conn`, not `malformed`.
- **Ownership harnesses need a live *foreign* object.** `verify-netd-boundary.sh`'s root pass
  leaks a socket on purpose — don't "clean up" that leak.
- **Gating polarity inverts the assertion.** Ungated syscalls (`SYS_ENV`, `SYS_TIME`): an
  unprivileged `-EPERM` is the bug. Ownership-gated (`SYS_TCPSOCK`, `SYS_CHMOD`): must succeed
  on the caller's own object. euid-gated (`SYS_NETRX`/`SYS_NETTX`). Measure new legs as **non-root**.
- **Witness the symptom, not a proxy.** `open(O_TRUNC)` is witnessed by `stat` (size), never
  `cat` — a `cat` harness passed with the fix removed.
- **Injected frames must clear three gates before any counter**, and all fail as delta 0
  (including the positive control): `handle_ip()`'s address gate (the guest's self-assigned
  `169.254.x.y` on the mcast netdev, not `10.0.2.15`), `is_bogon_ip()` (use TEST-NET-3, never
  RFC1918), and the firewall's default DENY ALL. `ifconfig`'s `RX ring:` vs `RX proto-ring:`
  localises the drop. UDP 68→67 bypasses `match_rule()` — to test a **rule**, use ICMP.
- `verify-netd-arbitration.sh`'s `e1000_rx_dequeue` guard is load-bearing — no leg drives the
  syscall side, so nothing else catches `SYS_NETRX` being pointed back at `rx_softirq_ring`.
- **Kernel tasks are `CAP_UNKILLABLE`** — a test that `kill`s one grades a daemon that never died.
- `verify-supervisor.sh`: step 3 asserts the RX counter **rises**, 5c that it is **pinned**
  — same counter, opposite directions; don't reconcile them.
