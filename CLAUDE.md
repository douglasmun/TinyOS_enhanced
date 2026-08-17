# TinyOS — project notes for Claude

Educational 32-bit (i386) Multiboot2 kernel in freestanding C + NASM. Single CPU,
interrupt-driven, round-robin scheduler with kernel threads and ring-3 user processes.
No kernel libc — only the kernel's own helpers (`util.c` memcpy/memset/strlen,
`kprintf`, etc.). Userspace has a tiny libc (`userspace/libc.{h,c}`, PR #26).

## Where the detail lives

This file is the always-loaded summary. The reasoning behind each area is in `doc/`
— read the relevant one before changing that area, because most of these designs
look arbitrary until you know which failure produced them.

| Topic | File |
|---|---|
| Ring-3 migration: every syscall's design rationale, PRs #43–#58, harness traps | `doc/RING3_MIGRATION.md` |
| Fixed kernel bugs worth remembering (ISR EAX clobber, exec triple-fault, sha256/PMM/COW faults) | `doc/KERNEL_BUGS.md` |
| Crypto invariants, ELF signing, what a harness must prove | `doc/CRYPTO_INVARIANTS.md` |
| Post-v2.2 roadmap with rationale | `doc/ROADMAP_NEXT.md` |
| Security mechanism reference (17 mechanisms) | `doc/SECURITY_HARDENING.md` |
| Security history index / latest audit | `doc/SECURITY_STATUS_COMPLETE.md`, `doc/MULTI_AGENT_SECURITY_AUDIT_2026.md` |
| Boot/login/shell/networking walkthrough | `doc/USER_GUIDE.md` |

## Build & run

- `make -j8 kernel.elf` — cross toolchain `i686-elf-gcc`, `nasm`. Compiles with
  `-Werror` plus many extra warnings; **must stay warning-clean**.
- ISO: `cp kernel.elf iso/boot/kernel.elf && i686-elf-grub-mkrescue -o dist/tinyos.iso iso`
  (needs `xorriso`; `brew install xorriso`).
- Headless boot: `qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso
  -boot d -m 256M -netdev user,id=net0 -device e1000,netdev=net0 -serial file:LOG -display none`.
- The EDR daemon spams `[EDR ADVANCED] ... Suspicious memory` on serial — filter with
  `grep -v Suspicious`.
- First boot asks to set a root password, then login. Scripted keystrokes drop under
  TCG load — echo-verify each char before advancing.

Build flags are all **explicitly named opt-outs, never defaults**:
`-DELF_PERMISSIVE_SIGNATURES` (warn-and-load unsigned binaries),
`-DTINYOS_FAST_KDF` (lower PBKDF2 iterations), `-DTINYOS_TRACE_SYSCALLS` (per-syscall
trace), `-DTINYOS_LEGACY_CRED_SYSCALLS` (re-enable ring-3 dispatch of
`SYS_CHANGE_PASSWORD`/`SYS_SWITCH_USER` — see `doc/RING3_MIGRATION.md`, PR #55).

## Rules that bite

- **Don't add per-operation `kprintf` to a path ring 3 can reach.** With the shell at
  ring 3 the kernel console and the user's own output are the same serial stream, so a
  single typed command buries itself in kernel chatter. `-DTINYOS_TRACE_SYSCALLS` is off
  by default and **must stay that way** (`readline()` costs one syscall per keystroke).
  Same for routine FS errors: a failed `rmdir` is a userspace error the caller already
  reports on its own stream.
- **The RX path is stricter still: no per-packet `kprintf` at all.** Those sites need no
  local account — any host on the segment drives them, from the ISR, before the firewall.
  Five such prints were replaced by counters surfaced in `ifconfig` (PR: `net_drop_runt`,
  `net_drop_ethertype`, `rx_drop_errors`, `rx_drop_badlen`). Count, don't print, and don't
  reach for `stream_printf` here either: interrupt context has no current user stream.
  Harness: `verify-rxdrop-counters.sh`; rationale in `doc/NETWORK_ISOLATION.md`.
  **That sweep covered the RX loops and so missed `icmp.c`**, which had three more
  (`icmp_echo_replies_rx`, `icmp_echo_requests_rx`, `icmp_replies_dropped` now).
  The echo-*reply* one was unbounded — its branch returns before the rate limiter,
  and the identifier it gates on is cleartext in every outbound ping, so an on-path
  attacker drove one line per packet. When looking for this class of bug, sweep the
  protocol files too, not just the loops. Harness: `verify-icmp-counters.sh`.
  **And that sweep in turn only fixed the file it was looking at** —
  `handle_dns_response()` had **20** more, now six counters via `dns_get_rx_stats()`.
  Worse than the ICMP case: the sites are the *drop* branches (source-IP, TID,
  question-name), so a spraying attacker bought more console lines than a legitimate
  response did, and the question branch printed `question_domain` — the attacker's
  own bytes — onto a console the ring-3 shell shares with the user. The three attack
  signatures stay **separate** counters; one "dropped" total hides which attack is
  underway. `dns.c`'s other 23 prints stay: they are on `send_dns_query` /
  `domain_to_dns_label`, driven by a local `dig`/`curl` and so bounded by local
  action — the rule is about what a *remote* host drives, and a file-wide grep here
  fails on correct code. Harness: `verify-dns-rx-counters.sh` (needs
  `-DTINYOS_FAULT_INJECT` for `dnsforge`), whose `valid` leg is the positive control
  — without it every drop leg passes against a forger emitting garbage.
- **`E1000_UNLOCK()` does not re-enable interrupts on the IRQ11 path.**
  `critical_section_exit()` only touches `IF` when `__interrupt_context_depth == 0`, and
  that clause is deliberate (a `popfl` mid-ISR would corrupt the preempted thread's
  flags). So `e1000_poll_rx`'s mid-loop unlocks and its post-budget "process with
  interrupts RE-ENABLED" block are depth decrements only, and `E1000_RX_PACKET_BUDGET`
  does not bound interrupt-off time the way its comments claim. Don't trust those
  comments; see `doc/NETWORK_ISOLATION.md`.
- **The RX path parses in *task* context, on `knetd` — keep it that way.** The ISR only
  copies each frame into `rx_softirq_ring` and returns; `e1000_rx_softirq_run()` drains
  it and calls `handle_packet()` with `IF=1`. Never call `handle_packet()` (or anything
  that reaches the parser) from an ISR — that is the ~8,350-line surface running with
  interrupts disabled at a remote host's chosen rate. Three things easy to undo: the
  frame **must be copied** before RDT is advanced (the NIC refills that descriptor, so a
  retained `rx_bufs[]` pointer is an attacker-timed UAF); the boot DHCP loop in
  `kernel.c` **must keep its explicit `e1000_rx_softirq_run()` call**, because `knetd`
  does not exist yet there (a "did it run" flag was tried and reverted — it masks a
  stalled `knetd`); and ring overflow is **drop-newest**, counted, because drop-oldest
  lets a fast sender evict frames already accepted. `ifconfig`'s `irq-ctx` count must
  read **0**. Harness: `verify-rx-thread-context.sh`.
- **`rx_softirq_ring` is single-consumer, and `knetd` is that consumer.** `SYS_NETRX`
  (`e1000_rx_dequeue`) must pop **`netd_ring`**, never `rx_softirq_ring` — pointing it
  back at the latter restores a race where each frame goes to whichever consumer reaches
  the tail first, so a live ring-3 netd steals TCP segments from the kernel parser at
  random (intermittent, load-dependent, presents as "networking is flaky"). PR B was safe
  only because `netprobe` runs on demand and never overlaps `knetd`. `knetd` now
  classifies: ICMP/UDP to `netd_ring`, everything else parsed in place — one `if`/`else`,
  so no frame is delivered twice or dropped between paths. TCP is **never** routed
  (`TCP_LOCK` is `cli`; ring 3 has IOPL=0). Routing is gated on `netd_claimed`, inert
  until claimed and reversible on release — the supervisor needs the release, or a dead
  netd takes ICMP/UDP down permanently. **The `e1000_rx_dequeue` guard in the harness is
  load-bearing: no leg drives the syscall side, so nothing else catches that edit.**
  Harness: `verify-netd-arbitration.sh` (needs `-DTINYOS_FAULT_INJECT` for `netdclaim`).
- **`irq-ctx` and `cpl3` are different questions — don't let one stand in for the
  other.** `knetd` runs with `IF=1` *and* at CPL 0, so a kernel where nothing has moved
  to ring 3 still reports a perfectly healthy `RX parsed: N thread-ctx, 0 irq-ctx`.
  Interrupt state and privilege level are independent axes. `handle_packet()` therefore
  also witnesses the ring from `%cs` (`RX ring: N cpl0, M cpl3`), read from the hardware
  and **never from a software flag** — a flag records what the code believes about
  itself, and the point of the counter is to catch a build whose belief is wrong.
  `cpl3` must read **0** — and that is now a **standing invariant, not a baseline
  awaiting inversion**. The parser move was withdrawn 2026-08-17 (see below), so there
  is no flag to flip: nonzero `cpl3` on any protocol means the witness is broken or
  something moved that must not have. `handle_ip()`'s L4 switch also witnesses per
  protocol (`RX proto-ring: icmp c/c, udp c/c, tcp c/c`), counted **before** any early
  return, which stays useful for exactly that reason. DNS and DHCP are not separable
  here: both ride UDP, and the witness sits at the dispatch switch, so splitting them
  means instrumenting the port demux in `handle_udp()` — a different seam. Harness:
  `verify-netd-ring3.sh`; rationale in `doc/NETDAEMON_DESIGN.md`.
- **The ring-3 parser move (D1) is WITHDRAWN — don't restart it without reading
  "D1 re-scoped" in `doc/NETDAEMON_DESIGN.md`.** The plan asked "can this protocol
  move?" (privileged instructions, TX path, stack budget) and never asked **"what does
  moving buy?"** The criterion that decides it: *does ring 0 consume a result this
  parser produces, and act on it?* DNS (`last_resolved_ip` → `curl`/`dig`), DHCP (all
  four interface globals → routing, ARP, **TCP ISN generation**) and ARP (`arp_cache` →
  every TX's destination MAC) all do, so moving them relocates the parse and hands the
  trust straight back through a syscall a compromised daemon can call at will. Kernel
  re-validation doesn't rescue DNS: question-name validation walks **compressed labels**
  and the A-record search walks the answer RRs, so validating honestly means ring 0
  re-executes essentially the whole parser — ring 3 would do a `memcpy`. ICMP's inbound
  half is the one honest candidate (it writes only counters); its blocker is the
  *reply* path, not a trusted result. Four PRs of prerequisites (#76–#80) survived
  because none of them depended on the answer — they are all still correct and worth
  keeping.
- **Four traps around kernel task lifetime**, each of which reads as healthy when
  wrong. `task_create_kernel()` allocates but does **not** enqueue — every caller needs
  `scheduler_add_task()`, or the task is created, listed by `ps`, counted by every
  status surface, and never runs one instruction. It grants `CAP_ALL` (`0xFFFFFFFF`),
  which **includes `CAP_UNKILLABLE`** — so every kernel task is unkillable, the explicit
  `|= CAP_UNKILLABLE` grants in `kernel.c` are no-ops, and a test that plans to `kill`
  one is grading a daemon that never died. And `task_exit()` is **inert** for
  scheduler-run tasks (it reads `process.c`'s `current_task`, set only by
  `task_switch_to`) — use `task_terminate(pid)`, capturing the pid first. Fourth: the
  post-context-switch reaper must `scheduler_remove_task_locked()` **before**
  `task_free_resources()`. A task that terminates *itself* defers the free to the reaper
  and is still linked in the ready queue; freeing the slot left a self-linked corpse
  there, and `scheduler_get_next_task()`'s later reject-and-remove hit the
  `task->next == task` case, which nulled head **and** tail and discarded every live
  task — panic "All tasks terminated" with five tasks alive. Invariant: *a freed slot is
  never in the ready queue*. Found by the supervisor give-up control, not by anything
  that existed before it.
- **Freeing a guard page requires restoring its mapping first.** They are
  identity-mapped **not present** in the kernel identity map every address space shares,
  so `pmm_free` without re-mapping poisons that frame permanently and the #PF lands on
  whoever `pmm_alloc()`s it next — nowhere near the task that died. The boot-time "no
  holes" check can't catch it (runtime hole). User tasks have one too.
- **`knetd` is supervised; the supervisor is `CAP_UNKILLABLE` and `knetd` is not.**
  `supervisor_run_once()` must use `task_get_validated(pid, generation)` — slots are
  recycled, so a bare `task_get()` can match a *different* task in the same slot and
  make a dead daemon look alive. The rate limit lives **inside** `supervisor_restart()`
  so no second restart path skips it. Its give-up branch **is** now exercised
  (`verify-supervisor.sh` step 5): `gave-up` rises, the line prints, and — the only
  independent part — a further injection parses **zero** frames, so the daemon provably
  stays dead. Step 5c asserts the RX counter is **pinned** while step 3 asserts it
  **rises**: same counter, opposite directions, don't reconcile them. The deaths come
  from `killknetd 8`, a countdown each restarted `knetd` decrements, because typing 8
  commands under TCG misses the 10 s window and missing it fails **silently** — a
  rolled-forward window reports `gave-up 0`, which is what a *broken* limiter reports
  too. Harness: `verify-supervisor.sh` (needs
  `-DTINYOS_FAULT_INJECT`, and `make clean`s on exit — that flag is not in the
  dependency graph, so its objects break the *other* harnesses at link time).
  Rationale in `doc/NETDAEMON_DESIGN.md`.
- **The e1000 DMA buffers are a guarded PMM region, not `.bss`.**
  `e1000_dma_region_init()` carves 38 contiguous pages with an **unmapped guard page at
  each end**; `rx_bufs/tx_bufs/rx_ring/tx_ring` are pointers into it. Three things to
  know before touching it: allocation **must stay after `pae_init()`**, whose identity-map
  sweep panics on any not-present page, so unmapping guards earlier is a boot panic;
  `TDLEN`/`RDLEN` must be computed from the **element count**, never `sizeof(ring)` —
  the rings are pointers now, so `sizeof` is 4 and the NIC would be told its ring is one
  dword long (a clean `-Werror` build, caught only by clang-tidy); and raising
  `NUM_RX_DESC`/`RX_BUF_SIZE` grows the payload, which the init-time bounds check
  catches. Guard pages do **not** contain a malicious bus master — no IOMMU does that
  here; they turn our own overruns into faults. Harness: `verify-dma-guard.sh`.
- **Route user-facing output through `stream_printf(get_current_streams())`**, not
  `kprintf` — the latter goes to the kernel console, which a shell session doesn't show.
- **`MAX_SYSCALL_NUM` must cover the highest syscall number**, not the highest in its own
  comment block. It sat at 16 while `SYS_SLEEP` (17) and `SYS_WAITPID` (18) had working
  dispatcher cases, so the range check silently rejected both. Bump it when adding syscalls.
- **Keep big locals off the kernel task stack.** See stack budgets below.
- **Don't "simplify" these three:** the user-ESP alignment bias in `process.c`, the
  page-table copy-on-write in `pae_map_page_into`, and the interrupt masking around
  PBKDF2 / sha256 / `csprng_reseed`. Each is load-bearing; `doc/KERNEL_BUGS.md` and
  `doc/CRYPTO_INVARIANTS.md` say what breaks.
- **Process visibility is own-only; root sees all.** `task_visible_to_current()` in
  `shell_monitor.c` is the single predicate — use it for any new command that lists
  tasks, rather than writing the uid check again. Two corollaries that are easy to
  miss: totals must count only the rows actually printed (a raw total states how many
  processes are being withheld), and a filtered-out PID must be reported as
  **nonexistent**, never "permission denied" — `cmd_kill` and `sys_waitpid` both do
  this, so a user cannot enumerate live PIDs through the error message.
- **Making a path reachable from ring 3 turns latent bugs into corruption primitives.**
  This recurred in PRs #45, #47, #54, #55 — every time, dead or kernel-only code carried
  serious bugs. Audit the path in the same PR that exposes it.
- **Enforce permissions in the ramfs primitive, not the command.** `ramfs_chmod` had no
  ownership check, so any user — `kshell` is ungated on purpose — could `chmod 666` a
  root-owned file and read it. Every other ramfs mutation routes through
  `ramfs_check_permission()`; that is what made this one exploitable, since the mode
  bits are only load-bearing *because* the rest is enforced. Putting the check in
  `cmd_chmod` would have left the primitive open to the next caller (a future
  `SYS_CHMOD`). Boot-time callers pass because `ramfs_get_current_credentials()`
  returns uid 0 with no current task. Harness: `verify-chmod-owner.sh`.
- **Check sentinel collisions before returning an errno.** `EPERM` is 1, so `-EPERM`
  is `-1` — already `ramfs_chmod`'s "file not found". Returning it made the refusal
  print "No such file or directory" and the new branch dead code, with the kernel
  behaving correctly the whole time. Use a distinct constant (`RAMFS_CHMOD_EPERM`).

## Stack budgets (important)

The kernel shell runs as a kernel task, not on the 256 KB boot stack, and the entire
`exec` chain — `cmd_exec → elf_load_process → ecdsa_verify → task_create_user → PAE
page-table setup` — runs on that one kernel stack. It is **128 KB**
(`KERNEL_TASK_STACK_PAGES = 32` in `process.h`); at 64 KB the signed-`exec` chain
overflowed into the guard page → #PF → #DF → **triple fault**.

Keep big locals off the task stack regardless: an earlier related overflow silently
corrupted the signature hash until `exec_buffer` and `elf_load_process`'s
`allocated_frames[4096]` were made `static`.

## Current state

The **ring-3 shell is the default login shell** (PR #51), with the kernel shell as a
fallback (`kshell` hands over; `exit` logs out). It has ~25 builtins against the kernel
shell's ~70 — redirection, pipelines, the credential commands, `ps`/`kill`/`top` and now
`cp`/`mv`/`touch` have landed; the machine-state commands (`pae`, `mem`, `wxaudit`,
`auditlog`, the networking and security tooling) are still kernel-shell only, and ~20 of
those stay that way by design (PR #58 gated them: together they are an ASLR defeat).

**`open(O_TRUNC)` did nothing on the RAM disk** until `ramfs_vfs_open` was wired to
`ramfs_truncate` — `ramfs_open` takes a `uint8_t` of `RAMFS_FLAG_*` and cannot represent
`VFS_O_TRUNC` (0x0200), so the flag was validated by `sys_open`, passed down, and then
dropped. Since `ramfs_write` only ever **grows** `node->size`, every short rewrite left
the old tail live inside the file — silent corruption in the shipping `write` builtin,
not a missing feature. The trap for anyone testing this: **`cat` cannot see it** (it
prints `BBB` either way); only `stat` can, because the symptom is the size (31 vs 4).
A `cat`-based harness passed against a build with the fix removed. Harness:
`verify-ring3-fileops.sh`, which asserts on `stat`.

Roadmap items 1–3 (background jobs, SYS_SPAWN + pipes, FAT32 write) are **done**. Item 4
(userspace shell) is in progress. `fork()` was skipped deliberately (PAE, no COW pages).

**Task-slot exhaustion is closed**: a per-uid live-task cap (`USER_MAX_CONCURRENT_TASKS`)
plus a root slot reserve (`TASK_ROOT_RESERVED_SLOTS`) in `task_create_user_argv`, checked
**before** the rate limiter and charged to the **creator's** uid (the child's is not set
until the caller overwrites it after the call). Both limiters return `-EAGAIN`, so only
the printed message identifies which one refused — see `doc/RING3_MIGRATION.md` and
`verify-slotcap.sh`. Fixing this also uncovered a pre-existing refill bug in the rate
limiter itself (`doc/KERNEL_BUGS.md`).

**`ps`/`kill`/`top` now work from ring 3** via `SYS_PSINFO` (33) / `SYS_KILL` (34), which
carry the listing across the ring boundary with `task_visible_to_current()` applied
kernel-side. Two invariants that are easy to undo: `sys_psinfo` walks **raw task slots**
(`task_get_slot`), not `task_get_all`'s compacted output, because it drops the lock
between records and a compacted index skips a task when an earlier one exits; and the
visibility check must read the fields in the **same** critical section that passed it,
or a reused slot copies another user's name out. Harness: `verify-ring3-ps.sh`.

**The socket API crosses the boundary as two syscalls with subcommands**, not
twenty-three entry points: `SYS_NETSTAT` (37, read-only queries) and `SYS_TCPSOCK`
(38, the data path — socket/connect/send/recv/close). Both are **ownership-gated,
the opposite polarity to `SYS_NETRX`/`SYS_NETTX`**, which are euid-gated because raw
frames are the whole segment's traffic. An unprivileged caller *must* succeed here;
a `-EPERM` is the bug. Copying an assertion between the two halves inverts it — that
has nearly happened three times, so the shared harness header says so explicitly.
Four things not to undo: the ownership check lives at the **syscall boundary**, not
in the TCP primitives (the one place the `ramfs_chmod` "enforce in the primitive"
rule inverts — `curl`/`tcp_tick`/the IRQ receiver have no current task to check);
`tcp_socket()` stamps `owner_uid` on **both** allocation paths, the fast scan and the
TIME_WAIT eviction retry, since `memset` zeroes it and uid 0 is root; `tcp_recv()`
takes `TCP_LOCK` **before** reading `in_use`/`state`/`rx_head`/`rx_tail`, because
`tcp_rx_available()` subtracts a head/tail pair the IRQ path mutates and a torn read
drives the copy loop; and a socket the caller cannot see is **`-EBADF`, never
`-EPERM`**, or the errno enumerates the table. Harness: `verify-netd-boundary.sh`.
**Its ownership assertion only works because the root pass leaks a socket** — a probe
that merely checks "I can see my own socket" passes against a completely inert
filter, since the caller's is the only socket in the table at that moment. Exclusion
needs a live *foreign* socket to not see. Don't "clean up" that leak.

**AUDIT-8E is closed for the network half.** `ids_inspect_payload()` (`ids.c`, called at
the end of `ids_analyze_packet`) scans every inbound IP payload against the signature
table, and `secstatus` reports a **match count** beside the signature count — a loaded
count alone is what let the gap read as protection. Two things not to undo: the bounds
check rejects `pattern_len > len` **before** the `len - pattern_len` subtraction (both
`size_t`; the wrap is a remote OOB read), and the inner loop **breaks on first match**
so one NOP sled cannot flood the alert ring. Harness: `verify-ids-signature.sh`.
**The host-based stubs are resolved** — one implemented, two deleted.
`ids_register_login_failure()` counts **distinct usernames** per window (a horizontal
spray; `user.c`'s per-account lockout structurally cannot see it) and is called from
**both** failure branches of `user_authenticate_for`, including user-not-found. Four
things not to undo: the threshold is `IDS_SPRAY_THRESHOLD` (3), **not** the
network-side `IDS_BRUTEFORCE_THRESHOLD` (5) — `shell_login_prompt()` halts after
`max_attempts = 3`, so 5 is unreachable from the only path that calls it; it alerts
and never denies (denying on username diversity is a self-inflicted console DoS); it
prints via `kprintf` because its own `AUDIT_WARN` never reaches serial; and
`ids_analyze_syscall`/`ids_check_fork_bomb` were **removed, not implemented** —
`edr_behavioral_check()` and the per-uid task cap already enforce those. Harness:
`verify-ids-spray.sh`; rationale in `doc/FIREWALL_AND_IDS_CONFIG.md`.

`shell_system.c` is **converted** (~220 sites → `stream_printf`), so `mem > f` now
writes the report to `f` instead of printing it to the console and leaving `f` empty.
`cmd_shutdown`/`cmd_reboot`'s banners deliberately stay on `kprintf` — each is
commented in place; don't "finish the job" on them. `env_list`/`alias_list`
moved too, and their locking became per-slot because `stream_printf` can reach
`ramfs_write`, which must not run with interrupts masked. Harness:
`verify-sysredirect.sh`; rationale in `doc/RING3_MIGRATION.md`.

`security_tests.c` is **converted** (161 sites) — the last console-only block, so
`cmd_sectest`'s banner now follows its output and **no console-only blocks remain**.
Two things easy to undo: the suite's report comes from **three** files, since
`scheduler_stats()` (scheduler.c) and `arp_security_self_test()` (net.c) have this
suite as their only caller — leaving either on `kprintf` drops 17 lines of results on
the console while the report still looks complete; and `scheduler_stats()` printed
**inside** its critical section, so it now snapshots under the lock and prints after
(the `env.c` pattern), a redirected stream reaching `ramfs_write`. Harness:
`verify-sectest-redirect.sh`.

## Not compiled (don't audit/fix)

`kernel_old.c`, `keyboard_old.c`, `tls13_demo.c`, `secure_delete.c` are not in the
build. `lib/python3.12/` is a vendored venv, not project code. `kernel_old.c` and
`keyboard_old.c` were accidentally committed to the public repo and have since been
untracked + gitignored (removed from GitHub; kept on disk only).

## Published

This repo is PUBLISHED at https://github.com/douglasmun/TinyOS_enhanced (public).
Some local-only branches/commits must never be pushed; the publish allow-list and the
reasons are tracked in the private publish notes (memory `tinyos-publish-setup`), not
here. `publish.sh` (gitignored) and the push workflow are in memory
`publish-push-gotchas`. PRs land as **merge commits** — do not amend or force-push main.

Demo ISO: the signed `v2.4` GitHub Release asset, mirrored to `web/tinyos.iso` and the
`gh-pages` branch — see `web/README.md`, and note those are four separate artifacts that
must be updated together.

Networking: NAT (10.0.2.x) works end-to-end; bridged 192.168.0.x is impossible on this
Mac (Wi-Fi can't be vmnet-bridged) — see memory `qemu-networking-wifi-limit`.
