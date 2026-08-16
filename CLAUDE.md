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
