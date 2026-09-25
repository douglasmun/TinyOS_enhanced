# TinyOS — project notes for Claude

Educational 32-bit (i386) Multiboot2 kernel in freestanding C + NASM. Single CPU,
interrupt-driven, round-robin scheduler with kernel threads and ring-3 user processes.
No kernel libc — only the kernel's own helpers (`util.c` memcpy/memset/strlen,
`kprintf`, etc.). Userspace has a tiny libc (`userspace/libc.{h,c}`, PR #26).

## Where the detail lives

This file is the always-loaded summary. Most designs here look arbitrary until you know
which failure produced them — read the relevant doc before changing an area.
`verify/CLAUDE.md` (harness rules) and `userspace/CLAUDE.md` (ring-3 shell) load when you
work in those directories.

| Topic | File |
|---|---|
| **Full text of every rule below, with the failure behind it** | `doc/RULES_THAT_BITE.md` |
| Ring-3 migration: every syscall's design rationale, PRs #43–#58, harness traps | `doc/RING3_MIGRATION.md` |
| Fixed kernel bugs worth remembering (ISR EAX clobber, exec triple-fault, sha256/PMM/COW faults) | `doc/KERNEL_BUGS.md` |
| Crypto invariants, ELF signing, what a harness must prove | `doc/CRYPTO_INVARIANTS.md` |
| `SYS_MSEAL` audit: the disproved latency hypothesis, the 16 kprintf sites | `doc/MSEAL_AUDIT.md` |
| Post-v2.2 roadmap with rationale | `doc/ROADMAP_NEXT.md` |
| Security mechanism reference (17 mechanisms) | `doc/SECURITY_HARDENING.md` |
| Latest audit: 16 findings, all fixed (PRs #103–#105) | `doc/SECURITY_AUDIT_2026-08.md` |
| Security history index | `doc/SECURITY_STATUS_COMPLETE.md`, `doc/MULTI_AGENT_SECURITY_AUDIT_2026.md` |
| RX path, counters, firewall/IDS vehicles | `doc/NETWORK_ISOLATION.md` |
| `knetd`, the supervisor, why the D1 parser move was withdrawn | `doc/NETDAEMON_DESIGN.md` |
| Firewall and IDS configuration | `doc/FIREWALL_AND_IDS_CONFIG.md` |
| Why the audit log is volatile and stays that way | `doc/AUDIT_LOG_PERSISTENCE.md` |
| Boot/login/shell/networking walkthrough | `doc/USER_GUIDE.md` |

## Build & run

- `make -j8 kernel.elf` — cross toolchain `i686-elf-gcc`, `nasm`. `-Werror` plus many extra
  warnings; **must stay warning-clean**.
- ISO: `cp kernel.elf iso/boot/kernel.elf && i686-elf-grub-mkrescue -o dist/tinyos.iso iso`
  (needs `xorriso`).
- Headless boot: `qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso
  -boot d -m 256M -netdev user,id=net0 -device e1000,netdev=net0 -serial file:LOG -display none`.
- First boot asks to set a root password, then login. Harnesses live in `verify/`
  (read `verify/CLAUDE.md` before writing or debugging one).

Build flags are all **explicitly named opt-outs, never defaults**:
`-DELF_PERMISSIVE_SIGNATURES` (warn-and-load unsigned binaries), `-DTINYOS_FAST_KDF` (lower
PBKDF2 iterations), `-DTINYOS_TRACE_SYSCALLS` (per-syscall trace),
`-DTINYOS_LEGACY_CRED_SYSCALLS` (ring-3 `SYS_CHANGE_PASSWORD`/`SYS_SWITCH_USER`, PR #55).
`-DTINYOS_FAULT_INJECT` is needed by several harnesses.

## Rules that bite

Condensed; full reasoning in `doc/RULES_THAT_BITE.md`. Harness names are in `verify/`.

**Output and logging**
- **No per-operation `kprintf` on a path ring 3 can reach** — kernel console and ring-3 shell
  share one serial stream. A syscall with no libc wrapper and no builtin is where this rots
  (`SYS_MSEAL` carried 16). Don't collapse `sys_mseal`'s two-pass walk. `verify-mseal-counters.sh`.
- **RX path: no per-packet `kprintf` at all** — count, don't print (counters show in
  `ifconfig`). Sweep the protocol files, not just the loops. Separate counters per attack
  signature, grouped by attacker position. Local-`dig`-driven prints in `dns.c` stay.
- **User-facing output goes through `stream_printf(get_current_streams())`**, not `kprintf`.

**Networking**
- **The RX parser runs in task context on `knetd`; never reach it from an ISR.** Copy the frame
  before RDT advances (else attacker-timed UAF); keep the boot DHCP loop's explicit
  `e1000_rx_softirq_run()`; ring overflow is drop-newest. `ifconfig` `irq-ctx` must read 0.
- **`rx_softirq_ring` is single-consumer (`knetd`).** `SYS_NETRX` pops `netd_ring`, never
  `rx_softirq_ring`. TCP is never routed to ring 3. Routing is gated on `netd_claimed` and
  must be releasable.
- **`cpl3` must read 0 — a standing invariant**, witnessed from `%cs`, never a software flag.
  `irq-ctx` and `cpl3` answer different questions.
- **The ring-3 parser move (D1) is WITHDRAWN** — read "D1 re-scoped" in
  `doc/NETDAEMON_DESIGN.md` before restarting it. Ring 0 consumes DNS/DHCP/ARP results, and an
  ICMP responder would need `SYS_NETTX`, whose `e1000_send()` does no source validation.
- **`E1000_UNLOCK()` does not re-enable interrupts on the IRQ11 path**, so
  `E1000_RX_PACKET_BUDGET` does not bound interrupt-off time. Don't trust those comments.
- **e1000 DMA buffers are a guarded PMM region**, allocated after `pae_init()`.
  `TDLEN`/`RDLEN` come from the element count, never `sizeof(ring)` (it's a pointer now).
- **`knetd` is supervised.** `supervisor_run_once()` uses `task_get_validated(pid, generation)`
  (slots are recycled); the rate limit lives inside `supervisor_restart()`.

**Tasks and memory**
- **`task_create_kernel()` does not enqueue** — call `scheduler_add_task()`. It grants
  `CAP_ALL` incl. `CAP_UNKILLABLE`. `task_exit()` is inert for scheduler-run tasks — use
  `task_terminate(pid)`. The reaper removes from the ready queue **before**
  `task_free_resources()`.
- **Teardown frees only what a `task_t` field names.** ELF image frames are tracked in
  `image_pages_phys[]`, registered only after the last failure return (earlier = double-free).
  Oversize images are refused. `verify-exec-frame-leak.sh` asserts exact equality.
- **Freeing a guard page requires restoring its mapping first**, or the frame is poisoned for
  whoever allocates it next.
- **Allocate before you disturb an array** — `editor_insert_row` allocates, then shifts.
- **`pmm_alloc()` does not zero.** Env/alias getters copy out under the lock;
  `env_refresh_identity()` runs from both `su` branches.
- **Stack: the kernel shell and the whole signed-`exec` chain run on one 128 KB task stack**
  (`KERNEL_TASK_STACK_PAGES = 32` in `process.h`; 64 KB triple-faulted). Keep big locals off it —
  `exec_buffer` and `allocated_frames[4096]` are `static` for that reason.
- **Don't "simplify":** the user-ESP alignment bias in `process.c`, the page-table COW in
  `pae_map_page_into`, the interrupt masking around PBKDF2 / sha256 / `csprng_reseed`.

**Syscalls and permissions**
- **`MAX_SYSCALL_NUM` must cover the highest syscall number** — bump it when adding one.
- **Making a path reachable from ring 3 turns latent bugs into corruption primitives** (PRs
  #45, #47, #54, #55). Audit the path in the same PR that exposes it.
- **Enforce permissions in the ramfs primitive, not the command** (`ramfs_check_permission()`).
  `SYS_CHMOD` inherits the refusal — don't add a second uid check at the boundary.
- **Check sentinel collisions before returning an errno** — `-EPERM` is `-1`, already
  `ramfs_chmod`'s "not found". Use a distinct constant.
- **Process visibility is own-only; root sees all** — use `task_visible_to_current()`. Totals
  count only printed rows. A hidden PID/socket is nonexistent / `-EBADF`, never `-EPERM`.
- **`sys_psinfo` walks raw slots** (`task_get_slot`) and reads fields in the same critical
  section as the visibility check. **`tcp_socket()` stamps `owner_uid` on both allocation
  paths**; `tcp_recv()` takes `TCP_LOCK` before reading ring state.
- **Syscall gating polarity is per-syscall and deliberate** — ungated `SYS_ENV`/`SYS_TIME`,
  ownership-gated `SYS_TCPSOCK`/`SYS_CHMOD`, euid-gated `SYS_NETRX`/`SYS_NETTX`.

## Current state

Ring-3 shell is the default login shell (see `userspace/CLAUDE.md`). Roadmap items 1–4 are
closed; `su` and `edit` stay kernel-shell only by decision. Task-slot exhaustion is closed
(per-uid cap + root reserve, both `-EAGAIN`). `kprintf`→`stream_printf` conversion is finished.
IDS scans every inbound payload; `secstatus` reports a match count; the login-spray detector
counts distinct usernames and never denies.

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
