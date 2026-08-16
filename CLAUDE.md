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
- **Making a path reachable from ring 3 turns latent bugs into corruption primitives.**
  This recurred in PRs #45, #47, #54, #55 — every time, dead or kernel-only code carried
  serious bugs. Audit the path in the same PR that exposes it.

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
fallback (`kshell` hands over; `exit` logs out). It has ~16 builtins against the kernel
shell's ~70 — redirection, pipelines, and the credential commands have landed; the
introspection and machine-state commands are still kernel-shell only.

Roadmap items 1–3 (background jobs, SYS_SPAWN + pipes, FAT32 write) are **done**. Item 4
(userspace shell) is in progress. `fork()` was skipped deliberately (PAE, no COW pages).

**Task-slot exhaustion is closed**: a per-uid live-task cap (`USER_MAX_CONCURRENT_TASKS`)
plus a root slot reserve (`TASK_ROOT_RESERVED_SLOTS`) in `task_create_user_argv`, checked
**before** the rate limiter and charged to the **creator's** uid (the child's is not set
until the caller overwrites it after the call). Both limiters return `-EAGAIN`, so only
the printed message identifies which one refused — see `doc/RING3_MIGRATION.md` and
`verify-slotcap.sh`. Fixing this also uncovered a pre-existing refill bug in the rate
limiter itself (`doc/KERNEL_BUGS.md`).

Open, in rough priority order:

- **`ps`/`kill`/`top` in ring 3** — the next migration step. `shell_monitor.c` is already
  stream-routed, so this is a **policy** question (what may an unprivileged process see
  and signal), not plumbing. Do this before `shell_system.c`, which needs ~222 `kprintf`
  conversions.
- **AUDIT-8E IDS-not-wired gap.**
- **`ps`/`kill`/`top` visibility policy** — undecided: may an unprivileged user see all
  processes (leaks what root runs) or only their own? Needed before that migration.

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
