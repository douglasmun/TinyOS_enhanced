# TinyOS — project notes for Claude

Educational 32-bit (i386) Multiboot2 kernel in freestanding C + NASM. Single CPU,
interrupt-driven, round-robin scheduler with kernel threads and ring-3 user processes.
No libc — only the kernel's own helpers (`util.c` memcpy/memset/strlen, `kprintf`, etc.).

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

## Stack budgets (important)

The shell runs as a **kernel task** (not on the 256 KB boot stack), and the entire
`exec` chain — `cmd_exec → elf_load_process → ecdsa_verify → task_create_user → PAE
page-table setup` — runs on that one kernel stack. The stack is now **128 KB**
(`KERNEL_TASK_STACK_PAGES = 32` in `process.h`); it was 64 KB, which the full
signed-`exec` chain overflowed into the guard page → #PF → #DF → **triple fault** (the
long-standing "`exec /hello.elf` triple-faults in ENFORCE mode" bug — see "ELF code
signing" below for the full root cause). Keep big locals off the task stack regardless:
an earlier related overflow silently corrupted the signature hash until `exec_buffer`
and `elf_load_process`'s `allocated_frames[4096]` were made `static`. ECDSA P-256 is
bit-serial and slow under QEMU/TCG, but that is a speed cost, **not** a correctness or
fault issue — the verify completes and passes.

## Security work

All security history is layered; the index is `doc/SECURITY_STATUS_COMPLETE.md`. The
latest pass is the **Layer 5 multi-agent audit (June 2026)** in
`doc/MULTI_AGENT_SECURITY_AUDIT_2026.md` — 73 verified findings, 78 fixes. The full
security-mechanism reference is `doc/SECURITY_HARDENING.md`.

- **ELF code signing**: trusted-key pinning is wired (`src/trusted_signing_key.h`,
  matching `keys/tinyos_dev_signing_key.pem`, gitignored). Verification works end to end
  and is **runtime-verified under default ENFORCE mode** (2026-06-14): hash PASS ->
  signature PASS -> signed `hello.elf` runs in ring 3, its syscalls succeed
  ("Hello from ELF!"), it `exit(0)`s and is reaped — zero triple faults.
  **CORRECTION (2026-06-14):** the long-standing "`exec` triple-faults in ENFORCE mode"
  bug was **NOT** crypto-under-preemption. An earlier note here claimed it was
  "preemption corrupting in-flight P-256 state (not a stack overflow — `-fstack-usage`
  ~1.6 KB)" and that masking the verify fixed it. That was wrong on both counts: the
  ~1.6 KB figure measured only the ECDSA subtree in isolation, missing the *cumulative*
  exec chain on the single shell kernel stack. Reading QEMU's `-d int,cpu_reset` trace
  showed the ECDSA verify *completes and passes*; the fault came afterward. The real
  causes were four OS bugs, all now fixed and verified:
  (1) **kernel-stack overflow** — the 64 KB shell stack couldn't hold the full exec
  chain (commit `a10a006`; now 128 KB + early #PF overflow detection);
  (2) **`tss.ss0` was the kernel *code* selector `0x10` instead of *data* `0x18`** — the
  first ring3→ring0 syscall #TS-faulted loading SS (commit `b8510ca`);
  (3) **user stack guard page never armed** — PTE looked up in kernel tables, not the
  user PDPT (commit `51e4f36`);
  (4) two **EDR false-positive detectors** spamming alerts (commits `9020d82`,
  `1064331`).
  `elf_verify_signature` does still run the verify with interrupts masked
  (`disable/restore_interrupts`); that is harmless preemption-safety but was **not** what
  made ENFORCE usable. The build **enforces signatures by default** (fail-closed:
  unsigned/tampered binaries rejected); the embedded `hello`/`shell` binaries carry valid
  `TINYOS_SIG_V1` trailers, so a normal build boots and execs them. ECDSA P-256 is ms on
  real hardware but slow under QEMU/TCG (a speed cost, not a fault) — for fast local dev
  that accepts unsigned binaries, build `-DELF_PERMISSIVE_SIGNATURES` (warn-and-load), an
  explicitly named opt-out, never the default. Re-sign userspace binaries with
  `tools/sign_elf.py`, regenerate embedded arrays with `tools/elf_to_c.py`. The
  `verify-exec.sh` harness at the repo root reproduces the end-to-end ENFORCE run
  (GUI QEMU; you log in and type `exec /hello.elf` by hand). For a **fully
  automated, headless** check use `auto-verify-exec.sh`: it boots a fresh blank
  disk, drives the whole first-boot flow (password setup → root login → decline
  regular-user → shell → `exec /hello.elf`) by scripting QEMU-monitor `sendkey`
  via `tools/qemu_typist.py`, and prints PASS only on `Signature verification:
  PASS` + `Hello from ELF!` + zero triple fault. Override the throwaway login
  password with `TINYOS_TEST_PASSWORD`. Slow under TCG (PBKDF2 + bit-serial
  ECDSA) — allow several minutes.

- **OPEN: first-`exec`-after-login intermittent Hash mismatch (sha256 preemption).**
  Separate from the fixed triple-faults above. `exec /hello.elf` as the FIRST command
  after login occasionally fails signature verification, passes on retry. ROOT-CAUSED
  2026-06-14 with a timing-neutral per-4KB page-sum probe before the hash: the hashed
  INPUT is byte-for-byte correct on a failing run, yet `sha256()` returns a wrong (and
  run-to-run different) digest → the corruption is in sha256's stack-local working state
  (`sha256_ctx_t` carried across init/update/final), clobbered when an IRQ/softirq/
  context-switch preempts the long hash — same class as the masked ECDSA/PBKDF2.
  FIX (elf.c:199, under verification, **not yet committed/proven**): wrap the sha256 call
  in `disable_interrupts()/restore_interrupts()`. Identical masking was tried once before
  and "passed then recurred", so it's only durable after 5+ failing-prone first-exec boots
  with zero mismatch — use `firstexec-trial.sh`. If it still fails, move the masking INTO
  sha256/the crypto layer. (The earlier-dropped attempt was rejected for the WRONG reason —
  "exec_buffer has no .bss neighbor"; the corruption was never in exec_buffer.)

- **OPEN: rare boot-time `memset` kernel page fault.** Intermittent KERNEL PANIC during
  EARLY boot (pre-shell), EIP=`memset`, CR2 a low frame, "PD present, PT walk ends
  not-present". RAMFS/PMM `alloc_node`-style code `memset`s a `pmm_alloc`'d frame via its
  physical address before that frame's PAE PTE is reliably present. Distinct from the
  sha256 bug (boot never reaches exec). Fix approach: map-before-touch in the alloc paths,
  or guarantee the identity map covers every pmm_alloc frame. See memory note
  `ramfs-identity-map-bug.md`.

- **Password hashing**: PBKDF2 is always **100,000 iterations** (OWASP), decoupled from
  `-DTINYOS_DEV` (a build-speed flag) — pass `-DTINYOS_FAST_KDF` to lower it explicitly.
  The interrupt masking around PBKDF2 is **load-bearing**: a preempted derivation
  corrupts the shared `crypto_ws` workspace (adjacent to `user_database`), wiping the
  user DB so login fails with "user not found".

- **CSPRNG reseed masking**: `csprng_random_bytes` generates keystream inside a
  `CRITICAL_SECTION` so nothing rewrites `ctx->state/counter` mid-stream. `csprng_reseed`
  must do the same — `csprng_periodic_reseed` runs it from the timer softirq in **task
  context with interrupts enabled**, so an unmasked reseed could tear/duplicate keystream
  from the generator backing password salts, ECDHE key material, ASLR, DNS/TCP randomness
  (SSH DH was also a consumer before SSH was removed from the build, commit `87cd874`).
  The mask in `csprng_reseed` is load-bearing; do not remove it (critical sections nest,
  so the call from inside `csprng_random_bytes` is fine).

- **User address space — page-table copy-on-write (commit `1596a04`)**: userspace links
  at `0x08000000` (PD[0] index 64), which falls inside the kernel's identity-mapped low
  range. `pae_create_user_pdpt` copies all of the kernel's `PD[0]` entries into the user
  PDPT *by value*, so user PD[0] slots initially share the kernel's identity-map page-table
  frames. Writing a user PTE into a shared PT would clobber the kernel's own mapping and
  corrupt whatever `pmm_alloc`'d frame it resolves (RAMFS/FAT32 nodes, `exec_buffer`) —
  this was the cause of intermittent FS corruption (flaky `ls`), exec hash mismatches, and
  the "first `exec` after login fails, retry works" symptom. **`pae_map_page_into` now
  copy-on-writes**: if a user PDE still points at the kernel-shared PT for that slot, it
  clones a fresh private PT (copying the kernel entries) before writing the user PTE, so the
  kernel identity map is never mutated by exec. Do not "optimize" this back to writing the
  shared PT directly.

- **FAT32 `ls C:` output routing (commit `f6074a2`)**: shell commands print via
  `stream_printf(get_current_streams())` (the user's shell stream), NOT `kprintf` (the
  kernel console). `ls C:` looked empty because `fat32_list_root()` printed every entry via
  `kprintf`, which the shell session didn't show. The FAT32 driver stays stdio-agnostic: it
  exposes `fat32_list_root_cb(emit, ctx)` (per-entry callback, `fat32_dir_emit_t`);
  `fat32_list_root()` is a kprintf wrapper for kernel logging, and `cmd_fatls` passes a
  `stream_printf` emitter. When adding user-facing FS output, route through the shell stream,
  not `kprintf`.

## Not compiled (don't audit/fix)

`kernel_old.c`, `keyboard_old.c`, `tls13_demo.c`, `secure_delete.c` are not in the
build. `lib/python3.12/` is a vendored venv, not project code. `kernel_old.c` and
`keyboard_old.c` were accidentally committed to the public repo and have since been
untracked + gitignored (removed from GitHub; kept on disk only).

## Published & documented

This repo is PUBLISHED at https://github.com/douglasmun/TinyOS_enhanced (public).
Some local-only branches/commits must never be pushed; the publish allow-list and
the reasons are tracked in the private publish notes (memory `tinyos-publish-setup`),
not here. Demo ISO = the `v2.0` GitHub Release
asset. `publish.sh` (gitignored) and the push workflow are documented in memory
`publish-push-gotchas`. Security docs (curated set under `doc/`):
- `SECURITY_HARDENING.md` — now the full security reference: stack guard, ASLR, lazy
  FPU, PAE/W^X, **kernel-only credential store (no /etc/shadow)**, **ELF signing**,
  **secure boot**, **crypto hardening**, **HW-RNG health**, **tamper-evident audit
  log**, **copy_user**, **guard pages/TSS**, **auth hardening**, **net anti-spoofing**,
  **PMM double-free/capabilities** (17 mechanisms total).
- `FIREWALL_AND_IDS_CONFIG.md` — firewall/IDS are compile-time only (no runtime CLI);
  notes the AUDIT-8E IDS-not-wired gap.
- `USER_GUIDE.md` — boot/login/shell/networking walkthrough.
- Networking: NAT (10.0.2.x) works end-to-end; bridged 192.168.0.x impossible on this
  Mac (Wi-Fi can't be vmnet-bridged) — see memory `qemu-networking-wifi-limit`.
