# Crypto and security invariants

Properties that are **load-bearing** — each one was arrived at by debugging a real
failure, and removing it reintroduces that failure. If you are tempted to
"simplify" something here, the rationale is why not.

## Interrupt masking is load-bearing in three places

The kernel's long-running crypto keeps working state in memory that a preemption
can tear. Three sites mask interrupts for that reason, and they are not
interchangeable with each other:

- **PBKDF2** — a preempted derivation corrupts the shared `crypto_ws` workspace,
  which is **adjacent to `user_database`**. The observable failure is the user DB
  being wiped, so login fails with "user not found".
- **sha256 in the ELF verify path** — `sha256_ctx_t` is carried across
  init/update/final on the stack; a preempting IRQ/softirq/context-switch clobbers
  it and the digest comes out wrong (and run-to-run different) even though the
  hashed input is byte-for-byte correct. See `KERNEL_BUGS.md` for the diagnosis.
- **`csprng_reseed`** — `csprng_random_bytes` already generates keystream inside a
  `CRITICAL_SECTION` so nothing rewrites `ctx->state/counter` mid-stream.
  `csprng_reseed` must do the same, because `csprng_periodic_reseed` runs it from
  the timer softirq in **task context with interrupts enabled**. An unmasked
  reseed could tear or duplicate keystream from the generator backing password
  salts, ECDHE key material, ASLR, and DNS/TCP randomness. Critical sections nest,
  so the call from inside `csprng_random_bytes` is fine. **Do not remove it.**

Note `elf_verify_signature` also masks around the ECDSA verify. That one is
harmless preemption-safety but was **not** what made ENFORCE mode usable — see the
correction in `KERNEL_BUGS.md`.

## Password hashing

PBKDF2 is always **100,000 iterations** (OWASP), decoupled from `-DTINYOS_DEV` (a
build-speed flag). Pass `-DTINYOS_FAST_KDF` to lower it explicitly.

**Do not weaken PBKDF2 or swap the signature scheme to Ed25519.** Crypto was never
the cause of the exec-path failures it was blamed for.

## ELF code signing

Trusted-key pinning is wired (`src/trusted_signing_key.h`, matching
`keys/tinyos_dev_signing_key.pem`, gitignored). The build **enforces signatures by
default** (fail-closed: unsigned/tampered binaries rejected); the embedded
`hello`/`shell` binaries carry valid `TINYOS_SIG_V1` trailers, so a normal build
boots and execs them.

Runtime-verified under default ENFORCE mode (2026-06-14): hash PASS → signature
PASS → signed `hello.elf` runs in ring 3, its syscalls succeed ("Hello from
ELF!"), it `exit(0)`s and is reaped, zero triple faults.

ECDSA P-256 is milliseconds on real hardware but slow under QEMU/TCG — a **speed
cost, not a correctness or fault issue**. For fast local dev that accepts unsigned
binaries, build `-DELF_PERMISSIVE_SIGNATURES` (warn-and-load).

Re-sign userspace binaries with `tools/sign_elf.py` (it loads the pinned key —
early versions used an ephemeral one), regenerate embedded arrays with
`tools/elf_to_c.py`.

## Verification harnesses for the exec path

- `verify-exec.sh` — end-to-end ENFORCE run, GUI QEMU; you log in and type `exec
  /hello.elf` by hand.
- `auto-verify-exec.sh` — fully automated and headless. Boots a fresh blank disk,
  drives the whole first-boot flow (password setup → root login → decline
  regular-user → shell → `exec /hello.elf`) by scripting QEMU-monitor `sendkey`
  via `tools/qemu_typist.py`, and prints PASS only on `Signature verification:
  PASS` + `Hello from ELF!` + zero triple fault. Override the throwaway login
  password with `TINYOS_TEST_PASSWORD`. Slow under TCG (PBKDF2 + bit-serial
  ECDSA) — allow several minutes.
- `firstexec-trial.sh` — repeated first-exec-after-login boots, for the sha256
  preemption class specifically.

## What a harness has to prove

Recurring lesson across the ring-3 work (`RING3_MIGRATION.md` has the per-PR
detail), stated once because it applies to every new harness:

- **Test the boundary the fix lives at.** A harness that drives the kernel shell
  proves nothing about a **syscall** gate — the shell often enforces the same
  policy itself before the syscall is ever reached. `verify-cred-deprecation.sh`
  had to be rewritten around `userspace/credprobe.c` calling `int 0x80` directly
  for exactly this reason; the first version passed against a deliberately
  reverted, vulnerable kernel.
- **Test as the unprivileged user.** Anything that succeeds for root both before
  and after a fix cannot be tested from a root session.
- **Assert counts and positions, not presence.** "The text appeared" is also true
  of a truncating append or a truncated pipe.
- **Pair every positive with a negative.** A command that prints its payload and
  *then* refuses satisfies a refusal check; only "no payload marker appears after
  this point" catches it.
- **Validate both ways where possible** — PASS on the fixed kernel, FAIL on one
  with the fix removed. A passing harness alone is weak evidence.

## Security document index

All security history is layered; the index is `doc/SECURITY_STATUS_COMPLETE.md`.
The latest pass is the **Layer 5 multi-agent audit (June 2026)** in
`doc/MULTI_AGENT_SECURITY_AUDIT_2026.md` — 73 verified findings, 78 fixes. The
full security-mechanism reference (17 mechanisms) is `doc/SECURITY_HARDENING.md`.

`doc/FIREWALL_AND_IDS_CONFIG.md` notes that firewall/IDS are compile-time only (no
runtime CLI) and records the **AUDIT-8E IDS-not-wired gap, which is still open**.
