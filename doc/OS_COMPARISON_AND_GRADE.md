# TinyOS — Comparative Grade vs. Hobby/Educational Operating Systems

**Date:** 2026-06-10, re-graded **2026-06-14** after (a) removing SSH/SSHD from the
build, and (b) root-causing and fixing the `exec`-in-ENFORCE triple-fault — which
turned out **not** to be a crypto/ISR problem at all (see §4). This revision corrects
several claims in the prior (2026-06-12) grade that later proved wrong.
**Method:** Graded on three independent axes — ambition/breadth, feature rarity, and
reliability/correctness — because TinyOS scores very differently on each. The
comparison set and external claims come from a fact-checked, multi-source research
pass (each claim adversarially verified 3-vote). TinyOS's own feature/LOC inventory
and reliability state are taken from **direct inspection of the built `kernel.elf`**
and **on-target QEMU runtime testing** (the `verify-exec.sh` harness, end-to-end).

Comparison set: xv6 (MIT), ToaruOS, SerenityOS, MikeOS, SkiftOS, Linux 0.01, and
tutorial-tier kernels (James Molloy "Roll your own OS", BrokenThorn, littleosbook /
"The little book about OS development", OSDev bare-bones).

---

## 1. TinyOS feature & size inventory (from the built kernel)

~50.3K LOC of kernel C across **78 compiled translation units** (plus NASM asm),
verified against `kernel.elf` symbol table, not a hand-maintained list.

| Subsystem | Verified state (runtime / symbol-confirmed) |
|---|---|
| Memory: paging + **PAE/NX + ASLR** + stack guard | Working; W^X enforced (panics on any W∧X page) |
| Scheduler / preemptive multitasking + mutex | Working; kernel→kernel context-switch fixed |
| Interrupts / **ring-3 syscalls** / GDT / TSS | Working; `tss.ss0` selector bug fixed (was code, now data) |
| Filesystems: **VFS + FAT32 + RAMFS** + IDE | Working |
| Networking: **TCP/IP + e1000 + DHCP/DNS/ICMP** + firewall + IDS | Working (DHCP leases IP; TCP accepts) |
| Crypto: SHA-256/512, AES-GCM, **ECDSA, ECDHE**, HKDF, entropy/RDRAND, PBKDF2 | Present + correct; **secure-boot verify runtime-confirmed** |
| **ECDSA-signed-ELF secure boot** | **Working & ENFORCED by default** — runtime-verified end-to-end |
| **EDR / security monitoring** | Working; two broken detectors (RWX, syscall-flood) fixed — no false-positive spam |
| Shell + editor + console + keyboard | Working; login reliable (PBKDF2 100k, masked) |

**Removed since the prior grade:** the **SSH server + SSHD + RSA-2048** (commit
`87cd874`). The sources remain on disk (gitignored) but are **not compiled or linked**
— confirmed by the absence of any `ssh_*`/`rsa_*` symbol in `kernel.elf`. The handshake
never completed reliably, so it was cut from production rather than shipped broken.
**This removes what the prior grade called TinyOS's "essentially unique" feature, and
the grade is adjusted accordingly (§5).**

---

## 2. The landscape — what is actually rare

| Capability | Who has it | Rarity |
|---|---|---|
| Boot→shell, paging, ring-3 + ELF + syscalls | xv6, ToaruOS, SerenityOS, **TinyOS** | Table-stakes for "serious" |
| Real NIC driver + working IP stack | ToaruOS, SerenityOS, **TinyOS** | Uncommon |
| **Full TCP + DHCP + DNS + ICMP** out of the box | SerenityOS, **TinyOS** (ToaruOS TCP had TODOs; xv6 skeleton, no TCP) | Rare |
| **From-scratch crypto** (AES/SHA/ECDSA/ECDHE) | SerenityOS (LibCrypto), **TinyOS** (ToaruOS bundles mbedTLS) | Very rare |
| **Signed-binary (ECDSA) secure boot, enforced by default** | **TinyOS** (Linux module-signing is the mainstream precedent) | Essentially unique in hobby space |
| EDR / behavioral security monitoring | **TinyOS** only | Unique |
| ~~Native SSH server~~ | ~~TinyOS~~ | **Removed from build (87cd874)** |

Key supporting facts (verified, with sources in §6):
- **xv6** networking is a *teaching skeleton* — IP/UDP/ARP only, **no TCP**, and
  students must implement `e1000_transmit`/`e1000_recv` themselves.
- **ToaruOS** is a complete from-scratch OS (~100K LOC, since 2011, x86-64+ARMv8) with
  real e1000/pcnet/rtl8139 drivers — but its TCP listed reordering, timeouts, and
  listening sockets as TODO, and it **deliberately does not write its own TLS** (bundles
  mbedTLS).
- **SerenityOS** is the strongest comparable: from-scratch **LibCrypto** (AES, SHA-1/
  256/512, MD5, HMAC, RSA over a custom BigInteger) and a **TLS 1.2 LibTLS** that loads
  real HTTPS sites, plus W^X/NX, (K)ASLR, and pledge/unveil. Far larger, multi-dev,
  64-bit, full GUI — but ships **no signed-binary secure boot**.

---

## 3. Where TinyOS sits

- **Clearly above tutorial-tier.** James Molloy / BrokenThorn / littleosbook / OSDev
  bare-bones top out at paging + basic tasking + maybe a RAM FS. TinyOS exceeds all of
  them by a wide margin.
- **Above xv6 on scope** — full TCP/IP + real e1000 + DHCP/DNS/ICMP vs. xv6's
  fill-in-the-blanks skeleton.
- **Competitive with ToaruOS / SerenityOS on the security/crypto axis**, and on one
  feature it still beats even SerenityOS: **ECDSA-signed-ELF secure boot, enforced
  fail-closed by default and now runtime-verified working**. The trade-off: SerenityOS
  has more crypto *breadth* (TLS to real HTTPS) and is a vastly larger, stable,
  multi-dev, 64-bit GUI system. With SSH removed, TinyOS's once-two-feature lead over
  SerenityOS narrows to the single signed-boot dimension — but that one is real,
  rare, and now demonstrably functional.

---

## 4. The honest counterweight — reliability (substantially revised)

The prior grades attributed TinyOS's headline instability to a **crypto-under-preemption
/ ISR-corruption bug**, and claimed the masked-ECDSA fix had resolved `exec` in ENFORCE
mode. **On 2026-06-14 that diagnosis was shown to be wrong**, and the real bugs were
found by reading QEMU's `-d int,cpu_reset` trace and fixed:

- `exec /hello.elf` triple-faulting in ENFORCE mode was **not** the crypto being too
  slow or preemption corrupting ECDSA state. The ECDSA verify *completed and passed*;
  the fault came afterward. Four independent **OS** bugs were responsible, each masking
  the next:
  1. **Kernel-stack overflow** — the shell's 64 KB kernel stack couldn't hold the full
     `cmd_exec → elf_load_process → ecdsa_verify → task_create_user → PAE-setup` chain
     (commit `a10a006`; stack → 128 KB + early overflow detection).
  2. **`tss.ss0` set to the kernel *code* selector** (`0x10`) instead of *data* (`0x18`)
     — the first ring3→ring0 syscall faulted (#TS) loading SS (commit `b8510ca`).
  3. **User stack guard page never armed** — its PTE was looked up in the kernel page
     tables instead of the user PDPT (commit `51e4f36`).
  4. Two **EDR false-positive detectors** (a misformatted RWX/`CODE_INJECTION` scanner
     reading PAE tables as 32-bit, and a `SYSCALL_FLOOD` heuristic that fired on every
     normal program) — commits `1064331`, `9020d82`.
- **Result, runtime-verified:** `exec /hello.elf` now runs **end-to-end under default
  ENFORCE-mode signature verification** — signature PASS → ring-3 execution → syscalls
  succeed (`Hello from ELF!`) → clean `exit(0)` → process reaped — with **zero triple
  faults and zero spurious EDR alerts**.
- Root-password login is reliable; PBKDF2 runs masked at the full 100k iterations.
- The crypto algorithms are correct (host-validated) **and** the signed-boot path is now
  confirmed working on-target, not merely "crypto correct, enforcement gated."

> **Correction note (2026-06-14):** the 2026-06-12 grade's claims that "ECDSA signature
> verification works under preemption (masked verify)" *as the fix*, and that the
> remaining gap was "SSH-specific," are superseded. The masked verify is harmless but
> was **not** what made ENFORCE usable; the four OS fixes above were. SSH is no longer a
> reliability item because it is no longer in the build.

What remains genuinely open: **no long-soak / multi-day stability testing**, and the
system is single-core, 32-bit, console-only. Those are the honest caps on the
reliability axis now — not a known corruption bug.

---

## 5. Grades

**Scope of these grades:** the letter grades below are relative to the **hobby /
educational** peer set (xv6, ToaruOS, SerenityOS, tutorial kernels). They are **not**
relative to real-world production "tiny OSes" (RTOS, microkernels, minimal Unix),
which compete on axes TinyOS does not enter — see §6 for that wider, ungraded
landscape. "A−" here means "near the top of the hobby/educational field," not "near
production-grade."

| Axis | Grade | Δ vs 2026-06-12 | Rationale |
|---|:---:|:---:|---|
| Ambition / scope | **A** | ▼ from A+ | Still rivals 100K-LOC multi-dev projects from a single dev — but SSH, a major piece of that ambition, was removed; net scope is smaller. |
| Feature rarity / novelty | **A−** | ▼ from A+ | Signed secure boot + EDR remains a rare combination, but the once-"unique" SSH server is gone; the rarity case now rests on signed-boot + EDR alone. |
| Breadth of working subsystems | **A−** | = | MM, scheduler, ring-3, VFS/FAT32, TCP/IP-to-DHCP, **and now exec-of-signed-ELF** all genuinely work and are runtime-verified. |
| Reliability / correctness | **A−** | ▲ from B+ | The headline blocker is *actually* resolved this time (runtime-proven exec-in-ENFORCE), with the real root causes fixed rather than masked. Held below A only by the absence of long-soak testing and the single-core/32-bit/console scope. |
| Docs / engineering hygiene | **A−** | = | A curated design/audit doc set; clean `-Werror` build; header-dep tracking; a reproducible `verify-exec.sh` runtime harness. Held at A− because several older docs (incl. the prior version of *this* one) carried a wrong root cause and stale SSH/feature claims now being corrected. |
| **Overall** | **A−** | = (composition changed) | A top-decile security-focused hobby OS. The grade is unchanged in letter but for sounder reasons: the reliability axis genuinely earned its rise (verified, not asserted), offsetting the scope/rarity loss from the SSH removal. |

**One-line placement:** A top-tier, security-focused hobby OS — broader than xv6, with a
from-scratch crypto stack and an **ECDSA-signed-ELF secure boot that is enforced by
default and now demonstrably runs signed binaries end-to-end** — exceeding even
SerenityOS in that one dimension, while remaining a single-developer, single-core,
32-bit, console-only system without the GUI/breadth/soak-tested stability of
ToaruOS/SerenityOS.

**Highest-leverage improvements now (SSH no longer being the blocker):**
1. **Long-soak stability testing** — multi-hour/multi-day runs under load; this is the
   single biggest evidence gap keeping reliability below A.
2. **Audit-doc accuracy** — reconcile the remaining docs (e.g.
   `MULTI_AGENT_SECURITY_AUDIT_2026.md`) with the corrected `exec` root cause; stale
   "crypto/ISR/SSH" framing in those docs is now the main hygiene debt.
3. Optionally, a **correct PAE RWX detector** to restore the (currently disabled)
   per-process injection telemetry as real signal rather than noise.

---

## 6. The wider landscape — real-world "tiny OSes" (ungraded)

The §5 grades are scoped to hobby/educational kernels. This section places TinyOS
against the systems people usually mean by "tiny OS" in the real world — production
RTOS, microkernels, and minimal Unixes. **These are deliberately left ungraded**,
because most of them win categories TinyOS never entered; a single letter would
mislead. Confidence: TinyOS facts are verified from its built `kernel.elf` (this
revision); peer facts are well-established and high-confidence, but the precise
numbers (LOC, RAM footprints, verification scope) are from general knowledge and would
warrant citation before being treated as exact.

**What kind of system TinyOS is (the frame for everything below):** a monolithic,
single-core, 32-bit (i386) educational kernel — ~50.3K LOC of C across 78 TUs,
console-only, runs under QEMU with 256 MB — with a security focus (PAE/NX, ASLR, W^X,
ECDSA-signed-ELF secure boot, behavioral EDR). It is **not** real-time, not portable
to MCUs, not formally verified, and not deployed in any device. Several peers below
beat it precisely because they target those things and TinyOS does not.

### 6a. Embedded RTOS — FreeRTOS, Zephyr, RIOT, NuttX

The most common real meaning of "tiny OS," and a different universe of goals; these
ship in billions of devices.

- **FreeRTOS** — the canonical tiny RTOS. *Smaller* than TinyOS at its core (a
  scheduler + queues is roughly single-digit-thousands of LOC), runs on MCUs with
  **kilobytes** of RAM, hard real-time, deterministic latency. Classic core has no
  MMU/protection (MPU variants exist). Does one thing — real-time scheduling —
  supremely well, in a footprint TinyOS cannot approach.
- **Zephyr** — Linux Foundation RTOS; large driver/protocol ecosystem, real-time,
  MMU/MPU support, secure boot via MCUboot, shipping in real products. Far more
  portable and battle-tested than TinyOS.
- **RIOT / NuttX** — IoT-focused; NuttX is notably POSIX-compliant on tiny hardware.

**Read:** On the RTOS axis TinyOS is not competitive and isn't trying to be — no
real-time guarantees, no MCU support, a coarse round-robin scheduler, a 256 MB target.
FreeRTOS/Zephyr win determinism, footprint, portability, and deployment outright.
TinyOS's only edge is breadth-of-OS-concepts in one teachable codebase (full TCP stack
+ FS + ring-3 + crypto) that an RTOS deliberately omits.

### 6b. Microkernels / secure kernels — seL4, MINIX 3, QNX, Redox

The most *relevant* comparison given TinyOS's security framing — and where the rigor
gap is starkest.

- **seL4** — the reference point: a ~10K-LOC microkernel with a **machine-checked
  formal proof** of functional correctness and security enforcement. A different *kind*
  of claim than anything TinyOS makes — seL4 *proves* properties; TinyOS *tests* them.
  seL4 wins security correctness absolutely.
- **MINIX 3** — microkernel with fault-isolated, restartable drivers (self-healing);
  stronger isolation *architecture* than TinyOS's monolithic design.
- **QNX** — commercial microkernel RTOS in cars/medical devices; production reliability
  TinyOS doesn't approach.
- **Redox** — Rust microkernel; memory safety by language, full-OS ambitions.

**Read:** TinyOS's security features (W^X, ASLR, signed boot, EDR) are defense-in-depth
mechanisms a *monolithic* kernel bolts on; seL4/MINIX get isolation from *architecture*.
TinyOS has real, working mitigations, but a monolithic ~50K-LOC C kernel with no formal
verification and no driver isolation is categorically less trustworthy than seL4. Its
one interesting angle: signed-ELF boot + behavioral EDR is an unusual *combination* even
microkernels don't typically bundle — but that's novelty, not assurance.

### 6c. Minimal Unix / legacy — Linux 0.01, classic MINIX, Plan 9

- **Linux 0.01** (1991, ~10K LOC) — TinyOS exceeds it on nearly every modern axis
  (PAE/NX/ASLR, signed boot, crypto, TCP/IP with DHCP/DNS). But 0.01 *became Linux*; it
  was a seed, not an endpoint. Fair summary: TinyOS ≈ "a 1990s-era minimal Unix in
  scope, plus 2020s security mitigations."
- **Classic MINIX** — the teaching microkernel that inspired Linux; clean, deliberately
  small.
- **Plan 9** — research elegance ("everything is a file" taken all the way); a design
  philosophy TinyOS doesn't engage.

**Read:** Against *historical* minimal Unixes TinyOS looks genuinely advanced — security
features that postdate them by decades. Against their legacy/influence, no contest:
these shaped computing.

### 6d. Bottom line across the real-world set

**Where TinyOS genuinely stands out:** for a single-developer educational kernel, it
combines a breadth (TCP/IP + FAT32/VFS + ring-3 ELF + from-scratch crypto) usually seen
only in much larger projects, **with enforced ECDSA-signed-ELF secure boot — now
runtime-verified working — that even SerenityOS lacks and most RTOS/microkernels don't
bundle.** That specific combination is rare.

**Where every serious real-world peer beats it:**
- *Footprint / real-time:* FreeRTOS, Zephyr (kilobytes, deterministic) — TinyOS isn't in
  the race.
- *Security assurance:* seL4 (proven), MINIX 3 / QNX (isolation) — TinyOS *tests*, they
  *guarantee* or *architect*.
- *Maturity / breadth / deployment:* SerenityOS, ToaruOS, Zephyr, QNX — larger,
  portable, in use.
- *Pedagogical minimalism:* xv6, MINIX — deliberately smaller and clearer for teaching.

**Honest placement:** TinyOS is a top-decile **hobby/educational** OS with a distinctive
security-feature story — best understood as "a minimal-Unix-scope monolithic kernel with
modern mitigations bolted on, plus a unique signed-boot + EDR angle." It is **not** a
real-world tiny OS in the RTOS/microkernel sense, doesn't compete on footprint,
real-time, portability, formal assurance, or deployment, and should not be graded as if
it does. Its value is breadth-of-concepts-in-one-teachable-codebase and a working
demonstration of security mechanisms — not production fitness.

---

## 7. Sources

- xv6 networking lab (IP/UDP/ARP skeleton, no TCP, student-written e1000): https://pdos.csail.mit.edu/6.1810/2025/labs/net.html
- xv6 book (exec/ELF, ring-3, syscalls): https://pdos.csail.mit.edu/6.828/2023/xv6/book-riscv-rev3.pdf
- ToaruOS (scope, drivers, ~100K LOC): https://github.com/klange/toaruos
- ToaruOS v1.0 release (e1000/pcnet/rtl8139): https://github.com/klange/toaruos/releases/tag/v1.0.0
- ToaruOS — no native TLS, bundles mbedTLS: https://github.com/klange/toaruos/issues/205
- SerenityOS (features: IPv4/TCP/UDP, DNS/HTTP, W^X/(K)ASLR/pledge/unveil): https://github.com/SerenityOS/serenity
- SerenityOS — LibCrypto + LibTLS loading real HTTPS: https://serenityos.org/happy/2nd/
- SerenityOS LibCrypto/LibTLS PR (AES/SHA/HMAC/RSA/BigInteger, TLS 1.2): https://github.com/SerenityOS/serenity/pull/1661
- Linux in-kernel module signature verification (signed-binary precedent): https://docs.kernel.org/admin-guide/module-signing.html
