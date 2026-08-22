# Hobby-OS comparison — what to study, and what (if anything) to adopt

Status: **TODO / not yet investigated.** This file records an external assessment of
where TinyOS sits among security-minded hobby operating systems, and turns the
"go look at the others" half of it into a checklist. Nothing here has been verified
against those projects' actual source — every claim below is *as advertised* by the
project, which is exactly the failure mode this file exists to avoid repeating.

## The assessment being recorded

> "Is TinyOS Enhanced one of the most security-**oriented** hobby operating systems?"
> Yes.
>
> "Is it objectively one of the most **secure** hobby operating systems?" The evidence
> isn't strong enough yet to make that claim.

The reasoning, kept verbatim in substance because the distinction is the useful part:

- A security **feature list** is not assurance. Neither are repeated internal or
  AI-assisted audits.
- What would raise confidence: years of hostile exposure, independent human review,
  sustained fuzzing, formal verification, extensive soak testing. TinyOS has none of
  these.
- A critical ring-3-reachable memory corruption plus two high-severity
  authorization/firewall bugs surviving until the 2026-08 audit
  (`doc/SECURITY_AUDIT_2026-08.md`) is *simultaneously* evidence in TinyOS's favour
  (they were found and fixed) and the reason "most secure" is premature — the
  assurance process is still **converging**, not converged.

Two findings from this repo's own history corroborate that, and are worth keeping in
view whenever the posture gets restated:

- `verify/verify-tcp-serverpath.sh` printed "TCP-over-NAT is broken tree-wide" on
  every run for months. It was **false** — that harness drives the *server* path and
  never calls `tcp_connect`; a pcap at HEAD shows a clean SYN/SYN-ACK/ACK and
  `HTTP/1.1 200 OK`. The tree was fine; the assurance artifact was wrong.
- `ecdsa_init()` was an empty function with its curve self-test commented out
  ("disabled to allow boot"), while the boot line printed `[OK]` unconditionally.
  See the status-surface lie class in `CLAUDE.md`.

Neither was exploitable. That is the point: both are **assurance** defects, the kind
another feature inventory or internal audit pass does not surface.

## The field

| OS | Claimed distinguishing property | Why it is a different bet than TinyOS |
|---|---|---|
| **SerenityOS** | Hardware protections, limited userland capabilities, W^X, `pledge`, `unveil`, (K)ASLR, process isolation, modern TLS | Same *category* of defence-in-depth as TinyOS, but on a far longer-lived and broader codebase with real contributor pressure. The closest direct comparison, and the one where TinyOS's youth shows most. |
| **AtomicOS** | Deterministic programming — the Tempo language guarantees Worst-Case Execution Time (WCET) | Attacks timing side-channels at the **language** level. TinyOS hardens at the system level and has no WCET story at all. |
| **Xyris OS** | Microkernel — minimises the TCB by running most drivers/services in user space | Architectural minimalism vs. TinyOS's monolithic kernel. Note TinyOS *evaluated and rejected* moving its protocol parsers to ring 3 (see D1 in `doc/NETDAEMON_DESIGN.md`) — not on feasibility grounds but because moving them buys nothing: DNS/DHCP/ARP each produce results ring 0 consumes, so the trust returns through a syscall, and an ICMP responder would need `SYS_NETTX`, i.e. unrestricted frame forgery. A considered position, not a default. |
| **AethelOS** | Radical "symbiotic" security — capability-based security and cooperative scheduling | Highly experimental; moves *away* from enforced isolation toward "system harmony". A stark contrast to TinyOS's defensive posture, and the one most likely to be interesting-but-inapplicable. |

## TODO — study each, then decide

For each project below the work is the same three steps, and **step 3 is the one that
matters**: TinyOS has a documented history of asking "is this reachable?" instead of
"does THIS component carry it?" (see `trace-the-path-not-the-component` and the
withdrawn D1). Ask what adopting the idea **buys**, not whether it is possible.

1. Read the actual source/design docs, not the README's feature list. Record what is
   really enforced vs. advertised.
2. Write down the concrete mechanism in TinyOS terms — which file, which syscall,
   which boundary it would live at.
3. Decide **adopt / adapt / reject**, with the reason written down. A reject with a
   recorded reason is a completed item; an unexamined idea is not.

- [ ] **SerenityOS — `pledge` / `unveil`.** Per-process syscall and filesystem-path
      restriction, declared by the process itself and irreversibly narrowing. TinyOS
      has capability bits (`CAP_*`) but they are granted at task creation and never
      voluntarily dropped. Question: could a ring-3 process drop capabilities after
      init? What would `shell.elf` or a spawned binary usefully give up?
- [ ] **SerenityOS — userland capability model** more broadly. Compare against
      TinyOS's `task_t` capability word and the per-uid task cap.
- [ ] **SerenityOS — KASLR.** TinyOS has ASLR for user mappings; kernel-text
      randomisation is absent. Weigh against PR #58's finding that `pae`/`mem`/`aslr`/
      `wxaudit` together were an ASLR defeat readable by any user — the *disclosure*
      surface may matter more than the randomisation.
- [ ] **SerenityOS — their bug/regression-test discipline.** Arguably the highest-value
      item in this whole file, given the "assurance still converging" verdict. How do
      they stop a fixed bug from returning? TinyOS has 63 harnesses and **no runner and
      no CI at all** (no `.github/workflows/`), despite a ~0.8 s clean build and five
      harnesses that need no QEMU.
- [ ] **AtomicOS — WCET / Tempo.** Almost certainly *not* adoptable (no language
      change is on the table), but the underlying question is: does TinyOS have any
      timing-side-channel posture? Note `doc/MSEAL_AUDIT.md` already measured one
      suspected interrupt-stall primitive and **disproved** it. Is there a cheap
      bounded-time property worth asserting anywhere (crypto compare, PBKDF2)?
- [ ] **Xyris — microkernel TCB minimisation.** Re-read D1's "what does moving buy?"
      criterion against Xyris's actual split. Specifically: do they move parsers whose
      *results the kernel consumes*, and if so how do they avoid handing the trust
      back through the IPC boundary? If they have an answer, D1 deserves a second look;
      if they don't, D1's withdrawal is externally corroborated.
- [ ] **AethelOS — capability-based security.** Compare to TinyOS's `CAP_*` bits.
      Genuine capabilities are unforgeable references, not a bitmask checked by the
      callee — that is a real architectural difference worth understanding even if
      rejected.
- [ ] **AethelOS — cooperative scheduling.** Reject-with-reason is the likely outcome:
      TinyOS is preemptive round-robin and cooperative scheduling reintroduces
      denial-of-service by a non-yielding ring-3 task. Confirm and record.
- [ ] **Cross-cutting: fuzzing.** None of the above matters as much as this. The
      syscall boundary (`MAX_SYSCALL_NUM`, ~40 syscalls) and the RX parser
      (`handle_packet()` and below, ~8,350 lines reachable from any host on the
      segment) are both fuzzable. `tools/inject_frames.py` already exists and already
      has a UDP/DHCP mode — it is the natural starting point.
- [ ] **Cross-cutting: soak testing.** `doc/OS_COMPARISON_AND_GRADE.md` concedes there
      is none. A long-running QEMU boot with a load generator would exercise the
      leak/lifetime invariants (`elf-image-frame-leak`, the reaper ordering trap, the
      guard-page free) that only show up over time.

## Rules for anything adopted from this list

Standing constraints that a borrowed mechanism must not violate — each is the residue
of a real bug, so a good idea from another OS does not get to override them:

- No per-operation `kprintf` on a ring-3-reachable path; **no per-packet `kprintf` at
  all** on the RX path. Count, don't print, and group counters by attacker position.
- Check sentinel collisions before returning an errno (`-EPERM` is `-1`).
- Enforce permissions in the **primitive** (ramfs), not the command.
- Pick the gating polarity deliberately (ungated / ownership-gated / euid-gated) — it
  inverts the harness assertion.
- Every new harness needs a **positive control** and gets run against the *unfixed*
  tree. An unrun harness reports PASS and proves nothing.

## Honest summary to keep on hand

Strong defensive intent; unusually honest documentation of its own false-passes; single
developer; no adversarial exposure; no fuzzing; no CI. **"One of the most
security-oriented" is defensible. "Most secure" needs hostile exposure, and there is no
shortcut to it.**
