# TinyOS documentation

TinyOS (v2.8) is an educational 32-bit (i386) Multiboot2 kernel in freestanding C and
NASM: PAE paging with NX/W^X, ASLR, ring-3 user processes running ECDSA-signed ELF
binaries (enforced by default), a ring-3 login shell, VFS over RAMFS and FAT32, an e1000
TCP/IP stack with firewall, IDS and EDR. See [`../README.md`](../README.md) for the
project overview, build and run instructions.

This page indexes the documents in `doc/`. Docs marked **historical** describe an
earlier state of the tree and are kept for the record; where they conflict with the
code, the code wins.

## Start here

| Document | What it covers |
|---|---|
| [`../README.md`](../README.md) | Project overview, build, ISO, QEMU boot |
| [`USER_GUIDE.md`](USER_GUIDE.md) | Boot, login, shell and networking walkthrough |
| [`../SECURITY.md`](../SECURITY.md) | Security policy and how to report a vulnerability |
| [`RULES_THAT_BITE.md`](RULES_THAT_BITE.md) | Every project rule, with the failure that produced it — read before changing an area |
| [`USER_SYSTEM_TEST_GUIDE.md`](USER_SYSTEM_TEST_GUIDE.md) | Manual walkthrough of accounts, su, permissions and lockout |

## Design and rules

| Document | What it covers |
|---|---|
| [`RING3_MIGRATION.md`](RING3_MIGRATION.md) | Ring-3 migration: each syscall's design rationale, PRs #43–#58, harness traps |
| [`KERNEL_BUGS.md`](KERNEL_BUGS.md) | Fixed kernel bugs worth remembering (ISR EAX clobber, exec triple-fault, sha256/PMM/COW faults) |
| [`CRYPTO_INVARIANTS.md`](CRYPTO_INVARIANTS.md) | Crypto invariants, ELF signing, what a harness must prove |
| [`NETWORK_ISOLATION.md`](NETWORK_ISOLATION.md) | RX path, counters, firewall/IDS test vehicles |
| [`NETDAEMON_DESIGN.md`](NETDAEMON_DESIGN.md) | `knetd`, its supervisor, why the ring-3 parser move (D1) was withdrawn |
| [`FIREWALL_AND_IDS_CONFIG.md`](FIREWALL_AND_IDS_CONFIG.md) | Configuring the firewall and IDS |
| [`EDR_QUICK_REFERENCE.md`](EDR_QUICK_REFERENCE.md) | What the EDR code does: hooks, signatures, responses, daemon |
| [`SHELL_FEATURES.md`](SHELL_FEATURES.md) | Shell environment variables, aliases, redirection, pipelines, jobs |
| [`STDIN_FEATURES.md`](STDIN_FEATURES.md) | Standard streams and the fd model |
| [`AUDIT_LOG_PERSISTENCE.md`](AUDIT_LOG_PERSISTENCE.md) | Why the audit log is volatile, and stays that way |
| [`MSEAL_AUDIT.md`](MSEAL_AUDIT.md) | `SYS_MSEAL` audit: the disproved latency hypothesis |
| [`LOCK_ORDERING.md`](LOCK_ORDERING.md) | Lock acquisition hierarchy |
| [`ROADMAP_NEXT.md`](ROADMAP_NEXT.md) | Post-v2.2 roadmap with rationale (all items done or closed) |

## Security references

| Document | What it covers |
|---|---|
| [`SECURITY_HARDENING.md`](SECURITY_HARDENING.md) | Reference for each security mechanism |
| [`SECURITY_STATUS_COMPLETE.md`](SECURITY_STATUS_COMPLETE.md) | Index of security work across all audit layers |
| [`SECURITY_ARCHITECTURAL_LIMITATIONS.md`](SECURITY_ARCHITECTURAL_LIMITATIONS.md) | Features deliberately not implemented, and why |

## Audits and reports

| Document | What it covers |
|---|---|
| [`SECURITY_AUDIT_2026-08.md`](SECURITY_AUDIT_2026-08.md) | Latest audit: 16 findings, all fixed (PRs #103–#105) |
| [`FUZZ_REPORT_2026-10.md`](FUZZ_REPORT_2026-10.md) | libFuzzer campaign over the input surfaces: 9 targets, 35 defects fixed (PR #141) |
| [`MULTI_AGENT_SECURITY_AUDIT_2026.md`](MULTI_AGENT_SECURITY_AUDIT_2026.md) | **Historical** (June 2026): 101-agent audit, 73 findings, 78 fixes |
| [`OS_COMPARISON_AND_GRADE.md`](OS_COMPARISON_AND_GRADE.md) | Grade against hobby/educational OSes, as of 2026-06-14 |
| [`HOBBY_OS_COMPARISON_TODO.md`](HOBBY_OS_COMPARISON_TODO.md) | What to study from other hobby OSes, and what (if anything) to adopt |
| [`WASM_BROWSER_FEASIBILITY.md`](WASM_BROWSER_FEASIBILITY.md) | Running the ISO in the browser via v86 (the web demo) |

## Historical

Kept for the record; superseded by the code and the documents above.

| Document | What it covers |
|---|---|
| [`ARCHITECTURAL_SECURITY_ISSUES.md`](ARCHITECTURAL_SECURITY_ISSUES.md) | Four architectural issues, all superseded by shipped code |
| [`CRYPTO_PHASE1_COMPLETE.md`](CRYPTO_PHASE1_COMPLETE.md) | Crypto infrastructure phase 1 (2025, v1.14) |
| [`SECURITY_ROADMAP_2025.md`](SECURITY_ROADMAP_2025.md) | 2025 security roadmap (v1.13) |
| [`EDR_FEATURES_ASSESSMENT.md`](EDR_FEATURES_ASSESSMENT.md) | 2025 assessment of proposed EDR features |

Harness rules live in [`../verify/CLAUDE.md`](../verify/CLAUDE.md); the ring-3 shell's
notes in [`../userspace/CLAUDE.md`](../userspace/CLAUDE.md).
