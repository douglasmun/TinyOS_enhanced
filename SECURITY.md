# Security Policy

TinyOS Enhanced is a **single-developer, educational / research operating-system kernel**.
It is **not** production software (see the status notice in the README): it is 32-bit,
single-core, console-only, intended to run under QEMU, and its from-scratch cryptography has
**not** had external review. Please calibrate expectations accordingly — but security
reports are genuinely welcome, since security mechanisms are the whole point of the project.

## Reporting a vulnerability

**Please do not open a public issue or discussion for a security vulnerability.**

Report it privately through either channel:

1. **GitHub private advisory (preferred):** the repository's **Security** tab →
   **Report a vulnerability**. This opens a private advisory visible only to the maintainer.
2. **Email:** `douglasmun@yahoo.com` with `[TinyOS_enhanced security]` in the subject.

As a single-developer educational project, reports are handled on a **best-effort basis**
with no guaranteed response timeline. I'll acknowledge your report and work with you on a
fix and coordinated disclosure as time permits.

## What to include

A clear, reproducible description is far more useful than a polished exploit:

- The component and code path (e.g. ELF loader / secure-boot verify, syscall handler
  (`int 0x80`), paging / NX / W^X, ASLR, the TCP/IP stack or e1000 driver, a crypto
  primitive, the EDR/IDS layer, FAT32/VFS).
- The class of bug (memory safety — overflow / OOB / UAF, integer overflow, privilege
  escalation ring3→ring0, secure-boot bypass, crypto weakness, parser/network DoS).
- How to reproduce under QEMU: build commit, command line, and any input/binary/packet
  needed to trigger it (a minimal description or generator is ideal).
- Expected vs. actual behaviour.

## Scope

In scope (security-relevant in the project's own terms):

- **Secure-boot bypass** — getting an unsigned or tampered ELF to execute when signed-ELF
  enforcement is on (this is a fail-closed control by design).
- **Privilege escalation** — a ring-3 user process gaining ring-0 / kernel control.
- **Memory-protection bypass** — defeating NX / W^X, ASLR, or kernel-stack guard pages;
  kernel memory-safety bugs reachable from user mode or the network.
- **Cryptographic flaws** — in the from-scratch AES / SHA / HMAC / PBKDF2 / ECDSA / ECDHE /
  HKDF / ChaCha20-CSPRNG implementations (within the educational caveat above).
- **Network-reachable bugs** — in the TCP/IP stack, DHCP/DNS/ICMP handling, or the e1000
  driver, including remote DoS.
- **Auth bypass** — defeating the first-boot password / login flow.

Out of scope:

- The documented **educational limitations** — single-core, 32-bit, no SMP, console-only,
  unreviewed crypto, "not for production / untrusted networks." These are stated, known
  constraints, not vulnerabilities.
- Issues requiring a modified build that has weakened a documented security control, or
  physical/hypervisor-level access outside the kernel's threat model.
- Theoretical findings with no reproducible path under the supported QEMU setup.

## Release artifacts

Released demo ISOs are signed with [minisign](https://jedisct1.github.io/minisign/)
(`tinyos.iso.minisig`). If you believe a published artifact is inauthentic or its signature
doesn't verify, report it privately as above.

## Disclosure

I follow coordinated disclosure: please give me reasonable time to ship a fix before any
public write-up, and I'll credit you (unless you prefer to remain anonymous).
