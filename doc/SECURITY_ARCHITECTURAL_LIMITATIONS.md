# TinyOS Security: Architectural Limitations

This document explains security features that are NOT implemented in TinyOS due to architectural constraints. These are documented to help users understand the security posture of this educational operating system.

---

## 1. Priority Inheritance Protocol (PIP) - NOT IMPLEMENTED

### Issue Description
The scheduler uses weighted round-robin scheduling based on task priority. However, it does NOT implement Priority Inheritance Protocol (PIP), which can lead to **Priority Inversion**.

### What is Priority Inversion?
Priority inversion occurs when:
1. Low-priority task L acquires a kernel lock (e.g., RAMFS mutex)
2. High-priority task H needs the same lock and blocks
3. Medium-priority task M preempts L (L never releases the lock)
4. Result: High-priority task H is effectively blocked by medium-priority task M

### Security/Stability Impact
- **High-priority task starvation** - Network handlers or time-critical tasks can be delayed
- **System responsiveness degradation** - Interactive tasks may become sluggish
- **Potential DoS** - Malicious low-priority task can intentionally hold locks

### Why Not Implemented in TinyOS?
Priority inheritance requires:
- Tracking lock ownership and waiter priority for EVERY kernel lock
- Dynamic priority boosting when high-priority tasks block
- Complex scheduler integration
- Significant code complexity (~500-1000 lines of careful synchronization code)

This level of complexity is beyond the scope of an educational OS focused on teaching fundamentals.

### Mitigation in TinyOS
- Keep critical sections SHORT - minimize time locks are held
- Use simple round-robin for fairness when priority doesn't matter
- Educational OS has few concurrent tasks, reducing probability of inversion

### Production OS Requirements
Real-world kernels (Linux, FreeBSD, QNX) implement full PIP or priority ceiling protocols. For production use, implement PIP or use an RTOS with PIP support.

---

## 2. Kernel Stack Guard Pages - RESOLVED

Originally listed here as NOT IMPLEMENTED (CRITICAL). Now implemented:

- Every task gets a **NOT-PRESENT guard page** immediately below its kernel
  stack (`task->guard_page_phys`), and user tasks a second one below the user
  stack (`task->user_guard_page_phys`) — `src/process.c`. An overflow faults
  instead of silently corrupting adjacent memory.
- A kernel-stack overflow that faults inside the #PF handler escalates to a
  double fault, which cannot run on the overflowed stack. Vector 8 is therefore
  a **task gate** to a dedicated TSS with its own stack
  (`tss_init_double_fault()` in `src/tss.c`, `idt_install_double_fault_gate()`
  in `src/idt.c`) — i386 has no IST, and a task gate is its only stack switch.
- Kernel tasks run on a 128 KB stack (`KERNEL_TASK_STACK_PAGES = 32`,
  `src/process.h`).
- Freeing a guard page restores its mapping first, or the frame stays poisoned
  for its next owner (see `doc/RULES_THAT_BITE.md`).

See `doc/SECURITY_HARDENING.md` ("Stack Guard Pages + TSS esp0/ss0 Integrity").

---

## 3. Other Known Limitations

### No Memory Barriers / Memory Ordering Guarantees
TinyOS is designed as a **single-core educational OS**. It does NOT implement memory barriers (`mfence`) or acquire/release semantics required for multi-core synchronization.

**Impact:** On multi-core systems, shared data structures could be corrupted due to out-of-order execution and cache coherency issues.

**Mitigation:** TinyOS should only be run on single-core systems (QEMU default is single-core).

### Resource Limits: partial
There is no general rlimit mechanism and **no per-process memory or CPU-time quota**. Specific exhaustion vectors are capped instead, each with a root reserve so an unprivileged user cannot lock root out:

- **Tasks:** per-uid cap of live tasks (`USER_MAX_CONCURRENT_TASKS`, 10) plus slots no non-root task may take (`TASK_ROOT_RESERVED_SLOTS`, 4); both refuse with `-EAGAIN` (`src/process.c`). uid 0 is exempt from the per-uid cap.
- **Task-creation rate:** token bucket (burst 10, 5/s sustained), `-EAGAIN` when empty (`src/process.c`).
- **ramfs file descriptors:** per-process `PROCESS_MAX_FDS` (`-EMFILE`), plus a per-uid cap (`RAMFS_USER_MAX_FDS`, 8) and a root reserve (`RAMFS_ROOT_RESERVED_FDS`, 4) — `src/ramfs.c`, `src/ramfs.h`.
- **TCP sockets:** per-uid cap (`TCP_USER_MAX_SOCKETS`, 2) and a root reserve (`TCP_ROOT_RESERVED_SOCKETS`, 2) — `src/tcp.c`, `src/tcp.h`.

**Remaining gap:** physical memory and CPU time are not accounted per process or per user.

### Deliberate non-goals
These were considered and are out of scope, not pending:

- **No TLS or SSH.** Both were built and then removed from the build (`Makefile`); `tls13_demo.c` is not compiled.
- **No disk encryption and no secure deletion** (`secure_delete.c` is not compiled).
- **No mandatory access control.** Access control is Unix DAC plus the `CAP_*` bits; there is no SELinux-style policy engine.
- **No CFI.** Control-flow integrity is not implemented.
- **No journaling or overlay filesystem.** ramfs is volatile and FAT32 has no journal.

### Stack Canaries: implemented
The whole kernel builds with `-fstack-protector-strong` (`CFLAGS` in `Makefile`). There is no per-file exception: the credential-path files (`user.o`, `shell_user.o`, `shell.o`) used to be built without it and now use the generic rule (see the comment in `Makefile`). The canary is seeded from `entropy_get_random32()` with the low byte cleared, and a mismatch calls `kernel_panic("Stack protection violation")` (`src/stack_guard.c`).

---

## Recommendations for Production Use

If you plan to build a production OS based on TinyOS concepts:

Done in TinyOS:

- **Kernel stack guard pages** — section 2.
- **Stack canaries** — `-fstack-protector-strong`, entropy-seeded canary.
- **ASLR** — user stacks, 12 bits (`src/aslr.c`).
- **W^X** — enforced via the PAE NX bit; see `SECURITY_HARDENING.md`.

Still to implement:

1. **MUST** (if targeting SMP): multi-core memory barriers — section 3.
2. **SHOULD**: priority inheritance or ceiling protocols — section 1 (`mutex_lock()` in `src/mutex.c` carries a TODO stub, no boost).
3. **SHOULD**: full per-process resource limits (memory, CPU time) — section 3.

---

## Conclusion

TinyOS is an **educational operating system** designed to teach OS concepts, not a production-ready kernel. The architectural limitations documented here are conscious trade-offs between simplicity/learnability and production-grade security.

Users should understand these limitations when evaluating TinyOS for any purpose beyond education.

For security-critical applications, use a mature, audited kernel (Linux, FreeBSD, QNX, etc.) with full security feature support.

---

**Document Version:** 1.14
**Last Updated:** 2026-10 (reviewed against v2.8)
**Maintained by:** TinyOS Security Team
