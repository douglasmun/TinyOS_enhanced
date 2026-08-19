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
- **The RX path is stricter still: no per-packet `kprintf` at all.** Any host on the
  segment drives those sites, from the ISR, before the firewall. Count, don't print —
  counters surface in `ifconfig`; `stream_printf` is wrong here too (interrupt context
  has no current user stream). Three sweeps were needed (the RX loops, then `icmp.c`,
  then `handle_dns_response`'s 20 sites), so **sweep the protocol files, not just the
  loops** — and keep distinct attack signatures as **separate** counters, since one
  "dropped" total hides which attack is underway. A file-wide grep fails on correct
  code: the rule is about what a *remote* host drives, so `dns.c`'s local-`dig`-driven
  prints stay. Harnesses: `verify-rxdrop-counters.sh`, `verify-icmp-counters.sh`,
  `verify-dns-rx-counters.sh` (needs `-DTINYOS_FAULT_INJECT`; its `valid` leg is the
  positive control). Rationale: `doc/NETWORK_ISOLATION.md`.
- **`E1000_UNLOCK()` does not re-enable interrupts on the IRQ11 path.**
  `critical_section_exit()` only touches `IF` at depth 0, and that clause is deliberate
  (a `popfl` mid-ISR would corrupt the preempted thread's flags). So `e1000_poll_rx`'s
  mid-loop unlocks are depth decrements only, and `E1000_RX_PACKET_BUDGET` does **not**
  bound interrupt-off time the way its comments claim. Don't trust those comments; see
  `doc/NETWORK_ISOLATION.md`.
- **The RX path parses in *task* context, on `knetd` — keep it that way.** The ISR only
  copies each frame into `rx_softirq_ring`; `e1000_rx_softirq_run()` drains it and calls
  `handle_packet()` with `IF=1`. Never reach the parser from an ISR — that is ~8,350
  lines running interrupts-disabled at a remote host's chosen rate. Three things easy to
  undo: the frame **must be copied** before RDT advances (the NIC refills that
  descriptor, so a retained `rx_bufs[]` pointer is an attacker-timed UAF); the boot DHCP
  loop in `kernel.c` **must keep its explicit `e1000_rx_softirq_run()` call** (`knetd`
  does not exist yet there, and a "did it run" flag was tried and reverted — it masks a
  stalled `knetd`); and ring overflow is **drop-newest**, counted, because drop-oldest
  lets a fast sender evict accepted frames. `ifconfig`'s `irq-ctx` must read **0**.
  Harness: `verify-rx-thread-context.sh`.
- **`rx_softirq_ring` is single-consumer, and `knetd` is that consumer.** `SYS_NETRX`
  (`e1000_rx_dequeue`) must pop **`netd_ring`**, never `rx_softirq_ring` — pointing it
  back restores a race where a live ring-3 netd steals TCP segments from the kernel
  parser at random (intermittent, load-dependent, presents as "networking is flaky").
  `knetd` classifies: ICMP/UDP to `netd_ring`, everything else parsed in place — one
  `if`/`else`, so no frame is delivered twice or dropped between paths. TCP is **never**
  routed (`TCP_LOCK` is `cli`; ring 3 has IOPL=0). Routing is gated on `netd_claimed`,
  inert until claimed and reversible on release — the supervisor needs the release, or a
  dead netd takes ICMP/UDP down permanently. **The `e1000_rx_dequeue` guard in the
  harness is load-bearing: no leg drives the syscall side, so nothing else catches that
  edit.** Harness: `verify-netd-arbitration.sh` (needs `-DTINYOS_FAULT_INJECT`).
- **`irq-ctx` and `cpl3` are different questions — don't let one stand in for the
  other.** `knetd` runs with `IF=1` *and* at CPL 0, so a kernel where nothing moved to
  ring 3 still reports a healthy `N thread-ctx, 0 irq-ctx`. `handle_packet()` witnesses
  the ring from `%cs`, read from the hardware and **never from a software flag** — a flag
  records what the code believes about itself. `cpl3` must read **0**, and that is a
  **standing invariant, not a baseline awaiting inversion**: the parser move was
  withdrawn, so nonzero `cpl3` means the witness is broken or something moved that must
  not have. `handle_ip()` also witnesses per protocol, counted **before** any early
  return. Harness: `verify-netd-ring3.sh`; rationale in `doc/NETDAEMON_DESIGN.md`.
- **The ring-3 parser move (D1) is WITHDRAWN — don't restart it without reading
  "D1 re-scoped" in `doc/NETDAEMON_DESIGN.md`.** The plan asked "can this protocol move?"
  (privileged instructions, TX path, stack budget) and never asked **"what does moving
  buy?"** The criterion that decides it: *does ring 0 consume a result this parser
  produces, and act on it?* DNS, DHCP and ARP all do, so moving them relocates the parse
  and hands the trust straight back through a syscall a compromised daemon can call at
  will. **ICMP passes that test and still fails** a second one: *what capability does the
  moved component need?* A responder must reply, so it needs `SYS_NETTX` — and
  `e1000_send()` does **no source validation**, so that is unrestricted frame forgery
  (ARP poisoning, DHCP spoofing, TCP injection). Nothing is being moved to ring 3; the
  four PRs of prerequisites stay correct because none depended on the answer.
- **Four traps around kernel task lifetime**, each of which reads as healthy when
  wrong. `task_create_kernel()` allocates but does **not** enqueue — every caller needs
  `scheduler_add_task()`, or the task is created, listed by `ps`, counted by every
  status surface, and never runs one instruction. It grants `CAP_ALL` (`0xFFFFFFFF`),
  which **includes `CAP_UNKILLABLE`** — so every kernel task is unkillable, the explicit
  `|= CAP_UNKILLABLE` grants in `kernel.c` are no-ops, and a test that plans to `kill`
  one is grading a daemon that never died. And `task_exit()` is **inert** for
  scheduler-run tasks (it reads `process.c`'s `current_task`, set only by
  `task_switch_to`) — use `task_terminate(pid)`, capturing the pid first. Fourth: the
  post-context-switch reaper must `scheduler_remove_task_locked()` **before**
  `task_free_resources()`. A task that terminates *itself* defers the free to the reaper
  and is still linked in the ready queue; freeing the slot left a self-linked corpse
  there, and `scheduler_get_next_task()`'s later reject-and-remove hit the
  `task->next == task` case, which nulled head **and** tail and discarded every live
  task — panic "All tasks terminated" with five tasks alive. Invariant: *a freed slot is
  never in the ready queue*. Found by the supervisor give-up control, not by anything
  that existed before it.
- **Allocate before you disturb the array — `editor_insert_row`'s ordering is
  load-bearing.** It used to shift rows down *then* `pmm_alloc()`, so a failed
  allocation returned with `E.rows[at]` a bitwise copy of `E.rows[at+1]` — same
  `chars`, same `render`, both below `E.numrows`, both freed by
  `editor_cleanup()`. `pmm_free`'s double-free guard (`pmm.c:963`) refuses the
  second free, so the counter **falls** (2 frames lost per failed insert) rather
  than rising, and a surviving row reads back `NULL` — one OOM hiccup silently
  eats a line of the user's file. Three of the four callers append at
  `E.numrows`, where the shift loop is empty and no alias exists, which is
  exactly why this survived. Harness: `verify-editor-rowfail.sh` (needs
  `-DTINYOS_FAULT_INJECT`), whose arms all insert **mid-file** for that reason,
  and whose arm 1 is a positive control because "balanced frames" is otherwise
  satisfied by an editor that allocated nothing.
- **Teardown frees only what a `task_t` field names — including the ELF image.**
  `task_free_resources()` walks `task->*_phys[]` arrays and `pae_free_user_pdpt()`
  frees the PDs/PDPT/page tables; **nothing walks the PTEs to free what they point
  at**. That leaked the whole image on every exit — measured at exactly 8 frames
  per `exec /hello.elf`, its exact page count — and since `SYS_SPAWN` is ungated
  and the frames leak on *exit*, a spawn-and-wait loop drained memory while never
  holding two tasks at once, so the per-uid cap (which bounds *concurrent* tasks)
  never fired. Now tracked in `task_t::image_pages_phys[256]`. **The ordering is
  the invariant:** registration happens only on the success path, *after the last
  failure return* (in `elf.c`, registration sits below every `return -1`), because every failure path already
  `pmm_free`s these frames and *then* calls `elf_abort_load()` → `task_terminate()`
  → `task_free_resources()` — registering earlier makes that a double-free. Image
  frames are private `pmm_alloc()`s, so the COW kernel-shared-PT concern does
  **not** apply to them (that is about page *tables*); an oversize image is
  **refused**, never loaded untracked. Harness: `verify-exec-frame-leak.sh`,
  whose assertion is **exact equality** of free frames, not a smaller delta — a
  double-free shows as free frames *rising*.
- **Freeing a guard page requires restoring its mapping first.** They are
  identity-mapped **not present** in the kernel identity map every address space shares,
  so `pmm_free` without re-mapping poisons that frame permanently and the #PF lands on
  whoever `pmm_alloc()`s it next — nowhere near the task that died. The boot-time "no
  holes" check can't catch it (runtime hole). User tasks have one too.
- **`knetd` is supervised; the supervisor is `CAP_UNKILLABLE` and `knetd` is not.**
  `supervisor_run_once()` must use `task_get_validated(pid, generation)` — slots are
  recycled, so a bare `task_get()` can match a *different* task in the same slot and
  make a dead daemon look alive. The rate limit lives **inside** `supervisor_restart()`
  so no second restart path skips it. Its give-up branch **is** now exercised
  (`verify-supervisor.sh` step 5): `gave-up` rises, the line prints, and — the only
  independent part — a further injection parses **zero** frames, so the daemon provably
  stays dead. Step 5c asserts the RX counter is **pinned** while step 3 asserts it
  **rises**: same counter, opposite directions, don't reconcile them. The deaths come
  from `killknetd 8`, a countdown each restarted `knetd` decrements, because typing 8
  commands under TCG misses the 10 s window and missing it fails **silently** — a
  rolled-forward window reports `gave-up 0`, which is what a *broken* limiter reports
  too. Harness: `verify-supervisor.sh` (needs
  `-DTINYOS_FAULT_INJECT`, and `make clean`s on exit — that flag is not in the
  dependency graph, so its objects break the *other* harnesses at link time).
  Rationale in `doc/NETDAEMON_DESIGN.md`.
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
  **That future caller has now arrived and the placement paid off**: `SYS_CHMOD`
  (40) inherited the refusal with no uid test of its own — `sys_chmod` only maps
  ramfs's private sentinels (`-1` not-found, `-2` bad mode, `RAMFS_CHMOD_EPERM`)
  onto errnos, and passing them through raw would have handed ring 3 a `-1` its
  libc reads as `-EPERM`, inverting the two cases that matter. Don't add a second
  uid check at the boundary. Harness: `verify-ring3-chmod.sh`, whose two adjacent
  legs are deliberately **opposite** — the same unprivileged user must be refused
  on root's file and must succeed on their own — because a filter that refuses
  everything passes the exclusion half alone.
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

The **ring-3 shell is the default login shell** (PR #51); the kernel shell is the
fallback (`kshell` hands over, `exit` logs out). ~35 builtins against the kernel shell's
~70 — redirection, pipelines, credentials, `ps`/`kill`/`top`, `cp`/`mv`/`touch`,
`date`/`chmod`, the env/alias group, and
`clear`/`history`/`jobs`/`grep`/`find`/`man`/`whoami` have landed. Those last seven
needed **no new syscall**. `whoami` is the one to remember: it was deferred as needing a
uid→username path across the boundary, and that was wrong — `env_refresh_identity()`
already resolves the name kernel-side and exports it as `$USER`, so ring 3 reads its own
identity through `SYS_ENV` and there is no account-enumeration primitive to weigh (the
kernel resolves `self->uid` and nothing else). `unalias` genuinely did need surface —
`SYS_ENV` had no alias-delete subcommand — so it took a ninth
(`ENV_OP_ALIAS_UNSET`, 8) and shipped separately with an audit of `alias_unset`. `history`/`jobs` are
ring-3-local by design, not migrations: sharing the kernel shell's buffers would leak one
session's command lines to another user. The machine-state commands (`pae`,
`mem`, `wxaudit`, `auditlog`, networking and security tooling) stay kernel-shell only,
~20 of them by design — together they are an ASLR defeat (PR #58).

**`su` stays kernel-shell only — decided, not deferred.** PR #55 already refused
`SYS_SWITCH_USER` (15) from ring 3 with `-ENOSYS`, because a ring-3 caller must hold the
**plaintext password** to make the call — the exposure `SYS_CRED` (32) exists to remove,
since there the kernel prompts and reads the keystrokes itself. The alternative that
avoids the plaintext (a `CRED_OP_SU` where the kernel prompts) is worse: it hands ring 3
a way to **mutate its own uid in place**, and every ownership gate in the tree
(`SYS_CHMOD`, `SYS_TCPSOCK`, `task_visible_to_current()`, the per-uid task cap) is
written against that uid. Don't reopen this by "just adding a subcommand"; reasoning in
`doc/ROADMAP_NEXT.md`.

Roadmap items 1–3 (background jobs, SYS_SPAWN + pipes, FAT32 write) are **done**; item 4
(userspace shell) has all its **implementation** done — what remains is `edit`, a design
call, not typing (`su` is settled above; **`fatls` needed no migration** — ring 3 already
lists FAT32 through the generic `ls`, since `SYS_OPEN`/`SYS_READDIR` dispatch on the
drive letter into FAT32's full `file_operations_t`. `ls C:/` *is* `fatls`; harness
`verify-ring3-fatls.sh`. Third instance of asking "does THIS component carry it?"
instead of "is it reachable at all?" — after `whoami` and D1; trace the path before
designing the migration). `fork()` was skipped deliberately (PAE, no COW pages).
Task-slot exhaustion is closed (per-uid cap + root reserve, both returning `-EAGAIN`, so
only the printed message identifies which refused). `kprintf`→`stream_printf` conversion
is **finished** — no console-only blocks remain.

Invariants worth keeping in mind before touching these areas — each is the residue of a
real bug, and `doc/RING3_MIGRATION.md` has the reasoning and the harness traps:

- **Syscall gating polarity is a deliberate per-syscall decision, and the harness
  assertion inverts with it.** Ungated (`SYS_ENV`, `SYS_TIME`) — storage is per-task, so
  there is no foreign object and an unprivileged `-EPERM` is *the bug*. Ownership-gated
  (`SYS_TCPSOCK`, `SYS_CHMOD`) — an unprivileged caller *must* succeed on its own object.
  euid-gated (`SYS_NETRX`/`SYS_NETTX`) — raw frames are the whole segment's traffic.
  Copying an assertion between two of these inverts it; that has nearly happened
  repeatedly, so measure new legs as a **non-root** user.
- **An ownership harness needs a live *foreign* object.** "I can see my own socket"
  passes against a completely inert filter. `verify-netd-boundary.sh`'s root pass leaks a
  socket on purpose so exclusion is falsifiable — don't "clean up" that leak.
- **A socket/PID the caller cannot see is `-EBADF`/nonexistent, never `-EPERM`** — the
  errno must not enumerate the table. Same rule in `cmd_kill` and `sys_waitpid`.
- **`sys_psinfo` walks raw task slots** (`task_get_slot`), not `task_get_all`'s compacted
  output: it drops the lock between records, and a compacted index skips a task when an
  earlier one exits. The visibility check must read the fields in the **same** critical
  section that passed it, or a reused slot copies another user's name out.
- **`tcp_socket()` stamps `owner_uid` on *both* allocation paths** (fast scan and
  TIME_WAIT eviction retry) — `memset` zeroes it, and uid 0 is root. `tcp_recv()` takes
  `TCP_LOCK` **before** reading `in_use`/`state`/`rx_head`/`rx_tail`, since the IRQ path
  mutates the head/tail pair a torn read would drive the copy loop with.
- **Per-task env storage:** `pmm_alloc()` **does not zero**; `env_get`/`alias_get` copy
  out **under the lock** (a borrowed pointer is a use-after-unlock once the page is freed
  at task exit); `env_inherit_exported()` allocates the child's page directly, since
  `env_state_alloc()` resolves the *parent* and would copy the page onto itself; and
  `env_refresh_identity()` must be called from **both** `su` branches. Neither isolation
  nor inheritance is observable from the shell (`su` shares the task) — both are asserted
  in `sectest` TEST 10.
- **`open(O_TRUNC)` is witnessed by `stat`, not `cat`.** `cat` prints the same bytes
  either way; the symptom is the *size*. A `cat`-based harness passed against a build
  with the fix removed.

Security posture: `ids_inspect_payload()` scans every inbound IP payload and `secstatus`
reports a **match count** beside the signature count (a loaded count alone let the gap
read as protection). The login-spray detector counts **distinct usernames** per window,
alerts and never denies. Rationale in `doc/FIREWALL_AND_IDS_CONFIG.md`.

**`SYS_ENV` (41) carries the env/alias group to ring 3** — one syscall, nine
subcommands, a fixed-width `env_record_t` mirrored in `userspace/libc.h` with
`_Static_assert`s on both copies. **Ungated**, the opposite polarity to `SYS_CHMOD`
directly above it: storage is per-task, so a caller can only address its own table and an
unprivileged `-EPERM` is *the bug* — measure its harness as a non-root user. There is
deliberately **no subcommand taking a pid**. Two traps: `LIST` enumerates **by index**
(filled slot 1, hole 0) because `env_list()` prints through `stream_printf` and cannot
cross; and the syscall **alone ships a dead feature**, since `$VAR`/alias expansion lived
only in the kernel shell — `expand_aliases`/`expand_vars` in `userspace/shell.c` are part
of the same change. Harness: `verify-ring3-env.sh`.


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
