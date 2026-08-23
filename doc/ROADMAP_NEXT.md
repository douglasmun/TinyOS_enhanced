# TinyOS — next improvements (planned 2026-08-06, post-v2.2)

Context: v2.2 shipped fbcon (VBE framebuffer console), userspace libc + VFS/FAT32
ELF exec, and blocking syscalls (SYS_SLEEP, SYS_WAITPID, wait-queue keyboard).
PR #26 merged (`d8d38b8`), release v2.2 cut and signed, web demo refreshed.

Priority order for the next round:

## 1. Real multitasking at the shell: background jobs — DONE
`exec foo.elf &` returns to the prompt immediately; the child is tracked by a
`{parent_pid, parent_generation}` pair on `task_t` and listed by the new `jobs`
builtin. `ps`/`kill` already covered user processes, and the scheduler already
reaped unwaited children, so neither needed changes. `sys_waitpid` now blocks
on a shared wait queue woken by `waitpid_notify_death()` (from both `sys_exit`
and `task_terminate`) instead of tick-polling; the exit-record ring stays as
the status store. `cmd_exec`'s foreground path calls `sys_waitpid` rather than
keeping a second hand-rolled poll loop.

Found and fixed along the way: `MAX_SYSCALL_NUM` was still 16 while `SYS_SLEEP`
(17) and `SYS_WAITPID` (18) had working dispatcher cases, so the range check
rejected both — the blocking syscalls added in PR #26 were unreachable from
userspace.

Test harness: `verify-bgjobs.sh` + `userspace/sleeper.c` (~6 s runtime, so a
backgrounded child is still alive when the next shell command runs; with
`hello.elf` an empty `jobs` would be indistinguishable from a broken
implementation).

## 2. SYS_SPAWN + pipes — DONE
`spawn(path, argv)` syscall so processes can start processes — makes the
userspace libc more than a demo. Then a pipe object over the existing
wait-queue machinery gives shell pipelines (`cat file | grep x`).
Deliberately skip `fork()`: under PAE with no COW pages it's a swamp; spawn
gives 90% of the educational value.

## 3. FAT32 write support — DONE
Files written to `C:` now survive a reboot. `fat32_write` already allocated
clusters, but nothing wrote the result back into the **directory entry**, so
the data and the FAT chain reached the disk while the dirent still said
"size 0, no first cluster" — after a remount the file read back empty. The
descriptor now records where its 8.3 entry lives (`dirent_cluster`,
`dirent_index`) and `flush_dirent` pushes size + first cluster back on write
and on close.

Four further write-path bugs were fixed alongside it:
- **Empty file never allocated.** A freshly created file has
  `first_cluster == current_cluster == 0`; the old allocation test
  (`current_cluster >= EOC || at a cluster boundary`) was false at position 0,
  so the write fell through to `cluster_to_sector(0)`, which computes
  `(0-2)*sectors_per_cluster` and underflows into the FAT/boot-sector region.
  The first cluster is now allocated up front.
- **Cluster advance.** The old "move to next cluster" branch `continue`d and
  relied on the top-of-loop test to allocate, which re-read the boundary
  condition and could allocate twice. Advance/extend is now explicit.
- **`fat32_seek` at an exact cluster boundary** walked one cluster too far and
  hit EOC — precisely the append case (seek to EOF of a file whose size is a
  multiple of the cluster size). It now stops on the last existing cluster.
- **`fat32_create` allowed duplicates** — creating an existing name appended a
  SECOND dirent with the same 8.3 name; `find_dir_entry` returned the first, so
  the duplicate's clusters became unreachable. It now refuses, and recycled
  (`0xE5`) slots are zeroed so no stale cluster/timestamp fields survive.

Wiring: `fat32_vfs_open` ignored its `flags` entirely, so `VFS_O_CREAT` on a
nonexistent `C:` file just returned ENOENT — the write path was unreachable
from the shell even though `fat32_write` existed. It now honours `O_CREAT` and
`O_TRUNC` (new `fat32_truncate` frees the chain so a shorter rewrite doesn't
leave the previous tail behind), and `fat32_vfs_close` propagates flush
failures as `VFS_EIO` instead of discarding them. `cmd_write` routes an
explicit `X:` prefix through the VFS (it was hard-wired to `ramfs_open`, so
`write C:/F.TXT` silently made a RAMFS file); bare paths keep RAMFS behaviour.

Test harness: `verify-fat32-write.sh` — boots QEMU **twice against the same
disk image**. Boot 1 writes and reads back; boot 2 is a fresh kernel that must
re-read the same content, confirm `fatls` reports a non-zero size (the
assertion that specifically catches a missing dirent writeback), and overwrite
with a shorter body to prove `O_TRUNC` truncates. Credentials are kernel-only
and not persisted, so both boots re-run first-boot setup while the FAT32
volume persists.

Still limited to the **root directory** and to `fat32_create`'s first root
cluster; subdirectory creation and multi-cluster root scans remain future work.

## 4. Move the shell to userspace (capstone) — CLOSED
Deferred design item; depends on 1–3 (shell needs spawn, waitpid, file
syscalls to live in ring 3). Once done, the kernel/user boundary becomes
architecturally honest — the kernel stops containing its own UI. Largest
item; do last.

**Landed so far:** the ring-3 shell is the default login shell (PR #51), with
redirection, pipelines, the credential commands, `ps`/`kill`/`top`, and
`cp`/`mv`/`touch`.

**The new-syscall group named below as "what is genuinely left" is now DONE**
(updated 2026-08-18). All three landed: `SYS_TIME` (39, `date`), `SYS_CHMOD`
(40) and `SYS_ENV` (41, the whole `env`/`export`/`set`/`unset`/`alias` group).
Each is wired dispatcher → libc → builtin and carries its own harness
(`verify-ring3-chmod.sh`, `verify-ring3-env.sh`). `MAX_SYSCALL_NUM` is 41.
**Nothing outstanding in item 4 requires a new syscall.**

**The remaining gap is smaller than the raw count suggests**, and splits three
ways. Roughly ten commands are machine-state and security tooling (`pae`,
`mem`, `aslr`, `wxaudit`, `auditlog`, `secstatus`, `sectest`, the networking
stack, `reboot`/`shutdown`/`mount`) that **should stay kernel-only**: PR #58
gated the first four behind `require_root` precisely because
`pae`+`mem`+`aslr`+`wxaudit` together are an ASLR defeat readable by any user.
Exposing them to ring 3 would re-open that. `exec` is not a gap either — the
ring-3 shell dispatches any word ending `.elf` straight through `spawn()`, so
there is no verb to migrate.

What is genuinely left splits by whether it needs kernel surface, and that
line falls in a different place than a first pass suggests.

**Six need none, and are DONE** (2026-08-18): `clear`, `history`, `jobs`,
`grep`, `find`, `man` — all pure userspace over syscalls that already exist.
Note that `history` and `jobs` are **not migrations**: the kernel shell's
history buffer (`src/shell_history.c`) and `cmd_jobs` (which walks the kernel
task table) are kernel-shell state. The ring-3 shell keeps its own, which is
also the more correct answer — a shared history buffer would leak one session's
command lines, arguments included, into another user's listing. Harness:
`verify-ring3-builtins.sh`.

**One looked like it belonged in that group and did not** — `unalias`.
`SYS_ENV`'s eight subcommands included no alias-delete, and `alias_unset()`
existed in `src/env.c:1015` but was unreachable from ring 3. It shipped in its
own PR with a ninth subcommand (`ENV_OP_ALIAS_UNSET`, 8) and an audit of the
newly-exposed `alias_unset()` — which came back clean: locked, bounds-checked,
and NULL-safe because `alias_find()` rejects a NULL state and returns -1 before
any dereference.

`whoami` was listed alongside it and that was wrong, twice over. The claim was
"there is no uid → username path across the boundary at all"; the per-struct
facts behind it hold (`psinfo_t` does carry a numeric uid and a *process* name,
and `SYS_CRED` does only passwd/useradd/userdel) but the conclusion does not,
because none of those is the path. `env_refresh_identity()` (`src/env.c:457`)
already resolves `user_find_by_uid(self->uid)` **kernel-side** and stores the
result in `$USER`, exported — so ring 3 reads its own username through
`SYS_ENV`/`ENV_OP_GET` with no new surface at all.

The second error was the security concern raised with it: that exposing
uid → username would let a user enumerate the account table. It cannot. The
kernel resolves `self->uid` and nothing else, so there is no argument to point
at another account, and the one string returned is the caller's own identity —
which they already have. `whoami` therefore shipped as a pure-userspace builtin
with the six above, reading `$USER` via `env_get_var()`.

### Item 4: the `su`/`fatls`/`edit` group

All implementation work on item 4 is finished. These three are what is left,
and they are **decisions, not typing**.

**`su` — DECIDED 2026-08-18: stays kernel-shell only. Not a deferral.**

This is not a new call so much as a confirmation of one already made in PR #55,
which is why it needs no further design work. `SYS_SWITCH_USER` (15) exists and
its ring-3 dispatch case is **refused with `-ENOSYS` by default**, deliberately.
The reason is structural and cannot be fixed by hardening the implementation: a
ring-3 caller must hold the **plaintext password** to make the call, so the
secret passes through a user address space and a syscall argument register.
That is precisely the exposure `SYS_CRED` (32) was built to remove — there the
kernel prompts and reads the keystrokes itself, so the plaintext never enters
ring 3 at all.

A ring-3 `su` would therefore have to be one of:

1. `SYS_SWITCH_USER` re-enabled from ring 3 — reintroduces the plaintext-in-
   register exposure PR #55 closed. Rejected.
2. A new `CRED_OP_SU` on `SYS_CRED`, with the kernel prompting for the password
   itself. This avoids the plaintext exposure, but hands ring 3 a syscall that
   **changes the calling task's credentials in place**. Every `task->uid` check
   in the kernel — the ownership gates on `SYS_CHMOD` and `SYS_TCPSOCK`, the
   `task_visible_to_current()` predicate, the per-uid task cap — is written
   against a uid that a compromised ring-3 shell could then move. Rejected: the
   value is one convenience builtin; the cost is making a central invariant
   mutable from the untrusted side.
3. Leave it in the kernel shell. **Chosen.** `kshell` is one command away, the
   kernel shell's `su` calls `sys_switch_user()` directly rather than through
   `int 0x80`, and nothing about it is broken.

Note this is the same criterion that killed the ring-3 parser move (D1) and
that mis-deferred `whoami`: *what does moving it buy, and what capability does
the moved component need?* Here it buys one builtin and needs the ability to
mutate the identity every other gate is written against.

**`fatls` — DECIDED 2026-08-19: nothing to migrate. Ring 3 already lists FAT32
through the generic `ls`.**

The question as recorded ("gating polarity, plus the cross-drive behaviour in
`doc/CROSS_DRIVE_ACCESS_ANALYSIS.md`") presumed the capability had to be
carried across the boundary. It does not: the path is already complete and
already compiled in.

```
cmd_ls -> open(path, O_RDONLY|O_DIRECTORY)      [SYS_OPEN 20]
       -> syscall_copy_path -> task_resolve_path
             (drive-qualified paths are returned VERBATIM — the
              `drive_qualified` branch copies and returns before any
              cwd prefix can be joined on)
       -> vfs_open -> vfs_resolve_drive('C')
       -> fat32_file_ops.readdir == fat32_vfs_readdir   [SYS_READDIR 22]
```

FAT32 registers the **full** `file_operations_t` (`src/fat32_vfs.c`), `C:` is
mounted at boot (`kernel.c`), and the VFS dispatches on the drive letter rather
than on a hardcoded driver. So `ls C:/` **is** `fatls`, with no new syscall and
no new builtin. Verified end to end as an unprivileged user:
`verify-ring3-fatls.sh`.

The gating polarity question answers itself once the path is seen: FAT32 has no
per-file uid, so there is nothing for an ownership gate to compare, and the
listing is reachable by a non-root caller exactly as `ls D:/scratch` is. The
kernel shell keeps its `fatls` because `ls C:` routes to `cmd_fatls` there;
that is a kernel-shell implementation detail, not a capability ring 3 lacks.

This is the **third** instance of one error shape, and the count is the reason
it is written down rather than just fixed. `whoami` was deferred for a
uid→username path that `env_refresh_identity()` already provided; the D1
parser move survived four PRs of feasibility work before one grep killed it;
`fatls` was carried as an open design call while the code to do it was already
linked into the kernel. Each time the question asked was *"does THIS component
carry the capability?"* — psinfo_t, then a protocol parser, then a builtin —
when the question that decides it is *"is the capability REACHABLE AT ALL?"*
Component-by-component review cannot answer that, because the answer lives in a
path that runs through no single component in particular. Trace the path before
designing the migration.

**`edit` — DECIDED: stays kernel-shell only.** Not deferred; the blocking
constraint is structural rather than a matter of surface still to be written.

The concern this entry used to carry — *"a ring-3 editor needs a way to write
back that does not simply re-expose the FAT32 write path"* — turned out to be
the wrong question, in exactly the way `whoami`, D1 and `fatls` were. Ring 3
can **already** write back to both drives with no new surface: `sys_write`
(`syscall.c:350`) routes any fd `>= TASK_FD_BASE` through `vfs_write`, which
dispatches on the fd's registered `file_operations_t` with no drive test of its
own (`vfs.c:829`), and FAT32 registers a live `.write = fat32_vfs_write`
(`fat32_vfs.c:632`). Nothing needed re-exposing, because `SYS_OPEN` +
`SYS_WRITE` are the FAT32 write path already — the same VFS dispatch that
settled `fatls`. (The `-EXDEV` refusals in `sys_chmod` and `sys_redirect` are
real, but neither is the write path: chmod has no FAT32 analogue, and the
stream layer's `STREAM_TYPE_FILE` is hard-wired to RAMFS. An editor holds its
own fd and touches neither.) Note also that `editor.c` contains **zero** FAT32
references — it is RAMFS-only today, so the ring-3 version would start with
*more* reach than the kernel one, not less.

What actually blocks it is **input**, and it is not a missing syscall. The
editor is event-oriented: `editor.c:745` calls `keyboard_getchar_nonblock()`
and switches on out-of-band codes the keyboard driver invents — `KEY_UP` is
`0x90` (`keyboard.h:54`), outside ASCII precisely so it cannot collide with
text. Ring 3 reads the console through `sys_read` ‒ `stdin_read`, whose
`STREAM_TYPE_CONSOLE` case (`stdio.c:320`) is **line-oriented**: it blocks in
`keyboard_getchar()` and returns only on `\n` or a full buffer, interpreting
just `\n` and `\b` and storing every other byte as text. A `0x90` therefore
arrives as an ordinary character *inside a line*, delivered only once the user
presses Enter. There is no non-blocking read, no timeout, no poll, and no
per-keystroke echo — `userspace/shell.c` echoes the whole accepted line after
`readline()` returns. All three raw-key consumers in the tree (`shell.c:1223`,
`editor.c:745`, `shell_monitor.c:240` — the shell, the editor, `top`) are
kernel-side for this reason.

So the capability a ring-3 editor needs is a **raw/cbreak mode**: per-keystroke
delivery, no line assembly, an escape or scancode encoding both sides agree on,
and echo control. That is a TTY discipline — `stdin_read`'s own comment already
says fixing the echo gap "means a real TTY discipline, not a printf here" — and
it is a new, ring-3-reachable kernel subsystem carrying per-task terminal
state, mode restoration on abnormal exit (an editor killed in raw mode leaves
the *next* shell unusable), and interaction with the existing stream and
redirection layers. Applying the standing test: what moving `edit` **buys** is
one builtin; what it **costs** is a terminal subsystem plus its audit. That is
the worst ratio of any item in this group, and `top` — the other raw-key
consumer — stays kernel-shell-only on the same reasoning without anyone having
proposed moving it.

This closes item 4. If a TTY discipline is ever wanted for its own sake, `edit`
becomes reachable as a consequence — but it must be that PR's *justification*,
not a rider on this one, and it needs its own audit (CLAUDE.md: exposing a path
to ring 3 turns latent bugs into corruption primitives).

Item 4 is now closed: `su`, `fatls` and `edit` are all settled above, and none
of the three ended up being a migration. One fact about the kernel shell's `su` outlives that decision and is
worth keeping here, because it stays true of the implementation that remains:
it changes credentials on the **same** task, so it must call
`env_refresh_identity()` on **both** branches — the root fast path and the
password-authenticating one. Fixing only the branch a harness drives leaves the
other lying, which is exactly the bug PR B found (`$USER` still reading `root`
after an `su`).

Any future item that *does* add ring-3-reachable kernel surface belongs in its
own PR with its own audit — see the recurring lesson in CLAUDE.md that exposing
a path to ring 3 turns latent bugs into corruption primitives (PRs #45, #47,
#54, #55).

Doing `cp`/`mv`/`touch` also surfaced a live kernel bug in a shipping builtin:
`open(O_TRUNC)` was a no-op on the RAM disk. See `doc/KERNEL_BUGS.md`.

### The env group is split in two, and the first half is not a migration

> **BOTH HALVES SHIPPED** (updated 2026-08-18). PR A woke the subsystem in the
> kernel shell; PR B added `SYS_ENV` (41), libc and the ring-3 builtins. Kept
> because the reasoning still explains why the split was necessary and why the
> isolation check lives where it does — read the two PR labels below as history,
> not as planned work.


`chmod` and `date` were each one PR: the kernel behaviour already existed and
only had to cross the ring boundary. **`env` is not like that** — the subsystem
was dead. `env_init()` sat commented out in `kernel.c` ("TEMPORARILY DISABLED
FOR TESTING") from the initial public release, while every consumer stayed
wired: alias substitution in `shell.c`, `$VAR` expansion, all six builtins
dispatched. So the commands existed, ran, and printed `(no variables)` forever
without erroring. Migrating that to ring 3 would have carried a dead subsystem
across the boundary and produced a ring-3 shell whose `env` printed nothing —
indistinguishable from a syscall bug.

Hence **PR A (this one): make it work in the kernel shell.** Re-enable the
defaults, and settle storage — which had no uid or task concept at all, two
file-scope 16-entry arrays. Storage is now **per-task**, a `pmm_alloc()`'d page
hanging off `task_t` (the `edr_advanced` pattern; embedding it would have cost
~102 KB of `.bss` at `MAX_TASKS 32`, charged to tasks that never touch an
environment variable). **PR B: the syscall + libc + ring-3 builtins.**

The trap PR A had to work around, and PR B inherits: **per-task isolation is
not observable from the shell in this build.** `su` changes credentials on the
*same* task, so both users share one env page; there is no re-login path in the
typist; and ring 3 has no env syscall yet. "Set FOO, read FOO back" passes
identically under global, per-uid and per-task storage. The check therefore
lives in the kernel — `env_pertask_self_test()`, `sectest`'s TEST 10 — and its
verdict is three-way, because a child whose page allocation *failed* also sees
none of its parent's variables and would pass a two-way check for the wrong
reason. `SYS_ENV` has since landed, and `verify-ring3-env.sh` asserts the group
from ring 3 (9/9); the kernel self-test is now the redundant-but-cheap half.
Note it still does **not** witness per-task isolation — `su` shares the task, so
that check remains `sectest` TEST 10's job.

## Hygiene (fold into whichever PR comes first)
Known, low-severity, from the PR #1 audit (see memory `exec-failure-path-leaks`):
- ~~`unmap_page_range` is a no-op under PAE → failed ELF loads leak PT frames~~
  DONE, but not as scoped: `pae_free_user_pdpt` already did this work correctly,
  and the real leak was the whole task + PDPT, not just PT frames. Failure paths
  now restore CR3 and call `task_terminate` (order is load-bearing — CR3 must be
  restored before teardown frees the tables the CPU translates through).
  `unmap_page_range`'s PAE branch is documented as legacy-paging-only.
- ~~`cmd_exec` doesn't reap task/PDPT on `task_create_user` failure (`pid < 0`)~~
  DONE — and `cmd_exec` deliberately does NOT reap: `elf.c` owns its teardown,
  so a second reap here could hit a recycled slot.
- ~~user guard page isn't wired into the #PF handler~~ DONE — required adding
  `user_guard_page_virt` to `task_t`; only the *physical* address was stored,
  but user faults report CR2 as a *virtual* address.
- ~~AUDIT-8E gap: IDS exists but isn't wired to anything at runtime~~ DONE for
  the network half — `ids_inspect_payload()` matches inbound payloads against
  the signature table, and `secstatus` reports match count alongside signature
  count so a dead matcher is distinguishable from a quiet network. Harness:
  `verify-ids-signature.sh`. The host half is now closed too, but by
  *subtraction* as much as addition: `ids_register_login_failure()` was written
  to catch a horizontal credential spray (distinct usernames per window — the
  case `user.c`'s per-account lockout cannot see), while
  `ids_analyze_syscall()` and `ids_check_fork_bomb()` were **deleted**, since
  `edr_behavioral_check()` and the per-uid task cap already own those and
  enforce rather than observe. Harness: `verify-ids-spray.sh`.

## Networking / network isolation — CLOSED, and not on this roadmap's terms
This roadmap predates the network-isolation work entirely, so nothing below was
ever one of its items. Recorded here only so the roadmap is not read as the
complete picture of what is outstanding.

The plan lived in `doc/NETWORK_ISOLATION.md` and `doc/NETDAEMON_DESIGN.md`. Its
prerequisites all landed and are independently correct: RX parsing moved to task
context on `knetd`, netd arbitration, the CPL witness, `knetd` supervision, and
per-packet print removal across the RX path, `icmp.c` and `dns.c`.

**Its destination — item 4 there, moving the protocol parsers to ring 3 — was
withdrawn on 2026-08-17 (PRs #81, #82).** Do not restart it without reading
"D1 re-scoped" in `doc/NETDAEMON_DESIGN.md`. In short: DNS, DHCP and ARP each
produce a result ring 0 consumes and acts on, so moving them relocates the parse
and hands the trust straight back through a syscall the untrusted side can call
at will; and ICMP, which passes that test, fails a second one — a responder must
reply, so it needs `SYS_NETTX`, and `e1000_send()` does no source validation, so
that is unrestricted frame forgery in exchange for ~60 lines of echo parse.

One consequence worth not undoing: `cpl3 == 0` in `verify-netd-ring3.sh` is now a
**standing invariant**, not a baseline awaiting inversion. Nonzero on any
protocol means the witness is broken or something moved that must not have.

## Recommendation
1, 2 and 3 are done. Next: 4 (move the shell to userspace) — its stated
dependencies (spawn, waitpid, file syscalls) are now all in place, as is the
new-syscall group it once blocked on. The seven no-new-syscall builtins are
done, and `unalias` has since landed with the ninth `SYS_ENV` subcommand it
needed. Item 4 is **closed**: `edit` is decided and stays kernel-shell only (it needs a
raw-input TTY discipline, not a syscall — its write-back was already reachable);
`su` is decided and stays kernel-shell only; and
`fatls` needed no migration at all — ring 3 already lists FAT32 through the
generic `ls` (see "Item 4: the su/fatls/edit group" above). AUDIT-8E is
closed on both halves and was independent of that work. Networking is closed too
(see above), and likewise never gated item 4.
