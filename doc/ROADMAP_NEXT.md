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

## 2. SYS_SPAWN + pipes
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

## 4. Move the shell to userspace (capstone) — IN PROGRESS
Deferred design item; depends on 1–3 (shell needs spawn, waitpid, file
syscalls to live in ring 3). Once done, the kernel/user boundary becomes
architecturally honest — the kernel stops containing its own UI. Largest
item; do last.

**Landed so far:** the ring-3 shell is the default login shell (PR #51), with
redirection, pipelines, the credential commands, `ps`/`kill`/`top`, and
`cp`/`mv`/`touch` — ~25 builtins against the kernel shell's ~70.

**The remaining gap is smaller than the raw count suggests.** Of the ~36
commands the ring-3 shell lacks, roughly 20 are machine-state and security
tooling (`pae`, `mem`, `aslr`, `wxaudit`, `auditlog`, the networking stack)
that **should stay kernel-only**: PR #58 gated them behind `require_root`
precisely because `pae`+`mem`+`aslr`+`wxaudit` together are an ASLR defeat
readable by any user. Exposing them to ring 3 would re-open that. `exec` is
not a gap either — the ring-3 shell already spawns `.elf` files directly.

What is genuinely left is one coherent group needing **new syscalls**:
`env`/`export`/`set`/`unset`/`alias` (needs an environment the kernel can
hand across the ring boundary), `chmod`, and `date`. Each adds ring-3-reachable
kernel surface, so it belongs in its own PR with its own audit — see the
recurring lesson in CLAUDE.md that exposing a path to ring 3 turns latent bugs
into corruption primitives (PRs #45, #47, #54, #55).

Doing `cp`/`mv`/`touch` also surfaced a live kernel bug in a shipping builtin:
`open(O_TRUNC)` was a no-op on the RAM disk. See `doc/KERNEL_BUGS.md`.

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

## Recommendation
1, 2 and 3 are done. Next: 4 (move the shell to userspace) — its stated
dependencies (spawn, waitpid, file syscalls) are now all in place. AUDIT-8E is
closed on both halves and was independent of that work.
