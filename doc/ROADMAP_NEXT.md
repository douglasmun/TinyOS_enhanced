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

## 3. FAT32 write support
FS story is read-only persistence today. Cluster allocation + directory-entry
update + `vfs_write` wiring means the editor can save to `C:` and files
survive reboot. Biggest bang for making it feel like an OS rather than a demo.

## 4. Move the shell to userspace (capstone)
Deferred design item; depends on 1–3 (shell needs spawn, waitpid, file
syscalls to live in ring 3). Once done, the kernel/user boundary becomes
architecturally honest — the kernel stops containing its own UI. Largest
item; do last.

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
- AUDIT-8E gap: IDS exists but isn't wired to anything at runtime — STILL OPEN
  (unrelated to the exec path; split out deliberately).

## Recommendation
1 (+ hygiene) is done. Next PR: 2 (SYS_SPAWN + pipes).
