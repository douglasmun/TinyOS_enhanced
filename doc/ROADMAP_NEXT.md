# TinyOS — next improvements (planned 2026-08-06, post-v2.2)

Context: v2.2 shipped fbcon (VBE framebuffer console), userspace libc + VFS/FAT32
ELF exec, and blocking syscalls (SYS_SLEEP, SYS_WAITPID, wait-queue keyboard).
PR #26 merged (`d8d38b8`), release v2.2 cut and signed, web demo refreshed.

Priority order for the next round:

## 1. Real multitasking at the shell: background jobs
`exec foo.elf &`, `ps`, `kill` for user processes. `cmd_exec` currently blocks
until the child exits, so only one user process ever runs — the scheduler's
concurrency is invisible. Mostly plumbing that already exists (task table,
generations, exit records).

Follow-up in the same theme: make `sys_waitpid` block on a wait queue instead
of tick-polling (deferred review item — the exit-record ring stays as the
status store, the wait queue just replaces the poll).

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
- `unmap_page_range` is a no-op under PAE → failed ELF loads leak PT frames
- `cmd_exec` doesn't reap task/PDPT on `task_create_user` failure (`pid < 0`)
- user guard page isn't wired into the #PF handler (overflow gets generic fault)
- AUDIT-8E gap: IDS exists but isn't wired to anything at runtime

## Recommendation
Do 1 (+ hygiene) as the next PR — small, high-visibility, and everything later
builds on it.
