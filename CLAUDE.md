# TinyOS — project notes for Claude

Educational 32-bit (i386) Multiboot2 kernel in freestanding C + NASM. Single CPU,
interrupt-driven, round-robin scheduler with kernel threads and ring-3 user processes.
No kernel libc — only the kernel's own helpers (`util.c` memcpy/memset/strlen,
`kprintf`, etc.). Userspace has a tiny libc (`userspace/libc.{h,c}`, PR #26).

## To-do next (post-v2.2 roadmap)

Full plan with rationale: `doc/ROADMAP_NEXT.md`. Priority order:
1. ~~**Background jobs**~~ **DONE** — `exec foo.elf &` + `{parent_pid,
   parent_generation}` tracking + `jobs` builtin; `sys_waitpid` now blocks on a
   shared wait queue woken by `waitpid_notify_death()` (exit-record ring stays
   as the status store). `ps`/`kill` and zombie reaping already worked.
   Harness: `verify-bgjobs.sh` + `userspace/sleeper.c`.
2. ~~**SYS_SPAWN + pipes**~~ **DONE** — fd-aware I/O (PR #31), `SYS_SPAWN` +
   full argc/argv (#32), shell pipelines `cmd | cmd` (#33). `fork()` skipped
   deliberately (PAE, no COW pages).
3. ~~**FAT32 write support**~~ **DONE** — cluster alloc already existed; the
   missing half was the **dirent writeback** (data + FAT chain reached the disk
   but the directory entry still said "size 0, no cluster", so files read back
   empty after a remount). `fat32_file_t` now records `dirent_cluster` /
   `dirent_index` and `flush_dirent` updates size + first cluster on write and
   close. Also fixed: empty-file first-cluster allocation (a write at position
   0 with `first_cluster == 0` fell through to `cluster_to_sector(0)`, which
   underflows into the FAT/boot region), the cluster-advance branch,
   `fat32_seek` at an exact cluster boundary (broke append), and duplicate
   dirents from `fat32_create`. `fat32_vfs_open` now honours `O_CREAT`/`O_TRUNC`
   (it ignored `flags` entirely, which is why the write path was unreachable
   from the shell) and `cmd_write` routes an explicit `X:` prefix through the
   VFS. Harness: `verify-fat32-write.sh` (boots twice against ONE disk image;
   boot 2 must re-read the file and see a non-zero `fatls` size).
   Subdirectories landed later — see PR #47 under item 4.
4. **Userspace shell** (capstone, depends on 1–3 — now all done). **IN PROGRESS
   — the ring-3 shell is now the DEFAULT LOGIN SHELL (PR #51), with the kernel
   shell as a fallback.** It is not yet a replacement: ~13 builtins against the
   kernel shell's ~70, and nothing privileged (redirection and pipelines both
   landed in PR #52; a pipeline's stages must both be programs). The syscall
   foundation landed first, one group per PR:
   - PR #43 — per-process **fd table** + `SYS_OPEN`/`SYS_CLOSE`/`SYS_READDIR`/
     `SYS_STAT` (19–22).
   - PR #44 — `SYS_LSEEK` (24).
   - PR #45 — `SYS_MKDIR`/`SYS_RMDIR`/`SYS_UNLINK` (25–27), plus a `.unlink` op
     in `file_operations_t` and `vfs_unlink`. Wiring was the small half: both
     drivers already had mkdir/rmdir/unlink but **nothing outside the driver
     files ever called them** — FAT32's ops table exposed none of the three —
     so they were dead code carrying serious bugs that ring-3 reachability
     would have turned into corruption primitives. `fat32_rmdir` was literally
     `return fat32_unlink(path);` (no is-directory check, no emptiness check —
     it freed a directory's cluster chain while entries inside still pointed at
     those clusters); `fat32_unlink` matched on name alone so it deleted
     directories and **open** files; `fat32_mkdir` appended a duplicate dirent
     for an existing name, leaked the just-allocated cluster on every failure
     path after `allocate_cluster` (which marks it EOC **on disk**), and
     ignored the dirent-writeback return so it reported *success* for a
     directory that never reached the disk. All fixed in the same PR as the
     syscalls, deliberately — see "RAMFS node ownership" below for the other
     half. Harness: `verify-fsyscalls.sh` (covers **both** D: and C:; the
     refusal cases run on C: because that is where the dangerous bugs lived).
   - PR #46 — `SYS_GETCWD`/`SYS_CHDIR` (28–29) + per-process cwd, so relative
     paths resolve. The blocker was POSIX **r vs x**: RAMFS's hardened 0700
     root made a process's own default cwd (`D:/`) unreachable to uid 1000 —
     `chdir` needs only *search*, not *read*. Fixed with a new `.access_dir`
     VFS op (deliberately **not** `vfs_stat`, which demands r), a new
     `RAMFS_FLAG_EXEC`, and `/` at **0711** (searchable, still unlistable to
     non-root). Note a NULL `.access_dir` means *permitted* — fine for a driver
     with no ownership model, but FAT32 still needs its own op so `chdir` to a
     missing path is refused.
   - PR #47 — **FAT32 subdirectories**, which lifts the `-ENOSYS` `chdir` gate
     on non-root C: paths. Reads were already nested-capable (`fat32_open` and
     `find_dir_entry` walk components and full cluster chains); the whole gap
     was that every *mutating* op and the listing took the entire path as one
     filename and acted on `root_dir_cluster` unconditionally — so `C:/A/B`
     meant a root entry named `A/B` truncated to 8 chars. One shared
     `resolve_parent_dir()` closed it. Directories now also **grow past one
     cluster** (`dir_find_free_slot` allocates and rolls back on write
     failure), and three latent bugs that subdirectory reachability would have
     turned live were fixed in the same change: one-cluster-only duplicate
     scans (the same duplicate-dirent corruption class already fixed twice in
     this file), `fat32_mkdir` skipping the 8.3 extension split and hardcoding
     `..` to the root, and `fat32_unlink` not skipping LFN entries. Unlink and
     rmdir now clear the dirent **before** freeing the chain — a dangling name
     is more dangerous than a leaked chain. `fat32_list_root_cb` is now a
     wrapper over `fat32_list_dir_cb(path, ...)`; `cmd_fatls` takes a path.
   - PR #48 — **the ring-3 shell itself**, first migration step. The kernel
     shell was still the default at this point (PR #51 below changed that);
     `userspace/shell.c` (was a
     183-line vestigial stub with 4 hardcoded commands and a hand-rolled
     `_start`) is now a libc-based `main(argc, argv)` reached with
     `exec /shell.elf`. Builtins: `help echo pwd cd ls cat stat write mkdir
     rmdir rm id exit`, plus program launch with argv and `&` backgrounding.
     `src/kernel.c` seeds `/shell.elf` into RAMFS at 0755 (`shell_elf_data.h`
     was already included but never referenced). Deferred by design: pipes and
     redirection (need pipe/dup2 syscalls) and the privileged commands (`pae`,
     `mem`, `wxaudit`, `auditlog`, `useradd`, `passwd`, `shutdown`, net).
     Harness: `verify-usershell.sh` — unlike the other harnesses, commands
     arrive as **keystrokes into a ring-3 `read()`**, so PASS proves the
     interactive path (prompt, line editing, argv split, dispatch), and it
     asserts the `rmdir`-non-empty **refusal**, not just success paths.
     The shell must **echo the accepted line itself**: the kernel echoes
     keystrokes in the keyboard IRQ, which reaches VGA but NOT the serial log,
     so without it a serial transcript shows output with no commands — and the
     typist's `type_verified` echo-check has nothing to match.

   **User ESP is 16-byte aligned DOWNWARD on first entry to ring 3.**
   `switch_to_user_mode` (`src/context_switch.S`) does `and eax, 0xFFFFFFF0` on
   the user ESP before building the iret frame (SSE wants 16). That silently
   moves ESP *down* by up to 15 bytes, past the argc/argv block
   `task_create_user_argv` just wrote — crt0 then read argc from zeroed stack
   below the block, so `main` saw `argc == 0` and a garbage argv. Whether it
   bit depended on the total length of the argument strings, so `exec
   /hello.elf` and shell→spawner.elf→hello.elf happened to align and passed
   while `/hello.elf shellarg` did not. Fixed in `process.c` by biasing the
   block's alignment so the FINAL esp is already 16-aligned (the mask becomes a
   no-op); the bounds check gained 15 bytes of slack. Do not "simplify" the
   alignment bias away — pre-existing kernel bug, only reachable once a ring-3
   parent passed a variable-length vector.

   - PR #51 — **the ring-3 shell becomes the DEFAULT LOGIN SHELL.** Login now
     runs `launch_login_shell()` (`src/shell.c`) instead of dropping straight
     into the kernel command loop. It is a launcher **with a fallback**, not a
     swap: if `/shell.elf` is missing, unsigned, or fails to load, it returns
     non-zero and the kernel command loop runs, because a broken shell.elf must
     never cost the user their login.

     Three things make this work:
     - **`exit` = logout.** The ring-3 shell cannot return to a login prompt by
       itself; its parent can. The process exits, `launch_login_shell` returns,
       and `shell_task`'s session loop falls back around to the login prompt.
     - **`kshell` = hand over to the kernel shell**, via the child's **exit
       status** (`SHELL_EXIT_WANT_KERNEL_SHELL`, 70). A first attempt used a
       kernel-side `static bool`, which cannot work — the ring-3 shell is a
       separate process and cannot set a kernel variable. The status is the
       only channel a dying child already has.
     - **Credentials are inherited from the session.** `task_create_user`
       hardcodes uid 1000 for every user task, so a root login would otherwise
       be silently demoted. Set before `scheduler_add_task`, for the same
       reason `sys_spawn` sets parentage first: after that call the child can
       run on the very next tick.

     `tools/qemu_typist.py` now types `kshell` right after login by default, so
     the eight harnesses that drive the *kernel* shell keep working unchanged;
     `TINYOS_STAY_IN_RING3=1` skips it (only `verify-usershell.sh` sets it).
     Two harnesses had to change for real reasons, not cosmetics: see the
     `memset`/`wait_queue_init` fix under "Security work" for the page-fault
     class this made deterministic, and note `verify-redirect.sh` now waits on
     `[EXEC] Process completed` rather than `Process exited` — the latter is
     printed from the exit syscall with the whole teardown still to come, and
     keystrokes sent in that window are dropped because nothing is in `read()`
     yet.

   Redirection and pipelines are written up separately below because they are
   two distinct designs, but they shipped as ONE commit in PR #52 — "part 1"
   and "part 2" are sections of that single merge, not two of them.

   - PR #52, part 1 — **ring-3 redirection** (`>`, `>>`, `<`), via a new
     **`SYS_REDIRECT` (30)**. Deliberately **NOT `dup2`**: fds 0/1/2 are not in
     `task->fdtable` at all — they live in `task->streams`, which is what
     already models console/file/pipe backing and what `sys_spawn` inherits
     into a child. A `dup2` taking an fd from `SYS_OPEN` would have to convert
     a VFS fd into a stream and *still* would not compose with inheritance, so
     the primitive is the one the stream layer actually has: rebind a standard
     stream to a path (`sys_redirect(fd, path, REDIR_MODE_*)`).

     That choice is what makes ONE mechanism cover builtins and programs alike:
     the shell redirects **itself**, runs the command, and restores. Builtins
     write through `write(1, ..)` so they land in the file; a spawned child
     inherits the redirected stream at spawn time (`streams_inherit` in
     `sys_spawn`) so it lands there too, with no per-command plumbing.

     Two limitations are refused **explicitly** rather than silently misbehaving:
     a non-`D:` target gets **`-EXDEV`** (`STREAM_TYPE_FILE` is hard-wired to
     RAMFS — `stdout_write` calls `ramfs_write` directly and the redirect
     helpers call `ramfs_open`, so a `C:` path cannot be represented and must
     not be quietly written to `D:`), and redirecting **stderr** to a file gets
     **`-ENOSYS`** (there is no `stderr_redirect_to_file`, and no shell parses
     `2>`; adding a helper for syntax nothing emits would be untested code on a
     security-relevant path). `RESTORE` works on all three and is checked
     *before* everything else, so a shell can restore unconditionally in its
     cleanup path.

     **`>` and `>>` were both broken in the shared stream layer** and are fixed
     here — this is not new-feature-only work, and it affects the KERNEL shell
     too. `stdout_redirect_to_file` had a literal `(void)append;` TODO, so `>>`
     was indistinguishable from `>` and destroyed exactly the data the user
     asked to keep. `>` was wrong in the other direction: RAMFS has **no
     truncate flag** and `ramfs_write` only ever **grows** `node->size`, so `>`
     onto a longer existing file overwrote from offset 0 and left the old tail
     readable by the very next `cat`. Fixed with a new **`ramfs_truncate(fd)`**
     (zeroes the retained pages — a later re-growth must not expose the old
     contents through the gap) plus a seek-to-end for append.

     `cat` with no operands now copies **stdin**; it is the only thing in the
     shell that reads fd 0 on demand, and therefore the only way `<` is
     observable from a builtin.

     Harness: `verify-ring3-redirect.sh`. It asserts by **counting marker
     occurrences**, not presence: "the new text appeared" is also true of a
     `>>` that truncated, so only the count (alpha must appear 4 times, having
     survived the append) catches it. Truncation is checked **positionally** —
     no marker from before an overwrite may appear after it. And the decisive
     negative for the child case: `Hello from ELF!` must appear only *after*
     `cat h.txt` echoes, since a child that ignored the inherited redirection
     would print to the console and satisfy every positive check.

     **`split_args` splits at `>` and `<` mid-word**, so `echo a>b` redirects
     rather than passing one literal argument — matching the kernel shell
     (`shell_redir.c:123` stops a token at those characters). Two shells that
     disagree about an identical-looking line is worse than either behaviour on
     its own. The split cannot be done purely in place: the word before the
     operator needs its NUL exactly where the operator byte sits, so the
     operator and the rest of the line shift one byte right and the NUL goes in
     the gap. That needs a spare byte, which is why `split_args` takes the
     buffer **capacity** (not the string length) — `readline` can return a line
     that fills the buffer completely, and an all-operators line would otherwise
     walk off the end. Out of room, the operator stays glued and parses as an
     ordinary argument: degraded, never corrupt. Harness case: `r3-delta`,
     asserted via an occurrence with the operator **not** attached, since a
     shell that never split still echoes the whole glued string.

     **A redirected command gives the typist nothing to wait on.** With no
     expect string the typist sends the next command immediately — harmless
     after a builtin, but after `/hello.elf > h.txt` the shell is in `waitpid`
     through signature verification and a full address-space build, nothing is
     in `read()`, and the keystrokes are dropped. A bare `pwd` after it is a
     **barrier, not a check**. Same failure as the `[EXEC] Process completed`
     note in `verify-redirect.sh`, reached from the other side.

   - PR #52, part 2 — **ring-3 pipelines** (`a | b`), via a new
     **`SYS_PIPE` (31)**.
     Deliberately **NOT POSIX `pipe(int fd[2])`**, for the same reason
     `SYS_REDIRECT` is not `dup2`: the ends a shell has to connect are stdin and
     stdout, which are **not in `task->fdtable` at all** — they live in
     `task->streams`. So a pipe is named by an **opaque integer ID**, its
     `pipe_buffer_t` stays in **kernel memory and is never mapped into any user
     address space**, and ring 3 only ever asks the kernel to bind an end to one
     of *its own* streams. The blocking pipe layer itself already existed in
     `src/shell_redir.c` (wait queues, EPIPE on both entry and post-wakeup
     re-check) — the new work is ownership, lifecycle, and the shell driving it.

     Unlike the KERNEL shell's pipeline, which is **sequential** (run stage N to
     completion → buffer ≤4 KB → feed stage N+1; fine there, its stages are
     function calls), ring-3 stages are **processes**, so both run at once with
     real backpressure. That is why the harness moves ~11 KB through a 4 KB
     buffer: the producer *must* fill it, block, and be woken by the consumer.

     Ops: `CREATE` / `BIND_STDIN` / `UNBIND_STDOUT` / `CLOSE_WRITE` / `RESTORE`
     / `DESTROY`. Three of them are load-bearing in non-obvious ways:

     - **`UNBIND_STDOUT` is not a convenience.** A child inherits the shell's
       streams **as they are at spawn time** (`streams_inherit` in `sys_spawn`),
       so with stdout still on the write end when the **consumer** is spawned,
       the consumer writes its output into the very pipe it is reading — its
       report never reaches the console and it partly feeds itself. This shipped
       broken first and the harness caught it: both stages exited 0 and printed
       nothing. `RESTORE` cannot substitute — it resets **both** streams, and
       stdin must stay on the read end across that spawn.
     - **`CLOSE_WRITE` has no safe default.** Until it runs, a consumer that has
       drained the buffer **blocks** rather than seeing EOF, because more data
       could still arrive. Nothing in task teardown does it — a dying child's
       inherited streams are marked `borrowed` precisely so they never touch the
       creator's resources — so the shell must call it *after reaping the
       producer*. A harness **timeout is itself the signal** that this regressed.
     - **`RESTORE` is checked before the ID lookup** (as `REDIR_MODE_RESTORE` is),
       so a shell can restore unconditionally in a cleanup path even if the pipe
       is already gone. `UNBIND_STDOUT` is unconditional for the same reason.

     Ownership: each slot records `{owner_pid, owner_generation}`. The
     **generation** is what makes an ID safe to hand to ring 3 — a guessed ID
     from another process gets `-EPERM`, and pid recycling cannot be used to
     inherit a dead task's pipe. `task_pipes_cleanup()` runs in the task-teardown
     path next to `task_fdtable_cleanup` (`process.c`), closing the
     8-slot-exhaustion vector left by a shell that dies mid-pipeline.

     `pipe_init`'s **lossy fallback mode** (it silently DROPS data when it cannot
     allocate its wait-queue page) is **refused with `-ENOMEM`**, not shipped:
     `CREATE` checks `buf->readers`/`buf->writers` and fails rather than hand
     back a pipe that quietly eats output.

     Two things are refused **explicitly** rather than misbehaving: a **builtin
     stage** (a builtin runs inside the shell process, which cannot also be the
     other stage — the message points at `kshell`), and a **redirection on the
     piped end** (`a > f | b`, `a | b < f`), which would fight the pipe for the
     stream and make the undo unbind the pipe instead of the file.

     `spawn_stage` is **silent on failure by design** — at the moment the
     producer is spawned, stdout *is* the pipe, so a message printed there would
     be fed to the consumer as if it were the producer's output. Both callers
     report the returned errno once stdout is theirs again.

     Harness: `verify-ring3-pipes.sh`. Its decisive check is the **exact** line
     count (801 = 800 + the producer's own `done`), not `>=`: "data arrived" is
     also true of a pipe that truncated at `PIPE_BUFFER_SIZE`. Paired with the
     **negative** — no `pipe-line` may appear on the console, which a shell that
     ignored the pipe entirely would fail while satisfying every positive check.
     Also note `tools/qemu_typist.py`'s follow-up expect went 120s → 240s: a
     pipeline follow-up spawns two ECDSA-verified processes and then streams
     kilobytes between them under TCG, which the shorter window did not cover.

   Remaining: the privileged commands in ring 3.

Hygiene: the three exec-path items are **done** (failure paths now restore CR3
then `task_terminate`; `cmd_exec` deliberately does NOT double-reap; user guard
page armed via a new `user_guard_page_virt` field — CR2 is virtual for user
faults). **AUDIT-8E IDS-not-wired gap is still open.**

**RAMFS node ownership (PR #45)**: `alloc_node` used to hardcode `uid = gid = 0`.
That was invisible while only the kernel created nodes, but the default modes are
**0700 dirs / 0600 files** (owner-only, deliberate hardening — and there is **no
sticky bit**, by design), so once ring 3 could `mkdir`, a uid-1000 process got a
root-owned directory back and then `EACCES` opening its own directory. `alloc_node`
now takes the creator's credentials. The root node stays explicitly root-owned, and
boot-time setup still yields root-owned system binaries because it runs with no
current task (`ramfs_get_current_credentials` falls back to uid/gid 0). This
affected file creation too, not just mkdir. Corollary: a 0777 RAMFS directory
(e.g. the `/scratch` created at boot for the harness) permits cross-user deletion —
a real property of the model, not an oversight.

**`MAX_SYSCALL_NUM` must cover the highest syscall number**, not the highest in
its own comment block. It sat at 16 while `SYS_SLEEP` (17) and `SYS_WAITPID`
(18) had working dispatcher cases, so the range check rejected both and PR
#26's blocking syscalls were unreachable from userspace. Bump it when adding
syscalls.

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
- `-DTINYOS_TRACE_SYSCALLS` logs every syscall dispatch. **Off by default and it must
  stay that way**: with the shell at ring 3 the kernel console and the user's own
  output are the same serial stream, and `readline()` costs one syscall per keystroke,
  so a single typed command buries itself in trace lines. Useful when bringing up a
  new syscall. Same for the routine-FS-error `kprintf`s that used to live in
  `ramfs_vfs` mkdir/rmdir/unlink — a failed `rmdir` is a userspace error the caller
  already reports on its own stream, so printing it kernel-side double-reports it.
  Don't add per-operation `kprintf` to a path ring 3 can reach.

Build flags are all **explicitly named opt-outs, never defaults**:
`-DELF_PERMISSIVE_SIGNATURES` (warn-and-load unsigned binaries),
`-DTINYOS_FAST_KDF` (lower PBKDF2 iterations), `-DTINYOS_TRACE_SYSCALLS` (per-syscall
trace).

## Stack budgets (important)

The **default** shell runs as a kernel task (the ring-3 shell from PR #48 is opt-in via
`exec /shell.elf` and has its own user stack; this section is about the kernel one).
It is not on the 256 KB boot stack, and the entire
`exec` chain — `cmd_exec → elf_load_process → ecdsa_verify → task_create_user → PAE
page-table setup` — runs on that one kernel stack. The stack is now **128 KB**
(`KERNEL_TASK_STACK_PAGES = 32` in `process.h`); it was 64 KB, which the full
signed-`exec` chain overflowed into the guard page → #PF → #DF → **triple fault** (the
long-standing "`exec /hello.elf` triple-faults in ENFORCE mode" bug — see "ELF code
signing" below for the full root cause). Keep big locals off the task stack regardless:
an earlier related overflow silently corrupted the signature hash until `exec_buffer`
and `elf_load_process`'s `allocated_frames[4096]` were made `static`. ECDSA P-256 is
bit-serial and slow under QEMU/TCG, but that is a speed cost, **not** a correctness or
fault issue — the verify completes and passes.

## FIXED: intermittent `Invalid TSS esp0` panic on `exec` (isr.S EAX clobber)

Separate from the stack-overflow triple-faults above. `exec /hello.elf` intermittently
(~1/9 boots) panicked with `Invalid TSS esp0: misaligned pointer` — the user task's
kernel stack came out as e.g. `0x00398018` (base `0x390018`, low `0x18` bits set),
which `tss_set_kernel_stack` rejects. Root-caused and fixed 2026-07-05, **merged to
`main` via PR #11** (merge `f24b391`, fix commit `2247c7b`, doc `ad3f825`).

**Root cause — `src/isr.S` `isr_common` reloaded the kernel data selector
(`mov ax,0x18`) BEFORE `pusha`.** Any interrupt taken while a live value sat in EAX had
its low 16 bits stamped with `0x0018` before the register was saved; `pusha` then
snapshotted the corrupted EAX and `iret` restored it. `pmm_alloc_contiguous` returns
`base<<12` (e.g. `0x390000`) in **EAX — the ABI return register** — live across the
interrupt-enabled return path; a timer IRQ in that window turned it into `0x390018`,
an unaligned kernel-stack base → `tss.esp0` panic. The `0x18` is **deterministic** (the
constant selector, not a timing tear); only *whether* the IRQ lands in the window is
timing-dependent (hence intermittent). This silently corrupts the low word of EAX for
**any** code preempted with a live value there — general, not allocator-specific.

**Fix:** move `pusha` before the `mov ax,0x18` segment-reload block so EAX is snapshotted
intact. Stack layout is unchanged (`push ds/es/fs/gs` then `pusha`; epilogue untouched),
so `interrupt_regs_t` and the return path are unaffected. `syscall.S` was already safe
(it `push eax`es before the selector reload). A **Makefile post-link objdump guard**
now fails the build if `isr_common` ever regresses to reloading `%ax` before `pusha`.

**Two OS bugs found while auditing for the same class, also fixed in the commit:**
(1) the #PF stack-overflow self-kill (`idt.c:247 task_terminate(current)`) freed the 8
kernel-stack frames the fault handler was still running on — now defers self-exit
resource/slot free to the post-switch reaper when `task == current` (the clean-exit
`sys_exit` ZOMBIE path was already safe); (2) `scheduler_get_next_task` only rejected
TERMINATED entries — now gates on `task_slot_is_live()` (valid ptr + pid + current
generation, accept only READY/RUNNING) so a stale/freed/recycled ready-queue entry's
`kernel_stack` never reaches `tss_set_kernel_stack`.

**WRONG theory, for the record:** this was first mis-diagnosed as a compiler floating
`pmm_alloc_contiguous`'s `base<<12` past an inline `popf` (a preemption tear of the
return value), "fixed" with a register-pin macro (`PMM_CRITICAL_EXIT_RET`). The panic
recurred with the **identical** `0x390018` and the pin objdump-verified present — a
deterministic value cannot be a timing tear, which is what pointed to the ISR. The pin
is kept as churn-neutral defense-in-depth with a corrected comment, but it is **not**
what fixed the panic. **Verified: 53/53 clean boots** (30+15+8), zero panics, zero
misaligned bases, vs the prior ~1/9 failure rate.

## Security work

All security history is layered; the index is `doc/SECURITY_STATUS_COMPLETE.md`. The
latest pass is the **Layer 5 multi-agent audit (June 2026)** in
`doc/MULTI_AGENT_SECURITY_AUDIT_2026.md` — 73 verified findings, 78 fixes. The full
security-mechanism reference is `doc/SECURITY_HARDENING.md`.

- **ELF code signing**: trusted-key pinning is wired (`src/trusted_signing_key.h`,
  matching `keys/tinyos_dev_signing_key.pem`, gitignored). Verification works end to end
  and is **runtime-verified under default ENFORCE mode** (2026-06-14): hash PASS ->
  signature PASS -> signed `hello.elf` runs in ring 3, its syscalls succeed
  ("Hello from ELF!"), it `exit(0)`s and is reaped — zero triple faults.
  **CORRECTION (2026-06-14):** the long-standing "`exec` triple-faults in ENFORCE mode"
  bug was **NOT** crypto-under-preemption. An earlier note here claimed it was
  "preemption corrupting in-flight P-256 state (not a stack overflow — `-fstack-usage`
  ~1.6 KB)" and that masking the verify fixed it. That was wrong on both counts: the
  ~1.6 KB figure measured only the ECDSA subtree in isolation, missing the *cumulative*
  exec chain on the single shell kernel stack. Reading QEMU's `-d int,cpu_reset` trace
  showed the ECDSA verify *completes and passes*; the fault came afterward. The real
  causes were four OS bugs, all now fixed and verified:
  (1) **kernel-stack overflow** — the 64 KB shell stack couldn't hold the full exec
  chain (commit `a10a006`; now 128 KB + early #PF overflow detection);
  (2) **`tss.ss0` was the kernel *code* selector `0x10` instead of *data* `0x18`** — the
  first ring3→ring0 syscall #TS-faulted loading SS (commit `b8510ca`);
  (3) **user stack guard page never armed** — PTE looked up in kernel tables, not the
  user PDPT (commit `51e4f36`);
  (4) two **EDR false-positive detectors** spamming alerts (commits `9020d82`,
  `1064331`).
  `elf_verify_signature` does still run the verify with interrupts masked
  (`disable/restore_interrupts`); that is harmless preemption-safety but was **not** what
  made ENFORCE usable. The build **enforces signatures by default** (fail-closed:
  unsigned/tampered binaries rejected); the embedded `hello`/`shell` binaries carry valid
  `TINYOS_SIG_V1` trailers, so a normal build boots and execs them. ECDSA P-256 is ms on
  real hardware but slow under QEMU/TCG (a speed cost, not a fault) — for fast local dev
  that accepts unsigned binaries, build `-DELF_PERMISSIVE_SIGNATURES` (warn-and-load), an
  explicitly named opt-out, never the default. Re-sign userspace binaries with
  `tools/sign_elf.py`, regenerate embedded arrays with `tools/elf_to_c.py`. The
  `verify-exec.sh` harness at the repo root reproduces the end-to-end ENFORCE run
  (GUI QEMU; you log in and type `exec /hello.elf` by hand). For a **fully
  automated, headless** check use `auto-verify-exec.sh`: it boots a fresh blank
  disk, drives the whole first-boot flow (password setup → root login → decline
  regular-user → shell → `exec /hello.elf`) by scripting QEMU-monitor `sendkey`
  via `tools/qemu_typist.py`, and prints PASS only on `Signature verification:
  PASS` + `Hello from ELF!` + zero triple fault. Override the throwaway login
  password with `TINYOS_TEST_PASSWORD`. Slow under TCG (PBKDF2 + bit-serial
  ECDSA) — allow several minutes.

- **OPEN: first-`exec`-after-login intermittent Hash mismatch (sha256 preemption).**
  Separate from the fixed triple-faults above. `exec /hello.elf` as the FIRST command
  after login occasionally fails signature verification, passes on retry. ROOT-CAUSED
  2026-06-14 with a timing-neutral per-4KB page-sum probe before the hash: the hashed
  INPUT is byte-for-byte correct on a failing run, yet `sha256()` returns a wrong (and
  run-to-run different) digest → the corruption is in sha256's stack-local working state
  (`sha256_ctx_t` carried across init/update/final), clobbered when an IRQ/softirq/
  context-switch preempts the long hash — same class as the masked ECDSA/PBKDF2.
  FIX (elf.c:199, under verification, **not yet committed/proven**): wrap the sha256 call
  in `disable_interrupts()/restore_interrupts()`. Identical masking was tried once before
  and "passed then recurred", so it's only durable after 5+ failing-prone first-exec boots
  with zero mismatch — use `firstexec-trial.sh`. If it still fails, move the masking INTO
  sha256/the crypto layer. (The earlier-dropped attempt was rejected for the WRONG reason —
  "exec_buffer has no .bss neighbor"; the corruption was never in exec_buffer.)

- **FIXED: `memset`/`wait_queue_init` kernel page fault on a `pmm_alloc`'d frame.**
  Was logged here as a *rare boot-time* fault (EIP=`memset`, CR2 a low frame, "PD
  present, PT walk ends not-present"). Making the ring-3 shell the default login
  shell turned it **deterministic**: that shell builds and tears down a full
  address space before the first file is created, which moves the PMM free list
  past the range the boot identity map happens to cover. `pmm_alloc()` returns a
  **physical** address, and three call sites dereferenced it directly —
  `ramfs.c` `alloc_node` (the documented one), `ramfs_write`'s `data_pages`
  allocation, and `shell_redir.c` `pipe_init`'s wait-queue page. Fixed by
  map-before-touch at all three, following the `pae.c:215-255` pattern.
  **Map into the KERNEL address space explicitly** —
  `pae_map_page_into(pae_get_kernel_pdpt(), ...)`, not `pae_map_page()`: nodes are
  created from exec paths that run with a **user PDPT loaded**, so `pae_map_page`
  would write the entry into the user's tables (copy-on-writing a kernel-shared
  page table on the way, see "User address space" below) and leave the kernel's
  own mapping absent. Harnesses: `verify-pipes.sh` and `verify-redirect.sh` both
  panicked before the fix and pass after.

- **Password hashing**: PBKDF2 is always **100,000 iterations** (OWASP), decoupled from
  `-DTINYOS_DEV` (a build-speed flag) — pass `-DTINYOS_FAST_KDF` to lower it explicitly.
  The interrupt masking around PBKDF2 is **load-bearing**: a preempted derivation
  corrupts the shared `crypto_ws` workspace (adjacent to `user_database`), wiping the
  user DB so login fails with "user not found".

- **CSPRNG reseed masking**: `csprng_random_bytes` generates keystream inside a
  `CRITICAL_SECTION` so nothing rewrites `ctx->state/counter` mid-stream. `csprng_reseed`
  must do the same — `csprng_periodic_reseed` runs it from the timer softirq in **task
  context with interrupts enabled**, so an unmasked reseed could tear/duplicate keystream
  from the generator backing password salts, ECDHE key material, ASLR, DNS/TCP randomness
  (SSH DH was also a consumer before SSH was removed from the build, commit `87cd874`).
  The mask in `csprng_reseed` is load-bearing; do not remove it (critical sections nest,
  so the call from inside `csprng_random_bytes` is fine).

- **User address space — page-table copy-on-write (commit `1596a04`)**: userspace links
  at `0x08000000` (PD[0] index 64), which falls inside the kernel's identity-mapped low
  range. `pae_create_user_pdpt` copies all of the kernel's `PD[0]` entries into the user
  PDPT *by value*, so user PD[0] slots initially share the kernel's identity-map page-table
  frames. Writing a user PTE into a shared PT would clobber the kernel's own mapping and
  corrupt whatever `pmm_alloc`'d frame it resolves (RAMFS/FAT32 nodes, `exec_buffer`) —
  this was the cause of intermittent FS corruption (flaky `ls`), exec hash mismatches, and
  the "first `exec` after login fails, retry works" symptom. **`pae_map_page_into` now
  copy-on-writes**: if a user PDE still points at the kernel-shared PT for that slot, it
  clones a fresh private PT (copying the kernel entries) before writing the user PTE, so the
  kernel identity map is never mutated by exec. Do not "optimize" this back to writing the
  shared PT directly.

- **FAT32 `ls C:` output routing (commit `f6074a2`)**: shell commands print via
  `stream_printf(get_current_streams())` (the user's shell stream), NOT `kprintf` (the
  kernel console). `ls C:` looked empty because `fat32_list_root()` printed every entry via
  `kprintf`, which the shell session didn't show. The FAT32 driver stays stdio-agnostic: it
  exposes `fat32_list_root_cb(emit, ctx)` (per-entry callback, `fat32_dir_emit_t`);
  `fat32_list_root()` is a kprintf wrapper for kernel logging, and `cmd_fatls` passes a
  `stream_printf` emitter. When adding user-facing FS output, route through the shell stream,
  not `kprintf`.

## Not compiled (don't audit/fix)

`kernel_old.c`, `keyboard_old.c`, `tls13_demo.c`, `secure_delete.c` are not in the
build. `lib/python3.12/` is a vendored venv, not project code. `kernel_old.c` and
`keyboard_old.c` were accidentally committed to the public repo and have since been
untracked + gitignored (removed from GitHub; kept on disk only).

## Published & documented

This repo is PUBLISHED at https://github.com/douglasmun/TinyOS_enhanced (public).
Some local-only branches/commits must never be pushed; the publish allow-list and
the reasons are tracked in the private publish notes (memory `tinyos-publish-setup`),
not here. Demo ISO = the `v2.0` GitHub Release
asset. `publish.sh` (gitignored) and the push workflow are documented in memory
`publish-push-gotchas`. Security docs (curated set under `doc/`):
- `SECURITY_HARDENING.md` — now the full security reference: stack guard, ASLR, lazy
  FPU, PAE/W^X, **kernel-only credential store (no /etc/shadow)**, **ELF signing**,
  **secure boot**, **crypto hardening**, **HW-RNG health**, **tamper-evident audit
  log**, **copy_user**, **guard pages/TSS**, **auth hardening**, **net anti-spoofing**,
  **PMM double-free/capabilities** (17 mechanisms total).
- `FIREWALL_AND_IDS_CONFIG.md` — firewall/IDS are compile-time only (no runtime CLI);
  notes the AUDIT-8E IDS-not-wired gap.
- `USER_GUIDE.md` — boot/login/shell/networking walkthrough.
- Networking: NAT (10.0.2.x) works end-to-end; bridged 192.168.0.x impossible on this
  Mac (Wi-Fi can't be vmnet-bridged) — see memory `qemu-networking-wifi-limit`.
