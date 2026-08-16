# Kernel bug root causes — the ones worth remembering

Fixed bugs whose *diagnosis* is reusable: each one names a class of mistake that
can recur elsewhere in the tree. Where a wrong theory was held first, it is kept
on the record — knowing what the symptom did NOT mean is most of the value.

## FIXED: intermittent `Invalid TSS esp0` panic on `exec` (isr.S EAX clobber)

`exec /hello.elf` intermittently (~1/9 boots) panicked with `Invalid TSS esp0:
misaligned pointer` — the user task's kernel stack came out as e.g. `0x00398018`
(base `0x390018`, low `0x18` bits set), which `tss_set_kernel_stack` rejects.
Root-caused and fixed 2026-07-05, merged via PR #11 (merge `f24b391`, fix commit
`2247c7b`, doc `ad3f825`).

**Root cause — `src/isr.S` `isr_common` reloaded the kernel data selector (`mov
ax,0x18`) BEFORE `pusha`.** Any interrupt taken while a live value sat in EAX had
its low 16 bits stamped with `0x0018` before the register was saved; `pusha` then
snapshotted the corrupted EAX and `iret` restored it. `pmm_alloc_contiguous`
returns `base<<12` (e.g. `0x390000`) in **EAX — the ABI return register** — live
across the interrupt-enabled return path; a timer IRQ in that window turned it
into `0x390018`, an unaligned kernel-stack base → `tss.esp0` panic.

The `0x18` is **deterministic** (the constant selector, not a timing tear); only
*whether* the IRQ lands in the window is timing-dependent, hence intermittent.
This silently corrupts the low word of EAX for **any** code preempted with a live
value there — general, not allocator-specific.

**Fix:** move `pusha` before the `mov ax,0x18` segment-reload block so EAX is
snapshotted intact. Stack layout is unchanged (`push ds/es/fs/gs` then `pusha`;
epilogue untouched), so `interrupt_regs_t` and the return path are unaffected.
`syscall.S` was already safe (it `push eax`es before the selector reload). A
**Makefile post-link objdump guard** now fails the build if `isr_common` ever
regresses to reloading `%ax` before `pusha`.

**Two OS bugs found while auditing for the same class, fixed in the same commit:**

1. the #PF stack-overflow self-kill (`idt.c:247 task_terminate(current)`) freed
   the 8 kernel-stack frames the fault handler was still running on — now defers
   self-exit resource/slot free to the post-switch reaper when `task == current`
   (the clean-exit `sys_exit` ZOMBIE path was already safe);
2. `scheduler_get_next_task` only rejected TERMINATED entries — now gates on
   `task_slot_is_live()` (valid ptr + pid + current generation, accept only
   READY/RUNNING) so a stale/freed/recycled ready-queue entry's `kernel_stack`
   never reaches `tss_set_kernel_stack`.

**WRONG theory, for the record:** first mis-diagnosed as a compiler floating
`pmm_alloc_contiguous`'s `base<<12` past an inline `popf` (a preemption tear of
the return value), "fixed" with a register-pin macro (`PMM_CRITICAL_EXIT_RET`).
The panic recurred with the **identical** `0x390018` and the pin objdump-verified
present — a deterministic value cannot be a timing tear, which is what pointed to
the ISR. The pin is kept as churn-neutral defense-in-depth with a corrected
comment, but it is **not** what fixed the panic. Verified 53/53 clean boots
(30+15+8), zero panics, vs the prior ~1/9 failure rate.

## FIXED: `exec` triple-fault in ENFORCE mode — four OS bugs, not crypto

**CORRECTION (2026-06-14):** an earlier note claimed this was "preemption
corrupting in-flight P-256 state (not a stack overflow — `-fstack-usage` ~1.6 KB)"
and that masking the verify fixed it. That was wrong on both counts: the ~1.6 KB
figure measured only the ECDSA subtree in isolation, missing the *cumulative* exec
chain on the single shell kernel stack. Reading QEMU's `-d int,cpu_reset` trace
showed the ECDSA verify *completes and passes*; the fault came afterward.

The real causes, all fixed and verified:

1. **kernel-stack overflow** — the 64 KB shell stack couldn't hold the full exec
   chain (commit `a10a006`; now 128 KB + early #PF overflow detection);
2. **`tss.ss0` was the kernel *code* selector `0x10` instead of *data* `0x18`** —
   the first ring3→ring0 syscall #TS-faulted loading SS (commit `b8510ca`);
3. **user stack guard page never armed** — PTE looked up in kernel tables, not the
   user PDPT (commit `51e4f36`);
4. two **EDR false-positive detectors** spamming alerts (commits `9020d82`,
   `1064331`).

`elf_verify_signature` does still run the verify with interrupts masked
(`disable/restore_interrupts`); that is harmless preemption-safety but was **not**
what made ENFORCE usable.

## FIXED: first-`exec`-after-login intermittent hash mismatch (sha256 preemption)

`exec /hello.elf` as the FIRST command after login occasionally failed signature
verification and passed on retry. Root-caused 2026-06-14 with a timing-neutral
per-4KB page-sum probe before the hash: the hashed **input** was byte-for-byte
correct on a failing run, yet `sha256()` returned a wrong (and run-to-run
different) digest → the corruption was in sha256's stack-local working state
(`sha256_ctx_t` carried across init/update/final), clobbered when an
IRQ/softirq/context-switch preempted the long hash — same class as the masked
ECDSA/PBKDF2.

Fixed by masking interrupts around the sha256 call (commit `240269c`, 5/5
verified), plus an EDR `has_run_before` gate and `task_get_any`. Harness:
`firstexec-trial.sh`. An earlier attempt at the identical masking had been dropped
for the WRONG reason — "exec_buffer has no .bss neighbor"; the corruption was
never in exec_buffer.

## FIXED: `memset`/`wait_queue_init` kernel page fault on a `pmm_alloc`'d frame

Was logged as a *rare boot-time* fault (EIP=`memset`, CR2 a low frame, "PD
present, PT walk ends not-present"). Making the ring-3 shell the default login
shell turned it **deterministic**: that shell builds and tears down a full address
space before the first file is created, which moves the PMM free list past the
range the boot identity map happens to cover.

**`pmm_alloc()` returns a physical address**, and three call sites dereferenced it
directly — `ramfs.c` `alloc_node` (the documented one), `ramfs_write`'s
`data_pages` allocation, and `shell_redir.c` `pipe_init`'s wait-queue page. Fixed
by map-before-touch at all three, following the `pae.c:215-255` pattern.

**Map into the KERNEL address space explicitly** —
`pae_map_page_into(pae_get_kernel_pdpt(), ...)`, not `pae_map_page()`: nodes are
created from exec paths that run with a **user PDPT loaded**, so `pae_map_page`
would write the entry into the user's tables (copy-on-writing a kernel-shared page
table on the way) and leave the kernel's own mapping absent.

Harnesses: `verify-pipes.sh` and `verify-redirect.sh` both panicked before the fix
and pass after. A related boot-time variant was the PAE identity-map pool being too
small (32→128 tables, commit `75cc8ae`, 10 boots clean).

## FIXED: user ESP 16-byte aligned DOWNWARD on first entry to ring 3

`switch_to_user_mode` (`src/context_switch.S`) does `and eax, 0xFFFFFFF0` on the
user ESP before building the iret frame (SSE wants 16). That silently moves ESP
*down* by up to 15 bytes, past the argc/argv block `task_create_user_argv` just
wrote — crt0 then read argc from zeroed stack below the block, so `main` saw
`argc == 0` and a garbage argv.

Whether it bit depended on the total length of the argument strings, so `exec
/hello.elf` and shell→spawner.elf→hello.elf happened to align and passed while
`/hello.elf shellarg` did not.

Fixed in `process.c` by biasing the block's alignment so the FINAL esp is already
16-aligned (the mask becomes a no-op); the bounds check gained 15 bytes of slack.
**Do not "simplify" the alignment bias away** — pre-existing kernel bug, only
reachable once a ring-3 parent passed a variable-length vector.

## FIXED: user address space — page-table copy-on-write (commit `1596a04`)

Userspace links at `0x08000000` (PD[0] index 64), which falls inside the kernel's
identity-mapped low range. `pae_create_user_pdpt` copies all of the kernel's
`PD[0]` entries into the user PDPT *by value*, so user PD[0] slots initially share
the kernel's identity-map page-table frames.

Writing a user PTE into a shared PT would clobber the kernel's own mapping and
corrupt whatever `pmm_alloc`'d frame it resolves (RAMFS/FAT32 nodes,
`exec_buffer`) — this was the cause of intermittent FS corruption (flaky `ls`),
exec hash mismatches, and the "first `exec` after login fails, retry works"
symptom.

**`pae_map_page_into` now copy-on-writes**: if a user PDE still points at the
kernel-shared PT for that slot, it clones a fresh private PT (copying the kernel
entries) before writing the user PTE, so the kernel identity map is never mutated
by exec. **Do not "optimize" this back to writing the shared PT directly.**

Note the user PDPT must copy **all 4 PDs** (the framebuffer lives in PD[3]).

## FIXED: FAT32 `ls C:` output routing (commit `f6074a2`)

Shell commands print via `stream_printf(get_current_streams())` (the user's shell
stream), NOT `kprintf` (the kernel console). `ls C:` looked empty because
`fat32_list_root()` printed every entry via `kprintf`, which the shell session
didn't show.

The FAT32 driver stays stdio-agnostic: it exposes `fat32_list_root_cb(emit, ctx)`
(per-entry callback, `fat32_dir_emit_t`); `fat32_list_root()` is a kprintf wrapper
for kernel logging, and `cmd_fatls` passes a `stream_printf` emitter. **When adding
user-facing FS output, route through the shell stream, not `kprintf`.**

## FIXED: FAT32 write support — the dirent writeback

Cluster allocation already existed; the missing half was the **dirent writeback**.
Data and the FAT chain reached the disk but the directory entry still said "size
0, no cluster", so files read back empty after a remount. `fat32_file_t` now
records `dirent_cluster`/`dirent_index` and `flush_dirent` updates size and first
cluster on write and close.

Also fixed: empty-file first-cluster allocation (a write at position 0 with
`first_cluster == 0` fell through to `cluster_to_sector(0)`, which underflows into
the FAT/boot region), the cluster-advance branch, `fat32_seek` at an exact cluster
boundary (broke append), and duplicate dirents from `fat32_create`.
`fat32_vfs_open` now honours `O_CREAT`/`O_TRUNC` (it ignored `flags` entirely,
which is why the write path was unreachable from the shell) and `cmd_write` routes
an explicit `X:` prefix through the VFS.

Harness: `verify-fat32-write.sh` — boots twice against ONE disk image; boot 2 must
re-read the file and see a non-zero `fatls` size.

## RAMFS node ownership (PR #45)

`alloc_node` used to hardcode `uid = gid = 0`. That was invisible while only the
kernel created nodes, but the default modes are **0700 dirs / 0600 files**
(owner-only, deliberate hardening — and there is **no sticky bit**, by design), so
once ring 3 could `mkdir`, a uid-1000 process got a root-owned directory back and
then `EACCES` opening its own directory.

`alloc_node` now takes the creator's credentials. The root node stays explicitly
root-owned, and boot-time setup still yields root-owned system binaries because it
runs with no current task (`ramfs_get_current_credentials` falls back to uid/gid
0). This affected file creation too, not just mkdir.

Corollary: a 0777 RAMFS directory (e.g. the `/scratch` created at boot for the
harness) permits cross-user deletion — a real property of the model, not an
oversight.

## Task-creation rate limiter never refilled at the configured rate

Found 2026-08-16 while building `verify-slotcap.sh`. Pre-existing, and independent
of the concurrent-task cap added in the same change.

`task_rate_limit_check()` (`src/process.c`) is a token bucket documented as "burst
of 10, sustained 5/sec". The refill computed:

```c
uint32_t refill_periods = ticks_since_refill / TASK_RATE_LIMIT_REFILL_INTERVAL;
uint32_t tokens_to_add = (refill_periods * TASK_RATE_LIMIT_REFILL_PER_SEC) /
                         (1000 / TASK_RATE_LIMIT_REFILL_INTERVAL);
```

`REFILL_INTERVAL` is 100 ticks and the PIT runs at 100 Hz (`pit_init(100)` in
`kernel.c`), so one period is exactly one second and the refill should simply be
`periods * 5`. The extra `/ (1000/100)` == `/10` made one elapsed second add
`(1 * 5) / 10` == **0 tokens** in integer arithmetic. The bucket only gained
tokens when a single check happened to see **≥2 seconds** elapse.

Compounding it, `task_rate_last_refill = now` discarded the leftover ticks on every
refill, so the partial second never accumulated toward the next one.

Net effect: after the initial burst of 10, task creation was denied far more
aggressively than the documented 5/sec. Not a security hole — it fails closed —
but it is the reason the first run of `verify-slotcap.sh` saw the RATE limiter
refuse at 9 spawns while the concurrent cap (10) was never reached.

Fixed to `refill_periods * TASK_RATE_LIMIT_REFILL_PER_SEC`, advancing
`task_rate_last_refill` by whole periods so the remainder carries.

**Why this matters for the harness**: both limiters return `-EAGAIN`, so an
assertion on the errno alone cannot tell them apart — and the wrong one firing
produced a count that looked exactly right. `verify-slotcap.sh` therefore asserts
the cap's own message (`already holds N tasks (limit M)`), not just the errno.

## FIXED: child processes did not inherit the caller's credentials

Found 2026-08-16, one layer down from the bug above and by the same harness: the
cap fired correctly but reported **`uid 1000`** in a session where `useradd` had
just assigned the user **uid 1002**.

`task_create_user` hardcodes `task->uid = task->euid = 1000` (`process.c:1089`),
leaving it to the caller to overwrite with the real owner. `launch_login_shell`
(`shell.c:1017`) does exactly that. **Neither path that creates a child did** —
`sys_spawn` (`syscall.c`) and `cmd_exec` (`shell_fileops.c`) both carefully
inherited streams (and, in spawn's case, parentage and cwd) while silently
skipping credentials.

Both had to be fixed. Fixing only `sys_spawn` left the bug fully live, because
the harness types `kshell` and so reaches task creation through `cmd_exec` — the
second run after the "fix" reported the identical wrong uid, which is what
pointed at the second call site.

So every child of every user ran as **uid 1000 regardless of who spawned it**:

- a uid-1002 process got a uid-1000 child, which could read and write uid-1000's
  files — a privilege boundary crossed by spawning, with no setuid bit involved;
- conversely a child could be *less* privileged than a parent whose uid was not
  1000, breaking the "a child is exactly its parent" expectation the rest of the
  model assumes;
- and every user's children pooled into a single uid for accounting, so under the
  new per-uid task cap one user's spawns consumed another user's quota.

Fixed by copying `uid`/`gid`/`euid`/`egid` from the caller at both sites, set
**before `scheduler_add_task`** for the same reason parentage is: the child can
run on the very next tick.

In `cmd_exec` the copy is deliberately **not** gated on `!background`, unlike the
adjacent `streams_inherit`. That gate exists because streams are a shallow fd
copy with a lifetime problem; credentials have no such relationship, and a
backgrounded child must run as its user just as a foreground one does.

Latent for the usual reason — while the only interesting user was the uid-1000
default, "hardcoded 1000" and "inherited" were indistinguishable. It became
observable the moment a harness created a user with a different uid.

## OPEN: a re-logged-in ring-3 session never receives keyboard input

Found while building `verify-ring3-ps.sh` (2026-08-16). The harness needed an
unprivileged ring-3 shell, and the obvious route — `logout` from the ring-3
shell, then log back in as the test user — reaches one. The session starts
correctly: `shell.elf` is loaded, ECDSA-verified, the process is created, and it
prints its banner and prompt. Then it ignores input entirely.

Reproduced twice, deterministically: 15 keystrokes sent over ~2.7s produced not
one echoed character, and the serial log ends exactly at the `D:/ $ ` prompt with
the shell parked in `read()`. The same keystrokes work in the *first* ring-3
session of the same boot, so this is specific to a session reached through
logout + login, not to ring-3 input generally.

Not diagnosed further, because it is not on the path the ps/kill/top work
touches. What is known:

- it is not the typist's per-character echo verification. That check is itself
  unsound in the ring-3 shell (see below) and the failure reproduces with the
  commands sent unverified, waiting only on their results;
- the second session is a normally-created user task — the ELF load and process
  creation log lines are identical to the first session's;
- so the suspicion is keyboard/stream routing: whatever binds the console input
  stream to the foreground session is not re-bound after the first ring-3 shell
  exits and login runs again.

`verify-ring3-ps.sh` works around it by reaching the unprivileged shell through
`kshell` → `su` → `exec /shell.elf` instead, which lands in a second ring-3 shell
that has inherited the test user's credentials. The workaround is documented at
the sequence in that script so it is not mistaken for an arbitrary choice.

### Corollary: the typist's echo verification is unsound in the ring-3 shell

`type_verified()` checks that each typed character appears, in order, anywhere in
the serial stream after a mark. The ring-3 shell does not echo keystrokes to
serial at all — the kernel echoes them in the keyboard IRQ, which reaches the VGA
console only; the shell echoes the *accepted line* after `readline()` returns.
Those per-character checks were therefore passing on coincidental matches in the
surrounding kernel chatter: `p`, `s`, and the letters of `useradd r3user` all
occur constantly in boot output. `/slothold.elf` was simply the first command
containing a character (`.`) rare enough not to appear by luck, which is how a
check that had never actually verified anything finally announced itself.

Ring-3 commands should be sent with the `!` (unverified) prefix and an expect on
their **result**, which is a stronger check than a per-character echo that
unrelated output can satisfy.

## FIXED: `open(O_TRUNC)` was a no-op on the RAM disk

`ramfs_vfs_open()` translated only the **access mode** of the `VFS_O_*` flags into
`ramfs_open`'s `uint8_t` of `RAMFS_FLAG_*`. `VFS_O_TRUNC` is `0x0200` and cannot be
represented in that byte at all, so the flag was validated by `sys_open`, carried
intact through `vfs_open`, handed to the driver — and then silently dropped.

Because `ramfs_write` only ever **grows** `node->size`, the consequence was data
corruption rather than a missing feature: rewriting a long file with a short one left
the previous tail in place, inside `node->size` and still reachable by `read()`. This
hit the shipping ring-3 `write` builtin, which has always passed `O_TRUNC`.

`stdio.c` had already hit exactly this for `>` and fixed it **locally** by calling
`ramfs_truncate()` itself (`stdout_redirect_to_file`). That fixed redirection and left
every other `open(O_TRUNC)` caller broken — which was every ring-3 user of the flag,
since userspace has no other way to ask for truncation. FAT32 was never affected:
`fat32_vfs_open` has always honoured the flag.

The fix is three lines in `ramfs_vfs_open`, after the `ramfs_open` call succeeds.

**The part worth remembering is how it hides.** `cat` cannot witness this bug:

```
write /p.txt AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA   (30 A's)
write /p.txt BBB
                       fix disabled      fix enabled
stat /p.txt            size=31           size=4
cat  /p.txt            BBB               BBB
```

The content check passes in both directions. An earlier version of
`verify-ring3-fileops.sh` asserted on `cat` and returned a full PASS against a build
with the fix reverted — `objdump` confirmed the shipped `kernel.elf` had zero
`ramfs_truncate` calls in `ramfs_vfs_open`. Only `stat` exposes it, because the
symptom **is** the size. Both `cat` assertions are kept in the harness on purpose, as
a standing demonstration that they cannot fail.

Generalises: when a bug's symptom is metadata, assert on metadata. A content check
that passes with the fix removed is not a weak test, it is not a test.
