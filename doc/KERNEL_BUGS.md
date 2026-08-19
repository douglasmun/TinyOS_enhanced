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

---

## FIXED: `chmod` did not check ownership — any user could re-permission any file

`ramfs_chmod` masked setuid/sgid/sticky (`mode &= RAMFS_PERM_MASK`) but never
compared the caller to `node->uid`, and `cmd_chmod` (`shell_fileops.c`) did not
check either. Every other ramfs mutation routes through
`ramfs_check_permission()` — open, create, unlink — and chmod was the single
one that did not.

That gap is reachable because `kshell` is deliberately ungated (`shell.c:1119`):
the ring-3 shell has no privileged commands, so a user who needs `passwd` or
`useradd` types `kshell`. From there, any user could rewrite the mode of any
file. Confirmed at runtime before the fix:

```
$ id                     uid=1002(chmoduser) gid=100 euid=1002 egid=100
$ cat /secret.txt        cat: /secret.txt: No such file or directory   <- 0600, denied
$ chmod 666 /secret.txt  chmod: '/secret.txt' -> rw-rw-rw-
$ cat /secret.txt        ROOTONLYDATA                                  <- escalated
```

The first `cat` is the point: permissions **are** enforced on the read path, so
the mode bits are load-bearing, and the ability to rewrite them at will defeats
the entire scheme. The bug was not that chmod was unchecked — it was that
everything *else* was checked.

The fix goes in `ramfs_chmod`, not `cmd_chmod`, so the primitive is guarded and
a future `SYS_CHMOD` inherits it. The 14 boot-time calls in `kernel.c` still
pass because `ramfs_get_current_credentials()` returns uid 0 when there is no
current task — the same boot-init mechanism the rest of ramfs relies on. Note
the rule is *stricter* than `ramfs_check_permission(WRITE)`: write access to a
file does not entitle you to re-permission it, so group/other bits are not
consulted.

**Two traps this one produced, both worth keeping.**

*`-EPERM` collided with an existing sentinel.* `EPERM` is 1, so `-EPERM` is
`-1` — which is already `ramfs_chmod`'s "file not found". The first version of
the fix returned `-EPERM`, and `cmd_chmod`'s `result == -1` branch caught it
first: the refusal printed "No such file or directory" and the new branch was
dead code. The kernel was correct and the observable behaviour was a lie. Hence
`RAMFS_CHMOD_EPERM` (-3). Before adding an errno return to a function that
already uses small negative sentinels, check whether they overlap.

*"Denied" and "absent" are the same string.* Two harness revisions passed
against a file that was simply not there. `cmd_chmod` runs its argument through
`resolve_path()`, which has no drive-letter awareness — `D:/secret.txt` does not
start with `/`, so it is treated as relative and becomes `/D:/secret.txt`, which
never exists, while `cat` resolves `D:` correctly through the VFS. The two
commands disagree about the same string, and chmod failed with "No such file or
directory" regardless of ownership. (That resolve_path/VFS mismatch is a
separate pre-existing chmod limitation.) `verify-chmod-owner.sh` therefore
asserts a **positive control** first: root must create, chmod *and read back*
the file at the same path before privileges drop. A file that does not exist
refuses everybody equally.

Generalises, and complements the `O_TRUNC` lesson above: a negative control
proves the harness can fail; a **positive control** proves it is testing the
thing it names. A denial is only evidence when you have shown the resource was
there to deny.

## FIXED: `editor_insert_row` destroyed a line of text (and leaked) on OOM

`editor_insert_row()` shifted the row array down **before** allocating:

```c
for (int i = E.numrows; i > at; i--) E.rows[i] = E.rows[i - 1];
E.rows[at].size  = len;
E.rows[at].chars = pmm_alloc();
if (!E.rows[at].chars) { editor_set_status_message("Out of memory"); return; }
```

The shift makes `E.rows[at]` a bitwise copy of `E.rows[at + 1]` — same `chars`,
same `render`. The failure return leaves that aliasing in place, and both slots
sit below `E.numrows`, so `editor_cleanup()`'s per-row `editor_free_row()` hands
the same frames to `pmm_free()` twice.

**What it actually cost — measured, and not what I first predicted.** I claimed
this degraded into frame aliasing (one frame served to two unrelated callers).
It does not: `pmm_free()` has a double-free guard (`pmm.c:963`) that detects the
second free and returns without freeing. The negative control produced:

```
[PMM] CRITICAL: Double-free detected at physical address 0x004a9000 (frame 1193)
[ROWTEST] arm2 FAIL: chars-alloc failure 64300 -> 64298 (leak)
[ROWTEST] arm4 FAIL: rows disturbed by failed insert (numrows=3 row1=(null))
```

So the real harm is (a) **2 frames permanently lost** per failed insert, since
the refused frees never return them, and (b) **a surviving row destroyed** —
the row previously at `at` reads back `NULL`, because the failed slot's pointers
were written over it. User-visible: a single OOM hiccup while editing silently
eats a line of the file. Note the frame counter goes **down**, not up; the guard
is why. A rewrite that removes that guard restores the aliasing.

**Why it hid.** `editor_insert_row` has four callers. Three append at
`E.numrows`, where the shift loop body never runs and no alias is created. Only
the mid-file insert (Enter pressed inside the file, `at = E.cy + E.rowoff + 1`)
actually shifts. Any test built from the common path passes against the bug.

**The fix is an ordering invariant, not a repair.** Allocate both frames first;
only touch `E.rows` once nothing can fail. A failure then returns with the array
completely untouched — no shift to unwind, no partial row, nothing for cleanup
to see. Do not "tidy" this back into shift-then-allocate.

Three adjacent defects fixed in the same pass, all the same shape (a pointer
outliving the frame it names):

- `editor_del_row` left a stale duplicate of the last row at `E.rows[E.numrows]`
  after shifting up. Out of range today, so nothing double-freed it — but that
  safety rested entirely on every future loop bound staying strictly below
  `numrows`. Now zeroed.
- `editor_init`'s allocation-failure path `return`ed **before** `E.filename = NULL`,
  so a failed init left the previous session's pointer live for the next
  `editor_open()` to overwrite. Now cleared on both exits.
- `editor_open` clamped the copy loop at 4095 but wrote the terminator at the
  **unclamped** `E.filename[len]`. Not reachable (`cmd_edit` is the only caller
  and `resolve_path` bounds it by `MAX_PATH == 256`) — fixed precisely because
  the next caller would make it reachable.

Reachability: `edit` is kernel-shell only (no `SYS_` case), but `kshell` is
ungated by design, so the actor is any logged-in user — only the trigger (OOM)
is hard.

Harness: `verify-editor-rowfail.sh` (needs `-DTINYOS_FAULT_INJECT`;
`make clean`s on exit). Four arms, all inserting at index 1 of a 3-row buffer
because the append shape would pass against the bug. Arm 1 is the positive
control (asserts the rows actually consume frames — without it every "balanced"
result is vacuous); arms 2 and 3 drive the `chars` and `render` failures
separately, since those were distinct defects; arm 4 asserts the surviving rows
are intact, because balanced frame accounting alone is also satisfied by a
failure path that mangles rows.

**Lesson worth keeping: run the negative control before believing the impact
statement, not just the fix.** The guard at `pmm.c:963` was invisible from
`editor.c`, and the harness's verdict branch was written to match a signature
("free frames rise") that the guard makes impossible — it would have printed a
generic FAIL and hidden its own best evidence. The measurement corrected the
severity claim in both directions.
## FIXED: every process exit leaked its whole ELF image

Measured, not inferred. Five `exec /hello.elf` cycles in the kernel shell, with
`mem` read before and after (`verify-exec-frame-leak.sh`):

```
free frames before : 64302
free frames after  : 64262     -> 40 frames over 5 execs = 8 per exec
```

`/hello.elf`'s LOAD segments are 1 + 1 + 6 = **exactly 8 pages**. The leak was
the image, precisely, with nothing else mixed in — the loader's own log shows
the PDPT/PDs/PTs being recycled to the *same physical addresses* every round,
which is why the number came out clean rather than noisy.

**Root cause: teardown frees only what a bookkeeping field names.**
`task_free_resources()` frees the kernel stack, the user stack, both guard
pages, the EDR page and the env page — each from a `task->*_phys[]` array.
`pae_free_user_pdpt()` frees the four PDs and the PDPT, and `pae_free_user_pt()`
frees each page table (or returns it to the static pool). Nothing anywhere
walked the PTEs to free what they point **at**. `grep image_pages src/process.h`
found no field, because there was none.

The frames were not untracked during the load: `elf_load_process_argv()` records
every one in `static uint32_t allocated_frames[MAX_TRACKED_PAGES]`. But all five
`pmm_free` loops over that array are **failure-path rollback**. On success the
array was simply left to be overwritten by the next exec, and the frames it
named became unreachable.

**Why this was a security bug and not untidiness.** `SYS_SPAWN` dispatches
ungated (`syscall.c`, `case SYS_SPAWN`) into the same loader. Because the frames
leak on **exit**, a spawn-and-wait loop never holds two tasks at once, so it
never approaches the per-uid task cap — that cap bounds *concurrent* tasks, not
the spawn/exit *rate*. Any unprivileged ring-3 process could therefore drain
physical memory permanently, 32 KB per iteration, while staying inside every
existing limit.

**The fix** is `task_t::image_pages_phys[256]` + `image_pages`, freed in
`task_free_resources()` next to the user-stack loop it mirrors, and populated by
`elf_load_process_argv()` from `allocated_frames[]`.

Two placement facts carry the whole correctness argument:

*Registration happens only on the success path, after the last failure return.*
Every failure path already `pmm_free`s these frames itself and **then** calls
`elf_abort_load()` → `task_terminate()` → `task_free_resources()`. Registering
earlier would make that second pass a double-free. The last failure return is
the last failure return; registration follows it. That ordering is the invariant — preserve
it if either end moves.

*Every image frame is a private `pmm_alloc()`.* They are never shared and never
kernel frames, so freeing them on exit is exactly the missing half of the
allocation. The COW kernel-shared concern (commit `1596a04`) applies to page
**tables**, which `pae_free_user_pdpt()` already handles by skipping entries
still shared with the kernel; it does not apply here. This is why the
track-a-list fix was chosen over walking the user PTEs in `pae_free_user_pdpt()`:
a PTE walker would have to reproduce that shared-entry skip at PTE granularity,
where a mistake corrupts the kernel instead of merely leaking.

Sizing is deliberate: 256 frames = 1 MB of image, against a largest shipped
binary (`shell.elf`) of 15 pages. `ELF_MAX_PROCESS_MEMORY` (16 MB / 4096 pages)
bounds what a malicious ELF may *declare*, and dimensioning to that would cost
4096 × 4 × `MAX_TASKS` = 512 KB of `.bss` — the trade `env.h` already rejected
for per-task storage. An image above the cap is **refused with a distinct
message**, not loaded untracked, because a silently untracked image is the
original leak. A `_Static_assert` pins `ELF_MAX_IMAGE_PAGES` to the array
dimension so a future resize breaks the build instead of reintroducing a leaked
tail.

After the fix the same harness reports **64308 → 64308 over 5 execs: zero
drift**. Exact equality is the assertion worth keeping — not "a smaller delta".
It says the freed set is precisely the allocated set: a double-free would show
as free frames *rising*, and a partial fix as them still falling.

*Harness lesson, learned the hard way in the same session:* the first run
against the fixed kernel printed **nothing** and exited 1. `mapfile` is bash 4+,
macOS ships bash 3.2, and under `set -u` the unset array killed the verdict
before its first line — so a **passing kernel looked like a broken harness**.
The raw serial log was the ground truth that caught it. Prefer a plain `while
read` loop; and when a harness reports failure, confirm the failure is in the
subject before believing it.
