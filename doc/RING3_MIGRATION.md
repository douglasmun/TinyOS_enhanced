# Ring-3 migration — PRs #43–#55, #58

The userspace-shell capstone (roadmap item 4) and the syscall foundation it
needed. This is the design record: **why** each syscall has the shape it has, and
which pre-existing bugs became reachable when ring 3 could call into a path only
trusted kernel code had used before.

The recurring pattern across this whole migration, worth stating once: **making
a path reachable from ring 3 turns latent bugs into corruption primitives.** It
shows up in PR #45 (FAT32 dead code), #47 (subdirectories), #54 (`userdel`), and
#55 (credential syscalls). Every one of those was fixed in the same PR that made
the path reachable, deliberately — not as follow-up work.

Status: the ring-3 shell is the **default login shell** (PR #51), with the kernel
shell as a fallback. It is not yet a replacement: ~16 builtins against the kernel
shell's ~70.

## Prerequisites (roadmap items 1–3)

- **Background jobs** (PR #30) — `exec foo.elf &` + `{parent_pid,
  parent_generation}` tracking + a `jobs` builtin. `sys_waitpid` blocks on a
  shared wait queue woken by `waitpid_notify_death()`; the exit-record ring stays
  as the status store. `ps`/`kill` and zombie reaping already worked. Harness:
  `verify-bgjobs.sh` + `userspace/sleeper.c`.
- **SYS_SPAWN + pipes** — fd-aware I/O (PR #31), `SYS_SPAWN` + full argc/argv
  (#32), kernel-shell pipelines `cmd | cmd` (#33). `fork()` was skipped
  deliberately (PAE, no COW pages). Harnesses: `verify-spawn.sh`,
  `verify-pipes.sh`, `userspace/spawner.c`.
- **FAT32 write support** — see `KERNEL_BUGS.md` for the dirent-writeback root
  cause and the bugs fixed alongside it. Harness: `verify-fat32-write.sh`.

## Syscall foundation

- **PR #43** — per-process **fd table** + `SYS_OPEN`/`SYS_CLOSE`/`SYS_READDIR`/
  `SYS_STAT` (19–22).
- **PR #44** — `SYS_LSEEK` (24).
- **PR #45** — `SYS_MKDIR`/`SYS_RMDIR`/`SYS_UNLINK` (25–27), plus a `.unlink` op
  in `file_operations_t` and `vfs_unlink`. Wiring was the small half: both
  drivers already had mkdir/rmdir/unlink but **nothing outside the driver files
  ever called them** — FAT32's ops table exposed none of the three — so they were
  dead code carrying serious bugs that ring-3 reachability would have turned into
  corruption primitives. `fat32_rmdir` was literally `return fat32_unlink(path);`
  (no is-directory check, no emptiness check — it freed a directory's cluster
  chain while entries inside still pointed at those clusters); `fat32_unlink`
  matched on name alone so it deleted directories and **open** files;
  `fat32_mkdir` appended a duplicate dirent for an existing name, leaked the
  just-allocated cluster on every failure path after `allocate_cluster` (which
  marks it EOC **on disk**), and ignored the dirent-writeback return so it
  reported *success* for a directory that never reached the disk. All fixed in
  the same PR as the syscalls, deliberately — see "RAMFS node ownership" for the
  other half. Harness: `verify-fsyscalls.sh` (covers **both** D: and C:; the
  refusal cases run on C: because that is where the dangerous bugs lived).
- **PR #46** — `SYS_GETCWD`/`SYS_CHDIR` (28–29) + per-process cwd, so relative
  paths resolve. The blocker was POSIX **r vs x**: RAMFS's hardened 0700 root
  made a process's own default cwd (`D:/`) unreachable to uid 1000 — `chdir`
  needs only *search*, not *read*. Fixed with a new `.access_dir` VFS op
  (deliberately **not** `vfs_stat`, which demands r), a new `RAMFS_FLAG_EXEC`,
  and `/` at **0711** (searchable, still unlistable to non-root). Note a NULL
  `.access_dir` means *permitted* — fine for a driver with no ownership model,
  but FAT32 still needs its own op so `chdir` to a missing path is refused.

## PR #47 — FAT32 subdirectories

Lifts the `-ENOSYS` `chdir` gate on non-root C: paths. Reads were already
nested-capable (`fat32_open` and `find_dir_entry` walk components and full
cluster chains); the whole gap was that every *mutating* op and the listing took
the entire path as one filename and acted on `root_dir_cluster` unconditionally
— so `C:/A/B` meant a root entry named `A/B` truncated to 8 chars. One shared
`resolve_parent_dir()` closed it.

Directories now also **grow past one cluster** (`dir_find_free_slot` allocates
and rolls back on write failure), and three latent bugs that subdirectory
reachability would have turned live were fixed in the same change:
one-cluster-only duplicate scans (the same duplicate-dirent corruption class
already fixed twice in this file), `fat32_mkdir` skipping the 8.3 extension split
and hardcoding `..` to the root, and `fat32_unlink` not skipping LFN entries.

Unlink and rmdir now clear the dirent **before** freeing the chain — a dangling
name is more dangerous than a leaked chain. `fat32_list_root_cb` is now a wrapper
over `fat32_list_dir_cb(path, ...)`; `cmd_fatls` takes a path.

## PR #48 — the ring-3 shell itself

First migration step; the kernel shell was still the default at this point (PR
#51 changed that). `userspace/shell.c` (was a 183-line vestigial stub with 4
hardcoded commands and a hand-rolled `_start`) is now a libc-based `main(argc,
argv)` reached with `exec /shell.elf`. Builtins: `help echo pwd cd ls cat stat
write mkdir rmdir rm id exit`, plus program launch with argv and `&`
backgrounding. `src/kernel.c` seeds `/shell.elf` into RAMFS at 0755
(`shell_elf_data.h` was already included but never referenced).

Deferred by design at this point: pipes and redirection (need pipe/dup2
syscalls) and the privileged commands.

Harness: `verify-usershell.sh` — unlike the other harnesses, commands arrive as
**keystrokes into a ring-3 `read()`**, so PASS proves the interactive path
(prompt, line editing, argv split, dispatch), and it asserts the `rmdir`-non-empty
**refusal**, not just success paths.

**The shell must echo the accepted line itself**: the kernel echoes keystrokes in
the keyboard IRQ, which reaches VGA but NOT the serial log, so without it a
serial transcript shows output with no commands — and the typist's
`type_verified` echo-check has nothing to match.

## PR #51 — the ring-3 shell becomes the default login shell

Login runs `launch_login_shell()` (`src/shell.c`) instead of dropping straight
into the kernel command loop. It is a launcher **with a fallback**, not a swap:
if `/shell.elf` is missing, unsigned, or fails to load, it returns non-zero and
the kernel command loop runs, because a broken shell.elf must never cost the user
their login.

Three things make this work:

- **`exit` = logout.** The ring-3 shell cannot return to a login prompt by
  itself; its parent can. The process exits, `launch_login_shell` returns, and
  `shell_task`'s session loop falls back around to the login prompt.
- **`kshell` = hand over to the kernel shell**, via the child's **exit status**
  (`SHELL_EXIT_WANT_KERNEL_SHELL`, 70). A first attempt used a kernel-side
  `static bool`, which cannot work — the ring-3 shell is a separate process and
  cannot set a kernel variable. The status is the only channel a dying child
  already has.
- **Credentials are inherited from the session.** `task_create_user` hardcodes
  uid 1000 for every user task, so a root login would otherwise be silently
  demoted. Set before `scheduler_add_task`, for the same reason `sys_spawn` sets
  parentage first: after that call the child can run on the very next tick.

`tools/qemu_typist.py` now types `kshell` right after login by default, so the
harnesses that drive the *kernel* shell keep working unchanged;
`TINYOS_STAY_IN_RING3=1` skips it (only `verify-usershell.sh` sets it).

Two harnesses had to change for real reasons, not cosmetics: see the
`memset`/`wait_queue_init` fix in `KERNEL_BUGS.md` for the page-fault class this
made deterministic, and note `verify-redirect.sh` now waits on `[EXEC] Process
completed` rather than `Process exited` — the latter is printed from the exit
syscall with the whole teardown still to come, and keystrokes sent in that window
are dropped because nothing is in `read()` yet.

## PR #52, part 1 — ring-3 redirection (`>`, `>>`, `<`)

Redirection and pipelines are written up separately because they are two distinct
designs, but they shipped as ONE commit in PR #52 — "part 1" and "part 2" are
sections of that single merge, not two of them.

Via a new **`SYS_REDIRECT` (30)**. Deliberately **NOT `dup2`**: fds 0/1/2 are not
in `task->fdtable` at all — they live in `task->streams`, which is what already
models console/file/pipe backing and what `sys_spawn` inherits into a child. A
`dup2` taking an fd from `SYS_OPEN` would have to convert a VFS fd into a stream
and *still* would not compose with inheritance, so the primitive is the one the
stream layer actually has: rebind a standard stream to a path (`sys_redirect(fd,
path, REDIR_MODE_*)`).

That choice is what makes ONE mechanism cover builtins and programs alike: the
shell redirects **itself**, runs the command, and restores. Builtins write
through `write(1, ..)` so they land in the file; a spawned child inherits the
redirected stream at spawn time (`streams_inherit` in `sys_spawn`) so it lands
there too, with no per-command plumbing.

Two limitations are refused **explicitly** rather than silently misbehaving: a
non-`D:` target gets **`-EXDEV`** (`STREAM_TYPE_FILE` is hard-wired to RAMFS —
`stdout_write` calls `ramfs_write` directly and the redirect helpers call
`ramfs_open`, so a `C:` path cannot be represented and must not be quietly
written to `D:`), and redirecting **stderr** to a file gets **`-ENOSYS`** (there
is no `stderr_redirect_to_file`, and no shell parses `2>`; adding a helper for
syntax nothing emits would be untested code on a security-relevant path).
`RESTORE` works on all three and is checked *before* everything else, so a shell
can restore unconditionally in its cleanup path.

**`>` and `>>` were both broken in the shared stream layer** and are fixed here —
this is not new-feature-only work, and it affects the KERNEL shell too.
`stdout_redirect_to_file` had a literal `(void)append;` TODO, so `>>` was
indistinguishable from `>` and destroyed exactly the data the user asked to keep.
`>` was wrong in the other direction: RAMFS has **no truncate flag** and
`ramfs_write` only ever **grows** `node->size`, so `>` onto a longer existing file
overwrote from offset 0 and left the old tail readable by the very next `cat`.
Fixed with a new **`ramfs_truncate(fd)`** (zeroes the retained pages — a later
re-growth must not expose the old contents through the gap) plus a seek-to-end
for append.

`cat` with no operands now copies **stdin**; it is the only thing in the shell
that reads fd 0 on demand, and therefore the only way `<` is observable from a
builtin.

**`split_args` splits at `>` and `<` mid-word**, so `echo a>b` redirects rather
than passing one literal argument — matching the kernel shell (`shell_redir.c:123`
stops a token at those characters). Two shells that disagree about an
identical-looking line is worse than either behaviour on its own. The split
cannot be done purely in place: the word before the operator needs its NUL
exactly where the operator byte sits, so the operator and the rest of the line
shift one byte right and the NUL goes in the gap. That needs a spare byte, which
is why `split_args` takes the buffer **capacity** (not the string length) —
`readline` can return a line that fills the buffer completely, and an
all-operators line would otherwise walk off the end. Out of room, the operator
stays glued and parses as an ordinary argument: degraded, never corrupt.

Harness: `verify-ring3-redirect.sh`. It asserts by **counting marker
occurrences**, not presence: "the new text appeared" is also true of a `>>` that
truncated, so only the count (alpha must appear 4 times, having survived the
append) catches it. Truncation is checked **positionally** — no marker from
before an overwrite may appear after it. And the decisive negative for the child
case: `Hello from ELF!` must appear only *after* `cat h.txt` echoes, since a
child that ignored the inherited redirection would print to the console and
satisfy every positive check. The `split_args` case is `r3-delta`, asserted via
an occurrence with the operator **not** attached, since a shell that never split
still echoes the whole glued string.

**A redirected command gives the typist nothing to wait on.** With no expect
string the typist sends the next command immediately — harmless after a builtin,
but after `/hello.elf > h.txt` the shell is in `waitpid` through signature
verification and a full address-space build, nothing is in `read()`, and the
keystrokes are dropped. A bare `pwd` after it is a **barrier, not a check**.

## PR #52, part 2 — ring-3 pipelines (`a | b`)

Via a new **`SYS_PIPE` (31)**. Deliberately **NOT POSIX `pipe(int fd[2])`**, for
the same reason `SYS_REDIRECT` is not `dup2`: the ends a shell has to connect are
stdin and stdout, which are **not in `task->fdtable` at all** — they live in
`task->streams`. So a pipe is named by an **opaque integer ID**, its
`pipe_buffer_t` stays in **kernel memory and is never mapped into any user
address space**, and ring 3 only ever asks the kernel to bind an end to one of
*its own* streams. The blocking pipe layer itself already existed in
`src/shell_redir.c` (wait queues, EPIPE on both entry and post-wakeup re-check) —
the new work is ownership, lifecycle, and the shell driving it.

Unlike the KERNEL shell's pipeline, which is **sequential** (run stage N to
completion → buffer ≤4 KB → feed stage N+1; fine there, its stages are function
calls), ring-3 stages are **processes**, so both run at once with real
backpressure. That is why the harness moves ~11 KB through a 4 KB buffer: the
producer *must* fill it, block, and be woken by the consumer.

Ops: `CREATE` / `BIND_STDIN` / `UNBIND_STDOUT` / `CLOSE_WRITE` / `RESTORE` /
`DESTROY`. Three are load-bearing in non-obvious ways:

- **`UNBIND_STDOUT` is not a convenience.** A child inherits the shell's streams
  **as they are at spawn time** (`streams_inherit` in `sys_spawn`), so with stdout
  still on the write end when the **consumer** is spawned, the consumer writes its
  output into the very pipe it is reading — its report never reaches the console
  and it partly feeds itself. This shipped broken first and the harness caught it:
  both stages exited 0 and printed nothing. `RESTORE` cannot substitute — it
  resets **both** streams, and stdin must stay on the read end across that spawn.
- **`CLOSE_WRITE` has no safe default.** Until it runs, a consumer that has
  drained the buffer **blocks** rather than seeing EOF, because more data could
  still arrive. Nothing in task teardown does it — a dying child's inherited
  streams are marked `borrowed` precisely so they never touch the creator's
  resources — so the shell must call it *after reaping the producer*. A harness
  **timeout is itself the signal** that this regressed.
- **`RESTORE` is checked before the ID lookup** (as `REDIR_MODE_RESTORE` is), so a
  shell can restore unconditionally in a cleanup path even if the pipe is already
  gone. `UNBIND_STDOUT` is unconditional for the same reason.

Ownership: each slot records `{owner_pid, owner_generation}`. The **generation**
is what makes an ID safe to hand to ring 3 — a guessed ID from another process
gets `-EPERM`, and pid recycling cannot be used to inherit a dead task's pipe.
`task_pipes_cleanup()` runs in the task-teardown path next to
`task_fdtable_cleanup` (`process.c`), closing the 8-slot-exhaustion vector left by
a shell that dies mid-pipeline.

`pipe_init`'s **lossy fallback mode** (it silently DROPS data when it cannot
allocate its wait-queue page) is **refused with `-ENOMEM`**, not shipped: `CREATE`
checks `buf->readers`/`buf->writers` and fails rather than hand back a pipe that
quietly eats output.

Two things are refused **explicitly** rather than misbehaving: a **builtin stage**
(a builtin runs inside the shell process, which cannot also be the other stage —
the message points at `kshell`), and a **redirection on the piped end** (`a > f |
b`, `a | b < f`), which would fight the pipe for the stream and make the undo
unbind the pipe instead of the file.

`spawn_stage` is **silent on failure by design** — at the moment the producer is
spawned, stdout *is* the pipe, so a message printed there would be fed to the
consumer as if it were the producer's output. Both callers report the returned
errno once stdout is theirs again.

Harness: `verify-ring3-pipes.sh`. Its decisive check is the **exact** line count
(801 = 800 + the producer's own `done`), not `>=`: "data arrived" is also true of
a pipe that truncated at `PIPE_BUFFER_SIZE`. Paired with the **negative** — no
`pipe-line` may appear on the console, which a shell that ignored the pipe
entirely would fail while satisfying every positive check. Also note
`tools/qemu_typist.py`'s follow-up expect went 120s → 240s: a pipeline follow-up
spawns two ECDSA-verified processes and then streams kilobytes between them under
TCG, which the shorter window did not cover.

## PR #54 — ring-3 credential commands (`passwd`, `useradd`, `userdel`)

Via a new **`SYS_CRED` (32)**. The first of the privileged commands to reach ring
3, and scoped to these three deliberately: they are the only ones that already
carry a real **euid-based authorization model** in `shell_user.c`, so ring 3
inherits a checked policy instead of needing a new one invented for it.

**There is no password parameter, and that is the design.** `read_password`
(`src/shell_user.c`) calls `keyboard_getchar()` directly, bypassing
`task->streams` entirely. Rather than route it through a stream so ring 3 could
supply the password, the syscall makes that bypass the security property: ring 3
names an **operation and a username**, the KERNEL prints the prompts, reads the
keystrokes into its own buffer, applies the euid checks, and zeroes the buffer
before returning. A plaintext password never enters a user address space, an
argv, or a syscall argument register — the ring-3 shell cannot leak or log what it
never holds.

Authorization is **delegated, not reimplemented**: `sys_cred` validates the op,
copies the username in with a bounded `copy_string_from_user` (sized to
`USER_MAX_USERNAME`, so an over-long name is rejected rather than truncated into a
match against a *different* account), and calls the same `shell_cmd_*` the kernel
shell calls. One definition of the policy.

The three commands changed from `void` to **`int`** so a ring-3 caller has an
outcome to branch on, and their 32 `kprintf`s became `cred_printf`
(`stream_printf(get_current_streams(), ...)`). That routing is load-bearing, not
cosmetic: the prompts are printed by the kernel but must appear in the **calling
process's** stream, or an interactive ring-3 user faces a shell that looks hung
while something invisible waits for a password. Only these three functions were
converted — the other ~106 `kprintf` call sites in the file are unreachable from
ring 3, and `stream_printf` falls back to `kprintf` when there is no current
stream, so kernel-shell callers are unaffected either way.

**A redirected credential command is refused explicitly** (`passwd > f`). The
prompts are printed by the kernel into the caller's stdout, so redirecting them
would put `Enter new password:` in the file while the kernel blocked on the
keyboard — an apparently-hung shell, with the user typing a password blind. `< f`
cannot work either, since `read_password` reads the keyboard and never stdin.
Neither is expressible, so the shell says so rather than misbehaving. (A
credential stage in a *pipeline* was already refused: `looks_like_program` rejects
every builtin.)

**Two pre-existing `userdel` holes were fixed in the same change**, both latent
while only root at a kernel console could reach them, serious once ring 3 could:

- it refused to delete **`root` by NAME**, comparing the argument to the string.
  An account created with **uid 0** is root in every way that matters, and under
  any other name it was deletable. Now refused by uid.
- it permitted deleting **the account you are logged in as**, leaving the session
  running on credentials no database entry backs and freeing the uid to be
  reissued to a new account that inherits that session.

Harness: `verify-ring3-cred.sh`. It does **two logins** on purpose: every
root-side assertion would pass even with the euid check deleted entirely, so the
decisive part is logging in as the just-created unprivileged user and watching
`useradd`/`userdel` get refused *by the kernel*. A shell that merely declines to
offer the command satisfies every other check while leaving the syscall reachable
by anything that calls it directly. Paired with the case that gate must **not**
catch — that user changing their **own** password, which also exercises the only
path that reads three passwords in a row. `tools/qemu_typist.py` grew a **`!`
prefix** for follow-up lines sent without the echo check, since a password prompt
echoes `*` per keystroke and verifying the characters back would always fail.

## PR #55 — legacy credential syscalls closed off from ring 3

`SYS_CHANGE_PASSWORD` (14) and `SYS_SWITCH_USER` (15) predate `SYS_CRED` and take
a **plaintext password in a syscall argument register** — the exposure SYS_CRED
exists to remove. A ring-3 caller must *hold* the plaintext to make the call at
all, so it cannot be hardened away, only removed: the dispatcher cases now return
**`-ENOSYS`** unless built `-DTINYOS_LEGACY_CRED_SYSCALLS`. The **C functions
stay** — the kernel shell's `su` calls `sys_switch_user()` directly, not through
`int 0x80`, so gating only the dispatch leaves it working.

Underneath that, three real bugs, all latent while only trusted kernel code
reached them:

- **`sys_switch_user` authenticated with `user_verify_password()`**, which is only
  the **hash comparison**. Every policy that makes a password meaningful lives in
  `user_authenticate()`: the `failed_attempts` counter, `USER_MAX_LOGIN_ATTEMPTS`
  lockout, `USER_LOCKOUT_DURATION` expiry, and the locked/inactive checks. So the
  login prompt was throttled while this path was an **unlimited, un-counted
  password oracle** against any account, including one an administrator had
  explicitly locked. Now delegates to `user_authenticate()` — one definition of
  the policy. `sys_change_password`'s non-root branch had the identical bug.
- **the root branches skipped the account STATE, not just the password.** Root
  `su` into a **locked or deactivated** account silently defeated an
  administrative lock. Fixed with a shared `switch_user_commit()` that re-checks
  `USER_FLAG_LOCKED`/`ACTIVE` on **every** path — including the kernel shell's own
  root fast path (`shell_user.c`), which bypasses `sys_switch_user` entirely by
  calling `sys_setgid`/`sys_setuid` and so needed the check added separately.
- **`user_authenticate()` forged LOGIN records for things that were not logins.**
  Delegating `su` and password-change to it (above) was the right call for
  *policy*, but it hardcoded `AUDIT_AUTH_LOGIN_SUCCESS` /
  `AUDIT_AUTH_LOGIN_FAILURE` for every outcome — correct only while login was its
  sole caller. An `su` therefore wrote *"User 'root' (UID 0) logged in
  successfully"* into the **tamper-evident** audit log. That is worse than no
  record: the log is trusted *because* it is append-only and HMAC-chained, so a
  false entry is indistinguishable from a true one, and an `su` from a compromised
  unprivileged shell read as a clean root login. Fixed with
  **`user_authenticate_for(username, password, op)`** — identical policy, caller
  names the operation. `user_authenticate()` remains as the `USER_AUTH_OP_LOGIN`
  wrapper, so the login path and the ABI are untouched. The **success** record is
  left to the caller, which alone knows whether the operation went on to *commit*:
  verification passing is not the same as the switch or the change succeeding, and
  only the failure is final at that point.
- **five audit event types had no string mapping** and printed as `UNKNOWN`:
  `AUDIT_USER_SWITCH`, `AUDIT_AUTH_SU_FAILURE`,
  `AUDIT_AUTH_PASSWORD_CHANGE_FAILURE`, `AUDIT_USER_PASSWORD_CHANGE`, and
  `AUDIT_MEMORY_SEAL` (emitted by `sys_mseal`). Pre-existing, and it directly
  undercuts the fix above — distinguishing an su from a login in the log is
  pointless if the su then renders as `UNKNOWN`. All 49 declared types now map;
  check with a `comm` of the enum against the `case` labels if you add one.

`sys_switch_user_preauth()` exists so the kernel shell's `su` does not pay
**PBKDF2 twice** (100k iterations, seconds under TCG): it already calls
`user_authenticate_for()` itself, so the commit path skips the second password
verification while still re-checking lock/active state. Nothing reachable from
ring 3 calls it.

**The harness had to be thrown away and rewritten, and that is the useful part.**
The first version drove `su` from the kernel shell and asserted the lockout
engaged. It **passed against a deliberately reverted, vulnerable kernel** —
because the kernel shell calls `user_authenticate()` *itself* before ever reaching
the syscall, so a shell-driven attack exercises the SHELL's throttling and proves
nothing about the syscall. The gate lives at the **syscall boundary**, so only a
caller that goes straight to `int 0x80` can test it: `userspace/credprobe.c`
(seeded at `/credprobe.elf`, 0755) issues both deprecated calls directly with a
real username and password string. `verify-cred-deprecation.sh` asserts the
**exact** errno `-38`, not merely "non-zero" — `-EPERM` would mean the call was
*dispatched and then declined*, a weaker property than never being dispatched.
Validated both ways: PASS on the fixed kernel, FAIL on one with the gate removed.

`verify-audit-optype.sh` covers the audit-record half, and has the **same trap**
in a different place: `shell_cmd_su`'s root fast path skips the password entirely,
so a root `su` reaches **none** of the changed code and would pass against a fully
unfixed kernel. The harness therefore creates a user, `su`s **down** to it (root
fast path — just how we become unprivileged), then `su`s **back to root with a
password**, which is the only step that reaches `user_authenticate_for()`. It
asserts the **count** of `AUTH_LOGIN_SUCCESS` records is exactly 1, not their
absence: zero would mean the genuine login record had been suppressed too, and a
presence/absence test catches neither failure. Counts are anchored on the record
shape (`| TYPE |`), since the typed `auditlog` command echoes into the same serial
stream.

## PR #58 — require root for the kernel shell's disclosure commands

`shell_system.c` had `require_root()` but only three commands called it —
`shutdown`, `reboot`, `shred`, the ones that **break** something. The ones that
merely **tell** you something were open to any logged-in user: `pae`
(page-directory/page-table **physical** addresses), `mem` (heap/stack bases and
region layout), `aslr` (entropy and randomized bases), `wxaudit` (pages both
writable and executable — where shellcode would go, ranked), `auditlog` (who
logged in and when, which accounts exist, which are locked; `-v` also reports
whether the HMAC chain is intact, i.e. whether a tamperer was caught), and
`sectest`.

Read together the first four are an **ASLR defeat**: the kernel randomizes its
layout and then had a command that printed the answer. And PR #55 above went to
some length to stop an `su` forging a clean root login in the audit log — a log
any user can *read* undercuts that from the other side. Guards now 3 → 9.

**`kshell` itself is deliberately left unguarded.** Any user can reach the kernel
command loop. Gating the handover would be a boundary in name only: the ring-3
shell can already `exec` arbitrary signed binaries, so the policy belongs on the
commands.

Two deliberate placements: **`auditlog`'s guard sits after the option-parsing
loop**, not at function entry, so `auditlog --help` still works for anyone (usage
text discloses nothing). And **`secstatus` is left unguarded** — it reports status
and counters, not addresses or account data; its footer names the root-only
detail commands.

Harness: `verify-privcmd-guard.sh`. The trap it exists to avoid: **every one of
these commands succeeds for root both before and after the change**, so a
root-side harness passes identically against a completely unguarded kernel. It
therefore creates a user, `su`s **down** to it, and asserts the **refusal** —
anchored to the command **name**, because a bare `permission denied` grep is
satisfied by one command refusing while five leak. Paired with the **negative**:
no disclosure marker may appear after the `su`, which catches a guard placed late
enough that the payload prints first — a case the refusal string alone cannot
distinguish, since "refused" and "leaked, then refused" both contain it. Plus a
root-side counter-check that the commands still produce real output, since a guard
refusing *everyone* would satisfy every refusal assertion while breaking the
commands.

**Validated both ways** (2026-08-16): PASS on the guarded kernel, and FAIL on the
pre-guard tree (`git checkout af05cf6^ -- src/shell_system.c`), where it caught
the first missing guard and the serial log shows `pae` printing full PAE status —
CPU support, CR4/EFER state, W^X enforcement — to unprivileged user `probe` with
no refusal.

## Remaining: introspection and machine-state commands in ring 3

They are **NOT one group**:

- `ps`/`kill`/`top` are **DONE** — see the next section.
- `pae`/`mem`/`wxaudit`/`auditlog`/`shutdown` live in `shell_system.c`. That file's
  ~220 `kprintf` calls are now **converted** — see the section below.

## `ps`/`kill`/`top` in ring 3 — DONE

`SYS_PSINFO` (33) and `SYS_KILL` (34) carry the listing across the boundary.
`MAX_SYSCALL_NUM` went 32 → 34 with them (it has silently swallowed new syscalls
before — see the `SYS_SLEEP`/`SYS_WAITPID` note).

**The policy is enforced kernel-side, not by the shell.** `task_visible_to_current()`
moved out of `shell_monitor.c` (it was `static` there) into `process.c` so both the
kernel shell and the two syscalls decide from one predicate. A ring-3 shell that
filtered its own output would be filtering data it had already been given.

Three things in `sys_psinfo` that look like they could be simplified and cannot:

- **It walks raw task slots (`task_get_slot`), not `task_get_all`.** `task_get_all`
  **compacts**: its output is dense. The loop drops the lock between records —
  `copy_to_user` touches a ring-3 page and can fault, which must not happen with
  interrupts masked — so if a task exits mid-walk, every live task after it shifts
  down one position and an index-based walk **skips a process outright**. A raw slot
  denotes the same task on every iteration. `scheduler_get_all_tasks` has the same
  problem plus a second one: it returns a pointer to a **shared static array**
  (`all_tasks_array`) that a concurrent caller refills underneath you.
- **The visibility check and the field reads are in the SAME critical section.** A
  task can terminate and its slot be reused between the two, so a record that passed
  as the caller's own would be copied out carrying the name and PID of whatever took
  the slot — the exact leak the filter exists to prevent, through the back door.
- **`psinfo_t` is zeroed in full before use.** It is a stack local; its padding and
  unused name bytes would otherwise carry whatever the last iteration left there into
  ring 3. The ABI (sizeof 64, `uid` at 24, `name` at 32) is pinned by `_Static_assert`
  on **both** sides of the boundary — kernel and `userspace/libc.h`.

`sys_kill` answers **-ESRCH, never -EPERM**, for a PID the caller cannot see.
Distinguishing "does not exist" from "exists but is not yours" would make `kill` an
existence oracle that hands back exactly the table `ps` withheld. Its lookup and both
checks are one critical section; `task_terminate` runs outside it.

`top`'s `%CPU` denominator at ring 3 is the ticks in the **visible** listing, whereas
the kernel shell's `cmd_top` keeps a system-wide one. This is deliberate: a system-wide
denominator would let an unprivileged user infer total system activity from their own
rows. The consequence is that the percentages a user sees are shares of what they can
see, not of the machine.

Harness: `verify-ring3-ps.sh`, which measures inside a ring-3 shell (the kernel shell
never calls these syscalls, so running it there would prove nothing). Two paired
positives carry it: the user must **see** their own `slothold.elf`, and must be able to
**kill** it. Without the first, a `sys_psinfo` returning an empty table passes every
leak assertion; without the second, a `sys_kill` that refuses everything answers "no
such process" to all requests and passes the existence-leak check while being entirely
broken.

Two traps this harness hit, both worth remembering:

- **A re-logged-in ring-3 session never receives keyboard input.** Logging out and back
  in as the test user was the obvious route and it does reach a ring-3 shell — which
  then ignores every keystroke. Open, recorded in `doc/KERNEL_BUGS.md`; the harness
  routes `kshell` → `su` → `exec /shell.elf` around it.
- **The typist's echo verification is unsound at ring 3.** The ring-3 shell does not
  echo to serial (the kernel echoes in the keyboard IRQ, to VGA only), so the
  per-character check was passing on coincidental matches in kernel chatter — a guard
  that could not fail. Those commands are sent with `!` and checked on their *result*.

## Process visibility policy — DECIDED

**An unprivileged user sees only their own processes; root sees all.**

The alternative — everyone sees everything, as on a stock Unix — leaks what root
is running to any logged-in user. Process names and argv are visible in `ps`, so
a root-run recovery or maintenance command becomes an announcement. On a
single-user teaching kernel that is a poor default, and own-only is the
conservative direction: it can be relaxed later without breaking anyone, whereas
tightening it afterwards would.

The rule lives in **one** predicate, `task_visible_to_current()`
(`shell_monitor.c`), shared by `ps` and `top` so the two cannot drift apart. It
uses **euid for the privilege decision and real uid for ownership**, matching
`cmd_kill` and `sys_waitpid` — so what you can *see* and what you can *signal*
are the same set. A `ps` listing a process you may not kill, or a `kill`
refusing a PID `ps` never showed, are both worse than one consistent rule.

Kernel tasks (Idle, the EDR daemon) are uid 0 and therefore hidden from
unprivileged users along with everything else. That is deliberate: the EDR
daemon's presence and the idle task's timing are exactly the machine state this
policy withholds.

Three consequences that are easy to get wrong, each fixed here:

- **Totals must count only what was printed.** `ps` reported the raw table
  count, which states precisely how many processes are being withheld — most of
  what hiding them was for. Both `ps` and `top` now count visible rows.
- **`top` must filter before it truncates.** It sorted by CPU time and took the
  first ten, so filtering afterwards would show an unprivileged user an *empty*
  table whenever root's tasks happened to occupy the ten busiest slots. The
  %CPU denominator deliberately stays system-wide: %CPU is a share of the
  machine, and rescaling to the visible subset would report a user's idle
  process as 100% of a busy system.
- **Errors must not leak existence.** `cmd_kill` answered "permission denied
  (not owner)" and named the owner's UID, which confirms the PID is live and
  lets a user enumerate every live PID. It now reports a foreign PID exactly as
  it reports a nonexistent one; `sys_waitpid` likewise returns `-ECHILD` rather
  than `-EPERM`.

Harness: `verify-psvisibility.sh`. Its load-bearing assertion is the **paired
positive** — the user must see their *own* process. "The unprivileged user sees
fewer rows than root" is also satisfied by a `ps` that shows them nothing, which
is not the policy and would be a plainly broken `ps`.

## Task-slot exhaustion — CLOSED

`shell.elf` can be run recursively (nested, and via `&`, which is the real bomb).
`task_rate_limit_check()` (`src/process.c`) is a real token bucket, but it limits
the **rate** of task creation (5/sec sustained), not the **quantity** of live
tasks one user holds. At that rate, filling the global `MAX_TASKS` (32) took ~5
seconds and the slots then stayed full — starving the kernel's own tasks and
blocking root from logging in to fix it, so recovery needed a reboot. Each shell
instance costs ~170 KB, so memory was never the binding constraint; the 32-slot
table was.

Fixed with the two limits recommended here — deliberately **not** a
recursion-depth limit, which misses the `&` case entirely:

- **`USER_MAX_CONCURRENT_TASKS` (10)** — a per-uid cap on *live* tasks,
  `-EAGAIN`.
- **`TASK_ROOT_RESERVED_SLOTS` (4)** — slots no non-root task may take, so root
  can always log in and `kill` the offender.

Both live in `task_create_user_argv`, which every user-task creation path
funnels through. Three details are load-bearing:

- **Charged to the CREATOR's uid.** `task_create_user` hardcodes uid 1000 and
  the caller overwrites it *after* the call returns, so the new task's own uid
  is not yet meaningful at check time.
- **ZOMBIEs count.** A zombie still occupies a slot, which is the resource being
  rationed. Excluding them would let an unreaped spawn loop past the cap.
- **Checked BEFORE the rate limiter.** Being over a standing ownership limit is
  more specific and more durable than a transient rate spike; reporting the rate
  limiter to a user who is *also* over their cap tells them to retry, which will
  keep failing.

A **pre-existing bug in the rate limiter** was found and fixed on the way: the
refill divided by `(1000 / REFILL_INTERVAL)` == 10, so one elapsed second added
`(1 * 5) / 10` == **0** tokens in integer arithmetic, and the reset discarded
leftover ticks. The bucket refilled only when a single check saw ≥2 seconds
elapse, making the limiter far more aggressive than its documented 5/sec. See
`doc/KERNEL_BUGS.md`.

Harness: `verify-slotcap.sh`, driving `userspace/slotbomb.c` (spawns
`/slothold.elf` in a loop, never reaps). Its decisive assertion is **which
guard refused**: both limiters return `-EAGAIN`, so the errno cannot tell them
apart, and early runs of this harness passed while the RATE limiter did the
refusing at a count that looked exactly right. It therefore requires the cap's
own message *and* the absence of the rate limiter's, and finishes by proving
root can still create a task while the attacker sits at their cap.

## `shell_system.c` stream routing — DONE

The file's ~220 `kprintf` calls became `stream_printf(get_current_streams(), ...)`.
This is a prerequisite for moving `mem`/`pae`/`wxaudit`/`auditlog` to ring 3, but it
fixes a bug that was already visible from the kernel shell: the shell has bound `>` to
`stdout_stream` since the redirection PR, so `mem > /m.txt` opened the file, printed
the whole report to the console anyway, and left an empty file behind. Binding a
stream does nothing for a command that never reads it.

That is also why the bug survived so long. `verify-redirect.sh` proved redirection
worked — it drives `exec /hello.elf > /out.txt`, and the *child* honours the stream
because `sys_write` routes through the task's `stream_context_t`. Every builtin in
this file bypassed that path entirely. A harness that only ever redirects a child
cannot see it.

### The three deliberate `kprintf` survivors

Each is commented in place, because a later mechanical sweep would otherwise
"finish the job" and reintroduce a defect:

- **`cmd_shutdown`'s banner and `cmd_reboot`'s notice.** The machine halts a few
  lines later. `shutdown > log` would put the notice in a ramfs file that dies with
  the RAM, and leave the user watching a console that says nothing before it stops.
  The argument errors and the permission refusal above them *are* converted — at that
  point the command has not committed to halting.
`cmd_sectest`'s banner was in this list until `security_tests.c` was converted; see
"`security_tests.c`: the report had three authors" below for why it was held back and
what releasing it required.

### `env.c`: the locking had to change with the routing

`env_list()` and `alias_list()` printed from inside a `CRITICAL_SECTION` held across
the whole listing. `kprintf` tolerates that; `stream_printf` on a redirected stream
reaches `ramfs_write`, which is far too much work to run with interrupts masked and
can take a mutex of its own. Both now take the lock **per slot**, copy one entry out,
drop the lock, and print outside it. The table is never read unlocked and no I/O
happens inside the critical section. The trade is that a variable added mid-listing
may or may not appear — acceptable for a listing, unlike the torn name/value read the
lock actually exists to prevent.

### `security_tests.c`: the report had three authors

161 call sites, the last console-only block in the tree, and the reason
`cmd_sectest`'s banner sat on `kprintf` for two PRs. Converting the file was the easy
part; two things about it were not mechanical.

**The suite does not print all of its own output.** Two functions it calls are defined
in other files and have *exactly one caller each* — this suite:

| Function | File | Lines of output |
|---|---|---|
| `scheduler_stats()` | `scheduler.c` | 10 (TEST 3) |
| `arp_security_self_test()` | `net.c` | 7 (TEST 9) |

Convert only `security_tests.c` and `sectest > report.txt` yields a file with the
banner, all nine test headers and all nine verdicts — structurally complete, and
missing 17 lines of the actual security results, which went to the console instead.
This is the failure a positive-only harness passes, so `verify-sectest-redirect.sh`
asserts on all three sources independently. It was validated against exactly this
half-done state: suite body and ARP passed, `scheduler_stats` failed.

**`scheduler_stats()` printed inside its critical section.** Seven of its ten lines
sat between `CRITICAL_SECTION_ENTER()` and `EXIT()`. That is survivable for `kprintf`
and not for `stream_printf`, for the same `ramfs_write` reason as `env.c` above — and
`sectest > f` is precisely the redirected case. It now snapshots every value the
report needs into locals under the lock (including `current->name` **by value**;
holding the pointer and dereferencing it after `EXIT` would race a task that exits in
between) and formats afterwards. The snapshot is what makes the report internally
consistent *and* the printing safe; those two properties are in tension and this is
where they get reconciled, so it should not be folded back into one pass.

Worth noting that `-Werror` catches a partial revert here for free: drop the
`stream_printf` calls from `scheduler_stats` and `ctx` becomes unused. That is defence
in depth, not a substitute for the harness — it only fires when a function loses its
*last* `stream_printf`, and says nothing about the other two files.

### A pre-existing `%f` bug fell out of the conversion

`cmd_aslr` printed `"%.4f"` and `"%.2f"`. Neither `kprintf` nor `vsnprintf_impl`
implements float conversion at all, so an unknown specifier is echoed **literally
and its argument is never consumed** — the four characters `%.4f` appeared in the
output and every following vararg in that call was shifted by one. Both quantities
were exact integers; they are now printed as the `1 in N` they actually are. Not a
regression from this work, but this is the PR that read those lines closely enough
to notice.

### Harness: `verify-sysredirect.sh`

Boundary: the **kernel shell**, deliberately. These are kernel-shell builtins with no
ring-3 equivalent yet, and the property under test is "the command reads its stream",
which is where the command lives. The shell's own `>` handling is held constant — it
was already working, which is exactly why the empty-file bug was invisible.

The assertion is **positional, not presence-based**: `Memory Usage:` appears in the
serial log in both the passing and the failing run. Only its line number relative to
the `cat` distinguishes "arrived from the file" from "was printed to the console while
the file stayed empty". The negative control is evaluated first and suppresses the
positive — if the marker showed up before the `cat`, nothing appearing after it proves
anything about where it came from.

The staleness guard disassembles `cmd_mem` and requires that *it* calls
`stream_printf`, rather than checking whether the symbol exists in `kernel.elf` —
stdio.c defines it in every build ever made, converted or not, so the obvious check
is one that cannot fail. Validated by actually reverting `cmd_mem`: the guard refused
to boot the wrong kernel, and with the guard bypassed the runtime negative control
tripped on the line-number comparison.

## Roadmap item 4, PR A — the env/alias group works, and its storage is per-task

`chmod` and `date` were each one PR: the kernel behaviour already existed and only
had to cross the ring boundary. **`env` is not like that.** `env_init()` sat
commented out in `kernel.c` — "TEMPORARILY DISABLED FOR TESTING" — from the initial
public release onward, while every consumer stayed wired: alias substitution in
`shell.c`, `$VAR` expansion, all six builtins dispatched. So the commands existed,
ran, and printed `(no variables)` / `(no aliases)` forever without erroring. That is
why it survived so long: a check that the `env` command *exists* passes against the
dead build.

Migrating that to ring 3 first would have carried a dead subsystem across the
boundary and produced a ring-3 `env` printing nothing, indistinguishable from a
syscall bug. Hence the split: **PR A makes it work in the kernel shell and settles
storage; PR B adds the syscall, the libc stubs and the ring-3 builtins.**

### Storage: per-task, inherited on spawn

`env.c` had two file-scope 16-entry arrays with no uid or task concept at all. The
decision was per-task with inheritance, and the shape follows `task->edr_advanced`:
`task_t` holds a **pointer** to a lazily `pmm_alloc()`'d page. Embedding
`env_state_t` directly would add ~102 KB of `.bss` at `MAX_TASKS 32`, charged to
every task including the ones that never set a variable; a task that never uses env
now costs four bytes.

Sizing forced two limit changes. At the old `ENV_MAX_VALUE_LEN`/`ALIAS_MAX_CMD_LEN`
of 256, `env_var_t` is 290 bytes and `alias_t` 289, so the two tables came to 9,264
bytes — 2.26 pages, i.e. `pmm_alloc_contiguous(3)` with ~3 KB wasted per task. At 64
they total 3,200 bytes and a plain `pmm_alloc()` works. A `_Static_assert` in `env.h`
holds the page-fit, and was **negative-controlled** (set the limit to 512, the build
fails with that exact message) rather than assumed. 256 was never reachable anyway:
`SHELL_BUFFER_SIZE` is 256 for the *entire* command line, and the longest default
value in the tree is `"/bin/shell"` at ten characters.

The default alias list went 16 → **12** of 16 slots (`ALIAS_DEFAULT_COUNT`, asserted
`< ALIAS_MAX_COUNT`). The old list filled the table exactly to capacity, so every
user `alias` failed "table full" against a table holding nothing of theirs.

Things not to undo, each from a real failure mode:

- `pmm_alloc()` **does not zero**. `env_state_alloc()` must `memset`, or a recycled
  frame presents as a table full of garbage variables.
- `env_state_alloc()` is called **outside** the critical section — same discipline
  as `stream_printf`/`ramfs_write`, since `pmm_alloc` must not run with interrupts
  masked.
- `env_get`/`alias_get` **copy out under the lock**. The old versions returned a
  pointer *into* the table after unlocking: harmless while one global table and one
  kernel shell existed, a genuine use-after-unlock once the page is freed at task
  exit.
- `env_free_for_task()` (from `task_free_resources`) nulls the field, so it is
  idempotent across the terminate and reaper paths.
- `env_inherit_exported()` allocates the child's page **directly**, not via
  `env_state_alloc()` — the latter resolves `scheduler_get_current_task()`, which at
  spawn time is the *parent*, so it would copy the parent's page onto itself. It runs
  **before `scheduler_add_task()`** at all three creation sites (`sys_spawn`,
  `cmd_exec`, the ring-3 shell launch), because the child can run on the next tick.
  The copy is a **snapshot**: sharing the page would undo the isolation entirely.
  Aliases deliberately do not cross — substitution happens in `shell.c` before
  dispatch, so a spawned binary never consults the table.

### Neither property is observable from the shell

This is the part worth remembering. **Per-task isolation cannot be witnessed from
userspace in this PR**, and the obvious tests all pass vacuously:

- "set FOO=bar, read FOO=bar back" behaves identically under global, per-uid and
  per-task storage.
- `su otheruser` changes credentials on the **same task**, so both users share one
  env page. A "the other user cannot see my variable" leg written that way would
  *fail* against correct per-task code and pass against per-uid.
- a logout/login pair needs the typist to re-drive the login sequence, which it does
  not do — the followup list simply ends.
- ring 3 had no env syscall yet. That was PR B — and **PR B did not change this
  conclusion**, because `SYS_ENV` is deliberately own-table-only. See below.

So the check lives in the kernel: `env_pertask_self_test()`, wired in as `sectest`
TEST 10, which creates real second and third tasks and prints **two** verdict lines.

Isolation is **three-way** — child saw nothing AND child set its own AND parent
intact — because a child whose page allocation simply *failed* also sees nothing and
would pass a "saw nothing" check for entirely the wrong reason. Inheritance is
**two-way** — heir got the exported variable AND did *not* get the un-exported one —
because a copy that ignored the export flag and cloned the whole table satisfies the
first clause perfectly.

The two halves also mask each other, which is why both must be asserted: a build
handing every task one shared page passes inheritance trivially and fails isolation;
a build that never copies passes isolation and fails inheritance. Neither line alone
describes the design that was chosen.

Negative-controlled both ways, and **the first attempt at the control was wrong in an
instructive way**. Redirecting only `env_state_alloc()` — the *allocating* path —
left the reader `env_state()` returning the child's own NULL, so the child "saw
nothing" and only the third clause fired; the verdict read `child saw parent's var:
no (good) | ... | parent's var intact: NO (BAD)`. A shared-storage regression must
redirect **both** the reader and the allocator, or the control quietly tests less
than it claims — the same failure mode the three-way verdict itself guards against.
With both redirected, clauses 1 and 3 both fire.

Two harness traps, neither of them kernel bugs, both of which first presented as one:

- `tools/qemu_typist.py` raises `SystemExit("typist: no keymap for char ...")` for
  unmapped punctuation. With its stderr sent to `/dev/null` the abort is invisible:
  half the command lands in the serial log and every leg blames the kernel. Hit on
  `alias myll='echo ALIASWORKS'` — `'` had no mapping, now added along with
  `" \ [ ] { } + ? ~` and backtick. Never discard the typist's stderr.
- `cmd_alias` reads only **`argv[1]`**, so `alias x='echo HI'` tokenizes to
  `argv[1]="x='echo"` and stores `x -> "echo"`. The alias is created successfully,
  prints a blank line, and a grep for `HI` fails while looking exactly like an
  alias-table-capacity failure. Pre-existing shell behaviour; use single-word alias
  values in harnesses.
- The serial log is **CRLF**. `grep -q '^root$'` silently fails to match `root\r`.
  Do **not** fix that with `\r\?` — grep here is ugrep, which rejects it as an
  empty subexpression. Strip once up front (`tr -d '\r'`) and assert on the
  stripped copy.

Harness: `verify-env-pertask.sh`.

## Roadmap item 4, PR B — the env/alias group crosses into ring 3 (`SYS_ENV`)

PR A woke the subsystem and made its storage per-task, but left it **kernel-only**:
the ring-3 shell had no `env`, no `set`, no `$VAR`, no aliases. PR B carries it
across the boundary.

### `SYS_ENV` (41) — one syscall, nine subcommands

Same shape as `SYS_NETSTAT`/`SYS_TCPSOCK`: a single entry point with an `op`
selector rather than nine syscall numbers, because the nine operations share one
fixed-width wire record and differ only in which fields they read.

```c
ENV_OP_GET / SET / UNSET / EXPORT / LIST
ENV_OP_ALIAS_GET / ALIAS_SET / ALIAS_LIST / ALIAS_UNSET
```

`ALIAS_UNSET` (8) arrived a PR later than the other eight and is the reason the
multiplexed shape earns its keep: adding deletion cost one `case`, not a tenth
syscall number and another `MAX_SYSCALL_NUM` bump. It is symmetric with
`ENV_OP_UNSET` including its errno — `alias_unset()` returns -1 both for an
absent name and in its defensive bounds branch, and both mean "no such alias" to
the caller, so `-ENOENT` covers each. That is checked, not assumed: `-ENOENT` is
-2 and nothing else in `sys_env` returns it, so there is no repeat of the
`ramfs_chmod` collision where `-EPERM` (-1) silently aliased "not found".

Exposing it meant auditing `alias_unset()` in the same PR, per the rule that
making a path ring-3-reachable turns latent bugs into corruption primitives. It
came back clean: the whole body is inside `CRITICAL_SECTION_ENTER/EXIT`, the
index is bounds-checked against `ALIAS_MAX_COUNT` before the array write, and
all three fields (`in_use`, `name`, `command`) are cleared rather than just the
flag. The NULL case is safe by delegation rather than by a local check —
`env_state()` returns NULL when the task has no env page yet (it is lazily
allocated), but `alias_find()` rejects a NULL state and returns -1, so the
`idx < 0` path returns before any dereference. Worth knowing, because a grep for
`!s` in the function finds nothing and reads like a missing check.

The record is built field by field into an explicit `env_record_t` (32-byte name,
64-byte value, `index`, `exported`), never `memcpy`'d out of a kernel struct, and
carries four `_Static_assert`s on `sizeof` and `offsetof` — **mirrored in
`userspace/libc.h`**, since that is a separate copy that can drift.

`syscall.h` deliberately does **not** include `env.h` (that would pull env into
every syscall.h consumer), so the tie-back assert — that `ENV_REC_NAME_LEN`/
`ENV_REC_VALUE_LEN` still match `ENV_MAX_NAME_LEN`/`ENV_MAX_VALUE_LEN` — lives in
`env.h`, which owns the limits. Both halves are needed: the ones in `syscall.h`
pin the *layout*, the one in `env.h` pins the *agreement*.

`LIST` enumerates **by index**, one record per call, because `env_list()` and
`alias_list()` print through `stream_printf` and cannot cross a ring boundary. A
filled slot returns 1, a hole returns 0, so the client skips holes rather than
stopping at the first one.

### `su` is NOT migrating — decided 2026-08-18

Recorded here because this file is where a future reader looks for "which
syscall carries X to ring 3", and for `su` the answer is **none, deliberately**.

`SYS_SWITCH_USER` (15) already has a ring-3 dispatch case and it is refused with
`-ENOSYS` by default (PR #55). The reason is structural: the call takes a
plaintext password through an argument register, so a ring-3 caller must hold
the secret to make it — the exact exposure `SYS_CRED` (32) was built to remove
by having the kernel prompt and read the keystrokes itself.

The obvious repair — a `CRED_OP_SU` on `SYS_CRED`, kernel-prompted, no plaintext
crossing — was considered and rejected on a different ground. It would give ring
3 a syscall that changes the **calling task's own uid in place**, and the uid is
what every ownership gate in the tree is written against: `SYS_CHMOD`,
`SYS_TCPSOCK`, `task_visible_to_current()`, the per-uid task cap. Making that
field mutable from the untrusted side to gain one convenience builtin is a bad
trade, and it is the same "what does moving it buy vs. what capability does it
need" test that withdrew the ring-3 parser move (D1).

The kernel shell's `su` calls `sys_switch_user()` directly rather than through
`int 0x80`, so it is unaffected and stays fully supported. `kshell` is one
command away from the ring-3 shell.

### Gating: UNGATED, and that is not the polarity of its neighbour

`SYS_CHMOD` sits directly above it in the header and is **ownership-gated**.
`SYS_ENV` is **ungated**, and the reasoning is worth keeping because copying the
neighbouring assertion would invert it:

> Storage is per-task. A caller can only ever address its own table — there is no
> foreign object to reach, so there is nothing to authorize. An unprivileged
> `-EPERM` from any op here is **the bug**, not the policy.

The harness therefore measures every leg as an **unprivileged** user. Running them
as root would pass against a kernel that had accidentally made `SYS_ENV` root-only.

### Deliberately not exposed

There is **no subcommand that takes a pid**. A "read another task's environment"
getter would hand straight back the isolation PR A was built to establish. This is
also why PR B does not make per-task isolation observable from ring 3 — the
self-test in `sectest` TEST 10 remains the only witness, and PR A's note to that
effect still stands.

### The syscall alone would have shipped a dead feature

This is the finding that set the PR's scope. A grep established that alias
substitution (`src/shell.c:542`) and `$VAR` expansion (`src/shell.c:565`) exist
**only in the kernel shell**. Shipping `SYS_ENV` plus the five builtins would have
produced a ring-3 shell where `env`, `set` and `alias` all listed their tables
perfectly and `echo $HOME` printed a literal `$HOME` — **PR A's failure mode
wearing a different hat**: a subsystem that looks wired and observably does
nothing.

So PR B also carries the client side, in `userspace/shell.c`:

- `expand_aliases()` — first word only, **single pass**, so `alias ls='ls -l'`
  cannot loop.
- `expand_vars()` — `$VAR` and `${VAR}`; an unset variable expands to **nothing**
  (POSIX), a bare `$` stays literal, an unclosed brace is emitted literally.
- `cmd_alias` reassembles multi-word values from the remaining argv and strips one
  layer of quotes — deliberately fixing what the kernel shell's `cmd_alias` gets
  wrong (it reads `argv[1]` only, the PR A harness trap recorded above).

Legs 5, 6 and 7 of the harness are the ones that would catch the syscall shipping
without this.

### `$USER` was a lie after `su` — found by the harness's first run

`env_init()` seeds `USER="root"` because it runs before anyone has logged in, so
every path that establishes **or changes** an identity has to correct it. Login
always did. **`su` did not**: it changes credentials on the *same task*, so the
per-task env page survives the switch untouched and the post-su shell went on
reporting `USER=root`.

Cosmetic while env was kernel-only. `SYS_ENV` makes it reachable from ring 3, where
a script can branch on `$USER` — the CLAUDE.md rule about exposing a path turning a
latent bug into a real one, in miniature, and caught the first time the harness ran
as a non-root user.

Fixed by factoring the login path's correction into `env_refresh_identity()` and
calling it from **both** `su` branches (the root fast path and the
password-authenticating one). Fixing only the branch the harness drives would leave
the other lying. It resolves the name from the task's **real uid** via the account
table — `task->name` is the *task's* name (`"shell"`), not a username — and does
nothing silently if there is no current task or no matching account, since this is
cosmetic state that must not fail an `su` the kernel already committed.

Leg 8 asserts it **both ways**: the new name present *and* `USER=root` gone.
Presence alone passes against a table holding both.

### Harness traps (`verify-ring3-env.sh`)

- **The prompt echo contains the command.** The shell echoes what it is about to
  run, so the log holds both `D:/ $ echo MARKER2 $ENVMARK` and the result line. A
  bare `grep -m1 MARKER2` takes the *echo* — which contains the literal `$ENVMARK`
  by construction — so the "expanded to its own name" assertion fired on every run,
  including correct ones. It did exactly that on the first run, against a shell
  whose output was right. Filter prompt lines before asserting on output.
- **Alias to a command the ring-3 shell actually has.** The first version aliased
  to `whoami`, which is a *kernel*-shell builtin. Substitution worked, the shell
  said `whoami: not found`, and the leg blamed the alias. `id` is the right target:
  it exists in ring 3, and its output (`uid=…`) is a string the `alias` listing
  line cannot contain, so the leg stays self-checking.
- **`grep -q "uid"` for the spawn leg collides with `id`'s output** from the alias
  leg above and passes without the child ever starting. Anchor on `TinyOS user
  process`, which only `info.elf` prints.
- The `env` listing shows four kernel-seeded defaults, so **"`env` printed rows"
  proves nothing**. Only a round trip separates "the syscall carries *this task's*
  table" from "something printed four plausible lines": leg 4 sets `ENVMARK=r3only`
  (a value no default can produce) via `ENV_OP_SET`, and leg 5 reads it back
  through `ENV_OP_GET` inside `expand_vars()` — a different code path than the
  write, so a stub faking either one alone fails.
- Legs 5 and 6 are a **pair on the same variable**, and neither is meaningful
  alone: "printed nothing" is also what a totally broken expander prints. Leg 5
  requires the value to appear, leg 6 requires it gone after `unset`.
