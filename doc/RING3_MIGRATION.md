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

- `ps`/`kill`/`top` live in `shell_monitor.c`, which is already **stream-routed**
  (16 `stream_printf` vs 10 `kprintf`). Exposing them was a **policy** question —
  what may an unprivileged process see and signal — and that policy is now
  **decided and enforced**; see below. What remains is a syscall to carry the
  listing to ring 3.
- `pae`/`mem`/`wxaudit`/`auditlog`/`shutdown` live in `shell_system.c`, which has
  ~222 `kprintf` and zero `stream_printf`: reaching those from ring 3 means the
  same conversion done for the three credential commands, but two orders of
  magnitude larger.

Do `ps`/`kill` first if this is picked up; do not convert `shell_system.c`
wholesale on the way.

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
