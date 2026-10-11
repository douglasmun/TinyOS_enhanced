# TinyOS Security Audit — 2026-10 (TCP, memory, ramfs/VFS, credentials, pipes)

> **STATUS: every confirmed finding is FIXED AND MERGED (PRs #183–#188, `main` @
> `e6012cc`). The two per-uid caps §3 used to list as gaps are added by #191.** §3 lists what was examined and deliberately *not* changed — the
> latent hazards, accepted trade-offs and gaps that are not worth re-reporting
> without new information.

Five areas that no earlier audit had covered as a whole: the TCP state machine,
physical/virtual memory, ramfs as a filesystem, the login/credential path, and
pipes/IPC. Each audit's headline claim was checked against the source before
anything was fixed. Each fix PR ships a QEMU harness that **FAILs on the
unfixed tree and PASSes on the fix**; both runs are recorded in the PR.

---

## 1. Most serious finding: a background job could read the next user's password

A background job inherits the console as stdin, and its `read()` ends in the
same `keyboard_getchar()` used by the login prompt, `su` and the password
prompt. `launch_login_shell()` waited for the login shell to exit and returned
without killing the session's other processes. A user could log out leaving a
stdin reader in the background (`/shell.elf &`). When root logged in next, the
keystrokes were split between the login prompt and that reader. This defeated
`SYS_CRED`'s guarantee that a plaintext password never enters a user process.

**Fix (PR #183):** `task_t.session_id` is set at each login and inherited by
`task_create_user`. `shell_task()` calls `task_kill_session()` before the next
login prompt. Harness: `verify-logout-session-teardown.sh`.

## 2. Findings fixed

| PR | Area | Finding | Harness |
|---|---|---|---|
| #183 | Session | Background ring-3 jobs survived logout and shared the keyboard ring with the next login (§1) | `verify-logout-session-teardown.sh` |
| #184 | TCP | `tcp_close()` in `SYN_SENT`/`SYN_RECEIVED` kept the slot; a late SYN-ACK made it an ownerless ESTABLISHED socket that counted against the cap | `verify-tcp-state-fixes.sh` |
| #184 | TCP | Every FIN site set `rcv_nxt = seq + 1`: a FIN past a gap skipped the missing bytes, and a FIN carrying data under-ACKed | same |
| #184 | TCP | Any RST aborted a connect in `SYN_SENT`; RFC 793 requires `ACK == SND.NXT` | same |
| #184 | TCP | `tcp_tick` changed slots without `TCP_LOCK` (no deterministic witness) | — |
| #185 | Pipes | `pipe_bind_stream` overwrote a stream without closing its fd; each rebind leaked a ramfs fd until reboot | `verify-pipe-fixes.sh` |
| #185 | Pipes | Kernel-shell `exec prog \| cat` hung the console once the stage wrote more than 4 KB | same |
| #185 | Pipes | Static kernel-shell pipes reached orphaned grandchildren; their output landed in a later pipeline | same |
| #186 | ramfs | Kernel-shell `ls`/`find` walked children themselves, bypassing READ: any user could list root's `0711 /` and `ls -l` a `0600` file | `verify-ramfs-vfs-fixes.sh` |
| #186 | ramfs | A write at the 64 KB file cap returned 0 (a write loop spins) and printed a kernel warning each time | same |
| #186 | VFS | `vfs_alloc_fd()` called `panic()` when the reserved pool emptied; root's processes opening `D:/` reached it | same |
| #187 | Creds | `passwd` and `useradd` accepted an empty password, which then logged in | `verify-cred-fixes.sh` |
| #187 | Creds | Over-long input at the username or `su` prompt spilled into the next read: the password tail ran as a shell command or became the password | same |
| #187 | Creds | `useradd` checked the full name for duplicates and then truncated it to 31, storing a second account under an existing name | same |
| #187 | Creds | The spray detector compared a truncated stored name against the full one with `strcmp`, so one over-long name counted as many | same |
| #188 | Memory | `task_create_user_argv()`'s argv-does-not-fit branch freed only the slot (24 frames leaked, measured) | `verify-memory-fixes.sh` |
| #188 | Memory | `pae_create_user_pdpt()` panicked on allocation failure, though it runs on every exec/spawn | same |
| #191 | Pipes | No per-uid share of the 8-slot pipe table: one user holding all 8 failed every other user's `PIPE_OP_CREATE`. Now 4 per uid plus a 2-slot root reserve, `-EAGAIN` | `verify-uid-caps.sh` |
| #191 | VFS | Directory opens met no per-uid cap (a ramfs directory open takes no ramfs fd), so one user could fill the VFS descriptor pool. Now 24 per uid, `-EAGAIN` | same |

#187 also replaced `/etc/issue`'s `root/root` and `user/user` hints with
neutral text. The text lives in `user_create_etc_structure()`, which nothing
calls (§3), so no boot can show it.

## 3. Examined and not changed

These are recorded so they are not re-reported as new findings.

- **Kernel RAM map overlaps user code at 128 MB (latent).** User programs link at
  `0x08000000` (`userspace/user.ld`), inside the range the kernel maps 1:1. While a
  process's address space is loaded, the kernel's direct view of each physical
  frame at 128 MB + n×4 KB is replaced by that process's image page n. Nothing
  reachable allocates that high today: getting there takes about 127 MB of
  allocations, and the per-uid caps stop that. The real fix is to move the link
  base and re-sign every binary. That is a design decision, and it should be
  taken before the per-uid caps are ever raised or RAM above 128 MB is used for
  kernel objects.
- **TCP has no retransmission and no keepalives.** This is a missing feature,
  not a bug. A lost data segment or FIN is never resent; only the zero-window
  probe repeats. `tcp.h` used to claim retransmission in two places, and both
  are corrected (#184 and this PR). `TCP_RETRANSMIT_TIMEOUT`/`TCP_MAX_RETRANSMITS`
  and the `retransmit_*` fields are unused.
- **`/scratch` has no sticky bit.** Any user can unlink another user's file
  there but cannot read or write it. This is by design; see "D:/scratch is
  shared too" in `doc/SECURITY_HARDENING.md`.
- **Any user can keep root locked out.** The lockout counter is per target
  account, so three failed `su root` a minute keep root locked. This is an
  accepted trade-off; see "Account lockout" in `doc/SECURITY_HARDENING.md`.
- **Kernel-shell `exec /shell.elf | cat` does not hang; the probe lost its
  keystrokes.** Kernel-shell pipelines run their stages one after another (see
  "Pipeline execution" in `src/shell.c`). An interactive program as stage 1
  writes its banner, prompt and echo into the pipe, so the console shows nothing
  until it exits and `cat` runs. An earlier run looked like a hang: typed lines
  and `exit` got no response, and the outer shell did not answer `echo` 60 s
  later. Serial-direct tracing showed the cause. The probe typed every line
  while `shell.elf` was still being signature-verified, which runs with
  interrupts masked. QEMU's PS/2 queue dropped what did not fit: `echo INNER`
  reached the child as `eche`, and `exit` never arrived. The child therefore
  waited in `stdin_read`, and the kernel shell correctly waited on the child.
  With typing held until the child read stdin, the run behaved normally. `INNER`
  and the inner prompts came out through `cat` after `exit`, and the outer shell
  answered. Any harness that drives this must wait for the child to be reading
  before it types.
- **`user_create_etc_structure()` is dead code.** It is declared in `user.h` and
  defined in `user.c`, but nothing calls it, so `/etc/issue` and the files it
  writes never exist on a booted system.
