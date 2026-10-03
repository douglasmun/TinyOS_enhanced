# Input-surface fuzzing campaign — results (2026-10)

Branch: `fuzz/input-surfaces` — 35 commits, shipped in release v2.8.
Scope: every surface where data the kernel does not control enters it — network
frames, disk images, ELF files, typed shell lines, editor keystrokes, and ring-3
syscall arguments.

## Summary

| | |
|---|---|
| Fuzz targets built | 9 (libFuzzer, real kernel sources on the host, ASan + UBSan) |
| Distinct defects fixed | **35**, in 20 fix commits |
| Found directly by a fuzzer oracle or sanitizer | 19 |
| Found by the follow-on ring-3 / QEMU work the fuzzing led into | 16 |
| Of which: memory safety (OOB, UAF, stale mapping) | 8 |
| Of which: cross-user / privilege boundary | 5 |
| Of which: denial of service (lockup, panic, exhaustion) | 9 |
| Regression seeds committed | 19 (each trips its oracle on the pre-fix source) |
| New QEMU harnesses | 9 (every fix negative-controlled: PASS on fix, FAIL on the parent) |
| Full regression after the last fix | 77/83 first pass; the 6 non-passes were all harness drift, fixed, re-run PASS |

## Fuzz targets

| Target | Surface (OS function under test) | Oracle | Executions | Result |
|---|---|---|---|---|
| `net` | `handle_packet()` — firewall, IDS, ICMP, TCP, DNS, DHCP RX path | ASan/UBSan | 230M | 1 bug (UBSan), then clean |
| `dns` | `handle_dns_response()` against a pending query | ASan/UBSan | — | clean |
| `dhcp` | DISCOVER/OFFER/REQUEST/ACK exchange | aborts on any config a reply must never set | — | clean |
| `fat32` | mount + every `fat32_*` entry point, disk image as input | write-placement oracle (only FAT + data region writable), alias oracle | 9.7M after fix | 5 + 1 bugs |
| `elfsig` | `elf_verify_signature()` + P-256 verify, with attacker fix-ups | forgery oracle: a PASS must be a shipped genuine signature | slow (~16k / 30 min) | clean — no forgery |
| `elfload` | ELF header / program-header validation (`-DELF_PERMISSIVE_SIGNATURES`) | ASan, exact-size buffer | — | 1 bug |
| `ramfs` | open/read/write/seek/truncate/mkdir/rmdir/unlink/rename/chmod as uid 1000 | protected files untouched; tree well-formed | 8.5M | 4 bugs |
| `shell` | `env_expand`, `parse_redirections`, `parse_pipeline`, `canonicalize_path`, pipe ring | per-function invariants | 95M | 1 bug |
| `editor` | `edit` keystrokes over a RAMFS file, injected row-alloc failure | buffer == file; save == rows | — | 6 bugs |

The crypto gate (`elfsig`) held: no input produced a PASS that was not a genuine
shipped signature.

## Defects by OS function

### Network stack — `src/ids.c`

| # | Commit | Defect | Nature | Reach |
|---|---|---|---|---|
| 1 | `b54941d` | `ids_analyze_packet()` shifted `src_ip[0]` (int) left by 24 | Undefined behaviour on every packet from a source ≥ 128.0.0.0 | Remote, any inbound frame |

### FAT32 driver — `src/fat32.c`

| # | Commit | Defect | Nature | Reach |
|---|---|---|---|---|
| 2 | `a052a50` | Cluster 0/1 mapped to LBA 0: a hostile volume made the boot sector the root dir, and `fat32_unlink()` wrote over it | Disk corruption | Hostile disk image |
| 3 | `a052a50` | `read/write_fat_entry()` indexed past the FAT into data sectors | Out-of-bounds disk read/write | Hostile disk image |
| 4 | `a052a50` | Chain walks bounded only by 2M; a self-loop spun ~4M sector reads holding `fat32_mutex` | Kernel lockup (DoS) from one `ls` | Hostile disk image |
| 5 | `a052a50` | `num_fats * fat_size_32` wrapped in 32 bits, putting data on top of the FAT | Integer overflow → corruption | Hostile disk image |
| 6 | `a052a50` | `find_free_cluster()` stopped two clusters short | Capacity loss | Any |
| 7 | `838ea66` | `parse_path()` / `filename_to_83()` silently clipped long names: `C:/REPORTFINAL.TXT` resolved to `C:/REPORTFI.TXT` | Wrong-file unlink/overwrite (data loss) | Any user, `C:` |

### RAMFS — `src/ramfs.c`

| # | Commit | Defect | Nature | Reach |
|---|---|---|---|---|
| 8 | `0a278b6` | No lookup checked the directory x bit; a root 0700 dir hid nothing | **Confidentiality bypass** — uid 1000 read files under root-only dirs | Ring 3 `SYS_OPEN` |
| 9 | `0a278b6` | Open-with-create never checked components were directories: `/file/x` hung children under a file, freed with it | Permanent slot leak → filesystem-wide DoS | Ring 3 |
| 10 | `e3fcf61` | `ramfs_rename` did not resolve the destination dir: two entries named `b` in one dir | Unreachable/undeletable files | Ring 3 `SYS_RENAME` |
| 11 | `e3fcf61` | Trailing `/` or `..` in rename produced empty / invalid names | Slot leak until reboot | Ring 3 `SYS_RENAME` |
| 12 | `7b17bfa` | 16 system-wide slots, only a per-process cap: one user with two processes took all; every exec opens through this table | **DoS of all exec, root included** | Ring 3, unprivileged |
| 13 | `7b17bfa` | `ramfs_open()` picked a slot and claimed it ~150 lines later across a sleep: two tasks could share a slot | Race → premature free under another task | Ring 3 |

### Shell / editor — `src/shell_redir.c`, `src/editor.c`, `src/shell.c`

| # | Commit | Defect | Nature | Reach |
|---|---|---|---|---|
| 14 | `2fa11e9` | `parse_redirections` copied trailing spaces past the NUL (`ls `) | Out-of-bounds read | Any user, kshell |
| 15 | `6f518a1` | `:w` did not truncate; a shorter save kept the old tail | Data corruption | Any user, `edit` |
| 16 | `6f518a1` | A file too large to hold loaded short but said "Loaded", next `:w` destroyed the original | Data loss | Any user, `edit` |
| 17 | `6f518a1` | Enter truncated the row even when inserting the new row failed | Data loss | `edit` |
| 18 | `6f518a1` | Backspace join over 4096 deleted the row after the append refused | Data loss | `edit` |
| 19 | `6f518a1` | Negative cursor column read/appended `E.rows[-1]` — the preceding pmm frame | **Kernel memory OOB read/write** | Any user, `edit` |
| 20 | `6f518a1` | Join at top of a scrolled view set `E.cy = -1` | Out-of-range cursor | `edit` |
| 21 | `e25bd9f` | Kernel-shell `echo x > f` printed to console, left `f` empty | Functional | kshell |

### ELF loader / process creation — `src/elf.c`, `src/process.c`

| # | Commit | Defect | Nature | Reach |
|---|---|---|---|---|
| 22 | `beca79f` | Program-header table bound checked against a fixed limit, not `elf_size` | Heap OOB read | Unsigned ELF (permissive build); defence in depth |
| 23 | `98491d0` | Child's guard page marked not-present in the **caller's** COW-cloned page table; frame freed and reused → ring-0 #PF | **Kernel panic** from spawn + waitpid + open | Ring 3, unprivileged |
| 24 | `9449aa8` | Every exec closed **every process's** close-on-exec RAMFS fds, not its own; the holder's next write hit whoever reused the slot | **Cross-user file write** | Ring 3, unprivileged |
| 25 | `46ea545` | Every spawn printed ~24 lines incl. the child's ASLR stack address and page-table physical addresses | **ASLR information leak** + console flood | Ring 3, unprivileged |

### Syscalls / pipes / streams — `src/syscall.c`, `src/stdio.c`

| # | Commit | Defect | Nature | Reach |
|---|---|---|---|---|
| 26 | `d472841` | `sys_readdir()` copied a reused stack dirent to ring 3; FAT32 names left stale bytes | **Kernel stack info leak** | Any user listing `C:/` |
| 27 | `bfe006b` | Pipe destroy / owner exit freed frames a spawned child still wrote through | **Use-after-free**: any user writes into recycled kernel memory | Ring 3, all calls ungated |
| 28 | `3f02d9a` | Inherited redirected stdout passed as a bare fd number; creator's close freed it, next `ramfs_open()` reused it | **Cross-user file write** | Ring 3 (`cmd > f &`, pipelines) |
| 29 | `0500765` | `sys_exit` released no fds or pipes (only kill did) | Resource leak → table exhaustion DoS | Ring 3 |
| 30 | `851b7e3` | `SYS_REDIRECT` / `SYS_CHMOD` refused absolute paths with `-EXDEV` | Functional | Ring-3 shell |
| 31 | `999f83d` | Exit/kill printed 4 lines per exit into the shared console | Console flood | Ring 3 loop |
| 32 | `5323b1c` | Bad read/write buffers and failed spawns printed per call | Console flood | Ring 3 loop |

### TCP — `src/tcp.c`

| # | Commit | Defect | Nature | Reach |
|---|---|---|---|---|
| 33 | `2d6c7bf` | 8-socket table, no per-user cap, CLOSED sockets never reclaimed: open 8 and exit | **TCP denied to kernel and root until reboot** | Ring 3 `SYS_TCPSOCK` (ungated) |
| 34 | `2d6c7bf` | FIN_WAIT_1 / CLOSING / LAST_ACK had no timeout | Socket leak via a silent peer | Remote peer |
| 35 | `fb164ed` | Send/connect refusals, reaps and zero-window printed per event | Console flood, peer-driven | Ring 3 / remote |

## Nature of the issues

| Class | Count | Defects |
|---|---|---|
| Memory safety (OOB, UAF, stale mapping) | 8 | 3, 14, 19, 22, 23, 26, 27, 13 |
| Cross-user / privilege boundary | 5 | 8, 24, 28, 25 (ASLR leak), 26 (info leak) |
| Denial of service (lockup, panic, exhaustion) | 9 | 4, 9, 11, 12, 23, 29, 33, 34, 6 |
| Data loss / corruption | 9 | 2, 5, 7, 10, 15–18, 20 |
| Console flooding by an unprivileged loop | 4 | 31, 32, 35, 25 |
| Undefined behaviour | 1 | 1 |
| Functional | 2 | 21, 30 |

(A defect appears under one primary class; #23 is listed under both memory safety
and DoS because the stale mapping is the cause and the panic the effect.)

### Highest severity

1. **#27 Pipe UAF** — any user writes into recycled kernel frames.
2. **#23 Guard-page stale mapping** — any user panics the kernel.
3. **#24, #28 fd reuse** — any user's writes land in another user's (or root's) file.
4. **#8 Missing directory search permission** — root-only directories hid nothing.
5. **#12, #33 Table exhaustion** — one unprivileged user stops all exec / all TCP.

## Where the bugs clustered

| OS function | Defects |
|---|---|
| Filesystems (RAMFS + FAT32) | 12 |
| Process lifecycle / ELF / syscalls / pipes | 11 |
| Kernel-shell editor and parser | 8 |
| TCP | 3 |
| Network RX (IDS) | 1 |

The network parsers, the hardened surface from earlier audits, produced one UB in
230M executions. The bugs concentrated where earlier ring-3 migration work made
older kernel code reachable from user space: shared global tables (RAMFS fds,
TCP sockets, pipes) with no per-user ownership, and lifetimes that assumed a
single kernel-shell caller.

## Regression and validation

- Every fix has a regression seed (fuzz) or a QEMU harness, run against the fix
  (PASS) and the parent (FAIL).
- New harnesses: `verify-pipe-uaf`, `verify-spawn-guard-frame`,
  `verify-ramfs-fd-reuse` (4 legs), `verify-tcp-socket-cap`, `verify-exit-quiet`,
  `verify-tcp-quiet`, `verify-syscall-io-quiet`, `verify-spawn-quiet`,
  `verify-kshell-echo-redirect`.
- Full regression (83 harnesses, 157 min): 77 pass first time. The 6 non-passes
  were harnesses keyed on prints that the quiet sweeps removed (4 by this branch,
  2 already broken on `main` by `b0946e0`), a stale module count in the
  architecture diagram, and a library the batch runner should not run. All fixed
  in `abe350f`, `6db98f6`, `2f525b3`, `47feb7e`; re-run PASS.
