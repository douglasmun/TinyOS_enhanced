# TinyOS Security Audit — 2026-08-21

> **STATUS: ALL 16 FINDINGS FIXED AND MERGED (as of 2026-08-22, `main` @ `b89b374`).**
> This document is a **historical record**, not a live vulnerability list. It is
> preserved because the *reasoning* — why each defect survived earlier sweeps, and
> what class of review would have caught it — is worth more than the individual
> fixes. The findings below are written in the present tense **as of the audit**;
> the "Fixed in" column of §2 gives the commit that closed each one.
>
> Fixes landed in PR #103 (all 16 fixes + nine harnesses), PR #104 (validated the
> five harnesses that had never been run end to end — no kernel defect, but two
> harness false-passes closed), and PR #105 (the firewall block/selectivity legs
> that §2 finding 3 recorded as NOT COVERED).

Tree audited: `main` @ `cb4110e` (clean). Scope: the `SRC :=` block of the Makefile only.
Every finding below was verified against the source at the cited line; findings that
contradicted a documented decision in `CLAUDE.md` or `doc/` were dropped rather than reported.

---

## 1. Executive summary

The kernel's *documented* invariants are in good shape — the areas that CLAUDE.md and `doc/`
call out (ELF image-frame tracking, the reaper's dequeue-before-free ordering, `ramfs_chmod`
ownership, TCP/ICMP/DNS-response RX counters, `SYS_MSEAL`'s print sweep, the netd arbitration
rules) all hold under inspection. The defects that survived verification are almost entirely in
the *gaps between* those documented sweeps: a filesystem primitive that every sibling function
guards and this one does not, a print sweep that stopped at the file it was written to fix, a
teardown fix applied to the exit path but not to the three creation-failure paths beside it.

Two findings are serious. `ramfs_unlink()` frees the inode and all of its data frames while open
file descriptors still hold a raw pointer to them, giving any unprivileged ring-3 process an
arbitrary-content write into PMM-recycled frames — the FAT32 driver refuses exactly this case,
with a comment explaining why, and RAMFS was simply never given the same check. `ramfs_open()`'s
create branch performs no write-permission check on the parent directory, so a uid-1000 process
can plant files in any root-owned directory outside the five hardcoded protected prefixes; the
comment at `kernel.c:971` shows the author believed the opposite was true and created a separate
0777 `/scratch` to work around a restriction that does not exist.

The network posture is weaker than the boot banner claims. Two convenience functions install
fully-zeroed wildcard ACCEPT rules at the two lowest priorities, which makes the firewall's
"default DENY ALL" unreachable and — because `firewall_block_ip()` shares priority 10 and is
appended later — renders the IDS's only enforcement action inert. Three protocol files
(`dns.c`'s `skip_dns_name`, `net.c`'s `handle_udp`, `dhcp.c`) still carry remote-driven `kprintf`
sites, which is the fifth recurrence of a class the project has now swept four times; the
`doc/NETWORK_ISOLATION.md` history predicts this failure mode exactly.

The remainder is lower-grade: three ring-3-driven console-flood sites in the syscall dispatcher,
one audit-buffer eviction primitive, a dangling `fpu_owner` after external kill, an off-by-one in
five shell path builders, a never-enqueued EDR daemon, and cross-session history retention in the
kernel shell. Nothing found is remotely exploitable for code execution: the highest-tier remote
issues are a defeated filter layer and console floods, not memory corruption. Two initially-reported
findings were refuted outright and appear in the appendix.

**Honest grade:** the hardening work that has been *done* is genuinely rigorous and the harness
discipline is unusual for a project this size. The weakness is coverage — every one of the top
findings sits one function, one file, or one code path away from an area that was audited
carefully. The recurring lesson is the one the project already wrote down and keeps re-learning:
*sweep the class, not the file that prompted the sweep.*

---

## 2. Confirmed findings, ranked

All sixteen are **fixed**; the final column names the commit that closed each.

| # | Sev | Location | Summary | Fixed in |
|---|-----|----------|---------|----------|
| 1 | Critical | `src/ramfs.c:1081` | `unlink` frees the inode under open fds → ring-3 arbitrary-content kernel write | `7197748` |
| 2 | High | `src/ramfs.c:651` | `open`'s create path never checks parent-directory write permission | `7197748` |
| 3 | High | `src/firewall.c:894` | Wildcard ACCEPT rules make "default DENY ALL" unreachable; IDS blocks are inert | `c5fa987`, legs `bf260a9` |
| 4 | Medium | `src/dns.c:315` | Seven remote-driven `kprintf` in `skip_dns_name()` missed by the DNS sweep | `c5fa987` |
| 5 | Medium | `src/net.c:1150` | Five remote-driven `kprintf` in `handle_udp()` — a never-swept protocol file | `c5fa987` |
| 6 | Medium | `src/dhcp.c:373` | Pre-XID `kprintf` on the one UDP path the firewall explicitly exempts | `c5fa987` |
| 7 | Medium | `src/process.c:1160` | Guard page freed without restoring its identity mapping (3 failure paths) | `a8b1749` |
| 8 | Medium | `src/syscall.c:3176` | Invalid-syscall `kprintf` before the EDR hook (+ two sibling sites) | `c12cc09` |
| 9 | Medium | `src/syscall.c:3120` | `sys_mseal` audit record lets ring 3 evict the forensic ring buffer | `b36de76` |
| 10 | Medium | `src/shell_fileops.c:349` | One-byte stack OOB write in five shell path builders | `c12cc09` |
| 11 | Medium | `src/shell.c:1123` | Kernel-shell history survives logout, leaking commands to the next user | `863b92f` |
| 12 | Low | `src/scheduler.c:1344` | Dangling `fpu_owner` after external kill corrupts another task's FPU state | `536ecf7` |
| 13 | Low | `src/ramfs.c:1481` | Access mode 3 yields a vacuous permission grant (size oracle) | `c12cc09` |
| 14 | Low | `src/elf.c:1254` | Head gap of an unaligned `PT_LOAD` never zeroed (signature-gated) | `c5772f8` |
| 15 | Low | `src/entropy.c:391` | `pool_counter` incremented only inside the branch it gates → pool never re-stirs | `536ecf7` |
| 16 | Low | `src/kernel.c:1066` | EDR daemon created but never enqueued; `secstatus` reports 0/0/0 forever | `6fd5ac5` |

---

### Finding 1 — `ramfs_unlink()` frees the inode while open fds still point at it

**Severity: CRITICAL** · `src/ramfs.c:1081` · use-after-free · *verified by direct read*

`ramfs_unlink()` ends with:

```c
    parent->child_count--;  // Decrement counter (v1.13)

    free_node(node);
    mutex_unlock(&ramfs_mutex);
    return 0;
```

`free_node()` (`src/ramfs.c:179`) `pmm_free()`s every `node->data_pages[i]` and then the
`ramfs_node_t` frame itself. Neither function consults `file_descriptors[]`. `ramfs_fd_t` holds a
raw `ramfs_node_t*` with no refcount, and nothing clears `.node` or `.in_use` on unlink.
`ramfs_read()`/`ramfs_write()` validate only `in_use`, the flag bits, and `node != NULL` — the
pointer is stale, not NULL — so both keep dereferencing freed PMM frames. The VFS layer makes it
worse: `ramfs_fd_handle_t` stores the ramfs fd *index* (`src/ramfs_vfs.c:47`), so every subsequent
`write()` re-reads the stale `file_descriptors[fd].node`.

The asymmetry is the tell. `src/fat32.c:1367-1384` refuses precisely this, with a comment:
*"Refuse to unlink a file that is currently open … return -3; // Busy"*. Both halves were the same
PR; only FAT32 got the check.

**Who can drive it, how.** An unprivileged ring-3 process, uid 1000, no setup, against the
world-writable `/scratch` (0777, `src/kernel.c:973-975`):

```c
fd = open("/scratch/x", O_RDWR);   /* SYS_OPEN  → ramfs_open, fd cached in the VFS handle  */
unlink("/scratch/x");              /* SYS_UNLINK → free_node(): frees node + 16 data_pages */
write(fd, attacker_bytes, 4096);   /* SYS_WRITE  → ramfs_write on freed frames             */
```

`pmm_free()` neither zeroes nor unmaps; the frames stay identity-mapped `PAE_PRESENT|
PAE_READWRITE` and go straight back on the free list for the next `pmm_alloc()` — a PAE page
table, a `task_t`/kernel stack, an ELF image page. `ramfs_write` bounds `pos` by `RAMFS_MAX_DATA`
and breaks at `RAMFS_MAX_PAGES`, so the corruption is confined to the ≤16 freed data frames plus
the freed node frame: **64 KB of attacker-chosen content written into PMM-recycled kernel frames.**
`ramfs_read` is the disclosure direction. `node->size = needed_size` also writes into the freed
node frame.

**Secondary variant, same root cause.** `ramfs_fd_handle_t.dir_node` (`src/ramfs_vfs.c:60`) is a
raw pointer walked by `ramfs_vfs_readdir()` and freed by `ramfs_rmdir() → free_node()` — a
read-side UAF of identical shape. The struct's own comment notes the *cursor* was made an index to
avoid a dangling child pointer, while leaving `dir_node` exposed.

**Fix.** Mirror `fat32.c:1367`: before `free_node()`, scan `file_descriptors[]` for
`in_use && node == victim` and return a distinct busy sentinel. `-1`, `-2`, `-4` and `-5` are
already taken in this function, so pick an unused constant — the same collision rule that produced
`RAMFS_CHMOD_EPERM`. Do the same in `ramfs_rmdir()` for cached `dir_node` handles. If
unlink-while-open must be supported, add a refcount to `ramfs_node_t` and defer `free_node()` to
the last `ramfs_close()`.

**Harness — `verify-ramfs-unlink-busy.sh`:**
- **Leg 1 (the bug):** as uid 1000, `open` a file in `/scratch`, `unlink` it, then `write` — assert
  the `write` returns the busy/`-EBADF` error, **not** success. Record `pmm` free-frame count before
  the `open` and after `close`; assert **exact equality** (a double-free shows as free frames
  *rising*, per the `verify-exec-frame-leak.sh` precedent).
- **Positive control (mandatory):** `unlink` a file with **no** open descriptor must still succeed
  and must still free its frames. Without this leg, an `unlink` that refuses *everything* passes
  Leg 1 perfectly.
- **Negative control:** re-run Leg 1 against a build with the busy check reverted and assert the
  harness fails. Do **not** assert on `cat` output — the freed frame frequently still reads back the
  old bytes, so a content-based assertion passes against the bug.
- **Directory leg:** `opendir` a directory, `rmdir` it, then `readdir` — assert refusal.

---

### Finding 2 — `ramfs_open()`'s create path performs no parent write-permission check

**Severity: HIGH** · `src/ramfs.c:651` · missing authorization · *verified by direct read*

Every other mutating ramfs primitive checks the parent before linking or unlinking a child:
`ramfs_mkdir` (`:498`), `ramfs_unlink` (`:1047`), `ramfs_rename`, `ramfs_rmdir` — each has the
identical `if (!ramfs_check_permission(parent, uid, gid, RAMFS_FLAG_WRITE))` block. The create
branch of `ramfs_open()` does not. I read the whole branch (`src/ramfs.c:590-665`): the parent walk
matches names only, the sole gate is `if (parent->child_count >= RAMFS_MAX_CHILDREN_PER_DIR)` — a
DoS limit, not an access check — and the node is then linked in unconditionally:

```c
            // Create new file
            node = alloc_node(components[num_components - 1],
                              RAMFS_TYPE_FILE, uid, gid);
            ...
            node->parent = parent;
            node->next = parent->children;
            parent->children = node;
            parent->child_count++;  // Increment counter (v1.13)
```

The caller's uid is read at `:548` but used only to *stamp* the new node's ownership. The trailing
`ramfs_check_permission` at `:690` tests the **new** node, which the caller now owns, so it passes
trivially. No caller compensates: `ramfs_vfs_open()` only translates flag bits (`ramfs_vfs.c:150`),
and `sys_open()` explicitly delegates (*"vfs_open enforces the uid/permission checks"*). `vfs_open`'s
only write gate is the hardcoded five-prefix `CAP_SYS_ADMIN` list (`/bin/`, `/sbin/`, `/etc/`,
`/boot/`, `/kernel`, `src/vfs.c:672-702`) — every other root-owned directory is uncovered.

This is the exact class `CLAUDE.md` documents for `ramfs_chmod`: *"Enforce permissions in the ramfs
primitive, not the command."* The mode bits on a directory are only load-bearing because everything
else is enforced; this is the one mutation that skips them.

**Who can drive it, how.** `/fio` is created root-owned 0755 (`src/kernel.c:951`). A uid-1000
ring-3 process calls `open("/fio/planted.txt", O_WRONLY)`. Path matches no protected prefix, so the
`CAP_SYS_ADMIN` gate is skipped; `ramfs_vfs_open` sets `RAMFS_FLAG_WRITE`; the create branch links
the node into `/fio`. The new node is 0600 owned by uid 1000, so the attacker writes it freely, and
it shows up in every `ls /fio`. The same works for any root-owned directory outside the five
prefixes, and it also lets an unprivileged user exhaust a root-owned directory's
`RAMFS_MAX_CHILDREN_PER_DIR` budget, denying root creation there.

**Broader than first reported:** `O_CREAT` is *not* required. `ramfs_open` never sees `O_CREAT` —
`ramfs_vfs_open`'s translation only ever sets READ/WRITE bits — so **any write-flagged open of a
missing path creates it.** A plain `O_WRONLY` suffices.

**Confirming evidence that this is an oversight, not a decision:** `src/kernel.c:971` states the
author's belief — *"It cannot share /fio: that one is 0755 root-owned, so a uid-1000 process cannot
create entries in it"* — and a separate 0777 `/scratch` was created to work around a restriction
`ramfs_open` does not enforce. `ramfs_mkdir` *does* enforce it, which is why the `mkdir` demo
genuinely needed `/scratch`, and why this went unnoticed.

**Fix.** In the create branch, after resolving `parent` and before `alloc_node()`:

```c
if (!ramfs_check_permission(parent, uid, gid, RAMFS_FLAG_WRITE)) {
    mutex_unlock(&ramfs_mutex);
    return -7;  /* permission denied */
}
```

Put it in the primitive, not in `ramfs_vfs_open`, so the next caller inherits it — the same
reasoning that made the `ramfs_chmod` fix hold when `SYS_CHMOD` later arrived.

**Harness — `verify-ramfs-create-perm.sh`, two deliberately opposite adjacent legs** (the
`verify-ring3-chmod.sh` pattern):
- **Exclusion leg:** as uid 1000, `open("/fio/x", O_WRONLY)` must fail, and `ls /fio` must not list
  `x`. Assert on the *listing*, not just the return code.
- **Positive control (mandatory, same user):** the same unprivileged user must still succeed at
  `open("/scratch/x", O_WRONLY)` and at creating a file in their own 0700 directory. A create path
  that refuses *everything* passes the exclusion leg alone.
- **Root leg:** root creating in `/fio` must still work.
- Drive it as a **non-root** user — this is an ownership-gated syscall, so an unprivileged
  `-EPERM` on the caller's *own* directory is the bug.

**VERIFIED 2026-08-22 — PASS.** All three legs green: `crperm` (uid 1002) refused on root-owned
0755 `/rootonly` via **both** entry points (`touch` and shell redirection, the two-entry-point
requirement that proves the check is in the primitive rather than in `cmd_touch`), and succeeded
at creating `/ownplace/mine.txt`.

Getting there took two harness repairs, both of which made a **correct kernel report FAIL** — the
failure mode worth remembering, since the instinct is to go hunting in the kernel:

1. *Setup.* `mkdir /ownplace` ran **after** `su`, but RAMFS root is 0711 (`ramfs.c:329`) — search,
   no write, for non-owners. So the unprivileged mkdir was correctly refused with `-5` and the
   **positive control was measuring that refusal instead of the create path**. Fixed by creating
   and `chmod 777`-ing the directory as root *before* `su`; there is no chown builtin, and the leg
   only needs the parent's write bit. The harness's own INCONCLUSIVE branch had predicted exactly
   this, which is why it reported a setup problem rather than a fix failure.
2. *Analysis.* Legs 1/1b grepped the session log for the filename — matching
   `Error: Cannot create file '/rootonly/planted.txt'`, i.e. **the message that proves the fix
   worked**, plus the typist's line-wrapped echo of the typed redirection target
   (`otonly/redir.txt`). A negative assertion grepped over a whole log matches the diagnostics
   that exist *because* the operation was blocked, so it misfires precisely when the kernel is
   right. Fixed by filtering the refusal shapes **and** dropping any candidate line containing
   `/` (`ls` prints bare basenames, so a path separator means echo or prose, never an entry), then
   re-validated with a negative control injecting a real listing entry to confirm the legs are not
   now blind.

**Follow-up applied.** Leg 3 reported `NOTE: no refusal message was printed (silent refusal)`.
The kernel's refusal was correct and the `RAMFS_CREATE_EPERM -> VFS_EACCES` mapping in
`ramfs_vfs.c:203` was already right — but `cmd_touch` (`shell_fileops.c:1177`) collapsed *every*
`ramfs_open` failure into one `Error: Cannot create file` string, discarding the sentinel. A
refusal on a directory that plainly exists therefore read the same as a missing path, which is
the ENOENT-vs-EACCES information-quality problem this finding calls out elsewhere. `cmd_touch`
now reports `touch: permission denied` for `RAMFS_CREATE_EPERM` specifically.

---

### Finding 3 — Wildcard ACCEPT rules make "default DENY ALL" unreachable

**Severity: HIGH** · `src/firewall.c:894` · access control · threat class 1 (remote) · *verified*

```c
void firewall_allow_established(void) {
    ...
     * SECURITY: This doesn't open new inbound connections, only allows
     * responses to connections we initiated.
     *=======================================================================*/
    firewall_rule_t rule = {0};
    rule.action = FW_ACTION_ACCEPT;
    rule.priority = 10;  /* High priority - check established first */
    safe_strcpy(rule.description, "Allow established/related", sizeof(rule.description) - 1);
    firewall_add_rule(&rule);
```

Only `action` and `priority` are set. Every match field stays 0, and `match_rule()` treats 0 as
"any" on all of them: `ip_matches` returns true when `rule_ip == 0` (`firewall.c:35`),
`port_matches` likewise (`:43`), and the protocol test is skipped entirely
(`if (rule->protocol != 0 && ...) continue;`, `:479`). Crucially, `firewall_rule_t`
(`src/firewall.h:57-81`) has **no direction field at all** — only an unread `bool bidirectional` —
so "established/outgoing" is not expressible, and `match_rule()` never consults the
connection-tracking table. The rule matches every packet, inbound included.

Three things close the obvious refutations. `firewall_add_rule()` does
`rules[rule_count].enabled = true;` unconditionally, so the zeroed `enabled` in `{0}` does not
disable it. It is installed at boot from `kernel.c:698` at priority **10**, the lowest numeric
value, scanned first by `for (uint32_t prio = 0; prio < 1000; prio++)`. And `is_bogon_ip()` has
10/8, 172.16/12 and 192.168/16 explicitly commented out (*"Disabled for LAN operation"*), so a
same-segment source is not caught earlier. `firewall_allow_outgoing()` (`:876`, priority 100) is
identically all-wildcard.

Consequently the `/* Default: DENY ALL */ stats.packets_dropped++; return false;` at `:744` is dead
code for anything that clears the bogon and rate-limit checks, and the boot banner *"[FIREWALL]
Default policy: DENY ALL"* (`:762`) prints identically whether the filter works or not — the
status-surface-lie class the project already tracks. `doc/FIREWALL_AND_IDS_CONFIG.md:34` asserts the
opposite of the implemented behaviour.

**Second-order: the IDS's only enforcement action is inert.** `firewall_block_ip()` (`:924`) also
uses priority 10 and is appended at a *higher array index* than the boot wildcard, so
`match_rule()`'s insertion-order inner loop finds the wildcard ACCEPT first within the same band.
`ids.c:170` (`firewall_block_ip(src_ip)`) is the IDS's sole blocking path — so a matched BLOCK
signature never blocks anything.

**Who can drive it, how.** Any host on the segment, no local account: send any IPv4 packet to the
guest's unicast IP or to any `x.x.x.255` (accepted as subnet broadcast, `net.c:1551`). Not a bogon,
passes the rate limit, matches the priority-10 wildcard, `FW_ACTION_ACCEPT`. Every inbound
UDP/TCP/ICMP datagram reaches the parsers regardless of any DROP rule.

**Fix.** Delete the `firewall_allow_established()` rule entirely and let the existing
connection-tracking branch in `firewall_check_packet()` be the sole established-traffic path — that
branch is what the rule's own comment claims to rely on, and it already runs before `match_rule()`.
For `firewall_allow_outgoing()`, either add a source predicate (`src_ip = my_ip`, mask
`0xFFFFFFFF`) or drop it, since nothing on the RX path is outgoing. Separately, give
`firewall_block_ip()` a numerically lower priority than any ACCEPT (e.g. 0), and make `match_rule()`
prefer DROP over ACCEPT within a priority band.

**Harness — `verify-firewall-default-deny.sh`** (needs a host-side packet sender):
- **Deny leg:** with no allow rule covering it, send a UDP datagram to an unbound port from the host
  and assert `firewall` stats show `packets_dropped` incrementing and `packets_accepted` **not**.
- **Positive control (mandatory):** the guest's own DHCP/DNS/`curl` traffic must still complete
  end-to-end in the same boot. "Everything is dropped" otherwise satisfies the deny leg perfectly —
  and would be an equally broken firewall.
- **Block leg:** call `firewall_block_ip(host_ip)` (via the IDS or a shell command), then send from
  that host and assert the packet is dropped. This is the leg that catches the priority collision;
  it fails today.
- **Selectivity leg:** a packet from a *different* source must still be accepted while the first is
  blocked — otherwise a `block_ip` that drops everything passes.

**VERIFIED 2026-08-22 - PASS (both arms), with one leg NOT covered.**

- **Arm A (deny):** 12 unsolicited inbound SYNs from TEST-NET-3 raised the firewall's `dropped`
  counter by **exactly 12**, so the default-DENY arm at the bottom of `firewall_check_packet()` is
  genuinely reachable and no wildcard ACCEPT outranks it.
- **Arm B (admit, positive control):** a DNS reply to the guest's own query was still admitted in a
  second boot on user-mode NAT. Without this arm, arm A is satisfied by a firewall that drops
  *everything* - equally broken.

Arm A needed the same addressing repairs as Findings 5 and 6 (`--dst-ip {GIP}` captured from the
guest, `--src-ip 203.0.113.9`). The bogon point is sharper here than elsewhere: `is_bogon_ip()`
*does* increment `dropped`, so an RFC1918 source would have satisfied arm A's assertion **without
the default-deny arm ever being reached** - the exact unfalsifiable shape the two-arm structure
exists to rule out. A third `secstatus` reading was also removed after review: the harness parses
readings 1 and 2, and adding a capture step would have made both of them *pre-injection*, giving
delta 0 and reporting the wildcard-ACCEPT bug against a correct kernel.

**BLOCK LEG NOW COVERED 2026-08-22 - PASS, with a negative control.** The gap noted here (no
end-to-end drive of `firewall_block_ip()`) is closed by a separate harness,
`verify-ids-block-leg.sh`, because it needs a different netdev and a different vehicle than either
arm above.

**The vehicle is ICMP, and that is forced.** The attack frame must reach `ids_analyze_packet()`,
which sits *below* `firewall_check_packet()` in `handle_ip()` - so it must first be **accepted by a
rule**, not by a short-circuit. Both short-circuits are disqualifying: the DHCP exception
(ports 67<->68) returns true *before* `match_rule()` is consulted, so a priority-0 block could never
be reached and leg 2 would be admitted whether the block worked or not - unfalsifiable, and exactly
the trick `verify-udp-rx-counters.sh` relies on for its own purposes. Established-connection
tracking also returns above the rules, but ICMP creates no connection entry. `firewall_allow_icmp()`
installs ACCEPT at **priority 50** (`kernel.c:704`) and `firewall_block_ip()` installs DROP at
**priority 0**, so ICMP is admitted by a real rule and the block genuinely has to outrank a live
ACCEPT - the precise collision this finding is about. Nothing else in the tree offers that.

Three legs, one boot, on the mcast netdev with `--dst-ip {GIP}` captured from the guest and
TEST-NET-3 sources:

| Leg | Frame | Required | Measured |
|---|---|---|---|
| 1 attack | ICMP + `90 90 90 90 31 c0`, attacker IP | IDS matches and blocks | matches 0->1, IPs blocked 0->1 |
| 2 block | **clean** ICMP, *same* source | dropped by the priority-0 rule | dropped **10 of 10** |
| 3 selectivity | **clean** ICMP, *different* source | accepted | **0 of 10** dropped, 10 counted |

Leg 2's frames carry **no signature on purpose**: the block rule is then the only thing that can
drop them, so a pass cannot be explained by the IDS dropping them again. Legs 2 and 3 are
*identical frames differing only in source IP*, so nothing but the source explains the difference -
and without leg 3, legs 1+2 are satisfied perfectly by a firewall that blocks **everything** after
any alert.

**Negative control run.** With `rule.priority` moved to 50 (the same band as the boot-time ICMP
ACCEPT) and the deny-before-accept tie-break disabled, **leg 2 failed with 0 of 10 dropped while
legs 1, 1b and 3 all still passed** - reproducing the original bug and confirming leg 2 is the only
leg that detects it. A second signal fell out of the same run: with no block installed, all four
attack frames matched (`matches 0->4`) instead of one, because the source was never blocked after
the first.

Two notes carried forward. The `priority = 0` source guard must scan the **whole function body**,
not a fixed `grep -A3` window - the explanatory comment above the assignment is long enough that
`-A3` misses a priority that *is* 0 and reports a correct kernel broken (caught before the first
run). And the deny-first guard is text-based and survives `if (0 && ...)`, so it was widened to
check the two-pass loop header as well; it is weaker than the priority guard by nature, and leg 2 is
what actually decides.

`tools/inject_frames.py` gained `--payload-hex` for this: the generated filler payload can never
match a signature, so the attack bytes have to be placed verbatim.

---

### Finding 4 — Seven remote-driven `kprintf` in `skip_dns_name()`

**Severity: MEDIUM** · `src/dns.c:315` (also 332, 357, 364, 375, 382, 392) · threat class 1

The DNS sweep documented at `dns.c:71-91` scoped itself to *"handle_dns_response() had 20 kprintf
sites"* and converted those to counters. The helper it calls on the same path was not swept.
`skip_dns_name()` still carries seven `kprintf` calls, selected purely by attacker-chosen bytes —
truncated name, pointer at packet edge, offset past `packet_end`, forward/self pointer, over-63
label length, label past end, 127-label chain. Two format attacker-chosen data (`offset`) into the
line.

```c
    while (label_count < MAX_DNS_LABELS) {
        // Boundary check: ensure we can read the length byte
        if (current_pos >= packet_end) {
            kprintf("[DNS] SECURITY: Name parsing exceeded packet boundary. Dropping.\n");
            return 0;  // Error: exceeded packet boundary
        }
```

**Correction to the initially-reported attack path.** The *question*-section call
(`dns.c:608`) is unreachable for these prints: the question name is first passed to
`dns_label_to_domain()` (`:594`), a near-duplicate validator that rejects every one of these
malformations **silently** at `:449` (bare `return false` → `dns_drop_question`). The finding
survives via the **answer** section: `skip_dns_name()` at `:649` parses the answer RR name with no
preceding `dns_label_to_domain` — those bytes are unfiltered.

**Who can drive it, how.** An on-path host on the segment observes an outbound query in cleartext
(both gates — the `memcmp` against `dns_server` at `:539` and the 16-bit `last_dns_tid` at `:549` —
are readable from it), then replies from the DNS server's IP with the matching TID, QR=1, RCODE=0
and a correctly echoed question name, and sets `ancount ≥ 1` with an answer name of `0xC0 0xFF`.
That hits `dns.c:357`, formatting the attacker-chosen `offset` onto the kernel console. The answer
loop runs per record with `ancount` up to 65535, so one 512-byte packet yields many lines onto the
serial console the ring-3 login shell shares with user output.

Note the CLAUDE.md exemption (*"dns.c's local-`dig`-driven prints stay"*) covers the **query** path
(`:715, 726, 754, 817, 872`), not these.

**Fix.** Replace all seven with counters, grouped by attacker position: fold the boundary/truncation
cases (315, 332, 382, 392) into the existing `dns_drop_malformed`; add **one** counter for the
compression-pointer signature covering 357 **and** 364 (both are one attack — a hostile pointer);
add one for invalid label length at 375. Surface them from `dns_get_rx_stats()`/`ifconfig`. Never
format `offset` or any name byte into output.

**Harness — extend `verify-dns-rx-counters.sh`** (already needs `-DTINYOS_FAULT_INJECT`):
- **Answer-name leg:** forge a response whose *answer* RR name is `0xC0 0xFF`; assert the
  compression-pointer counter rises by exactly 1 and that **no** new line appears on serial.
- **Selectivity:** a forged response with a malformed *question* name must land on
  `dns_drop_question`, not on the new pointer counter — otherwise a count-everything counter passes
  the exact-delta assertion.
- **Positive control:** the existing `valid` leg must still resolve, so the counters are not
  satisfied by a parser that rejects every response.

---

### Finding 5 — Five remote-driven `kprintf` in `handle_udp()`

**Severity: MEDIUM** · `src/net.c:1150` (also 1112, 1157, 1159, 1178) · threat class 1

```c
    /* VALIDATION 1: UDP length must be at least size of UDP header */
    if (len < sizeof(udp_header_t)) {
        kprintf("UDP: SECURITY - Invalid UDP length %u (< UDP header size %zu). Dropping.\n",
                len, sizeof(udp_header_t));
        return;
    }

    /* VALIDATION 2: UDP length must not exceed IP payload size */
    if (len > ip_payload_len) {
        kprintf("UDP: SECURITY - UDP length %u exceeds IP payload %u. Dropping.\n",
                len, ip_payload_len);
        kprintf("UDP: Possible attack: IP claims %u bytes, UDP claims %u bytes\n",
                ip_payload_len, len);
        return;
    }
```

Each is selected by a header field the sender controls; one malformed datagram produces **two**
console lines. Line 1178 fires on a bad UDP checksum, which costs the attacker nothing. None sits
behind a port match, a socket lookup, or any authentication. `handle_ip()` dispatches to
`handle_udp()` (`net.c:1670`) for any inbound IPv4 UDP datagram with `payload_len >= 8` that the
firewall accepts — and per Finding 3, the firewall accepts everything.

`doc/NETWORK_ISOLATION.md` enumerates the swept sites (`net.c:1652`, `net.c:1687`, four in
`e1000.c`) as *Resolved*; `handle_udp`'s five are absent from that list, and no UDP drop counters
exist in `net.h`. This is a fifth protocol file, sitting between the already-swept `dns.c` and
`tcp.c`.

**Who can drive it, how.** Any host on the segment sends IPv4/UDP to the guest's IP (or any
`x.x.x.255`) with a 40-byte IP payload and the UDP length field set to `0xFFFF`. Each packet fails
VALIDATION 2 and emits two lines. The one genuine mitigation is `check_rate_limit()`
(`firewall.c:309`, ~100 packets/window per source), but buckets are per-source-IP and the RFC1918
bogon checks are disabled, so spoofing across the allowed private space restores the flood.

**Note on severity:** these run in *task* context on `knetd`, not the ISR, so unlike the swept
`e1000.c` sites they do not extend interrupt-off time. Medium, not high.

**Fix.** Convert all five to counters grouped by attacker position: one for a malformed UDP length
(1112, 1150, 1157, 1159 are all one signature — *"the UDP length field disagrees with the IP
payload"*) and one for a failed checksum (1178). Add `udp_get_rx_stats()` and print both in
`ifconfig` beside the DNS/ICMP/TCP counters.

**Harness — `verify-udp-rx-counters.sh`:**
- **Malformed leg:** send `len = 0xFFFF` over a 40-byte payload; assert the malformed counter rises
  by exactly 1 per packet and serial gains **zero** new `UDP:` lines.
- **Checksum leg:** send a well-formed datagram with a corrupted checksum; assert the *checksum*
  counter rises, and the malformed counter does **not** — the selectivity leg.
- **Positive control:** a well-formed datagram to an open port must still be delivered (DNS
  resolution still works in the same boot), so the counters are not satisfied by a handler that
  drops everything.

**VERIFIED 2026-08-22 - PASS.** All five legs green in one boot: forged-length **+12** (exact),
bad-checksum **+11** (exact and a *different* number, so the selectivity leg is real), accepted
**+13** (positive control), well-formed traffic touched no drop counter, and 36 injected datagrams
produced **0** console lines.

Getting there required three harness repairs, none of them kernel bugs, and all three failed the
same indistinguishable way - every delta 0 *including the positive control*, which reads as a dead
parser rather than a misaddressed sender:

1. **Address gate.** On the `socket,mcast=` netdev there is no DHCP server, so the guest
   self-assigns a per-boot link-local `169.254.x.y` and never holds the `10.0.2.15` the injector
   defaults to. Fixed by capturing the guest's own address (`@GIP=IP Address: +([0-9.]+)`) and
   passing `--dst-ip {GIP}`; this also required teaching `tools/qemu_typist.py` to substitute
   captures into **host hooks**, which it previously did only for typed commands.
2. **Bogon source.** `is_bogon_ip()` drops `10/8`, so the injector's default `--src-ip 10.0.2.99`
   died at the firewall one gate further along. Fixed with TEST-NET-3 `203.0.113.9` (RFC 5737).
3. **Firewall default-DENY.** The decisive one, and it invalidates this finding's original premise
   that "handle_udp validates lengths before any port dispatch or address state is consulted". The
   real order is address gate -> `firewall_check_packet()` -> L4 dispatch -> `handle_udp()`, the
   default policy is **DENY ALL**, and no shell command can add a rule - so an unsolicited datagram
   to port 9999 never reaches these counters at all. Fixed by injecting on ports **68->67**: the
   firewall's standing DHCP exception matches 67<->68 in either direction and returns accept before
   any rule lookup, while `handle_udp`'s dispatch test (`src_port==67 && dest_port==68`) does *not*
   match, so the frames fall through to no handler - which is exactly what the "port with no
   handler" requirement wanted. All four counters increment before port dispatch, so this measures
   the parser as intended.

The misleading comment above the counters in `src/net.c` ("before the firewall") has been corrected
in the same change, since it is what pointed the diagnosis the wrong way.

Diagnostic worth reusing: compare `ifconfig`'s `RX ring: N cpl0` (frames arrived) against
`RX proto-ring:` (frames reached the L4 dispatch switch, counted before any early return). A gap
localises the drop to `handle_ip` above the switch, which is how gate 3 was found.

---

### Finding 6 — Pre-XID `kprintf` in `handle_dhcp()`, on the one path the firewall exempts

**Severity: MEDIUM** · `src/dhcp.c:373` · threat class 1

```c
void handle_dhcp(const uint8_t* data, size_t len) {
    /* Suppress noisy logging of invalid packets to avoid interfering with VGA display.
     * Only log valid packets that pass XID validation (see below). */
    // kprintf("[DHCP] Received packet (%u bytes)\n", (unsigned int)len);

    if (len < sizeof(dhcp_header_t)) {
        kprintf("[DHCP] Packet too short (need %u bytes)\n", (unsigned int)sizeof(dhcp_header_t));
        return;
    }
```

This is the **first** statement in the function, before the `dhcp->op != DHCP_OP_BOOTREPLY` check
(`:379`) and the XID check (`:386`) — the two gates that would otherwise restrict the path to a
party who has seen our DISCOVER (XID is CSPRNG-generated, `:51-61`). The file's own header comment
states the invariant this line breaks.

It matters more than the file's other prints (`:89, 105, 120` in `parse_dhcp_options`, called at
`:411` *after* the XID gate, and `:452, 456, 484, 490, 492`) because
`firewall_check_packet()` contains an **unconditional DHCP exemption** at `firewall.c:635-639` that
returns `true` for any UDP 67↔68 packet **above** the bogon filter, the rate limiter, connection
tracking and rule matching. The one UDP path guaranteed to bypass every filter in the stack is also
the one carrying an ungated print.

**Who can drive it, how.** Any host on the segment, with no account and no observation of our
traffic: UDP src 67 → dst 68 at the guest's IP or `255.255.255.255`/any `x.x.x.255`, with a 10-byte
payload — enough to clear `handle_ip()`'s 8-byte minimum and `handle_udp()`'s length validation,
short of `sizeof(dhcp_header_t)`. The firewall's DHCP exception accepts it before any rule is
consulted, `handle_udp()` routes on `src_port == 67 && dest_port == 68` (`net.c:1218`), and
`dhcp.c:373` prints one line per packet at the attacker's rate.

`dhcp.c` was never swept at all — a grep for counters/stats in the file returns nothing.

**Fix.** Replace with a `dhcp_drop_short` counter, consistent with the intent already stated in the
comment above it, surfaced via `dhcp_get_rx_stats()` in `ifconfig`. **Sweep the whole file** while
there — patching only `:373` and marking `dhcp.c` done repeats the exact pattern
`doc/NETWORK_ISOLATION.md:274-286` records four times.

**Harness — `verify-dhcp-rx-counters.sh`:**
- **Short-packet leg:** send a 10-byte UDP 67→68 datagram; assert `dhcp_drop_short` rises by exactly
  1 and serial gains no `[DHCP]` line.
- **Positive control (mandatory):** boot-time DHCP must still acquire a lease in the same run —
  otherwise a `handle_dhcp` that returns immediately satisfies the drop leg and breaks networking.
- **Selectivity:** a full-length DHCP packet with a *wrong XID* must land on a distinct
  XID-mismatch counter, not on `dhcp_drop_short`.

**VERIFIED 2026-08-22 - PASS.** All five legs green: truncated **+9** (exact), bad-cookie **+5**
(exact, and a different number from the short count so the selectivity leg is falsifiable), replies
**+5** (positive control), the two signatures landed on separate counters, and 14 injected frames
produced **0** console lines.

The cookie leg is the one that could have measured nothing: `dhcp_drop_cookie` sits behind an
`op == BOOTREPLY` test **and** an xid match against the guest's own in-flight transaction, so an
off-path injector with a guessed xid falls into the silent-ignore arm and the leg passes while
proving nothing. The hook scrapes the **last** xid the guest printed (`dhcp_start()` regenerates
one per retransmit, so an early one is stale) and the run confirms it fired with a live value,
`HOOK-XID: 0xd3053b52`. The hook writes that xid to a file and the harness echoes it into the
verdict specifically so a silently-unreachable leg cannot masquerade as a pass.

Addressing needed the same treatment as Finding 5 but resolved more simply: DHCP replies to an
unconfigured client are **broadcast**, so `--dst-ip 255.255.255.255` satisfies `handle_ip`'s address
gate regardless of the guest's per-boot link-local address and needs no capture at all. `--src-ip`
is TEST-NET-3 for symmetry - the firewall's DHCP exception does return accept before
`is_bogon_ip()`, so an RFC1918 source would in fact survive here, but relying on that couples the
harness to the internal ordering of two unrelated checks.

---

### Finding 7 — Guard page freed without restoring its identity mapping

**Severity: MEDIUM** · `src/process.c:1160` (also `:1145`, `:1187`) · deferred kernel corruption

`task_create_user_argv()` marks the kernel-side guard page **not present** in the shared kernel
identity map at `src/process.c:1116-1129`:

```c
    if (pae_is_active()) {
        pae_pte_t* guard_pte = pae_get_pte(guard_page_phys);
        if (guard_pte) {
            *guard_pte = (guard_page_phys & PAE_FRAME_MASK) | PAE_READWRITE;  // Present=0
            flush_tlb_single(guard_page_phys);
        }
    }
```

Three failure returns *after* that point release the frame with a bare `pmm_free(guard_page_phys);`
and never restore the PTE — `:1145` (page-directory creation failed), `:1160` (user guard page
alloc failed), `:1187` (user stack page alloc failed).

`task_free_resources()` at `:1698-1703` does it correctly, and its own comment even notes the hazard
is *"NOT specific to kernel tasks: task_create_user_argv allocates the same kernel-side guard
page."* Only the teardown path got the fix. `pae_get_pte()` resolves through
`pae_default_pdpt_phys()`, i.e. the map every address space shares, so the hole is global; the
boot-time "no holes" sweep cannot catch a runtime hole. This directly violates the standing
invariant in `CLAUDE.md`.

`:1145` is effectively dead under PAE (`pae_create_user_pdpt` panics on OOM); `:1160` and `:1187`
are live. `task_create_kernel()` is clean — it has no failure return between marking and function
end.

**Who can drive it, how.** Ring 3, but with real setup cost. `SYS_SPAWN` is ungated, but the spawn
loop is throttled by `USER_MAX_CONCURRENT_TASKS`, the root slot reserve and
`task_rate_limit_check()`, so the attacker needs a separate memory-exhaustion primitive (ramfs
writes) to drive `pmm_alloc()` at `:1156`/`:1177` to 0. Once triggered: one physical frame
permanently poisoned per failed creation, returned to the free list as an ordinary page. The next
`pmm_alloc()` hands it to an unrelated caller — a RAMFS node, a kernel stack, an env page — and the
first write takes a supervisor-mode `#PF` on a not-present page: panic or triple fault, nowhere near
the cause. It also fires on an honestly out-of-memory system with no attacker at all.

**Fix.** Mirror `task_free_resources()` at all three sites, or better, factor a helper so a future
failure path cannot reintroduce it:

```c
static void guard_page_release(uint32_t phys) {
    map_page(phys, phys, PAGE_PRESENT | PAGE_READWRITE | PAE_NX);
    flush_tlb_single(phys);
    pmm_free(phys);
}
```

**Harness — `verify-guard-page-release.sh`** (needs `-DTINYOS_FAULT_INJECT` to force the
`pmm_alloc()` at `:1156` to fail once):
- **Poison leg:** force one creation failure, then **allocate and memset every remaining frame in
  the pool**. Assert no page fault. A pure free-frame-count assertion **passes against this bug** —
  the frame *is* returned to the pool; only its mapping is broken. The write-after-realloc is the
  only assertion that discriminates.
- **Positive control:** with injection off, task creation must still succeed and the frame count
  must return to baseline after exit (exact equality).
- **Negative control:** revert the fix and confirm the poison leg faults.

---

### Finding 8 — Invalid-syscall `kprintf` before the EDR hook (three sites)

**Severity: MEDIUM** · `src/syscall.c:3176` (also `:3391`, `:3586`) · ring-3 console flood

```c
    if (syscall_num > MAX_SYSCALL_NUM) {
        kprintf("[SYSCALL] ERROR: Invalid syscall number %d (max %d)\n",
                syscall_num, MAX_SYSCALL_NUM);
        state->eax = (uint32_t)(-ENOSYS);
        return;
    }
```

This is the very first thing an unprivileged ring-3 process reaches through `int 0x80`
(`idt_usermode.c:66` installs the gate at DPL=3), driven purely by the caller's own EAX — no memory,
no mapped pages, no privilege, no state consumed. The compare is unsigned and `MAX_SYSCALL_NUM` is
41, so `EAX = 0xFFFFFFFF` takes the branch. The `syscall_filter` gate is *below* this and defaults
false; `TINYOS_TRACE_SYSCALLS` is off. The `return` at `:3179` precedes `edr_behavioral_check`
(~`:3262`), so these calls never enter `edr_state.history[]` and are never scored — invisible to
forensics. (No working *throttle* is bypassed: `edr_detect_syscall_flood` only alerts and scores;
`allow_syscall = false` is set solely by the shellcode detector.)

**Two sibling sites, same class, same sweep:**
- `:3391` — `case SYS_CRYPTO:` prints *"[SYSCALL] SYS_CRYPTO called but not implemented"* then
  returns `-ENOSYS`. This is the textbook instance of the rot `CLAUDE.md` names: `sys_crypto` is
  prototyped at `syscall.h:1001` and never defined, has no libc wrapper and no builtin, so nothing
  in the tree drives it and no harness ever sees the site — which is exactly why it survived the
  `SYS_MSEAL` sweep.
- `:3586` — the switch `default:` prints *"Unknown system call number %d"* for any in-range but
  unimplemented number (gaps exist below 41). It at least sits after EDR, but is otherwise identical.

**Who can drive it, how.** `for(;;) asm volatile("int $0x80" :: "a"(0xFFFFFFFFu));` from any
unprivileged process. One console line per iteration at syscall rate. `serial_putc` spins on the
UART THRE bit per character (bounded by `SERIAL_TIMEOUT` 100000, so it degrades rather than hangs),
and the output buries any concurrent ring-3 shell session (`stdio.c:634` falls back to `vkprintf`
for a non-redirected stream) plus any harness-grepped serial log.

**Fix.** Replace all three with static counters grouped by caller intent
(`syscall_reject_range`, `syscall_reject_unimpl`), surfaced on an existing status line, matching the
`mseal_reject_*` pattern already in this file. **Count successes too**, per `CLAUDE.md`, or the
surface reports only failures and an unused mechanism reads as a working one.

**Harness — `verify-syscall-reject-counters.sh`** (needs a ring-3 driver, e.g.
`/syscallprobe.elf`, since nothing in the tree drives these):
- **Range leg:** issue N calls with `EAX = 0xFFFFFFFF`; assert `syscall_reject_range` rises by
  exactly N and serial gains zero `[SYSCALL] ERROR` lines.
- **Unimplemented leg:** issue N calls with `EAX = 13`; assert `syscall_reject_unimpl` rises by
  exactly N and the range counter does **not** — the selectivity leg.
- **Positive control (mandatory):** a valid syscall in the same run must still succeed and increment
  the success counter. The reject deltas are all satisfied perfectly by a dispatcher that refuses
  everything — the same trap `doc/MSEAL_AUDIT.md` documents.

---

### Finding 9 — `sys_mseal` audit record lets ring 3 evict the forensic ring buffer

**Severity: MEDIUM** · `src/syscall.c:3120` · anti-forensics

```c
    mseal_sealed++;

    uint16_t cur_uid = cur ? cur->uid : 0;
    audit_log(AUDIT_MEMORY_SEAL, AUDIT_INFO, cur_uid,
              "Sealed memory region 0x%08x - 0x%08x",
              (unsigned int)addr, (unsigned int)end);
```

`audit_log_raw()` writes into a 1000-entry circular buffer (`audit.c:25,28`) that is
**drop-oldest**: when full it overwrites the oldest record and only bumps
`audit_statistics.events_dropped` (`:156-161`). No rate limit, no dedup, no severity partitioning.
That same buffer holds the `AUDIT_CRITICAL` records — `SEC_MEMORY_VIOLATION` and
`SEC_EXPLOIT_ATTEMPT` (`interrupts.c:361/372`), EDR policy violations (`syscall.c:3269`), login
failures (`user.c:983`) — and is the only backing store for the root-only `auditlog` surface
(`shell_system.c:964`).

Sealing is **idempotent**: `pae_seal_memory_in` (`pae.c:1483`) has no already-sealed test — it
re-ORs `PAE_SEALED` and returns 0 every time — so the success path is repeatable indefinitely on one
page the caller already owns. `SYS_MSEAL` is not in EDR's `rare_syscalls[]`, and
`edr_detect_syscall_flood` never sets `allow_syscall = false`, so nothing throttles it.

`doc/MSEAL_AUDIT.md` audits this function exhaustively — the sixteen `kprintf` sites, validation
order, allocation, atomicity, frame leaks, blast radius — and never mentions the `audit_log` sink.
Its *"blast radius is self-inflicted"* clause is explicitly scoped to the caller's own address
space, which is true of the page table but not of this process-global buffer. The same PR that added
`mseal_sealed++` to fix the print flood left the write to shared forensic state one line below it.

**Who can drive it, how.** Unprivileged ring 3: `for (i=0;i<1000;i++) mseal(my_page, 4096);`. Each
call succeeds and writes one record; ~1000 iterations wrap the buffer, discarding every prior entry
including `AUDIT_CRITICAL` exploit-attempt and page-fault records. Run the exploit, then run the loop
to push the evidence out before root ever runs `auditlog`. The HMAC chain does not detect it —
eviction is legitimate ring behaviour, not tampering. Capped at medium because `events_dropped` is
visible under `auditlog -s`, so the wipe is detectable (though not recoverable, and that counter also
rises from ordinary boot traffic).

**Fix.** Drop the per-call record — `mseal_sealed` already counts successes, which is what the
counter work added it for — or suppress the record when the region is already sealed. More generally,
any `AUDIT_INFO` record on an ungated, repeatable ring-3 path needs the 1-per-100-tick limiter
pattern from `edr_behavioral.c:306`.

**Harness — extend `verify-mseal-counters.sh`:**
- **Eviction leg:** record an identifiable `AUDIT_CRITICAL` event (trigger a page fault), run 1000
  `mseal` calls from `/msealprobe.elf`, then `auditlog` as root and assert the critical record is
  **still present**.
- **Positive control:** `mseal_sealed` must still rise by 1000 — otherwise a `sys_mseal` that refuses
  everything passes the eviction leg.
- **Negative control:** revert the fix and confirm the critical record is gone.

---

### Finding 10 — One-byte stack OOB write in five shell path builders

**Severity: MEDIUM** · `src/shell_fileops.c:349` (also `:1046`, `:1303`, `:810`, `:1446`)

```c
    char new_path[MAX_PATH];
...
            size_t pos = 0;
            for (size_t i = 0; current_dir[i] != '\0' && pos < sizeof(new_path) - 1; i++) {
                new_path[pos++] = current_dir[i];
            }
            new_path[pos++] = '/';
            for (size_t i = 0; path[i] != '\0' && pos < sizeof(new_path) - 1; i++) {
                new_path[pos++] = path[i];
            }
            new_path[pos] = '\0';
```

The copy loops are bounded at `sizeof(buf)-1` but the separator and the terminator are not
re-checked. With `current_dir` at 255 chars: loop 1 stops at `pos == 255`; the unguarded `'/'` write
takes the last valid byte and leaves `pos == 256`; loop 2 is skipped; `new_path[256] = '\0'` writes
one byte past a 256-byte stack array. `MAX_PATH` is 256 (`util.h:8`).

Sites: `cmd_cd` (`:342-349`), `canonicalize_path` (`:1046-1052`, whose separator is guarded only by
`pos == 0 || working_path[pos-1] != '/'` — still true at `pos == 255`), `rm_recursive`
(`:1303-1317`), `cmd_cat` (`:810-824`), `cmd_exec` (`:1446-1453`). The correct model is in the same
file: `resolve_path()` (`:1005-1008`) pre-checks `cwd_len + 1 + path_len + 1 > abs_path_size`.
`cmd_cd`'s own length check at `:386` runs *after* the overflow, on the already-built string.

**Who can drive it, how.** Threat level 3, a logged-in non-root user. `SHELL_BUFFER_SIZE` is 256, so
a 255-char path cannot be typed in one command — but `current_dir` accumulates across commands via
repeated relative `cd` of ≤31-char components (ramfs allows 16 components × 31 chars; 7×31 + 30 + 8
slashes = 255 exactly). With `-fstack-protector-strong` active on a 256-byte char array, the
realistic outcome is a canary panic (DoS) or a clobbered adjacent local — the OOB byte is a fixed
`'\0'`, not attacker-chosen, so "high" would overstate it. `canonicalize_path` is the widest-reaching
site: `shell_redir.c:39` reaches it on every **relative** redirection filename.

Precedent for fixing: `doc/KERNEL_BUGS.md:486` records an identical off-by-one in `editor_open`
that was fixed even though unreachable, *"precisely because the next caller would make it
reachable."*

**Fix.** Pre-compute the required length before copying, as `resolve_path()` does. If the
incremental style is kept, guard the separator and terminator with the same bound:
`if (pos < sizeof(buf) - 1) buf[pos++] = '/';`. Apply to all five.

**Harness — `verify-shell-path-overflow.sh`:**
- **Overflow leg:** script `mkdir`/`cd` to build a 255-char `current_dir`, then `cd sub`; assert the
  shell reports a path-too-long error and **does not panic**. Grep serial for the stack-protector
  panic string and assert it is absent.
- **Redirection leg:** at the same depth, run `echo hi > f` (relative filename) — this drives
  `canonicalize_path`.
- **Positive control:** normal `cd`/`cat`/redirection at shallow depth must still work, so a
  path builder that rejects everything does not pass.
- **Negative control:** revert the guards and assert the panic string *appears*.

---

### Finding 11 — Kernel-shell history is not cleared on logout

**Severity: MEDIUM** · `src/shell.c:1123` · information disclosure · threat level 3

```c
void shell_task(void) {
    kprintf("[SHELL] Shell task started! (ESP check)\n");
    /* Initialize history system */
    history_init();
```

`history_init()` is called once, **above** the `while (1)` session loop at `:1139` that re-runs
login after a logout. It is the only call to it in the entire tree, and no `history_clear()` exists.
`history_buffer` is file-scope static (`shell_history.c:13`), as are `history_count` and
`history_index`. Both logout exits clear only the screen.

The session loop deliberately resets *other* per-session state each iteration — uid/euid/gid/egid,
then `env_init()` and `env_refresh_identity()` — with a comment explaining these run *"Per SESSION,
not once at boot … so a logout/login as a different user starts from the defaults rather than
inheriting the previous user's variables."* History was simply omitted from that list.

`doc/ROADMAP_NEXT.md:116` states the opposite rationale for the ring-3 shell, which is deliberately
ring-3-local because *"a shared history buffer would leak one session's command lines, arguments
included, into another user's listing."* The threat is documented as understood; the kernel shell has
that exact leak within its own buffer across sessions.

**Who can drive it, how.** User A reaches the kernel shell via `kshell` (ungated on purpose), types
commands with sensitive operands — file paths, hostnames, `curl` URLs with query strings — then
logs out. User B logs in at the same console, types `kshell`, and runs `history` or presses Up.
`cmd_history` has no `require_root` guard and prints `history_buffer[pos]` raw. Persisted
`history_index`/`history_count` mean A's entries remain numbered above B's first command.

**Fix.** Call `history_init()` (or a new `history_clear()`) inside the session loop after a
successful login, alongside the existing `env_init()` reset. Zero the buffer contents, not just the
count, so strings are not recoverable through a later index bug.

**Harness — `verify-shell-history-logout.sh`:**
- **Leak leg:** log in as A, `kshell`, run a uniquely-identifiable command, `logout`; log in as B,
  `kshell`, `history`; assert the marker string is **absent** from serial after B's `history`.
- **Positive control (mandatory):** B's *own* commands must still appear in B's `history` —
  otherwise a `history` that prints nothing passes the leak leg.
- Use `TINYOS_STAY_IN_RING3=1` handling carefully here: this harness *must* reach the kernel shell,
  so it deliberately types `kshell` — the inverse of the usual trap.

---

### Finding 12 — Dangling `fpu_owner` after external task termination

**Severity: LOW** · `src/scheduler.c:1344` · stale pointer

`static volatile task_t* fpu_owner` (`scheduler.c:68`) is cleared in exactly one place: the deferred
cleanup-queue reaper (`:1092-1094`). But `task_terminate()` has two asymmetric branches
(`process.c:1838-1849`): only the *self-exit* branch defers to that reaper. The *external kill*
branch tears down inline — `task_free_resources(task); … scheduler_remove_task(task);
task_free_slot_for_task(task);` — and never clears `fpu_owner`. Slots are `static task_t
tasks[MAX_TASKS]` reused in place, so the stale pointer aliases the new occupant's `task_t`.

`scheduler_handle_fpu_exception()` (`:1303-1362`) checks only `!current` and `fpu_owner != current`
— no generation, `pid != 0`, or state test — then:

```c
    if (fpu_owner && fpu_owner != current) {
        task_t* prev_owner = (task_t*)fpu_owner;
        __asm__ volatile("fxsave %0" : "=m"(prev_owner->context.fpu_state));
    }
```

Not dead code: `context_switch.S:229,334,417` set `CR0.TS` on every switch and `interrupts.c:222`
dispatches `#NM` here.

**Who can drive it.** Ring 3 via `SYS_KILL` on its own task (`syscall.c:1607`), or any of the
fault-kill sites (`idt.c:247, 284`). Result: a 512-byte in-bounds write of the dead task's FPU/SSE
image over a live task's saved `context.fpu_state`, restored into that task's registers at `:1354`.

**Why LOW, not medium.** Turning it into a cross-task *leak* requires the killed task to have owned
the FPU at kill time, winning a slot-reuse race against crypto-random slot/PID allocation, and the
new occupant belonging to another user. On a single-CPU kernel whose security-relevant crypto
(PBKDF2/sha256) is integer-only, the realistic outcome is silent FPU state corruption of an
unrelated task. It does defeat the isolation the comment at `scheduler.c:66` claims.

**Fix.** Export `void scheduler_fpu_release(task_t* t) { if (fpu_owner == t) fpu_owner = NULL; }`
and call it from `task_free_resources()` — the single choke point on both branches. Defensively,
validate the owner with `task_slot_is_live` before the `fxsave`.

**Harness leg:** extend an existing scheduler harness — force a task to use the FPU, kill it
externally, spawn until the slot is recycled, then have the new occupant checksum its own FPU state
across a `#NM`; assert unchanged. Positive control: the same checksum must survive a normal context
switch (proving lazy FPU save/restore still works at all).

---

### Finding 13 — Access mode 3 yields a vacuous permission grant

**Severity: LOW** · `src/ramfs.c:1481` · auth bypass (metadata only)

`ramfs_check_permission()` builds `required_perms` (init 0 at `:1406`) only from the
READ/WRITE/EXEC bits of `access`; every `|=` is guarded. With `access == 0` the final test is
`(node->mode & 0) == 0` — unconditionally true:

```c
    /* Check if all required permissions are present */
    return (node->mode & required_perms) == required_perms;
```

`ramfs_vfs_open()` produces exactly that: `access_mode = flags & 0x3` == 3 matches neither the READ
test (0 or 2) nor the WRITE test (1 or 2), so `ramfs_open(path, 0)` is called. `sys_open()` does not
reject it — its whitelist is `0x0F03`, and `3 & ~0x0F03 == 0`. `vfs_open` *does* treat 3 as a write
for the protected-prefix check, so `/etc` etc. remain covered; nothing else does.

**Impact is metadata only.** `ramfs_read`/`ramfs_write` test the stored flags explicitly, so no bytes
move. But `ramfs_fd_size()` has no flag test and is reachable as `lseek(fd, 0, SEEK_END)` →
`ramfs_vfs_seek` → `ramfs_fd_size` (`ramfs.c:961`), returning `node->size` for a file the caller
cannot read: **a file-size and existence oracle over non-protected ramfs paths from ring 3.** Note
the codebase already closed the same leak on the stat path — `ramfs_vfs_stat` (`:450`) explicitly
requires `RAMFS_FLAG_READ` *"so stat cannot be used to probe sizes inside a directory the caller
cannot open."* The open(3)+lseek route is the one that stayed open.

The broader hazard is that the single permission predicate can be driven to `true` by an
attacker-chosen argument, so any future `ramfs_open()` caller or new `RAMFS_FLAG_*` reaching it with
a zero mask is unprotected.

**Fix.** Two independent, both worth making: (1) in `ramfs_check_permission()`, reject a zero access
mask up front — `if ((access & (READ|WRITE|EXEC)) == 0) return false;` — so the predicate can never
grant vacuously; (2) in `sys_open()`, `if ((flags & 0x3) == 3) return -EINVAL;` — 3 is not a valid
POSIX access mode and both `ramfs_vfs_open` and `fat32_vfs_open` mishandle it.

**Harness leg:** as uid 1000, `open("/rootfile", 3)` on a root-owned 0600 file must fail. Positive
control: `open("/rootfile", O_RDONLY)` as root must still succeed, and the unprivileged user must
still `open` their own file with mode 0/1/2.

---

### Finding 14 — Head gap of an unaligned `PT_LOAD` is never zeroed

**Severity: LOW** · `src/elf.c:1254` · info disclosure, signature-gated

`elf_load_process_argv` allocates whole frames from `start_page = vaddr & ~0xFFF` (`:1090`) and maps
from `start_page` (`:1201`, with `PAGE_USER`), but initialises only `[vaddr, page_end)`: memcpy at
`:1211`, BSS memset at `:1217`, tail memset at `:1259`. A tree-wide grep confirms those are the only
two `memset`s in the file, both at or above `vaddr`. Nothing zeroes `[start_page, vaddr)`, and
`pmm_alloc()` does not zero — as this loader's own AUDIT 9F comment (`:1226-1229`) says of the tail.
No `p_align` validation exists anywhere.

So an unaligned `p_vaddr` leaves up to 4095 bytes of recycled kernel/other-process memory mapped
`PRESENT|USER` inside the new process. This is the exact class the AUDIT 9F block fixes; it just
covers one of the two gaps a partially-used page has.

**Why LOW.** `elf_verify_signature()` hashes the **entire** image and pins the key against the
secure-boot config, so the program headers are inside the signed region — an attacker cannot craft an
unaligned `p_vaddr` and keep a valid signature. `elf_require_signatures` is `true` by default
(`:568-572`) and rejects before any segment is mapped. Every shipped binary is page-aligned
(`userspace/user.ld` uses `. = ALIGN(4K)`), so the gap is zero-width in practice. Reaching it needs
either the named `-DELF_PERMISSIVE_SIGNATURES` dev opt-out or the signing key — and an attacker with
the key already has code execution, making the leak redundant. Defense-in-depth, not an exploitable
primitive; worth closing because a linker change or a hand-built binary makes it live immediately.

**Fix.** Zero the head gap symmetrically, after the mapping loop and before the memcpy:

```c
if (vaddr > start_page) {
    memset((uint8_t*)start_page, 0, vaddr - start_page);
}
```

Alternatively reject an unaligned `p_vaddr` outright — defensible, since every binary in the tree is
already aligned.

**Harness leg:** needs a deliberately **unaligned-vaddr fixture** built for the purpose (and signed,
or run under the permissive flag). Every binary currently in `userspace/` has a zero-width head gap,
so any test built from them passes against the bug. Assert the head bytes read back as zero.

---

### Finding 15 — Entropy pool never re-stirs

**Severity: LOW** · `src/entropy.c:391` · weak randomness in a dormant fallback

```c
    CRITICAL_SECTION_ENTER();
    bool need_stir = (pool_counter >= POOL_STIR_THRESHOLD);
    if (need_stir) {
        pool_counter++;  /* Increment so we don't re-trigger */
    }
    CRITICAL_SECTION_EXIT();

    if (need_stir) {
        pool_stir();
    }
```

`pool_counter` is incremented **only inside the branch it gates**. All four references in the tree:
`:38` init 0, `:372` reset in `pool_stir()`, `:391` the read, `:393` the increment. Nothing
increments per request, so `0 >= 100` is false forever and `pool_stir()` is dead on this path. The
comment shows the increment was written as re-entrancy suppression; the per-call bump was never
added. The other `pool_stir()` callers are all one-shot (`entropy_init`, `entropy_reseed` ←
`aslr_reseed` ← `aslr_init`, `entropy_wait_for_strong`), so after boot the 64-word pool is frozen —
entries are read round-robin via `pool_index` and never rewritten.

Consumers: `stack_guard.c:42` (`__stack_chk_guard`), `aslr.c:131`, and 128 of the 256 bytes of
`crypto_collect_entropy()` (`crypto.c:1009`). `stats.pool_stirs` reads 1 forever — another
status-surface lie.

**Why LOW.** Every run script, harness, and the published boot command use
`-cpu Broadwell,+rdrand,+rdseed`, so `rdrand_available` is true and `pool_get_random()` is never
reached on the supported configuration. RDRAND availability is fixed at boot by CPUID/health-check,
so no attacker at tier 1–3 can force execution onto the fallback. Even on a no-RDRAND host each
output still gets `value ^= read_tsc()` plus xorshift, so it is degraded freshness, not a predictable
stream. Tier 4.

**Fix.** `bool need_stir = (++pool_counter >= POOL_STIR_THRESHOLD);` — `pool_stir()` already resets
to 0. Keep a re-entrancy guard: since `pool_stir()` runs outside the critical section, either latch a
separate `stir_in_progress` flag or zero `pool_counter` where `need_stir` is latched.

**Harness leg:** with RDRAND forced off (drop `+rdrand` from the QEMU `-cpu`), make >100
`entropy_get_random32()` calls and assert `pool_stirs` **strictly increases**. A one-sided
`pool_stirs >= 1` assertion passes vacuously against the current bug — the init stir already
satisfies it.

**RESOLVED 2026-08-22.** Fix applied as specified: the draw is now counted unconditionally
(`bool need_stir = (++pool_counter >= POOL_STIR_THRESHOLD);`), and the re-entrancy question was
settled by **zeroing `pool_counter` where `need_stir` is latched**, under the same
`CRITICAL_SECTION` — not by relying on `pool_stir()`'s own reset. That residual window is real
but benign: `pool_stir()` runs *outside* the critical section and re-enables interrupts between
batches, so between the latch and the reset an interrupt-context caller could push the counter
past the threshold and latch a second, redundant stir. An extra stir only adds entropy, so the
cost is wasted work in interrupt context; the invariant is cheaper to state than the window is
to reason about.

Harness: `verify-entropy-pool-stir.sh` — **PASS (source-level only).** Leg 1 guards the source
shape (the defect is the `++` moving inside the `if`, a change too small for a behavioural leg
alone to localise) and was proven falsifiable by injecting the buggy form: both of its checks
then FAIL. **Leg 2, the runtime advance of `pool_stirs`, is UNREACHABLE on this kernel**, and the
harness now says so explicitly rather than reporting a pass it did not earn.

The chain was established by measurement, not assumption:

1. On the project's standard QEMU line the pool path is **dead** — `entropy_get_random32()`
   returns from RDRAND *before* `pool_get_random()` is reached, so every reading is 0 on fixed and
   broken kernels alike. A leg inheriting the usual command would have passed vacuously.
2. Clearing RDRAND needs **`-cpu Broadwell,-rdrand,-rdseed`**, not merely dropping `+rdrand`:
   Broadwell carries RDRAND in its *base* feature set, so omission is not negation. Confirmed by a
   standalone boot.
3. With RDRAND genuinely cleared the pool does come alive (`[ASLR] Entropy quality: MEDIUM
   (Pool)`), but the boot then **panics** in `crypto_collect_entropy()` —
   `validate_entropy_quality()` (`crypto.c:1045`) rejects the pool and `crypto.c:1128` panics.
4. The `-DTINYOS_ALLOW_WEAK_ENTROPY` bypass that would have admitted it was **deliberately
   removed** (`crypto.c:1061`, "SECURITY FIX (Issue #2)"), and the keystroke-entropy prompt the
   panic text promises **does not exist** in `entropy.c`.

So reaching the counter would require adding a fault-injection hook to make a *present* RDRAND
fail — new code in the crypto path, to test a LOW-severity counter fix, against the standing rule
in `CLAUDE.md` about that path. Recorded as UNREACHABLE in-harness rather than silently dropped,
and the verdict was corrected from an earlier overclaiming *"the pool stirs, and the counter still
advances"* to **"PASS (source-level only)"**.

**Severity confirmed LOW, not re-graded.** The re-grade question was whether the frozen pool is
reachable on a supported configuration. It is not: RDRAND availability is fixed at boot by
CPUID plus a health check, so no attacker at tier 1–3 can force execution onto the fallback.
Tier 4 stands.

---

### Finding 16 — EDR daemon created but never enqueued

**Severity: LOW** · `src/kernel.c:1066` · status-surface lie

```c
    int pid_edr = edr_daemon_start();
```

`edr_daemon_start()` (`edr_daemon.c:299-319`) calls `task_create_kernel()`, then only `task_get()` +
`task_set_priority()`, and returns. It never calls `scheduler_add_task()` — the documented
`CLAUDE.md` trap. The complete set of `scheduler_add_task()` calls in `kernel.c` is lines
1127, 1129, 1132, 1135, 1138, 1140, 1141, 1142, 1148; `pid_edr` is not among them. The other enqueue
paths cannot reach it: `task_unblock()` requires `TASK_STATE_BLOCKED` (unreachable for a task never
made READY), and `supervisor.c:122` re-adds only watched tasks, where `kernel.c:1051` watches
`knetd` alone.

So `edr_daemon_main()` never executes an instruction: its scan loop, its four
`edr_response_execute()` calls, and all `g_edr_daemon_state` counters stay at initializer values.
The task is nevertheless allocated a slot, listed by `ps`, granted `PRIORITY_HIGH` and
`CAP_UNKILLABLE`, and `edr_daemon_start()` prints *"EDR daemon started successfully"*.
`shell_system.c:1319-1321` prints scans/threats/responses that are permanently 0/0/0.

Two refutations chased and eliminated: the `[EDR ADVANCED] … Suspicious memory` serial spam comes
from `edr_advanced.c` via the timer softirq (`interrupts.c:116`), a separate subsystem; and
`verify-edr-pid.sh` passes because every leg asserts strings printed on the boot path **before**
`scheduler_start()` — no leg asserts any of the four strings unique to `edr_daemon_main()`
(`edr_daemon.c:187/217/246/264`), so it passes identically either way.

**Why LOW.** No attacker drives it, and `scan_process()`'s sole detector is a name heuristic matching
processes beginning with `"mal"`, so actual detection capability lost is negligible. The defect is the
lie: two surfaces assert a state neither can observe.

**Fix.** Add `scheduler_add_task(task_get((uint32_t)pid_edr));` beside the other daemons around
`kernel.c:1140-1142`, guarded on `pid_edr >= 0`. Separately, make the `secstatus` EDR line report
whether the daemon is actually scheduled, not only counters a never-run daemon reports as zero.

**Harness leg:** `verify-edr-pid.sh` must gain a leg asserting a string emitted from **inside**
`edr_daemon_main()`'s loop body (e.g. `edr_daemon.c:187`) appears on serial after
`scheduler_start()`. Negative control: revert the `scheduler_add_task` and confirm that string
disappears while every existing leg still passes — which is precisely what makes the current harness
a false pass.

**RESOLVED 2026-08-22.** Fix applied at `kernel.c:1195-1196`, guarded on `pid_edr >= 0` because
`edr_daemon_start()` returns -1 on failure. Note the fix went in `kernel.c` beside the other
daemon enqueues rather than inside `edr_daemon_start()`, matching where every other
`scheduler_add_task()` call already lives.

`verify-edr-pid.sh` gained **leg 2b**, asserting two strings emitted from *inside*
`edr_daemon_main()`: `"Starting EDR background daemon"` (`edr_daemon.c:246`, the first statement
in the function, so it can only appear if the task was scheduled) and `"[EDR DAEMON] Scan
complete"` (`edr_daemon.c:206`, in the loop body, which proves the daemon is not merely entered
but running — and is what makes `scans_performed` non-zero). Runtime evidence from the
post-fix boot log: both lines present, `"Scan complete: 6 processes"`, and the daemon pid in the
allocatable range.

**Negative control run, and it did its job.** With the `scheduler_add_task()` call replaced by
`(void)0`, leg 2b FAILED on both of its checks (*"edr_daemon_main() never ran -- task created but
never enqueued"*, *"daemon entered but never completed a scan -- its counters stay 0"*) while legs
1, 2, 3 and 4 all still PASSED — reproducing exactly the false pass this finding identified, and
confirming 2b is the only leg that detects the bug. `src/kernel.c` was then restored and re-run
on the clean tree: **9 passed, 0 failed**.

**Severity confirmed LOW, not re-graded.** No attacker drives the daemon, and `scan_process()`'s
sole detector is a name heuristic matching processes beginning with `"mal"`, so the detection
capability actually restored is negligible. The defect was the status-surface lie, and the lie
is what the new leg closes.

---

## 3. Subsystems audited and found clean

Explicitly clean, per domain — no findings, and the documented invariants hold under inspection:

- **ELF image lifetime.** `task_t::image_pages_phys[]` registration sits below every `return -1` in
  `elf.c`, exactly as the invariant requires; no double-free path found. Oversize images are refused,
  never loaded untracked. (The one `elf.c` finding, #14, is a distinct info-leak gap, not a lifetime
  bug.)
- **Signature verification / secure boot.** `elf_verify_signature()` hashes the entire image and pins
  the public key against the secure-boot config; `elf_require_signatures` is fail-closed by default
  and rejects before any segment is mapped. This closed the exploitability of Finding 14 and is the
  strongest control in the tree.
- **PBKDF2 / sha256 / `csprng_reseed` masking.** Untouched and intact; the interrupt masking is
  load-bearing as documented. No weakening found. (Finding 15 is a *fallback* pool that these do not
  depend on when RDRAND is present.)
- **The reaper / task-slot lifetime.** `scheduler_remove_task_locked()` before
  `task_free_resources()` holds; no self-linked-corpse path found. The per-uid cap and root slot
  reserve both return `-EAGAIN` as documented.
- **`ramfs_chmod` ownership + `SYS_CHMOD`.** The primitive-level check is intact and `sys_chmod` maps
  the private sentinels without adding a second uid test — the placement paid off exactly as
  documented. No sentinel collision found.
- **TCP RX counters and `tcp.c` prints.** The PR #101 sweep holds; the two `data_offset` sites are
  counted, the RST/FIN flood detectors no longer print per packet, and the once-per-connection
  transitions at 800/815/1028 are correctly left as prints.
- **ICMP RX and `handle_dns_response()`.** Both fully counter-converted; no residual per-packet
  prints. (Finding 4 is the *helper*, not the swept function.)
- **`SYS_MSEAL` print sweep.** All sixteen sites are gone and the counters are grouped by caller
  intent with successes counted. (Finding 9 is the `audit_log` sink, which that audit never
  examined.)
- **netd arbitration / `rx_softirq_ring`.** `SYS_NETRX` pops `netd_ring`, `knetd` is the single
  consumer of `rx_softirq_ring`, TCP is never routed, and routing is gated on `netd_claimed` and
  reversible. Intact.
- **RX task context.** Frames are copied before RDT advances; the boot DHCP loop keeps its explicit
  `e1000_rx_softirq_run()` call; ring overflow is drop-newest and counted. Intact.
- **e1000 DMA guard region.** Allocation stays after `pae_init()`; `TDLEN`/`RDLEN` computed from
  element counts, not `sizeof`. Intact.
- **EDR behavioral gate.** `edr_behavioral_init()` is called on the success path of both
  `task_create_kernel()` and `task_create_user_argv()`, past every failure return, so
  `EDR_FLAG_DETECTION_ENABLED` is set on every live task and the gate is not inert. (See appendix.)
- **Account locking / `user.c` auth.** The failed-attempts timeout logic and the root-created-locked
  path are internally consistent; the one reported issue was unreachable (see appendix).
- **`SYS_ENV` / per-task env storage.** Ungated as designed, no pid subcommand, copy-out under the
  lock, `env_inherit_exported()` allocates the child's page directly. Intact.
- **Process visibility.** `task_visible_to_current()` is the single predicate; totals count printed
  rows only, and a filtered-out PID reports as nonexistent in both `cmd_kill` and `sys_waitpid`.
  Intact.
- **`tcp_socket()` ownership.** `owner_uid` stamped on both allocation paths; `tcp_recv()` takes
  `TCP_LOCK` before reading the head/tail pair. Intact.

---

## 4. Appendix — refuted claims

**A. `user_lock_account()` does not zero `failed_attempts`** (`src/user.c:1017`).
The facts check out — the function does only `user->flags |= USER_FLAG_LOCKED;` and never touches
`failed_attempts`, unlike `user_unlock_account()` immediately below it, and the comment at `:932`
does assert the invariant. **Refuted on reachability:** `grep -rn "user_lock_account" src/
userspace/` returns exactly two hits — the definition and the prototype. Zero callers. No `usermod`,
no `passwd -l`, no builtin, no syscall. The claimed attack explicitly requires a step
(*"an administrator locks the account via user_lock_account()"*) that cannot occur at any privilege
level, including root. The only other site setting `USER_FLAG_LOCKED` outside the failed-attempts
branch is `:458` (root created locked at init), where `failed_attempts = 0` on the very next line, and
that account's empty `password_hash` returns `-6` at `:924` before the lock block is evaluated. There
is no state, reachable or otherwise, in which the described auto-unlock misfires. A stale-comment
code-quality note, not a security finding.

**B. "EDR behavioral analysis is inert: the enable flag is never set."**
**Refuted — the central premise is false.** The report grepped for `edr_behavioral_init_task`, a name
that does not exist anywhere in the repository. The actual initializer is `edr_behavioral_init`
(`edr_behavioral.c:28`), with two live callers: `process.c:869` in `task_create_kernel()` and
`process.c:1482` in `task_create_user_argv()` (which all `task_create_user*` variants funnel into).
`edr_behavioral.c:43` does `task->edr_state.flags = EDR_FLAG_DETECTION_ENABLED;`. The supporting
point about `memset(task, 0, sizeof(task_t))` is real but non-load-bearing: both memsets sit early
(`process.c:596`, `:1023`) while `edr_behavioral_init` runs on the success path past every failure
`return`. So the gate at `:343` passes, the anomaly score accumulates, and the `allow == false`
branch at `syscall.c:3263` is live. The only true sub-claim — that `edr_behavioral_set_enabled`
(`:482`) has no caller — is unused code, not a defect, since the default is on.
