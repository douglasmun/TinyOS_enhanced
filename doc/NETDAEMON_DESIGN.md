# Item 4 — ring-3 network daemon: design and audit plan

Status: **design only. No code has been written.** This document exists to be
argued with before anything is built, per item 4's own instruction: *design the
harness before the code.*

Companion to `doc/NETWORK_ISOLATION.md`, which carries items 1–3 (all landed).

## What the measurement changed

The item-4 sketch in `NETWORK_ISOLATION.md` assumed the hard part was the sheer
line count — "roughly 5,000 lines would change trust domain at once". Measuring
the actual coupling changed the shape of the problem, and this design is built on
the measurement rather than the estimate.

Parser sizes as compiled (`ssh.c` matched an earlier grep but is **not in
`SRCS`** — it is gitignored and not built; do not count it):

| File | Lines |
|---|---|
| `net.c` | 1978 |
| `tcp.c` | 1772 |
| `e1000.c` | 1351 |
| `firewall.c` | 932 |
| `dns.c` | 835 |
| `dhcp.c` | 729 |
| `ids.c` | 633 |
| `icmp.c` | 466 |

The decisive number is not any of those. It is this: **the inbound parser's total
dependency on kernel services is `e1000_send()`.**

A sweep of `tcp/dns/dhcp/icmp/firewall/ids/net.c` for calls to `kmalloc`, `kfree`,
`pmm_*`, `pae_*`, `task_*`, `scheduler_*`, `critical_section_*`, `mutex_*`,
`ramfs_*`, `rtc_*`, the port I/O intrinsics and the timer found:

- `e1000_send()` — 11 sites (tcp 1, dhcp 1, icmp 2, net 7)
- `scheduler_yield()` — 8 sites, **all in `icmp_ping()`**, the outbound command
  path, not the receive path
- `task_create_user_argv` in `ids.c` — a **false positive**: it appears inside the
  comment block explaining why `ids_check_fork_bomb` was removed. There is no call.

No allocator. No page tables. No scheduler on the RX path. The parser is already
close to a pure function over a byte buffer, which is why this item is tractable
at all — and it is a far better argument for the move than the line count was.

## What actually crosses the boundary

Two surfaces, and they should not be confused.

### Surface A — the packet path (the point of the item)

Ring 0 keeps: MMIO, DMA, descriptor rings, `e1000_send()`. These need physical
addresses and port access and cannot move.

Ring 3 gets: `handle_packet()` and everything below it.

The daemon needs exactly two primitives, mirroring the shape already established
by item 1's `rx_softirq_ring`:

- **receive** — block until a frame is available, copy it to a user buffer
- **transmit** — hand a fully-formed frame to `e1000_send()`

That is the whole packet-path boundary. Two syscalls.

### Surface B — the socket API (the part that is easy to underestimate)

Kernel-side consumers of the network stack, confirmed against `SRCS`:
`http_test.c`, `tcp_tests.c`, `shell_network.c`, `kernel.c`, `interrupts.c`,
`test_tasks.c`. They call 23 functions:

```
tcp_socket  tcp_bind  tcp_listen  tcp_accept  tcp_connect  tcp_send  tcp_recv
tcp_close  tcp_available  tcp_is_connected  tcp_get_state  tcp_state_to_string
tcp_init  tcp_tick  tcp_get_time_ms  tcp_dump_connections
dns_get_resolved_ip  dns_is_resolved
dhcp_init  dhcp_start  dhcp_tick  dhcp_is_configured  dhcp_get_client_info
```

Moving the parser to ring 3 moves `tcp_connections[]` with it. Every one of those
callers is then reaching across a trust boundary for state that no longer exists
in its address space. **This is the majority of the work, and it is not parser
code.** Any plan that budgets only for "move 8,350 lines" is wrong about which
lines are hard.

The configuration globals are the same problem in miniature: `my_ip`, `my_mac`,
`gateway_ip`, `subnet_mask` are written by DHCP (moving to ring 3) and read by
`kernel.c` (11 sites), `shell_network.c` (6), `tcp.c` (5), `icmp.c` (4). They
become a query, not a symbol.

## Proposed sequencing

Deliberately ordered so each PR is independently verifiable and independently
revertable. **No PR after the first exposes new attack surface until its own
audit has run.**

**PR A — audit the parser, change nothing.** Item 4's own words: *the audit is not
a step in this item; it is the majority of it.* PRs #45/#47/#54/#55 each found
serious bugs in code that was dead or kernel-only until it was exposed. The parser
has never been reached by a hostile ring-3 process, only by hostile packets. Audit
first, land fixes as their own commits, and let the exposure PR come after.

**PR B — the two packet-path syscalls, daemon still in ring 0.** Introduce
receive/transmit and prove the boundary carries real traffic before anything
changes trust domain. Fully revertable; nothing is exposed yet.

*As built, PR B deviates from the plan above in one way worth recording.* The
plan said "route the existing in-kernel parser through them". It does not. The
parser still runs in the kernel and does not call the syscalls at all, so in
normal operation both counters read **zero**.

The reason is that routing the in-kernel parser through the pair would have made
the syscalls a detour: kernel code calling a syscall wrapper to hand a frame back
to kernel code, with `copy_to_user`/`copy_from_user` replaced by plain copies
because there is no user address space involved. That exercises the counters and
the ring buffer, but it does **not** exercise the ring transition, the euid gate,
or the user-pointer validation — which are the three things that have to be right
before PR D, and the only three the detour cannot test.

So the boundary is driven by `userspace/netprobe.c` instead: a root-only ring-3
program that goes straight to `int 0x80`. It costs one embedded binary and proves
the property the detour would have faked. The zero baseline is then an asset
rather than an embarrassment — `verify-netd-boundary.sh` asserts on it explicitly,
so any frame the counters report is unambiguously one that crossed the ring.

Root-only, and non-blocking. Raw TX forges any source MAC or IP (ARP poisoning,
DHCP spoofing) and raw RX exposes traffic addressed to every other service on the
host, so ring 3 needs a privilege check before it needs anything else. Blocking
receive is deferred because it requires an ISR-driven wait queue, and a lost
wakeup there is a silently wedged network stack — that belongs in the PR that
actually needs it, not in the one that opens the boundary.

Not covered by the harness, and deliberately: the `-EMSGSIZE` path where a queued
frame is larger than the caller's buffer. The frame is **consumed** in that case
(a retained oversized frame at the tail wedges the queue for every later frame —
a remote DoS from one packet), so the caller loses it and learns only from the
return value. Reaching it needs a frame larger than the probe's buffer, which the
socket netdev cannot produce on demand; it is asserted by reading, not by running.

**PR C — socket API across the boundary.** The 23 functions. Largest and least
glamorous PR; likely splits further.

*The count was stale, and the first step of PR C was finding that out.* Three of
the 23 — `tcp_bind`, `tcp_listen`, `tcp_accept` — have **no live caller**. Their
only consumer was `ssh.c`, which is not in the build (Makefile:164 records SSH,
`ssh_crypto.c` and `rsa.c` as removed, source retained on disk). So the surface
to carry across is 20, not 23, and the remaining three were dead code.

**C0 (landed) — delete the server path rather than export it.** CLAUDE.md's rule
is that making a path reachable from ring 3 turns latent bugs into corruption
primitives, and that PRs #45/#47/#54/#55 each found serious bugs in code that was
dead or kernel-only until it was exposed. Auditing these three before exporting
them found two more:

- **`tcp_bind` took no lock.** Every other mutating entry point takes
  `TCP_LOCK()`. It did an unlocked read-modify-write of `conn->local_port` and
  called `tcp_allocate_port()`, which itself walks `tcp_connections[]` and
  mutates the `next_ephemeral_port` global. Two concurrent binds could be handed
  the same port — defeating the collision check that exists for that exact
  reason.
- **`tcp_bind` ignored allocation failure.** `tcp_allocate_port()` returns 0 when
  exhausted; `tcp_bind` stored that into `conn->local_port` and returned success.
  Today `tcp_listen` rejects `local_port == 0` so the damage stops at a
  misleading errno, but the moment any future caller does not recheck, port 0 is
  live state.

Deleting is the honest reading of "least surface" for a client-only stack. The
consequence worth stating: `tcp_listen` was the only thing that could assign
`TCP_LISTEN`, and the passive-open branch in `tcp_handle_packet` was gated on
that state — so **TinyOS now accepts no inbound connections at all**, and an
unsolicited segment is counted (`net_get_tcp_no_connection`, surfaced in
`ifconfig`) and dropped. That deletion also removed a per-inbound-SYN `kprintf`,
which a remote host chose the rate of — the class CLAUDE.md rules out entirely.

Harness: `verify-tcp-serverpath.sh`. Both guard halves were negative-controlled
separately, because they catch different failures: restoring a `tcp_listen`
definition trips the first, and restoring only a `state = TCP_LISTEN` assignment
(with no API function anywhere) trips the second — the latter being the one that
would silently reopen remote SYN handling while every deleted function stayed
deleted.

**A TCP-over-NAT failure was found and is NOT this PR's.** `curl` reaches
`SYN_SENT` and times out after 10010 ms with no SYN-ACK. Measured identically at
three points: HEAD with the deletion, HEAD with the deletion stashed (server path
fully intact), and `9fdf257` (before the entire network-isolation series). DHCP,
ARP and DNS all work; the outbound SYN leaves and nothing returns. It therefore
predates this work and needs its own investigation. This is why the harness
asserts end-to-end on **DNS** rather than an HTTP body: DNS is real inbound
traffic through the same `handle_packet` dispatch the branch was cut from, and it
demonstrably works, so a failure there is attributable to this edit. Asserting on
an HTTP body would fail on `main` too — measuring the pre-existing bug while
looking like a regression report for this change. The TCP client path is
consequently not covered end-to-end; that gap is stated in the harness header
rather than papered over.

**C1 (landed) — the read-only state queries, as one syscall.** `SYS_NETSTAT`
(37) covers all seven accessors (`tcp_available`, `tcp_is_connected`,
`tcp_get_state`, `dns_is_resolved`, `dns_get_resolved_ip`, `dhcp_is_configured`,
`dhcp_get_client_info`) plus the interface addresses, behind five subcommands.
One entry point rather than seven: each separate syscall needs its own
credential check and its own bounds check, and seven of those is seven chances
to omit one.

Three decisions worth keeping:

*It is not euid-gated, unlike `SYS_NETRX`/`SYS_NETTX`.* Those hand over raw
frames — the whole segment's traffic — so they are root-only. These report the
caller's **own** sockets, so the access control is ownership, not privilege.
Gating on euid would make the ring-3 shell unable to see its own connections,
which is the point of the syscall.

*The audit found the socket table unowned.* `tcp_connection_t` had no uid field
and a `sockfd` is a bare index into a global array, so exporting the queries
as-is would have handed any user a read oracle over every other user's
connections: peer address, state, and `tcp_available` as a traffic side channel.
Fixed in the **primitive** — `tcp_socket()` stamps `owner_uid`, and one
predicate (`tcp_owner_visible`) is consulted by `tcp_snapshot()` — rather than
in the syscall, per the `ramfs_chmod` lesson. Same shape as
`task_visible_to_current()`: euid for privilege, real uid for ownership, root
sees all. A socket the caller cannot see is `-EBADF`, never `-EPERM`, or the
errno alone enumerates the table (the `cmd_kill`/`sys_waitpid` policy).

*The individual accessors take no lock.* Harmless while the only caller was the
kernel shell; not once ring 3 can ask, since those reads race `tcp_handle_packet`
on `knetd`. Calling three in a row can report a state from before a segment
arrived beside a byte count from after it, and `rx_head`/`rx_tail` are worse —
`tcp_rx_available()` subtracts them, so a torn pair returns a wildly wrong
length. `tcp_snapshot()` reads everything the caller sees in one `TCP_LOCK()`.

**What the C1 harness does NOT prove.** The socket bitmap reads 0 for root *and*
for the unprivileged caller, because the TCP table is empty on a stock boot:
DHCP and DNS use raw UDP and never call `tcp_socket()`, and `tcp_tests.c` is
compiled but reachable from no shell command. A negative control confirmed the
consequence — replacing the ownership comparison with `return true` left every
call site intact, so all other source guards passed, the probe printed
byte-identical output, and the harness returned **PASS** against a build where
any user could read every socket. The runtime half structurally cannot catch
this; the source guard asserting on the comparison itself is what stands in the
way, and it is commented as load-bearing. C2 can prove it end-to-end, because C2
can open a socket. Stated rather than implied, because a zero that looks like
evidence is exactly the O_TRUNC/`cat` trap.

**C2 closed that gap — and the first attempt at closing it failed the same way.**
The obvious fix was to have the probe open a socket and assert it appears in its
own bitmap. That passed, and a negative control showed it passed against an
inert filter too: at the moment the bitmap is read, the caller's socket is the
*only* one in the table, so `mask=1` either way. "I can see my own socket" is
necessary and proves nothing about **exclusion**, which is the entire property.
What works: the **root pass deliberately leaks a socket** (opens one, never
closes it), so a live *foreign* socket exists while the unprivileged pass runs.
Working filter → `mask=1`, `foreign=0`; hollowed filter → `mask=3`, `foreign=2`,
and the harness names it. That is the first end-to-end proof of the ownership
filter in this tree.

`dhcp_get_client_info()` returns a pointer **into** kernel state; it is read
field-by-field and never handed across. The copied struct also omits the DHCP
transaction id, which is the value needed to forge a reply into an in-flight
exchange and is no business of an unprivileged caller.

The syscall ABI carries three registers (`ebx`/`ecx`/`edx`) and this call wants
four values, so subcommand and sockfd share arg1 (`NETSTAT_ARG`). Widening the
ABI to a fourth register would touch the asm entry path and every existing
syscall — not this PR's job.

**C2 (landed) — the data path.** `SYS_TCPSOCK` (38) carries
`tcp_socket`/`tcp_connect`/`tcp_send`/`tcp_recv`/`tcp_close` across the boundary
behind five subcommands, same one-syscall-with-a-subcommand shape and same
three-register packing as C1. Ownership-gated, not euid-gated — the opposite
polarity to `SYS_NETRX`/`SYS_NETTX`, and the third place in this tree where
copying an assertion between the two halves would invert it.

The ownership check lives at the **syscall boundary**, not inside
`tcp_send`/`tcp_recv`/`tcp_close`. This is the one place the `ramfs_chmod`
"enforce in the primitive" rule does *not* apply: the kernel's own callers
(`curl`, `tcp_tick`, the IRQ-path receiver) run with no current task or as root
and must not be filtered. The primitive stays uid-blind; the boundary is where a
credential exists at all.

**The audit found two live bugs in the primitives, fixed in the same PR** (the
#45/#47/#54/#55 rule — every time a dead or kernel-only path was exposed, it
turned out to carry something serious):

- `tcp_socket()` has two allocation paths, and the **TIME_WAIT eviction retry
  never stamped `owner_uid`**. `memset` zeroes it and uid 0 is root, so a socket
  allocated under TIME_WAIT pressure came back *root-owned* — invisible to the
  unprivileged caller that asked for it, visible to every root query. Latent
  while `tcp_socket` was kernel-only.
- `tcp_recv()` read `in_use`/`state`/`rx_head`/`rx_tail` **outside `TCP_LOCK`**.
  `tcp_rx_available()` subtracts head and tail, both mutated by the IRQ-path
  receiver; a torn pair returns a length near `TCP_RX_BUFFER_SIZE` for an
  almost-empty buffer, and that length drove the copy loop. With `SYS_TCPRECV`
  the remote peer chooses the arrival timing and the caller chooses when to race
  it.

Neither is reachable from the ring-3 probe (the first needs half the table in
TIME_WAIT), so both are held by source guards rather than runtime assertions —
each verified by removing the fix and confirming the guard fires.

`tcp_recv` is **non-blocking**, matching `SYS_NETRX`: byte count, 0 for
nothing-queued-or-EOF, negative errno on a dead socket. A blocking variant needs
an ISR-driven wait queue where one lost wakeup wedges the stack with no
diagnostic — a separate PR, not a flag on this one.

**TCP-over-NAT was never broken.** The belief that a handshake could not complete
came from reading `verify-tcp-serverpath.sh`, which drives `dig`, exercises the
*server* path, and never calls `tcp_connect`. A pcap of `curl example.com` shows
a clean SYN / SYN-ACK / ACK, HTTP/1.1 200, and a two-way FIN. Before fixing a
network bug, run the reproducer for the **direction** in question.

**PR D — move the parser to ring 3.** Only after A–C. This is the PR where the
trust domain actually changes.

**D is not one PR, and measuring it is what established that.** The first step
of D was counting what the four parser files actually call out to, the same way
the first step of C was discovering the 23 was really 20:

| Callee | Sites | Why it blocks a clean move |
|---|---|---|
| `kprintf` | 144 | ring-0 primitive, on code that would run at CPL 3 |
| `scheduler_yield` | 8 | ring-0 primitive |
| `csprng_random_bytes` | 7 | feeds TCP ISN generation — exposing it to ring 3 **is** an ISN-prediction primitive |
| `e1000_send` | 4 | raw TX; forges any source MAC/IP, which is exactly why `SYS_NETTX` is euid-gated |
| `scheduler_get_current_task` | 2 | ring-0 primitive |
| `sha256`, `firewall_allow_port`, `task_visible_to_current` | 1 each | ring-0 primitives |

Each becomes a new syscall or a daemon-side reimplementation. Two of them —
`e1000_send` and `csprng_random_bytes` — are precisely the primitives that
cannot be handed to ring 3 unguarded, so they need the same gating treatment
`SYS_NETTX` got, not a mechanical port.

Three further constraints, all measured rather than assumed:

1. **`tcp_connections[]` gets two writers in two rings.** The RX parser mutates
   it, and since PR C2 so does `SYS_TCPSOCK` from ring 3 via kernel calls. Open
   question 2 below is framed as "shared buffer ownership", but the frame buffer
   is the easy half — the hard half is this table. `tcp_send_segment`'s standing
   DANGEROUS INVARIANT comment already names "socket API syscalls that call TCP
   directly" as what breaks its unlocked `static uint8_t packet[1514]`.
2. **17 external call sites** — 12 in `syscall.c`, 5 in `kernel.c` — reach into
   the parser files. The `kernel.c` ones include the boot DHCP path, which runs
   before any ring-3 daemon could exist (open question 3, still unanswered).
3. **Finding A3's `uint8_t buf[1514]`** (`icmp.c:254`) was flagged for this PR
   because ring 3 has a different stack budget. It stays flagged; it is not
   reachable until the move it is waiting on.

**What landed instead: the CPL witness.** The one piece of D with no design
ambiguity, and the only piece that *must* be built before the move rather than
after. `handle_packet()` now reads the low two bits of `%cs` at the same site and
on the same "counted before any early return" rule as the interrupt-context pair,
surfaced by `ifconfig` as `RX ring: N cpl0, M cpl3`.

The reason it goes first is that a harness written *after* the parser moves has
nothing to compare against — it can only observe the post-move state and declare
it correct. Recording the baseline against a kernel whose ring is known means the
move has to invert two numbers that are currently pinned the other way.

**Why this is a separate counter from `irq-ctx`, and why that is not pedantry.**
`knetd` runs with `IF=1` **and** at CPL 0. So a build in which nothing has moved
reports a perfectly healthy `RX parsed: N thread-ctx, 0 irq-ctx`. Interrupt state
and privilege level are independent axes; item 1 pinned the first and says
nothing about the second. This document already names the weak version of the D
harness ("ping still works") as something that passes against a kernel where the
parser never moved — "thread-ctx is healthy" is the same false pass in better
disguise, and more dangerous because it looks like evidence.

The witness reads `%cs`, **not** a software flag such as "am I on the knetd
task". A flag records what the code believes about itself; the entire purpose of
the counter is to catch a build whose belief is wrong. `verify-netd-ring3.sh`
has a source guard on that specific shape, because a flag-based rewrite is a
plausible-looking "simplification" that silently destroys the property.

**Negative controls, both run.** The instrument being new is the argument for
controlling it, and both halves of the assertion were confirmed falsifiable:

- **NC1 — hollow the witness** (`net_current_cpl()` body → `return 3;`, keeping the
  `%cs` read so the source guard stays green): harness **FAILED** correctly with
  `cpl3 delta=20`, caught on reading #2. Without this control the runtime
  assertion would have been decorative in exactly the way PR C1's was.
- **NC2 — delete the increment block**: harness **FAILED** correctly with
  `cpl0 delta=0`. This is the instructive one — `cpl3 == 0` was *true* under NC2,
  and a one-sided harness would have reported PASS. Zero of nothing is zero; the
  positive half is what gives the zero meaning.

Baseline recorded: 20 injected frames, `cpl0 delta=20`, `cpl3 == 0` across all
readings. `verify-netd-ring3.sh` flips via `TINYOS_EXPECT_CPL3=1` when the move
lands; if the move requires rewriting the assertions rather than flipping that
flag, the counters moved with the code instead of measuring it.

`MAX_SYSCALL_NUM` is **38** as of PR C2 (`SYS_NETRX` 35, `SYS_NETTX` 36,
`SYS_NETSTAT` 37, `SYS_TCPSOCK` 38); it was 34 (`SYS_KILL`) before PR B. Every PR that adds a syscall must bump it — CLAUDE.md records
this exact bug: it sat at 16 while `SYS_SLEEP` (17) and `SYS_WAITPID` (18) had
working dispatcher cases, silently rejecting both. `verify-netd-boundary.sh`'s
source guard now compares the two numerically rather than trusting a reading, on
the grounds that a stale bound makes the dispatcher cases unreachable while
leaving every line of the diff looking correct.

## PR A — audit findings

Scope as settled above: the L4 parsers (`tcp.c`, `dns.c`, `dhcp.c`, `icmp.c`) and
the dispatch switch in `net.c` below line 1553.

### Audited and found sound

Recorded because "we looked and it was fine" is a result, and because the next
person to read this should not re-derive it:

- **DNS name decompression** (`dns.c:329-413`) — the classic remote-code-execution
  site in any DNS implementation. It is correct. Compression pointers must point
  **strictly backward** (`packet_start + offset >= current_pos` rejects), which
  makes decompression loops structurally impossible rather than merely bounded;
  the output-space check precedes the `memcpy`; label length is capped at 63 and
  label count at 127. The `followed_pointer` flag is dead code (assigned, never
  read) — harmless, since the backward-only rule is what actually prevents loops,
  but it advertises a defence that isn't the real one.
- **`last_queried_domain`** (`dns.c:655-661`) — buffer is `MAX_DOMAIN_NAME_LEN + 1`
  and the guard rejects `> MAX_DOMAIN_NAME_LEN`, so the copy fits with the NUL.
- **ICMP echo-reply construction** (`icmp.c:241-315`) — bounds arithmetic is sound.
  `reply_total > 1514` rejects before any write, and `off` cannot exceed it.

### Finding A1 — unthrottled per-packet `kprintf` on the ICMP echo-**reply** path

`icmp.c:208` prints once per received echo reply whose identifier matches
`ping_identifier`. It sits in the `ICMP_ECHO_REPLY` branch, which returns before
reaching the rate limiter — so unlike the echo-*request* prints below it, nothing
bounds it.

`ping_identifier` is CSPRNG-derived (`icmp.c:449`) and fixed for the boot, so an
off-path attacker faces 1-in-65536 per packet. An **on-path** attacker does not
have to guess at all: the identifier travels in cleartext in every outbound ping,
so observing one ping yields it, after which every injected packet drives a
console print from the RX path.

This is precisely the class item 2 closed — CLAUDE.md: *"The RX path is stricter
still: no per-packet `kprintf` at all. Those sites need no local account — any host
on the segment drives them."* Five such sites were replaced with counters; this one
was missed, because it is in `icmp.c` rather than in the RX loops that sweep
covered.

**Fix — landed.** Counter plus `ifconfig` reporting, following the `net_drop_runt`
pattern: `icmp_echo_replies_rx`, surfaced through `icmp_get_rx_stats()`. Harness
`verify-icmp-counters.sh`.

The per-reply detail line is gone, not relocated. `send_test_ping()` already
prints a transmitted/received/loss summary from `pings_received` (which still
increments), so the `ping` command keeps its actual result reporting; what is lost
is the per-packet line, which is precisely the thing a remote host was driving.

**Coverage limit, stated plainly:** the harness cannot drive this path. Acceptance
requires matching `ping_identifier`, which is CSPRNG-derived at boot and never
printed, so injected traffic cannot reach the branch. A1 is therefore proven by
the harness's **source guard only** — the print is gone and a counter stands in
its place — while A2's sibling path is proven end-to-end by traffic. A guard-only
proof is weaker than an end-to-end one and is not presented as equivalent.

### Finding A2 — the two echo-*request* prints are throttled, but by accident

`icmp.c:238` and `icmp.c:320` are also per-packet, but the `ICMP_RATE_LIMIT_TICKS`
check (10 ticks ≈ 100 ms) precedes them, capping the flood at ~10 lines/second.
That is a real bound, so this is not the same severity as A1.

It is worth recording that the bound is **incidental**: the rate limiter exists to
cap reply *generation*, not console output, and the prints are downstream of it by
placement rather than by design. Anyone who later moves the rate limiter, or adds a
print above it, silently reopens A1. They are converted to counters in the same
change so the invariant is structural rather than positional.

**Fixed alongside A1**, as `icmp_echo_requests_rx` and the existing
`icmp_replies_dropped`, both surfaced by `ifconfig`. The negative control put a
number on the "incidental" claim: with this print restored, 20 injected frames
produced exactly **one** console line, the limiter throttling it — visibly bounded,
and bounded by something that was never meant to bound it.

### Finding A3 — 1514-byte stack buffer on the path that is moving

`icmp.c:254` declares `uint8_t buf[1514]` as a local. On the kernel task stack this
is the pattern CLAUDE.md warns about ("keep big locals off the kernel task stack";
an earlier overflow silently corrupted a signature hash until the offenders were
made `static`). At 1.5 KB against 128 KB it is not currently a problem, and this
audit does not change it — but it is on the code path that PR D moves to ring 3,
where the stack is a different size and the budget is not the one reasoned about
here. Flagged for PR D, not fixed now.

### Finding A4 — `handle_dns_response()` had twenty of them, and one leaked attacker bytes

Found while scoping D1b. The `icmp.c` sweep (A1–A3) fixed the file it was looking
at; `dns.c` was never swept, and `handle_dns_response()` carried **20** `kprintf`
sites — four times A1's count, on the same remotely-driven RX path.

Severity above A1 on two counts. First, **the drop branches are the ones an
attacker reaches**: source-IP mismatch, transaction-ID mismatch, and question-name
mismatch are precisely what a spraying off-path attacker trips, so a forged
response bought several console lines each while a *legitimate* response bought
few. The print density was inverted with respect to who was driving it. Second,
the question-mismatch branch printed **`question_domain`** — bytes copied out of
the attacker's own packet — onto the kernel console, which a ring-3 shell shares
with the user's own output. That is attacker-chosen content on the operator's
terminal, not merely attacker-driven volume.

Neither the TID nor the source-IP check bounds this: both branches *are* the
print sites, so tripping the defence is what produces the output. Unlike A2 there
is no rate limiter anywhere on the path, incidental or otherwise.

**Fix — landed.** Six counters through `dns_get_rx_stats()`, on the
`net_drop_runt`/`icmp_get_rx_stats` pattern, surfaced by `ifconfig` as two lines.
The three *attack* signatures are kept apart deliberately: one combined "dropped"
total would tell an operator that something is being rejected while hiding which
attack is underway, and those three imply different attacker positions. Malformed
and truncated share one counter — same signal, no such distinction.

**This one is proven end-to-end, unlike A1.** A1 could only be guard-proven because
acceptance needed a CSPRNG `ping_identifier` that is never printed. DNS has the
same shape — matching TID and question name are required — but the values are
*ours*, recorded in file statics from our own outbound query. So
`dns_forge_response()` (`TINYOS_FAULT_INJECT`, driven by `dnsforge`) lives in
`dns.c` where it can read them, and builds one synthetic response per signature.

Three things about that forger not to undo. It lives in `dns.c` **because**
`last_dns_tid` and `dns_server_get` must stay file-static: exposing a TID getter to
build a test elsewhere would hand every caller the one value the anti-poisoning
check depends on staying private. Each variant differs from a valid response in
**exactly one** respect, or a rise in one counter would not identify which branch
ran. And the `question` case is a genuine name **mismatch**, not `qdcount=0` —
both land on `dns_drop_question`, so either makes the leg pass, but only the
mismatch runs the `strcasecmp` branch that used to print the attacker's bytes;
`qdcount=0` exits at the separate "require a question section" guard and would
leave the interesting site untested while the harness reported OK. The first
version of the forger had exactly that bug.

`dnsforge valid` is the **positive control** and is load-bearing: without it every
drop leg also passes against a forger emitting malformed garbage — the packets
would be rejected for a reason other than the one named, while the counters moved
exactly as expected. Proving the forger can produce an *accepted* packet is what
makes the rejections attributable.

The counter legs pair with a leg asserting `resolved` is **pinned** across the
drop-only window: all six counters could rise while the resolver *also* accepted
the forged answers, which is the spoofing defence failing while wearing the
metrics of a fix. Same counter as the positive control, opposite direction — do
not reconcile them.

The remaining 23 `kprintf` in `dns.c` stay. They are in `send_dns_query` and
`domain_to_dns_label`, driven by a local user typing `dig`/`curl` and therefore
bounded by local action; the rule is about paths a *remote* host drives. The
harness's print assertion is scoped to `handle_dns_response`'s body for this
reason — a file-wide grep fails on correct code and pushes the next person into
"fixing" the outbound path.

Harness: `verify-dns-rx-counters.sh`. Negative control run, not assumed: restoring
one print inside `handle_dns_response` fails the print leg **alone** while all
seven counter legs still pass — counters correct, print still there, which is the
bug exactly.

**Trap worth recording.** The harness read three `ifconfig` outputs but the typist
produces **four** — `TINYOS_EXEC_CMD` fires its own reading before the followup
list runs. Off by one, it compared the pre-`dig` baseline against the post-`valid`
reading, and reported *every* drop leg as "did not move" against a kernel whose
counters were all correct. The failure mode of an index error here is a false
FAIL, which is the safe direction, but it cost a full boot cycle to attribute.

## Harness design — before the code

Per instruction, and per `harness-design-principles`: test the boundary the fix
lives at, assert counts and positions rather than presence, and pair every
positive with a negative control that fails against a reverted build.

**`verify-netd-boundary.sh` (PR B).** Assert frames traverse the syscall pair, not
merely that networking still works — networking working is exactly what a build
with the syscalls bypassed also shows. Needs a counter at the syscall, compared
against the existing `RX parsed:` accounting from item 1, with the two-sided
assertion: delta > 0 **and** the bypass path reads 0.

**`verify-netd-ring3.sh` (PR D).** Assert the parser is executing at CPL 3. The
weak version of this harness — "ping still works" — passes against a kernel where
nothing moved, so it must instead witness the ring: parse-context accounting
extended with a CPL field, asserted as 3, paired with a negative control that
restores the ring-0 call and must read 0.

### What building `verify-icmp-counters.sh` cost, and what PRs B–D should expect

Two earlier versions of that harness passed nothing while looking healthy. Both
showed `RX packets: 20` and `RX parsed: 20 thread-ctx` — every indicator green
except the counter under test, which stayed at 0.

- **v1** addressed packets to `net.c`'s compiled-in default `192.168.0.80`. The
  socket netdev has no DHCP, so the guest self-assigns a link-local `169.254.x.x`;
  every frame died at the destination-IP check.
- **v2** read the guest IP at runtime but used a link-local **source**. Every frame
  died one layer later, in the firewall's bogon filter — which rejects `0/8`,
  `127/8`, `169.254/16`, `10/8`, `172.16/12`, `192.168/16`, `224/4` and `240/4`,
  i.e. every range a lab setup reaches for by instinct. The fix was TEST-NET-3
  (`203.0.113.0/24`, RFC 5737).

The generalizable points, all of which apply directly to PRs B–D:

1. **An exact-count assertion is what caught this.** A `>= 1` or "networking still
   works" check passes in both failure modes above. This is the harness-design
   principle "assert counts, not presence" earning its keep twice in one afternoon.
2. **Injected traffic must survive every layer above the one under test.** The
   ICMP counters sit below IP validation, the destination check, the firewall and
   the IDS. Any of them silently eats the test. PR B's syscall boundary sits below
   all of the same layers.
3. **Instrument to find the drop point; don't read harder.** Both were located in
   one run by temporarily printing at each early return in `handle_ip`. Two rounds
   of careful source reading had already missed them.
4. **Assert the sum when a limiter splits the count.** 20 frames arrived as 1
   answered + 19 rate-limited. Asserting either half alone is either flaky or
   toothless; asserting `answered + limited == sent` is neither.

**Explicitly not planned: a memory-poke command to inspect daemon state.** Item 3
faced this and declined for the same reason — it would be a kernel-address read
primitive of the class PR #58 gated behind root. Assert through existing
interfaces or add a purpose-built read-only one.

## Open questions — genuinely undecided

Not rhetorical; each changes the design and none should be answered by whoever
writes the code without saying so.

1. ~~**Does the daemon dying take networking down?**~~ **In scope — decided by the
   maintainer, 2026-08-17.** Restart policy is a first-class requirement of the
   parser move, not a follow-up. See "Settled: what moves first" below for what
   that costs, and note the finding that made it expensive: **the kernel has no
   supervision machinery of any kind.** `grep` for respawn/restart/watchdog across
   `src/` returns nothing but unrelated matches, and `task_knetd()` is a `while(1)`
   that cannot exit. So this is new subsystem work — a supervisor that can observe
   a task's death and re-create it — rather than a policy flag on an existing
   mechanism.
2. ~~**Shared buffer ownership.**~~ **RESOLVED 2026-08-17 — copy-in.** Item 1
   established that a deferred parser **must copy** the frame before RDT advances,
   because the NIC refills the descriptor and a retained pointer is an
   attacker-timed UAF. A ring-3 shared buffer has the same hazard with a second
   reader. No argument for zero-copy was ever produced, and the copy is forced by
   hardware rather than chosen. See "Open question 2, resolved" at the end of this
   document.
3. **Does DHCP move?** It writes the config globals at boot, before a ring-3
   daemon plausibly exists. Item 1 already hit this: `kernel.c`'s boot DHCP loop
   needs its explicit `e1000_rx_softirq_run()` drain because `knetd` does not
   exist yet. The same ordering problem, one ring further out.
   **Partly forced by the D1 split below:** DHCP is in the moving set, so the boot
   lease must either complete in ring 0 before the daemon starts (a two-phase
   parser, ring 0 until handoff) or the daemon must start earlier than the lease.
   The former is strongly preferred — it keeps the existing boot drain exactly as
   item 1 left it, and CLAUDE.md records that a "did it run" flag was tried there
   and reverted because it masks a stalled `knetd`. Still open only in the sense
   that the handoff mechanism is unwritten; the shape is decided.
4. ~~**Is `firewall.c`/`ids.c` on the ring-3 side?**~~ **Settled — they stay in
   ring 0.** See below; this reshaped the split, as predicted.

## Settled: where the boundary actually falls

Question 4 was the one flagged as most likely to reshape the item, and it did —
though the answer is better than either option originally sketched.

`firewall_check_packet()` and `ids_analyze_packet()` are called from `net.c:1543`
and `1553`, **after** IP header validation and **before** the L4 dispatch switch.
That is a seam that exists nowhere else in `handle_packet()`, and it splits the
parser in two along exactly the line this item needs:

```
  ethernet + IP header validation      <- stays ring 0 (small, already audited)
  firewall_check_packet()              <- stays ring 0 (enforcement)
  ids_analyze_packet()                 <- stays ring 0 (enforcement)
  ---------------------------------- the boundary
  switch (protocol) { TCP UDP ICMP }   <- moves to ring 3 (the bulk)
  tcp.c / dns.c / dhcp.c / icmp.c      <- moves to ring 3
```

The seam holds under inspection: `firewall.c` and `ids.c` call **nothing** in the
L4 parsers (no `tcp_*`, `dns_*`, `dhcp_*`, `icmp_*`, `handle_*`), and their state —
`rules[]`, `connections[]`, `rate_limits[]`, `attack_detectors[]` — is entirely
their own. Neither reaches across.

**Why they stay in ring 0.** Moving the enforcement point out of the kernel is a
regression precisely when the daemon is what is being attacked: a compromised
ring-3 parser that also owns the firewall can switch it off. Keeping enforcement
kernel-side means a hostile packet must get past the firewall and the IDS *before*
it reaches the code that would be running at CPL 3 — and if it compromises that
code, the firewall is still there, still enforcing, in an address space the daemon
cannot write. This is the arrangement that makes the move a security improvement
rather than a lateral relocation of the same trust.

It also shrinks the item: L2/L3 validation and enforcement stay put, so the code
changing trust domain is the L4 parsers and nothing else.

**Consequence for PR A's audit scope**, which this question was blocking: the audit
covers the L4 parsers and their dispatch — `tcp.c`, `dns.c`, `dhcp.c`, `icmp.c`,
and the switch in `net.c` below line 1553. `firewall.c` and `ids.c` are *out* of
the exposure audit, because they are not being exposed. They stay in scope for the
separate question of whether they remain correct when their caller is no longer
the same-privilege code that follows them.

## Settled: what moves first, and what the restart policy costs

Decided by the maintainer, 2026-08-17, after PR #74 landed the CPL witness and
the scope measurement above. These answer open questions 1 and 3.

### D1 — TCP stays in ring 0; ICMP/DNS/DHCP move first

> **Sequencing note added later.** This section settles *which set* moves, and
> that is unchanged. It does not settle the order within the set, and D1 turned
> out not to be one PR: see "PR D1a — ring arbitration" and "D1b — the audit that
> changed which protocol moves first" at the end of this document. Short version:
> a ring-arbitration fix has to land first, and DNS moves before ICMP, not after.

The deciding fact is in the code, not in the preference: `tcp_connections[]` has
**three independent mutators**, not the two the "two writers in two rings" note
above assumed.

1. `tcp_handle_packet()` — the RX path, i.e. the code PR D moves
2. the socket API — `tcp_connect/send/recv/close`, driven from ring 3 via
   `SYS_TCPSOCK` since PR C2
3. `tcp_tick()` — the timer path (`interrupts.c:111`, deferred onto `ktimerd`),
   which **forcibly closes** connections on the SYN_SENT / SYN_RECEIVED timeout:
   `conn->state = TCP_CLOSED; conn->in_use = false;`

Mutator 3 is what makes TCP unmovable in this increment. Move the TCP parser to
ring 3 while the timer stays in ring 0 and a connection record can be freed by a
ring-0 timeout while a ring-3 parser holds a reference to it. That is not fixable
with a wider lock: `TCP_LOCK()` is a kernel critical section (`critical.h`), and a
ring-3 daemon cannot take it. The real options are to move the timer as well, or
to build an IPC-serialised ownership model where exactly one side may mutate a
record. Both are larger than the PR that first crosses the boundary, and both are
much easier to get right once a daemon exists to host them.

ICMP, DNS and DHCP have no equivalent hazard: request/response, no long-lived
table that a ring-0 timer mutates behind the parser's back.

**State the cost plainly: this is the smaller half of the attack surface.** TCP is
the largest and most stateful parser in the set. D1 is the right first increment
because it is the one that can be made correct, not because it finishes the job.
Ring-0 L4 surface after D1 is reduced, not eliminated.

**Consequence for `verify-netd-ring3.sh`, which must be handled before D1 lands.**
The harness's post-move branch currently fails when `cpl0` is nonzero, on the
grounds that a parser running in *both* rings is a partial move. After D1 that
assertion is wrong: TCP frames legitimately keep parsing at CPL 0. The counters
must therefore become **per-protocol** — the assertion is "no ICMP/DNS/DHCP frame
parsed at CPL 0" and "no TCP frame parsed at CPL 3", not a single global pair.

That change belongs in the PR *before* the move, for the same reason the witness
itself did: an assertion rewritten in the same commit as the code it grades is not
an independent check. Note also that the current global `cpl0`/`cpl3` pair remains
correct and useful as a total; the per-protocol counters supplement it rather than
replacing it, so the PR #74 baseline stays comparable.

### D2 — restart policy is in scope

Requested explicitly, and it is the half that makes the daemon model meaningful:
a ring-3 parser that cannot be restarted converts every parser crash into a
permanent loss of networking, which is *worse* than the monolithic arrangement it
replaces. "The daemon can die" is the entire premise; a design that has no answer
for the death has not moved the fault-tolerance needle at all.

**The finding that sets the price: there is no supervision machinery in this
kernel.** A sweep of `src/` for respawn / restart / watchdog / supervisor turns up
nothing but unrelated matches (`supervisor` in the paging sense, a `serial.c`
comment noting the absence of a watchdog). `task_knetd()` is:

```c
void task_knetd(void) {
    kprintf("[KNETD] RX bottom-half task started [OK]\n");
    while (1) { e1000_rx_softirq_run(); scheduler_yield(); }
}
```

— an infinite loop with no exit path, so nothing has ever had to notice a
system task dying. D2 is therefore a new subsystem, not a policy flag:
something must observe task death and re-create the task.

Questions D2 has to answer, none of which should be decided silently by whoever
writes the code:

- **What owns the restart?** A supervisor task, or the scheduler's exit path. A
  supervisor is preferable (the scheduler should not know about networking), but
  it is another always-running task that itself cannot be allowed to die.
- **What happens to in-flight state?** The softirq ring is kernel-owned and
  survives, which is an argument for keeping copy-in (open question 2) rather
  than a shared buffer whose ownership is ambiguous across a restart.
- **Restart storms.** A parser that crashes on a *specific* attacker-chosen frame
  restarts, re-reads the ring, and crashes again. The restart policy needs a rate
  limit and a give-up state, and the give-up state needs to be visible — a
  silently dead network daemon is the failure item 1's "did it run" flag was
  reverted for masking.
- **Does the frame that killed the daemon get dropped?** It must be, or the
  storm above is guaranteed. That means the ring must record a consumed-but-not-
  completed position, which is new bookkeeping.
- **What does the harness assert?** By the standard this document has held to
  elsewhere: kill the daemon deliberately, prove networking recovers, and prove
  the counter says it restarted. A negative control that removes the supervisor
  must fail that assertion — otherwise "networking still works" passes against a
  build where the daemon never died in the first place.

Sequencing: D2's supervisor is independent of D1's parser move and can be built
and tested against `knetd` as it exists today (a deliberately-killed `knetd` is a
complete test case without any ring-3 code). Building it first means D1 lands into
a kernel that already survives the death of the task it is about to make killable.

#### D2 as built — what was answered, and what was not

Landed: `src/supervisor.{c,h}`, `knetd` registered in `kernel.c`, supervision state
on `ifconfig`, harness `verify-supervisor.sh`.

Three of the five questions above are answered:

- **What owns the restart** — a supervisor task, as preferred. It is itself
  `CAP_UNKILLABLE` while `knetd` deliberately is not; a killable supervisor would
  let one `kill` disable restarts for everything it watches.
- **Restart storms** — `SUPERVISOR_MAX_RESTARTS` within `SUPERVISOR_WINDOW_MS`,
  checked inside `supervisor_restart()` so no second restart path can skip it.
  Give-up is one-way, printed, and surfaced in `ifconfig`'s `gave-up` count.
- **What the harness asserts** — four parts, the load-bearing one being that the
  RX counter *rises* across the kill. "Networking still works" was rejected
  exactly as this document warned: it passes when the kill silently failed.

Two were **not** answered at D2 time. Both have since been resolved by reading
the code — neither needed new machinery:

- **What happens to in-flight state** — settled with open question 2: copy-in.
  The softirq ring is kernel-owned and survives a `knetd` restart today, which
  was always the argument for it.
- **Does the killing frame get dropped** — **yes, already.** Both ring consumers
  advance `rx_softirq_tail` *before* using the frame, so a restarted daemon
  resumes at the next frame and cannot re-read the one that killed it. The claim
  previously made here — that the rate limiter was the only thing between an
  attacker-chosen frame and an unbounded restart loop — was **backwards**; the
  ordering is fail-safe. Corrected in full at the end of this document.

Corresponding harness gap: `verify-supervisor.sh` only ever asserts `gave-up == 0`,
proving the limiter does not fire spuriously and nothing more. **D1 must not land
without a control that drives `knetd` past the budget and asserts the daemon stays
dead** — a give-up that still restarts is worse than no limiter at all.
**Closed by the D1-prerequisite PR below.**

### D1 prerequisites — landed before the move

Two things the sections above required *before* D1, plus one kernel bug the second
of them found. All in one PR, none of it touching the parser.

**1. Per-protocol CPL counters.** `net_parse_proto_cpl` in `net.c`, incremented in
`handle_ip()`'s L4 dispatch switch — the exact seam the move falls on — and
surfaced by `ifconfig` as `RX proto-ring: icmp N/M, udp N/M, tcp N/M (cpl0/cpl3)`.
The global `cpl0`/`cpl3` pair stays as a running total so the PR #74 baseline
remains comparable.

`verify-netd-ring3.sh`'s post-move branch is rewritten to the D1 shape: three
assertions, two of which point in **opposite directions** —
`icmp_cpl0 == 0 && udp_cpl0 == 0` (the moved set moved), `tcp_cpl3 == 0` (TCP did
*not*), and `icmp_cpl3 + udp_cpl3 > 0` (the zeros are not vacuous). The opposite
polarity is the thing most likely to be "cleaned up" by someone making the three
checks look consistent; `verify-netd-boundary.sh` records that doing exactly that
has nearly inverted an assertion three times. The pre-move branch now also pins
every per-protocol `cpl3` field at 0, so the new counters are graded by the PR
that adds them rather than first exercised by the PR they are meant to grade.

**DNS and DHCP are not counted separately, deliberately.** Both ride UDP, and the
witness sits at the dispatch switch. Separating them would mean instrumenting the
port demux inside `handle_udp()` — a later, different seam that classifies a frame
by its destination port rather than by which ring executed the switch.

**2. The give-up control** (`verify-supervisor.sh` step 5). Three parts:
`gave-up` becomes 1, the `GIVING UP` line reaches the console, and — the only
independent one — the daemon **stays dead**, witnessed by injecting frames
afterwards and asserting the RX counter does **not** move. The first two are the
supervisor's opinion of itself; a give-up that sets the flag, prints the line and
restarts anyway passes both and is worse than no limiter, because the operator now
believes the loop has stopped. Note step 5c asserts the RX counter is pinned while
step 3 asserts it rises — same counter, opposite directions, on purpose.

The deaths are driven from **inside the guest** (`killknetd 8` sets a countdown
each restarted `knetd` decrements) rather than by typing the command eight times.
The budget is 5 deaths in 10 s; eight echo-verified keystrokes under TCG do not
reliably fit, and missing the window fails *silently* — the supervisor restarts
each time, the window rolls forward, `gave-up` stays 0, and the run reports
exactly what a **broken** limiter reports.

Negative control run: raising `SUPERVISOR_MAX_RESTARTS` to 50 so give-up cannot
fire. Steps 1–3 still pass (the daemon does keep recovering) and step 5a fails
with 9 restarts and `gave-up 0` — confirming step 5 is the only thing separating a
working limiter from an absent one.

**3. A scheduler panic on rapid restart, found by that control** — pre-existing,
not specific to supervision, and the first thing to ever kill the same daemon
twice in quick succession. The second death halted the kernel with
`All tasks terminated` while Shell, Idle, `ktimerd`, the supervisor and
`edr_daemon` were all alive and runnable.

The post-context-switch reaper freed a task's slot (`pid = 0`, state
`TERMINATED`) **without dequeuing it**, leaving a corpse in the circular ready
queue. `scheduler_get_next_task()` later rejects such an entry and calls
`scheduler_remove_task()` — whose `task->next == task` special case nulls **both**
head and tail. Correct for a genuine single-entry queue; catastrophic for a stale
self-linked node, because it discards every other live task with it. The next tick
sees `!ready_queue_head` and panics.

Fixed in the reaper (dequeue before freeing) rather than by teaching the queue to
tolerate corpses — the invariant worth keeping is *a freed slot is never in the
ready queue*, and hardening only the remove path leaves the window open for every
other reader of the list. The special case additionally now requires
`task == ready_queue_head` before emptying the queue.

**This is squarely a D1 concern, not an incidental fix.** A ring-3 parser that
crashes repeatedly is exactly the trigger, and after D1 a remote host chooses when
it fires.

Both of the items this section previously left open have since been resolved by
reading the code rather than the prose — see "Open question 2, resolved" below.
Copy-in is forced, not chosen; and the killing frame is *already* dropped, which
inverts what this document used to claim about the restart loop. What remains
open for D1 is `tcp_connections[]`, the hard half named in constraint 1.

Two pre-existing kernel bugs surfaced while building this; both are fixed here and
neither is specific to supervision. `task_free_resources()` returned the task's
guard page to the PMM without restoring its not-present identity mapping, poisoning
that physical frame for the next `pmm_alloc()` — live for every user process exit,
not just kernel tasks, and invisible because the panic lands on an unrelated later
allocation. And `task_create_kernel()` does not enqueue, so both the restart path
and the supervisor's own creation needed an explicit `scheduler_add_task()`;
without it a task is created, listed by `ps`, counted healthy, and never run.

## Open question 2, resolved — and a claim this document had backwards

Settled 2026-08-17 by reading `e1000.c` against the prose above. Both items the
D2 section left "open for D1" turn out not to be design forks at all. Recording
the reasoning, because in both cases the document's own framing was the thing
that made them look open.

### Copy-in: forced, not chosen

Open question 2 was framed as "copy-in vs shared buffer". It is not a choice.
Item 1 already established that a deferred parser **must** copy the frame before
RDT advances, because the NIC refills the descriptor and a retained pointer is an
attacker-timed UAF. A ring-3 shared buffer has that same hazard with a second
reader, and adds a worse one: the buffer would be writable by the parser whose
compromise is the entire threat model for moving it out of ring 0.

The document already said "copy-in remains the default; zero-copy needs a real
argument." No such argument has been produced, and the cost copy-in was suspected
of — a per-frame `memcpy` — is one the RX path already pays twice (ISR into
`rx_softirq_ring`, then ring into the parser's frame buffer). Zero-copy would
have to eliminate a copy that a hardware constraint requires.

**Decided: copy-in.** Reopen only with a measurement showing the copy is a real
cost, and a scheme where a ring-3 writer cannot reach a buffer the kernel still
trusts.

### The killing frame is already dropped — the inverted claim

This document stated that no consumed-but-not-completed bookkeeping exists, and
that without it "the rate limiter is the only thing standing between an
attacker-chosen frame and an unbounded restart loop." The first half is true.
The consequence is backwards.

Both ring consumers advance the tail **before** the frame is used, under
`E1000_LOCK()`:

- `e1000_rx_softirq_run()` (`e1000.c:385`) advances `rx_softirq_tail`, unlocks,
  and only then calls `handle_packet()` at line 388.
- `e1000_rx_dequeue()` (`e1000.c:436`) does the same, and its oversize branch at
  line 431 advances the tail with an explicit "Consume it anyway" comment.

So a frame that kills the parser has already been consumed. A restarted daemon
resumes at the *next* frame and cannot re-read the one that killed it. The
current ordering is **fail-safe (drop-on-dequeue)**, not fail-open, and the
restart loop this document feared is not reachable by replaying one frame — an
attacker must resend it, which is a different and much weaker primitive that the
rate limiter already bounds.

The real bookkeeping question at D1 is the *reverse* one, and it is a
reliability concern rather than a security one: drop-on-dequeue means a parser
that dies mid-frame loses that frame silently. For a malicious frame that is
exactly right. For a legitimate frame during an unrelated crash it is a silent
drop — acceptable for a datagram protocol (ICMP/DNS/DHCP all tolerate loss and
retry), which is precisely the moving set. **No new bookkeeping is required for
D1.** It would only be required if a lossless protocol moved, and TCP is staying
in ring 0.

### What is actually still open: `tcp_connections[]`

Constraint 1 named this "the hard half" and it is the one that survives. TCP
stays in ring 0 at D1, so the table is not crossing the boundary — but it
already has three writers, and D1 changes who can be running concurrently with
them:

| Writer | Context | Since |
|---|---|---|
| RX parser (`tcp_handle_packet`) | task, `knetd` | item 1 |
| `SYS_TCPSOCK` kernel calls | task, syscall from ring 3 | PR C2 |
| `tcp_tick()` | task, `ktimerd` | pre-existing |

One correction worth recording, because it was briefly believed otherwise while
writing this: **`tcp_tick()` does not run in the ISR.** `interrupts.c:111` sits
inside `timer_softirq_run()`, which the timer ISR only flags; `task_ktimerd()`
drains it in task context, the same top/bottom-half split as `knetd`. All three
writers are therefore task-context and serialized by `TCP_LOCK()`, which is why
the table is safe *today*.

What D1 changes is that `knetd` becomes killable and restartable. The question
to answer before the move is not locking but **interruption**: whether a parser
that dies between two `TCP_LOCK()` sections can leave `tcp_connections[]`
structurally valid but semantically half-updated (a connection advanced to a
state whose follow-up write never happened). The lock guarantees no torn read;
it guarantees nothing about a multi-step update abandoned midway. That is the
open D1 item, and it is answerable by auditing `tcp_handle_packet`'s multi-step
state transitions for a safe abort point — not by a new mechanism.

**That audit has since been run; the section below supersedes this paragraph.**
The window it hypothesises does not exist, and the audit found something more
important on the way to establishing that.

## The `tcp_connections[]` audit — and why D1's split is forced, not chosen

Run 2026-08-17, as the last item gating D1. The question posed was whether a
ring-3 parser dying between two `TCP_LOCK()` sections could leave
`tcp_connections[]` structurally valid but semantically half-updated. **The
answer is no, and the reason turns out to matter more than the answer.**

### Finding 1 — there is no multi-step window to abandon

`tcp_handle_packet()` (`tcp.c:1555–1579`) takes `TCP_LOCK()` once and releases it
once, with the entire state machine in between: `tcp_find_connection()` and the
whole of `tcp_process_segment()` execute inside that single critical section.
`tcp_process_segment` contains no `TCP_LOCK`, no `TCP_UNLOCK`, and no
`scheduler_yield` on any path — every early return inside it returns with the
lock still held by the caller, which then unlocks on the single exit.

`TCP_LOCK()` is `CRITICAL_SECTION_ENTER()`, i.e. `cli` (`tcp.c:126`). A task
holding it has interrupts disabled and therefore **cannot be preempted, cannot be
descheduled, and cannot be killed** partway through. The half-updated table this
audit went looking for is not reachable. No safe-abort-point work is needed, and
no new mechanism.

### Finding 2 — the same fact makes a ring-3 TCP parser impossible

The header comment at `tcp.c:50` lists among the lock's advantages that it "works
in any context (interrupt, kernel, **future user-mode**)." That is false, and it
is the one load-bearing false assumption in this area:

- `cli` and `sti` are privileged. They execute at CPL ≤ IOPL.
- User tasks are created with `eflags = 0x0202` — **IOPL=0** (`process.c:1391`).
- So `TCP_LOCK()` executed from ring 3 raises **#GP**, immediately.

A ring-3 TCP parser cannot take the only lock protecting the table it parses
into. It could not be given one either: the whole point of `cli` here is to
exclude the *other* two writers, and ring 3 cannot be trusted with an instruction
that disables preemption globally — that is a denial-of-service primitive handed
to the component most likely to be compromised.

**This is an independent derivation of the D1 split.** PR #75 settled "TCP stays
ring 0" from the `tcp_tick()` UAF argument — a ring-0 timer freeing a record
under a ring-3 parser. The lock reaches the same conclusion by a different route,
and more strongly: even with the UAF solved, TCP could not move, because its
mutual exclusion is built from an instruction ring 3 may not execute. Two
independent arguments for the same boundary is a good sign the boundary is real.

It also explains why the per-protocol CPL witness has TCP's polarity inverted
(`tcp_cpl3` must stay 0 while `icmp_cpl3`/`udp_cpl3` go nonzero). That is not a
staging decision to be revisited later; it is a hardware constraint. A future
build reporting a nonzero `tcp_cpl3` is not "further along" — it is a build where
TCP is #GP-faulting on every segment, and the counter is the thing that would
catch it.

### What this means for the moving set

ICMP, DNS and DHCP are unaffected by finding 2, because none of them takes
`TCP_LOCK`. Confirming this is a prerequisite of the move rather than an
assumption, and it is the natural first commit of D1 proper: sweep the moving
parsers for every `CRITICAL_SECTION_ENTER` / `cli` / `sti` / `TCP_LOCK` reach,
directly or through a callee. Any hit is a site that must become a syscall before
that protocol can move, on exactly the reasoning above.

### D1 is therefore unblocked

Every prerequisite this document recorded is now closed:

| Gate | Status |
|---|---|
| Give-up branch harness | Closed — PR #77, `verify-supervisor.sh` step 5 |
| Per-protocol CPL counters | Closed — PR #77 |
| Open question 2 (copy-in) | Closed — copy-in, forced by RDT/UAF |
| Killing-frame bookkeeping | Closed — already drop-on-dequeue; the old claim was inverted |
| `tcp_connections[]` | Closed — this audit; no window exists, and TCP cannot move regardless |

The remaining work is the move itself, and its first step is the privileged-
instruction sweep above — not because it is expected to find much, but because
finding 2 is precisely the kind of thing that is invisible until something
#GP-faults at ring 3, and the sweep is how it is caught before the move rather
than during it.

### The sweep, run — and what it found in `dns.c`

Run immediately rather than deferred to D1, because it is three greps and its
result changes D1's first commit. Sweeping the moving set (`icmp.c`, `dns.c`,
`dhcp.c`) for `CRITICAL_SECTION_ENTER`/`EXIT`, `TCP_LOCK`, `E1000_LOCK` and raw
`cli`/`sti`:

- **`icmp.c` — clean.** No privileged instruction, directly or via a callee.
- **`dhcp.c` — clean.**
- **`dns.c` — three hits**, all guarding the same 4-byte object,
  `dns_server_ip[4]` (`dns.c:25`):

| Site | Function | On the moving RX path? |
|---|---|---|
| `dns.c:73` | `set_dns_server()` | No — DHCP-side writer |
| `dns.c:441` | `handle_dns_response()` | **YES** |
| `dns.c:678` | DNS query send path | No — outbound, task context |

`dns.c:441` is the one that matters: it is inside `handle_dns_response()`, on the
inbound path that D1 moves. As written, a ring-3 DNS parser would **#GP on the
first DNS response it handled** — exactly the failure mode finding 2 predicts,
and exactly the reason to sweep before the move rather than debug it after.

All three protect against the same thing: `dns_server_ip` is written by DHCP and
read by DNS, and a 4-byte `memcpy` is not atomic, so a torn read yields a query
sent to a spliced address (the comment at `dns.c:665` works the attack through).
The protection is real and must not simply be deleted when the code moves.

The fix is not to hand ring 3 a lock. `dns_server_ip` is 4 bytes — one aligned
32-bit load or store on i386 is atomic with respect to interrupts by hardware,
with no `cli` required. Replacing the `memcpy`-under-`cli` pattern with a single
aligned `uint32_t` read/write removes all three critical sections and keeps the
tear-free property, at ring 3 and ring 0 alike. That is a small, self-contained,
independently verifiable change and it is **D1's first commit**: it can land and
be proven before any parser changes ring, and the existing DNS path exercises it
immediately.

Worth noting for whoever writes it: the object must be *declared* in a way that
guarantees 4-byte alignment for this to hold — `uint8_t dns_server_ip[4]` at
`dns.c:25` carries no alignment guarantee of its own, so the commit needs to
change the declaration, not only the accesses.

## PR D1a — ring arbitration, before any parser moves

D1 was scoped as one PR ("move the parsers, flip the harness flag"). Reading the
code first turned up four problems with that shape, and the first one is a
correctness bug that would have shipped inside the parser move where it would
have been very hard to see.

### The two-consumer race

`rx_softirq_ring` is single-consumer by construction. Two functions pop its tail:

- `e1000_rx_softirq_run()` — knetd, ring 0, calls `handle_packet()`
- `e1000_rx_dequeue()` — the `SYS_NETRX` half, added in PR B

PR B was safe only by accident of scheduling: `netprobe.elf` runs on demand, and
knetd is never draining at the same instant. A real ring-3 netd polling
`SYS_NETRX` in a loop changes that completely. Both consumers advance
`rx_softirq_tail`, so **each frame is delivered to exactly one of them, chosen by
whoever gets there first** — meaning TCP segments would be handed to the daemon
that does not parse TCP and silently dropped, at a rate that varies with load.

That is the worst failure shape available: intermittent, load-dependent, and it
presents as "networking is flaky" rather than as anything pointing at the ring.

### The fix keeps one consumer per ring

knetd stays the sole consumer of `rx_softirq_ring` and gains a classify step.
Frames whose L4 protocol is in the moving set (ICMP, UDP) are copied to a second
ring, `netd_ring`, which only `SYS_NETRX` pops. Everything else — TCP, ARP,
non-IPv4, malformed — it parses itself exactly as before.

```
ISR ──> rx_softirq_ring ──> knetd (sole consumer)
                              │
                    ┌─────────┴─────────┐
              TCP / ARP            ICMP / UDP
           parse in ring 0    ──> netd_ring ──> SYS_NETRX ──> netd (ring 3)
```

Route or parse, never both and never neither: it is one `if`/`else`, so no frame
can be delivered twice and none can be dropped between the two paths.

**Why classify in ring 0 rather than let netd filter.** The kernel must parse
Ethernet and IP headers regardless, because TCP stays in ring 0 permanently
(finding 2 — `TCP_LOCK` is `cli`, ring 3 has IOPL=0). Given that, classification
adds no new parsing surface; it reads the two headers the kernel already reads.
The alternative — netd receives everything and hands TCP back through another
syscall — makes ring-0 TCP depend on a killable ring-3 task, so every supervisor
restart window becomes a TCP outage. That trades a bounded ICMP/UDP outage for an
unbounded TCP one, in the name of a surface reduction the kernel does not get
anyway.

### The switch is inert until claimed, and reversible

`netd_claimed` gates the whole thing. While false, knetd parses everything and
the kernel behaves identically to the pre-D1a build — which is what makes this
PR safe to land before any parser has moved. Deregistration discards whatever is
queued: those frames predate the new daemon, and handing a restarted netd traffic
from before the crash is both wrong and a small leak across the restart boundary.

Reversibility is a supervisor requirement, not a nicety. A netd that dies must
hand its protocols back, or its death takes ICMP and UDP down permanently — which
is precisely the failure D2 exists to prevent.

### Harness — `verify-netd-arbitration.sh`

Every leg pins one counter while another moves, because "ping still replies"
passes against a build where the claim never takes effect, and a routing switch
that silently does nothing looks exactly like a healthy kernel.

| Leg | Claim | Assertion |
|---|---|---|
| 1 | off | `routed` pinned at 0 while `icmp_cpl0` **rises** |
| 2 | on | `routed` **rises** while `icmp_cpl0` is **pinned** |
| 3 | on | `tcp_cpl0` **rises** — TCP is never routed (no-movement scores FAIL, not pass: `>=` is satisfied by `0 >= 0`) |
| 4 | off | `routed` pinned again after release |

Legs 1 and 2 are each other's negative control: same traffic, opposite routing
outcome, and the only difference is the claim. Leg 1c exists because leg 1b
("routed == 0") passes vacuously on a kernel receiving no traffic at all.

The `netdclaim` lever is `-DTINYOS_FAULT_INJECT`-gated, like `killknetd`, because
claiming with no daemon running deliberately breaks ICMP/UDP — nothing drains the
ring. That is the observation leg 2 is built on, and it is not something a
production path should be able to do.

**Leg 3's driver cannot use DNS, and this follows from the paragraph above.**
Under the claim, UDP is routed to `netd_ring` with nothing draining it, so a
guest-side name lookup never completes: `curl example.com` inside the claimed
window resolves nothing, sends no SYN, and leaves `tcp_cpl0` at 0 — which scores
FAIL, correctly, but for a reason that has nothing to do with routing TCP. The
same command in an unclaimed probe boot gives `tcp 5/0`, which is what makes the
cause unambiguous. The harness therefore resolves its target **on the host** and
types a raw IP into the guest. Two tempting alternatives are both wrong: the NAT
gateway (`10.0.2.2`, with or without a port) never answers — measured `tcp 0/0`,
it drops the SYN without an RST — and a hardcoded literal rots when the CDN
address behind the name changes.

**One guard carries more weight than any leg**: `e1000_rx_dequeue` must read
`netd_ring_tail`. If it is ever pointed back at `rx_softirq_ring` the race
returns, and **no leg here would catch it** — every leg drives the knetd side,
not the syscall side. The guard is the only thing standing between that edit and
a silent regression.

## D1b — the audit that changed which protocol moves first

The plan was ICMP first, on the grounds that it is stateless request/response.
A dependency audit of all three moving handlers says otherwise.

| | `handle_dns_response` | `handle_icmp_with_context` | `handle_dhcp` |
|---|---|---|---|
| Needs a TX syscall | **No** | Yes (raw frame) | Yes (raw frame + ARP) |
| Direct `cli` | No | No | No |
| **Indirect `cli`** | **None** | **2** (timer, e1000) | **4** (timer, CSPRNG, ARP, e1000) |
| Writes ring-0 iface config | No | No | **Yes — all four** |
| `kprintf` sites | 19 (+7 in a callee) | 1 | 20 (+5 in callees) |
| Largest stack local | 254 B | **1514 B** | 1024 B (in a callee) |

**ICMP is not the easy one.** `handle_icmp_with_context` reaches `cli` twice on
the reply path — `get_timer_ticks()` (`icmp.c:241`, the rate limiter) and
`e1000_send()` (`icmp.c:334`) — so *every inbound ping* would #GP at ring 3. It
also carries a 1514-byte frame buffer, which sets the floor for the ring-3 stack.

**DNS is the clean first mover.** `handle_dns_response` reaches no TX path at
all: it parses and stores, and the query side (`send_dns_query`) is not on the
response path. After PR #78 it has no `cli` reach, direct or indirect. Its
largest local is 254 bytes. Its only ring-3 obstacle is `kprintf`, which is
shared by all three and has to be solved once regardless.

**DHCP is the hard one, and it is worse than "more of the same."** Its CSPRNG
dependency (`dhcp.c:542` → `crypto.c:576`) is structural — that critical section
protects a multi-block mutable keystream and cannot be made lock-free the way
`dns_server` was. More seriously, `handle_dhcp` writes **all four** interface
globals (`my_ip`, `subnet_mask`, `gateway_ip` via `set_network_config`, plus
`dns_server`), and ring-0 code reads every one of them: routing decisions
(`net.c:204`), ARP frame construction, TCP source-IP selection (`tcp.c:634`) and
**TCP ISN generation** (`tcp.c:1216`). Moving DHCP to ring 3 makes an untrusted
daemon the writer of state that ring-0 TCP depends on for its initial sequence
numbers. Those writes must become a **validating syscall**, not a shared page —
and that is a security design problem, not a code move.

### Revised sequencing

- **D1a** — ring arbitration (this PR). Nothing moves ring.
- **D1b** — DNS to ring 3. Needs the `kprintf` answer and a ring-3 netd skeleton;
  needs no TX syscall and no new locking.
- **D1c** — ICMP. Needs a raw-frame TX syscall and a timer-read syscall.
- **D1d** — DHCP. Needs D1c's TX plus a validating ifconfig syscall; the CSPRNG
  call has to move to the kernel side of that boundary.

The `TINYOS_EXPECT_CPL3=1` flag in `verify-netd-ring3.sh` cannot be a single
global switch across this sequence. After D1b, `udp_cpl3` is nonzero while
`icmp_cpl3` is still 0 and `tcp_cpl3` must stay 0 forever. The expectation is
per protocol, and it changes at each step.

## D1 re-scoped — the movability criterion the earlier plan never applied

**This section retracts the sequencing directly above it.** D1b step 1 (the
`kprintf` sweep, PR #80) stands and was worth landing on its own merits. D1b
step 2 — moving the DNS parser to ring 3 — was scoped, found unbuildable as
specified, and is **withdrawn**. So are D1c and D1d in their stated form. What
follows is why, and what replaces them.

### The criterion

Every earlier gate asked what a protocol *needs* in order to run at ring 3:
privileged instructions, a TX path, stack budget. Those are real and they were
answered correctly. They are also the wrong question, because they only decide
whether the move is *possible*. The question that decides whether it is
*worthwhile* is the opposite one:

> **Does ring 0 consume a result this parser produces, and act on it?**

If yes, moving the parser does not remove the trust — it relocates the parse and
then hands the result back across the boundary. A syscall carrying that result is
a syscall by which a compromised daemon drives the kernel, which is the exact
capability the move was supposed to cost the attacker.

Applied to the moving set:

| Protocol | Result ring 0 consumes | Acts on it |
|---|---|---|
| DNS | `last_resolved_ip`, `dns_resolution_complete` | `curl`/`dig`/`http_test` connect to it; `SYS_NETSTAT` reports it |
| DHCP | `my_ip`, `subnet_mask`, `gateway_ip`, `dns_server` | routing, ARP, TCP source-IP selection, **TCP ISN generation** (`tcp.c:1216`) |
| ARP | `arp_cache` | every TX picks its destination MAC from it |
| ICMP (inbound) | `pings_received` and three counters | **nothing** — statistics only |
| TCP | connection state | ring 0 permanently; `TCP_LOCK` is `cli` (finding 2) |

Three of the five are load-bearing state. ICMP's inbound half is the only one
that isn't, and its blocker was never the result — it is the *reply* path.

### Why kernel re-validation does not rescue DNS

The obvious repair is to have ring 3 parse and ring 0 re-check: keep the trust
decision in the kernel, give the untrusted daemon only the copying. That is the
right instinct and it fails on this particular protocol, for a structural reason.

DNS's three security checks are not a shell around the parser. They are
interleaved with it:

- Source-IP and transaction-ID are cheap header comparisons. Separable.
- **Question-name validation requires walking compressed labels**
  (`dns_label_to_domain` → `skip_dns_name`), including the compression-pointer
  loop guard and bounds checks at `dns.c:289`. This is the most attack-prone code
  in the file.
- **Finding the A record requires walking the answer resource records**, bounds-
  checking each RR header and every RDATA length against the packet end.

And ring 0 cannot skip that last step by trusting ring 3's *claimed* address —
that is the "trusted netd" design, wearing a validator's clothes. To validate
honestly, ring 0 must re-derive the address from the raw bytes, which means
re-executing substantially all 193 lines of `handle_dns_response()`, compression
handling included.

The result: ring 3 performs a `memcpy` and a syscall; ring 0 retains the entire
attack surface *and* gains a new entry point into it that ring 3 can call at
will. That is a net loss. A migration whose commit message claimed a privilege
reduction would be claiming something untrue.

### The error in the earlier scoping, stated plainly

The audit above graded DNS "the clean first mover" on the criteria that blocked
the other two: no TX path on the response path, zero `cli` reach after PR #78,
254-byte maximum local. Every one of those findings is correct. All of them are
irrelevant to the blocker, which is that DNS produces a result the kernel trusts.

The criteria measured cost of moving and never asked what moving would buy. That
is why the plan survived four PRs of prerequisite work before failing at contact
with the actual move: nothing in D1a, or in the CPL witness, or in the print
sweep, depended on the answer.

### What replaces D1

Two things are worth keeping and one is worth abandoning.

**Abandon:** "move ICMP/DNS/DHCP to ring 3" as a unit. DNS and DHCP stay in ring
0 for the reason above; ARP joins them, having never been examined and having the
same property.

**Keep — the measuring instruments.** The per-protocol CPL witness (PR #77), the
ring arbitration (D1a, PR #79) and the RX counters (PRs A1–A3, #80) are all
independently correct and all still useful. In particular `cpl3` pinned at **0**
stops being a pre-move baseline and becomes a **standing invariant**: with the
move withdrawn, any nonzero `cpl3` on any protocol is now a bug report rather
than progress. `verify-netd-ring3.sh` keeps its assertion and loses its flip;
`TINYOS_EXPECT_CPL3` should be removed rather than left as a switch nothing sets.

**ICMP — examined separately, and also declined.** Its inbound half passes the
result criterion cleanly: `handle_icmp_with_context` writes `pings_received` and
three counters, and nothing in the kernel acts on any of them. On that test alone
ICMP is the one protocol that could move.

It fails on a **second** test the DNS scoping never had to reach, because DNS's
response path has no TX half at all: *what capability does the moved component
need in order to do its job?*

An ICMP responder must reply, so it needs `SYS_NETTX`. And `e1000_send()`
performs **no source validation** — it bounds the length and writes the frame.
Raw TX is therefore unrestricted frame forgery: any source MAC, any source IP.
A compromised ring-3 responder holding that syscall can poison the ARP cache,
spoof DHCP, and inject TCP segments against the connections that deliberately
stayed in ring 0.

Set against what the move removes:

| | Ring 0 today | Ring-3 responder |
|---|---|---|
| Surface removed | — | ICMP echo parse, ~60 lines, audited clean (`icmp.c:241-315`, finding A3) |
| Capability granted | — | **unrestricted raw TX** |

Trading a general forgery primitive for a small audited parser is a worse deal
than the DNS one, not a better one. The reassuring version of this — "a
compromised responder can only forge echo replies, which an on-path attacker can
already do" — is false: it can forge *anything*, including traffic that an
on-path attacker on a switched segment cannot inject.

Two further costs, for the record. Finding A3's 1514-byte stack local would have
to be resolved against a ring-3 stack budget. And `get_timer_ticks()`
(`icmp.c:241`) gates the **rate limiter**: a responder reading a timer it does
not control needs that limiter to stay kernel-side, or the DoS protection
migrates into the untrusted component along with the parser.

**What would change the answer:** a *validating* TX syscall that pins the source
MAC and IP and restricts the caller to ICMP echo replies. That is buildable, and
it is a security design problem of the same class as DHCP's validating ifconfig
syscall — most of the total work, in service of protecting 60 audited lines. The
ratio is what decides it, and the ratio is bad.

**Decision: not built.** Recorded here so it is not restarted from momentum. The
general form of the second test is worth carrying forward: *a component that must
ACT, not merely observe, needs an actuator — and the actuator is usually worth
more to an attacker than the parser is.*

### The general lesson

The prerequisite work was good and the destination was wrong, which is a failure
mode worth naming: every gate asked "can this move?" and none asked "what does
moving buy?" A migration plan needs the second question answered *first*, because
it is the one that can invalidate the whole sequence — and it is cheapest to
answer at the start, when the answer costs a grep for who reads the parser's
output rather than four PRs of scaffolding.
