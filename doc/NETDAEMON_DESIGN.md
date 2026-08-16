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

**C1/C2 (not started) — the remaining 20.** Split proposed as C1 = the read-only
state queries (`tcp_available`, `tcp_is_connected`, `tcp_get_state`,
`dns_is_resolved`, `dns_get_resolved_ip`, `dhcp_is_configured`,
`dhcp_get_client_info`, plus `my_ip`/`my_mac`/`gateway_ip`/`subnet_mask` as one
query), which carry no write surface and so land with a much smaller audit; C2 =
the data path (`tcp_socket`/`tcp_connect`/`tcp_send`/`tcp_recv`/`tcp_close`).
Fixing TCP-over-NAT first would be sensible, since C2 cannot be verified
end-to-end while a handshake cannot complete.

**PR D — move the parser to ring 3.** Only after A–C. This is the PR where the
trust domain actually changes.

`MAX_SYSCALL_NUM` is **36** as of PR B (`SYS_NETRX` 35, `SYS_NETTX` 36); it was 34
(`SYS_KILL`) before. Every PR that adds a syscall must bump it — CLAUDE.md records
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

1. **Does the daemon dying take networking down?** A ring-3 parser can crash or be
   killed. Restart policy, and what happens to `tcp_connections[]` across a
   restart, is unresolved. "It cannot happen" is not an answer — the entire point
   is that it now can.
2. **Shared buffer ownership.** Item 1 established that a deferred parser **must
   copy** the frame before RDT advances, because the NIC refills the descriptor
   and a retained pointer is an attacker-timed UAF. A ring-3 shared buffer has the
   same hazard with a second reader. Copy-in remains the default; zero-copy needs
   a real argument.
3. **Does DHCP move?** It writes the config globals at boot, before a ring-3
   daemon plausibly exists. Item 1 already hit this: `kernel.c`'s boot DHCP loop
   needs its explicit `e1000_rx_softirq_run()` drain because `knetd` does not
   exist yet. The same ordering problem, one ring further out.
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
