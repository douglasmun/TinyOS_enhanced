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
receive/transmit and route the existing in-kernel parser through them. Proves the
boundary carries real traffic before anything changes trust domain. Fully
revertable; nothing is exposed yet.

**PR C — socket API across the boundary.** The 23 functions. Largest and least
glamorous PR; likely splits further.

**PR D — move the parser to ring 3.** Only after A–C. This is the PR where the
trust domain actually changes.

`MAX_SYSCALL_NUM` is currently 34 (`SYS_KILL`). Every PR that adds a syscall must
bump it — CLAUDE.md records this exact bug: it sat at 16 while `SYS_SLEEP` (17)
and `SYS_WAITPID` (18) had working dispatcher cases, silently rejecting both.

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
4. **Is `firewall.c`/`ids.c` on the ring-3 side?** Moving the enforcement point
   out of the kernel is a security *regression* if the daemon is the thing being
   attacked. Plausibly these stay in ring 0 and the split is not simply
   "driver | parser".

Question 4 is the one most likely to reshape the whole item, and it should be
settled before PR A's audit scope is fixed.
