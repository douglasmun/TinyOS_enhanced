# Ephemeral port allocation issues

Status: **FIXED** (branch `fix/ephemeral-port-random`), witnessed by
`verify/verify-tcp-ephemeral-port.sh`. Recorded 2026-10-21 from a read-only
review of `main` at `925458d`. Nothing here was exploitable on its own. TinyOS
is a client-only TCP stack, there is no inbound accept path, and the TCP ISN is
already keyed (RFC 6528).

## Resolution

| # | Issue | Outcome |
|---|---|---|
| 1 | Sequential TCP ports | **Fixed.** `tcp_allocate_port()` now uses RFC 6056 Algorithm 1: a fresh `global_csprng` draw over 49152-65535 for each connection, retried up to 64 times on collision. There is no fallback: the CSPRNG panics if used before `crypto_init()`, and that runs before any network bring-up. |
| 2 | Dead exhaustion check | **Removed** along with the counter. The loop is now bounded only by the attempt count. |
| 3 | Collision check uses the local port only | **Kept** on purpose, and now documented on `tcp_port_is_free()`. |
| 4 | TIME_WAIT eviction frees the port early | **Fixed.** `tcp_evict_oldest_time_wait()` records the evicted port and the time its 30 s would have ended in `tcp_port_quarantine[]` (16 entries; when full, the entry closest to expiry is overwritten). `tcp_port_is_free()` refuses quarantined ports. The "LIFO" comments now say oldest-first. |
| 5 | Inconsistent locking | **Fixed.** `tcp_connect()` takes `TCP_LOCK` around its state check, half-open count and allocation. A slot that is in_use but still CLOSED now holds its port too: `tcp_connect()` assigns the port before the slot leaves CLOSED, and that state used to count as free. |

The harness drives ten real `tcp_socket()`/`tcp_connect()`/`tcp_close()`
cycles (transmission muted) and grades the ports. It also builds a synthetic
full table so that `tcp_socket()` evicts a TIME_WAIT entry, then checks which
ports are busy. Each fix was mutation-checked:

| Mutant | Result |
|---|---|
| Allocator from `main`, verbatim | FAIL (draws were 49152, 49153, ...) |
| Quarantine not consulted | FAIL (evicted port reads free) |
| CLOSED-slot exception restored | FAIL (in-progress connect's port reads free) |

The `TCP_LOCK` part of #5 has no witness. Two kernel-shell connects racing for
the same random port is a 1-in-16384 event, so no harness can make it happen on
demand. It is a code-reading fix only.

The original analysis follows unchanged.

## Where the code lives

| Protocol | Allocator | Scheme |
|---|---|---|
| TCP | `tcp_allocate_port()`, `src/tcp.c:398`; state is `next_ephemeral_port`, `src/tcp.c:142` | A sequential counter over 49152-65535. Before handing out a port it walks `tcp_connections[]` and treats any non-`TCP_CLOSED` entry (TIME_WAIT included) as a collision. Returns 0 when exhausted. |
| UDP (DNS) | `src/dns.c:951` | A fresh draw from the CSPRNG for every query: `49152 + (r % 16384)`. There is no bias because `65536 % 16384 == 0`. Replies are accepted only on `last_dns_src_port` (`dns.c:584`). |
| UDP (DHCP) | `src/dhcp.c:259` | Always port 68. The protocol requires this. |

The only allocation call site is `tcp_connect()` (`src/tcp.c:1327`). It
allocates when `local_port == 0`, and when allocation fails it counts the
refusal in `net_count_tcp_connect_refused()`. The port then feeds
`tcp_generate_isn()`. `tcp_bind` was deleted earlier because it took no lock
and ignored allocation failure (see the comment at `src/tcp.c:1275`).

## Issues

### 1. TCP ports are sequential and the same on every boot (main issue)

`next_ephemeral_port` starts at 49152 and goes up by one per connection. The
first outbound connection after boot always comes from 49152, the next from
49153, and so on.

- RFC 6056 says to obfuscate the ephemeral port. A blind off-path attacker
  injecting RST/data into a connection has to guess the 4-tuple plus an
  in-window sequence number. A predictable source port removes about 14 bits
  from that search.
- The keyed ISN still protects the sequence-number part, so this is
  defence in depth, not a reachable bug.
- It is also inconsistent with the DNS path, which randomises.

**Fix direction:** RFC 6056 Algorithm 1 (fully random port per connection,
then the existing collision check) or Algorithm 3 (a keyed hash of the
4-tuple plus an increment). Algorithm 1 is the simpler fit: the table has
only 8 slots, so a random draw almost never collides. Draw from
`global_csprng`, the same source DNS uses. The CSPRNG fails closed, so decide
what `tcp_connect` does when it is unavailable: refuse, or fall back to
sequential.

### 2. Dead exhaustion check in the TCP allocator

`MAX_PORT_SEARCH_ATTEMPTS` is 100, but the counter would need 16384 steps to
get back to `start_port`. So `if (next_ephemeral_port == start_port) return 0;`
(`tcp.c:455`) can never be true. With `TCP_MAX_CONNECTIONS = 8`
(`tcp.h:23`), the loop always finds a free port within 9 tries anyway.
Remove this check, or change it to match whatever scheme replaces issue 1.

### 3. The collision check uses the local port alone, not the 4-tuple

A port counts as busy if any live connection holds it, whatever the remote
endpoint. This is stricter than RFC 793 requires. At 8 connections it costs
nothing, so it is fine to leave as is. Recorded so that nobody reads it as a
4-tuple uniqueness guarantee.

### 4. The TIME_WAIT comment overstates the protection

The comment block at `tcp.c:415-435` says a port is "unavailable until
TIME_WAIT expires (30 seconds)". Actually:

- The 30 s timer exists (`TCP_TIME_WAIT_TIMEOUT`, `tcp.c:1789`).
- But `tcp_socket()` evicts the oldest TIME_WAIT entry once there are 4 or
  more of them (`TIME_WAIT_EVICTION_THRESHOLD = TCP_MAX_CONNECTIONS / 2`,
  `tcp.c:1237-1241`; counted by `net_count_tcp_tw_evicted()`). That frees the
  entry's port before 30 s are up.
- Today, sequential allocation hides this, because an evicted port is not
  handed out again until the counter wraps. **A randomised fix for issue 1
  removes that cover.** A random draw can land on a port that was just
  evicted from TIME_WAIT. The fix should either keep evicted ports out of the
  draw for the rest of TIME_WAIT, or state in the comment that this is an
  accepted trade-off.
- Minor: the header of `tcp_evict_oldest_time_wait()` (`tcp.c:194`) says
  "LIFO eviction", but the function evicts the *oldest* entry.

### 5. Inconsistent locking around allocation

`tcp_allocate_port()` reads and writes `next_ephemeral_port` and walks
`tcp_connections[]`. On the ring-3 path, `SYS_TCPSOCK` runs `tcp_connect`
inside `tcpsock_lock_owned()` ... `CRITICAL_SECTION_EXIT()`
(`syscall.c:2240`), so it is serialised. Kernel-shell callers
(`shell_network.c:914`, `http_test.c:84`, `tcp_tests.c`) call `tcp_connect`
directly, and inside `tcp_connect` `TCP_LOCK` covers only the SYN send
(`tcp.c:1358`). Either take `TCP_LOCK` inside `tcp_connect` around the
allocation, or document that callers must hold the lock. This is the same
class of bug as the deleted `tcp_bind`.

## Verification plan for the fix

- Fail-first test showing that two boots (or two consecutive connects) get
  the same/sequential source ports on the old code, and different ones with
  the fix. Use a wire witness (dgram netdev + `tools/net_peer.py`, see
  `doc/NETWORK_ISOLATION.md`), not a kernel counter.
- Mutation check: revert the randomisation and confirm the harness FAILs.
- A leg that fills TIME_WAIT past the eviction threshold and asserts that no
  new connection reuses an evicted port inside 30 s (issue 4).
- Run the existing TCP harnesses (`verify-tcp-*.sh`) afterwards.
