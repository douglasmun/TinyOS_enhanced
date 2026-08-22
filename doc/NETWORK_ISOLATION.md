# Network stack isolation — assessment and to-do

Prompted by the question "Qubes OS separates its network stack into an unprivileged
VM; can we do the same?" This file records the answer, the evidence behind it, and
the four items that follow from it.

Companion to `doc/ROADMAP_NEXT.md`. Read this before touching the RX path.

## The short answer on a Qubes-style NetVM

**Not achievable here, and the reason matters more than the verdict.**

Qubes' own architecture page states the property as two clauses, not one:

> No networking code in the privileged domain (dom0) — networking code
> sand-boxed in an unprivileged VM (using IOMMU/VT-d).

The isolation is enforced by **the IOMMU, not the VM boundary**. A NIC is a
bus-mastering device: it writes to physical addresses on its own initiative. Without
VT-d to constrain which physical pages the device may target, a compromised driver
in a "sandboxed" VM programs the NIC to DMA over the hypervisor and the sandbox is
decorative. The VM is where the code lives; the IOMMU is what makes that placement
mean anything.

TinyOS has **no IOMMU support of any kind** — `grep -rni "iommu\|vt-d\|DMAR" src/`
returns nothing. It is also single-CPU, has no hypervisor, and uses PAE paging. So a
NetVM here would relocate the parser without constraining the device, which buys
approximately nothing while costing a great deal.

That is not a reason to leave the RX path as it is. The items below take the parts
of Qubes' model that *are* reachable without an IOMMU: shrink what runs privileged,
shrink what runs with interrupts disabled, and constrain what the device can reach
by placement rather than by hardware enforcement.

## Current state (verified against source, 2026-08-16)

**~8,350 lines** of attacker-reachable packet parsing:

| File | Lines |
|---|---|
| `src/net.c` | 1921 |
| `src/tcp.c` | 1772 |
| `src/e1000.c` | 1062 |
| `src/firewall.c` | 932 |
| `src/dns.c` | 835 |
| `src/dhcp.c` | 729 |
| `src/ids.c` | 633 |
| `src/icmp.c` | 466 |

All of it runs at **ring 0**. The entry path is:

```
IRQ11 (src/interrupts.c:552)
  └─ e1000_poll_rx()            src/e1000.c:425
       └─ handle_packet()       src/net.c:1646
            └─ handle_ip() → firewall → IDS → TCP/UDP/ICMP/DNS/DHCP
```

`src/tcp.c:1498` documents the invariant in a comment: *"This function is called
from interrupt context (e1000_poll_rx)."*

### What is already right

Worth stating so nobody "fixes" it:

- **Length checks at every layer boundary.** `handle_packet` validates against
  `sizeof(eth_header_t)` before casting, and again per-EtherType before dispatch.
- **Firewall and IDS run before transport dispatch** (`src/net.c:1542` and `1552`),
  so the deepest parsers sit behind both.
- **DMA coherence is handled correctly** — `lfence` after the DD-bit check and
  before reading the buffer (the TOCTOU between descriptor status and payload),
  `sfence` before the RDT write. Both are load-bearing and well commented.
- **Descriptor length is validated against `RX_BUF_SIZE`**, treating the NIC's
  descriptor as untrusted input. That is the right posture for a bus-mastering
  device.
- **An RX budget already exists** (`E1000_RX_PACKET_BUDGET`, 16), modelled on Linux
  NAPI.

### Finding: the interrupt-context mitigations do not hold

The budget and the mid-loop unlocks are written as if they re-enable interrupts.
**In interrupt context they cannot**, and the code that makes them no-ops is
correct and deliberate — the two halves were simply written against different
assumptions.

`critical_section_exit()` (`src/critical.h`) restores `IF` only when
`__critical_section_depth == 0 && __interrupt_context_depth == 0`, and the comment
explains exactly why the second clause must be there:

> In interrupt context, IF must stay cleared until iret restores it; doing popfl
> here would (a) prematurely re-enable interrupts mid-ISR and (b) write back flags
> captured/clobbered by ISR-context entries, corrupting the preempted thread.

`interrupts.c:552` calls `e1000_poll_rx()` with `__interrupt_context_depth > 0`.
Therefore, for the entire IRQ11 path:

1. **`E1000_UNLOCK()` before `handle_packet()` (`e1000.c:652`) does not re-enable
   interrupts.** The whole parser runs with `IF=0`. The unlock is a depth
   decrement only.
2. **The post-budget "process with interrupts RE-ENABLED" block (`e1000.c:703`)
   does not re-enable interrupts either.** Its comment claims *"Unlock E1000
   driver (releases cli())"* and *"Interrupts are now enabled - timer ticks can
   execute."* Neither is true on this path.
3. **The budget therefore does not bound interrupt-off time.** After 16 packets the
   drain loop at `e1000.c:709` continues to `NUM_RX_DESC`, all with `IF=0`. The
   budget bounds the *first* loop and then the drain finishes the ring anyway, so
   the measured "60x improvement" in the comment does not describe the IRQ path.

The `NUM_RX_DESC` safety limit does bound each invocation, so this is
latency/starvation, not a hang. But the stated micro-packet DoS mitigation is not
in effect where it was intended, and the comments actively assert otherwise —
which is how it survived review.

This is the single strongest argument for item 1, and it revises the original
framing: moving the parser to a thread is not merely defence-in-depth, it is what
makes the *existing* budget mechanism behave as documented.

### Finding: five remotely-floodable `kprintf` sites, not two

CLAUDE.md's rule — *don't add per-operation `kprintf` to a path ring 3 can reach* —
applies with more force here, because these need **no local account at all**. Anyone
on the segment reaches them, and they execute in the ISR with `IF=0`. Serial console
output is slow enough that this is a genuine amplification primitive.

| Site | Trigger | Reachable before firewall? |
|---|---|---|
| `net.c:1652` | frame shorter than an Ethernet header | **yes** |
| `net.c:1687` | unhandled EtherType (anything not ARP/IPv4) | **yes** |
| `e1000.c:630` | NIC checksum/CRC error, primary RX loop | **yes** |
| `e1000.c:735` | NIC checksum/CRC error, drain loop | **yes** |
| `e1000.c:565`, `578` | descriptor length over `RX_BUF_SIZE`, or zero | **yes** |

The first pass found two, then three; the full count is five. The checksum-error
print is duplicated across the primary loop and the drain loop, and the length
validators are per-packet in the same loop. The drain-loop copy is the worst of them:
one line per corrupted frame from an unbounded loop, at a rate the attacker sets
directly by sending frames with bad CRCs.

`e1000.c:452` (RXO) and `e1000.c:771` (micro-packet detection) are also
attacker-triggerable but fire per-interrupt rather than per-packet, so they
rate-limit themselves. Left in place; worth reviewing, not in the same class.

**Resolved** — all five replaced by counters (`net_drop_runt`,
`net_drop_ethertype`, `rx_drop_errors`, `rx_drop_badlen`) surfaced in `ifconfig`.
Harness `verify-rxdrop-counters.sh`, validated both ways.

### DMA buffer placement

From `nm -S kernel.elf`:

```
rx_bufs  0x224260  131072  .bss
tx_bufs  0x244260   16384  .bss
rx_ring  0x248260    1024  .bss
```

Declared at `e1000.c:136-139` as plain `static` arrays with `aligned(16)`. They sit
in `.bss` adjacent to ordinary kernel data, with no guard pages. Without an IOMMU
the NIC can in principle be programmed to write anywhere; what placement buys is
that *descriptor-driven* overruns — the failure mode actually reachable through a
driver bug rather than through full device compromise — land in a guard page instead
of in neighbouring kernel state.

## The four items

Ordered by value per unit of risk. 1–3 are independent of each other; 4 depends on
all three.

### 1. Move packet parsing out of interrupt context — **DONE**

**Why first:** it is the only item that changes the severity of the entire ~8,350-line
surface at once, and it repairs the budget mechanism described above rather than
adding a new one.

**Shape:** the ISR does the minimum — read the descriptor, validate length, copy the
frame into a ring, advance RDT, set a flag. A kernel thread (`knetd`, following the
existing `task_ktimerd` pattern at `kernel.c:967`) drains that ring and calls
`handle_packet()` in thread context, where `E1000_UNLOCK()` genuinely re-enables
interrupts and preemption works.

**Design points that need deciding, not assuming:**

- **Overflow policy must be drop-oldest or drop-newest, chosen explicitly and
  counted.** A silent drop here is indistinguishable from a firewall drop when
  reading a capture later.
- **The copy is not optional.** The parser currently reads `rx_bufs[]` in place; once
  parsing is deferred, the NIC may have recycled that descriptor. Copy into the
  handoff ring before advancing RDT.
- **`kernel.c:557`'s boot-time DHCP loop also calls `e1000_poll_rx()`**, in *thread*
  context, where the unlocks do work as written. That path must keep working before
  the scheduler is running. Simplest answer: keep a synchronous mode for boot and
  switch to the daemon once `knetd` is started — but this is the sharpest edge in
  the item and deserves its own review.
- Interaction with `interrupt_context_exit()` ordering, and with the existing EOI
  timing at `interrupts.c:563`.

**Harness:** must prove parsing happened in thread context, not merely that
networking still works — assert on `__interrupt_context_depth` observed inside
`handle_packet`, or on a preemption that could not occur with `IF=0`. Per
`harness-design-principles`: a test that shows "ping still replies" passes against
the unfixed kernel and proves nothing.

#### How it was resolved

`rx_softirq_ring` in `e1000.c` (a `RX_BUF_SIZE` slot per descriptor), fed by
`rx_softirq_enqueue()` in the top half and drained by `e1000_rx_softirq_run()` from
`task_knetd()` (`test_tasks.c`), mirroring `task_ktimerd` exactly.

- **Overflow policy: drop-newest**, counted as `rx_drop_backlog` and reported on its
  own `RX backlog:` line in `ifconfig` — deliberately separate from the hardware-side
  drops, because "knetd fell behind" is a different diagnosis from "the NIC rejected
  it". Drop-oldest was rejected: it would let an attacker who outruns the consumer
  evict already-accepted legitimate frames, whereas drop-newest degrades to an honest
  "we are full".
- **The frame is copied** into the ring before RDT is advanced, and copied out again
  before the lock is released. A retained pointer into `rx_bufs[]` would be an
  attacker-timed use-after-free in a buffer the attacker refills.
- **The boot-path question** — the sharpest edge, per the note above — was resolved by
  keeping it explicit rather than implicit: the DHCP wait loop in `kernel.c` calls
  `e1000_rx_softirq_run()` directly after `e1000_poll_rx()`, because `knetd` does not
  exist yet at that point. An intermediate `rx_softirq_ran` flag was tried and
  reverted: it would have silently masked a stalled `knetd`.

**Harness: `verify-rx-thread-context.sh`.** `handle_packet()` counts its own calls by
context via `in_interrupt_context()`; `ifconfig` reports `RX parsed: N thread-ctx,
M irq-ctx`. The assertion is two-sided — thread-ctx must rise by the injected count,
and irq-ctx must be 0 at *every* reading — because each half alone passes a broken
build: irq-ctx == 0 is trivially true when no frame ever arrives, and a rising
thread-ctx is trivially true on a kernel that parses in *both* contexts.

The negative control proved that concretely. Restoring the in-ISR call in the primary
loop only, leaving the drain loop deferred, produced `4 thread-ctx, 16 irq-ctx` — 16
being exactly `E1000_RX_PACKET_BUDGET`. A delta-only harness would have passed that
kernel. The 16/4 split is also the tidiest statement of the original bug: the attacker's
arrival rate decided how much of the parser ran with `IF=0`.

Also re-ran `verify-ids-signature.sh`, which at the time needed a DHCP lease and inbound
UDP and so covered the boot-drain path this harness's NAT-less netdev cannot reach. Both
pass.

> **Since superseded (2026-08-22).** `verify-ids-signature.sh` was migrated to the mcast
> netdev when the default-deny firewall stranded its UDP vehicle, and it no longer takes a
> lease. The boot-drain witness is now `verify-firewall-default-deny.sh`, whose arm B
> guards on the lease explicitly. The run recorded above was real; only the citation is
> stale.

### 2. Remove the remotely-floodable `kprintf` sites — **DONE** (reopened for `tcp.c`, closed again)

**Why:** nearly free, no design questions, closes a no-account-required console DoS.

Drop them, or convert to a counter surfaced through `secstatus`/`netstat` — the same
shape as the IDS match count added in PR #63, where a count proved more useful than a
line per event. A counter is strictly better here: it survives the flood and makes the
event *more* visible, not less.

Do **not** convert these to `stream_printf` — this is the ISR, and there is no user
stream to route to.

**Harness:** `verify-rxdrop-counters.sh`. Floods malformed frames and asserts both
halves against the same traffic: the counter delta is **exactly** the frame count, and
the console gains **zero** lines. Both are load-bearing — deleting the prints alone
passes a console check while destroying the information; bumping a counter alone
passes a counter check while leaving the flood.

Two things the run established that are worth keeping:

- The frame count (20) deliberately exceeds `E1000_RX_PACKET_BUDGET` (16), so the
  exact delta also proves the increment is once-per-frame *across* the budget
  boundary and into the drain loop. A ≤16-frame run would not have shown that.
- The negative control had to be run twice. With the print reintroduced, the source
  guard caught it **before boot** — correct behaviour, but it meant the runtime
  console assertion never executed. Re-running with the guard bypassed produced the
  needed result: counter delta a clean 20, console assertion FAIL. A harness
  asserting only the delta would have passed that build, which is the live
  vulnerability.

`ifconfig` is where the counters surface. Note `e1000_get_stats()` had **no callers**
before this — surfacing new counters through it alone would have left them invisible.

#### Reopened, then closed again: `tcp.c` was never swept

This item was marked DONE three times — the RX loops, then `icmp.c`, then
`handle_dns_response`'s 20 sites — and each time the sweep stopped at the file it
had come to fix. `tcp.c` was never swept at all, and it carried **nine**
remote-driven `kprintf` sites the whole time.

The file itself proves the rule was known. `tcp.c:1579` removed the passive-open
branch partly to drop "a per-packet kprintf on the RX path", and cites CLAUDE.md
while doing it. One branch was fixed; the sites on either side of it kept theirs.
So the failure was not ignorance of the rule — it was applying it at the point of
the edit rather than sweeping the file. That is the same shape as the three earlier
rounds, which is why "sweep the protocol files, not just the loops" is now stated
as a rule rather than a description of what was done.

**Two of the nine are materially worse than the rest**, and they set the severity:

    tcp_handle_packet()   "TCP: Invalid data_offset=%d words"
    tcp_handle_packet()   "TCP: data_offset (%d bytes) exceeds segment length"

Both run **before `tcp_find_connection()`**. No connection, no listening port, no
matching 4-tuple, no local account — one malformed 60-byte frame from any host on
the segment produced one console line, at a rate that host chose. The other seven
need an established connection (on-path, or a 4-tuple guess), so they are attacker-
driven but not attacker-*reachable* in the same unauthenticated way.

Three of the nine were self-defeating rather than merely noisy. "RST flood
detected" and "FIN flood detected" printed **once per flooding packet**: the branch
whose entire purpose is to absorb a flood was amplifying it into the console
instead. A rate limiter that logs per rejected packet has not limited anything.

One leaked state: the invalid-sequence site printed `seq`, `rcv_nxt` and `rcv_wnd`
— our receive-window position — to a console the ring-3 shell shares.

**Grouping.** Six counters, not one and not nine. Distinct attack signatures stay
separate (a single "dropped" total hides which attack is underway), but sites an
attacker reaches from the *same position* with the *same* frame share a counter:
both `data_offset` validations are one malformed header, and the RX-full site
printed two lines per packet and now counts once. Grouping is by attacker position,
not by source line.

**Harness:** `verify-tcp-rx-counters.sh`. Three legs: exact delta on the malformed
counter, a **selectivity** leg, and console silence.

The selectivity leg is the one worth keeping. It sends well-formed TCP
(`--tcp-data-offset 5`) matching no connection and asserts it lands on the existing
**no-conn** counter and *not* on malformed. Without it, a counter that simply
incremented on every inbound TCP segment would pass the exact-delta leg perfectly.
The two frame counts are deliberately **different** (20 malformed, 7 control) so a
counter catching both cannot match either expected delta by accident.

The RED run was more informative than the GREEN one, and corrected the harness. With
the two sites reverted to `kprintf`, leg 1 read `malformed +0` while leg 2 read
`no-conn +7` — the frames plainly arrived and parsed. But leg 1's failure hint
blamed delivery ("the frames never reached tcp_handle_packet"), which would have
sent a future reader to debug the network setup instead of the counter. The hint now
reads leg 2 first and distinguishes *nothing arrived* from *arrived but uncounted*.
Leg 3 caught the defect directly and unambiguously: 20 attacker-chosen console lines
from a host with no account.

**Left in place deliberately** (`tcp.c` 800, 815, 1028): once-per-connection state
transitions, bounded by the connection count, not by the packet rate. A file-wide
grep would flag these; the rule is about what a *remote* host drives at a rate of
its choosing, not about the word `kprintf`.

### 3. Constrain DMA by placement — **DONE**

**Why:** contained, driver-local, no cross-subsystem risk.

Move `rx_bufs`/`tx_bufs`/`rx_ring`/`tx_ring` out of `.bss` into a page-aligned region
with unmapped guard pages either side, away from general kernel data.

**Be honest about what this buys:** it does not constrain a fully attacker-controlled
NIC, because nothing short of an IOMMU can. It converts a descriptor-driven overrun
from silent neighbouring-data corruption into a page fault. That is a real
improvement in *diagnosability* and a partial one in containment; the doc and commit
message should not claim more.

#### How it was resolved

`e1000_dma_region_init()` allocates the whole region with `pmm_alloc_contiguous()` at
`e1000_init()` time and hands out pointers; the four objects are no longer link-time
arrays. Layout, 38 pages total:

```
[ guard ][ rx_bufs 128K ][ tx_bufs 16K ][ rx_ring ][ tx_ring ][ guard ]
```

`rx_bufs` sits against the low guard because it is the object the NIC fills from
remote input. Payload pages are mapped `PAE_PAGE_KERNEL_DATA` (NX); the two guards are
`pae_unmap_page`'d. Observed at boot: 148 KB at `0x00357000`, guards `0x00356000` and
`0x0037c000`.

- **Ordering is load-bearing.** `pae_init()` sweeps the identity map and *panics* on
  any not-present page ("would fault in memset later"). Allocating and unmapping after
  that sweep — `pmm_init` (353) → `pae_init` (371) → `net_init` (522) — is what makes
  deliberate holes safe rather than a boot panic. `pae_wx_audit` skips non-present
  pages, so the guards do not register as W^X violations either.
- **`TDLEN`/`RDLEN` were a real trap.** They program the descriptor-ring length *in
  bytes* and read `sizeof(tx_ring)`. Once the rings became pointers that silently
  evaluates to 4 — the NIC would be told its ring is one dword long. The build stayed
  clean and the source still read plausibly. Now computed from the element count, and
  asserted permanently by the harness's source guard.

**Harness: `verify-dma-guard.sh`,** three-sided: placement asserted against the
*linked binary* with `nm` (all four symbols must be ≤8 bytes, i.e. pointers, not
arrays), both guards must report `unmapped` from a live `pae_get_pte()` query at every
reading, and frames must still DMA through the relocated region.

Each half alone is insufficient. The negative control — guards left mapped, region
still allocated, used and correctly DMA'd into — keeps *placement* and *function*
passing and fails only on `MAPPED(!)`. A harness asserting "the buffers moved" would
have passed that build, and the `ifconfig` output looks healthy at a glance either
way, since the guard addresses print regardless and only the mapping state differs.

**What this does not prove:** that touching a guard address actually faults.
`ifconfig` reads the PTE rather than dereferencing, because a shell command that reads
arbitrary kernel addresses is exactly the read primitive PR #58 gated behind root —
adding one to test a hardening feature would be a poor trade. The assertion is one
inference step short of a demonstrated `#PF`, and is labelled as such in the harness.

### 4. Ring-3 network daemon (the reachable ProxyVM analogue)

> **WITHDRAWN 2026-08-17 for the protocols named below.** Scoping the first
> actual move (DNS) found the criterion this item never applied: *does ring 0
> consume a result the parser produces, and act on it?* DNS, DHCP and ARP all
> do, so moving them relocates the parse and hands the trust back across a
> syscall. TCP was already excluded on a hardware constraint. ICMP's inbound
> half is the only remaining candidate. The prerequisite work (items 1–3, and
> PRs #76–#80) is unaffected and still correct. Full reasoning:
> `doc/NETDAEMON_DESIGN.md`, "D1 re-scoped". The rest of this section is kept as
> written, because the reasoning that made it look right is worth preserving.

**Why last:** it is the architecturally correct destination and the largest risk.

Keep e1000 MMIO and DMA in ring 0 — they need physical addresses and port access —
and move the ~5,000 lines of TCP/DNS/DHCP/ICMP parsing to a ring-3 daemon
communicating over a shared buffer plus syscalls.

**This is a multi-PR effort and must not start before 1–3 land.** Item 1 is a
prerequisite in the strong sense: handing packets to a ring-3 process from an ISR
with `IF=0` is not workable.

**CLAUDE.md's rule applies at full force:** *making a path reachable from ring 3
turns latent bugs into corruption primitives* — this recurred in PRs #45, #47, #54
and #55, and every time the newly-exposed code carried serious bugs. Roughly 5,000
lines would change trust domain at once. The audit is not a step in this item; it is
the majority of it.

Design the harness before the code.

**Design written: `doc/NETDAEMON_DESIGN.md`** (design only, no code). Measuring the
actual coupling changed the shape of the item — see that document, but two points
belong here because they correct the sketch above:

- The parser's *entire* kernel-service dependency on the receive path is
  `e1000_send()`. No allocator, no page tables, no scheduler. The packet-path
  boundary is **two syscalls**, and the line count was never the hard part.
- The hard part is the **socket API**: 23 functions across six compiled callers,
  plus the `my_ip`/`my_mac`/`gateway_ip`/`subnet_mask` globals. Moving the parser
  moves `tcp_connections[]` with it, and every kernel-side caller is then reaching
  for state that is no longer in its address space.

## Sequencing

1. ~~**Item 2**~~ — **done**, `verify-rxdrop-counters.sh`.
2. ~~**Item 1**~~ — **done**, `verify-rx-thread-context.sh` (+
   `verify-firewall-default-deny.sh` for the DHCP/boot-drain path — its arm B
   guards on the lease explicitly). The boot-path question was the sharp edge as
   predicted; it is resolved with an explicit drain in `kernel.c`'s DHCP loop.
3. ~~**Item 3**~~ — **done**, `verify-dma-guard.sh`.
4. ~~**Item 4**~~ — **WITHDRAWN**, not next up. Design landed as
   `doc/NETDAEMON_DESIGN.md` and proposed four PRs (audit → packet syscalls →
   socket API → move to ring 3). The first three landed and stay correct; the
   fourth — moving the parser to ring 3 — is **cancelled**. See "D1 re-scoped"
   in `doc/NETDAEMON_DESIGN.md` before reopening this.

   The short version: the plan asked "can this protocol move?" (privileged
   instructions, TX path, stack budget) and never asked **"what does moving
   buy?"** DNS, DHCP and ARP all produce results ring 0 consumes and acts on,
   so moving them relocates the parse and hands the trust straight back through
   a syscall a compromised daemon can call at will. ICMP passes that test and
   still fails a second one: a responder must reply, so it needs `SYS_NETTX`,
   and `e1000_send()` does no source validation — that is unrestricted frame
   forgery (ARP poisoning, DHCP spoofing, TCP injection).

## Corrections to the first-pass assessment

Recorded so the reasoning is auditable:

- Parser size is **~8,350 lines**, not the ~9,500 first estimated.
- There are **five** floodable per-packet `kprintf` sites, not the two first cited.
  The count went 2 → 3 → 5 as the RX loops were read properly: the checksum-error
  print exists twice (primary and drain loop) and the two length validators are also
  per-packet. Anything that says "three" predates the full sweep.
- The RX budget and mid-loop unlocks were initially read as working mitigations.
  They are **inert on the IRQ path** because `critical_section_exit()` will not touch
  `IF` while `__interrupt_context_depth > 0`. This strengthens item 1 considerably and
  was only visible by reading `src/critical.h` rather than the driver's own comments.
  Item 1's negative control later put a number on it: with the in-ISR call restored,
  exactly `E1000_RX_PACKET_BUDGET` (16) frames were parsed with `IF=0` before the
  budget spilled — the budget bounds which *loop* runs, never the interrupt-off time.
- Item 3's `sizeof(tx_ring)` → `4` trap (above) is the sharpest reminder that a clean
  `-Werror` build proves nothing about a value programmed into hardware. It was caught
  by clang-tidy's `bugprone-sizeof-expression`, not by the compiler or by any test.
- Item 1's first harness run was **INCONCLUSIVE from a harness bug, not a kernel one**:
  a whole-file `grep handle_packet src/e1000.c` source guard matched the bottom half,
  where that call is the whole point, and so reported the fix as the bug. The guard is
  now scoped to `e1000_poll_rx()` with a staleness check, so renaming that function
  fails loudly instead of matching nothing and passing.
- Item 4 was framed as "~5,000 lines change trust domain at once", i.e. as a problem
  of scale. Measurement disagrees: the receive-path parser's only kernel dependency
  is `e1000_send()`, so the packet-path boundary is two syscalls. The real weight is
  the **socket API** (23 functions, six callers) and the config globals — none of
  which is parser code. Sizing this item by parser line count mis-estimates both how
  hard it is and *which part* is hard.
- `ssh.c` appears in a naive grep for network consumers but is **not in `SRCS`** —
  it is gitignored and not compiled. Counting it inflates the boundary by ~129 KB of
  source that no longer exists as far as the build is concerned.
- The item-4 sweep also flagged `task_create_user_argv` in `ids.c`, which would have
  been a remotely-reachable parser calling process creation. It is a **false
  positive**: the text is inside the comment explaining why `ids_check_fork_bomb` was
  removed. Grepping for call syntax matches prose that quotes call syntax.
