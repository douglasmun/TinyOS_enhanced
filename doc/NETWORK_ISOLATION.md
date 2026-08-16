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

Also re-ran `verify-ids-signature.sh`, which needs a DHCP lease and inbound UDP and so
covers the boot-drain path this harness's NAT-less netdev cannot reach. Both pass.

### 2. Remove the remotely-floodable `kprintf` sites — **DONE**

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

### 3. Constrain DMA by placement

**Why:** contained, driver-local, no cross-subsystem risk.

Move `rx_bufs`/`tx_bufs`/`rx_ring`/`tx_ring` out of `.bss` into a page-aligned region
with unmapped guard pages either side, away from general kernel data.

**Be honest about what this buys:** it does not constrain a fully attacker-controlled
NIC, because nothing short of an IOMMU can. It converts a descriptor-driven overrun
from silent neighbouring-data corruption into a page fault. That is a real
improvement in *diagnosability* and a partial one in containment; the doc and commit
message should not claim more.

### 4. Ring-3 network daemon (the reachable ProxyVM analogue)

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

## Sequencing

1. ~~**Item 2**~~ — **done**, `verify-rxdrop-counters.sh`.
2. ~~**Item 1**~~ — **done**, `verify-rx-thread-context.sh` (+ `verify-ids-signature.sh`
   for the DHCP/boot-drain path). The boot-path question was the sharp edge as
   predicted; it is resolved with an explicit drain in `kernel.c`'s DHCP loop.
3. **Item 3** — independent of both; can land in any order. **Next up.**
4. **Item 4** — its own roadmap entry, after 1–3, with its harness designed up front.

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
- Item 1's first harness run was **INCONCLUSIVE from a harness bug, not a kernel one**:
  a whole-file `grep handle_packet src/e1000.c` source guard matched the bottom half,
  where that call is the whole point, and so reported the fix as the bug. The guard is
  now scoped to `e1000_poll_rx()` with a staleness check, so renaming that function
  fails loudly instead of matching nothing and passing.
