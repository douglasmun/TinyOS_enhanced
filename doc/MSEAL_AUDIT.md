# SYS_MSEAL (16) — audit, and what the measurement changed

Audit of the memory-sealing syscall, its page-walk path, and the sixteen
`kprintf` sites that lived on it. Written after the fact, and deliberately
records a hypothesis that **measurement disproved** — because the shape of
`pae_seal_memory_in` invites that hypothesis, and the next reader will form it
again from the same evidence.

## The concern this audit started from — and why it is WRONG

`pae_seal_memory_in()` walks an attacker-chosen page count **twice inside one
`CRITICAL_SECTION`**: a validation pass, then a mutation pass with an `invlpg`
each. `SYS_MSEAL` is ungated and reachable by a raw `int 0x80` from any ring-3
task, and `MAX_SEAL_SIZE` is 64 MB — 16384 pages, so 32768 page walks and
16384 `invlpg`s with interrupts off, at a size the caller chooses.

That reads exactly like an unprivileged interrupt-stall primitive. It is not.

`CRITICAL_SECTION_ENTER()` does `cli` in thread context, so `get_timer_ticks()`
— the 100 Hz IRQ-driven counter in `interrupts.c` — freezes for the duration of
a genuine stall. That makes it a **hardware-grounded witness**, not a software
flag recording what the code believes about itself. Holding *total work*
constant at 16384 pages and varying only how it is split across calls:

| pages/call | reps | tick delta | ms/seal | us/page |
|-----------:|-----:|-----------:|--------:|--------:|
|         16 | 1024 |        230 |    2.25 |  140.38 |
|        256 |   64 |         17 |    2.66 |   10.38 |
|       4096 |    4 |          3 |    7.50 |    1.83 |
|      16384 |    1 |          1 |   10.00 |    0.61 |

The tick delta **falls** as the region grows. That is the opposite of an
interrupt-stall signature: the tick keeps advancing across the work, and
per-call overhead dominates the walk itself. A worst-case single call at the
64 MB cap costs roughly **10 ms under TCG**, which is ~10x slower than native
hardware. Not a meaningful stall, and not worth restructuring the function for.

**Do not re-open this from the function's shape alone.** The two-pass walk
inside one critical section is load-bearing for a different reason, below.

## What the audit found CLEAN

- **Validation is sound.** `addr >= KERNEL_BASE`, `size == 0 || size >
  MAX_SEAL_SIZE`, `end < addr` (overflow), `end > KERNEL_BASE` — in that
  order. The overflow check is **unreachable from ring 3** (`addr <
  0xC0000000` and `size <= 64 MB` bound `addr+size` below `0xC4000000`); it is
  correct defence-in-depth against a future caller that relaxes either bound,
  and `msealprobe.c` deliberately does **not** claim a leg for it — a leg
  aimed at it would land on the size check instead and quietly measure the
  wrong thing.
- **The walk allocates nothing.** `pae_get_pte_in`/`pae_get_pde_in` are
  read-only; a caller cannot drive page-table allocation through this path.
- **Failure cannot leave a partial seal.** The validation pass completes over
  the *whole* region before the mutation pass writes anything, so the
  operation is atomic by construction. This is what the two-pass shape buys,
  and it is the reason not to "simplify" it into one pass.
- **Sealing cannot leak frames.** Teardown ignores `PAE_SEALED` and frees
  unconditionally, so a sealed region is still reclaimed at task exit.
- **Blast radius is self-inflicted.** Sealing targets `cur->page_directory` —
  the caller's own address space. This is *why* `SYS_MSEAL` is ungated, and it
  makes an `-EPERM` for an unprivileged caller the bug rather than the pass.
- **The two `[MSEAL] DENIED` enforcement sites** operate on the kernel PDPT in
  nearly every caller, so they are not a rate-driven flood primitive and were
  left alone.

## The defect that survived: sixteen ring-3-driven `kprintf` sites

Seven in `sys_mseal()`, nine in `pae_seal_memory_in()`. Every one is driven by
a ring-3 caller's **own argument**, on the console the ring-3 shell shares.
This is the class CLAUDE.md closed for the RX path in PR #101 — *count, don't
print* — reached here through a syscall instead of a frame.

Three things made it worse than the average instance:

1. **The cheapest rejection needs nothing.** `size == 0` is rejected in
   `sys_mseal` above any page walk: no memory, no mapped pages, no privilege.
   One instruction sequence, repeatable at syscall rate.
2. **Two sites sat INSIDE the page loop.** `not mapped` and `not
   user-accessible` printed from within the walk, so one call over a large
   unmapped region printed from inside the loop itself.
3. **Nothing could reach it, so nothing caught it.** `SYS_MSEAL` has no libc
   wrapper and no shell builtin. There was no driver in the tree, so the sites
   never fired and no harness ever saw them.

### Grouping

By **caller intent**, the same principle as grouping the TCP counters by
attacker position rather than by source line:

| counter | covers |
|---|---|
| `bounds` | kernel address, range crossing into kernel space, wrap — one signature: *someone testing where the boundary is* |
| `size` | size 0 or over the cap — the cheap, no-memory flood signature |
| `nospace` | no address space to seal in |
| `failed` | `pae_seal_memory_in()` refused |
| `sealed` / `pages` | **successes** |
| `pae args` | alignment / size / wrap / PAE-inactive, inside the PAE layer |
| `pae unmapped` | both per-page rejections — a caller passing a region that is not entirely its own mapped user memory made *one* mistake, not two |

The four unmapped calls increment **both** `pae unmapped` and the syscall's
`failed`: each layer counts its own view (the PAE layer refuses, `sys_mseal`
observes the refusal). That is deliberate rather than double-counting, and the
harness asserts the two agree — a divergence would mean a refusal is invented
at one layer or swallowed at the other, and the surface would be naming a
rejection reason that never happened.

`sealed` and `pages` count successes deliberately. Without them the surface
reports only failures, and **a mechanism that is never successfully used looks
identical to one that is working fine** — the status-surface lie class.

Reported by `secstatus` under *Memory protection*.

## Harness

`verify-mseal-counters.sh`, driven by `/msealprobe.elf` (`userspace/
msealprobe.c`), which goes straight to `int 0x80` because nothing else can
reach the syscall.

- Each counter is driven a **distinct** number of times (3/5/7 bounds,
  11+13 size, 4 unmapped) and asserted as an **exact delta**. A single
  count-everything counter would read 43 on all three and satisfy any "did it
  rise" test.
- The probe runs as an **unprivileged** user. `SYS_MSEAL` is ungated, so this
  is the polarity that matters — the same trap CLAUDE.md records for
  `SYS_ENV`.
- **Leg 5 is a positive control and is not optional.** Every rejection
  assertion above it is satisfied perfectly by a `sys_mseal` that refuses
  every call; only a successful seal of the probe's own page separates
  "correctly rejects bad input" from "rejects everything".
- The silence assertion (`0` `[MSEAL]` lines) is measured **last**, because
  silence is also what a probe that never ran produces — it means something
  only after the deltas have proven the path executed 43 times and sealed
  once.
