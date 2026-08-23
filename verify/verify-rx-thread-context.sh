#!/usr/bin/env bash
#
# verify-rx-thread-context.sh — FULLY AUTOMATED check that inbound packets are
# parsed in TASK context with interrupts enabled, not inside the e1000 ISR.
#
# WHAT THIS IS TESTING
#
# doc/NETWORK_ISOLATION.md item 1. Before the knetd bottom half, the e1000 ISR
# called handle_packet() directly, so the entire ~8,350-line IP/TCP/UDP/DNS/DHCP
# parser ran with IF=0, driven by whatever a host on the segment chose to send.
#
# The driver LOOKED like it bounded this -- E1000_RX_PACKET_BUDGET (16), with a
# comment claiming a "60x improvement" in interrupt latency. It did not:
#
#   * E1000_UNLOCK() -> critical_section_exit() only touches IF when
#     __critical_section_depth == 0 AND __interrupt_context_depth == 0. Inside
#     an ISR the second clause is false, so the unlock is INERT. (That clause is
#     deliberate and correct -- a popfl mid-ISR would corrupt the preempted
#     thread's flags -- so the bug was never the unlock, it was parsing there.)
#   * the post-budget drain loop finishes the ring anyway, so the budget bounds
#     nothing.
#
# The fix is the same top-half/bottom-half split ktimerd already uses: the ISR
# copies the frame into a software ring and returns; task_knetd() drains it and
# runs handle_packet() with interrupts enabled.
#
# WHY "PING STILL REPLIES" PROVES NOTHING HERE
#
# This is the whole reason this harness exists separately from the functional
# network harnesses. Item 1 changes WHERE the parser runs, not WHAT it computes.
# Every functional test -- ping, DHCP, verify-ids-signature.sh -- passes
# identically before and after, because the parser produces the same replies in
# either context. A harness built on "networking still works" would pass a build
# with item 1 entirely reverted. So the assertion has to read the context
# itself.
#
# handle_packet() therefore counts its own calls into two buckets using
# in_interrupt_context() (critical.h), surfaced by ifconfig as:
#
#   RX parsed:    N thread-ctx, M irq-ctx
#
# THE ASSERTION IS TWO-SIDED, AND BOTH HALVES ARE LOAD-BEARING
#
#   POSITIVE  thread-ctx RISES by at least the number of frames injected --
#             the frames really did reach the parser, via knetd
#   NEGATIVE  irq-ctx is 0 at every reading, including the boot-time baseline
#
# Neither half alone is sufficient, and the reason is specific:
#
#   * irq-ctx == 0 alone passes trivially on a build where no frames arrive at
#     all (a broken netdev, a wrong MAC, a guest that never got far enough to
#     receive). Zero of nothing is zero. The POSITIVE half is what proves the
#     path was actually exercised, which is what gives the zero its meaning.
#   * thread-ctx rising alone passes on a build that parses in BOTH contexts --
#     e.g. a partial revert that keeps knetd but restores the in-ISR call, or a
#     new call site added to the ISR later. That is the realistic regression,
#     and only the irq-ctx half catches it.
#
# WHY THE BASELINE READING MATTERS TOO, NOT JUST THE DELTA
#
# The baseline reading is checked too, not just the delta, because boot is the
# most interrupt-dense stretch of a normal run: the DHCP exchange completes
# before the shell exists. Item 1 introduced a genuine hazard there -- knetd is
# not scheduled yet during the boot DHCP wait, so kernel.c drains the ring
# explicitly in that loop. If that drain were ever dropped in favour of "knetd
# will get it", the lease would hang or be parsed from the ISR.
#
# Be honest about what that check earns HERE, though: this harness's netdev has
# no NAT, so the guest never takes a lease (it self-assigns 169.254.x.x) and
# boot generates no inbound traffic to parse. The baseline reads 0 thread-ctx /
# 0 irq-ctx, and the negative control failed on reading #2 rather than #1. So
# the baseline assertion is NOT load-bearing on this netdev -- it is retained
# for the DHCP-carrying case. verify-firewall-default-deny.sh is the harness
# that actually requires a lease -- its arm B boots on the NAT netdev and exits
# INCONCLUSIVE if no lease appears -- and therefore actually exercises the boot
# drain; run it as well when touching this path.
#
# (This used to cite verify-ids-signature.sh. That harness was migrated off the
# NAT netdev on 2026-08-22 when the default-deny firewall stranded its UDP
# vehicle, and it no longer takes a lease at all. Nothing failed when that
# happened -- the boot-drain claim here simply became false, silently, which is
# why the citation now names a harness with an explicit lease GUARD rather than
# one that merely happens to boot with NAT.)
#
# HOW THE FRAMES ARE SENT
#
# Same mechanism as verify-rxdrop-counters.sh: a `socket,mcast=` netdev and
# tools/inject_frames.py, so no special privileges are needed. An unhandled
# EtherType (0x88b5) is deliberately used even though nothing here cares about
# the EtherType: it reaches handle_packet(), which is the function under test,
# and then exits down the cheapest arm without perturbing any protocol state.
# What is being measured is the CONTEXT of the call, not its outcome.
#
# The trade-off, inherited and deliberate: this netdev has no NAT, so the guest
# gets no DHCP lease. That is fine -- the parse counters are bumped at the very
# top of handle_packet(), before any address state is consulted. The boot-drain
# path is separately covered by verify-firewall-default-deny.sh, whose arm B
# requires a lease and guards on it explicitly.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: rxctx.log (serial), rxctx-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=rxctx.log
TRACE=rxctx-trace.log
RUN_DISK=/tmp/tinyos-rxctx-disk.img
MON_SOCK=/tmp/tinyos-rxctx-mon.sock

# Chosen to exceed E1000_RX_PACKET_BUDGET (16) so the run crosses into the
# post-budget drain loop -- the second of the two former in-ISR handle_packet()
# call sites, and the one the budget never bounded.
FRAME_COUNT=${TINYOS_RXCTX_FRAMES:-20}

BAD_ETHERTYPE=0x88b5

# ---------------------------------------------------------------------------
# SOURCE GUARD
#
# Checks the SHAPE of the fix before boot so a stale tree fails fast with a
# reason. Note the lesson from verify-rxdrop-counters.sh run 2: a guard that
# fires can MASK the runtime assertion you are trying to validate. When running
# a negative control against this harness, bypass the guard deliberately.
# ---------------------------------------------------------------------------
guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

grep -q "net_parse_irq" src/net.c \
    || guard_fail "src/net.c has no parse-context counters; tree predates item 1"
grep -q "task_knetd" src/test_tasks.c \
    || guard_fail "src/test_tasks.c has no task_knetd; tree predates item 1"
grep -q "e1000_rx_softirq_run" src/e1000.c \
    || guard_fail "src/e1000.c has no e1000_rx_softirq_run; tree predates item 1"

# The RX path must ENQUEUE, not parse. Scoped to e1000_poll_rx() -- the
# function the ISR drives -- because handle_packet() legitimately appears
# elsewhere in this file: e1000_rx_softirq_run() is the bottom half and calling
# it there is the entire point. A whole-file grep flags that correct call and
# reports the fix as the bug (it did, on the first run of this harness).
#
# Comment lines are stripped first so the explanatory comments in poll_rx --
# which necessarily discuss handle_packet -- do not trip the guard either.
POLL_RX_BODY=$(sed -n '/^void e1000_poll_rx(void)/,/^}/p' src/e1000.c \
               | grep -v '^\s*\*' | grep -v '^\s*/\*' | grep -v '^\s*//')
if [ -z "$POLL_RX_BODY" ]; then
    guard_fail "could not locate e1000_poll_rx() in src/e1000.c; this guard has
  gone stale and would silently stop checking the ISR path"
fi
if printf '%s' "$POLL_RX_BODY" | grep -q "handle_packet"; then
    guard_fail "e1000_poll_rx() calls handle_packet directly; the ISR is parsing again"
fi
if ! printf '%s' "$POLL_RX_BODY" | grep -q "rx_softirq_enqueue"; then
    guard_fail "e1000_poll_rx() does not enqueue to the softirq ring; the top
  half is not feeding knetd"
fi

# knetd must actually be scheduled. A build with the task defined but never
# added would drop every packet into the ring and never drain it.
grep -q "task_knetd" src/kernel.c \
    || guard_fail "src/kernel.c never creates task_knetd, so the ring is never drained"

# The boot-time explicit drain (see the baseline rationale above).
grep -q "e1000_rx_softirq_run" src/kernel.c \
    || guard_fail "src/kernel.c does not drain the ring during the boot DHCP wait"

command -v python3 >/dev/null 2>&1 || guard_fail "python3 not found"
[ -f tools/inject_frames.py ] || guard_fail "tools/inject_frames.py is missing"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# Verify the ARTIFACT, not the source -- the ISO is two copies downstream of
# the edit (harness-design-principles). grep -c not -q: under pipefail, -q
# SIGPIPEs `strings`.
ISO_MARKERS=$(strings "$ISO" | grep -c "irq-ctx")
if [ "$ISO_MARKERS" -eq 0 ]; then
    guard_fail "the ISO predates item 1 (ifconfig has no parse-context line), so
  the run would measure a kernel with no context accounting at all"
fi

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

QEMU_MCAST=230.0.0.2:1235

echo "==> Launching headless QEMU (monitor $MON_SOCK, mcast socket $QEMU_MCAST)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev socket,id=net0,mcast="$QEMU_MCAST" \
    -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# Ends in `true`: the proof the frames landed is the counter delta, not the
# sender's exit status.
export TINYOS_HOOK_BADETH="sleep 2; python3 tools/inject_frames.py \
    --mcast '$QEMU_MCAST' --count $FRAME_COUNT --ethertype $BAD_ETHERTYPE \
    --dst 52:54:00:12:34:56 >/dev/null 2>&1; sleep 5; true"

# ifconfig is a kernel-shell command, so this harness stays in the kernel shell.
#   ifconfig : BASELINE -- irq-ctx must already be 0 after the boot traffic
#   >BADETH  : inject
#   ifconfig : AFTER -- thread-ctx must have risen, irq-ctx must still be 0
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="RX parsed" \
TINYOS_FOLLOWUP_CMDS="\
>BADETH;\
ifconfig=>RX parsed" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"

[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    echo "  --- last 40 serial lines ---"
    tail -40 "$SERIAL"
    exit 1
}

# --- knetd must have started ----------------------------------------------
# Without it the ring is never drained and thread-ctx can only come from the
# boot-time explicit drain, which would make a rising delta misleading.
if ! grep -qa "KNETD" "$SERIAL"; then
    fail_with "task_knetd never announced itself on the console" \
        "The bottom half is not running, so any thread-ctx parsing seen here" \
        "came from the boot drain rather than from the deferral path."
fi

# --- Extract both fields, in order ----------------------------------------
# The ifconfig line reads:
#   RX parsed:    12 thread-ctx, 0 irq-ctx
# Anchored on the field NAMES so adding a counter nearby cannot shift what
# this reads.
THREAD_LIST=$(grep -a "irq-ctx" "$SERIAL" \
              | sed -n 's/.*  *\([0-9][0-9]*\) thread-ctx.*/\1/p')
IRQ_LIST=$(grep -a "irq-ctx" "$SERIAL" \
           | sed -n 's/.*, *\([0-9][0-9]*\) irq-ctx.*/\1/p')
READINGS=$(printf '%s\n' "$IRQ_LIST" | grep -c '[0-9]')

if [ "$READINGS" -lt 2 ]; then
    fail_with "expected 2 ifconfig readings, got $READINGS" \
        "The command sequence did not complete, so there is no baseline." \
        "thread-ctx seen: ${THREAD_LIST:-none}   irq-ctx seen: ${IRQ_LIST:-none}"
fi

TB=$(printf '%s\n' "$THREAD_LIST" | sed -n '1p')
TA=$(printf '%s\n' "$THREAD_LIST" | sed -n '2p')
DELTA=$((TA - TB))
echo "  thread-ctx: before=$TB  after=$TA  delta=$DELTA (injected $FRAME_COUNT)"
echo "  irq-ctx readings: $(printf '%s' "$IRQ_LIST" | tr '\n' ' ')"

# --- NEGATIVE: nothing was EVER parsed in interrupt context ----------------
#
# Checked across EVERY reading, not just the last, so the boot-time DHCP
# traffic is covered as well as the injected frames. This is the half that
# proves item 1 is actually in force; the positive half below only proves the
# parser ran at all.
IDX=0
while IFS= read -r irq; do
    IDX=$((IDX + 1))
    [ -n "$irq" ] || continue
    if [ "$irq" -ne 0 ]; then
        fail_with "reading #$IDX shows $irq frame(s) parsed in INTERRUPT context" \
            "handle_packet() ran inside an ISR, so the ~8,350-line parser" \
            "executed with IF=0 driven by remote input. Item 1 has been undone" \
            "-- most likely a handle_packet() call restored in the e1000 ISR," \
            "or a new call site added to an interrupt path." \
            "Compare the count against E1000_RX_PACKET_BUDGET (16): a count of" \
            "exactly the budget means the PRIMARY loop is parsing in-ISR while" \
            "the post-budget drain still defers, which is what a partial revert" \
            "looks like."
    fi
done <<< "$IRQ_LIST"

# --- POSITIVE: the frames actually reached the parser ----------------------
#
# Without this, irq-ctx == 0 above would pass trivially on a build where no
# packet ever arrived.
if [ "$DELTA" -eq 0 ]; then
    fail_with "the injected frames never reached handle_packet ($TB -> $TA)" \
        "irq-ctx is 0, but that is meaningless if nothing was parsed at all." \
        "Check the socket netdev bridging and the guest MAC before reading" \
        "this as anything about interrupt context."
fi
if [ "$DELTA" -lt "$FRAME_COUNT" ]; then
    fail_with "only $DELTA of $FRAME_COUNT injected frames were parsed" \
        "Frames are being lost between the ISR and knetd. Check the" \
        "'RX backlog' line in the ifconfig output above: a nonzero backlog" \
        "means the softirq ring filled because the bottom half fell behind," \
        "which is a real capacity finding, not a harness flake."
fi

echo "RESULT: PASS"
echo "  $FRAME_COUNT frames parsed in thread context, 0 in interrupt context."
echo "  The parser runs with interrupts enabled, on knetd, as item 1 requires."
exit 0

# =============================================================================
# VALIDATION LOG — validated BOTH WAYS on 2026-08-16
#
# RUN 0 (item 1 present, first attempt) -> INCONCLUSIVE, harness bug
#   "src/e1000.c calls handle_packet directly" -- from a whole-file grep that
#   matched e1000_rx_softirq_run(), i.e. the bottom half, where that call is
#   the entire point of the fix. The guard reported the fix as the bug. It is
#   now scoped to e1000_poll_rx() with comments stripped, plus a staleness
#   check so a renamed function fails loudly instead of matching nothing and
#   silently passing.
#
# RUN 1 (item 1 present) -> PASS
#   thread-ctx: before=0 after=20 delta=20 (injected 20); irq-ctx: 0 0.
#   The delta of 20 clears E1000_RX_PACKET_BUDGET (16), so both former in-ISR
#   call sites -- the primary loop and the post-budget drain -- are confirmed
#   deferred, not just the first.
#
# RUN 2 (negative control: the PRIMARY-loop handle_packet call restored, the
#        drain loop left enqueuing, knetd left running, guard bypassed)
#        -> FAIL, as required:
#   "reading #2 shows 16 frame(s) parsed in INTERRUPT context"
#   with the split reading `RX parsed: 4 thread-ctx, 16 irq-ctx`.
#
#   That 16/4 split is exactly E1000_RX_PACKET_BUDGET and is the clearest
#   statement of the bug this item fixes: the first 16 frames were parsed
#   inside the ISR with IF=0, and only the 4 that spilled past the budget
#   reached knetd. An attacker choosing the arrival rate chooses how much of
#   the ~8,350-line parser runs with interrupts disabled.
#
#   Two things this run establishes about the harness itself. First, the
#   POSITIVE half alone would have PASSED this vulnerable build: thread-ctx
#   still rose (0 -> 4), so a delta-only assertion sees a working path. Only
#   the irq-ctx half caught it -- which is the reason both halves are here.
#   Second, it failed on reading #2, NOT the baseline: this netdev has no NAT,
#   so boot produces no inbound traffic to parse (the guest self-assigns
#   169.254.82.90). The baseline check is therefore not load-bearing on THIS
#   netdev -- it is retained for the DHCP-carrying case, where the boot-time
#   drain in kernel.c is what it covers, and where
#   verify-firewall-default-deny.sh is the harness that actually exercises a
#   lease.
#
# CROSS-CHECK, not covered here: this netdev has no NAT, so the guest never
# takes a DHCP lease and the boot-drain path is exercised only by broadcast
# chatter. verify-firewall-default-deny.sh is the complement -- its arm B boots
# on the NAT netdev, guards on the lease explicitly (INCONCLUSIVE if absent),
# and then requires an inbound DNS reply to be admitted. Run both when touching
# the RX path; neither alone covers it.
# =============================================================================
