#!/usr/bin/env bash
#
# verify-e1000-budget-counter.sh — FULLY AUTOMATED check that an RX burst past
# the per-interrupt packet budget is COUNTED, not printed.
#
# WHAT THIS IS TESTING
#
# e1000_handle_interrupt() drains up to E1000_RX_PACKET_BUDGET (16) frames with
# interrupts off, then the rest with interrupts on. Whenever that second loop
# ran, it printed
#
#     E1000: Micro-packet DoS detected - processed N packets beyond budget
#
# once per interrupt. Any host on the segment picks how often: a burst of >16
# small frames is enough. That is a remote-driven console flood from the RX
# path, the class CLAUDE.md forbids -- and the ICMP oversize harness's own
# 21-frame burst tripped it. It is now two counters on ifconfig's "RX budget:"
# line (interrupts that overran, frames drained past the budget).
#
# LEGS
#
#   TRICKLE  8 frames, 0.2 s apart -- never more than one waiting, so the
#            budget counters must NOT move (selectivity: a counter bumped per
#            interrupt or per frame fails here). unsupported-ethertype +8 proves
#            the frames arrived.
#   BURST    48 frames from one process, back to back. overrun-irqs >= 1,
#            frames-past-budget in [1, 48-16]. unsupported-ethertype +48
#            exactly: frames past the budget are still delivered, not dropped.
#   PRINT    zero "Micro-packet" lines anywhere in the serial log.
#
# The burst's split across interrupts depends on host scheduling, so the
# overrun counters are bounded, not pinned; the delivery count is pinned.
#
# VALIDATION LOG (filled in from actual runs, not written in advance)
#
#   2026-09-28, QEMU 11.1.1 TCG, mcast netdev (inject-only):
#   - fixed tree: PASS. trickle ethertype +8, budget +0/+0; burst ethertype
#     +48, backlog +0, overrun-irqs +1, frames-past-budget +32.
#   - unfixed main (10ce782): FAIL, "Micro-packet DoS detected" printed once.
#   - negative control, counters bumped on every non-overrun interrupt: FAIL
#     at the trickle leg (irqs +8, frames +8).
#
# Exit: 0 PASS, 1 FAIL, 2 no serial, 3 INCONCLUSIVE.

set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=e1000budget.log
TRACE=e1000budget-trace.log
RUN_DISK=/tmp/tinyos-e1000budget-disk.img
MON_SOCK=/tmp/tinyos-e1000budget-mon.sock

GUEST_MAC=52:54:00:12:34:56
QEMU_MCAST=230.0.0.2:1235
TRICKLE=8
BURST=${TINYOS_E1000_BURST:-48}
BUDGET=16

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

grep -q "e1000_get_budget_stats" src/shell_network.c \
    || guard_fail "ifconfig does not report the RX budget counters; tree predates the fix"
command -v python3 >/dev/null 2>&1 || guard_fail "python3 not found"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

ISO_MARKERS=$(strings "$ISO" | grep -c "frames-past-budget")
[ "$ISO_MARKERS" -gt 0 ] || guard_fail "the ISO predates the fix (no RX budget line)"

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

echo "==> Launching headless QEMU (monitor $MON_SOCK, mcast socket $QEMU_MCAST)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev socket,id=net0,mcast="$QEMU_MCAST" \
    -device e1000,netdev=net0,mac="$GUEST_MAC" \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# Unsupported EtherType: dropped at net.c's dispatch, after the e1000 loop has
# already counted the frame, so it exercises the budget without touching any
# protocol handler, firewall or address gate.
INJ="python3 tools/inject_frames.py --mcast '$QEMU_MCAST' --mode ethertype \
     --ethertype 0x88b5 --dst $GUEST_MAC"
export TINYOS_HOOK_TRICKLE="
    i=0; while [ \$i -lt $TRICKLE ]; do
        $INJ --count 1 >/dev/null 2>&1; sleep 0.2; i=\$((i + 1)); done
    sleep 2; true"
export TINYOS_HOOK_BURST="
    $INJ --count $BURST >/dev/null 2>&1
    sleep 3; true"

#   ifconfig  : BASELINE
#   >TRICKLE ; ifconfig : after trickle
#   >BURST   ; ifconfig : after burst
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="RX budget" \
TINYOS_FOLLOWUP_CMDS="\
>TRICKLE;\
ifconfig=>RX budget;\
>BURST;\
ifconfig=>RX budget" \
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
    echo "  --- last 30 serial lines ---"
    tail -30 "$SERIAL"
    exit 1
}

HITS=$(grep -ca "Micro-packet" "$SERIAL")
if [ "$HITS" -ne 0 ]; then
    fail_with "the console printed \"Micro-packet DoS detected\" $HITS time(s)" \
        "A frame burst from a remote host still drives console output (finding 7)."
fi

# RX budget:    0 overrun-irqs, 0 frames-past-budget
# RX dropped:   0 hw-error, 0 bad-length, 0 runt, 0 unsupported-ethertype
field() { grep -a "$1" "$SERIAL" | sed -n "s/.*[ ,]\([0-9][0-9]*\) $2.*/\1/p"; }
IRQ=$(field "RX budget:" overrun-irqs)
FRM=$(field "RX budget:" frames-past-budget)
ETH=$(field "RX dropped:" unsupported-ethertype)
BKL=$(field "RX backlog:" dropped)
READINGS=$(printf '%s\n' "$IRQ" | grep -c '[0-9]')
[ "$READINGS" -eq 3 ] || fail_with "expected 3 ifconfig readings with an RX budget line, got $READINGS"

nth() { printf '%s\n' "$1" | sed -n "${2}p"; }
d() { echo $(( $(nth "$1" "$3") - $(nth "$1" "$2") )); }

T_IRQ=$(d "$IRQ" 1 2); T_FRM=$(d "$FRM" 1 2); T_ETH=$(d "$ETH" 1 2)
B_IRQ=$(d "$IRQ" 2 3); B_FRM=$(d "$FRM" 2 3); B_ETH=$(d "$ETH" 2 3); B_BKL=$(d "$BKL" 2 3)
MAXPAST=$((BURST - BUDGET))

echo "  trickle: ethertype +$T_ETH (expected $TRICKLE), overrun-irqs +$T_IRQ, frames-past-budget +$T_FRM (expected 0, 0)"
echo "  burst:   ethertype +$B_ETH (expected $BURST), backlog +$B_BKL, overrun-irqs +$B_IRQ (>=1), frames-past-budget +$B_FRM (1..$MAXPAST)"

[ "$T_ETH" -eq "$TRICKLE" ] || fail_with "trickle delivered $T_ETH of $TRICKLE frames" \
    "The frames did not reach the guest; the selectivity leg measured nothing."
if [ "$T_IRQ" -ne 0 ] || [ "$T_FRM" -ne 0 ]; then
    fail_with "the budget counters moved on a trickle (irqs +$T_IRQ, frames +$T_FRM)" \
        "Spaced frames never exceed the budget: the counter is not selective."
fi
[ "$B_ETH" -eq "$BURST" ] || fail_with "burst delivered $B_ETH of $BURST frames (backlog drops +$B_BKL)" \
    "Frames past the budget must still be delivered."
[ "$B_IRQ" -ge 1 ] || fail_with "the burst never overran the budget (overrun-irqs +0)" \
    "The burst was spread across interrupts by the host; try TINYOS_E1000_BURST=60." \
    "INCONCLUSIVE in substance: the counter was not exercised."
if [ "$B_FRM" -lt 1 ] || [ "$B_FRM" -gt "$MAXPAST" ]; then
    fail_with "frames-past-budget +$B_FRM is outside 1..$MAXPAST"
fi
if [ "$B_FRM" -lt "$B_IRQ" ]; then
    fail_with "frames-past-budget ($B_FRM) < overrun-irqs ($B_IRQ): every overrun drains >= 1 frame"
fi

echo ""
echo "RESULT: PASS"
echo "  A $BURST-frame burst overran the RX budget in $B_IRQ interrupt(s), $B_FRM frames"
echo "  past it, all delivered, counted with no console output; a trickle moved nothing."
exit 0
