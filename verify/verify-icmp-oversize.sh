#!/usr/bin/env bash
#
# verify-icmp-oversize.sh -- an echo request too large to answer is COUNTED,
# not printed, and does not take the reply slot from one that can be answered.
#
# WHAT THIS IS TESTING
#
# icmp.c mirrors an echo request's payload into a 1514-byte reply buffer and
# refused anything larger with
#
#     kprintf("ICMP: Reply too large (%u bytes), dropping.\n", ...)
#
# QEMU's e1000 (and real ones) accept frames up to 1518 bytes -- VLAN-sized,
# CRC already stripped -- so a 1515-1518 byte echo request from ANY host on the
# segment reached that print. It was the one remote-driven RX print the earlier
# ICMP sweep (verify-icmp-counters.sh) left behind, because it only fires on a
# size nobody's ping produces by default.
#
# The print sat BELOW the rate limiter, so it was bounded to ~10 lines/second.
# The fix counts instead (ifconfig "oversize") and moves the size check ABOVE
# the limiter, so the three echo-request buckets are disjoint:
#
#     answered (echo-request) | rate-limited | oversize
#
# THE FRAME SEQUENCE AND WHY IT IS ONE BURST
#
# One injector process sends, back to back (well inside the 100 ms limiter
# window):
#
#     OVERSIZE_PAIRS x [1518-byte, 1515-byte]   then   one 1514-byte frame
#
# 1518 is the largest frame the NIC accepts; 1515 is the smallest oversize one;
# 1514 is the largest answerable one (the boundary). Expected on a fixed kernel:
#
#     oversize      delta == 2 * OVERSIZE_PAIRS   exactly
#     echo-request  delta == 1   the boundary frame was answered
#     rate-limited  delta == 0
#
# Each leg fails a different wrong fix:
#   - print merely deleted (no counter)            -> oversize absent (guard)
#   - counter left BELOW the limiter               -> oversize 1, rate-limited
#                                                     2*PAIRS, boundary dropped
#   - off-by-one bound (>= 1514) / count-all       -> oversize 2*PAIRS+1,
#                                                     echo-request 0
# The boundary frame is the selectivity leg: without it a counter that counted
# every echo request would pass the exact-delta assertion.
#
# THE REPLY ON THE WIRE (added 2026-09)
#
# echo-request is incremented BEFORE e1000_send(), whose result icmp.c does not
# check, so the counter alone says the boundary request was accepted, not that
# a 1514-byte reply left the NIC. The harness now runs on a dgram netdev with
# tools/net_peer.py capturing the guest's frames, and asserts exactly one echo
# reply, 1514 bytes long, and none of any other size.
#
# VALIDATION LOG (filled in from actual runs, not written in advance)
#
#   POSITIVE, fixed build, 10 pairs
#     oversize 20, echo-request 1, rate-limited 0, 0 prints -> PASS
#
#   UNFIXED main (204be95), source/ISO guards stripped so the run reaches
#   the verdict
#     -> FAIL: 'the console printed "Reply too large" 1 time(s)'.
#     Reachability proven: "ICMP: Reply too large (1518 bytes), dropping."
#     from a remote host with no account. One line for 20 frames -- the old
#     limiter-first ordering throttled it and also ate the boundary frame.
#
#   NEGATIVE 1, counter kept but moved back BELOW the limiter
#     -> FAIL: oversize 1, echo-request 0, rate-limited 20.
#
#   NEGATIVE 2, bound off by one (>= 1514)
#     -> FAIL: oversize 21, echo-request 0 -- the boundary frame is what
#     separates this from a correct kernel; without it both count 20.
#
#   2026-09-28, dgram netdev + capture (QEMU 11.1.1 TCG):
#   - fixed tree: PASS, one 1514-byte echo reply captured.
#   - negative control, the 1514-byte reply's e1000_send() skipped: FAIL on
#     the capture leg alone -- every counter leg still passed, which is the
#     gap the capture closes.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: icmpovr.log (serial), icmpovr-trace.log, icmpovr-peer.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=icmpovr.log
TRACE=icmpovr-trace.log
PEER_LOG=icmpovr-peer.log
RUN_DISK=/tmp/tinyos-icmpovr-disk.img
MON_SOCK=/tmp/tinyos-icmpovr-mon.sock

OVERSIZE_PAIRS=${TINYOS_ICMP_OVERSIZE_PAIRS:-10}
OVERSIZE_FRAMES=$((2 * OVERSIZE_PAIRS))

# inject_frames.py builds 42 bytes of headers (ETH 14 + IP 20 + ICMP 8) around
# the payload, so payload N gives a 42+N byte frame and a reply of the same size.
LENS=""
i=0
while [ "$i" -lt "$OVERSIZE_PAIRS" ]; do LENS="${LENS}1476,1473,"; i=$((i + 1)); done
LENS="${LENS}1472"

GUEST_MAC=52:54:00:12:34:56
# TEST-NET-3: public, so the firewall's bogon filter passes it. See
# verify-icmp-counters.sh for the two versions of that harness that measured
# nothing by getting this and the destination wrong.
SRC_IP=203.0.113.99
# dgram, not socket,mcast=: on macOS the mcast netdev never puts the guest's
# frames on the wire, so the reply could not be captured. See the header of
# tools/net_peer.py.
GUEST_EP=127.0.0.1:41285
PEER_EP=127.0.0.1:41286

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

# ---------------------------------------------------------------------------
# SOURCE GUARD -- the counter exists, ifconfig reports it, the print is gone.
# ---------------------------------------------------------------------------
grep -q "icmp_echo_oversize" src/icmp.c \
    || guard_fail "src/icmp.c has no icmp_echo_oversize counter; tree predates the fix"
grep -q "oversize" src/shell_network.c \
    || guard_fail "ifconfig does not report the oversize counter; tree predates the fix"
if grep -qa "Reply too large" src/icmp.c; then
    guard_fail "src/icmp.c still contains the \"Reply too large\" print"
fi

command -v python3 >/dev/null 2>&1 || guard_fail "python3 not found"
grep -q "len={len(frame)}" tools/net_peer.py 2>/dev/null \
    || guard_fail "tools/net_peer.py does not log frame lengths"
HELP=$(python3 tools/inject_frames.py --help 2>&1)
case "$HELP" in
    *--payload-lens*) ;;
    *) guard_fail "tools/inject_frames.py has no --payload-lens; it predates this harness" ;;
esac

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# The ISO, not just the tree, must carry the fix. grep -c, not -q (pipefail).
ISO_MARKERS=$(strings "$ISO" | grep -c "rate-limited, %u oversize")
[ "$ISO_MARKERS" -gt 0 ] \
    || guard_fail "the ISO predates the fix (ifconfig has no oversize field)"

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$PEER_LOG" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

echo "==> Launching headless QEMU (monitor $MON_SOCK, dgram $GUEST_EP <-> $PEER_EP)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev dgram,id=net0,local.type=inet,local.host=127.0.0.1,local.port=${GUEST_EP##*:},remote.type=inet,remote.host=127.0.0.1,remote.port=${PEER_EP##*:} \
    -device e1000,netdev=net0,mac="$GUEST_MAC" \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# Guest IP is read at runtime: no DHCP on this netdev, so it self-assigns
# 169.254.x.x rather than keeping net.c's compiled-in default.
#
# The leading sleep puts the burst outside any limiter window left open by
# earlier traffic, so the boundary frame's fate depends only on the frames in
# this burst. Ends in `true`: the proof the frames landed is the counter delta.
export TINYOS_HOOK_ICMPBIG="
    GUEST_IP=\$(grep -a 'IP Address:' '$SERIAL' | tail -1 \
                | sed -n 's/.*IP Address:  *\([0-9.][0-9.]*\).*/\1/p')
    if [ -z \"\$GUEST_IP\" ]; then
        echo 'ICMPBIG: could not read guest IP from serial log' >&2
    else
        python3 tools/net_peer.py --listen $PEER_EP --send $GUEST_EP --guest $GUEST_MAC \
            --duration 7 --out '$PEER_LOG' >/dev/null 2>&1 &
        PEER=\$!
        sleep 1
        python3 tools/inject_frames.py \
            --mcast '$GUEST_EP' --mode icmp --icmp-type 8 --count 1 \
            --payload-lens '$LENS' \
            --dst $GUEST_MAC --dst-ip \"\$GUEST_IP\" --src-ip $SRC_IP \
            >/dev/null 2>&1
        wait \$PEER
    fi
    true"

#   ifconfig   : BASELINE
#   >ICMPBIG   : host hook -- the burst
#   ifconfig   : AFTER
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="ICMP rx" \
TINYOS_FOLLOWUP_CMDS="\
>ICMPBIG;\
ifconfig=>ICMP rx" \
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

# --- The print is the vulnerability, so it is checked first ---------------
#
# First so that a kernel with the print but no counter still reaches a verdict
# naming the flood rather than a missing-field error.
HITS=$(grep -ca "Reply too large" "$SERIAL")
if [ "$HITS" -ne 0 ]; then
    fail_with "the console printed \"Reply too large\" $HITS time(s)" \
        "$OVERSIZE_FRAMES oversize echo requests from a remote host produced" \
        "$HITS console lines from the RX path."
fi

# ICMP rx:      0 echo-reply, 0 echo-request, 0 rate-limited, 0 oversize
# Anchored on each field NAME.
extract() { grep -a "ICMP rx:" "$SERIAL" | sed -n "s/.*[ ,]\([0-9][0-9]*\) $1.*/\1/p"; }

REQ_LIST=$(extract "echo-request")
LIM_LIST=$(extract "rate-limited")
OVR_LIST=$(extract "oversize")
READINGS=$(printf '%s\n' "$OVR_LIST" | grep -c '[0-9]')

if [ "$READINGS" -lt 2 ]; then
    fail_with "expected 2 ifconfig readings with an oversize field, got $READINGS" \
        "Readings seen: ${OVR_LIST:-none}"
fi

nth() { printf '%s\n' "$1" | sed -n "${2}p"; }
REQ_D=$(( $(nth "$REQ_LIST" 2) - $(nth "$REQ_LIST" 1) ))
LIM_D=$(( $(nth "$LIM_LIST" 2) - $(nth "$LIM_LIST" 1) ))
OVR_D=$(( $(nth "$OVR_LIST" 2) - $(nth "$OVR_LIST" 1) ))

echo "  oversize:      delta=$OVR_D  (expected $OVERSIZE_FRAMES)"
echo "  echo-request:  delta=$REQ_D  (expected 1, the 1514-byte boundary frame)"
echo "  rate-limited:  delta=$LIM_D  (expected 0)"

if [ "$OVR_D" -eq 0 ] && [ "$REQ_D" -eq 0 ] && [ "$LIM_D" -eq 0 ]; then
    fail_with "the burst moved no ICMP counter" \
        "The frames never reached icmp.c. Check the guest IP captured from the" \
        "serial log and the firewall/bogon gates (see verify-icmp-counters.sh)."
fi
if [ "$OVR_D" -eq 0 ] && [ "$REQ_D" -ge 1 ]; then
    fail_with "the boundary frame arrived but no oversize frame was counted" \
        "The 1515-1518 byte frames were dropped before icmp.c -- by the NIC" \
        "(frame size limit) or an earlier length check -- so the counter under" \
        "test was never exercised."
fi
if [ "$OVR_D" -ne "$OVERSIZE_FRAMES" ]; then
    fail_with "oversize counted $OVR_D, expected exactly $OVERSIZE_FRAMES" \
        "1 with rate-limited ~$OVERSIZE_FRAMES means the size check still" \
        "sits below the limiter; $((OVERSIZE_FRAMES + 1)) means the 1514-byte" \
        "boundary frame was counted too (off-by-one or count-all)."
fi
if [ "$REQ_D" -ne 1 ] || [ "$LIM_D" -ne 0 ]; then
    fail_with "the 1514-byte boundary frame was not answered (echo-request $REQ_D, rate-limited $LIM_D)" \
        "It followed $OVERSIZE_FRAMES oversize frames inside one limiter window." \
        "rate-limited 1 means an unanswerable request consumed the reply slot;" \
        "echo-request 0 with oversize over-counted means the bound is wrong."
fi

# --- The reply itself -------------------------------------------------------
[ -s "$PEER_LOG" ] || fail_with "the host-side capture never ran (no $PEER_LOG)"
REPLY_LENS=$(grep "icmp type=0 " "$PEER_LOG" | sed -n 's/^len=\([0-9]*\) .*/\1/p')
echo "  echo replies captured, by length: [$(echo $REPLY_LENS)] (expected exactly 1514)"
if [ "$(echo $REPLY_LENS)" != "1514" ]; then
    fail_with "the wire carried echo replies [$(echo $REPLY_LENS)], expected exactly one of 1514 bytes" \
        "The counters above passed, so the request was accepted; none means the" \
        "reply never left the NIC, other sizes mean an oversize request was answered."
fi

echo ""
echo "RESULT: PASS"
echo "  $OVERSIZE_FRAMES oversize echo requests were counted exactly with no console"
echo "  output, and the 1514-byte request behind them was answered on the wire."
exit 0
