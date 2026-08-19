#!/usr/bin/env bash
#
# verify-tcp-rx-counters.sh — is malformed inbound TCP COUNTED, not printed?
#
# WHAT THIS IS TESTING
#
# tcp.c was never swept the way icmp.c and dns.c were. Nine remote-driven
# kprintf sites remained in tcp_process_segment() and tcp_handle_packet() --
# and the file itself shows the rule was known: the passive-open branch was
# removed partly to drop "a per-packet kprintf on the RX path", citing
# CLAUDE.md, while the sites around it kept theirs. A partial sweep.
#
# THE SITE THIS HARNESS DRIVES, and why it is the worst of them:
#
#   tcp_handle_packet()  "TCP: Invalid data_offset=%d words"
#   tcp_handle_packet()  "TCP: data_offset (%d bytes) exceeds segment length"
#
# Both run BEFORE tcp_find_connection(). No connection, no listening port, no
# matching 4-tuple, no local account: one malformed 60-byte frame from any host
# on the segment produced one console line, at whatever rate that host chose.
# That is an unauthenticated remote console flood, and the console is shared
# with the ring-3 shell's own output.
#
# The other seven sites are attacker-driven too but need an established
# connection (on-path, or a 4-tuple guess). Two of them were self-defeating in
# a way worth naming: "RST flood detected" and "FIN flood detected" printed
# once per flooding packet, so the branch that exists to ABSORB a flood
# amplified it into the console instead. One more printed seq/rcv_nxt/rcv_wnd
# -- our receive-window state -- to that shared console.
#
# WHAT IS ASSERTED
#
#   1. EXACT delta. The malformed counter must rise by exactly the number of
#      malformed frames sent. Not ">= 1": a per-interrupt rather than
#      per-frame increment, or a counter that also caught the control frames,
#      both pass a >= test and fail this one.
#   2. NEGATIVE CONTROL / selectivity. A well-formed TCP frame (data_offset 5)
#      matching no connection must land on the EXISTING no-conn counter and
#      NOT on the malformed counter. Without this leg, a counter that simply
#      incremented on every inbound TCP segment would pass leg 1 perfectly.
#   3. SILENCE. The console must gain no TCP line while the malformed frames
#      arrive. This is the actual finding -- legs 1 and 2 only establish that
#      the replacement counter is honest.
#
# Leg 3 is checked over the serial region BETWEEN the two ifconfig baselines,
# not over the whole log: the boot sequence legitimately prints TCP lines
# ("TCP: initialized"), and a whole-log grep would either fail always or need
# an exclusion list that quietly grows until it hides the thing under test.
#
# WHY A SOCKET NETDEV. User-mode NAT cannot deliver an arbitrary crafted frame
# to the guest -- the guest's NAT address is not reachable from the host. With
# `socket,mcast=`, bytes written to the group appear on the guest's wire
# verbatim. No root required: an ordinary UDP multicast socket, not AF_PACKET.
#
# The guest IP is read from the RUNNING guest, never assumed: this netdev has
# no DHCP, so the guest self-assigns link-local rather than keeping net.c's
# compiled-in default. Hardcoding it made an earlier harness drop every frame
# at handle_packet's destination check while looking perfectly healthy.
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem.
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=tcprx.log
TRACE=tcprx-trace.log
MON_SOCK=/tmp/tinyos-tcprx-mon.sock
RUN_DISK=/tmp/tinyos-tcprx-disk.img
GUEST_MAC=52:54:00:12:34:56
SRC_IP=10.0.2.99

BAD_COUNT=${TINYOS_TCP_BAD_FRAMES:-20}
CTL_COUNT=${TINYOS_TCP_CTL_FRAMES:-7}   # deliberately != BAD_COUNT, so a
                                        # counter catching both cannot match
                                        # either expected delta by accident.

guard_fail() { echo "HARNESS GUARD FAILED: $*"; exit 2; }

# Guard: the counters must exist. Without this the run below would still
# "pass" every numeric assertion by reading 0 == 0 twice.
grep -q "net_count_tcp_malformed" src/tcp.c \
    || guard_fail "src/tcp.c does not call net_count_tcp_malformed; the site
under test still prints, and every delta below would read 0."
grep -q "TCP rx drops" src/shell_network.c \
    || guard_fail "ifconfig does not surface the TCP rx counters; nothing to parse."

command -v python3 >/dev/null 2>&1 || guard_fail "python3 not found"
python3 tools/inject_frames.py --help 2>&1 | grep -q "tcp-data-offset" \
    || guard_fail "tools/inject_frames.py has no --tcp-data-offset; cannot craft
a malformed TCP header."

echo "==> Building kernel + ISO..."
make >/dev/null || { echo "build failed"; exit 2; }
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || { echo "mkrescue failed"; exit 2; }

rm -f "$SERIAL" "$TRACE" "$MON_SOCK" "$RUN_DISK"
[ -f disk.img ] && cp disk.img "$RUN_DISK"

QEMU_MCAST=230.0.0.3:1236

echo "==> Launching headless QEMU (monitor $MON_SOCK, mcast socket $QEMU_MCAST)"
QEMU_DISK=""
[ -f "$RUN_DISK" ] && QEMU_DISK="-drive file=$RUN_DISK,format=raw,if=ide"
# shellcheck disable=SC2086
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M $QEMU_DISK \
    -netdev socket,id=net0,mcast="$QEMU_MCAST" \
    -device e1000,netdev=net0,mac="$GUEST_MAC" \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() {
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "${QEMU_PID:-}" ] && wait "$QEMU_PID" 2>/dev/null
    rm -f "$MON_SOCK" "$RUN_DISK"
    return 0
}
trap cleanup EXIT

# Ends in `true` for the same reason the icmp harness does: the proof the
# frames landed is the counter delta, not the sender's exit status.
export TINYOS_HOOK_TCPFLOOD="
    GUEST_IP=\$(grep -a 'IP Address:' '$SERIAL' | tail -1 \
                | sed -n 's/.*IP Address:  *\([0-9.][0-9.]*\).*/\1/p')
    if [ -z \"\$GUEST_IP\" ]; then
        echo 'TCPFLOOD: could not read guest IP from serial log' >&2
    else
        # data_offset 0: below the 5-word minimum -> validation 1.
        python3 tools/inject_frames.py \
            --mcast '$QEMU_MCAST' --mode tcp --tcp-data-offset 0 \
            --count $BAD_COUNT \
            --dst $GUEST_MAC --dst-ip \"\$GUEST_IP\" --src-ip $SRC_IP \
            >/dev/null 2>&1
        # data_offset 5: LEGAL. Must land on no-conn, never on malformed.
        python3 tools/inject_frames.py \
            --mcast '$QEMU_MCAST' --mode tcp --tcp-data-offset 5 \
            --count $CTL_COUNT \
            --dst $GUEST_MAC --dst-ip \"\$GUEST_IP\" --src-ip $SRC_IP \
            >/dev/null 2>&1
    fi
    sleep 5; true"

# ifconfig is a kernel-shell command and is where the counters surface.
#   ifconfig   : BASELINE
#   >TCPFLOOD  : host hook -- injects malformed then well-formed frames
#   ifconfig   : AFTER
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="TCP rx drops" \
TINYOS_FOLLOWUP_CMDS="\
>TCPFLOOD;\
ifconfig=>TCP rx drops" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: harness problem — no serial output (typist rc=$TYPIST_RC)"
    exit 2
fi
if grep -q "Triple fault" "$TRACE" 2>/dev/null; then
    grep -E "check_exception|v=0e|v=08|Triple fault|^EIP=|CR2=" "$TRACE" | tail -15
    echo "RESULT: harness problem — triple fault during the run"
    exit 2
fi

CLEAN=$(mktemp); tr -d '\r' < "$SERIAL" > "$CLEAN"

# Two "TCP rx drops:" readings, in order. Portable read loop, not mapfile:
# macOS ships bash 3.2 and under `set -u` an unset array kills the verdict
# before it prints, making a PASSING kernel look like a broken harness.
MAL=""; NOCONN=""
while read -r n; do MAL="$MAL $n"; done < <(
    grep -oE "TCP rx drops: +[0-9]+ malformed" "$CLEAN" | grep -oE "[0-9]+")
while read -r n; do NOCONN="$NOCONN $n"; done < <(
    grep -oE "TCP no-conn: +[0-9]+ segments" "$CLEAN" | grep -oE "[0-9]+")

set -- $MAL; MAL_N=$#; MAL_B="${1:-}"; eval MAL_A=\"\${$MAL_N:-}\"
set -- $NOCONN; NC_N=$#; NC_B="${1:-}"; eval NC_A=\"\${$NC_N:-}\"

if [ "$MAL_N" -lt 2 ] || [ "$NC_N" -lt 2 ]; then
    echo "RESULT: harness problem — need two readings of each counter"
    echo "  got $MAL_N malformed, $NC_N no-conn"
    grep -v Suspicious "$CLEAN" | tail -25
    rm -f "$CLEAN"; exit 2
fi

MAL_D=$(( MAL_A - MAL_B ))
NC_D=$(( NC_A - NC_B ))

echo "  malformed : $MAL_B -> $MAL_A  (delta $MAL_D, expected $BAD_COUNT)"
echo "  no-conn   : $NC_B -> $NC_A  (delta $NC_D, expected $CTL_COUNT)"
echo ""

FAIL=0

# Leg 1: exact delta.
if [ "$MAL_D" -ne "$BAD_COUNT" ]; then
    echo "FAIL leg 1: malformed delta $MAL_D != $BAD_COUNT sent."
    if [ "$MAL_D" -eq 0 ]; then
        # Read leg 2 BEFORE blaming the network. If no-conn rose, the frames
        # arrived and were parsed, so a zero here means the malformed branch
        # is not counting -- not that delivery failed. The RED run of this
        # harness looked exactly like that: no-conn +7, malformed +0, and the
        # 20 malformed frames sitting in the console log under leg 3.
        if [ "$NC_D" -gt 0 ]; then
            echo "  Zero, but no-conn rose by $NC_D: the frames DID arrive and parse."
            echo "  The malformed branch is not counting them (still printing?)."
        else
            echo "  Zero, and no-conn did not move either: nothing arrived. Check the"
            echo "  guest IP was discovered (this netdev has no DHCP) and the group."
        fi
    fi
    FAIL=1
else
    echo "PASS leg 1: every malformed frame counted, exactly once."
fi

# Leg 2: selectivity. A counter incrementing on all inbound TCP passes leg 1
# only if BAD_COUNT happens to equal the total -- which is why CTL_COUNT
# differs from BAD_COUNT.
if [ "$NC_D" -ne "$CTL_COUNT" ]; then
    echo "FAIL leg 2: no-conn delta $NC_D != $CTL_COUNT well-formed frames sent."
    echo "  The legal frames were not classified as 'no connection'."
    FAIL=1
elif [ "$MAL_D" -ne "$BAD_COUNT" ]; then
    : # already reported by leg 1
else
    echo "PASS leg 2: legal frames landed on no-conn, not on malformed."
fi

# Leg 3: the actual finding. Look only BETWEEN the two ifconfig baselines.
FIRST=$(grep -n "TCP rx drops" "$CLEAN" | head -1 | cut -d: -f1)
LAST=$(grep -n "TCP rx drops" "$CLEAN" | tail -1 | cut -d: -f1)
if [ -n "$FIRST" ] && [ -n "$LAST" ] && [ "$LAST" -gt "$FIRST" ]; then
    NOISE=$(sed -n "$((FIRST+1)),$((LAST-1))p" "$CLEAN" \
            | grep -E "^\[?TCP\]?:? " \
            | grep -vE "TCP rx|TCP no-conn|TCP Connection Table" || true)
    if [ -n "$NOISE" ]; then
        echo "FAIL leg 3: console gained TCP lines while malformed frames arrived:"
        echo "$NOISE" | head -10
        echo "  A remote host with no account chose how often those printed."
        FAIL=1
    else
        echo "PASS leg 3: console stayed silent across $((BAD_COUNT + CTL_COUNT)) injected frames."
    fi
else
    echo "FAIL leg 3: could not locate the two ifconfig readings to bracket."
    FAIL=1
fi

rm -f "$CLEAN"
echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: PASS — malformed TCP is counted exactly, classified selectively,"
    echo "        and prints nothing to a console the ring-3 shell shares."
    exit 0
fi
echo "RESULT: FAIL — see the legs above.  Serial: $SERIAL"
exit 1
