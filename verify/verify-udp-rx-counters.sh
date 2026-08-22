#!/bin/bash
# =============================================================================
# verify-udp-rx-counters.sh -- handle_udp()'s RX counters, driven remotely.
#
# WHAT THIS PROVES
#
# handle_udp() (src/net.c) drops a malformed datagram on one of two attacker
# positions and accepts a well-formed one on a third. Every site is reachable
# by any host on the segment, before the firewall, so all three are counted
# and never printed (doc/NETWORK_ISOLATION.md).
#
#   udp_drop_length   -- ONE counter shared by three length tests, because
#                        they are one forged-length signature: too short for
#                        the IP payload to hold a UDP header, a length field
#                        below the 8-byte header minimum, and a length field
#                        exceeding the IP payload. That last one is the
#                        OOB-read shape (CVE-2018-5391 class) the check exists
#                        for. Grouped by ATTACKER POSITION, not source line.
#   udp_drop_checksum -- a DIFFERENT position: honest length, wrong checksum.
#                        Kept separate so one "dropped" total cannot hide
#                        which malformation is arriving.
#   udp_rx_accepted   -- the POSITIVE CONTROL, and the reason this harness is
#                        not satisfied by a handle_udp() that refuses
#                        everything. A drop-counter-only surface reads exactly
#                        the same whether the parser works or rejects every
#                        datagram on the wire.
#
# THE SELECTIVITY LEG
#
# Exact deltas are asserted per counter, and the two drop counters are given
# DIFFERENT expected values, so a single counter incremented on every inbound
# datagram cannot satisfy both. Without that, a count-everything counter
# passes an exact-delta assertion perfectly (the trap that verify-tcp-rx-
# counters.sh was built to avoid; see doc/NETWORK_ISOLATION.md).
#
# HOW THE FRAMES ARE SENT
#
# A UDP length field that disagrees with the frame is not something the host
# stack will emit -- it fixes the length up. So the guest is attached to a
# `socket,mcast=` netdev rather than user-mode NAT, and tools/inject_frames.py
# writes the bytes verbatim (ordinary UDP multicast socket, no root, TTL
# pinned to 1 so malformed frames cannot leave the host).
#
# That netdev has no NAT, so the guest gets no DHCP lease and self-assigns a
# per-boot link-local 169.254.x.y instead. The frames are therefore addressed
# to {GIP}, captured from the guest's own ifconfig below, NOT to the
# injector's 10.0.2.15 default -- handle_ip's address gate runs before all of
# this and discards anything that is neither our IP nor a broadcast. Do not
# "fix" the missing lease by switching to user-mode NAT; that would silently
# stop the malformed frames from ever arriving and every leg would read
# delta 0.
#
# THE PORTS ARE 68 -> 67, AND THAT IS THE WHOLE TRICK.
#
# handle_udp() is NOT the first thing an inbound datagram meets, despite what
# the counter block in src/net.c says about being "before the firewall". The
# real order inside handle_ip() is: address gate -> firewall_check_packet()
# -> L4 dispatch -> handle_udp(). The firewall's default policy is DENY ALL
# (only outgoing, established and ICMP are allowed, and no shell command can
# add a rule), so an unsolicited inbound datagram to an arbitrary port such
# as 9999 is dropped one layer ABOVE these counters. Every delta then reads
# 0 -- including the positive control -- which looks exactly like a dead
# parser. That is how this harness first failed against correct counters.
#
# firewall_check_packet() has one standing exception that needs no rule: DHCP,
# matched on ports 67<->68 in EITHER direction, returning accept before the
# bogon test and before any rule lookup. So 68 -> 67 is the one unsolicited
# inbound datagram this kernel lets through to handle_udp() by default.
#
# 67 would be wrong in the other direction: handle_udp() dispatches to
# handle_dhcp() on `src_port == 67 && dest_port == 68`, so a 67 -> 68 frame
# would be accepted AND then fed to the DHCP parser, moving the DHCP counters
# and disturbing the lease -- coupling this harness to
# verify-dhcp-rx-counters.sh. 68 -> 67 satisfies the firewall exception and
# fails that dispatch test, so it falls through to no handler at all. src_port
# 68 is also not DNS_PORT (53), so the DNS arm is missed as well.
#
# All four counters increment BEFORE the port dispatch, so routing the frames
# through the DHCP-shaped hole measures the parser exactly as intended.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: udprx.log (serial), udprx-trace.log.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=udprx.log
TRACE=udprx-trace.log
RUN_DISK=/tmp/tinyos-udprx-disk.img
MON_SOCK=/tmp/tinyos-udprx-mon.sock

# Counts are deliberately DISTINCT primes-ish values, one per attacker
# position, so no single miscounted site can satisfy two assertions at once.
N_SHORT=5          # length field below the 8-byte UDP header minimum
N_OOB=7            # length field exceeding the IP payload
N_CSUM=11          # honest length, corrupted checksum
N_OK=13            # fully well-formed -> positive control
EXP_LENGTH=$((N_SHORT + N_OOB))     # 12: both share one counter by design

GUEST_MAC=52:54:00:12:34:56
QEMU_MCAST=230.0.0.1:1234

# ---------------------------------------------------------------------------
# SOURCE GUARD -- fail fast and clearly on a tree that predates the fix.
# ---------------------------------------------------------------------------
guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

grep -q "udp_rx_accepted" src/net.c \
    || guard_fail "src/net.c has no udp_rx_accepted counter; tree predates the fix.
  Without the positive control this harness cannot distinguish a working
  parser from one that refuses every datagram."
grep -q "udp_drop_length" src/net.c \
    || guard_fail "src/net.c has no udp_drop_length counter; tree predates the fix"
grep -q "udp_drop_checksum" src/net.c \
    || guard_fail "src/net.c has no udp_drop_checksum counter; tree predates the fix"
grep -q "UDP rx:" src/shell_network.c \
    || guard_fail "ifconfig does not surface the UDP counters (shell_network.c);
  the counters could be correct and this harness would still read nothing"

command -v python3 >/dev/null 2>&1 || guard_fail "python3 not found"
[ -f tools/inject_frames.py ] || guard_fail "tools/inject_frames.py is missing"
python3 tools/inject_frames.py --help 2>&1 | grep -q "udp-length" \
    || guard_fail "tools/inject_frames.py has no UDP mode (--udp-length);
  it predates the injector work this harness depends on"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# Prove the ISO carries THIS build, not a stale one two copies downstream.
ISO_MARKERS=$(strings "$ISO" | grep -c "bad-checksum")
if [ "$ISO_MARKERS" -eq 0 ]; then
    guard_fail "the ISO predates the fix (ifconfig's UDP line is absent), so
  the run would measure a kernel with no counters at all"
fi

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

echo "==> Launching headless QEMU (monitor $MON_SOCK, mcast socket $QEMU_MCAST)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev socket,id=net0,mcast="$QEMU_MCAST" \
    -device e1000,netdev=net0,mac=$GUEST_MAC \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# Host hook: four bursts, one per attacker position, all in one hook so the
# ifconfig readings bracket the whole set. Ends in `true` -- the proof the
# frames landed is the counter delta, not the sender's exit status.
#
# --dst-ip is {GIP}, captured from the guest's own ifconfig. It is NOT the
# injector's 10.0.2.15 default: that is the NAT lease, and this harness runs
# on a socket/mcast netdev with no DHCP server, so the guest fails discovery
# and self-assigns a per-boot link-local 169.254.x.y. Frames sent to
# 10.0.2.15 are addressed to nobody and handle_ip discards all of them
# BEFORE handle_udp, so every counter -- including the accepted positive
# control -- reads 0. That is indistinguishable from a dead parser, which is
# exactly how this harness first failed against correct counters.
#
# --src-ip is TEST-NET-3 (RFC 5737), and that is load-bearing too. The
# firewall runs BETWEEN handle_ip's address gate and handle_udp, and
# is_bogon_ip() drops any source in 10/8, 172.16/12, 192.168/16 or
# 169.254/16 unconditionally -- only DHCP is excepted. The injector's
# 10.0.2.99 default is RFC1918, so every frame would be dropped by the
# firewall instead, one gate further along than the addressing bug above
# and with the same symptom: all four counters read 0.
INJ="python3 tools/inject_frames.py --mcast '$QEMU_MCAST' --dst $GUEST_MAC \
     --dst-ip {GIP} --src-ip 203.0.113.9 \
     --udp-src-port 68 --udp-dst-port 67"
export TINYOS_HOOK_UDPINJ="sleep 2; \
$INJ --mode udp --udp-length 4    --count $N_SHORT >/dev/null 2>&1; \
$INJ --mode udp --udp-length 5000 --count $N_OOB   >/dev/null 2>&1; \
$INJ --mode udp --udp-corrupt-checksum --count $N_CSUM >/dev/null 2>&1; \
$INJ --mode udp --count $N_OK >/dev/null 2>&1; \
sleep 6; true"

# ifconfig is a kernel-shell command, so this harness stays in the kernel shell.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="UDP rx:" \
TINYOS_FOLLOWUP_CMDS="\
ifconfig=>UDP rx:@GIP=IP Address: +([0-9.]+);\
>UDPINJ;\
ifconfig=>UDP rx:" \
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
    echo "  --- UDP rx lines seen ---"
    grep -a "UDP rx:" "$SERIAL"
    exit 1
}

# --- Extract the three counters, in order ---------------------------------
#
# The ifconfig line reads:
#   UDP rx:       3 accepted, 0 bad-length, 0 bad-checksum
# Each field is anchored on its own NAME, so adding a counter on either side
# does not silently shift what is read. `^[0-9]+` on the second stage, not
# `[0-9]+$` -- the number precedes the name, and an end-anchor would bind
# nothing and report a working kernel as a broken harness.
extract() {
    grep -aoE "[0-9]+ $1" "$SERIAL" | grep -oE "^[0-9]+"
}
OK_LIST=$(extract "accepted")
LEN_LIST=$(extract "bad-length")
CSUM_LIST=$(extract "bad-checksum")

# The LAST TWO readings, not the first two. There are three ifconfig runs in
# this sequence: TINYOS_EXEC_CMD's, the follow-up that carries the @GIP
# capture, and the post-injection one. Taking readings 1 and 2 compares two
# PRE-injection baselines, so every delta is 0 and the harness reports a
# missing length test against a kernel whose counters are perfect. Anchoring
# on the tail keeps this correct however many baseline readings precede the
# hook.
last2() { printf '%s\n' "$1" | grep '[0-9]' | tail -2; }
COUNT_OK=$(printf '%s\n' "$OK_LIST" | grep -c '[0-9]')

if [ "$COUNT_OK" -lt 2 ]; then
    fail_with "expected at least 2 ifconfig readings, got $COUNT_OK" \
        "The command sequence did not complete, so there is no baseline."
fi

OK_B=$(last2 "$OK_LIST" | sed -n 1p);    OK_A=$(last2 "$OK_LIST" | sed -n 2p)
LEN_B=$(last2 "$LEN_LIST" | sed -n 1p);  LEN_A=$(last2 "$LEN_LIST" | sed -n 2p)
CS_B=$(last2 "$CSUM_LIST" | sed -n 1p);  CS_A=$(last2 "$CSUM_LIST" | sed -n 2p)

OK_D=$((OK_A - OK_B)); LEN_D=$((LEN_A - LEN_B)); CS_D=$((CS_A - CS_B))

echo "  accepted     : $OK_B -> $OK_A  (delta $OK_D, expected >= $N_OK)"
echo "  bad-length   : $LEN_B -> $LEN_A  (delta $LEN_D, expected $EXP_LENGTH)"
echo "  bad-checksum : $CS_B -> $CS_A  (delta $CS_D, expected $N_CSUM)"

# --- Leg 1: forged length, exact ------------------------------------------
if [ "$LEN_D" -ne "$EXP_LENGTH" ]; then
    fail_with "bad-length delta $LEN_D != $EXP_LENGTH" \
        "$N_SHORT frames had a length below the 8-byte header minimum and" \
        "$N_OOB claimed more than the IP payload holds. Both are one forged-" \
        "length signature and share one counter by design. An inexact delta" \
        "means a length test is missing or is counting per interrupt rather" \
        "than per datagram -- which under-reports exactly under the burst" \
        "load the counter exists to measure."
fi
echo "PASS leg 1: both forged-length shapes counted, exactly once each."

# --- Leg 2: bad checksum, exact AND a different number --------------------
if [ "$CS_D" -ne "$N_CSUM" ]; then
    fail_with "bad-checksum delta $CS_D != $N_CSUM" \
        "A corrupted checksum is a different attacker position from a forged" \
        "length and must not share a counter with it. Note $N_CSUM and" \
        "$EXP_LENGTH are deliberately different, so a single counter" \
        "incremented on every drop cannot satisfy both legs."
fi
echo "PASS leg 2: checksum failures counted separately and exactly."

# --- Leg 3: POSITIVE CONTROL ----------------------------------------------
#
# >= rather than ==: the guest's own stack may accept unrelated datagrams
# during the window. The point is that a well-formed datagram is ACCEPTED,
# which is what the two drop legs above cannot establish on their own.
if [ "$OK_D" -lt "$N_OK" ]; then
    fail_with "accepted rose by only $OK_D, expected >= $N_OK" \
        "This is the positive control. $N_OK fully well-formed datagrams were" \
        "sent (honest length, checksum computed and verified host-side). If" \
        "they were not accepted, the parser is refusing valid traffic -- and" \
        "the two drop legs above would pass IDENTICALLY against a handle_udp()" \
        "that rejects everything on the wire."
fi
echo "PASS leg 3 (positive control): $OK_D well-formed datagrams accepted."

# --- Leg 4: SELECTIVITY ---------------------------------------------------
#
# The well-formed burst must NOT have landed on a drop counter. Without this,
# a counter that increments on every inbound datagram would satisfy legs 1-3.
TOTAL_DROP=$((LEN_D + CS_D))
EXP_DROP=$((EXP_LENGTH + N_CSUM))
if [ "$TOTAL_DROP" -ne "$EXP_DROP" ]; then
    fail_with "drop counters moved by $TOTAL_DROP total, expected $EXP_DROP" \
        "The $N_OK well-formed datagrams must land on accepted and on no" \
        "drop counter. A counter incrementing on every inbound datagram" \
        "passes an exact-delta assertion perfectly; this leg is what makes" \
        "the drop counters falsifiable."
fi
echo "PASS leg 4 (selectivity): well-formed traffic touched no drop counter."

# --- Leg 5: console silence -----------------------------------------------
#
# The half that proves the remote console-flood path is closed rather than
# just that counters exist. handle_udp is reached from the RX path for any
# host on the segment, so a per-datagram print is the vulnerability itself.
TOTAL_SENT=$((N_SHORT + N_OOB + N_CSUM + N_OK))
for dead in "UDP: Packet received" "UDP: Checksum" "UDP: Invalid length" \
            "Dropping UDP"; do
    HITS=$(grep -ca "$dead" "$SERIAL")
    if [ "$HITS" -ne 0 ]; then
        fail_with "the console printed \"$dead\" $HITS time(s)" \
            "The counters may work, but a per-datagram print is back. That is" \
            "the actual vulnerability: $TOTAL_SENT frames produced $HITS console" \
            "lines from the RX path, and a remote host sets that rate."
    fi
done
echo "PASS leg 5: $TOTAL_SENT injected datagrams produced 0 console lines."

echo ""
echo "RESULT: PASS"
echo "  forged-length +$LEN_D, bad-checksum +$CS_D, accepted +$OK_D, console +0."
echo "  Both malformation signatures are counted separately, well-formed"
echo "  traffic is accepted and counted, and the remote flood path is closed."
exit 0
