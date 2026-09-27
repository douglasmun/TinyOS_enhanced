#!/usr/bin/env bash
#
# verify-icmp-broadcast.sh — FULLY AUTOMATED check that TinyOS is not a smurf
# reflector and does not treat another subnet's x.x.x.255 as its own.
#
# WHAT THIS IS TESTING
#
# handle_ip()'s address gate accepted `dest_ip[3] == 255` -- ANY address ending
# in .255, on any subnet -- as a broadcast for us, and icmp.c answered echo
# requests without looking at the destination at all. So:
#
#   1. An echo request to 255.255.255.255 or our subnet's broadcast was
#      answered: one spoofed request draws a reply aimed at the forged source
#      (smurf amplification; RFC 1122 3.2.2.6 lets a host discard these).
#   2. A frame for 10.9.8.255 -- not our address, not our broadcast -- was
#      processed as ours and answered too.
#
# The fix: the gate accepts only 255.255.255.255 and OUR directed broadcast
# (my_ip | ~mask), keeping the legacy x.x.x.255 acceptance only while
# unconfigured (DHCP); icmp.c counts broadcast echo requests and never answers.
#
# WITNESSES
#
#   Symptom  tools/net_peer.py captures the guest's echo replies. Each probe
#            carries its own ICMP identifier and the reply mirrors it, so the
#            capture says exactly which probes were answered:
#              0xF001  to 10.9.8.255        (foreign .255, unicast MAC)
#              0xB001  to 169.254.255.255   (our directed broadcast)
#              0xB002  to 255.255.255.255   (limited broadcast)
#              0xA001  to the guest's own IP  -- POSITIVE CONTROL
#            Exactly 0xA001 must be answered. A gate that refuses everything
#            fails the positive control.
#   Counters "ICMP rx:" broadcast +2 exactly (B001, B002 -- selectivity: the
#            foreign .255 is dropped at the gate, before icmp.c, and must NOT
#            land here), echo-request +1, rate-limited 0.
#
# The probes are 0.3 s apart, outside the 100 ms reply rate limiter, so an
# unfixed tree answers all four rather than having three rate-limited away.
#
# VALIDATION LOG (filled in from actual runs, not written in advance)
#
#   2026-09-28, QEMU 11.1.1 TCG, dgram netdev:
#   - fixed tree: PASS. Only 0xa001 answered; broadcast +2, echo-request +1,
#     rate-limited +0.
#   - unfixed main (10ce782): FAIL. All four answered (f001 b001 b002 a001).
#   - negative control, ICMP broadcast check disabled (gate fix kept): FAIL,
#     b001 and b002 answered.
#   - negative control, address gate loosened back to any x.x.x.255 (ICMP
#     check kept): FAIL, f001 answered -- so each half is witnessed alone.
#
# Exit: 0 PASS, 1 FAIL, 2 no serial, 3 INCONCLUSIVE.

set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=icmpbcast.log
TRACE=icmpbcast-trace.log
PEER_LOG=icmpbcast-peer.log
RUN_DISK=/tmp/tinyos-icmpbcast-disk.img
MON_SOCK=/tmp/tinyos-icmpbcast-mon.sock

GUEST_MAC=52:54:00:12:34:56
# TEST-NET-3: passes the bogon filter (see verify-icmp-counters.sh).
SRC_IP=203.0.113.99
FOREIGN_BCAST=10.9.8.255
# dgram netdev, not socket,mcast=: on macOS the mcast netdev never puts the
# guest's frames on the wire, so there would be nothing to capture. See the
# header of tools/net_peer.py. GUEST_EP is where the guest receives (injectors
# and the peer's replies go there); PEER_EP is where it sends.
GUEST_EP=127.0.0.1:41245
PEER_EP=127.0.0.1:41246

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

grep -q "net_is_broadcast_ip" src/icmp.c \
    || guard_fail "src/icmp.c does not check for broadcast; tree predates the fix"
command -v python3 >/dev/null 2>&1 || guard_fail "python3 not found"
[ -f tools/net_peer.py ] || guard_fail "tools/net_peer.py missing"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

ISO_MARKERS=$(strings "$ISO" | grep -c "oversize, %u broadcast")
[ "$ISO_MARKERS" -gt 0 ] || guard_fail "the ISO predates the fix (no broadcast field)"

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

# The directed broadcast is computed from the guest's IP and mask as read from
# the serial log -- hardcoding 169.254.255.255 would silently stop testing it
# if the APIPA mask ever changed.
export TINYOS_HOOK_BCAST="
    GUEST_IP=\$(grep -a 'IP Address:' '$SERIAL' | tail -1 \
                | sed -n 's/.*IP Address:  *\([0-9.][0-9.]*\).*/\1/p')
    MASK=\$(grep -a 'Subnet Mask:' '$SERIAL' | tail -1 \
                | sed -n 's/.*Subnet Mask:  *\([0-9.][0-9.]*\).*/\1/p')
    if [ -z \"\$GUEST_IP\" ] || [ -z \"\$MASK\" ]; then
        echo 'BCAST: could not read guest IP/mask from serial log' >&2
    else
        DBCAST=\$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1]+\"/\"+sys.argv[2], strict=False).broadcast_address)' \"\$GUEST_IP\" \"\$MASK\")
        echo \"\$DBCAST\" > '$PEER_LOG.dbcast'
        python3 tools/net_peer.py --listen $PEER_EP --send $GUEST_EP --guest $GUEST_MAC \
            --duration 6 --out '$PEER_LOG' >/dev/null 2>&1 &
        PEER=\$!
        sleep 1
        # No shell function: the typist rejects any brace in a hook.
        INJ=\"python3 tools/inject_frames.py --mcast $GUEST_EP --mode icmp --icmp-type 8 --count 1 --src-ip $SRC_IP\"
        \$INJ --dst $GUEST_MAC --dst-ip $FOREIGN_BCAST --icmp-id 0xF001 >/dev/null 2>&1; sleep 0.3
        \$INJ --dst ff:ff:ff:ff:ff:ff --dst-ip \"\$DBCAST\" --icmp-id 0xB001 >/dev/null 2>&1; sleep 0.3
        \$INJ --dst ff:ff:ff:ff:ff:ff --dst-ip 255.255.255.255 --icmp-id 0xB002 >/dev/null 2>&1; sleep 0.3
        \$INJ --dst $GUEST_MAC --dst-ip \"\$GUEST_IP\" --icmp-id 0xA001 >/dev/null 2>&1
        wait \$PEER
    fi
    true"

TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="ICMP rx" \
TINYOS_FOLLOWUP_CMDS="\
>BCAST;\
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
    echo "  --- peer log ---"
    cat "$PEER_LOG" 2>/dev/null | head -40
    echo "  --- last 30 serial lines ---"
    tail -30 "$SERIAL"
    exit 1
}

[ -s "$PEER_LOG" ] || fail_with "the host-side capture never ran (no $PEER_LOG)"
echo "  directed broadcast probed: $(cat "$PEER_LOG.dbcast" 2>/dev/null)"
rm -f "$PEER_LOG.dbcast"

replied() { grep -c "icmp type=0 id=$1\$" "$PEER_LOG"; }
R_F=$(replied 0xf001); R_B1=$(replied 0xb001); R_B2=$(replied 0xb002); R_A=$(replied 0xa001)
echo "  replies: foreign-.255=$R_F directed-bcast=$R_B1 limited-bcast=$R_B2 unicast=$R_A (expected 0 0 0 1)"

if [ "$R_B1" -ne 0 ] || [ "$R_B2" -ne 0 ]; then
    fail_with "the guest answered an echo request sent to a broadcast address" \
        "directed=$R_B1 limited=$R_B2: a spoofed request to the broadcast draws a" \
        "reply at the forged source -- smurf reflection (finding 4)."
fi
if [ "$R_F" -ne 0 ]; then
    fail_with "the guest answered an echo request for $FOREIGN_BCAST" \
        "Not our address and not our broadcast: the address gate still accepts" \
        "any x.x.x.255 (finding 4)."
fi
if [ "$R_A" -ne 1 ]; then
    fail_with "the unicast positive control was answered $R_A time(s), expected 1" \
        "0 means the gate or icmp.c refuses everything; the exclusions above prove nothing."
fi

extract() { grep -a "ICMP rx:" "$SERIAL" | sed -n "s/.*[ ,]\([0-9][0-9]*\) $1.*/\1/p"; }
BC=$(extract broadcast); REQ=$(extract echo-request); LIM=$(extract rate-limited)
READINGS=$(printf '%s\n' "$BC" | grep -c '[0-9]')
[ "$READINGS" -ge 2 ] || fail_with "expected 2 ICMP rx readings with a broadcast field, got $READINGS"

nth() { printf '%s\n' "$1" | sed -n "${2}p"; }
BC_D=$(( $(nth "$BC" "$READINGS") - $(nth "$BC" 1) ))
REQ_D=$(( $(nth "$REQ" "$READINGS") - $(nth "$REQ" 1) ))
LIM_D=$(( $(nth "$LIM" "$READINGS") - $(nth "$LIM" 1) ))
echo "  broadcast:    delta=$BC_D  (expected 2)"
echo "  echo-request: delta=$REQ_D  (expected 1)"
echo "  rate-limited: delta=$LIM_D  (expected 0)"

[ "$BC_D" -eq 2 ] || fail_with "broadcast counted $BC_D, expected exactly 2" \
    "3 means the foreign .255 reached icmp.c (gate still loose); 0 means the" \
    "broadcasts never arrived."
[ "$REQ_D" -eq 1 ] || fail_with "echo-request counted $REQ_D, expected 1"
[ "$LIM_D" -eq 0 ] || fail_with "rate-limited counted $LIM_D, expected 0"

echo ""
echo "RESULT: PASS"
echo "  Echo requests to both broadcast forms were counted and not answered, one to"
echo "  a foreign .255 was not processed at all, and the unicast control was answered."
exit 0
