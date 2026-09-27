#!/usr/bin/env bash
#
# verify-dhcp-config-validation.sh — FULLY AUTOMATED check that the DHCP
# client refuses configuration it must not apply, and NAKs it must not honour.
#
# WHAT THIS IS TESTING (network audit finding 5)
#
#   - An OFFER's address, mask, gateway and DNS server were stored unchecked
#     and applied at ACK time. A mask of 0.0.0.0 makes every destination look
#     on-link (ARPed for directly, where any host on the segment can answer);
#     255.255.255.255 or 127.0.0.1 were accepted as our own address.
#   - The ACK's server-ID check compared against the OFFER's, so an OFFER and
#     ACK that both omitted option 54 matched (0 == 0).
#   - The ACK's yiaddr was applied although only the OFFER's was requested.
#   - A NAK reset the client from ANY state, BOUND included, from any source.
#
# METHOD
#
# tools/dhcp_peer.py is the only DHCP server on a dgram netdev. It answers the
# boot DISCOVER with a scripted sequence (see its header) and logs, in order,
# what it sent and what the guest answered. A REQUEST after an OFFER is the
# witness that the offer was ACCEPTED; a DISCOVER after a NAK is the witness
# that the NAK was HONORED. The bound address comes from the guest's own boot
# banner. Every hostile leg is paired with a positive control:
#
#   8 hostile OFFERs refused         <-> a valid OFFER draws a REQUEST
#   bogus NAKs (wrong / no server-ID) <-> a genuine NAK draws a DISCOVER
#     ignored while REQUESTING
#   ACK for another address ignored  <-> the correct ACK binds 10.0.2.15
#   NAK while BOUND ignored
#
# Then ifconfig's "DHCP config:" counters must match exactly: 8 bad-offer,
# 1 bad-ack, 3 nak-ignored, 1 nak-honored.
#
# The peer resets the guest with a NAK after any ACCEPTED hostile offer, so
# each offer is graded independently even on a broken kernel.
#
# VALIDATION LOG (filled in from actual runs, not written in advance)
#
#   2026-09-28, QEMU 11.1.1 TCG, dgram netdev:
#   - fixed tree, first draft: FAIL, offer 'mask-zero' accepted. The fix read
#     a 0.0.0.0 mask as "option absent" and substituted the classful default;
#     presence is now tracked separately. Re-run: PASS, counters 8/1/3/1.
#   - unfixed main (a46f0cc): FAIL, 12 legs -- all 8 hostile offers drew a
#     REQUEST, the bogus NAKs and the NAK while BOUND each restarted
#     discovery, and the guest bound 10.0.2.99 from the second ACK.
#   - negative control, NAK state gate removed (server-ID check kept): FAIL,
#     exactly the NAK-while-BOUND leg and its two counters.
#   - negative control, ACK yiaddr check disabled: FAIL, exactly the bound
#     address leg (10.0.2.99) and bad-ack = 0.
#
# Exit: 0 PASS, 1 FAIL, 2 no serial, 3 INCONCLUSIVE.

set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=dhcpcfg.log
TRACE=dhcpcfg-trace.log
PEER_LOG=dhcpcfg-peer.log
RUN_DISK=/tmp/tinyos-dhcpcfg-disk.img
MON_SOCK=/tmp/tinyos-dhcpcfg-mon.sock

GUEST_MAC=52:54:00:12:34:56
# dgram, not socket,mcast=: see the header of tools/net_peer.py.
GUEST_EP=127.0.0.1:41265
PEER_EP=127.0.0.1:41266

BAD_OFFERS="mask-zero mask-holes no-server-id yiaddr-bcast yiaddr-loopback yiaddr-subnet-bc router-offlink dns-multicast"

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

command -v python3 >/dev/null 2>&1 || guard_fail "python3 not found"
[ -f tools/dhcp_peer.py ] || guard_fail "tools/dhcp_peer.py missing"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$PEER_LOG" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

# The server first: the DISCOVER goes out long before the shell exists.
python3 tools/dhcp_peer.py --listen $PEER_EP --send $GUEST_EP \
    --guest $GUEST_MAC --duration 400 --out "$PEER_LOG" >/dev/null 2>&1 &
PEER_PID=$!
sleep 1

echo "==> Launching headless QEMU (dgram $GUEST_EP <-> $PEER_EP)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev dgram,id=net0,local.type=inet,local.host=127.0.0.1,local.port=${GUEST_EP##*:},remote.type=inet,remote.host=127.0.0.1,remote.port=${PEER_EP##*:} \
    -device e1000,netdev=net0,mac="$GUEST_MAC" \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() {
    kill "$PEER_PID" 2>/dev/null
    kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"
}
trap cleanup EXIT

# "UDP rx" is on the ifconfig of both trees; "DHCP config" only on the fixed
# one, and waiting for it would stall the unfixed run instead of grading it.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=300 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="UDP rx" \
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
    cat "$PEER_LOG" 2>/dev/null | head -60
    echo "  --- DHCP lines in serial ---"
    grep -aE "Address:|Netmask:|Gateway:|DNS: |DHCP (rx|drops|config):" "$SERIAL" | tr -d '\r' | head -20
    exit 1
}

[ -s "$PEER_LOG" ] || fail_with "the DHCP peer never started"
grep -q "^peer: xid=.* discover" "$PEER_LOG" \
    || fail_with "the peer never saw the guest's DISCOVER; nothing below was measured"
grep -q "^peer: done" "$PEER_LOG" \
    || fail_with "the peer's script did not finish; a positive control failed" \
        "$(grep -E 'refused$|no rediscover|ignored$' "$PEER_LOG" | tail -3)"

FAILS=()

# --- Hostile OFFERs --------------------------------------------------------
for o in $BAD_OFFERS; do
    if grep -q "^peer: offer $o accepted" "$PEER_LOG"; then
        FAILS+=("OFFER '$o' drew a REQUEST: the client accepted it")
    elif ! grep -q "^peer: offer $o refused" "$PEER_LOG"; then
        FAILS+=("OFFER '$o' was never graded")
    fi
done
# Positive control: "done" requires it, but say so explicitly.
grep -q "^peer: valid offer accepted" "$PEER_LOG" \
    || FAILS+=("the valid OFFER was refused (positive control)")

# --- NAKs ------------------------------------------------------------------
grep -q "^peer: bogus nak honored" "$PEER_LOG" \
    && FAILS+=("a NAK from the wrong server / without server-ID restarted discovery")
grep -q "^peer: genuine nak honored" "$PEER_LOG" \
    || FAILS+=("a NAK from the requested server did NOT restart discovery (positive control)")
grep -q "^peer: bound nak honored" "$PEER_LOG" \
    && FAILS+=("a NAK while BOUND threw the lease away")

# --- The address actually bound -------------------------------------------
ADDRS=$(grep -a "    Address:" "$SERIAL" | tr -d '\r' | awk '{print $2}')
echo "  bound address(es): [$(echo $ADDRS)] (expected exactly 10.0.2.15)"
[ "$(echo $ADDRS)" = "10.0.2.15" ] \
    || FAILS+=("bound [$(echo $ADDRS)], not exactly once 10.0.2.15: the ACK for another address was applied")
MASKS=$(grep -a "    Netmask:" "$SERIAL" | tr -d '\r' | awk '{print $2}' | sort -u)
[ "$(echo $MASKS)" = "255.255.255.0" ] \
    || FAILS+=("netmask(s) applied: [$(echo $MASKS)], expected 255.255.255.0")

# --- Counters --------------------------------------------------------------
# DHCP config:  8 bad-offer, 1 bad-ack, 3 nak-ignored, 1 nak-honored
CFG=$(grep -a "DHCP config:" "$SERIAL" | tr -d '\r' | tail -1)
echo "  counters: ${CFG:-<no DHCP config line>}"
count() { printf '%s\n' "$CFG" | sed -n "s/.*[ ,]\([0-9][0-9]*\) $1.*/\1/p"; }
if [ -z "$CFG" ]; then
    FAILS+=("ifconfig has no 'DHCP config:' line")
else
    for pair in bad-offer=8 bad-ack=1 nak-ignored=3 nak-honored=1; do
        k=${pair%=*}; want=${pair#*=}; got=$(count "$k")
        [ "$got" = "$want" ] || FAILS+=("counter $k = ${got:-?}, expected exactly $want")
    done
fi

[ ${#FAILS[@]} -eq 0 ] || fail_with "${#FAILS[@]} leg(s) failed" "${FAILS[@]}"

echo ""
echo "RESULT: PASS"
echo "  8 hostile OFFERs refused, the valid one accepted; bogus NAKs ignored and"
echo "  the genuine one honoured; the ACK for another address ignored and"
echo "  10.0.2.15/24 bound; a NAK while BOUND ignored; counters exact."
exit 0
