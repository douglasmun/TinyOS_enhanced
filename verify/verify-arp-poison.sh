#!/usr/bin/env bash
#
# verify-arp-poison.sh — FULLY AUTOMATED check that a host on the segment
# cannot pre-seed TinyOS's ARP cache for a peer TinyOS has not contacted yet.
#
# WHAT THIS IS TESTING
#
# handle_arp() refused to REPLACE an existing mapping without a pending request,
# and refused to LEARN the gateway without one -- but it learned every OTHER
# local IP passively, from any ARP request (and from the source of any inbound
# IP packet). So an attacker could announce "V is-at ATTACKER" before TinyOS
# ever spoke to V, and the replace-rule then made the forged entry stick
# against V's real replies. V can be the DNS server.
#
# The fix: a NEW mapping is learned only in answer to a request TinyOS sent,
# for every IP; get_route_mac() sends that request on a local miss.
#
# WITNESSES
#
#   Symptom  tools/net_peer.py sits on the segment as V's legitimate owner
#            (answers who-has V with LEGIT_MAC) and captures every frame the
#            guest sends. The echo requests of `ping V` must be addressed to
#            LEGIT_MAC and never to ATTACKER_MAC. This is the property; the
#            counters below only explain it.
#   Counters ifconfig "ARP rx:" -- the attacker's pre-seed is `unsolicited`
#            (+1 exactly), the legitimate answer is `learned` (+1 exactly: the
#            positive control -- a cache that refuses everything cannot answer
#            the ping at all), and a later unsolicited "V is-at ATTACKER" reply
#            against the now-learned entry is `change-refused` (+1 exactly).
#
# The legs are ordered: attacker FIRST, before any contact with V. That is the
# only order in which the old code was exploitable, so it is the order that
# distinguishes the trees.
#
# VALIDATION LOG (filled in from actual runs, not written in advance)
#
#   2026-09-28, QEMU 11.1.1 TCG, dgram netdev:
#   - fixed tree: PASS. 4 echoes -> legit, 0 -> attacker; who-has 1;
#     learned/unsolicited/change-refused each +1.
#   - unfixed main (10ce782): FAIL. All 4 echoes went to the attacker's MAC,
#     the guest never sent who-has (it even ARP-replied to the attacker).
#   - negative control, fix present but the "no pending request" refusal
#     disabled for new entries: FAIL, same symptom (4 -> attacker, who-has 0).
#
# Exit: 0 PASS, 1 FAIL, 2 no serial, 3 INCONCLUSIVE.

set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=arppoison.log
TRACE=arppoison-trace.log
PEER_LOG=arppoison-peer.log
PEER_PID_FILE=/tmp/tinyos-arppoison-peer.pid
RUN_DISK=/tmp/tinyos-arppoison-disk.img
MON_SOCK=/tmp/tinyos-arppoison-mon.sock

GUEST_MAC=52:54:00:12:34:56
ATTACKER_MAC=52:54:00:66:66:66
LEGIT_MAC=52:54:00:11:11:11
# A link-local peer: on the mcast netdev the guest self-assigns 169.254.x.y/16,
# so V is on-link and resolved by ARP directly (no gateway on this netdev).
VICTIM_IP=169.254.77.77
# dgram netdev, not socket,mcast=: on macOS the mcast netdev never puts the
# guest's frames on the wire, so there would be nothing to capture. See the
# header of tools/net_peer.py. GUEST_EP is where the guest receives (injectors
# and the peer's replies go there); PEER_EP is where it sends.
GUEST_EP=127.0.0.1:41235
PEER_EP=127.0.0.1:41236

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

# ---------------------------------------------------------------------------
# SOURCE GUARD
# ---------------------------------------------------------------------------
grep -q "arp_get_rx_stats" src/shell_network.c \
    || guard_fail "ifconfig does not report ARP rx counters; tree predates the fix"
command -v python3 >/dev/null 2>&1 || guard_fail "python3 not found"
[ -f tools/net_peer.py ] || guard_fail "tools/net_peer.py missing"
case "$(python3 tools/inject_frames.py --help 2>&1)" in
    *--arp-op*) ;;
    *) guard_fail "tools/inject_frames.py has no arp mode" ;;
esac

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

ISO_MARKERS=$(strings "$ISO" | grep -c "change-refused")
[ "$ISO_MARKERS" -gt 0 ] || guard_fail "the ISO predates the fix (no ARP rx line)"

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$PEER_LOG" "$MON_SOCK" "$PEER_PID_FILE"
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

cleanup() {
    [ -f "$PEER_PID_FILE" ] && kill "$(cat "$PEER_PID_FILE")" 2>/dev/null
    rm -f "$PEER_PID_FILE"
    kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"
}
trap cleanup EXIT

# PRESEED: start V's legitimate owner (who stays up for the rest of the run),
# then the attacker's ARP request "V is-at ATTACKER", targeted at the guest.
# A request, not a reply: the old code learned passively from requests.
export TINYOS_HOOK_PRESEED="
    GUEST_IP=\$(grep -a 'IP Address:' '$SERIAL' | tail -1 \
                | sed -n 's/.*IP Address:  *\([0-9.][0-9.]*\).*/\1/p')
    if [ -z \"\$GUEST_IP\" ]; then
        echo 'PRESEED: could not read guest IP from serial log' >&2
    elif [ \"\$GUEST_IP\" = '$VICTIM_IP' ]; then
        echo 'PRESEED: guest self-assigned the victim IP; rerun' >&2
    else
        nohup python3 tools/net_peer.py --listen $PEER_EP --send $GUEST_EP \
            --guest $GUEST_MAC --duration 240 --out '$PEER_LOG' \
            --arp-reply '$VICTIM_IP=$LEGIT_MAC' >/dev/null 2>&1 &
        echo \$! > '$PEER_PID_FILE'
        sleep 1
        python3 tools/inject_frames.py --mcast $GUEST_EP --mode arp \
            --arp-op 1 --count 1 --dst ff:ff:ff:ff:ff:ff --src $ATTACKER_MAC \
            --src-ip $VICTIM_IP --dst-ip \"\$GUEST_IP\" >/dev/null 2>&1
    fi
    sleep 2; true"

# OVERWRITE: after V is learned, an unsolicited reply "V is-at ATTACKER".
export TINYOS_HOOK_OVERWRITE="
    GUEST_IP=\$(grep -a 'IP Address:' '$SERIAL' | tail -1 \
                | sed -n 's/.*IP Address:  *\([0-9.][0-9.]*\).*/\1/p')
    python3 tools/inject_frames.py --mcast $GUEST_EP --mode arp \
        --arp-op 2 --count 1 --dst $GUEST_MAC --src $ATTACKER_MAC \
        --src-ip $VICTIM_IP --dst-ip \"\$GUEST_IP\" >/dev/null 2>&1
    sleep 2; true"

#   ifconfig        : BASELINE
#   >PRESEED        : legit peer up; attacker pre-seeds V
#   ping V 2        : first contact with V -- must ARP and reach LEGIT
#   >OVERWRITE      : unsolicited change attempt
#   ping V 2        : must still reach LEGIT
#   ifconfig        : AFTER
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="ARP rx" \
TINYOS_FOLLOWUP_CMDS="\
>PRESEED;\
ping $VICTIM_IP 2=>ping statistics;\
>OVERWRITE;\
ping $VICTIM_IP 2=>ping statistics;\
ifconfig=>ARP rx" \
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

[ -s "$PEER_LOG" ] || fail_with "the host-side peer never started (no $PEER_LOG)" \
    "Check the PRESEED hook: the guest IP must be readable from the serial log."

# --- Symptom first: where did the pings go? ------------------------------
ECHO_LINES=$(grep "icmp type=8" "$PEER_LOG" | grep "dst=$VICTIM_IP ")
TO_ATTACKER=$(printf '%s\n' "$ECHO_LINES" | grep -cE "^(len=[0-9]+ )?dst=$ATTACKER_MAC ")
TO_LEGIT=$(printf '%s\n' "$ECHO_LINES" | grep -cE "^(len=[0-9]+ )?dst=$LEGIT_MAC ")
WHO_HAS=$(grep -c "arp op=1 .*tpa=$VICTIM_IP\$" "$PEER_LOG")

echo "  echo requests to V: $TO_LEGIT -> legit, $TO_ATTACKER -> attacker (expected 4, 0)"
echo "  guest who-has V:    $WHO_HAS (expected >= 1)"

if [ "$TO_ATTACKER" -ne 0 ]; then
    fail_with "$TO_ATTACKER echo request(s) to $VICTIM_IP were sent to the attacker's MAC" \
        "The attacker's unsolicited ARP request was learned before TinyOS ever" \
        "contacted $VICTIM_IP: the cache was pre-seeded (finding 2)."
fi
if [ "$WHO_HAS" -eq 0 ]; then
    fail_with "the guest never ARPed for $VICTIM_IP" \
        "A local miss must send a request, or strict learning can never resolve a peer."
fi
if [ "$TO_LEGIT" -ne 4 ]; then
    fail_with "expected 4 echo requests to the legitimate MAC, saw $TO_LEGIT" \
        "0 means the legitimate answer was not learned (positive control)."
fi

# --- Counters --------------------------------------------------------------
# ARP rx:       0 learned, 1 unsolicited, 0 change-refused
extract() { grep -a "ARP rx:" "$SERIAL" | sed -n "s/.*[ ,]\([0-9][0-9]*\) $1.*/\1/p"; }
LRN=$(extract learned); UNS=$(extract unsolicited); CHG=$(extract change-refused)
READINGS=$(printf '%s\n' "$LRN" | grep -c '[0-9]')
[ "$READINGS" -ge 2 ] || fail_with "expected 2 ARP rx readings, got $READINGS"

nth() { printf '%s\n' "$1" | sed -n "${2}p"; }
LRN_D=$(( $(nth "$LRN" "$READINGS") - $(nth "$LRN" 1) ))
UNS_D=$(( $(nth "$UNS" "$READINGS") - $(nth "$UNS" 1) ))
CHG_D=$(( $(nth "$CHG" "$READINGS") - $(nth "$CHG" 1) ))

echo "  learned:        delta=$LRN_D  (expected 1, the legitimate answer)"
echo "  unsolicited:    delta=$UNS_D  (expected 1, the attacker's pre-seed)"
echo "  change-refused: delta=$CHG_D  (expected 1, the attacker's overwrite)"

[ "$LRN_D" -eq 1 ] || fail_with "learned moved by $LRN_D, expected exactly 1"
[ "$UNS_D" -eq 1 ] || fail_with "unsolicited moved by $UNS_D, expected exactly 1"
[ "$CHG_D" -eq 1 ] || fail_with "change-refused moved by $CHG_D, expected exactly 1"

echo ""
echo "RESULT: PASS"
echo "  An attacker's pre-seed for an uncontacted peer was refused and counted;"
echo "  the peer was resolved on demand to its legitimate MAC, and a later"
echo "  unsolicited overwrite was refused. All 4 pings went to $LEGIT_MAC."
exit 0
