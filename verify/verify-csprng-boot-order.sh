#!/usr/bin/env bash
#
# verify-csprng-boot-order.sh — FULLY AUTOMATED check that the network's
# random identifiers are random: the boot DHCP XID and the ICMP ping id.
#
# WHAT THIS IS TESTING
#
# kernel_main() ran crypto_init() -- the only place global_csprng is seeded --
# in PHASE 10, after net_init() (PHASE 8) and the boot DHCP exchange (PHASE 9).
# An unseeded context is a zero key (and zero constants), so its keystream is
# one fixed sequence, identical on every boot: block 0 is all zeros, later
# blocks are constant but nonzero. Measured on main (6c5ea8b):
#
#   icmp_init()     first draw: ping_identifier = 0x0000 on every boot. icmp.c
#                   accepts an echo reply iff its id matches, so the
#                   "1-in-65536 for an off-path attacker" was 1-in-1.
#   generate_xid()  XID 0xd3053b52 on every boot, so an off-path host could
#                   forge the OFFER and ACK (address, gateway, DNS server)
#                   without seeing the DISCOVER.
#
# The fix seeds the CSPRNG before PHASE 8, and csprng_random_bytes() panics on
# an unseeded context so a consumer moved above crypto_init() fails loudly.
#
# METHOD
#
# The guest is booted TWICE on a dgram netdev with tools/net_peer.py already
# listening, so the boot DISCOVERs are captured. In each boot the shell pings
# a link-local peer the tool answers ARP for, capturing the echo id. The
# symptom is a CONSTANT, so the assertion is across boots:
#
#   - each boot: >= 1 DISCOVER and >= 1 echo request captured (positive
#     control: without it "no bad id seen" passes on a dead capture)
#   - no echo id of 0 (the zero block)
#   - boot 1 and boot 2 differ in XID and in echo id (the fixed sequence;
#     this is the leg that catches the XID, which was never 0)
#
# Every failing leg is reported, not just the first. A correct kernel fails
# the echo-id legs by chance with p ~ 2/65536.
#
# VALIDATION LOG (filled in from actual runs, not written in advance)
#
#   2026-09-28, QEMU 11.1.1 TCG, dgram netdev:
#   - fixed tree: PASS, twice. XIDs 0xf99d66ec/0x18180581, ids 0x516d/0x6ba1;
#     then 0x04441e92/0x43999ad9, 0xef62/0x223b.
#   - unfixed main (6c5ea8b): FAIL, 3 legs. Both boots XID 0xd3053b52 and
#     ping id 0x0000 -- the XID was never 0 or 1 as first assumed, so the
#     cross-boot leg is the one that catches it.
#   - negative control, panic guard kept but crypto_init() back in PHASE 10:
#     FAIL, boot 1 panicked "CSPRNG used before crypto_init()".
#
# Exit: 0 PASS, 1 FAIL, 2 no serial, 3 INCONCLUSIVE.

set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
RUN_DISK=/tmp/tinyos-csprngorder-disk.img
MON_SOCK=/tmp/tinyos-csprngorder-mon.sock

GUEST_MAC=52:54:00:12:34:56
PEER_MAC=52:54:00:11:11:11
# On-link for the guest's self-assigned 169.254.x.y/16 (no DHCP server here).
PEER_IP=169.254.77.77
# dgram, not socket,mcast=: on macOS the mcast netdev never puts guest TX on
# the wire. See the header of tools/net_peer.py.
GUEST_EP=127.0.0.1:41255
PEER_EP=127.0.0.1:41256

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

command -v python3 >/dev/null 2>&1 || guard_fail "python3 not found"
grep -q "dhcp xid" tools/net_peer.py 2>/dev/null \
    || guard_fail "tools/net_peer.py cannot decode DHCP XIDs"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }

QEMU_PID=
PEER_PID=
cleanup() {
    [ -n "$PEER_PID" ] && kill "$PEER_PID" 2>/dev/null
    [ -n "$QEMU_PID" ] && { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; }
    PEER_PID=; QEMU_PID=
    rm -f "$MON_SOCK"
}
trap cleanup EXIT

boot() {  # $1 = boot number
    local n=$1
    local serial=csprngorder-$n.log peer_log=csprngorder-peer-$n.log
    rm -f "$RUN_DISK" "$serial" "csprngorder-trace-$n.log" "$peer_log" "$MON_SOCK"
    cp disk.img "$RUN_DISK"

    # The peer first: the DISCOVERs go out before the shell exists.
    python3 tools/net_peer.py --listen $PEER_EP --send $GUEST_EP \
        --guest $GUEST_MAC --duration 400 --out "$peer_log" \
        --arp-reply "$PEER_IP=$PEER_MAC" >/dev/null 2>&1 &
    PEER_PID=$!
    sleep 1

    echo "==> Boot $n (dgram $GUEST_EP <-> $PEER_EP)"
    qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
        -boot d -m 256M \
        -drive file="$RUN_DISK",format=raw,if=ide \
        -netdev dgram,id=net0,local.type=inet,local.host=127.0.0.1,local.port=${GUEST_EP##*:},remote.type=inet,remote.host=127.0.0.1,remote.port=${PEER_EP##*:} \
        -device e1000,netdev=net0,mac="$GUEST_MAC" \
        -serial "file:$serial" \
        -monitor "unix:$MON_SOCK,server,nowait" \
        -no-reboot -d int,cpu_reset -D "csprngorder-trace-$n.log" -display none &
    QEMU_PID=$!

    TINYOS_SERIAL="$serial" \
    TINYOS_MON_SOCK="$MON_SOCK" \
    TINYOS_PASSWORD="$PASSWORD" \
    TINYOS_FOLLOWUP_TIMEOUT=300 \
    TINYOS_EXEC_CMD="ping $PEER_IP 3" \
    TINYOS_EXPECT="ping statistics" \
    python3 tools/qemu_typist.py
    echo "    typist rc=$?"
    sleep 2
    cleanup
}

boot 1
boot 2

echo ""
echo "================ VERDICT ================"

for n in 1 2; do
    [ -s csprngorder-$n.log ] || { echo "RESULT: FAIL — boot $n produced no serial output"; exit 2; }
done

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    for n in 1 2; do
        echo "  --- boot $n peer log (DHCP / ICMP) ---"
        grep -E "dhcp xid|icmp type=8" csprngorder-peer-$n.log 2>/dev/null | head -8
    done
    exit 1
}

for n in 1 2; do
    if grep -aq "CSPRNG used before" csprngorder-$n.log; then
        fail_with "boot $n panicked: a CSPRNG consumer runs before crypto_init()" \
            "$(grep -a 'CSPRNG used before' csprngorder-$n.log | head -1)"
    fi
done

xids() { sed -n 's/.* dhcp xid=\(0x[0-9a-f]*\).*/\1/p' "csprngorder-peer-$1.log" 2>/dev/null | sort -u; }
ids()  { grep "icmp type=8" "csprngorder-peer-$1.log" 2>/dev/null | grep "dst=$PEER_IP " \
         | sed -n 's/.* id=\(0x[0-9a-f]*\).*/\1/p' | sort -u; }

X1=$(xids 1); X2=$(xids 2); I1=$(ids 1); I2=$(ids 2)
echo "  boot 1: dhcp xid(s) [$(echo $X1)]  echo id(s) [$(echo $I1)]"
echo "  boot 2: dhcp xid(s) [$(echo $X2)]  echo id(s) [$(echo $I2)]"

for n in 1 2; do
    x=$(xids $n); i=$(ids $n)
    [ -n "$x" ] || fail_with "no DHCP DISCOVER captured on boot $n" \
        "The capture is dead; the random-id legs would measure nothing."
    [ -n "$i" ] || fail_with "no echo request to $PEER_IP captured on boot $n" \
        "Did the ping resolve $PEER_IP? The peer answers ARP for it."
done

FAILS=()
BAD_I=$(printf '%s\n%s\n' "$I1" "$I2" | grep -cx "0x0000")
[ "$BAD_I" -eq 0 ] || FAILS+=("a ping carried identifier 0x0000 (the unseeded CSPRNG's zero block)")
[ "$X1" != "$X2" ] || FAILS+=("both boots used the same DHCP XID ($(echo $X1)): generate_xid() drew from an unseeded CSPRNG")
[ "$I1" != "$I2" ] || FAILS+=("both boots used the same ping identifier ($(echo $I1)): icmp_init() drew from an unseeded CSPRNG")
[ ${#FAILS[@]} -eq 0 ] || fail_with "${#FAILS[@]} leg(s) failed" "${FAILS[@]}" \
    "A value that repeats across boots is known to an off-path host."

echo ""
echo "RESULT: PASS"
echo "  Both boots drew a non-trivial DHCP XID and ping identifier, and neither"
echo "  value repeated across boots: the CSPRNG was seeded before the network."
exit 0
