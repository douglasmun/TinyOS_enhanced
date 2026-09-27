#!/usr/bin/env bash
#
# verify-icmp-checksum.sh — FULLY AUTOMATED check that icmp.c verifies the
# ICMP checksum before acting on a message.
#
# WHAT THIS IS TESTING (network audit finding 6)
#
# handle_icmp_with_context() dispatched on type without ever verifying the
# checksum, so a corrupted echo request was answered and a corrupted echo
# reply counted as a ping response. The fix verifies the RFC 792 checksum over
# the whole message before any dispatch and counts failures ("bad-checksum").
#
# WITNESSES
#
#   Symptom  tools/net_peer.py captures the guest's echo replies; each probe
#            carries its own identifier, which the reply mirrors:
#              0xC001  bad checksum, even length (46-byte payload)
#              0xC002  bad checksum, odd length  (47-byte payload)
#              0xA001  good checksum, even length -- POSITIVE CONTROL
#              0xA002  good checksum, odd length  -- POSITIVE CONTROL for the
#                      odd-byte path: a verifier that sums the trailing byte
#                      wrongly refuses every odd-length ping, which the even
#                      control alone would never show.
#            Exactly 0xA001 and 0xA002 must be answered.
#   Counters "ICMP rx:" bad-checksum +2 exactly, echo-request +2, rate-limited
#            0 (selectivity: the corrupted probes must land on bad-checksum,
#            not be dropped somewhere that counts nothing).
#
# The IP header of every probe is valid, so nothing before icmp.c drops them.
# Probes are 0.3 s apart, outside the 100 ms reply rate limiter.
#
# VALIDATION LOG (filled in from actual runs, not written in advance)
#
#   2026-09-28, QEMU 11.1.1 TCG, dgram netdev:
#   - fixed tree: PASS. Only 0xa001/0xa002 answered; bad-checksum +2,
#     echo-request +2, rate-limited +0.
#   - checksum check disabled (the unfixed behaviour): FAIL, 4 legs -- all
#     four probes answered, bad-checksum +0, echo-request +4.
#   - negative control, odd trailing byte summed into the high half: FAIL on
#     exactly the odd-length positive control (0xa002 unanswered, counted as
#     bad-checksum), so that control has teeth.
#
# Exit: 0 PASS, 1 FAIL, 2 no serial, 3 INCONCLUSIVE.

set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=icmpcsum.log
TRACE=icmpcsum-trace.log
PEER_LOG=icmpcsum-peer.log
RUN_DISK=/tmp/tinyos-icmpcsum-disk.img
MON_SOCK=/tmp/tinyos-icmpcsum-mon.sock

GUEST_MAC=52:54:00:12:34:56
# TEST-NET-3: passes the bogon filter (see verify-icmp-counters.sh).
SRC_IP=203.0.113.99
# dgram, not socket,mcast=: see the header of tools/net_peer.py.
GUEST_EP=127.0.0.1:41275
PEER_EP=127.0.0.1:41276

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

command -v python3 >/dev/null 2>&1 || guard_fail "python3 not found"
[ -f tools/net_peer.py ] || guard_fail "tools/net_peer.py missing"
grep -q -- "--icmp-bad-checksum" tools/inject_frames.py \
    || guard_fail "tools/inject_frames.py cannot corrupt an ICMP checksum"

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

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

export TINYOS_HOOK_CSUM="
    GUEST_IP=\$(grep -a 'IP Address:' '$SERIAL' | tail -1 \
                | sed -n 's/.*IP Address:  *\([0-9.][0-9.]*\).*/\1/p')
    if [ -z \"\$GUEST_IP\" ]; then
        echo 'CSUM: could not read guest IP from serial log' >&2
    else
        python3 tools/net_peer.py --listen $PEER_EP --send $GUEST_EP --guest $GUEST_MAC \
            --duration 6 --out '$PEER_LOG' >/dev/null 2>&1 &
        PEER=\$!
        sleep 1
        # No shell function: the typist rejects any brace in a hook.
        INJ=\"python3 tools/inject_frames.py --mcast $GUEST_EP --mode icmp --icmp-type 8 --count 1 --src-ip $SRC_IP --dst $GUEST_MAC --dst-ip \$GUEST_IP\"
        \$INJ --icmp-id 0xC001 --payload-len 46 --icmp-bad-checksum >/dev/null 2>&1; sleep 0.3
        \$INJ --icmp-id 0xC002 --payload-len 47 --icmp-bad-checksum >/dev/null 2>&1; sleep 0.3
        \$INJ --icmp-id 0xA001 --payload-len 46 >/dev/null 2>&1; sleep 0.3
        \$INJ --icmp-id 0xA002 --payload-len 47 >/dev/null 2>&1
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
>CSUM;\
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
    echo "  --- ICMP rx lines ---"
    grep -a "ICMP rx:" "$SERIAL" | tr -d '\r'
    exit 1
}

[ -s "$PEER_LOG" ] || fail_with "the host-side capture never ran (no $PEER_LOG)"

replied() { grep -c "icmp type=0 id=$1\$" "$PEER_LOG"; }
R_C1=$(replied 0xc001); R_C2=$(replied 0xc002); R_A1=$(replied 0xa001); R_A2=$(replied 0xa002)
echo "  replies: bad-even=$R_C1 bad-odd=$R_C2 good-even=$R_A1 good-odd=$R_A2 (expected 0 0 1 1)"

FAILS=()
[ "$R_C1" -eq 0 ] || FAILS+=("an even-length echo request with a bad checksum was answered")
[ "$R_C2" -eq 0 ] || FAILS+=("an odd-length echo request with a bad checksum was answered")
[ "$R_A1" -eq 1 ] || FAILS+=("the even-length good request was answered $R_A1 time(s), expected 1 (positive control)")
[ "$R_A2" -eq 1 ] || FAILS+=("the odd-length good request was answered $R_A2 time(s), expected 1 (positive control: odd-byte summing)")

extract() { grep -a "ICMP rx:" "$SERIAL" | tr -d '\r' | sed -n "s/.*[ ,]\([0-9][0-9]*\) $1.*/\1/p"; }
BAD=$(extract bad-checksum); REQ=$(extract echo-request); LIM=$(extract rate-limited)
READINGS=$(printf '%s\n' "$BAD" | grep -c '[0-9]')
if [ "$READINGS" -lt 2 ]; then
    FAILS+=("expected 2 ICMP rx readings with a bad-checksum field, got $READINGS")
else
    nth() { printf '%s\n' "$1" | sed -n "${2}p"; }
    BAD_D=$(( $(nth "$BAD" "$READINGS") - $(nth "$BAD" 1) ))
    REQ_D=$(( $(nth "$REQ" "$READINGS") - $(nth "$REQ" 1) ))
    LIM_D=$(( $(nth "$LIM" "$READINGS") - $(nth "$LIM" 1) ))
    echo "  bad-checksum: delta=$BAD_D  (expected 2)"
    echo "  echo-request: delta=$REQ_D  (expected 2)"
    echo "  rate-limited: delta=$LIM_D  (expected 0)"
    [ "$BAD_D" -eq 2 ] || FAILS+=("bad-checksum counted $BAD_D, expected exactly 2")
    [ "$REQ_D" -eq 2 ] || FAILS+=("echo-request counted $REQ_D, expected exactly 2")
    [ "$LIM_D" -eq 0 ] || FAILS+=("rate-limited counted $LIM_D, expected 0")
fi

[ ${#FAILS[@]} -eq 0 ] || fail_with "${#FAILS[@]} leg(s) failed" "${FAILS[@]}"

echo ""
echo "RESULT: PASS"
echo "  Both corrupted echo requests were counted and not answered; both good"
echo "  ones, even and odd length, were answered."
exit 0
