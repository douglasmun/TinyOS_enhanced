#!/usr/bin/env bash
#
# verify-tcp-state-fixes.sh — three TCP state-machine fixes, graded on the state
# each leaves a connection slot in.
#
# THE BUGS
#
#  1. tcp_close() in SYN_SENT / SYN_RECEIVED fell to the "already closing"
#     default and left the slot in_use. A SYN-ACK arriving later promoted it to
#     ESTABLISHED with no owner left to read or close it: a leaked socket.
#  2. Every FIN site set rcv_nxt = seq + 1 regardless of where the FIN sat.
#     A FIN ahead of a gap jumped rcv_nxt over the missing bytes and moved the
#     connection to CLOSE_WAIT (stream truncated); a FIN carrying data ACKed one
#     past the segment START, i.e. the data short.
#  3. SYN_SENT accepted any RST. RFC 793 requires ACK == SND.NXT, so a bare RST
#     (or one with a wrong ACK) from anyone who guessed the 4-tuple aborted an
#     outgoing connect().
#
# THE VEHICLE
#
# `tcpstate` (TINYOS_FAULT_INJECT kernel-shell command, tcp.c) builds each
# segment in the kernel and feeds it straight to tcp_process_segment() on a
# synthetic slot with transmission muted, then prints
#   TCPSTATE <leg> state=<S> rcv_nxt=<N> in_use=<0|1>
# A wire peer cannot do this deterministically: SLIRP plays the remote end.
#
# Each fix has a control leg that must still change state, so an inert stack
# (one that ignores every segment) FAILs too.
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem.
# NB: `make clean`s on exit -- TINYOS_FAULT_INJECT objects must not linger.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=tcpstate.log
TRACE=tcpstate-trace.log
MON_SOCK=/tmp/tinyos-tcpstate-mon.sock

guard_fail() { echo "HARNESS GUARD FAILED: $*"; exit 2; }

grep -q "tcp_state_selftest" src/tcp.c || guard_fail "src/tcp.c has no tcp_state_selftest()"
grep -q '"tcpstate"' src/shell.c || guard_fail "src/shell.c has no tcpstate command"

echo "==> Building kernel + ISO (TINYOS_FAULT_INJECT)..."
make clean >/dev/null 2>&1
make EXTRA_CFLAGS=-DTINYOS_FAULT_INJECT >/dev/null || guard_fail "build failed"
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || guard_fail "mkrescue failed"

rm -f "$SERIAL" "$TRACE" "$MON_SOCK"

echo "==> Launching headless QEMU"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() {
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "${QEMU_PID:-}" ] && wait "$QEMU_PID" 2>/dev/null
    rm -f "$MON_SOCK"
    echo "==> make clean (TINYOS_FAULT_INJECT objects must not linger)"
    make clean >/dev/null 2>&1
    return 0
}
trap cleanup EXIT

# tcpstate is kernel-shell only; the typist hands over to kshell by itself.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_EXEC_CMD="tcpstate" \
TINYOS_EXPECT="TCPSTATE done" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 2
[ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: FAIL — no serial output at all (typist rc=$TYPIST_RC)"
    exit 2
fi
RAW=$(tr -d '\r' < "$SERIAL")
if grep -q "Triple fault" "$TRACE" 2>/dev/null || printf '%s\n' "$RAW" | grep -q "KERNEL PANIC"; then
    echo "RESULT: FAIL — the guest faulted"
    exit 1
fi
if printf '%s\n' "$RAW" | grep -q "^TCPSTATE no-free-slot"; then
    echo "RESULT: INCONCLUSIVE — no free TCP slot for the self-test"
    exit 2
fi
if ! printf '%s\n' "$RAW" | grep -q "^TCPSTATE done"; then
    echo "RESULT: INCONCLUSIVE — tcpstate never completed (typist rc=$TYPIST_RC); see $SERIAL"
    exit 2
fi

leg() {  # $1 = leg -> "state rcv_nxt in_use"
    printf '%s\n' "$RAW" |
        sed -n "s/^TCPSTATE $1 state=\([A-Z_0-9]*\) rcv_nxt=\([0-9]*\) in_use=\([01]\)$/\1 \2 \3/p" |
        head -1
}

FAILS=0
INCONC=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
inconc() { echo "  INCONCLUSIVE: $*"; INCONC=$((INCONC + 1)); }

# expect <leg> <state> <rcv_nxt|-> <in_use|-> <control?> <why>
expect() {
    local name=$1 want_s=$2 want_n=$3 want_u=$4 control=$5 why=$6 s n u
    read -r s n u <<<"$(leg "$name")"
    printf '  %-18s state=%-12s rcv_nxt=%-5s in_use=%s\n' "$name" "${s:-?}" "${n:-?}" "${u:-?}"
    if [ -z "${s:-}" ]; then
        inconc "$name: no TCPSTATE line"
        return
    fi
    if [ "$s" != "$want_s" ] ||
       { [ "$want_n" != - ] && [ "$n" != "$want_n" ]; } ||
       { [ "$want_u" != - ] && [ "$u" != "$want_u" ]; }; then
        if [ "$control" = control ]; then
            inconc "$name control: want state=$want_s rcv_nxt=$want_n in_use=$want_u — $why"
        else
            fail "$name: want state=$want_s rcv_nxt=$want_n in_use=$want_u — $why"
        fi
    fi
}

# Controls first: if these fail, the exclusions below grade nothing.
expect close-established FIN_WAIT_1 - 1    control "an established close() must still FIN"
expect fin-inorder       CLOSE_WAIT 1001 1 control "an in-order FIN must still close, consuming one seq"
expect rst-goodack       CLOSED     - 0    control "a RST acking our SYN must still abort SYN_SENT"

expect close-synsent     CLOSED      -    0 x "close() in SYN_SENT left the slot in_use (leaked socket)"
expect close-synrcvd     CLOSED      -    0 x "close() in SYN_RECEIVED left the slot in_use (leaked socket)"
expect fin-gap           ESTABLISHED 1000 1 x "a FIN beyond a gap closed the stream / skipped rcv_nxt"
expect fin-data          CLOSE_WAIT  2004 1 x "a FIN with 3 data bytes must leave rcv_nxt = seq+3+1"
expect rst-bare          SYN_SENT    -    1 x "a bare RST aborted SYN_SENT (RFC 793: needs ACK == SND.NXT)"
expect rst-badack        SYN_SENT    -    1 x "a RST with ACK != SND.NXT aborted SYN_SENT"

if [ "$INCONC" -ne 0 ]; then
    echo "RESULT: INCONCLUSIVE — $INCONC control/leg problem(s), $FAILS failure(s); see $SERIAL"
    exit 2
fi
if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS assertion(s); see $SERIAL (typist rc=$TYPIST_RC)"
    exit 1
fi
echo "RESULT: PASS — handshake close frees the slot; only an in-order FIN closes and rcv_nxt counts its data; SYN_SENT ignores unacceptable RSTs"
exit 0
