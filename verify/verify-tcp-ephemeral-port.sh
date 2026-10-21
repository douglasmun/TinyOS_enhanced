#!/usr/bin/env bash
#
# verify-tcp-ephemeral-port.sh — the TCP ephemeral port allocator: random per
# connection (RFC 6056), and never handing out a port that is still owed its
# TIME_WAIT. doc/EPHEMERAL_PORT_ISSUES.md has the background.
#
# THE BUGS
#
#  1. tcp_allocate_port() was a counter starting at 49152 on every boot, so the
#     first outbound connection always came from 49152 and every later one from
#     the next port up. A blind attacker knew the local port of every connection.
#  2. tcp_evict_oldest_time_wait() frees a TIME_WAIT slot early under table
#     pressure, and the slot was the only record of the port. Sequential
#     allocation hid this until the counter wrapped; a random draw would not.
#  3. A slot that is in_use but still CLOSED (tcp_connect() assigns the port
#     before the slot leaves CLOSED) did not count as holding its port.
#
# THE VEHICLE
#
# `tcpport` (TINYOS_FAULT_INJECT kernel-shell command, tcp.c) prints
#   TCPPORT draw <n> port=<P> rc=<rc>     ten real socket/connect/close cycles,
#                                         transmission muted, peer TEST-NET-3
#   TCPPORT evict sock=<n>                tcp_socket() on a synthetic full table
#   TCPPORT <leg> free=<0|1>              tcp_port_is_free() on chosen ports
# The draw port is conn->local_port, the value tcp_send_segment() writes into
# every header. It must be the first TCP use after boot.
#
# Controls: every draw must be a real port in range, and an unrelated port and
# the evicted port after its 30 s must read free, so an allocator that refuses
# everything FAILs too.
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem.
# NB: `make clean`s on exit -- TINYOS_FAULT_INJECT objects must not linger.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=tcpport.log
TRACE=tcpport-trace.log
MON_SOCK=/tmp/tinyos-tcpport-mon.sock

guard_fail() { echo "HARNESS GUARD FAILED: $*"; exit 2; }

grep -q "tcp_port_selftest" src/tcp.c || guard_fail "src/tcp.c has no tcp_port_selftest()"
grep -q '"tcpport"' src/shell.c || guard_fail "src/shell.c has no tcpport command"

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

# tcpport is kernel-shell only; the typist hands over to kshell by itself.
# Root: the eviction leg needs tcp_socket() past the per-uid socket cap.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_EXEC_CMD="tcpport" \
TINYOS_EXPECT="TCPPORT done" \
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
if printf '%s\n' "$RAW" | grep -q "^TCPPORT table-not-empty"; then
    echo "RESULT: INCONCLUSIVE — a TCP slot was in use before the self-test"
    exit 2
fi
if ! printf '%s\n' "$RAW" | grep -q "^TCPPORT done"; then
    echo "RESULT: INCONCLUSIVE — tcpport never completed (typist rc=$TYPIST_RC); see $SERIAL"
    exit 2
fi

FAILS=0
INCONC=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
inconc() { echo "  INCONCLUSIVE: $*"; INCONC=$((INCONC + 1)); }

# ---- Draw legs ---------------------------------------------------------------
PORTS=$(printf '%s\n' "$RAW" | sed -n 's/^TCPPORT draw [0-9]* port=\([0-9]*\) rc=.*$/\1/p')
NDRAWS=$(printf '%s\n' "$PORTS" | grep -c '^[0-9]')
echo "  draws: $(printf '%s ' $PORTS)"

if [ "$NDRAWS" -ne 10 ]; then
    inconc "expected 10 draw lines, got $NDRAWS"
else
    # Control: every draw is a real ephemeral port.
    BAD=$(printf '%s\n' "$PORTS" | awk '$1 < 49152 || $1 > 65535' | head -1)
    if [ -n "$BAD" ]; then
        inconc "control: draw port $BAD is not in 49152-65535 (0 = allocation failed)"
    fi

    FIRST=$(printf '%s\n' "$PORTS" | head -1)
    # False-FAIL odds on a random allocator: 1/16384.
    if [ "$FIRST" = 49152 ]; then
        fail "the first connection after boot came from 49152 (counter start)"
    fi
    # Old allocator: every step is +1. Random: all nine steps +1 has odds ~2^-126.
    STEPS1=$(printf '%s\n' "$PORTS" | awk 'NR > 1 && $1 == prev + 1 { n++ } { prev = $1 } END { print n + 0 }')
    if [ "$STEPS1" -eq 9 ]; then
        fail "draws are sequential (every step +1): the allocator is a counter"
    fi
    # Random draws over 16384 ports: odds that 10 contain a repeat ~ 0.3%.
    # Repeats are legal (each port is freed before the next draw) but more than
    # one points at a weak source; flag as a problem, not a bug in the allocator.
    DUPS=$(printf '%s\n' "$PORTS" | sort | uniq -d | wc -l | tr -d ' ')
    if [ "$DUPS" -gt 1 ]; then
        inconc "$DUPS ports repeated in 10 random draws (odds ~1e-5): check the entropy source"
    fi
fi

# ---- Busy legs ---------------------------------------------------------------
leg() { printf '%s\n' "$RAW" | sed -n "s/^TCPPORT $1 free=\([01]\)$/\1/p" | head -1; }

# expect <leg> <want free> <control?> <why>
expect() {
    local name=$1 want=$2 control=$3 why=$4 got
    got=$(leg "$name")
    printf '  %-10s free=%s\n' "$name" "${got:-?}"
    if [ -z "$got" ]; then
        inconc "$name: no TCPPORT line"
    elif [ "$got" != "$want" ]; then
        if [ "$control" = control ]; then
            inconc "$name control: want free=$want — $why"
        else
            fail "$name: want free=$want — $why"
        fi
    fi
}

EVSOCK=$(printf '%s\n' "$RAW" | sed -n 's/^TCPPORT evict sock=\(-*[0-9]*\)$/\1/p' | head -1)
echo "  evict sock=${EVSOCK:-?}"
if [ -z "$EVSOCK" ] || [ "$EVSOCK" -lt 0 ]; then
    inconc "tcp_socket() on the full table did not evict (sock=${EVSOCK:-?}); the busy legs grade nothing"
fi

expect unrelated 1 control "a port nothing holds must be free"
expect expired   1 control "an evicted port must come free when its 30 s TIME_WAIT would have ended"
expect timewait  0 x "a port in live TIME_WAIT was offered for reuse"
expect evicted   0 x "a port evicted from TIME_WAIT was free again before its 30 s were up"
expect closed    0 x "a port held by an in_use CLOSED slot (connect in progress) was offered for reuse"

if [ "$INCONC" -ne 0 ]; then
    echo "RESULT: INCONCLUSIVE — $INCONC control/leg problem(s), $FAILS failure(s); see $SERIAL"
    exit 2
fi
if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS assertion(s); see $SERIAL (typist rc=$TYPIST_RC)"
    exit 1
fi
echo "RESULT: PASS — ports are random per connection, and TIME_WAIT (live or evicted) and in-progress connects hold their port"
exit 0
