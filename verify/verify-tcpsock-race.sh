#!/usr/bin/env bash
#
# verify-tcpsock-race.sh -- does SYS_TCPSOCK act on a socket it no longer owns?
#
# THE BUG. sys_tcpsock() checked ownership (tcpsock_check_owner) BEFORE
# copy_from_user and outside TCP_LOCK, and the primitives it then called --
# tcp_connect/send/recv/close -- never re-checked: the kernel's own callers
# have no owner to check. If the slot was freed and reallocated to another
# user in between, the call read, wrote or closed THAT user's connection.
#
# HOW IT IS WITNESSED. Nothing today yields in that window, so racing it for
# real is luck. TINYOS_FAULT_INJECT adds tcpsock_race_point() exactly where
# the window is: armed, it hands the call's slot to uid 0 there, as a
# free-and-reallocate would. `tcpsockrace` (kernel shell, absent from `help`)
# drives sys_tcpsock as uid 1000 -- never root, whose euid sees every socket
# and would pass any version of this:
#
#   arm1  RECV on the reassigned slot: -EBADF. Acting on it gives -ENOTCONN.
#   arm2  CLOSE on the reassigned slot: -EBADF, and the foreign socket lives.
#   arm3  CLOSE on our own socket, unarmed: succeeds (positive control).
#
# Controls prove the hook fired; CONTROL-DEAD is a harness problem.
# Negative control: arms 1 and 2 FAIL on the commit before the fix.
#
# NB: `make clean`s on exit -- TINYOS_FAULT_INJECT objects must not linger.
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=tcpsockrace.log
TRACE=tcpsockrace-trace.log
MON_SOCK=/tmp/tinyos-tcprace-mon.sock

guard_fail() { echo "HARNESS GUARD FAILED: $*"; exit 2; }

grep -q "tcpsock_race_point" src/syscall.c \
    || guard_fail "src/syscall.c has no tcpsock_race_point hook"
grep -q '"tcpsockrace"' src/shell.c \
    || guard_fail "src/shell.c has no tcpsockrace command"

echo "==> Building kernel + ISO (TINYOS_FAULT_INJECT)..."
make clean >/dev/null 2>&1
make EXTRA_CFLAGS=-DTINYOS_FAULT_INJECT >/dev/null || { echo "build failed"; exit 2; }
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || { echo "mkrescue failed"; exit 2; }

rm -f "$SERIAL" "$TRACE" "$MON_SOCK"

echo "==> Launching headless QEMU (monitor on $MON_SOCK)"
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

# Kernel-internal invariant, kernel-shell command: the typist's default route
# to kshell is the right one (no TINYOS_STAY_IN_RING3).
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="tcpsockrace" \
TINYOS_EXPECT="TCPSOCKRACE. VERDICT" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
[ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null

echo ""
echo "================ VERDICT ================"

[ -s "$SERIAL" ] || { echo "RESULT: harness problem — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

if grep -q "Triple fault" "$TRACE" 2>/dev/null; then
    echo "RESULT: harness problem — triple fault during the run"
    exit 2
fi

OUT=$(tr -d '\r' < "$SERIAL" | grep "\[TCPSOCKRACE\]")
if [ -z "$OUT" ]; then
    echo "RESULT: harness problem — tcpsockrace produced no output."
    tr -d '\r' < "$SERIAL" | tail -25
    exit 2
fi
echo "$OUT"
echo ""

if tr -d '\r' < "$SERIAL" | grep -q "KERNEL PANIC"; then
    echo "RESULT: FAIL — kernel panic during the run"
    exit 1
fi
if echo "$OUT" | grep -q "CONTROL-DEAD"; then
    echo "RESULT: harness problem — a control is dead; the arms prove nothing."
    exit 2
fi
for arm in sockets arm1 arm2; do
    echo "$OUT" | grep -q "$arm.*: ok" || {
        echo "RESULT: harness problem — $arm never reported (run truncated?)"
        exit 2
    }
done

# Count the arm results, not just the verdict line: 4 PASS lines, 0 FAIL.
NPASS=$(echo "$OUT" | grep -v VERDICT | grep -c ": PASS$")
NFAIL=$(echo "$OUT" | grep -v VERDICT | grep -c ": FAIL$")
if [ "$NPASS" -eq 4 ] && [ "$NFAIL" -eq 0 ] && echo "$OUT" | grep -q "VERDICT: PASS"; then
    echo "RESULT: PASS — ownership re-checked at the point of use; own sockets still work."
    exit 0
fi
echo "RESULT: FAIL — $NFAIL arm assertion(s) failed (see lines above)."
exit 1
