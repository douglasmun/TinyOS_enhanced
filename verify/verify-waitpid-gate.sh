#!/usr/bin/env bash
#
# verify-waitpid-gate.sh -- who may waitpid() a process, and what does a lost
# exit status read as?
#
# THE BUGS. sys_waitpid admitted any caller whose uid matched the target's
# (and root for anything), not just the target's parent: a process could block
# on, and collect the exit status of, any same-uid process it never started.
# And when the target's slot was gone and its record had already been pushed
# out of the 16-entry exit ring, it returned 0 -- "exited successfully" -- for
# a status it did not have.
#
# HOW IT IS WITNESSED. `waitgate` (a TINYOS_FAULT_INJECT kernel-shell command,
# absent from `help`; sys_waitgate_test() in syscall.c) calls sys_waitpid on
# kernel-task targets parked on a wait queue, with the parent fields set per
# leg. A one-shot hook inside sys_waitpid, AFTER its admission check, kills the
# target -- so a wrongly admitted waitpid returns 127 instead of hanging, and
# the hook firing at all is the witness that admission happened.
#
#   child     parent = caller: admitted, returns 127 (the control)
#   nonchild  same uid, no parent: refused with -ECHILD, hook never fires
#   stale     caller's pid but another generation: refused, hook never fires
#   evicted   child dies, 16 fake exits evict its record: -ECHILD, not 0
#
# The child leg is the positive control for both refusal legs; the evicted
# leg's own control proves the record really was evicted.
#
# NB: `make clean`s on exit -- TINYOS_FAULT_INJECT objects must not linger.
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=waitgate.log
TRACE=waitgate-trace.log
MON_SOCK=/tmp/tinyos-waitgate-mon.sock

guard_fail() { echo "HARNESS GUARD FAILED: $*"; exit 2; }

grep -q "sys_waitgate_test" src/syscall.c \
    || guard_fail "src/syscall.c has no sys_waitgate_test()"
grep -q '"waitgate"' src/shell.c \
    || guard_fail "src/shell.c has no waitgate command"

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
TINYOS_EXEC_CMD="waitgate" \
TINYOS_EXPECT="[WAITGATE] VERDICT" \
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

OUT=$(tr -d '\r' < "$SERIAL" | grep "\[WAITGATE\]")
if [ -z "$OUT" ]; then
    echo "RESULT: harness problem — waitgate produced no output."
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
    echo "RESULT: harness problem — a control is dead; the legs prove nothing."
    exit 2
fi
for leg in child nonchild stale evicted; do
    echo "$OUT" | grep -q "\] $leg control: ok" || {
        echo "RESULT: harness problem — $leg never reported (run truncated?)"
        exit 2
    }
done
# The child leg is the positive control for the refusals: if a real child is
# not admitted, "refused" proves nothing.
if ! echo "$OUT" | grep -q "child admitted, status read: PASS"; then
    echo "RESULT: harness problem — the child control failed; the refusal legs grade nothing."
    exit 2
fi

NPASS=$(echo "$OUT" | grep -c ": PASS (")
NFAIL=$(echo "$OUT" | grep -c ": FAIL (")
if [ "$NPASS" -eq 4 ] && [ "$NFAIL" -eq 0 ] && echo "$OUT" | grep -q "VERDICT: PASS"; then
    echo "RESULT: PASS — waitpid admits only the caller's own child, and a lost status is an error, not exit 0."
    exit 0
fi
echo "RESULT: FAIL — $NFAIL FAIL / $NPASS PASS (want 4)."
exit 1
