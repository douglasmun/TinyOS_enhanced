#!/usr/bin/env bash
#
# verify-context-switch-esp.sh -- does a task resumed by context_switch() get
# back the ESP it called with? (issue #126)
#
# THE BUG. context_switch.S saved ESP pointing AT the return address rather
# than past it. Resume stages EIP/EFLAGS below the saved ESP, then popf; ret --
# leaving ESP 4 bytes lower than the caller's `call` expects. Every caller here
# was EBP-framed on Homebrew's i686-elf gcc, and `leave` repaired ESP before
# anything read it. CI's i686-linux-gnu gcc gave a caller an ESP-relative
# epilogue: it popped shifted registers and `ret` loaded the zero word below
# the real return address -- the shell task panicked at EIP=0 on every CI boot.
#
# HOW IT IS WITNESSED. `ctxswtest` (a TINYOS_FAULT_INJECT kernel-shell command,
# absent from `help`; scheduler_ctxsw_esp_test() in scheduler.c) switches the
# current task to itself through context_switch() from an asm probe and
# reports ESP-after minus ESP-before, four rounds. The probe is asm so no
# compiler framing can hide the error, which is what hid it for so long: the
# unfixed kernel reports -4 on any toolchain, not only CI's.
#
# NB: `make clean`s on exit -- TINYOS_FAULT_INJECT objects must not linger.
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=ctxsw.log
TRACE=ctxsw-trace.log
MON_SOCK=/tmp/tinyos-ctxsw-mon.sock

guard_fail() { echo "HARNESS GUARD FAILED: $*"; exit 2; }

grep -q "scheduler_ctxsw_esp_test" src/scheduler.c \
    || guard_fail "src/scheduler.c has no scheduler_ctxsw_esp_test()"
grep -q '"ctxswtest"' src/shell.c \
    || guard_fail "src/shell.c has no ctxswtest command"

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
TINYOS_EXEC_CMD="ctxswtest" \
TINYOS_EXPECT="[CTXSW] VERDICT" \
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

OUT=$(tr -d '\r' < "$SERIAL" | grep "\[CTXSW\]")
if [ -z "$OUT" ]; then
    echo "RESULT: harness problem — ctxswtest produced no output."
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
    echo "RESULT: harness problem — no current task to switch."
    exit 2
fi
NROUNDS=$(echo "$OUT" | grep -c "round [0-3]: ESP delta across context_switch = ")
if [ "$NROUNDS" -ne 4 ]; then
    echo "RESULT: harness problem — $NROUNDS of 4 rounds reported (run truncated?)"
    exit 2
fi

NZERO=$(echo "$OUT" | grep -c "ESP delta across context_switch = 0$")
if [ "$NZERO" -eq 4 ] && echo "$OUT" | grep -q "VERDICT: PASS (0 of 4"; then
    echo "RESULT: PASS — context_switch() resumes every task with the ESP it called with."
    exit 0
fi
echo "RESULT: FAIL — $((4 - NZERO)) of 4 rounds resumed with a moved ESP."
exit 1
