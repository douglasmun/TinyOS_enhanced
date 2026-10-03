#!/usr/bin/env bash
#
# verify-edr-kill-reap.sh -- is a task EDR kills while NOT running ever reaped?
#
# THE BUG. edr_response_terminate() (and edr_advanced_raise_alert()) set
# task->state = TERMINATED and rely on "the scheduler will clean up". The
# scheduler only queues a TERMINATED task for cleanup when it switches AWAY
# from it, i.e. when the task was the one running. A target that is blocked
# is not in the ready queue at all; a target that is ready is dropped from the
# queue by scheduler_get_next_task() ("Rejecting non-runnable") and nothing
# else. Neither is ever freed: the slot stays claimed in free_slot_bitmap, a
# blocked target stays on its wait queue, and none of task_terminate()'s
# releases (fds, pipes, sockets, waitpid notification) run.
#
# HOW IT IS WITNESSED. EDR's real triggers (threat score >= 90, ROP/shellcode
# heuristics) are not a deterministic test vehicle, and the trigger is not
# what is broken. `edrkill` (a TINYOS_FAULT_INJECT kernel-shell command,
# absent from `help`) calls the real response functions on kernel-task
# targets it parks in a known state -- see task_edrkill_test() in process.c:
#
#   control    blocked target killed by task_terminate(): all witnesses PASS
#   blocked    target parked on a wait queue, killed by EDR
#   ready      target in the ready queue, killed by EDR
#   protected  CAP_UNKILLABLE target: EDR must refuse it, counted not printed
#   stale      EDR handed the slot's PREVIOUS {pid, generation}: must refuse
#
# Witnesses: free_slot_bitmap (what the allocator consults -- task_get() and
# task_count_free_slots() both treat TERMINATED as gone, so they hide the
# leak), the wait queue's count, and the exit ring waitpid() reads (EDR kills
# report 137, task_terminate() 0x7F = 127). The refusal legs are the
# exclusions; the blocked/ready legs are their positive controls.
#
# Each leg prints a control proving the target was created, holds a slot and
# reached its starting state; CONTROL-DEAD is a harness problem, never a pass.
#
# SELF-KILL LEG (ring 3). EDR's behavioural check runs inside the flagged
# task's own syscall. Killing in place there let the syscall run anyway and
# return to ring 3 on a task already marked TERMINATED. `edrkill` arms a
# one-shot hook that fires EDR's terminate response on hello.elf's first
# SYS_WRITE. The harness logs out of kshell, logs back in, runs hello.elf at
# the ring-3 shell and requires: the hook fired (positive control), the write
# did NOT happen ("Hello from ELF!" absent), and the shell's waitpid got 137.
#
# NB: `make clean`s on exit -- TINYOS_FAULT_INJECT objects must not linger.
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=edrkill.log
TRACE=edrkill-trace.log
MON_SOCK=/tmp/tinyos-edrkill-mon.sock

guard_fail() { echo "HARNESS GUARD FAILED: $*"; exit 2; }

grep -q "task_edrkill_test" src/process.c \
    || guard_fail "src/process.c has no task_edrkill_test()"
grep -q '"edrkill"' src/shell.c \
    || guard_fail "src/shell.c has no edrkill command"

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
TINYOS_EXEC_CMD="edrkill" \
TINYOS_EXPECT="self-kill leg armed" \
TINYOS_FOLLOWUP_CMDS="\
exit=>TinyOS login:;\
root=>Password:;\
!$PASSWORD=>create a regular user now;\
!n=>TinyOS shell (ring 3);\
/hello.elf=>exited with status" \
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

OUT=$(tr -d '\r' < "$SERIAL" | grep "\[EDRKILL\]")
if [ -z "$OUT" ]; then
    echo "RESULT: harness problem — edrkill produced no output."
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
for leg in control blocked ready protected stale; do
    echo "$OUT" | grep -q "$leg control: ok" || {
        echo "RESULT: harness problem — $leg never reported (run truncated?)"
        exit 2
    }
done
# The control leg is task_terminate(), the path that already works. If IT
# fails, the witnesses are broken, not EDR.
if echo "$OUT" | grep "^\[EDRKILL\] control " | grep -q ": FAIL ("; then
    echo "RESULT: harness problem — the task_terminate() control failed; the witnesses are broken."
    exit 2
fi

# Count the leg results, not just the verdict line: 12 PASS lines, 0 FAIL
# (control 3, blocked 3, ready 2, protected 2, stale 2).
NPASS=$(echo "$OUT" | grep -c ": PASS (")
NFAIL=$(echo "$OUT" | grep -c ": FAIL (")
KERNEL_OK=0
if [ "$NPASS" -eq 12 ] && [ "$NFAIL" -eq 0 ] && echo "$OUT" | grep -q "VERDICT: PASS"; then
    KERNEL_OK=1
fi

# --- Self-kill leg (ring 3) ---------------------------------------------
# Everything after the arm line. Rejoined: the EDR bursts tear lines at an
# arbitrary character (verify/CLAUDE.md).
. verify/edr-rejoin.sh
AFTER=$(rejoin_edr < "$SERIAL" | awk '/\[EDRKILL\] self-kill leg armed/{on=1} on')
echo "--- self-kill leg ---"
echo "$AFTER" | grep -E "EDR RESPONSE\] Terminating|Hello from ELF|exited with status" || true
echo ""

if [ -z "$AFTER" ]; then
    echo "RESULT: harness problem — the self-kill leg was never armed."
    exit 2
fi
# Positive control: the hook fired against hello.elf. Without it, "no Hello"
# would only mean hello.elf never ran.
if ! echo "$AFTER" | grep -q "EDR RESPONSE\] Terminating PID [0-9]* (.*hello"; then
    echo "RESULT: harness problem — the EDR self-kill hook never fired on hello.elf."
    exit 2
fi
SELF_OK=1
if echo "$AFTER" | grep -q "Hello from ELF"; then
    echo "self-kill: FAIL — the flagged SYS_WRITE ran after EDR killed its caller"
    SELF_OK=0
fi
if ! echo "$AFTER" | grep -q "hello.elf: exited with status 137"; then
    echo "self-kill: FAIL — waitpid did not report 137 (hang or wrong status)"
    SELF_OK=0
fi

if [ "$KERNEL_OK" -eq 1 ] && [ "$SELF_OK" -eq 1 ]; then
    echo "RESULT: PASS — EDR kills are reaped, report 137, refuse protected/stale targets, and stop the flagged syscall."
    exit 0
fi
echo "RESULT: FAIL — kernel legs: $NFAIL FAIL / $NPASS PASS (want 12); self-kill ok=$SELF_OK."
exit 1
