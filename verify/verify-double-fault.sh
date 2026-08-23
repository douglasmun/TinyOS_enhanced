#!/usr/bin/env bash
#
# verify-double-fault.sh — does a blown kernel stack produce a #DF dump, or a
# silent triple fault?
#
# THE BUG (issue #119). Vector 8 was installed as an ordinary 32-bit interrupt
# gate:
#
#     // idt_set_gate(8, double_fault_handler, 0x8E);   <- commented out
#     idt_set_gate( 8, isr8,  0x8E);
#
# so #DF took the same path as every other exception: isr8 -> isr_common ->
# isr_common_handler, whose FIRST action is pushing a register frame onto the
# CURRENT stack. Meanwhile double_fault_c_handler() — written to run on a
# dedicated stack, and documenting in its own comment why that is mandatory —
# was never reachable: no call site anywhere in the linked binary. An 8 KB
# double_fault_stack and tss_get_double_fault_stack_top() were allocated and
# never used.
#
# WHY IT MATTERED ONLY IN ONE CASE, AND WHY THAT CASE IS THE COMMON ONE.
# For a #DF on a HEALTHY stack (corrupt IDT/GDT, nested #PF) the generic path
# is fine and already prints more than the dead handler would:
# exception_can_kill_user_task(8) returns false, so it correctly reaches the
# kernel panic path with a full register dump. Nothing was broken there.
#
# The gap is kernel STACK EXHAUSTION — the single most common cause of #DF.
# There the stack is already gone, so isr_common's pushes fault again and the
# CPU escalates to a TRIPLE FAULT: instant reset, no output, no forensics.
# TinyOS has hit exactly this: the signed-exec chain overflowed a 64 KB kernel
# stack into its guard page (#PF -> #DF -> triple fault), which is why
# KERNEL_TASK_STACK_PAGES is 32 today. A recurrence produced nothing to debug.
#
# THE FIX. i386 has no IST (that is x86-64). The only mechanism that switches
# stacks on an exception is a hardware task switch, so vector 8 is now a TASK
# GATE (type 0x85, selector = a dedicated TSS, offset ignored) pointing at a
# second TSS whose esp/eip/cr3/segments the CPU loads wholesale. The handler
# therefore starts on a known-good stack no matter what the faulting one looks
# like, and reads the interrupted context out of the outgoing TSS.
#
# WHAT THIS HARNESS ASSERTS.
#   1. The task gate is actually installed at boot (not merely compiled).
#   2. `dftest` — unbounded kernel recursion — reaches the #DF handler and it
#      PRINTS. This is the leg that fails against the unfixed kernel.
#   3. QEMU's own trace records NO triple fault (`-d int,cpu_reset`). This is
#      the independent witness: it comes from the CPU, not from our kprintf, so
#      it cannot be satisfied by a handler that merely claims to have run.
#   4. The dump identifies stack exhaustion rather than printing a bare frame.
#
# NEGATIVE CONTROL. Run against the pre-fix tree, leg 2 finds no dump and leg 3
# finds `Triple fault` in the trace. Both must flip together; if leg 2 fails
# while leg 3 is clean, the recursion never blew the stack and the run proves
# nothing (see CONTROL-WEAK below).
#
# Needs -DTINYOS_FAULT_INJECT for the `dftest` command, and make cleans on exit
# because that flag is not in the make dependency graph.
#
# EXIT: 0 pass, 1 fail, 2 harness problem.

set -uo pipefail
cd "$(dirname "$0")/.."

ISO=dist/tinyos.iso
SERIAL=dfault-serial.log
TRACE=dfault-trace.log
MON_SOCK=/tmp/tinyos-dfault-mon.sock
PASSWORD="rootpass123"

echo "==> Building with -DTINYOS_FAULT_INJECT"
make clean >/dev/null 2>&1
if ! make -j8 EXTRA_CFLAGS="-DTINYOS_FAULT_INJECT" kernel.elf >/tmp/dfault-build.log 2>&1; then
    echo "RESULT: INCONCLUSIVE — build failed"
    tail -20 /tmp/dfault-build.log
    exit 2
fi
cp kernel.elf iso/boot/kernel.elf
if ! i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1; then
    echo "RESULT: INCONCLUSIVE — grub-mkrescue failed (need xorriso?)"
    exit 2
fi

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

# `dftest` is a kernel-shell command, so TINYOS_STAY_IN_RING3 is deliberately
# NOT set — same documented exception as verify-editor-rowfail.sh. What is
# under test is a CPU-level fault-delivery mechanism, not a ring-3 boundary.
#
# TINYOS_EXPECT matches the #DF banner. The guest HALTS inside the handler and
# never returns a prompt, which is the intended outcome, so there is no later
# marker to wait on.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=300 \
TINYOS_EXEC_CMD="dftest" \
TINYOS_EXPECT="DOUBLE FAULT EXCEPTION" \
python3 tools/qemu_typist.py &
TYPIST_PID=$!

# WATCHDOG. On the UNFIXED kernel the #DF triple-faults, and -no-reboot does
# not stop the guest from being reset by the typist's next boot cycle: the
# typist simply sees a fresh login prompt, logs in, types dftest again, and
# faults again. Left alone it loops until the harness's own caller times out,
# which reports as a hang rather than as the FAIL it actually is.
#
# So poll for the triple fault directly. The trace is written by QEMU, not by
# the guest, so it is available even though the guest produced no output.
WATCHDOG_LIMIT=$(( 300 / 5 ))
for _ in $(seq 1 "$WATCHDOG_LIMIT"); do
    kill -0 "$TYPIST_PID" 2>/dev/null || break
    if grep -aq "Triple fault" "$TRACE" 2>/dev/null; then
        echo "typist: watchdog -- triple fault seen in trace, stopping early"
        kill "$TYPIST_PID" 2>/dev/null
        break
    fi
    sleep 5
done
wait "$TYPIST_PID" 2>/dev/null
TYPIST_RC=$?

sleep 3
[ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null
sleep 1

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: INCONCLUSIVE — no serial output at all (typist rc=$TYPIST_RC)"
    exit 2
fi

LOG=$(tr -d '\r' < "$SERIAL")

# ---- LEG 1: the task gate was installed at boot -------------------------
# Without this the run is untestable: the other legs would be grading the old
# interrupt gate while reporting on the new one.
if ! echo "$LOG" | grep -q "Vector 8 (#DF) is a task gate"; then
    echo "RESULT: INCONCLUSIVE — the DF task gate was never installed."
    echo "  Expected the boot line from kernel.c. Without it there is nothing"
    echo "  to test; this is a build/boot problem, not a kernel verdict."
    echo "$LOG" | grep -v Suspicious | tail -20
    exit 2
fi
DF_TSS_LINE=$(echo "$LOG" | grep "Double-fault TSS at" | head -1)
echo "  gate:  $(echo "$LOG" | grep 'task gate' | head -1)"
echo "  tss:   $DF_TSS_LINE"

# ---- LEG 3 (evaluated early): the CPU's own triple-fault witness --------
# Checked before leg 2 so a triple fault is reported as the DEFECT it is,
# rather than as "no dump found".
TRIPLE=0
if [ -s "$TRACE" ] && grep -q "Triple fault" "$TRACE" 2>/dev/null; then
    TRIPLE=1
fi

# ---- LEG 2: the handler ran and printed --------------------------------
if ! echo "$LOG" | grep -q "DOUBLE FAULT EXCEPTION"; then
    if [ "$TRIPLE" -eq 1 ]; then
        echo ""
        echo "  QEMU trace (tail):"
        grep -E "check_exception|v=0e|v=08|Triple fault" "$TRACE" | tail -8
        echo ""
        echo "RESULT: FAIL — kernel stack exhaustion still triple-faults."
        echo "  The #DF never reached a handler: the CPU reset instead. This is"
        echo "  exactly the pre-fix behaviour issue #119 describes."
        exit 1
    fi
    # No dump AND no triple fault: the recursion never actually blew the
    # stack, so nothing was exercised. Not a pass.
    echo "RESULT: INCONCLUSIVE — CONTROL-WEAK: no #DF dump and no triple fault."
    echo "  dftest did not exhaust the stack (tail-call optimised away?), so"
    echo "  this run did not test the fault path at all."
    echo "$LOG" | grep -v Suspicious | tail -20
    exit 2
fi

echo ""
echo "  --- #DF dump as captured ---"
echo "$LOG" | sed -n '/DOUBLE FAULT EXCEPTION/,/halted to prevent/p' | sed 's/^/  /'
echo ""

# ---- LEG 3 asserted -----------------------------------------------------
if [ "$TRIPLE" -eq 1 ]; then
    echo "RESULT: FAIL — a #DF dump was printed, but the CPU still triple-faulted."
    grep -E "Triple fault" "$TRACE" | tail -5
    echo "  The handler is being entered and then dying, e.g. its stack, cr3 or"
    echo "  code selector in the DF TSS is wrong."
    exit 1
fi

# ---- LEG 4: the dump is useful, not just present ------------------------
# A handler that prints a banner and nothing else would satisfy leg 2. These
# fields are what make the dump worth having.
MISSING=""
echo "$LOG" | grep -q "Interrupted task state" || MISSING="$MISSING interrupted-state"
echo "$LOG" | grep -qE "EIP=0x[0-9a-f]{8}" || MISSING="$MISSING eip"
echo "$LOG" | grep -q "dedicated stack"     || MISSING="$MISSING dedicated-stack"
echo "$LOG" | grep -q "Backlink"            || MISSING="$MISSING backlink"
if [ -n "$MISSING" ]; then
    echo "RESULT: FAIL — the #DF dump is missing fields:$MISSING"
    exit 1
fi

# The stack-exhaustion tell. dftest blows the stack by construction, so if the
# handler cannot recognise that, its diagnosis is wrong even though it printed.
# Either NOTE branch is a correct diagnosis: "is the cause" when ESP ran
# past the stack base (what dftest does), "is the likely cause" when it is
# merely deep. Matching only one wording FAILs a correct kernel.
if ! echo "$LOG" | grep -qE "stack exhaustion is (the|the likely) cause"; then
    echo "RESULT: FAIL — handler ran but did not identify stack exhaustion."
    echo "  dftest exhausts the kernel stack by construction, so the ESP/esp0"
    echo "  same-page test should have fired. Check the heuristic."
    exit 1
fi

echo "RESULT: PASS — kernel stack exhaustion delivers a #DF on the dedicated"
echo "        stack, prints full forensics, and the CPU never triple-faults."
exit 0
