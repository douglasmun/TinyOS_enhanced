#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-edr-decay-gap.sh — the EDR behavioral "Large decay gap" line is a
# recoverable TRACE, not a per-syscall console print.
#
# THE FIX (PR #174)
#
# edr_behavioral_check() runs on EVERY syscall (syscall.c dispatcher). Its
# decay block printed, with a plain kprintf, a "[EDR BEHAVIORAL] PID N: Large
# decay gap (...)" line whenever a task's score was still non-zero after a
# >1000-tick (>10 s) gap between its syscalls. A ring-3 task reaches that, so
# the line was a per-operation print on the serial stream the kernel console
# and the ring-3 shell share -- the thing CLAUDE.md forbids. The fix demoted
# it to kdbg(): default-suppressed, recoverable at runtime with `loglevel
# debug`, and NEVER a verdict (real detections stay on kprintf via
# edr_raise_alert). See src/kprintf.h for the kdbg/verdict contract.
#
# THE VEHICLE
#
# `edrdecaygap` (TINYOS_FAULT_INJECT kernel-shell command, edr_behavioral.c)
# sets a static task_t shell (PID 9996, never in the task table) to
# anomaly_score=500 with last_decay_tick 1100 ticks in the past, then makes one
# BENIGN syscall (SYS_GETPID trips no detector, so no alert prints). That is the
# only way to hit decay_periods > 10 deterministically -- a real task would have
# to pump its score and then idle ten-plus seconds between syscalls, slow under
# TCG and buried in alert spam. The hook brackets itself with two kprintf
# markers ("EDRDECAY selftest begin/end pid=9996") so this harness can tell "the
# hook ran and the trace stayed silent" from "the hook never ran". Those markers
# are NOT the line under test.
#
# WHY TWO RUNS (the status-surface trap)
#
# Absence alone is not a witness: a kernel that simply DELETED the line would
# also show it absent. So we run the vehicle twice --
#
#   run 1, `loglevel normal` (default): the decay-gap line must be ABSENT
#          (this is the fix's payoff; a kprintf kernel prints it here).
#   run 2, `loglevel debug`           : the decay-gap line must be PRESENT
#          (proves it is a recoverable trace, not deleted).
#
# Each run is isolated between its own begin/end markers. Run 2 is the positive
# control for run 1's exclusion.
#
# AGAINST A BROKEN TREE
#   pre-fix (kprintf): run 1 FAILs -- the line appears at normal loglevel.
#   line-deleted     : run 2 FAILs -- the line never appears, even at debug.
#
# NB: `make clean`s on exit -- TINYOS_FAULT_INJECT objects must not linger.
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=edrdecay.log
TRACE=edrdecay-trace.log
MON_SOCK=/tmp/tinyos-edrdecay-mon.sock

DECAY_RE='\[EDR BEHAVIORAL\] PID 9996: Large decay gap'

guard_fail() { echo "HARNESS GUARD FAILED: $*"; exit 2; }

grep -q "edr_decay_gap_selftest" src/edr_behavioral.c \
    || guard_fail "src/edr_behavioral.c has no edr_decay_gap_selftest()"
grep -q '"edrdecaygap"' src/shell.c \
    || guard_fail "src/shell.c has no edrdecaygap command"
# The line under test must be kdbg(); if someone reverts it to kprintf this
# harness still runs, but flag the obvious regression at the source too.
grep -q 'kdbg("\[EDR BEHAVIORAL\] PID %u: Large decay gap' src/edr_behavioral.c \
    || echo "WARN: decay-gap line is not the expected kdbg() call in source"

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

# Kernel-shell commands: edrdecaygap and loglevel are both kernel-shell only
# (loglevel is require_root; the typist logs in as root). Do NOT set
# TINYOS_STAY_IN_RING3. Sequence:
#   1) edrdecaygap           at normal loglevel  (begin/end markers)
#   2) loglevel debug        (confirms "debug")
#   3) edrdecaygap           at debug loglevel   (begin/end markers)
# Each followup carries its own expect so a slow TCG boot never races the grep.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="edrdecaygap" \
TINYOS_EXPECT="EDRDECAY selftest end pid=9996" \
TINYOS_FOLLOWUP_CMDS="\
loglevel debug=>debug;\
edrdecaygap=>EDRDECAY selftest end pid=9996" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
[ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null

REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: FAIL — no serial output at all (typist rc=$TYPIST_RC)"
    exit 2
fi
if grep -q "Triple fault" "$TRACE" 2>/dev/null || tr -d '\r' < "$REJOINED" | grep -q "KERNEL PANIC"; then
    echo "RESULT: FAIL — the guest faulted"
    exit 1
fi

# Whole kprintf/kdbg lines are not what the EDR tear splits, so the raw log is
# the right source for the markers and the decay line.
RAW=$(tr -d '\r' < "$SERIAL")

# Each edrdecaygap run brackets itself with begin/end markers. Slice run 1
# (lines between the 1st begin and 1st end) and run 2 (2nd begin..2nd end) so a
# line emitted in the debug run cannot be miscounted against the normal run.
slice_run() {  # $1 = occurrence (1 or 2)
    printf '%s\n' "$RAW" | awk -v want="$1" '
        /EDRDECAY selftest begin pid=9996/ { n++; if (n==want) grab=1 }
        grab { print }
        grab && /EDRDECAY selftest end pid=9996/ { exit }'
}
RUN1=$(slice_run 1)
RUN2=$(slice_run 2)

have_marker() { printf '%s\n' "$1" | grep -q "EDRDECAY selftest end pid=9996"; }
has_decay()   { printf '%s\n' "$1" | grep -Eq "$DECAY_RE"; }

echo "  run 1 (loglevel normal): markers $(have_marker "$RUN1" && echo present || echo MISSING), decay line $(has_decay "$RUN1" && echo PRESENT || echo absent)"
echo "  run 2 (loglevel debug) : markers $(have_marker "$RUN2" && echo present || echo MISSING), decay line $(has_decay "$RUN2" && echo present || echo ABSENT)"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }

# The hook must have run both times, or the absence/presence assertions below
# are vacuous (an unrun selftest proves nothing).
have_marker "$RUN1" || fail "edrdecaygap run 1 did not complete (no begin/end markers at normal loglevel)"
have_marker "$RUN2" || fail "edrdecaygap run 2 did not complete (no begin/end markers at debug loglevel)"

# The fix: suppressed at normal loglevel.
if has_decay "$RUN1"; then
    fail "decay-gap line printed at 'loglevel normal' — it is still a kprintf on the per-syscall path (the PR #174 regression)"
fi
# The recoverability: present at debug loglevel (also the positive control that
# proves run 1's absence is suppression, not deletion).
if ! has_decay "$RUN2"; then
    fail "decay-gap line absent even at 'loglevel debug' — the trace was deleted, not demoted (status-surface trap)"
fi

if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS assertion(s); see $SERIAL (typist rc=$TYPIST_RC)"
    exit 1
fi
echo "RESULT: PASS — decay-gap line is suppressed by default and recoverable with 'loglevel debug' (kdbg, not a per-syscall kprintf)"
exit 0
