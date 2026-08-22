#!/usr/bin/env bash
#
# verify-editor-rowfail.sh — does editor_insert_row() double-free on OOM?
#
# THE BUG. editor_insert_row() used to shift the row array down BEFORE
# allocating:
#
#     for (i = E.numrows; i > at; i--) E.rows[i] = E.rows[i-1];
#     E.rows[at].chars = pmm_alloc();
#     if (!E.rows[at].chars) { status("Out of memory"); return; }
#
# The shift makes E.rows[at] a bitwise copy of E.rows[at+1] -- same `chars`,
# same `render`. The failure return leaves that aliasing in place, and both
# slots sit below E.numrows, so editor_cleanup()'s per-row editor_free_row()
# hands the SAME frames to pmm_free() twice.
#
# WHAT THAT ACTUALLY COSTS (measured, not predicted). pmm_free() has a
# double-free guard at pmm.c:963 which detects the second free and returns
# without freeing, so this does NOT degrade into frame aliasing. Running this
# harness against the unfixed kernel gives, per failed mid-file insert:
#
#     [PMM] CRITICAL: Double-free detected at physical address 0x004a9000
#     [ROWTEST] arm2 FAIL: chars-alloc failure 64300 -> 64298 (leak)
#     [ROWTEST] arm4 FAIL: rows disturbed (numrows=3 row1=(null))
#
# i.e. 2 frames permanently lost (the refused frees never return them) AND a
# surviving row destroyed -- the row that was at `at` reads back NULL, because
# the failed slot's pointers were written over it. So the user-visible harm is
# silent loss of a line of text after any OOM hiccup while editing, with a
# slow frame leak alongside. Note the counter goes DOWN, not up: the guard is
# the reason. Any future rewrite that removes the guard restores the aliasing.
#
# WHY THIS HID. editor_insert_row has four callers. THREE of them append at
# E.numrows, where the shift loop body never runs and no alias is created.
# Only the mid-file insert (Enter pressed inside the file:
# at = E.cy + E.rowoff + 1) actually shifts. Any test built from the common
# path passes against the unfixed kernel. Every arm below therefore inserts at
# index 1 of a 3-row buffer.
#
# WHY IT NEEDS FAULT INJECTION. The path is reachable only when pmm_alloc()
# fails. Producing genuine PMM exhaustion under QEMU would disturb everything
# else being measured (and the editor costs 8 KB per line, so it is a slow way
# to get there). TINYOS_FAULT_INJECT adds editor_fail_next_alloc(n), which
# fails the n-th allocation inside editor_insert_row exactly once -- arm 2
# fails `chars`, arm 3 fails `render`. Those were SEPARATE defects with
# separate consequences, so both are driven.
#
# WHAT IS ASSERTED. pmm_free_frames() bracketing each arm, requiring EXACT
# return to baseline:
#     after < base  -> allocated and never freed: this bug, or a plain leak
#     after > base  -> freed more often than allocated, which is what the same
#                      aliasing would produce on a kernel whose PMM guard was
#                      removed or bypassed
#     after == base -> the freed set is precisely the allocated set
# Exact equality BOTH ways is the point: a one-sided check passes against
# whichever direction it does not test.
#
# POSITIVE CONTROL. Arm 1 runs with no injection and asserts the 3-row build
# actually CONSUMES frames. Without it, an editor that allocated nothing (or a
# rowtest that silently no-op'd) would satisfy every "balanced" assertion
# trivially. Arm 4 is the other half: balanced accounting alone would also be
# satisfied by a failure path that dropped or mangled surviving rows, so it
# checks the 3 existing rows are untouched and row 1 still reads "beta".
#
# `rowtest` is a kernel-shell command that exists ONLY under
# TINYOS_FAULT_INJECT and is deliberately absent from the command table, so it
# never shows in `help` and never ships in a normal build.
#
# NB: this script `make clean`s on exit. TINYOS_FAULT_INJECT is not in the
# dependency graph, so leaving its objects behind breaks the OTHER harnesses
# at link time -- the same trap verify-supervisor.sh documents.
#
# Exit 0 = PASS, 1 = FAIL (double free or leak), 2 = harness/setup problem.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=rowfail.log
TRACE=rowfail-trace.log
MON_SOCK=/tmp/tinyos-rowfail-mon.sock

guard_fail() { echo "HARNESS GUARD FAILED: $*"; exit 2; }

# Guard: the hook must exist, or every arm below grades the success path.
grep -q "editor_fail_next_alloc" src/editor.c \
    || guard_fail "src/editor.c has no editor_fail_next_alloc hook; the
failure path cannot be reached and arms 2-4 would silently test nothing."
grep -q "rowtest" src/shell.c \
    || guard_fail "src/shell.c has no rowtest command; the guest cannot be
driven and the typist would sit on an unknown-command error."

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

# `rowtest` is a kernel-shell command, so TINYOS_STAY_IN_RING3 is deliberately
# NOT set here: the typist's default route to kshell is the correct one. The
# thing under test is a kernel-internal allocator invariant, not a ring-3
# boundary. (This is the documented exception to the ring-3 harness rule.)
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="rowtest" \
TINYOS_EXPECT="ROWTEST. VERDICT" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
[ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: harness problem — no serial output at all (typist rc=$TYPIST_RC)"
    exit 2
fi

if grep -q "Triple fault" "$TRACE" 2>/dev/null; then
    grep -E "check_exception|v=0e|v=08|Triple fault|^EIP=|CR2=" "$TRACE" | tail -15
    echo "RESULT: harness problem — triple fault during the run"
    exit 2
fi

# CRLF: strip with tr, never a \r\? pattern (grep here is ugrep).
OUT=$(tr -d '\r' < "$SERIAL" | grep "ROWTEST")
if [ -z "$OUT" ]; then
    echo "RESULT: harness problem — rowtest produced no output."
    echo "  Check the typist reached the kernel shell as root."
    tr -d '\r' < "$SERIAL" | grep -v Suspicious | tail -25
    exit 2
fi

echo "$OUT"
echo ""

# The control arm must have MOVED the counter. If it did not, every "balanced"
# assertion below is vacuous and the run proves nothing.
if echo "$OUT" | grep -q "CONTROL-DEAD"; then
    echo "RESULT: harness problem — the positive control allocated nothing."
    echo "  editor_insert_row is not doing what the arms assume; the balanced"
    echo "  results from arms 2-4 are vacuous and must NOT be read as a pass."
    exit 2
fi
echo "$OUT" | grep -q "arm1 control:" || {
    echo "RESULT: harness problem — no control line; cannot confirm the arms measure anything."
    exit 2
}

# All four arms must have reported.
for arm in arm1 arm2 arm3 arm4; do
    echo "$OUT" | grep -q "$arm " || {
        echo "RESULT: harness problem — $arm never reported (run truncated?)"
        exit 2
    }
done

if echo "$OUT" | grep -q "VERDICT: PASS"; then
    echo "RESULT: PASS — allocation-failure path is frame-balanced and non-destructive."
    echo ""
    echo "  Arm 1 proves the sequence really allocates (control), arms 2 and 3"
    echo "  drive the chars- and render-alloc failures on a MID-FILE insert --"
    echo "  the only shape that shifts -- and both return exactly to baseline."
    echo "  Arm 4 proves the failed insert left the surviving rows intact."
    exit 0
fi

# The PMM's own guard is independent evidence, and it names the frame. Check
# it separately from the counter arms: if it fires, the aliasing is present
# regardless of what the arithmetic says.
if tr -d '\r' < "$SERIAL" | grep -q "Double-free detected"; then
    echo "RESULT: FAIL — the PMM's double-free guard fired."
    echo ""
    tr -d '\r' < "$SERIAL" | grep "Double-free detected" | head -4
    echo ""
    echo "  editor_cleanup() handed one frame to pmm_free() twice: the"
    echo "  shift-before-allocate aliasing in editor_insert_row(). The guard"
    echo "  refuses the second free, which is why the frame counters FALL"
    echo "  (frames lost) rather than rise. A row of the user's text is also"
    echo "  destroyed -- see the arm4 line."
    exit 1
fi

if echo "$OUT" | grep -q "DOUBLE FREE"; then
    echo "RESULT: FAIL — frames freed more often than allocated."
    echo "  Free frames rose above baseline, so the PMM guard did not catch"
    echo "  the second free. Check whether pmm.c's guard is still in place."
    exit 1
fi

echo "RESULT: FAIL — see the arm lines above."
exit 1
