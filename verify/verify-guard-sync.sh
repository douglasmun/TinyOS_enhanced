#!/usr/bin/env bash
#
# verify-guard-sync.sh -- do PRIVATE page-table copies track kernel guard pages?
#
# THE BUG. A user PDPT shares the kernel's page tables for the RAM identity
# map until pae_map_page_into() puts a user page in a 2 MB range; then that
# range's table is COPIED into a private one. The copy is a snapshot.
# guard_page_mark() and guard_page_release() edit only the kernel tables
# (98491d0 moved them there), so:
#
#   - a copy taken while some task's guard page was not-present kept that
#     entry not-present after the guard was released and the frame went back
#     to the PMM. The next kernel use of the frame under that CR3 -- any
#     object the allocator hands out -- took a ring-0 #PF: the 98491d0 panic,
#     reached by a different route.
#   - a copy taken before a guard was marked never saw it: a stack overflow
#     into the guard under that CR3 wrote a live frame instead of faulting.
#
# HOW IT IS WITNESSED. Racing real allocations into the one 2 MB range a
# process happens to have copied is luck, not a test. `guardsync` (a
# TINYOS_FAULT_INJECT kernel-shell command, absent from `help`) drives the
# real guard_page_mark()/guard_page_release() against a scratch PDPT that is
# never loaded into CR3 -- see task_guardsync_test() in process.c:
#
#   arm1  copy taken while the guard is absent; after release it must be present
#   arm2  copy taken before the guard is marked; it must see mark AND release
#   arm3  a guard frame that is a USER address in the copy: the user mapping
#         must survive both (the fix must only touch identity entries)
#
# Each arm prints a control proving the copy is private and held the arm's
# starting state; CONTROL-DEAD is a harness problem, never a pass.
#
# Negative control: arms 1 and 2 FAIL on the commit before the fix.
# arm3 passes on both -- it guards the fix against overreach.
#
# NB: `make clean`s on exit -- TINYOS_FAULT_INJECT objects must not linger.
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=guardsync.log
TRACE=guardsync-trace.log
MON_SOCK=/tmp/tinyos-guardsync-mon.sock

guard_fail() { echo "HARNESS GUARD FAILED: $*"; exit 2; }

grep -q "task_guardsync_test" src/process.c \
    || guard_fail "src/process.c has no task_guardsync_test()"
grep -q '"guardsync"' src/shell.c \
    || guard_fail "src/shell.c has no guardsync command"

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
TINYOS_EXEC_CMD="guardsync" \
TINYOS_EXPECT="GUARDSYNC. VERDICT" \
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

OUT=$(tr -d '\r' < "$SERIAL" | grep "\[GUARDSYNC\]")
if [ -z "$OUT" ]; then
    echo "RESULT: harness problem — guardsync produced no output."
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
for arm in arm1 arm2 arm3; do
    echo "$OUT" | grep -q "$arm control: ok" || {
        echo "RESULT: harness problem — $arm never reported (run truncated?)"
        exit 2
    }
done
if echo "$OUT" | grep -q "VERDICT: SKIP"; then
    echo "RESULT: harness problem — the test skipped"
    exit 2
fi

# Count the arm results, not just the verdict line: 4 PASS lines, 0 FAIL.
NPASS=$(echo "$OUT" | grep -v VERDICT | grep -c ": PASS$")
NFAIL=$(echo "$OUT" | grep -v VERDICT | grep -c ": FAIL$")
if [ "$NPASS" -eq 4 ] && [ "$NFAIL" -eq 0 ] && echo "$OUT" | grep -q "VERDICT: PASS"; then
    echo "RESULT: PASS — private copies follow guard mark and release; user mappings untouched."
    exit 0
fi
echo "RESULT: FAIL — $NFAIL arm assertion(s) failed (see lines above)."
exit 1
