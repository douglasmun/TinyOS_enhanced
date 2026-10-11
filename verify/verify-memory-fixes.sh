#!/usr/bin/env bash
#
# verify-memory-fixes.sh -- two task-creation failure paths, forced.
#
# F1  task_create_user_argv()'s argv-does-not-fit branch restored CR3, freed
#     the slot and returned -1. By then the task owned a kernel guard page,
#     eight kernel stack pages, a user guard page, its user stack and a whole
#     PDPT -- all leaked. Fix: task_free_resources() before the slot goes.
#
# F2  pae_create_user_pdpt() called kernel_panic() when a frame allocation
#     failed. Its comment called that "boot-critical", but it runs for every
#     user task (every exec and spawn): any user able to exhaust memory took
#     the kernel down by starting one more program. Fix: free what was taken
#     and return 0; every caller already handles 0.
#
# HOW IT IS WITNESSED. Neither path is reachable by input -- the argv limits
# keep the block far below a page, and real OOM is not a test. `memunwind` (a
# TINYOS_FAULT_INJECT kernel-shell command, absent from `help`; see
# task_memunwind_test() in process.c) forces each failure and measures
# pmm_free_frames() across the failed creation:
#
#   argv-nofit  the argv branch forced                      (F1)
#   pdpt-alloc  the PDPT's own frame allocation fails       (F2)
#   pd1-alloc   PD[1]'s allocation fails, PDPT and PD[0]    (F2: the partial
#               already taken                                unwind)
#
# Each leg is tried three times; it is clean if any try returns every frame
# (other tasks allocate concurrently). "fault NOT-FIRED" means the injection
# never reached its path -- a harness problem, never a pass.
#
# Negative control (unfixed tree): argv-nofit leaks every try, and pdpt-alloc
# panics the kernel.
#
# NB: `make clean`s on exit -- TINYOS_FAULT_INJECT objects must not linger.
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=memory-fixes.log
TRACE=memory-fixes-trace.log
MON_SOCK=/tmp/tinyos-memfixes-mon.sock

guard_fail() { echo "RESULT: INCONCLUSIVE — $*"; exit 2; }

grep -q "task_memunwind_test" src/process.c \
    || guard_fail "src/process.c has no task_memunwind_test()"
grep -q '"memunwind"' src/shell.c \
    || guard_fail "src/shell.c has no memunwind command"

echo "==> Building kernel + ISO (TINYOS_FAULT_INJECT)..."
make clean >/dev/null 2>&1
make EXTRA_CFLAGS=-DTINYOS_FAULT_INJECT >/dev/null || guard_fail "build failed"
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || guard_fail "mkrescue failed"

rm -f "$SERIAL" "$TRACE" "$MON_SOCK"

echo "==> Launching headless QEMU..."
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none 2>/dev/null &
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
TINYOS_EXEC_CMD="memunwind" \
TINYOS_EXPECT="[MEMUNWIND] VERDICT" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup
trap - EXIT

echo ""
echo "================ VERDICT ================"

[ -s "$SERIAL" ] || guard_fail "no serial output (typist rc=$TYPIST_RC)"
if grep -qa "Triple fault\|triple fault" "$TRACE" 2>/dev/null; then
    echo "RESULT: FAIL — the kernel triple-faulted during the run"
    exit 1
fi

OUT=$(tr -d '\r' < "$SERIAL" | grep -a "\[MEMUNWIND\]")
[ -n "$OUT" ] || guard_fail "memunwind produced no output (typist rc=$TYPIST_RC)"
echo "$OUT"
echo ""

FAILS=()
note_fail() { FAILS+=("$1"); }

if tr -d '\r' < "$SERIAL" | grep -qa "KERNEL PANIC"; then
    note_fail "the kernel panicked: $(tr -d '\r' < "$SERIAL" | grep -a -A2 'KERNEL PANIC' | head -3 | tr '\n' ' ')"
fi

for leg in argv-nofit pdpt-alloc pd1-alloc; do
    LINE=$(printf '%s\n' "$OUT" | grep -a "\] $leg: " | tail -1)
    if [ -z "$LINE" ]; then
        # After a panic the later legs never print; the panic is the finding.
        [ "${#FAILS[@]}" -gt 0 ] && continue
        guard_fail "$leg never reported"
    fi
    case "$LINE" in
        *"fault NOT-FIRED"*) guard_fail "$leg: the injected failure never reached its path: $LINE" ;;
    esac
    DELTAS=$(printf '%s\n' "$LINE" | sed 's/.*deltas \([-0-9]* [-0-9]* [-0-9]*\).*/\1/')
    case " $DELTAS " in
        *" 0 "*) ;;
        *) note_fail "$leg: every try lost frames (free-frame deltas $DELTAS)" ;;
    esac
done

if [ "${#FAILS[@]}" -eq 0 ] && ! printf '%s\n' "$OUT" | grep -q "VERDICT: PASS"; then
    guard_fail "the legs passed but the kernel's verdict did not"
fi

if [ "${#FAILS[@]}" -gt 0 ]; then
    echo "RESULT: FAIL — ${#FAILS[@]} assertion(s)"
    for f in "${FAILS[@]}"; do echo "  - $f"; done
    exit 1
fi

echo "RESULT: PASS"
echo "  - F1: a forced argv-does-not-fit failure returned every frame"
echo "  - F2: PDPT and PD allocation failures returned 0 and their frames; no panic"
exit 0
