#!/usr/bin/env bash
#
# verify-pipes-exec.sh — regression test for the console-capture hook leaking
# across a BLOCKING pipeline stage.
#
# Runs:
#
#     exec /hello.elf | cat -n
#
# `exec` is the important stage: cmd_exec calls sys_waitpid(), which sleeps on a
# wait queue and YIELDS.  The first version of the capture hook was a plain
# global with no notion of who installed it, justified by "the hook is set and
# cleared without yielding in between".  That is false for exec.  While the
# shell sat blocked in waitpid, EVERY other task's kprintf -- EDR alerts, timer
# softirq logging, and kernel PANIC messages -- was diverted into a 4KB pipe
# buffer and silently dropped once it filled.
#
# The fix binds the hook to the installing task and consults it only while that
# task is running.  This harness pins the resulting behaviour:
#
#   1. THE REGRESSION: kernel logging emitted while the CHILD task runs -- the
#      [SYSCALL] traces from hello.elf's own syscalls, plus the [PAGING]/[PAE]
#      teardown after it exits -- must reach the console unnumbered.  With the
#      old global hook every one of these was diverted into the shell's 4KB pipe
#      while the shell sat blocked in sys_waitpid.  A NUMBERED [SYSCALL] line
#      means the hook is capturing output produced on another task's behalf.
#
#      This is the signal to key on precisely because it lands INSIDE the
#      blocking window.  An earlier draft asserted on [EDR] lines instead and
#      passed against the known-buggy build: all EDR logging happens at boot,
#      hundreds of lines before the pipeline runs, so the window it examined was
#      empty.  A regression test that cannot fail is worse than none.
#
#   2. The shell's own pre-block message ("[EXEC] Waiting") is produced by the
#      shell task itself with the hook installed, so it MUST be captured and
#      come back out numbered.  Without this check the test would also pass with
#      capture disabled entirely, which is the trivial way to satisfy (1).
#
#   3. No kernel panic / triple fault.
#
# Together those make the test fail in both directions: too much capture breaks
# (1), too little breaks (2).
#
# NOT asserted, deliberately: hello.elf's own "Hello from ELF!" IS numbered, and
# that is correct.  The child inherits the shell's stream context at load time
# (streams_inherit), so its stdout is legitimately bound to the pipe and its
# SYS_WRITE goes through the stream layer, not the capture hook.  `exec prog |
# cat` piping the child's stdout is the whole point of a pipeline.  An earlier
# draft of this harness asserted the opposite and failed on correct behaviour.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: pipes-exec.log (serial),
# pipes-exec-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=pipes-exec.log
TRACE=pipes-exec-trace.log
RUN_DISK=/tmp/tinyos-pipesexec-disk.img
MON_SOCK=/tmp/tinyos-pipesexec-mon.sock

echo "==> Building kernel + ISO..."
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

echo "==> Fresh BLANK disk (forces first-boot password setup)"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
dd if=/dev/zero of="$RUN_DISK" bs=1m count=128 status=none

echo "==> Launching headless QEMU (monitor on $MON_SOCK)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

echo "==> Driving the boot flow (ECDSA verify under TCG is slow; be patient)..."
# Wait for the child's exit message: by then the shell has been through the
# whole block/resume cycle, which is the window under test.
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_EXEC_CMD="exec /hello.elf | cat -n" \
TINYOS_EXPECT="ELF program exiting" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup
trap - EXIT

echo
echo "================ VERDICT ================"

if grep -q "Triple fault" "$TRACE" 2>/dev/null; then
    echo "RESULT: FAIL — 'Triple fault' in $TRACE"
    grep -E "check_exception|v=0e|v=08|Triple fault|^EIP=|CR2=" "$TRACE" | tail -15
    exit 1
fi

if grep -qE "KERNEL PANIC" "$SERIAL" 2>/dev/null; then
    echo "RESULT: FAIL — kernel panic during the piped exec"
    grep -E "KERNEL PANIC" -A5 "$SERIAL" | tail -20
    exit 1
fi

# The child must have actually run; otherwise the rest proves nothing.
if ! grep -q "Hello from ELF!" "$SERIAL" 2>/dev/null; then
    echo "RESULT: FAIL/INCONCLUSIVE (typist rc=$TYPIST_RC) — hello.elf never ran"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi

# (1) THE REGRESSION: kernel logging produced while the CHILD runs must not be
#     captured.  These lines land inside the blocking window by construction --
#     hello.elf cannot make a syscall before exec starts waiting, nor can its
#     address space be torn down after the wait returns.
#
#     Scoped to the window between "[EXEC] Waiting" and "[EXEC] Process
#     completed".  Kernel logging BEFORE the wait ([PAE] building the child's
#     page tables) is emitted synchronously by the shell task itself, so it is
#     legitimately captured and must not be counted -- an unscoped grep flags
#     that correct output and fails a correct build.
win_start=$(grep -nE "\[EXEC\] Waiting" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
win_end=$(grep -nE "\[EXEC\] Process completed" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
if [ -z "$win_start" ] || [ -z "$win_end" ] || [ "$win_end" -le "$win_start" ]; then
    echo "RESULT: FAIL/INCONCLUSIVE — could not locate the blocking window"
    echo "  (start=${win_start:-none} end=${win_end:-none}); exec may not have run."
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi

leaked=$(sed -n "${win_start},${win_end}p" "$SERIAL" \
         | grep -cE "^[[:space:]]*[0-9]+[[:space:]]+\[(SYSCALL|PAGING|PAE)\]")
if [ "${leaked:-0}" -gt 0 ]; then
    echo "RESULT: FAIL — capture hook leaked across the blocking stage"
    echo "  $leaked line(s) of kernel logging emitted on another task's behalf"
    echo "  were diverted into the shell's pipe while it sat blocked in waitpid."
    echo "  With a full pipe these are dropped outright — including panics."
    sed -n "${win_start},${win_end}p" "$SERIAL" \
        | grep -E "^[[:space:]]*[0-9]+[[:space:]]+\[(SYSCALL|PAGING|PAE)\]" | head -5
    exit 2
fi

# Corollary: this kernel logging must EXIST somewhere unnumbered, otherwise the
# build emits none at all and (1) is vacuous.  The buggy build produced 29 such
# lines numbered; the fixed build produces them on the console instead.
if ! grep -qE "^\[(SYSCALL|PAGING|PAE)\]" "$SERIAL" 2>/dev/null; then
    echo "RESULT: INCONCLUSIVE — no unnumbered [SYSCALL]/[PAGING]/[PAE] logging,"
    echo "  so there was no kernel output to distinguish captured from not."
    echo "  (Was kernel logging compiled out?)"
    exit 3
fi

# (2) The shell's OWN pre-block line must still be captured, or capture is
#     simply off and check (1) is vacuous.
if ! grep -qE "[0-9]+[[:space:]]+\[EXEC\] Waiting" "$SERIAL" 2>/dev/null; then
    echo "RESULT: FAIL — the shell's own output was NOT captured into the pipe"
    echo "  Expected a numbered '[EXEC] Waiting...' line from cat -n."
    echo "  Capture is off or the owner check is too strict; check (1) proves"
    echo "  nothing in this state."
    grep -E "\[EXEC\]" "$SERIAL" | head -10
    exit 2
fi

if [ "$TYPIST_RC" -eq 0 ]; then
    echo "RESULT: PASS — capture stayed bound to the shell across the blocking stage"
    echo "  captured (shell's own output, numbered):"
    grep -E "[0-9]+[[:space:]]+\[EXEC\] Waiting" "$SERIAL" | head -2
    echo "  NOT captured (kernel logging during the block, plain — $(grep -cE '^\[(SYSCALL|PAGING|PAE)\]' "$SERIAL") lines):"
    grep -E "^\[(SYSCALL|PAGING|PAE)\]" "$SERIAL" | head -2
    exit 0
else
    echo "RESULT: FAIL (typist rc=$TYPIST_RC despite the expected lines being present)"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi
