#!/usr/bin/env bash
#
# verify-pipes.sh — FULLY AUTOMATED shell-pipeline check.
#
# Same headless first-boot drive as auto-verify-exec.sh, but runs
#
#     echo pipeworks | cat
#
# and requires the string to come back out of the LAST stage.
#
# Why that one line proves the whole chain:
#
#   - run_pipeline() must split the line on '|' and run two stages;
#   - the console-capture hook (kprintf_set_capture) must divert stage 1's
#     output into the pipe -- cmd_echo prints with kprintf, so WITHOUT the hook
#     "pipeworks" goes straight to the console and the pipe carries nothing;
#   - pipe_write/pipe_read must move the bytes, and pipe_close_write must let
#     the reader see EOF rather than blocking;
#   - stdin_read()'s STREAM_TYPE_PIPE case must feed cmd_cat, which must accept
#     a pipe as stdin (stdin_is_pipe) instead of rejecting it as "keyboard";
#   - the hook must be REMOVED before the last stage, so its output reaches the
#     console at all.
#
# The trap this harness is built around: "pipeworks" appearing on the console is
# NOT sufficient -- stage 1 printing straight past the pipe produces exactly the
# same visible string.  So the test greps for a marker that can only exist if
# cat actually ran and emitted it, and separately requires the shell NOT to have
# reported the pipeline as unsupported/truncated.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: pipes.log (serial),
# pipes-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=pipes.log
TRACE=pipes-trace.log
RUN_DISK=/tmp/tinyos-pipes-disk.img
MON_SOCK=/tmp/tinyos-pipes-mon.sock

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

echo "==> Driving the boot flow (slow under TCG; be patient)..."
# "-n" makes cat number the line, so the output carries a marker that ONLY cat
# can produce.  If the hook failed and echo printed straight to the console we
# would still see "pipeworks", but never the "     1  " prefix.
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_EXEC_CMD="echo pipeworks | cat -n" \
TINYOS_EXPECT="1  pipeworks" \
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

# The load-bearing assertion: the numbered line can only come from cmd_cat, so
# its presence proves the bytes travelled echo -> pipe -> cat.
if ! grep -qE "1[[:space:]]+pipeworks" "$SERIAL" 2>/dev/null; then
    echo "RESULT: FAIL/INCONCLUSIVE (typist rc=$TYPIST_RC) — cat never emitted the piped line"
    if grep -q "pipeworks" "$SERIAL" 2>/dev/null; then
        echo "  NOTE: 'pipeworks' IS present but unnumbered — stage 1 printed straight"
        echo "        to the console, i.e. the capture hook did not divert it."
    fi
    echo "--- tail of $SERIAL ---"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi

# The shell must not have bailed out or lost data on the way.
if grep -qE "shell: (syntax error near|invalid pipeline|cannot run pipeline)" "$SERIAL" 2>/dev/null; then
    echo "RESULT: FAIL — shell rejected the pipeline"
    grep "shell: " "$SERIAL" | tail -10
    exit 2
fi

if grep -q "output truncated" "$SERIAL" 2>/dev/null; then
    echo "RESULT: FAIL — pipeline dropped output on a one-line payload"
    grep "output truncated" "$SERIAL" | tail -5
    exit 2
fi

# "not supported" would mean cmd_cat still rejected the pipe as a keyboard.
if grep -q "reading from keyboard not supported" "$SERIAL" 2>/dev/null; then
    echo "RESULT: FAIL — cat rejected the pipe as keyboard input"
    exit 2
fi

if [ "$TYPIST_RC" -eq 0 ]; then
    echo "RESULT: PASS — echo | cat carried data through the pipe"
    grep -E "1[[:space:]]+pipeworks" "$SERIAL" | head -3
    exit 0
else
    echo "RESULT: FAIL (typist rc=$TYPIST_RC despite the expected line being present)"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi
