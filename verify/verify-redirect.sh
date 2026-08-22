#!/usr/bin/env bash
#
# verify-redirect.sh — FULLY AUTOMATED fd-aware I/O check.
#
# Same headless first-boot drive as auto-verify-exec.sh, but instead of running
# hello.elf straight to the console it runs
#
#     exec /hello.elf > /out.txt
#     cat /out.txt
#
# which is the end-to-end proof that PR-A actually did something:
#
#   - sys_write must honour fd and route through the calling task's
#     stream_context_t (it used to discard fd and always console_putc), and
#   - cmd_exec must hand the child the shell's streams (a freshly created task
#     is streams_init'd to the console), and
#   - the shell must bind `>` to stdout_stream at all (has_output_redir was
#     computed and never used, so `>` silently did nothing).
#
# Break any one of those and hello.elf's output goes to the console instead of
# the file, so /out.txt comes back empty and `cat` prints nothing.
#
# PASS requires:
#   - "Hello from ELF!" appears AFTER the `cat /out.txt` command  (came from
#     the file, not from the original exec — the exec itself must NOT have
#     printed it to the console)
#   - zero triple faults
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: redirect.log (serial),
# redirect-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=redirect.log
TRACE=redirect-trace.log
RUN_DISK=/tmp/tinyos-redirect-disk.img
MON_SOCK=/tmp/tinyos-redirect-mon.sock

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
# The redirected exec prints nothing to the console, so there is no output to
# wait on; a kernel-side marker has to stand in for it. It must be the marker
# that means the SHELL IS READY AGAIN, not merely that the child died:
# "Process exited" is printed from the exit syscall, with the whole teardown
# (task reap, page-directory and PDPT free) still to come, and keystrokes sent
# in that window are dropped because nothing is in read() yet. "[EXEC] Process
# completed" is the last line cmd_exec prints before it returns to the prompt.
# `cat` then has to produce the text from the file.
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_EXEC_CMD="exec /hello.elf > /out.txt" \
TINYOS_EXPECT="[EXEC] Process completed" \
TINYOS_FOLLOWUP_CMDS="cat /out.txt=>Hello from ELF" \
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

# The decisive check: "Hello from ELF!" must appear only AFTER the cat command
# echoes. If it shows up before, the write bypassed the file and went to the
# console, meaning redirection did not take effect.
# Both greps must read the SAME file or the line numbers are not comparable,
# and that file must be the REJOINED one. The `cat /out.txt` echo is typed
# text, so the EDR burst tears it ("$ cat /ou" + burst + "t.txt") and a raw
# grep returns cat_line=none -- reported as FAIL/INCONCLUSIVE against a kernel
# that redirected correctly and printed the file. Measured on a real run:
# raw match 0, rejoined match 1. "Hello from ELF" is kernel output on its own
# line and survives either way, which is exactly why only one half of the
# comparison looked broken.
. "$(dirname "$0")/edr-rejoin.sh"
REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"

cat_line=$(grep -n "cat /out.txt" "$REJOINED" 2>/dev/null | head -1 | cut -d: -f1)
hello_line=$(grep -n "Hello from ELF" "$REJOINED" 2>/dev/null | head -1 | cut -d: -f1)

if [ -z "$cat_line" ] || [ -z "$hello_line" ]; then
    echo "RESULT: FAIL/INCONCLUSIVE (typist rc=$TYPIST_RC; cat_line=${cat_line:-none} hello_line=${hello_line:-none})"
    echo "--- tail of $SERIAL ---"
    grep -v "Suspicious" "$REJOINED" | tail -30
    exit 2
fi

if [ "$TYPIST_RC" -eq 0 ] && [ "$hello_line" -gt "$cat_line" ]; then
    echo "RESULT: PASS — exec output went to /out.txt, not the console"
    echo "  (cat at serial line $cat_line, first 'Hello from ELF' at $hello_line)"
    exit 0
else
    echo "RESULT: FAIL (typist rc=$TYPIST_RC; 'Hello from ELF' at line $hello_line, cat at $cat_line)"
    echo "  If hello_line < cat_line, output reached the console => redirection did not apply."
    grep -v "Suspicious" "$REJOINED" | tail -30
    exit 2
fi
