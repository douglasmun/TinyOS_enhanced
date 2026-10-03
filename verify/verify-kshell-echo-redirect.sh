#!/bin/bash
# =============================================================================
# verify-kshell-echo-redirect.sh -- the kernel shell's `echo` honours `>`.
#
# WHAT THIS PROVES
#
# cmd_echo wrote with kprintf, which goes to the console whatever the
# command's streams say. `echo hello > /scratch/sq.elf` created the file (the
# redirection layer opened it) and printed "hello" on the console, leaving the
# file EMPTY. Every other builtin had moved to stream_printf; echo was missed.
#
#   echo kecho-alpha > /scratch/ke.txt     the marker must NOT reach the
#                                          console here
#   cat /scratch/ke.txt                    ...and MUST come back here
#
# Graded by position, not presence -- the marker is on screen either way, the
# question is which command printed it:
#
#   between the echo and the cat   fixed: 0   broken: 1
#   after the cat                  fixed: 1   broken: 0   (POSITIVE CONTROL)
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: kecho.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
ISO=dist/tinyos.iso
SERIAL=kecho.log
TRACE=kecho-trace.log
RUN_DISK=/tmp/tinyos-kecho-disk.img
MON_SOCK=/tmp/tinyos-kecho-mon.sock
MARK=kecho-alpha

echo "==> Building kernel + ISO..."
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

echo "==> Launching headless QEMU"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!
cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# No expect on the echo or the cat: on a broken kernel the cat prints nothing,
# and on a fixed one the echo does. The `id` after each is the barrier.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
echo $MARK > /scratch/ke.txt;\
id=>uid=0;\
cat /scratch/ke.txt;\
id=>uid=0" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 2
cleanup

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

LOG=$(tr -d '\r' < "$SERIAL")
E=$(printf '%s\n' "$LOG" | grep -nF "echo $MARK > /scratch/ke.txt" | head -1 | cut -d: -f1)
C=$(printf '%s\n' "$LOG" | grep -nF "cat /scratch/ke.txt" | head -1 | cut -d: -f1)
[ -n "$E" ] && [ -n "$C" ] && [ "$C" -gt "$E" ] \
    || { echo "RESULT: INCONCLUSIVE — could not find both commands (echo=${E:-none} cat=${C:-none})"; exit 3; }

# A line that is exactly the marker; the command echoes carry it mid-line.
BETWEEN=$(printf '%s\n' "$LOG" | sed -n "$((E + 1)),$((C - 1))p" | grep -cx "$MARK")
AFTER=$(printf '%s\n' "$LOG" | sed -n "$((C + 1)),\$p" | grep -c "^$MARK")

echo "  marker between echo and cat: $BETWEEN (expected 0)"
echo "  marker after cat:            $AFTER (expected 1)"

if [ "$BETWEEN" -ne 0 ]; then
    echo "RESULT: FAIL — echo ignored '>' and printed to the console"
    exit 1
fi
if [ "$AFTER" -lt 1 ]; then
    echo "RESULT: FAIL — the file does not hold what echo was told to write"
    exit 1
fi
echo "RESULT: PASS — echo wrote to the file and printed nothing"
exit 0
