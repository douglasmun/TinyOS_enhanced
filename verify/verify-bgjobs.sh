#!/usr/bin/env bash
#
# verify-bgjobs.sh — FULLY AUTOMATED background-jobs check.
#
# Same headless first-boot drive as auto-verify-exec.sh, but the shell command
# under test is `exec /sleeper.elf &`. sleeper.elf runs for ~6 seconds, so the
# shell regains its prompt while the child is STILL ALIVE — which is the only
# way `jobs` and `ps` can prove backgrounding actually worked. With hello.elf
# (milliseconds) the child would always be reaped before the next command ran,
# and an empty `jobs` would be indistinguishable from a broken implementation.
#
# PASS requires all of:
#   - "[<pid>] sleeper.elf"     — cmd_exec returned immediately (didn't block)
#   - "Sleeper started"         — the child actually ran
#   - `jobs` lists the child    — parent_pid/generation matching works
#   - "Sleeper done"            — the child finished on its own afterwards
#   - zero triple faults
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: bgjobs.log (serial),
# bgjobs-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=bgjobs.log
TRACE=bgjobs-trace.log
RUN_DISK=/tmp/tinyos-bgjobs-disk.img
MON_SOCK=/tmp/tinyos-bgjobs-mon.sock

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
# The first command is the backgrounded exec; its expect is "Sleeper started"
# (proof the child ran), then `jobs` runs WHILE it is still sleeping.
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_EXEC_CMD="exec /sleeper.elf &" \
TINYOS_EXPECT="Sleeper started" \
TINYOS_FOLLOWUP_CMDS="jobs=>sleeper.elf;ps" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

# The child still has seconds of sleep left; wait it out so "Sleeper done"
# (clean exit of an unwaited background job) lands in the log.
sleep 12
cleanup
trap - EXIT

echo
echo "================ VERDICT ================"
count() { c=$(grep -c "$1" "$SERIAL" 2>/dev/null); [ -n "$c" ] && echo "$c" || echo 0; }

if grep -q "Triple fault" "$TRACE" 2>/dev/null; then
    echo "RESULT: FAIL — 'Triple fault' in $TRACE"
    grep -E "check_exception|v=0e|v=08|Triple fault|^EIP=|CR2=" "$TRACE" | tail -15
    exit 1
fi

started=$(count 'Sleeper started')
done_=$(count 'Sleeper done')
# The "[pid] name" acknowledgement cmd_exec prints for a backgrounded launch.
bgack=$(grep -cE '^\[[0-9]+\] sleeper\.elf' "$SERIAL" 2>/dev/null || echo 0)

if [ "$bgack" -gt 0 ] && [ "$started" -gt 0 ] && [ "$done_" -gt 0 ] && [ "$TYPIST_RC" -eq 0 ]; then
    echo "RESULT: PASS — backgrounded, listed by jobs, and completed independently"
    grep -E '^\[[0-9]+\] sleeper|Sleeper started|Sleeper done|PID' "$SERIAL" | tail -20
    exit 0
else
    echo "RESULT: FAIL/INCONCLUSIVE (typist rc=$TYPIST_RC; bgack=$bgack started=$started done=$done_)"
    echo "--- tail of $SERIAL ---"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi
