#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-argv.sh — FULLY AUTOMATED argc/argv check.
#
# Same headless first-boot drive as auto-verify-exec.sh, but runs
#
#     exec /hello.elf alpha beta
#
# and requires hello.elf to echo back the whole vector:
#
#     argv[0]=hello.elf
#     argv[1]=alpha
#     argv[2]=beta
#
# That is the end-to-end proof of the argv work:
#
#   - task_create_user_argv must write the strings, the pointer array and argc
#     onto the child's user stack while CR3 is the child's PDPT (the stack is
#     mapped in no other address space), and
#   - crt0.S must pop argc/argv and pass them to main() per cdecl, and
#   - cmd_exec must build the vector from the command line, with argv[0] being
#     the program name and a trailing "&" excluded.
#
# Break the stack layout and the child faults or prints garbage; break crt0 and
# main() sees the wrong count; break cmd_exec and the extra words never arrive.
#
# PASS requires all three argv lines, in order, plus zero triple faults.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: argv.log (serial),
# argv-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=argv.log
TRACE=argv-trace.log
RUN_DISK=/tmp/tinyos-argv-disk.img
MON_SOCK=/tmp/tinyos-argv-mon.sock

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
# Wait on the LAST argv line: if the vector is short or the pointer array is
# malformed, the earlier lines can still appear, so only argv[2] proves the
# whole block survived the trip to ring 3.
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_EXEC_CMD="exec /hello.elf alpha beta" \
TINYOS_EXPECT="argv[2]=beta" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

# The 60-second EDR status report tears whatever line is in flight, at an
# ARBITRARY character, so any witness can be split in two and stop matching.
# Every read below is a POSITION comparison, and a torn witness reports as
# absent -- i.e. as a kernel that never produced it. The tear is PROBABILISTIC
# (it only bites when the burst lands on that particular line), so a green run
# does NOT show the raw read is safe; it shows the burst missed this time.
# Analyse the REJOINED copy. See verify/edr-rejoin.sh (cases: edr-rejoin-test.sh).
REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"

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

# Each line must be present AND in ascending order, so a stale/duplicated line
# from an earlier command cannot stand in for a missing one.
l0=$(grep -n "argv\[0\]=hello.elf" "$REJOINED" 2>/dev/null | head -1 | cut -d: -f1)
l1=$(grep -n "argv\[1\]=alpha"     "$REJOINED" 2>/dev/null | head -1 | cut -d: -f1)
l2=$(grep -n "argv\[2\]=beta"      "$REJOINED" 2>/dev/null | head -1 | cut -d: -f1)

if [ -z "$l0" ] || [ -z "$l1" ] || [ -z "$l2" ]; then
    echo "RESULT: FAIL/INCONCLUSIVE (typist rc=$TYPIST_RC; argv0=${l0:-none} argv1=${l1:-none} argv2=${l2:-none})"
    echo "--- tail of $SERIAL ---"
    grep -v "Suspicious" "$REJOINED" | tail -30
    exit 2
fi

# argc must be exactly 3: a fourth line would mean the trailing NULL terminator
# was missed and main() walked off the end of the array.
if grep -q "argv\[3\]=" "$REJOINED" 2>/dev/null; then
    echo "RESULT: FAIL — argv[3] present, so the NULL terminator was not honoured"
    grep "argv\[" "$REJOINED" | tail -10
    exit 2
fi

if [ "$TYPIST_RC" -eq 0 ] && [ "$l1" -gt "$l0" ] && [ "$l2" -gt "$l1" ]; then
    echo "RESULT: PASS — argc/argv reached main() intact"
    grep "argv\[" "$REJOINED" | head -5
    exit 0
else
    echo "RESULT: FAIL (typist rc=$TYPIST_RC; lines $l0 $l1 $l2 not in ascending order)"
    grep -v "Suspicious" "$REJOINED" | tail -30
    exit 2
fi
