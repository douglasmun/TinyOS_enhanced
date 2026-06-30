#!/usr/bin/env bash
#
# auto-verify-exec.sh — FULLY AUTOMATED ENFORCE-mode exec check.
#
# Unlike verify-exec.sh (manual GUI), this drives QEMU's monitor over a Unix
# socket with `sendkey`, scripting the whole first-boot flow headlessly:
#   first-boot password setup -> root login -> decline regular-user -> shell ->
#   `exec /hello.elf`  -> check for ENFORCE-mode signature PASS + "Hello from ELF!"
#   with zero triple faults.
#
# It uses a FRESH (zeroed) disk every run so first-boot password setup always
# fires deterministically. Echo-verifies each visible char from the serial log
# and waits for each prompt before advancing (TCG under load drops scripted keys).
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: panic.log (serial),
# qemu.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=panic.log
TRACE=qemu.log
RUN_DISK=/tmp/tinyos-auto-verify-disk.img
MON_SOCK=/tmp/tinyos-auto-mon.sock

echo "==> Building kernel + ISO..."
make >/dev/null
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

echo "==> Fresh BLANK disk (forces first-boot password setup)"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
# 128 MiB zeroed image, same geometry as disk.img
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

echo "==> Driving the boot flow (this is slow under TCG; be patient)..."
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

# Give the exec a moment to print results, then stop QEMU.
sleep 3
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

mismatch=$(count 'Hash mismatch')
verified=$(count 'Signature verification: PASS')
ran=$(count 'Hello from ELF')

if [ "$mismatch" -gt 0 ]; then
    echo "RESULT: FAIL — sha256/sig Hash mismatch x$mismatch"
    grep -E "Hash mismatch|Signature" "$SERIAL" | tail -10
    exit 1
elif [ "$verified" -gt 0 ] && [ "$ran" -gt 0 ]; then
    echo "RESULT: PASS — ENFORCE verify PASS and hello.elf ran (Hello from ELF! x$ran)"
    grep -E "Signature verification|Hello from ELF|exit" "$SERIAL" | tail -10
    exit 0
else
    echo "RESULT: INCONCLUSIVE (typist rc=$TYPIST_RC; verify=$verified ran=$ran)"
    echo "--- tail of $SERIAL ---"
    grep -v "Suspicious" "$SERIAL" | tail -25
    exit 2
fi
