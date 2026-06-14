#!/usr/bin/env bash
#
# verify-exec.sh — runtime check for the ENFORCE-mode exec triple-fault fix.
#
# Builds the ISO, boots TinyOS in a GUI QEMU window with CPU-reset/interrupt
# tracing, and (after you close the window) reports whether `exec /hello.elf`
# triple-faulted.
#
# In the QEMU window:
#   1. Complete first-boot password setup (or log in as root if already set).
#   2. At the shell, run:   exec /hello.elf
#   3. Close the QEMU window (Ctrl+Alt+G releases the mouse first).
#
# PASS  = no "Triple fault" in qemu.log and hello.elf ran.
# FAIL  = "Triple fault" present (the new idt.c guard should also have printed
#         "STACK OVERFLOW DETECTED" with CR2/EIP to panic.log).

set -euo pipefail
cd "$(dirname "$0")"

ISO=dist/tinyos.iso
SRC_DISK=disk.img
RUN_DISK=/tmp/tinyos-verify-disk.img   # throwaway copy so disk.img stays pristine
QEMU=qemu-system-i386

echo "==> Building (make)..."
make >/dev/null

echo "==> Fresh disk copy: $SRC_DISK -> $RUN_DISK"
cp "$SRC_DISK" "$RUN_DISK"

echo "==> Clearing previous logs"
rm -f panic.log qemu.log

echo "==> Launching QEMU (GUI). In the window:"
echo "      log in as root, then run:  exec /hello.elf"
echo "      then CLOSE the window (Ctrl+Alt+G releases the mouse)."
echo

"$QEMU" -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
	-boot d \
	-m 256M \
	-drive file="$RUN_DISK",format=raw,if=ide \
	-netdev user,id=net0 \
	-device e1000,netdev=net0,mac=52:54:00:12:34:56 \
	-serial file:panic.log \
	-no-reboot -d int,cpu_reset -D qemu.log

echo
echo "================ VERDICT ================"
if grep -q "Triple fault" qemu.log 2>/dev/null; then
	echo "RESULT: FAIL — 'Triple fault' found in qemu.log"
	echo
	echo "Last fault frame from qemu.log:"
	grep -E "check_exception|v=0e|v=08|Triple fault|^EIP=|CR2=" qemu.log | tail -20
	echo
	if grep -q "STACK OVERFLOW DETECTED" panic.log 2>/dev/null; then
		echo "Stack-overflow guard fired (panic.log):"
		grep -A3 "STACK OVERFLOW DETECTED" panic.log | tail -8
		echo "(=> 128 KiB still not enough; bump KERNEL_TASK_STACK_PAGES and re-run.)"
	fi
	exit 1
elif grep -q "Signature verification: PASS" panic.log 2>/dev/null; then
	echo "RESULT: PASS — no triple fault; ECDSA verify passed and exec proceeded."
	echo
	echo "Relevant serial lines (panic.log):"
	grep -E "Signature verification|hello.elf|Creating process|ELF HEADER" panic.log | tail -10
	exit 0
else
	echo "RESULT: INCONCLUSIVE — no triple fault, but no verify-PASS marker seen."
	echo "Did you run 'exec /hello.elf' before closing the window?"
	echo
	echo "Tail of panic.log:"
	tail -15 panic.log 2>/dev/null || echo "(panic.log empty)"
	exit 2
fi
