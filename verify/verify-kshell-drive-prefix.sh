#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-kshell-drive-prefix.sh — the kernel shell's file commands accept the
# default drive prefix (D:) that `cat`, `ls` and the ring-3 shell accept.
#
# chmod, cp, mv, mkdir, touch, write, rm and edit resolve their argument with
# shell_fileops.c resolve_path(), which had no drive-letter awareness:
# `D:/scratch/f` does not start with '/', so it was joined to the cwd as
# `/D:/scratch/f` and every one of them reported "No such file or directory"
# for a file `cat D:/scratch/f` reads.
#
# Files (all under /scratch, 0777), from the kernel shell as root:
#   dpa  echo abc > /scratch/dpa             control, created by a '/' path
#   dpm  echo abc > /scratch/dpm; chmod 604 D:/scratch/dpm   mode must be 604
#   dpd  mkdir D:/scratch/dpd                must exist, a directory
#   dpt  touch D:/scratch/dpt                must exist
#   dpc  cp D:/scratch/dpa D:/scratch/dpc    must exist, size == size(dpa)
#   dpr  echo abc > /scratch/dpr; rm D:/scratch/dpr          must be gone
# The witness is the ring-3 `stat`, which resolves D: through the syscall path.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: kdrive.log (serial), kdrive-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=kdrive.log
TRACE=kdrive-trace.log
RUN_DISK=/tmp/tinyos-kdrive-disk.img
MON_SOCK=/tmp/tinyos-kdrive-mon.sock

echo "==> Building kernel + ISO..."
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

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

TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=300 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
kshell=>Switching to the kernel shell;\
!echo abc > /scratch/dpa;\
!echo abc > /scratch/dpm;\
!chmod 604 D:/scratch/dpm;\
!mkdir D:/scratch/dpd;\
!touch D:/scratch/dpt;\
!cp D:/scratch/dpa D:/scratch/dpc;\
!echo abc > /scratch/dpr;\
!rm D:/scratch/dpr;\
exec /shell.elf=>TinyOS shell (ring 3);\
stat D:/scratch/dpm D:/scratch/dpd D:/scratch/dpt D:/scratch/dpc D:/scratch/dpr D:/scratch/dpa=>D:/scratch/dpa  size=" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"
cleanup

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

BANNER=$(grep -an "TinyOS shell (ring 3)" "$REJOINED" | tail -1 | cut -d: -f1)
[ -n "$BANNER" ] || { echo "RESULT: INCONCLUSIVE — never reached the ring-3 shell"; exit 3; }
REGION=$(tail -n +"$BANNER" "$REJOINED")

line_of() { printf '%s\n' "$REGION" | grep -a "^D:/scratch/$1  size=" | tail -1; }
size_of() { line_of "$1" | sed -n 's/.*size=\([0-9]*\).*/\1/p'; }
mode_of() { line_of "$1" | sed -n 's/.*mode=\([0-7]*\).*/\1/p'; }

A=$(size_of dpa)
if [ -z "$A" ] || [ "$A" -eq 0 ]; then
    echo "RESULT: INCONCLUSIVE — control /scratch/dpa missing or empty"
    exit 3
fi
for f in dpm dpd dpt dpc dpr; do echo "  $f: $(line_of $f)"; done

FAILS=0
M=$(mode_of dpm)
if [ "$M" != "604" ]; then
    echo "  FAIL: chmod 604 D:/scratch/dpm left mode=${M:-?}"; FAILS=$((FAILS + 1))
fi
if ! line_of dpd | grep -q "directory$"; then
    echo "  FAIL: mkdir D:/scratch/dpd created no directory"; FAILS=$((FAILS + 1))
fi
if [ -z "$(line_of dpt)" ]; then
    echo "  FAIL: touch D:/scratch/dpt created nothing"; FAILS=$((FAILS + 1))
fi
C=$(size_of dpc)
if [ "${C:-x}" != "$A" ]; then
    echo "  FAIL: cp D:/scratch/dpa D:/scratch/dpc gave size=${C:-missing}, expected $A"; FAILS=$((FAILS + 1))
fi
if [ -n "$(line_of dpr)" ]; then
    echo "  FAIL: rm D:/scratch/dpr left the file in place"; FAILS=$((FAILS + 1))
fi
if grep -aqi "triple fault\|PANIC" "$REJOINED"; then
    echo "  FAIL: kernel panicked during the run"; FAILS=$((FAILS + 1))
fi
if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS check(s)"
    exit 1
fi
echo "RESULT: PASS — chmod, mkdir, touch, cp and rm accept the D: prefix"
exit 0
