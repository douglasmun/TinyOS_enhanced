#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-kshell-redirect-trunc.sh — the kernel shell's `>` truncates and `>>`
# appends.
#
# Both operators opened the target with the same flags and nothing else:
# ramfs_open does not truncate and its cursor starts at 0, so `>` onto a longer
# file left the old tail behind and `>>` overwrote from the start, destroying
# the data it was asked to keep. The ring-3 shell's stdio.c fixed exactly this
# (ramfs_truncate / ramfs_fd_size + ramfs_seek); the kernel shell kept a TODO.
#
# The witness is `stat` size, not `cat`: a stale tail is invisible to a cat
# that only greps for the new text.
#
# Files (all under /scratch, 0777), written from the kernel shell:
#   a   echo abcdefghij > a                       control: one long write
#   b   echo xy > b                               control: one short write
#   t1  echo abcdefghij > t1; echo xy > t1        must equal size(b)
#   t2  echo abcdefghij > t2; echo zz >> t2       must equal size(a)+size(b)
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: kredir.log (serial), kredir-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=kredir.log
TRACE=kredir-trace.log
RUN_DISK=/tmp/tinyos-kredir-disk.img
MON_SOCK=/tmp/tinyos-kredir-mon.sock

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
!echo abcdefghij > /scratch/a;\
!echo xy > /scratch/b;\
!echo abcdefghij > /scratch/t1;\
!echo xy > /scratch/t1;\
!echo abcdefghij > /scratch/t2;\
!echo zz >> /scratch/t2;\
exec /shell.elf=>TinyOS shell (ring 3);\
stat D:/scratch/a D:/scratch/b D:/scratch/t1 D:/scratch/t2=>D:/scratch/t2  size=" \
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

size_of() {
    printf '%s\n' "$REGION" | grep -a "^D:/scratch/$1  size=" | tail -1 |
        sed -n 's/.*size=\([0-9]*\).*/\1/p'
}
A=$(size_of a); B=$(size_of b); T1=$(size_of t1); T2=$(size_of t2)
echo "  sizes: a=${A:-?} b=${B:-?} t1=${T1:-?} t2=${T2:-?}"
if [ -z "$A" ] || [ -z "$B" ] || [ -z "$T1" ] || [ -z "$T2" ]; then
    echo "RESULT: INCONCLUSIVE — a file was not created or stat printed no size"
    exit 3
fi
if [ "$A" -le "$B" ] || [ "$B" -eq 0 ]; then
    echo "RESULT: INCONCLUSIVE — controls a=$A b=$B are not a long and a short write"
    exit 3
fi

FAILS=0
if [ "$T1" -ne "$B" ]; then
    echo "  FAIL: '>' did not truncate: t1=$T1, expected $B (the old tail survived)"
    FAILS=$((FAILS + 1))
fi
if [ "$T2" -ne $((A + B)) ]; then
    echo "  FAIL: '>>' did not append: t2=$T2, expected $((A + B))"
    FAILS=$((FAILS + 1))
fi
if grep -aqi "triple fault\|PANIC" "$REJOINED"; then
    echo "  FAIL: kernel panicked during the run"
    FAILS=$((FAILS + 1))
fi
if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS check(s)"
    exit 1
fi
echo "RESULT: PASS — kernel-shell '>' truncates (t1=$T1) and '>>' appends (t2=$T2)"
exit 0
