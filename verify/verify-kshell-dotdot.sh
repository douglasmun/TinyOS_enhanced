#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-kshell-dotdot.sh — the kernel shell's file commands must resolve "."
# and ".." the way the VFS does.
#
# chmod, touch, write and rm in shell_fileops.c resolved their argument with
# resolve_path(), which only joined the cwd on and never canonicalized; cp, mv
# and mkdir did not resolve at all. All of them hand the path to ramfs
# directly. ramfs's splitter refuses any ".."
# component, so `chmod 644 /d/../f` answered "No such file or directory" for a
# file `cat /d/../f` (VFS-backed) read without complaint.
#
# ASSERTIONS (kernel shell as root, witnessed from the ring-3 shell's stat)
#   1. POSITIVE CONTROL: chmod on a plain path sets the mode
#   2. chmod, touch, write, rm, mkdir, cp and mv through "dir/.." each act
#      on the file the path names
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: kdotdot.log (serial), kdotdot-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=kdotdot.log
TRACE=kdotdot-trace.log
RUN_DISK=/tmp/tinyos-kdotdot-disk.img
MON_SOCK=/tmp/tinyos-kdotdot-mon.sock

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

# Setup and the stats run in the ring-3 shell; the commands under test run in
# the kernel shell. The last stat waits for "size=" on the control file, which
# only stat's OUTPUT carries, after every graded stat has been typed.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=300 \
TINYOS_EXEC_CMD="help" \
TINYOS_EXPECT="change permission bits" \
TINYOS_FOLLOWUP_CMDS="\
!mkdir D:/kdd;\
!write D:/kddctl.txt c;\
!write D:/kddchm.txt c;\
!write D:/kddrm.txt r;\
!write D:/kddmv.txt m;\
!stat D:/kddrm.txt=>size=;\
kshell=>Switching to the kernel shell;\
!chmod 644 /kddctl.txt;\
!chmod 644 /kdd/../kddchm.txt;\
!touch /kdd/../kddtouch.txt;\
!write /kdd/../kddw.txt w;\
!rm /kdd/../kddrm.txt;\
!mkdir /kdd/../kddmk;\
!cp /kdd/../kddctl.txt /kdd/../kddcp.txt;\
!mv /kdd/../kddmv.txt /kdd/../kddmv2.txt;\
exec /shell.elf=>TinyOS shell (ring 3);\
!stat D:/kddchm.txt;\
!stat D:/kddtouch.txt;\
!stat D:/kddw.txt;\
!stat D:/kddrm.txt;\
!stat D:/kddmk;\
!stat D:/kddcp.txt;\
!stat D:/kddmv2.txt;\
!stat D:/kddctl.txt=>mode=" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"
cleanup

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

# Only the stats typed after `exec /shell.elf`: the last ring-3 banner on.
LAST=$(grep -an "TinyOS shell (ring 3)" "$REJOINED" | tail -1 | cut -d: -f1)
[ -n "$LAST" ] || { echo "RESULT: INCONCLUSIVE — never returned to the ring-3 shell"; exit 3; }
STATS=$(tail -n +"$LAST" "$REJOINED")
has() { printf '%s\n' "$STATS" | grep -aq "^$1  size=[0-9]*  mode=$2"; }

if ! has D:/kddctl.txt 644; then
    echo "RESULT: INCONCLUSIVE — kernel-shell chmod on a plain path did not set 644, so nothing below is graded"
    printf '%s\n' "$STATS" | grep -a "kddctl" | tail -3 | sed 's/^/    /'
    exit 3
fi
echo "  control: chmod 644 /kddctl.txt set the mode"

FAILS=0
check() {  # ok? label path
    if [ "$1" = 1 ]; then
        echo "  ok    $2"
    else
        echo "  FAIL  $2: $(printf '%s\n' "$STATS" | grep -a "$3" | tail -1)"
        FAILS=$((FAILS + 1))
    fi
}
has D:/kddchm.txt 644 && r=1 || r=0;     check $r "chmod 644 /kdd/../kddchm.txt set the mode" kddchm
has D:/kddtouch.txt "[0-7]*" && r=1 || r=0; check $r "touch /kdd/../kddtouch.txt created it" kddtouch
has D:/kddw.txt "[0-7]*" && r=1 || r=0;  check $r "write /kdd/../kddw.txt created it" kddw
printf '%s\n' "$STATS" | grep -aq "^stat: D:/kddrm.txt: no such file" && r=1 || r=0
check $r "rm /kdd/../kddrm.txt removed it" kddrm
has D:/kddmk "[0-7]*  directory" && r=1 || r=0; check $r "mkdir /kdd/../kddmk created it" kddmk
has D:/kddcp.txt "[0-7]*" && r=1 || r=0; check $r "cp to /kdd/../kddcp.txt created it" kddcp
has D:/kddmv2.txt "[0-7]*" && r=1 || r=0; check $r "mv to /kdd/../kddmv2.txt renamed it" kddmv

if grep -aqi "triple fault\|PANIC" "$REJOINED"; then
    echo "  FAIL: kernel panicked during the run"
    FAILS=$((FAILS + 1))
fi
if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS kernel-shell command(s) refused a path with '..'"
    exit 1
fi
echo "RESULT: PASS — kernel-shell chmod/touch/write/rm/mkdir/cp/mv resolve '..'"
exit 0
