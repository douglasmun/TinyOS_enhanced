#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-syscall-dotdot.sh — SYS_CHMOD and SYS_REDIRECT must resolve "." and
# ".." the way every VFS-backed path syscall does.
#
# Both call ramfs directly instead of going through the VFS, so they never got
# the VFS's canonicalization: ramfs's splitter refuses any ".." component, and
# `chmod 644 D:/d/../f`, `echo x > D:/d/../f` and -- because the cwd is joined
# in front of a relative path -- `echo x > ../f` all failed with ENOENT while
# `stat`, `cat` and `write` on the same strings worked.
#
# ASSERTIONS (ring-3 shell, root, the boundary both syscalls live at)
#   1. POSITIVE CONTROL: chmod and redirect on plain paths work
#   2. chmod through "dir/.." changes the mode of the file it names
#   3. redirect through "dir/.." and through a relative "../" creates the
#      file it names
#   Every effect is witnessed by stat, never by the command's own silence.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: dotdot.log (serial), dotdot-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

DIR=D:/dddir
CTL=D:/ddctl.txt            # chmod control
RCTL=D:/ddrctl.txt          # redirect control
TGT=D:/ddtgt.txt            # chmod through ..
RDOT=D:/ddrdot.txt          # redirect through dir/..
RREL=D:/ddrrel.txt          # redirect through a relative ../

ISO=dist/tinyos.iso
SERIAL=dotdot.log
TRACE=dotdot-trace.log
RUN_DISK=/tmp/tinyos-dotdot-disk.img
MON_SOCK=/tmp/tinyos-dotdot-mon.sock

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

# The last command waits for "size=", which only stat's OUTPUT carries, so
# every earlier line has drained before the verdict.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=300 \
TINYOS_EXEC_CMD="help" \
TINYOS_EXPECT="change permission bits" \
TINYOS_FOLLOWUP_CMDS="\
!mkdir $DIR;\
!write $CTL c;\
!chmod 644 $CTL;\
!stat $CTL=>mode=644;\
!echo ctl > $RCTL;\
!stat $RCTL=>size=;\
!write $TGT t;\
!chmod 644 $DIR/../ddtgt.txt;\
!echo dot > $DIR/../ddrdot.txt;\
!cd $DIR;\
!echo rel > ../ddrrel.txt;\
!cd D:/;\
!stat $TGT;\
!stat $RDOT;\
!stat $RREL;\
!stat $CTL=>size=" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"
cleanup

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

has() { grep -aq "^$1  size=[0-9]*  mode=$2" "$REJOINED"; }

if ! has "$CTL" 644 || ! has "$RCTL" "[0-7]*"; then
    echo "RESULT: INCONCLUSIVE — chmod or redirect failed on a plain path, so nothing below is graded"
    grep -a "ddctl\|ddrctl" "$REJOINED" | tail -6 | sed 's/^/    /'
    exit 3
fi
echo "  controls: chmod and redirect work on plain paths"

FAILS=0
check() {  # path mode-pattern label
    if has "$1" "$2"; then
        echo "  ok    $3"
    else
        echo "  FAIL  $3: $(grep -a "^stat: $1: \|^$1  size=" "$REJOINED" | tail -1)"
        FAILS=$((FAILS + 1))
    fi
}
check "$TGT"  644      "chmod 644 $DIR/../ddtgt.txt set the mode"
check "$RDOT" "[0-7]*" "redirect to $DIR/../ddrdot.txt created the file"
check "$RREL" "[0-7]*" "redirect to ../ddrrel.txt from $DIR created the file"

if grep -aqi "triple fault\|PANIC" "$REJOINED"; then
    echo "  FAIL: kernel panicked during the run"
    FAILS=$((FAILS + 1))
fi
if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS path(s) with '..' refused by a syscall that skips canonicalization"
    exit 1
fi
echo "RESULT: PASS — chmod and redirect resolve '..' like the VFS-backed syscalls"
exit 0
