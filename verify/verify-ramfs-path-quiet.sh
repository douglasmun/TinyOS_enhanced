#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-ramfs-path-quiet.sh — ramfs's path splitter must not print when it
# refuses a path.
#
# split_path() refuses three shapes: a ".." component (twice, mid-path and
# final) and more than 16 components. Each refusal printed a
# "[RAMFS] SECURITY:" line, and ring 3 reaches all of them once per syscall:
#
#   - depth: the VFS canonicalizer allows 32 components, ramfs 16, so
#     `stat` of a 17..32-component path reaches split_path through SYS_STAT
#   - "..": the kernel shell's chmod (ungated `kshell`) passes ramfs its
#     resolve_path() result, which is never canonicalized, so
#     `chmod 600 /x/../f` reaches it with "..". SYS_CHMOD and the redirect
#     syscall did too until they canonicalized (verify-syscall-dotdot.sh).
#
# Every caller already returns an errno, so the line recorded nothing the
# caller did not get, on the console the ring-3 shell shares.
#
# ASSERTIONS (ring-3 shell for the depth legs, kernel shell for "..")
#   1. POSITIVE CONTROL: each probe produced its own refusal line, so the
#      syscall ran and refused
#   2. zero "[RAMFS] SECURITY" lines in the whole log
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: rpathq.log (serial), rpathq-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

FILE=D:/rpq.txt
DOTDOT=/rpqdir/../rpq.txt
DEEP=D:/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t     # 20 components

ISO=dist/tinyos.iso
SERIAL=rpathq.log
TRACE=rpathq-trace.log
RUN_DISK=/tmp/tinyos-rpathq-disk.img
MON_SOCK=/tmp/tinyos-rpathq-mon.sock

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

# The last command waits for "size=", which only stat's OUTPUT carries (the
# ring-3 shell echoes the command line, so waiting on a command name would
# match the echo and grade before the earlier refusals were drained).
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=300 \
TINYOS_EXEC_CMD="help" \
TINYOS_EXPECT="change permission bits" \
TINYOS_FOLLOWUP_CMDS="\
!write $FILE x;\
!stat $FILE=>mode=600;\
!stat $DEEP;\
!chmod 600 $DEEP;\
!stat $FILE=>size=;\
kshell=>Switching to the kernel shell;\
chmod 600 $DOTDOT=>cannot access;\
chmod 600 $DOTDOT=>cannot access;\
cat /rpq.txt=>x" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"
cleanup

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

DOTDOT_REF=$(grep -ac "^chmod: cannot access '$DOTDOT'" "$REJOINED")
DEEP_STAT_REF=$(grep -ac "^stat: $DEEP: " "$REJOINED")
DEEP_CHMOD_REF=$(grep -ac "^chmod: $DEEP: " "$REJOINED")
echo "  refusals: chmod '..' x$DOTDOT_REF, stat deep x$DEEP_STAT_REF, chmod deep x$DEEP_CHMOD_REF"
if [ "$DOTDOT_REF" -lt 2 ] || [ "$DEEP_STAT_REF" -lt 1 ] || [ "$DEEP_CHMOD_REF" -lt 1 ]; then
    echo "RESULT: INCONCLUSIVE — a probe never produced its refusal line, so nothing below is graded"
    grep -a "rpq\|/a/b/c" "$REJOINED" | tail -10 | sed 's/^/    /'
    exit 3
fi

PRINTS=$(grep -ac "\[RAMFS\] SECURITY" "$REJOINED")
echo "  [RAMFS] SECURITY lines: $PRINTS"
if [ "$PRINTS" -ne 0 ]; then
    echo "RESULT: FAIL — $PRINTS console line(s) from ramfs's path splitter"
    grep -a "\[RAMFS\] SECURITY" "$REJOINED" | head -6 | sed 's/^/    /'
    exit 1
fi
if grep -aqi "triple fault\|PANIC" "$REJOINED"; then
    echo "RESULT: FAIL — kernel panicked during the run"
    exit 1
fi
echo "RESULT: PASS — four path refusals reached ramfs and printed nothing but their own errors"
exit 0
