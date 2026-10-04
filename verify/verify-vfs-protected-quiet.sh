#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-vfs-protected-quiet.sh — VFS refusals are counted, not printed.
#
# vfs_open/vfs_mkdir/vfs_rmdir/vfs_unlink printed a console line for every
# write to a protected path ([VFS SECURITY] ... Denied, or [VFS] ... Granted)
# and for every path naming an unmounted drive ([VFS] ERROR: Drive X: not
# mounted). Ring-3 tasks reach all four through SYS_OPEN/MKDIR/RMDIR/UNLINK and
# hold no capabilities, so any user could drive the shared console at syscall
# rate with `write D:/etc/x y` in a loop. Same class as RULES_THAT_BITE's
# "no per-operation kprintf on a path ring 3 can reach".
#
# ASSERTIONS
#   1. POSITIVE CONTROLS: every ring-3 leg printed its own refusal line, so
#      each one reached the VFS and was refused
#   2. no [VFS SECURITY], "[VFS] PID" or "[VFS] ERROR: Drive" line anywhere
#      after boot -- neither the ring-3 denials nor the kernel shell's grant
#   3. secstatus counts them: "Protected paths" shows >= 4 denied (the four
#      ring-3 protected legs) and >= 1 granted (the kernel shell's setup write)
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: vfsquiet.log (serial), vfsquiet-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=vfsquiet.log
TRACE=vfsquiet-trace.log
RUN_DISK=/tmp/tinyos-vfsquiet-disk.img
MON_SOCK=/tmp/tinyos-vfsquiet-mon.sock

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

# The kernel shell (CAP_ALL) builds /etc/motd -- through vfs_open, hence the
# drive letter, so it counts as a grant -- and /bin/d, then hands over to a
# ring-3 shell as root -- no capabilities -- for the refused legs, then back
# to the kernel shell for secstatus. "Syscall blocks" is the line after the
# EDR block in secstatus on both the fixed and unfixed kernel, so the wait
# does not depend on the counter this harness grades.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=300 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
kshell=>Switching to the kernel shell;\
!mkdir /etc;\
!write D:/etc/motd hello;\
!mkdir /bin;\
!mkdir /bin/d;\
exec /shell.elf=>TinyOS shell (ring 3);\
!write D:/etc/motd x;\
!mkdir D:/etc/newd;\
!rmdir D:/bin/d;\
!rm D:/etc/motd;\
!cat Z:/nofile;\
!mkdir Z:/d;\
!rmdir Z:/d;\
!stat D:/etc/motd=>size=;\
kshell=>Switching to the kernel shell;\
secstatus=>Syscall blocks" \
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

# 1. Each leg produced its own refusal line.
MISSING=0
for leg in "write: D:/etc/motd: " "mkdir: D:/etc/newd: " "rmdir: D:/bin/d: " \
           "rm: D:/etc/motd: " "cat: Z:/nofile: " "mkdir: Z:/d: " "rmdir: Z:/d: "; do
    if ! printf '%s\n' "$REGION" | grep -aq "^$leg"; then
        echo "  missing refusal: [$leg]"
        MISSING=$((MISSING + 1))
    fi
done
if [ "$MISSING" -ne 0 ]; then
    echo "RESULT: INCONCLUSIVE — $MISSING leg(s) printed no refusal, so they may not have reached the VFS"
    exit 3
fi
if ! printf '%s\n' "$REGION" | grep -aq "^D:/etc/motd  size="; then
    echo "RESULT: INCONCLUSIVE — /etc/motd is gone, so the rm leg was not refused"
    exit 3
fi
echo "  controls: all 7 ring-3 legs refused; /etc/motd survived"

FAILS=0
# 2. No per-operation VFS line anywhere.
PRINTS=$(grep -aE '\[VFS SECURITY\]|\[VFS\] PID|\[VFS\] ERROR: Drive' "$REJOINED")
NPRINTS=$(printf '%s' "$PRINTS" | grep -c .)
if [ "$NPRINTS" -ne 0 ]; then
    echo "  FAIL: $NPRINTS per-operation VFS console line(s):"
    printf '%s\n' "$PRINTS" | head -8 | sed 's/^/      /'
    FAILS=$((FAILS + 1))
fi

# 3. secstatus counts them.
PP=$(grep -a "Protected paths" "$REJOINED" | tail -1)
DENIED=$(printf '%s' "$PP" | sed -n 's/.*\.\. *\([0-9]*\) denied.*/\1/p')
GRANTED=$(printf '%s' "$PP" | sed -n 's/.* \([0-9]*\) granted.*/\1/p')
echo "  secstatus: [${PP:-<no Protected paths line>}]"
if [ -z "$DENIED" ] || [ -z "$GRANTED" ]; then
    echo "  FAIL: secstatus has no protected-path counters"
    FAILS=$((FAILS + 1))
elif [ "$DENIED" -lt 4 ] || [ "$GRANTED" -lt 1 ]; then
    echo "  FAIL: expected >= 4 denied and >= 1 granted, got $DENIED / $GRANTED"
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
echo "RESULT: PASS — 7 refused VFS operations printed nothing and were counted ($DENIED denied, $GRANTED granted)"
exit 0
