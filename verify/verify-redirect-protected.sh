#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-redirect-protected.sh — output redirection must honour the VFS's
# protected-path rule.
#
# vfs_open() refuses a write under /bin/, /sbin/, /etc/, /boot/ or /kernel to a
# task without CAP_SYS_ADMIN, and ring-3 tasks hold no capabilities -- ring-3
# root included -- so `write D:/etc/motd x` is refused. SYS_REDIRECT opened
# its file through ramfs directly, below that check, so `echo x > D:/etc/motd`
# rewrote the same file with only ramfs's permission bits in the way, which
# root passes.
#
# Nothing creates /etc at boot, so the kernel shell (CAP_ALL) makes
# /etc/motd first, then hands back to a ring-3 shell running as root.
#
# ASSERTIONS (ring-3 shell as root)
#   1. POSITIVE CONTROLS: the VFS write to /etc/motd is refused, and a
#      redirect to an unprotected path works
#   2. after `>` and `>>` redirects to /etc/motd, its size is unchanged
#      (witnessed by stat before and after, not by the redirect's silence)
#   3. a `>` redirect does not create a new file under /etc/
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: redirprot.log (serial), redirprot-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
PROT=D:/etc/motd
OPEN=D:/scratch/rpok.txt
NEWF=D:/etc/rpnew.txt

ISO=dist/tinyos.iso
SERIAL=redirprot.log
TRACE=redirprot-trace.log
RUN_DISK=/tmp/tinyos-redirprot-disk.img
MON_SOCK=/tmp/tinyos-redirprot-mon.sock

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

# The stats run after the LAST ring-3 banner. The final stat waits for "size=" after the second motd stat is typed; the
# control-file stat sits between them so the before/after lines are distinct.
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
!write /etc/motd hello;\
exec /shell.elf=>TinyOS shell (ring 3);\
!stat $PROT=>size=;\
!write $PROT PWNED;\
!echo PWNED > $PROT;\
!echo PWNED >> $PROT;\
!echo PWNED > $NEWF;\
!stat $NEWF;\
!echo ok > $OPEN;\
!stat $OPEN=>size=;\
!stat $PROT;\
!stat $OPEN=>size=" \
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
[ -n "$BANNER" ] || { echo "RESULT: INCONCLUSIVE — never returned to the ring-3 shell"; exit 3; }
REGION=$(tail -n +"$BANNER" "$REJOINED")
SIZES=$(printf '%s\n' "$REGION" | grep -a "^$PROT  size=" | sed 's/.*size=\([0-9]*\).*/\1/')
BEFORE=$(printf '%s\n' "$SIZES" | sed -n 1p)
AFTER=$(printf '%s\n' "$SIZES" | sed -n 2p)
WRITE_REF=$(printf '%s\n' "$REGION" | grep -ac "^write: $PROT: ")

if [ -z "$BEFORE" ] || [ -z "$AFTER" ]; then
    echo "RESULT: INCONCLUSIVE — did not get both stats of $PROT (before=[$BEFORE] after=[$AFTER])"
    exit 3
fi
if [ "$WRITE_REF" -lt 1 ]; then
    echo "RESULT: INCONCLUSIVE — the VFS write to $PROT was not refused, so the rule is not live here"
    grep -a "motd" "$REJOINED" | tail -6 | sed 's/^/    /'
    exit 3
fi
if ! grep -aq "^$OPEN  size=[1-9]" "$REJOINED"; then
    echo "RESULT: INCONCLUSIVE — a redirect to an unprotected path did not work"
    exit 3
fi
echo "  controls: VFS write to $PROT refused; redirect to $OPEN works"
echo "  $PROT size before=$BEFORE after=$AFTER"

FAILS=0
if [ "$BEFORE" != "$AFTER" ]; then
    echo "  FAIL: a redirect rewrote a protected file the VFS refuses to open for write"
    FAILS=$((FAILS + 1))
fi
if printf '%s\n' "$REGION" | grep -aq "^$NEWF  size="; then
    echo "  FAIL: a redirect created a file under a protected directory"
    FAILS=$((FAILS + 1))
elif ! printf '%s\n' "$REGION" | grep -aq "^stat: $NEWF: "; then
    echo "RESULT: INCONCLUSIVE — no stat answer for $NEWF"
    exit 3
fi
if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS redirect(s) got past the protected-path rule"
    exit 1
fi
if grep -aqi "triple fault\|PANIC" "$REJOINED"; then
    echo "RESULT: FAIL — kernel panicked during the run"
    exit 1
fi
echo "RESULT: PASS — redirects to a protected path are refused like VFS writes"
exit 0
