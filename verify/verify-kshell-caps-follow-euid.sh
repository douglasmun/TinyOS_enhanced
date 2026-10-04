#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-kshell-caps-follow-euid.sh — the kernel shell loses CAP_SYS_ADMIN when
# it runs as a non-root user, and its file commands honour the protected-path
# rule (/bin /sbin /etc /boot need CAP_SYS_ADMIN).
#
# The login task is a kernel task created with CAP_ALL. It runs the kernel
# shell as whoever logged in or su'd, and kept CAP_ALL as that user. On top of
# that, cp/mv/mkdir/touch/write/rm/chmod, `>`/`>>` and the editor modify the RAM
# disk through ramfs directly, below vfs_open()'s protected-path check, so the
# rule applied to nobody there. Only ramfs's mode bits stood in the way.
#
# To isolate the second layer, root makes a protected directory the mode bits
# do NOT protect: /etc (755) and /etc/pp (777, root's mkdir makes 700),
# holding a root-owned 666 file and a file to delete; the cp source is 644.
# Without those chmods the mode bits refuse first and the harness PASSes the
# unfixed kernel -- the guard below scores that INCONCLUSIVE. Then, su'd to an unprivileged user, the kernel shell tries to
# create, write, copy into, redirect into, overwrite and delete there. Every
# attempt must be refused. Controls:
#   - the same user creates a file and a directory in /scratch (must work);
#   - after `su root` (password), root creates /etc/pp/rootback, which proves
#     the capability came back with euid 0.
# The witness is the ring-3 `stat`, run as root afterwards.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: kcaps.log (serial), kcaps-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
PROBER=kcprober
PROBERPW=kcprober1

ISO=dist/tinyos.iso
SERIAL=kcaps.log
TRACE=kcaps-trace.log
RUN_DISK=/tmp/tinyos-kcaps-disk.img
MON_SOCK=/tmp/tinyos-kcaps-mon.sock

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

# Each listing is bracketed by echo markers; the trailing `id` waits for the
# prober's uid so the second listing has printed before the verdict.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=300 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
useradd $PROBER=>Enter password for new user;\
!$PROBERPW=>created;\
kshell=>Switching to the kernel shell;\
!mkdir /etc;\
!chmod 755 /etc;\
!mkdir /etc/pp;\
!chmod 777 /etc/pp;\
!echo v > /etc/pp/victim;\
!chmod 666 /etc/pp/victim;\
!echo r > /etc/pp/rmv;\
!chmod 666 /etc/pp/rmv;\
!echo control > /scratch/kcc;\
!chmod 644 /scratch/kcc;\
su $PROBER=>Now running as;\
!write /etc/pp/uw hello;\
!touch /etc/pp/ut;\
!mkdir /etc/pp/ud;\
!cp /scratch/kcc /etc/pp/uc;\
!echo hi > /etc/pp/ur;\
!write /etc/pp/victim pwnedpwned;\
!rm /etc/pp/rmv;\
!touch /scratch/kcuok;\
!mkdir /scratch/kcudok;\
su root=>Password for root;\
!$PASSWORD=>Switched to user;\
!touch /etc/pp/rootback;\
exec /shell.elf=>TinyOS shell (ring 3);\
stat D:/etc/pp/uw D:/etc/pp/ut D:/etc/pp/ud D:/etc/pp/uc D:/etc/pp/ur D:/etc/pp/victim D:/etc/pp/rmv D:/etc/pp/rootback D:/scratch/kcuok D:/scratch/kcudok D:/scratch/kcc=>D:/scratch/kcc  size=" \
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
REGION=$(tail -n +"$BANNER" "$REJOINED" | tr -d '\r')

line_of() { printf '%s\n' "$REGION" | grep -a "^D:/$1  size=" | tail -1; }
size_of() { line_of "$1" | sed -n 's/.*size=\([0-9]*\).*/\1/p'; }

for f in etc/pp/uw etc/pp/ut etc/pp/ud etc/pp/uc etc/pp/ur etc/pp/victim \
         etc/pp/rmv etc/pp/rootback scratch/kcuok scratch/kcudok; do
    L=$(line_of "$f"); echo "  $f: ${L:-(absent)}"
done

if [ -z "$(line_of scratch/kcc)" ]; then
    echo "RESULT: INCONCLUSIVE — the root setup never ran (/scratch/kcc missing)"; exit 3
fi
if [ -z "$(line_of scratch/kcuok)" ] || [ -z "$(line_of scratch/kcudok)" ]; then
    echo "RESULT: INCONCLUSIVE — the unprivileged control could not create in /scratch (did su run?)"; exit 3
fi
VSIZE=$(size_of etc/pp/victim)
if [ -z "$VSIZE" ]; then
    echo "RESULT: INCONCLUSIVE — /etc/pp/victim was never created (root setup failed)"; exit 3
fi

# The refusals must come from the protected-path rule, not from the mode bits
# (a traversal or read refusal looks identical in stat). On a fixed kernel the
# rule speaks first, so neither of these ramfs messages may appear.
if printf '%s\n' "$(tr -d '\r' < "$REJOINED")" |
        grep -aqE "cp: cannot open '/scratch/kcc'|cannot remove '/etc/pp/rmv': No such file"; then
    echo "RESULT: INCONCLUSIVE — the mode bits refused before the rule under test (setup chmods missing?)"
    exit 3
fi

FAILS=0
for f in uw ut ud uc ur; do
    if [ -n "$(line_of etc/pp/$f)" ]; then
        echo "  FAIL: a non-root kernel shell created /etc/pp/$f"; FAILS=$((FAILS + 1))
    fi
done
if [ "$VSIZE" -ge 10 ]; then
    echo "  FAIL: a non-root kernel shell overwrote /etc/pp/victim (size=$VSIZE)"; FAILS=$((FAILS + 1))
fi
if [ -z "$(line_of etc/pp/rmv)" ]; then
    echo "  FAIL: a non-root kernel shell deleted /etc/pp/rmv"; FAILS=$((FAILS + 1))
fi
if [ -z "$(line_of etc/pp/rootback)" ]; then
    echo "  FAIL: after su root the kernel shell could not create /etc/pp/rootback (capability not restored)"
    FAILS=$((FAILS + 1))
fi
if grep -aqi "triple fault\|PANIC" "$REJOINED"; then
    echo "  FAIL: kernel panicked during the run"; FAILS=$((FAILS + 1))
fi
if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS check(s)"
    exit 1
fi
echo "RESULT: PASS — non-root kernel shell refused on protected paths; root regained CAP_SYS_ADMIN"
exit 0
