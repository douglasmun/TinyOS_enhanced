#!/bin/bash
# =============================================================================
# verify-fat32-stale-fd.sh -- unlink and O_TRUNC cannot strand another open fd
# on C: storage that was released under it.
#
# WHAT THIS PROVES
#
# Each fat32 descriptor caches its file's first cluster and size. unlink's
# "is it open?" check compared first clusters, which are 0 for an empty file,
# so an open empty file could be unlinked; its fd's next flush rewrote the
# entry of whatever file reused the freed slot. And O_TRUNC through one fd
# freed the chain while every other fd on the file kept its cached clusters,
# so they read and wrote another file's data. Open files are now matched by
# directory-entry location, and truncate/write propagate to sibling fds.
#
# /fatprobe.elf stale, run as a NON-ROOT user, each leg in a fresh directory:
#
#   unlink  open EMPTY.TXT, unlink it (must be refused), create VICTIM.TXT
#           (12 bytes) in the slot an unlink would free, write+close the held
#           fd. VICTIM must keep its size and content. after=0: once the fd is
#           closed the same unlink succeeds -- the POSITIVE CONTROL that the
#           refusal is about the open fd, not a broken unlink.
#   trunc   fd1 open on a 3000-byte file; fd2 opens it O_TRUNC; OTHER.BIN
#           (3000 bytes) is written into the freed clusters; fd1 writes 100
#           'Z's. TRUNC must hold exactly those 100 bytes and OTHER must be
#           intact. other_size=3000 is the positive control that OTHER was
#           written at all.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: fat32stale.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=fatsuser
TESTPASS=fatspass1

ISO=dist/tinyos.iso
SERIAL=fat32stale.log
TRACE=fat32stale-trace.log
RUN_DISK=/tmp/tinyos-fat32stale-disk.img
MON_SOCK=/tmp/tinyos-fat32stale-mon.sock


guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

[ -f userspace/fatprobe.c ] \
    || guard_fail "userspace/fatprobe.c is missing; nothing would write to C:"
grep -q "fatprobe_elf_data" src/kernel.c \
    || guard_fail "src/kernel.c does not install /fatprobe.elf into ramfs"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
for prog in shell fatprobe; do
    python3 tools/sign_elf.py userspace/$prog.elf >/dev/null 2>&1 || exit 1
    python3 tools/elf_to_c.py userspace/$prog.elf.signed \
        src/${prog}_elf_data.c src/${prog}_elf_data.h ${prog}_elf_data >/dev/null || exit 1
done
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

if [ "$(strings "$ISO" | grep -c 'PROBE stale unlink busy=')" -eq 0 ]; then
    guard_fail "the ISO does not contain fatprobe's output strings"
fi

rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

echo "==> Launching headless QEMU"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!
# A panicked guest halts and the typist would wait out its whole timeout for
# "PROBE done"; stop QEMU and the typist as soon as the log says so.
( while kill -0 "$QEMU_PID" 2>/dev/null; do
      if grep -qa "KERNEL PANIC" "$SERIAL" 2>/dev/null; then
          sleep 2; kill "$QEMU_PID"; pkill -P $$ -f qemu_typist; break
      fi
      sleep 1
  done ) &
WATCH_PID=$!
cleanup() { kill "$QEMU_PID" "$WATCH_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
su $TESTUSER=>Now running as;\
!id=>uid=;\
exec /fatprobe.elf stale=>PROBE done" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

if grep -qa "KERNEL PANIC" "$SERIAL"; then
    echo "RESULT: FAIL — the kernel panicked"
    grep -a -A12 "KERNEL PANIC" "$SERIAL" | head -30
    grep -a "PROBE" "$SERIAL"
    exit 1
fi

if ! grep -qa "PROBE done" "$SERIAL"; then
    echo "RESULT: INCONCLUSIVE — /fatprobe.elf did not run to completion."
    grep -a "PROBE" "$SERIAL"
    exit 3
fi

if grep -qaE "PROBE (open|mkdir) .* failed" "$SERIAL"; then
    echo "RESULT: INCONCLUSIVE — the probe could not set up its files on C:"
    grep -a "PROBE" "$SERIAL"
    exit 3
fi

field() {
    grep -a "PROBE stale $1 .*$2=" "$SERIAL" | tail -1 \
        | sed -n "s/.* $2=\(-\{0,1\}[0-9][0-9]*\).*/\1/p"
}

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    grep -a "PROBE" "$SERIAL"
    exit 1
}

BUSY=$(field unlink busy)
VSIZE=$(field unlink victim_size)
VBAD=$(field unlink victim_bad)
AFTER=$(field unlink after)
TSIZE=$(field trunc size)
TBAD=$(field trunc bad)
OSIZE=$(field trunc other_size)
OBAD=$(field trunc other_bad)

echo "  unlink: busy=${BUSY:-none} victim_size=${VSIZE:-none} victim_bad=${VBAD:-none} after=${AFTER:-none}"
echo "          (expected <0, 12, -1, 0)"
echo "  trunc : size=${TSIZE:-none} bad=${TBAD:-none} other_size=${OSIZE:-none} other_bad=${OBAD:-none}"
echo "          (expected 100, -1, 3000, -1)"

for v in BUSY VSIZE VBAD AFTER TSIZE TBAD OSIZE OBAD; do
    [ -n "${!v}" ] || fail_with "the probe never reported $v"
done

FAILED=""
mark() { case " $FAILED " in *" $1 "*) ;; *) FAILED="$FAILED $1" ;; esac; }
if [ "$BUSY" -ge 0 ]; then
    mark unlink
    echo "FAIL unlink: an open empty file was unlinked (rc=$BUSY)"
fi
if [ "$VSIZE" -ne 12 ] || [ "$VBAD" -ne -1 ]; then
    mark unlink
    echo "FAIL unlink: VICTIM.TXT was rewritten through the stale fd (size=$VSIZE bad=$VBAD)"
fi
if [ "$BUSY" -lt 0 ] && [ "$AFTER" -ne 0 ]; then
    fail_with "unlink of the closed file failed (rc=$AFTER)" \
        "Positive control: a refusal that persists after close is not about the open fd."
fi
case " $FAILED " in *" unlink "*) ;; *) echo "PASS unlink: refused while open, allowed after close, VICTIM intact." ;; esac

[ "$OSIZE" -eq 3000 ] \
    || fail_with "OTHER.BIN has size $OSIZE, expected 3000" \
        "Positive control: the trunc leg grades nothing unless OTHER was written."
if [ "$TSIZE" -ne 100 ] || [ "$TBAD" -ne -1 ]; then
    mark trunc
    echo "FAIL trunc: the file fd1 wrote holds size=$TSIZE bad=$TBAD (expected 100 'Z's)"
fi
if [ "$OBAD" -ne -1 ]; then
    mark trunc
    echo "FAIL trunc: OTHER.BIN corrupted from offset $OBAD by the stale fd"
fi
case " $FAILED " in *" trunc "*) ;; *) echo "PASS trunc: the truncated fd followed the truncate; OTHER intact." ;; esac

if [ -n "$FAILED" ]; then
    fail_with "a stale C: fd acted on released storage:$FAILED"
fi

echo ""
echo "RESULT: PASS"
exit 0
