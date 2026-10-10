#!/bin/bash
# =============================================================================
# verify-fat32-access-mode.sh -- C: honours the open access mode and O_APPEND,
# and the protected-path gate cannot be dodged by case or by a backslash.
#
# WHAT THIS PROVES
#
# FAT32 kept no access mode: fat32_vfs_open applied O_TRUNC under O_RDONLY,
# and vfs_read/vfs_write dispatched without looking at the mode, so a write on
# an O_RDONLY fd reached the disk -- past the protected-path gate, which only
# screens opens that ask to write. O_APPEND was accepted by sys_open and
# ignored by both drivers. The gate matched case-sensitively while FAT32 names
# are not, so a non-root user could mkdir C:/ETC; and fat32's parser split on
# a backslash the VFS never canonicalized, so C:/<bs>etc reached /ETC as one
# unprotected component.
#
# /fatprobe.elf mode, run as a NON-ROOT user (disk.img has no /etc, so a
# refusal of a protected name is the gate's -13, never "exists"):
#
#   bs      mkdir C:/<bs>etc and create C:/MODE<bs>BS.TXT must both fail, and
#           /MODE/BS.TXT must not exist. Runs before the case leg so a bypass
#           cannot hide behind its EEXIST.
#   case    mkdir C:/etc = -13 is the POSITIVE CONTROL that the gate is live
#           for this uid; mkdir C:/ETC and create C:/Etc/X.TXT must also be
#           -13; mkdir C:/MODE/SUB = 0 shows mkdir on C: works otherwise.
#   access  O_RDONLY|O_TRUNC leaves the 100-byte file intact; write on an
#           O_RDONLY fd and read on an O_WRONLY fd are refused and the
#           content is unchanged. wctl=5 / rctl=100: the same calls on
#           correctly opened fds succeed (POSITIVE CONTROLS; rctl reads its
#           own file, since T.BIN is the one the bugs damage).
#   append  10 'A's then an O_APPEND write of 5 'B's gives exactly
#           AAAAAAAAAABBBBB, on C: and on D: (the fix is in the VFS).
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: fat32mode.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=fatmuser
TESTPASS=fatmpass1

ISO=dist/tinyos.iso
SERIAL=fat32mode.log
TRACE=fat32mode-trace.log
RUN_DISK=/tmp/tinyos-fat32mode-disk.img
MON_SOCK=/tmp/tinyos-fat32mode-mon.sock


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

if [ "$(strings "$ISO" | grep -c 'PROBE mode access trunc_size=')" -eq 0 ]; then
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
exec /fatprobe.elf mode=>PROBE done" \
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
    echo "RESULT: INCONCLUSIVE — the probe could not set up its files"
    grep -a "PROBE" "$SERIAL"
    exit 3
fi

field() {
    grep -a "PROBE mode $1 .*$2=" "$SERIAL" | tail -1 \
        | sed -n "s/.* $2=\(-\{0,1\}[0-9][0-9]*\).*/\1/p"
}

inconclusive() {
    echo "RESULT: INCONCLUSIVE — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    grep -a "PROBE" "$SERIAL"
    exit 3
}

BSDIR=$(field bs dir);        BSFILE=$(field bs file);   BSSIZE=$(field bs file_size)
LOWER=$(field case lower);    UPPER=$(field case upper)
CFILE=$(field case file);     CTL=$(field case ctl)
TSIZE=$(field access trunc_size); RDW=$(field access rdwrite); WRR=$(field access wrread)
ABAD=$(field access bad);     WCTL=$(field access wctl); RCTL=$(field access rctl)
CSIZE=$(field append c_size); CBAD=$(field append c_bad)
DSIZE=$(field append d_size); DBAD=$(field append d_bad)

echo "  bs    : dir=${BSDIR:-none} file=${BSFILE:-none} file_size=${BSSIZE:-none}   (expected <0, <0, <0)"
echo "  case  : lower=${LOWER:-none} upper=${UPPER:-none} file=${CFILE:-none} ctl=${CTL:-none}   (expected -13, -13, -13, 0)"
echo "  access: trunc_size=${TSIZE:-none} rdwrite=${RDW:-none} wrread=${WRR:-none} bad=${ABAD:-none} wctl=${WCTL:-none} rctl=${RCTL:-none}"
echo "          (expected 100, <0, <0, -1, 5, 100)"
echo "  append: c_size=${CSIZE:-none} c_bad=${CBAD:-none} d_size=${DSIZE:-none} d_bad=${DBAD:-none}   (expected 15, -1, 15, -1)"

for v in BSDIR BSFILE BSSIZE LOWER UPPER CFILE CTL TSIZE RDW WRR ABAD WCTL RCTL CSIZE CBAD DSIZE DBAD; do
    [ -n "${!v}" ] || inconclusive "the probe never reported $v"
done

# Positive controls first: without them a refusal grades nothing.
[ "$LOWER" -eq -13 ] \
    || inconclusive "mkdir C:/etc returned $LOWER, not -13" \
        "The gate is not live for this uid (running as root?), so the case rows grade nothing."
[ "$CTL" -eq 0 ] \
    || inconclusive "mkdir C:/MODE/SUB returned $CTL" \
        "mkdir on C: fails outright, so a refused protected mkdir grades nothing."
[ "$WCTL" -eq 5 ] && [ "$RCTL" -eq 100 ] \
    || inconclusive "the control write/read returned $WCTL/$RCTL, expected 5/100" \
        "A refused write or read grades nothing if a correctly opened fd fails too."

FAILED=""
mark() { case " $FAILED " in *" $1 "*) ;; *) FAILED="$FAILED $1" ;; esac; }

if [ "$BSDIR" -ge 0 ] || [ "$BSFILE" -ge 0 ] || [ "$BSSIZE" -ge 0 ]; then
    mark bs
    echo "FAIL bs: a backslash path reached the driver as separate components"
fi
case " $FAILED " in *" bs "*) ;; *) echo "PASS bs: backslash paths name nothing on C:." ;; esac

if [ "$UPPER" -ne -13 ]; then
    mark case
    echo "FAIL case: mkdir C:/ETC as non-root returned $UPPER (gate dodged by case)"
fi
if [ "$CFILE" -ne -13 ]; then
    mark case
    echo "FAIL case: create C:/Etc/X.TXT as non-root returned $CFILE"
fi
case " $FAILED " in *" case "*) ;; *) echo "PASS case: every case variant of /etc is refused like /etc." ;; esac

if [ "$TSIZE" -ne 100 ]; then
    mark access
    echo "FAIL access: O_RDONLY|O_TRUNC emptied the file (size=$TSIZE)"
fi
if [ "$RDW" -ge 0 ]; then
    mark access
    echo "FAIL access: write on an O_RDONLY fd returned $RDW"
fi
if [ "$WRR" -ge 0 ]; then
    mark access
    echo "FAIL access: read on an O_WRONLY fd returned $WRR"
fi
if [ "$ABAD" -ne -1 ]; then
    mark access
    echo "FAIL access: the file's content changed (first bad=$ABAD)"
fi
case " $FAILED " in *" access "*) ;; *) echo "PASS access: the open mode is enforced; content intact." ;; esac

if [ "$CSIZE" -ne 15 ] || [ "$CBAD" -ne -1 ]; then
    mark append
    echo "FAIL append: C: O_APPEND gave size=$CSIZE bad=$CBAD"
fi
if [ "$DSIZE" -ne 15 ] || [ "$DBAD" -ne -1 ]; then
    mark append
    echo "FAIL append: D: O_APPEND gave size=$DSIZE bad=$DBAD"
fi
case " $FAILED " in *" append "*) ;; *) echo "PASS append: O_APPEND writes at end of file on C: and D:." ;; esac

if [ -n "$FAILED" ]; then
    echo "RESULT: FAIL —$FAILED"
    grep -a "PROBE" "$SERIAL"
    exit 1
fi

echo ""
echo "RESULT: PASS"
exit 0
