#!/bin/bash
# =============================================================================
# verify-fat32-content.sh -- a C: file larger than one cluster reads back
# byte for byte what was written, through plain write()/read() syscalls.
#
# WHAT THIS PROVES
#
# fat32_read/fat32_write advanced the cluster cursor only when bytes remained
# in the SAME call. A call ending exactly on a cluster boundary left the
# cursor on the old cluster, so the next call re-read it (reads) or wrote
# over it (writes). sys_write feeds the VFS 512 bytes at a time and sys_read
# 1024; disk.img has 1024-byte clusters. Every C: file over 1 KB was stored
# or read wrong, and `cat` of a short file never crosses a boundary.
#
# /fatprobe.elf big, run as a NON-ROOT user (C: has no ownership model, so
# uid does not change the path -- it just keeps the leg honest):
#
#   one    one write() of 3000 bytes        (sys_write's 512-byte chunks)
#   three  three write()s of 1000 bytes     (call boundaries mid-cluster)
#   append 2048 bytes, reopen, lseek END, write 100  (EOF on a boundary)
#
# Each leg reports stat size, bytes read back, and the first mismatching
# offset (bad=-1: identical). size == expected is the POSITIVE CONTROL: the
# write path claimed to store the bytes, so a content mismatch is corruption
# rather than a refused write. The pattern differs per cluster, so a cluster
# read twice never compares equal by accident.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: fat32content.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=fatuser
TESTPASS=fatpass1

ISO=dist/tinyos.iso
SERIAL=fat32content.log
TRACE=fat32content-trace.log
RUN_DISK=/tmp/tinyos-fat32content-disk.img
MON_SOCK=/tmp/tinyos-fat32content-mon.sock


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

if [ "$(strings "$ISO" | grep -c 'PROBE big %s')" -eq 0 ]; then
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
exec /fatprobe.elf big=>PROBE done" \
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

if grep -qa "PROBE open .* failed" "$SERIAL"; then
    echo "RESULT: INCONCLUSIVE — the probe could not create its files on C:"
    grep -a "PROBE" "$SERIAL"
    exit 3
fi

field() {
    grep -a "PROBE big $1 .*$2=" "$SERIAL" | tail -1 \
        | sed -n "s/.* $2=\(-\{0,1\}[0-9][0-9]*\).*/\1/p"
}

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    grep -a "PROBE" "$SERIAL"
    exit 1
}

FAILED=""
check_leg() {
    local leg=$1 expect=$2 what=$3
    local size read bad
    size=$(field "$leg" size)
    read=$(field "$leg" read)
    bad=$(field "$leg" bad)
    echo "  $leg: size=${size:-none} read=${read:-none} bad=${bad:-none}   (expected $expect, $expect, -1)"
    [ -n "$size" ] && [ -n "$read" ] && [ -n "$bad" ] \
        || fail_with "the probe never reported the $leg leg"
    # Positive control: the write path claimed every byte.
    [ "$size" -eq "$expect" ] \
        || fail_with "$leg: C: stored size $size, expected $expect -- the write itself fell short" \
            "The content check below grades nothing until the bytes were accepted."
    if [ "$read" -ne "$expect" ]; then
        FAILED="$FAILED $leg"
        echo "FAIL $leg: read back $read bytes of $expect ($what)"
    elif [ "$bad" -ne -1 ]; then
        FAILED="$FAILED $leg"
        echo "FAIL $leg: content differs from offset $bad ($what)"
    else
        echo "PASS $leg: $expect bytes read back identical ($what)"
    fi
}

check_leg one    3000 "one 3000-byte write"
check_leg three  3000 "three 1000-byte writes"
check_leg append 2148 "append at a cluster-boundary EOF"

if [ -n "$FAILED" ]; then
    fail_with "C: content corrupted in leg(s):$FAILED" \
        "A read or write ending on a cluster boundary left the cursor on the old cluster."
fi

echo ""
echo "RESULT: PASS"
exit 0
