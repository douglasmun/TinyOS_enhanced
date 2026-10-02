#!/bin/bash
# =============================================================================
# verify-syscall-io-quiet.sh -- a bad read/write buffer or a failed spawn is
# counted, not printed.
#
# WHAT THIS PROVES
#
# sys_write and sys_read each printed a kernel line for every refused buffer
# (over MAX_IO_SIZE, wrapping, ending past user space, faulting copy), and
# sys_spawn one for every failed spawn. All are reachable by any ring-3
# caller at any rate, and kprintf goes to the console whatever the caller's
# redirection -- into the stream every user's output shares.
#
# `/callprobe.elf io`, run unprivileged, makes 3 bad writes, 3 bad reads and
# 3 spawns of a missing file, and reports:
#
#   PROBE io refused=6 spawn_failed=3   POSITIVE CONTROL: all were refused
#
# Between "PROBE io start" and "PROBE io end" no kernel line may appear
# (HEAD: 6 + 3). The refusals must still be COUNTED: secstatus's "Syscall arg
# rejects" bad-buffer rises by 6 and spawn-failed by 3. The two oversize
# calls never reach sys_write/sys_read -- the dispatcher refuses len > 1 MB
# first, silently on both trees -- so they are counted there, and the +6 is
# what proves it.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: sysioquiet.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=iouser
TESTPASS=iopass12

ISO=dist/tinyos.iso
SERIAL=sysioquiet.log
TRACE=sysioquiet-trace.log
RUN_DISK=/tmp/tinyos-sysioquiet-disk.img
MON_SOCK=/tmp/tinyos-sysioquiet-mon.sock

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

grep -q '"io"' userspace/callprobe.c \
    || guard_fail "userspace/callprobe.c has no io mode; nothing would drive the sites"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
for prog in shell callprobe; do
    python3 tools/sign_elf.py userspace/$prog.elf >/dev/null 2>&1 || exit 1
    python3 tools/elf_to_c.py userspace/$prog.elf.signed \
        src/${prog}_elf_data.c src/${prog}_elf_data.h ${prog}_elf_data >/dev/null || exit 1
done
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

if [ "$(strings "$ISO" | grep -c 'PROBE io refused=')" -eq 0 ]; then
    guard_fail "the ISO does not contain fdprobe's io-mode strings"
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
secstatus=>Syscall dispatch;\
exec /callprobe.elf io=>PROBE io end;\
secstatus=>Syscall dispatch" \
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
    exit 1
fi

if ! grep -qa "PROBE io refused=" "$SERIAL"; then
    echo "RESULT: INCONCLUSIVE — /callprobe.elf io did not report."
    grep -a "PROBE" "$SERIAL"
    exit 3
fi

REPORT=$(grep -a "PROBE io refused=" "$SERIAL" | tail -1)
REFUSED=$(printf '%s\n' "$REPORT" | sed -n 's/.*refused=\([0-9][0-9]*\).*/\1/p')
SPAWNF=$(printf '%s\n' "$REPORT" | sed -n 's/.*spawn_failed=\([0-9][0-9]*\).*/\1/p')
WINDOW=$(awk '/PROBE io start/{on=1} on{print} /PROBE io end/{exit}' "$SERIAL")
NOISE=$(printf '%s\n' "$WINDOW" | grep -a -c -E 'sys_write:|sys_read:|\[SPAWN\]')

# Counters: first secstatus is the baseline, last is after the probe.
B0=$(grep -a "Syscall arg rejects" "$SERIAL" | head -1 | sed -n 's/.* \([0-9][0-9]*\) bad-buffer.*/\1/p')
B1=$(grep -a "Syscall arg rejects" "$SERIAL" | tail -1 | sed -n 's/.* \([0-9][0-9]*\) bad-buffer.*/\1/p')
S0=$(grep -a "Syscall arg rejects" "$SERIAL" | head -1 | sed -n 's/.* \([0-9][0-9]*\) spawn-failed.*/\1/p')
S1=$(grep -a "Syscall arg rejects" "$SERIAL" | tail -1 | sed -n 's/.* \([0-9][0-9]*\) spawn-failed.*/\1/p')
NREAD=$(grep -a -c "Syscall arg rejects" "$SERIAL")

echo "  refused=${REFUSED:-none} spawn_failed=${SPAWNF:-none} kernel lines=$NOISE"
echo "  (expected refused=6 spawn_failed=3, 0 lines)"
echo "  bad-buffer ${B0:-none} -> ${B1:-none}, spawn-failed ${S0:-none} -> ${S1:-none} (expected +6, +3)"

[ "${REFUSED:-0}" -eq 6 ] && [ "${SPAWNF:-0}" -eq 3 ] \
    || { echo "RESULT: INCONCLUSIVE — the probe's calls were not all refused"; exit 3; }

if [ "$NOISE" -ne 0 ]; then
    echo "RESULT: FAIL — $NOISE kernel lines landed in an unprivileged user's output"
    printf '%s\n' "$WINDOW" | grep -a -E 'sys_write:|sys_read:|\[SPAWN\]' | head
    exit 1
fi

if [ "$NREAD" -lt 2 ] || [ $((B1 - B0)) -ne 6 ] || [ $((S1 - S0)) -ne 3 ]; then
    echo "RESULT: FAIL — silent, but not counted (secstatus Syscall arg rejects)"
    exit 1
fi

echo "RESULT: PASS — 6 bad buffers and 3 failed spawns printed nothing and were counted"
exit 0
