#!/bin/bash
# =============================================================================
# verify-exit-quiet.sh -- a ring-3 process's exit or kill prints nothing to
# the kernel console.
#
# WHAT THIS PROVES
#
# The kernel console is the stream ring-3 output shares. sys_exit printed
# "[SYSCALL] Process exited with status N" and "[SYSCALL] Terminating process
# PID=..." for every exit, and task_terminate() "[PROCESS] Terminating task
# PID=..." for every kill -- so each stage of a pipeline or each iteration of
# a loop wrote lines into the middle of the user's own output.
#
# `/fdprobe.elf quiet`, run unprivileged, has 4 children exit normally and
# kills a fifth, then reports:
#
#   PROBE quiet exits=4 kill=0      POSITIVE CONTROL: the exits and the kill
#                                   happened
#
# Between "PROBE quiet start" and that line, none of the kernel's exit or
# kill lines may appear. Before, there were 2 per exit and 1 per kill.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: exitquiet.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=quser
TESTPASS=qpass12

ISO=dist/tinyos.iso
SERIAL=exitquiet.log
TRACE=exitquiet-trace.log
RUN_DISK=/tmp/tinyos-exitquiet-disk.img
MON_SOCK=/tmp/tinyos-exitquiet-mon.sock

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

grep -q '"quiet"' userspace/fdprobe.c \
    || guard_fail "userspace/fdprobe.c has no quiet mode; nothing would exit or be killed"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
for prog in shell fdprobe; do
    python3 tools/sign_elf.py userspace/$prog.elf >/dev/null 2>&1 || exit 1
    python3 tools/elf_to_c.py userspace/$prog.elf.signed \
        src/${prog}_elf_data.c src/${prog}_elf_data.h ${prog}_elf_data >/dev/null || exit 1
done
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

if [ "$(strings "$ISO" | grep -c 'PROBE quiet exits=')" -eq 0 ]; then
    guard_fail "the ISO does not contain fdprobe's quiet-mode strings"
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
exec /fdprobe.elf quiet=>PROBE done" \
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

if ! grep -qa "PROBE quiet exits=" "$SERIAL"; then
    echo "RESULT: INCONCLUSIVE — /fdprobe.elf quiet did not report."
    grep -a "PROBE" "$SERIAL"
    exit 3
fi

EXITS=$(grep -a "PROBE quiet exits=" "$SERIAL" | tail -1 | sed -n 's/.*exits=\([0-9][0-9]*\).*/\1/p')
KILLRC=$(grep -a "PROBE quiet exits=" "$SERIAL" | tail -1 | sed -n 's/.*kill=\(-\{0,1\}[0-9][0-9]*\).*/\1/p')
# Only the window the probe brackets: the probe's own exit comes after it.
WINDOW=$(awk '/PROBE quiet start/{on=1} on{print} /PROBE quiet exits=/{exit}' "$SERIAL")
NOISE=$(printf '%s\n' "$WINDOW" | grep -a -c \
    -e 'Process exited with status' -e 'Terminating process PID' \
    -e 'Terminating task PID' -e 'Removing terminated task' \
    -e 'Process cleanup complete')

echo "  exits=${EXITS:-none} kill=${KILLRC:-none} kernel exit/kill lines=$NOISE"
echo "  (expected exits=4 kill=0, 0 lines)"

[ "${EXITS:-0}" -eq 4 ] && [ "${KILLRC:-1}" -eq 0 ] \
    || { echo "RESULT: INCONCLUSIVE — the children did not all exit or the kill failed"; exit 3; }

if [ "$NOISE" -ne 0 ]; then
    echo "RESULT: FAIL — $NOISE kernel exit/kill lines landed in the user's output"
    printf '%s\n' "$WINDOW" | grep -a -e 'exited with status' -e 'Terminating' \
        -e 'Removing terminated' -e 'cleanup complete' | head
    exit 1
fi

echo "RESULT: PASS — 4 exits and a kill printed nothing to the console"
exit 0
