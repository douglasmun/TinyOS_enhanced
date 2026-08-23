#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-spawn.sh — FULLY AUTOMATED SYS_SPAWN check.
#
# Same headless first-boot drive as auto-verify-exec.sh, but runs
#
#     exec /spawner.elf
#
# spawner.elf is a RING-3 program that calls spawn("/hello.elf", {...}) and
# then waitpid()s the child. That is the point of the test: the shell's own
# `exec` builds a process from inside the kernel, so it cannot prove that a
# USER process can start one. Only this path exercises
#
#   - the SYS_SPAWN syscall number actually being dispatched (MAX_SYSCALL_NUM
#     must cover it, or the range check rejects the call and spawn returns
#     -ENOSYS), and
#   - copy_string_from_user pulling the path and every argv string out of user
#     memory, and
#   - elf_exec_from_path serializing the shared load buffers under the exec
#     lock while the shell's own exec path is live, and
#   - the child inheriting the spawner's streams (its output must reach the
#     same console), and
#   - parentage being recorded before scheduling, so waitpid() on the returned
#     PID actually finds the child instead of returning -ECHILD.
#
# PASS requires the full chain: spawner announces a child PID, the CHILD's own
# argv (passed from ring 3, through the kernel, onto a new user stack) prints,
# and the spawner's waitpid returns.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: spawn.log (serial),
# spawn-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=spawn.log
TRACE=spawn-trace.log
RUN_DISK=/tmp/tinyos-spawn-disk.img
MON_SOCK=/tmp/tinyos-spawn-mon.sock

echo "==> Building kernel + ISO..."
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

echo "==> Fresh BLANK disk (forces first-boot password setup)"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
dd if=/dev/zero of="$RUN_DISK" bs=1m count=128 status=none

echo "==> Launching headless QEMU (monitor on $MON_SOCK)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

echo "==> Driving the boot flow (slow under TCG; be patient)..."
# Wait on the spawner's LAST line: it is only reached after waitpid() returns,
# so it proves the child ran to completion and the parent was woken, not just
# that the spawn call returned a number.
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_EXEC_CMD="exec /spawner.elf" \
TINYOS_EXPECT="spawner: done status=" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

# The 60-second EDR status report tears whatever line is in flight, at an
# ARBITRARY character, so any witness can be split in two and stop matching.
# Every read below is a POSITION comparison, and a torn witness reports as
# absent -- i.e. as a kernel that never produced it. The tear is PROBABILISTIC
# (it only bites when the burst lands on that particular line), so a green run
# does NOT show the raw read is safe; it shows the burst missed this time.
# Analyse the REJOINED copy. See verify/edr-rejoin.sh (cases: edr-rejoin-test.sh).
REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"

sleep 3
cleanup
trap - EXIT

echo
echo "================ VERDICT ================"

if grep -q "Triple fault" "$TRACE" 2>/dev/null; then
    echo "RESULT: FAIL — 'Triple fault' in $TRACE"
    grep -E "check_exception|v=0e|v=08|Triple fault|^EIP=|CR2=" "$TRACE" | tail -15
    exit 1
fi

if grep -q "spawner: spawn failed" "$REJOINED" 2>/dev/null; then
    echo "RESULT: FAIL — spawn() returned an error"
    grep "spawner:" "$REJOINED" | tail -5
    exit 1
fi

# Ordered, like verify-argv.sh: a stale or duplicated line must not be able to
# stand in for a missing one.
l_pid=$(grep -n "spawner: child pid=" "$REJOINED" 2>/dev/null | head -1 | cut -d: -f1)
# The CHILD's argv, passed by the spawner through the syscall. "from"/"spawn"
# come from spawner.c, so these lines cannot be produced by the shell's own
# exec path — they prove the vector survived ring3 -> kernel -> new stack.
l_a1=$(grep -n "argv\[1\]=from"  "$REJOINED" 2>/dev/null | head -1 | cut -d: -f1)
l_a2=$(grep -n "argv\[2\]=spawn" "$REJOINED" 2>/dev/null | head -1 | cut -d: -f1)
l_hi=$(grep -n "Hello from ELF!" "$REJOINED" 2>/dev/null | head -1 | cut -d: -f1)
l_done=$(grep -n "spawner: done status=" "$REJOINED" 2>/dev/null | head -1 | cut -d: -f1)

if [ -z "$l_pid" ] || [ -z "$l_a1" ] || [ -z "$l_a2" ] || [ -z "$l_hi" ] || [ -z "$l_done" ]; then
    echo "RESULT: FAIL/INCONCLUSIVE (typist rc=$TYPIST_RC)"
    echo "  child pid line=${l_pid:-none} argv1=${l_a1:-none} argv2=${l_a2:-none}" \
         "hello=${l_hi:-none} done=${l_done:-none}"
    echo "--- tail of $SERIAL ---"
    grep -v "Suspicious" "$REJOINED" | tail -30
    exit 2
fi

# waitpid must return AFTER the child has produced its output, otherwise the
# parent was woken early and the "wait" proved nothing.
if [ "$TYPIST_RC" -eq 0 ] && [ "$l_hi" -gt "$l_pid" ] && [ "$l_done" -gt "$l_a2" ]; then
    echo "RESULT: PASS — ring-3 spawn + argv + waitpid all work"
    grep -E "spawner:|argv\[|Hello from ELF!" "$REJOINED" | head -12
    exit 0
else
    echo "RESULT: FAIL (typist rc=$TYPIST_RC; out of order:" \
         "pid=$l_pid a1=$l_a1 a2=$l_a2 hello=$l_hi done=$l_done)"
    grep -v "Suspicious" "$REJOINED" | tail -30
    exit 2
fi
