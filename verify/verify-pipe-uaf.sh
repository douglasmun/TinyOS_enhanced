#!/bin/bash
# =============================================================================
# verify-pipe-uaf.sh -- destroying a pipe a spawned child still holds does not
# free the buffer under the child.
#
# WHAT THIS PROVES
#
# A child spawned while its creator's stdout is a pipe inherits the stream by
# shallow copy (streams_inherit), so it holds the raw pipe_buffer_t pointer.
# PIPE_OP_DESTROY, and the owner's exit through task_pipes_cleanup(), used to
# pmm_free the buffer's frames at once. The child's next write then went
# through the stale pointer into whatever the PMM handed those frames to next.
# Every call involved is an ungated ring-3 syscall, so any user could do it.
#
# HOW IT IS WITNESSED
#
# /pipeprobe.elf destroys the pipe under its sleeping child and immediately
# creates a second pipe, which takes the freed frames on the broken kernel.
# The child's write then lands in the second pipe and the parent reads it back
# ("stray bytes"). A freed pipe that nobody reuses still says "read end
# closed", so without the re-allocation the broken kernel would also return
# EPIPE and this harness would grade nothing.
#
#   leg 1  control: a live pipe        -> write 5, parent reads 5  [POSITIVE CONTROL]
#   leg 2  write after DESTROY         -> -EPIPE (-32)
#   leg 3  bytes in the second pipe    -> 0
#
# Leg 1 is not optional: a probe whose spawn or read never worked reports
# "write failed, nothing stray", which is exactly the fixed kernel's answer.
#
# Runs as a NON-ROOT user: the use-after-free needed no privilege.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: pipeuaf.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=pipeuser
TESTPASS=pipepass1

ISO=dist/tinyos.iso
SERIAL=pipeuaf.log
TRACE=pipeuaf-trace.log
RUN_DISK=/tmp/tinyos-pipeuaf-disk.img
MON_SOCK=/tmp/tinyos-pipeuaf-mon.sock

MSG_LEN=5            # "STRAY", userspace/pipeprobe.c
EXP_EPIPE=-32        # src/errno.h

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

[ -f userspace/pipeprobe.c ] \
    || guard_fail "userspace/pipeprobe.c is missing; nothing would destroy a
  pipe under a live child and the harness would grade a no-op"
grep -q "pipeprobe_elf_data" src/kernel.c \
    || guard_fail "src/kernel.c does not install /pipeprobe.elf into ramfs"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
for prog in shell pipeprobe; do
    python3 tools/sign_elf.py userspace/$prog.elf >/dev/null 2>&1 || exit 1
    python3 tools/elf_to_c.py userspace/$prog.elf.signed \
        src/${prog}_elf_data.c src/${prog}_elf_data.h ${prog}_elf_data >/dev/null || exit 1
done
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

if [ "$(strings "$ISO" | grep -c 'PROBE stray-bytes')" -eq 0 ]; then
    guard_fail "the ISO does not contain pipeprobe's output strings"
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
cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
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
exec /pipeprobe.elf=>PROBE done" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

if ! grep -qa "PROBE done" "$SERIAL"; then
    echo "RESULT: INCONCLUSIVE — /pipeprobe.elf did not run to completion."
    grep -a "PROBE" "$SERIAL"
    exit 3
fi

field() {
    grep -a "PROBE .*$1=" "$SERIAL" | tail -1 \
        | sed -n "s/.*$1=\(-\{0,1\}[0-9][0-9]*\).*/\1/p"
}
CTL_WRITE=$(field control-write)
CTL_BYTES=$(field control-bytes)
UAF_WRITE=$(field child-write)
STRAY=$(field stray-bytes)

echo "  control write / read : ${CTL_WRITE:-none} / ${CTL_BYTES:-none}  (expected $MSG_LEN / $MSG_LEN)"
echo "  write after DESTROY  : ${UAF_WRITE:-none}  (expected $EXP_EPIPE)"
echo "  bytes in second pipe : ${STRAY:-none}  (expected 0)"

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    grep -a "PROBE" "$SERIAL"
    exit 1
}

for v in CTL_WRITE CTL_BYTES UAF_WRITE STRAY; do
    [ -n "${!v}" ] || fail_with "the probe never reported $v"
done

# --- Leg 1: POSITIVE CONTROL ----------------------------------------------
if [ "$CTL_WRITE" -ne "$MSG_LEN" ] || [ "$CTL_BYTES" -ne "$MSG_LEN" ]; then
    fail_with "control pipe: child wrote $CTL_WRITE, parent read $CTL_BYTES" \
        "The probe's spawn-onto-a-pipe plumbing does not work, so legs 2 and 3" \
        "would report 'failed, nothing stray' on any kernel."
fi
echo "PASS leg 1 (positive control): a live pipe carries the child's bytes."

# --- Leg 2/3: the use-after-free ------------------------------------------
if [ "$STRAY" -ne 0 ]; then
    fail_with "the child's write after DESTROY appeared in an unrelated pipe ($STRAY bytes)" \
        "PIPE_OP_DESTROY freed the frames while the child still held the" \
        "buffer; the next PIPE_CREATE got them, and the child's write landed" \
        "in it. That is a ring-3 write into recycled kernel memory."
fi
if [ "$UAF_WRITE" -ne "$EXP_EPIPE" ]; then
    fail_with "the child's write after DESTROY returned $UAF_WRITE, expected $EXP_EPIPE" \
        "A destroyed pipe must refuse writes with EPIPE. A success means the" \
        "write went somewhere -- into freed frames, if not into the second pipe."
fi
echo "PASS leg 2: the write after DESTROY was refused with EPIPE."
echo "PASS leg 3: nothing reached the second pipe."

echo ""
echo "RESULT: PASS"
exit 0
