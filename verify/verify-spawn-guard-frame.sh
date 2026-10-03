#!/bin/bash
# =============================================================================
# verify-spawn-guard-frame.sh -- creating a task does not leave its kernel
# guard page not-present in the CALLER's page tables.
#
# WHAT THIS PROVES
#
# task_create_*() mapped each new task's kernel stack, and marked its guard
# page not-present, through map_page()/pae_get_pte() -- which act on the
# CURRENT CR3. Called from SYS_SPAWN, that is the spawning process's user
# PDPT, and the write COW-cloned the shared kernel page table into it. The
# guard's release at the child's exit then restored the mapping in the dying
# child's tables, never the parent's. The parent kept a not-present entry over
# a frame the PMM now handed out again, and the first kernel write to it on
# the parent's behalf -- a ramfs node for its next new file -- took a #PF in
# ring 0: KERNEL PANIC, reachable by any user with spawn + waitpid + open.
#
# HOW IT IS WITNESSED
#
# `/fdprobe.elf guard` runs ROUNDS rounds of {spawn, waitpid, create a file,
# write a byte}. Broken kernel: panic in the first rounds. Fixed: every round
# completes and every file is created.
#
#   rounds  == 8   every spawn/wait round ran          [POSITIVE CONTROL]
#   created == 8   every file creation after it worked
#   no "KERNEL PANIC" anywhere in the log
#
# Runs as a NON-ROOT user: the panic needed no privilege.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: guardframe.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=gfuser
TESTPASS=gfpass1

ISO=dist/tinyos.iso
SERIAL=guardframe.log
TRACE=guardframe-trace.log
RUN_DISK=/tmp/tinyos-guardframe-disk.img
MON_SOCK=/tmp/tinyos-guardframe-mon.sock

ROUNDS=8             # userspace/fdprobe.c

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

[ -f userspace/fdprobe.c ] \
    || guard_fail "userspace/fdprobe.c is missing"
grep -q "fdprobe_elf_data" src/kernel.c \
    || guard_fail "src/kernel.c does not install /fdprobe.elf into ramfs"

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

if [ "$(strings "$ISO" | grep -c 'PROBE guard rounds=')" -eq 0 ]; then
    guard_fail "the ISO does not contain fdprobe's guard-mode strings"
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
exec /fdprobe.elf guard=>PROBE done" \
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
    echo "RESULT: INCONCLUSIVE — /fdprobe.elf guard did not run to completion."
    grep -a "PROBE" "$SERIAL"
    exit 3
fi

field() {
    grep -a "PROBE .*$1=" "$SERIAL" | tail -1 \
        | sed -n "s/.*$1=\(-\{0,1\}[0-9][0-9]*\).*/\1/p"
}
GOT_ROUNDS=$(field rounds)
CREATED=$(field created)

echo "  spawn/wait rounds : ${GOT_ROUNDS:-none}  (expected $ROUNDS)"
echo "  files created     : ${CREATED:-none}  (expected $ROUNDS)"

if [ "${GOT_ROUNDS:-}" != "$ROUNDS" ]; then
    echo "RESULT: INCONCLUSIVE — only ${GOT_ROUNDS:-none} spawn rounds ran; the probe"
    echo "  never reached the state the bug needs"
    exit 3
fi
if [ "${CREATED:-}" != "$ROUNDS" ]; then
    echo "RESULT: FAIL — only ${CREATED:-none} of $ROUNDS files were created"
    exit 1
fi
echo "RESULT: PASS — $ROUNDS spawn/wait/create rounds, no panic"
exit 0
