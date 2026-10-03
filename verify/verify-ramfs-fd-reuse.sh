#!/bin/bash
# =============================================================================
# verify-ramfs-fd-reuse.sh -- a RAMFS descriptor is not closed behind the task
# that holds it.
#
# WHAT THIS PROVES
#
# RAMFS descriptors are one global table, and the next ramfs_open() anywhere
# reuses the lowest free slot. A holder whose slot was closed behind its back
# therefore reads and writes whichever file -- anyone's -- is opened next.
# Two paths did that:
#
#   sweep   every ELF load ran ramfs_close_on_exec(), which closed every
#           close-on-exec descriptor in the system. All SYS_OPEN descriptors
#           are close-on-exec, so one user's spawn closed every other
#           process's open files, and their next read() could return root's.
#   stream  a child inherits a redirected stdout/stdin as the bare RAMFS fd;
#           the shell's restore right after spawning a background job or a
#           pipeline stage closed it, and the child's output went to the next
#           file opened.
#
# /fdprobe.elf drives both and reports where the bytes landed:
#
#   leg 1  sweep:  a=4 (POSITIVE CONTROL), b=0
#   leg 2  stream: out=4 (POSITIVE CONTROL), victim=0
#   leg 3  exit:   with 5 of the uid's 8 RAMFS slots held, 4 children exit
#                  holding an inherited redirected stdout, then 2 exit holding
#                  2 open files each; the uid must still have room after each
#                  batch. sys_exit released nothing.
#   leg 4  cap:    root holds 3 slots from a background job, a child of the
#                  probe holds 2; the probe then opens 6 (its uid's 8, less 2)
#                  and is refused with -EAGAIN. Root then holds 7: the probe
#                  opens 3 and the last 4 free slots stay root's. Before, one
#                  user's two processes could hold all 16, and with none free
#                  no exec -- root's included -- could open its ELF.
#
# The controls matter: a kernel that refused the write outright would keep B
# and VICTIM clean too, and break `cmd > f &`.
#
# Runs as a NON-ROOT user; root only starts the leg-4 holder.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: fdreuse.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=fduser
TESTPASS=fdpass1

ISO=dist/tinyos.iso
SERIAL=fdreuse.log
TRACE=fdreuse-trace.log
RUN_DISK=/tmp/tinyos-fdreuse-disk.img
MON_SOCK=/tmp/tinyos-fdreuse-mon.sock


guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

[ -f userspace/fdprobe.c ] \
    || guard_fail "userspace/fdprobe.c is missing; nothing would hold a
  descriptor across a spawn or a restore and the harness would grade a no-op"
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

if [ "$(strings "$ISO" | grep -c 'PROBE stream out=')" -eq 0 ]; then
    guard_fail "the ISO does not contain fdprobe's output strings"
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
TINYOS_EXEC_CMD="exec /fdprobe.elf roothold &" \
TINYOS_EXPECT="PROBE roothold held=" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
su $TESTUSER=>Now running as;\
!id=>uid=;\
exec /fdprobe.elf=>PROBE done" \
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
    echo "RESULT: INCONCLUSIVE — /fdprobe.elf did not run to completion."
    grep -a "PROBE" "$SERIAL"
    exit 3
fi

field() {
    grep -a "PROBE $1 .*$2=" "$SERIAL" | tail -1 \
        | sed -n "s/.* $2=\(-\{0,1\}[0-9][0-9]*\).*/\1/p"
}
SW_A=$(field sweep a)
SW_B=$(field sweep b)
ST_OUT=$(field stream out)
ST_VIC=$(field stream victim)
exfield() {
    grep -a "PROBE exit $1 .*$2=" "$SERIAL" | tail -1 \
        | sed -n "s/.* $2=\(-\{0,1\}[0-9][0-9]*\).*/\1/p"
}
EX_HELD=$(exfield stream held)
EX_S_SP=$(exfield stream spawned)
EX_S_OPEN=$(exfield stream open)
EX_F_SP=$(exfield files spawned)
EX_F_N=$(exfield files opened)
EX_F_OPEN=$(exfield files open)
capfield() {
    grep -a "PROBE cap $1 .*$2=" "$SERIAL" | tail -1 \
        | sed -n "s/.* $2=\(-\{0,1\}[0-9][0-9]*\).*/\1/p"
}
ROOT_FIRST=$(grep -a "PROBE roothold held=" "$SERIAL" | head -1 | sed -n 's/.*held=\([0-9][0-9]*\).*/\1/p')
CAP_CHILD=$(grep -a "PROBE cap child-held=" "$SERIAL" | tail -1 | sed -n 's/.*child-held=\([0-9][0-9]*\).*/\1/p')
CAP_U_N=$(capfield user opened)
CAP_U_RC=$(capfield user refused)
CAP_ACK=$(capfield reserve acked)
CAP_R_N=$(capfield reserve opened)
CAP_R_RC=$(capfield reserve refused)

echo "  sweep : a=${SW_A:-none} b=${SW_B:-none}        (expected a=4 b=0)"
echo "  stream: out=${ST_OUT:-none} victim=${ST_VIC:-none} (expected out=4 victim=0)"
echo "  exit  : held=${EX_HELD:-none} stream spawned=${EX_S_SP:-none} open=${EX_S_OPEN:-none}; files spawned=${EX_F_SP:-none} opened=${EX_F_N:-none} open=${EX_F_OPEN:-none}"
echo "          (expected held=5, 4 and open>=0, 2/4 and open>=0)"
echo "  cap   : root=${ROOT_FIRST:-none} child=${CAP_CHILD:-none} user opened=${CAP_U_N:-none} refused=${CAP_U_RC:-none}; reserve acked=${CAP_ACK:-none} opened=${CAP_R_N:-none} refused=${CAP_R_RC:-none}"
echo "          (expected root=3 child=2, 6/-11, acked=1 3/-11)"

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    grep -a "PROBE" "$SERIAL"
    exit 1
}

for v in SW_A SW_B ST_OUT ST_VIC EX_HELD EX_S_SP EX_S_OPEN EX_F_SP EX_F_N EX_F_OPEN \
         ROOT_FIRST CAP_CHILD CAP_U_N CAP_U_RC CAP_ACK CAP_R_N CAP_R_RC; do
    [ -n "${!v}" ] || fail_with "the probe never reported $v"
done

if [ "$SW_B" -ne 0 ]; then
    fail_with "a write through a descriptor opened BEFORE a spawn landed in a file opened after it" \
        "The spawn closed the descriptor behind its holder (ramfs_close_on_exec" \
        "is global), and the next open reused the slot."
fi
[ "$SW_A" -eq 4 ] || fail_with "sweep: the write did not reach its own file (a=$SW_A)" \
    "Positive control: the descriptor must still work after a spawn."
echo "PASS leg 1: a spawn leaves other descriptors alone, and the write arrived."

if [ "$ST_VIC" -ne 0 ]; then
    fail_with "a child's inherited stdout wrote into a file someone else opened later" \
        "The parent's restore closed the RAMFS fd the child still used."
fi
[ "$ST_OUT" -eq 4 ] || fail_with "stream: the child's output did not reach the redirect target (out=$ST_OUT)" \
    "Positive control: \`cmd > f &\` must still write f."
echo "PASS leg 2: the child's output reached its file and nothing else."

# On a leaking kernel the uid's budget runs out mid-batch: the next spawn
# fails (it opens the ELF and the redirect target), and the redirect it gives
# back is what the final open then finds. So a short spawn count IS the
# stream leak.
[ "$EX_HELD" -eq 5 ] \
    || fail_with "exit: the slots were not held (held=$EX_HELD)" \
    "Positive control: with fewer slots held, 4 leaks cannot exhaust the uid."
[ "$EX_S_SP" -eq 4 ] && [ "$EX_S_OPEN" -ge 0 ] \
    || fail_with "children that exited with a redirected stdout filled the RAMFS table (spawned=$EX_S_SP of 4, open=$EX_S_OPEN)" \
    "sys_exit did not drop the reference an inherited file stream carries."
[ "$EX_F_SP" -eq 2 ] && [ "$EX_F_N" -eq 4 ] && [ "$EX_F_OPEN" -ge 0 ] \
    || fail_with "children that exited with files open filled the RAMFS table (spawned=$EX_F_SP of 2, opened=$EX_F_N, open=$EX_F_OPEN)" \
    "sys_exit did not close the task's SYS_OPEN descriptors."
echo "PASS leg 3: normal exits give their RAMFS descriptors back."

[ "$ROOT_FIRST" -eq 3 ] && [ "$CAP_CHILD" -eq 2 ] && [ "$CAP_ACK" -eq 1 ] \
    || fail_with "cap: the setup did not hold (root=$ROOT_FIRST child=$CAP_CHILD acked=$CAP_ACK)" \
    "Positive control: the counts below assume root holds 3, then 7, and the child 2."
[ "$CAP_U_N" -eq 6 ] && [ "$CAP_U_RC" -eq -11 ] \
    || fail_with "one uid's processes held $((CAP_U_N + CAP_CHILD)) RAMFS slots (refused=$CAP_U_RC); the cap is 8, refused -EAGAIN" \
    "Only the per-process cap applied, so one user could hold the whole table."
[ "$CAP_R_N" -eq 3 ] && [ "$CAP_R_RC" -eq -11 ] \
    || fail_with "with 7 slots free a non-root user opened $CAP_R_N (refused=$CAP_R_RC); the last 4 are root's" \
    "Without the reserve, two users together could still take every slot."
echo "PASS leg 4: a uid is capped at 8 RAMFS slots and the last 4 free are root's."

echo ""
echo "RESULT: PASS"
exit 0
