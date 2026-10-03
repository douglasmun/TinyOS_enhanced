#!/bin/bash
# =============================================================================
# verify-tcp-socket-cap.sh -- an unprivileged user cannot take the TCP socket
# table, and a task's sockets are released when it exits.
#
# WHAT THIS PROVES
#
# TCPSOCK_SOCKET is ungated. The table holds 8 sockets, there was no per-user
# limit, and nothing released a socket its owner never closed: a CLOSED
# socket is never reclaimed. So any user could open eight, exit, and leave
# the kernel and root without TCP until reboot.
#
# /tcpcap.elf, run as a NON-ROOT user:
#
#   leg 1  cap:  opens until refused -- exactly 2 (TCP_USER_MAX_SOCKETS),
#                refused with -EAGAIN (-11), not -EMFILE (table full).
#   leg 2  exit: a child opens until refused and exits holding them; the
#                parent (same uid) then opens 2 again. Without exit cleanup
#                the child's sockets still count against the uid and the
#                parent opens 0. child=2 is the POSITIVE CONTROL: the child
#                really held sockets when it died.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: tcpcap.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=tcpuser
TESTPASS=tcppass1

ISO=dist/tinyos.iso
SERIAL=tcpcap.log
TRACE=tcpcap-trace.log
RUN_DISK=/tmp/tinyos-tcpcap-disk.img
MON_SOCK=/tmp/tinyos-tcpcap-mon.sock


guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

[ -f userspace/tcpcap.c ] \
    || guard_fail "userspace/tcpcap.c is missing; nothing would open sockets"
grep -q "tcpcap_elf_data" src/kernel.c \
    || guard_fail "src/kernel.c does not install /tcpcap.elf into ramfs"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
for prog in shell tcpcap; do
    python3 tools/sign_elf.py userspace/$prog.elf >/dev/null 2>&1 || exit 1
    python3 tools/elf_to_c.py userspace/$prog.elf.signed \
        src/${prog}_elf_data.c src/${prog}_elf_data.h ${prog}_elf_data >/dev/null || exit 1
done
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

if [ "$(strings "$ISO" | grep -c 'PROBE exit child=')" -eq 0 ]; then
    guard_fail "the ISO does not contain tcpcap's output strings"
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
exec /tcpcap.elf=>PROBE done" \
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
    echo "RESULT: INCONCLUSIVE — /tcpcap.elf did not run to completion."
    grep -a "PROBE" "$SERIAL"
    exit 3
fi

field() {
    grep -a "PROBE $1 .*$2=" "$SERIAL" | tail -1 \
        | sed -n "s/.* $2=\(-\{0,1\}[0-9][0-9]*\).*/\1/p"
}
CAP_N=$(field cap opened)
CAP_RC=$(field cap refused)
EX_CHILD=$(field exit child)
EX_N=$(field exit opened)

echo "  cap : opened=${CAP_N:-none} refused=${CAP_RC:-none}   (expected 2, -11)"
echo "  exit: child=${EX_CHILD:-none} opened=${EX_N:-none}     (expected 2, 2)"

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    grep -a "PROBE" "$SERIAL"
    exit 1
}

for v in CAP_N CAP_RC EX_CHILD EX_N; do
    [ -n "${!v}" ] || fail_with "the probe never reported $v"
done

[ "$CAP_N" -eq 2 ] || fail_with "an unprivileged user opened $CAP_N TCP sockets (cap is 2)" \
    "With no per-user cap one user takes the whole 8-slot table."
[ "$CAP_RC" -eq -11 ] || fail_with "the refusal was $CAP_RC, expected -EAGAIN (-11)"
echo "PASS leg 1: capped at 2, refused with -EAGAIN."

[ "$EX_CHILD" -eq 2 ] || fail_with "the child opened $EX_CHILD sockets, expected 2" \
    "Positive control: the child must die holding sockets for leg 2 to grade anything."
[ "$EX_N" -eq 2 ] || fail_with "after the child exited holding 2 sockets, its uid could open $EX_N" \
    "The exiting task's sockets were not released."
echo "PASS leg 2: a task's sockets are released at exit."

echo ""
echo "RESULT: PASS"
exit 0
