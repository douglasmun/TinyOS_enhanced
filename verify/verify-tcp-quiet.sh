#!/bin/bash
# =============================================================================
# verify-tcp-quiet.sh -- an unprivileged SYS_TCPSOCK caller cannot make the
# kernel print.
#
# WHAT THIS PROVES
#
# tcp_send() printed a line for every send on a socket that was not
# ESTABLISHED, tcp_connect() one for every connect (and one per refusal), and
# the TCP timer two for every SYN_SENT connection it reaped. SYS_TCPSOCK made
# all of them ring-3 reachable, so an unprivileged loop could write as many
# kernel lines as it liked into the stream every user's output shares.
#
# `/netprobe.elf tcpquiet`, run unprivileged, sends 20 times on a socket that
# never connected, connects it to TEST-NET-3 (nothing answers), and waits past
# the 10 s SYN_SENT timeout. It reports:
#
#   PROBE tcpquiet ... refused=20 connect=0 after=-9
#       POSITIVE CONTROL: 20 sends refused (-ENOTCONN), the connect was
#       accepted, and the socket was gone afterwards (reaped -> -EBADF)
#
# Between "PROBE tcpquiet start" and "PROBE tcpquiet end", none of the old TCP
# lines may appear (HEAD: 20 + 1 + 2). The events must still be COUNTED:
# ifconfig's "TCP local:" send-refused rises by 20 and "TCP reaped:"
# timed-out by 1.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: tcpquiet.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=tquser
TESTPASS=tqpass12

ISO=dist/tinyos.iso
SERIAL=tcpquiet.log
TRACE=tcpquiet-trace.log
RUN_DISK=/tmp/tinyos-tcpquiet-disk.img
MON_SOCK=/tmp/tinyos-tcpquiet-mon.sock

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

grep -q '"tcpquiet"' userspace/netprobe.c \
    || guard_fail "userspace/netprobe.c has no tcpquiet mode; nothing would drive TCP"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
for prog in shell netprobe; do
    python3 tools/sign_elf.py userspace/$prog.elf >/dev/null 2>&1 || exit 1
    python3 tools/elf_to_c.py userspace/$prog.elf.signed \
        src/${prog}_elf_data.c src/${prog}_elf_data.h ${prog}_elf_data >/dev/null || exit 1
done
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

if [ "$(strings "$ISO" | grep -c 'PROBE tcpquiet fd=')" -eq 0 ]; then
    guard_fail "the ISO does not contain fdprobe's tcpquiet strings"
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
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="Supervisor:" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
su $TESTUSER=>Now running as;\
!id=>uid=;\
exec /netprobe.elf tcpquiet=>PROBE tcpquiet end;\
ifconfig=>Supervisor:" \
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

if ! grep -qa "PROBE tcpquiet fd=" "$SERIAL"; then
    echo "RESULT: INCONCLUSIVE — /netprobe.elf tcpquiet did not report."
    grep -a "PROBE" "$SERIAL"
    exit 3
fi

REPORT=$(grep -a "PROBE tcpquiet fd=" "$SERIAL" | tail -1)
field() { printf '%s\n' "$REPORT" | sed -n "s/.* $1=\(-\{0,1\}[0-9][0-9]*\).*/\1/p"; }
REFUSED=$(field refused); CONNECT=$(field connect); AFTER=$(field after)
WINDOW=$(awk '/PROBE tcpquiet start/{on=1} on{print} /PROBE tcpquiet end/{exit}' "$SERIAL")
NOISE=$(printf '%s\n' "$WINDOW" | grep -a -c -E \
    'tcp_send:|Initiating connection|Cannot resolve MAC|SYN flood protection|SYN_SENT timeout|SYN_RECEIVED timeout|Forcefully closing|No free sockets|TIME_WAIT (threshold|exhaustion)|Zero window')

# Counters: first ifconfig is the baseline, last is after the probe.
num() { sed -n "s/.*$1: *\([0-9][0-9]*\) $2.*/\1/p"; }
L0=$(grep -a "TCP local:" "$SERIAL" | head -1 | num "TCP local" send-refused)
L1=$(grep -a "TCP local:" "$SERIAL" | tail -1 | num "TCP local" send-refused)
T0=$(grep -a "TCP reaped:" "$SERIAL" | head -1 | num "TCP reaped" timed-out)
T1=$(grep -a "TCP reaped:" "$SERIAL" | tail -1 | num "TCP reaped" timed-out)
NLOCAL=$(grep -a -c "TCP local:" "$SERIAL")

echo "  refused=${REFUSED:-none} connect=${CONNECT:-none} after=${AFTER:-none} kernel TCP lines=$NOISE"
echo "  (expected refused=20 connect=0 after=-9, 0 lines)"
echo "  send-refused ${L0:-none} -> ${L1:-none}, timed-out ${T0:-none} -> ${T1:-none} (expected +20, +1)"

[ "${REFUSED:-0}" -eq 20 ] && [ "${CONNECT:-1}" -eq 0 ] && [ "${AFTER:-0}" -eq -9 ] \
    || { echo "RESULT: INCONCLUSIVE — the sends were not refused, the connect failed, or the socket was not reaped"; exit 3; }

if [ "$NOISE" -ne 0 ]; then
    echo "RESULT: FAIL — $NOISE kernel TCP lines landed in an unprivileged user's output"
    printf '%s\n' "$WINDOW" | grep -a -E 'TCP' | head
    exit 1
fi

if [ "$NLOCAL" -lt 2 ] || [ $((L1 - L0)) -ne 20 ] || [ $((T1 - T0)) -ne 1 ]; then
    echo "RESULT: FAIL — silent, but not counted (ifconfig TCP local/reaped)"
    exit 1
fi

echo "RESULT: PASS — 20 refused sends and a reaped connect printed nothing and were counted"
exit 0
