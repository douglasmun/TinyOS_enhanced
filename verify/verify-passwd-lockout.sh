#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-passwd-lockout.sh — a wrong current password at `passwd` counts
# toward the account lockout like a wrong password anywhere else.
#
# shell_cmd_passwd() checked the current password with bare
# user_verify_password(), the hash comparison alone: no failure count, no
# lockout, no refusal of a locked account. Login and su go through
# user_authenticate_for(), which keeps all three. So `passwd` was the one
# password prompt an account's lockout did not cover, and a locked account
# could still change its own password.
#
# Sequence (an unprivileged user in the ring-3 shell, via SYS_CRED):
#   passwd with the right current password      -> changed   (control)
#   passwd with a wrong one, three times        -> refused x3, account locks
#   passwd with the right one again             -> must be refused
#
# ASSERTIONS
#   1. POSITIVE CONTROL: the first change succeeded
#   2. exactly one "password updated successfully" and four refusals
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: pwlock.log (serial), pwlock-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=pluser
PW1=plpass1
PW2=plpass2

ISO=dist/tinyos.iso
SERIAL=pwlock.log
TRACE=pwlock-trace.log
RUN_DISK=/tmp/tinyos-pwlock-disk.img
MON_SOCK=/tmp/tinyos-pwlock-mon.sock

echo "==> Building kernel + ISO..."
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

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

# The last passwd is typed unverified, followed by three `id`s. On a fixed
# kernel it is refused and all three run; on an unfixed one the first two are
# taken as the new password and its confirmation, and the third runs. Either
# way the final wait for the user's own uid only matches after the attempt
# has resolved.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$PW1=>created;\
kshell=>Switching to the kernel shell;\
su $TESTUSER=>Now running as;\
exec /shell.elf=>TinyOS shell (ring 3);\
passwd=>(current);\
!$PW1=>Enter new password;\
!$PW2=>Retype new password;\
!$PW2=>password updated successfully;\
passwd=>(current);\
!wrongpw1=>token manipulation error;\
passwd=>(current);\
!wrongpw2=>token manipulation error;\
passwd=>(current);\
!wrongpw3=>token manipulation error;\
passwd=>(current);\
!$PW2;\
!id;\
!id;\
!id=>uid=10" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"
cleanup

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

UPDATED=$(grep -ac "passwd: password updated successfully" "$REJOINED")
REFUSED=$(grep -ac "passwd: authentication token manipulation error" "$REJOINED")
echo "  updated: $UPDATED  refused: $REFUSED"

if [ "$UPDATED" -lt 1 ] || [ "$REFUSED" -lt 3 ]; then
    echo "RESULT: INCONCLUSIVE — the control change or the three wrong attempts did not happen"
    grep -a "passwd:" "$REJOINED" | tail -8 | sed 's/^/    /'
    exit 3
fi
if [ "$UPDATED" -ne 1 ] || [ "$REFUSED" -ne 4 ]; then
    echo "RESULT: FAIL — after three wrong current passwords, passwd still accepted the right one"
    exit 1
fi
if grep -aqi "triple fault\|PANIC" "$REJOINED"; then
    echo "RESULT: FAIL — kernel panicked during the run"
    exit 1
fi
echo "RESULT: PASS — passwd's current-password check counts toward and honours the lockout"
exit 0
