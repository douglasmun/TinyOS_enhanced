#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-auth-user-oracle.sh — login and su refuse an unknown user, a wrong
# password and a locked account with the same words.
#
# Both prompts named the reason: login printed "Login incorrect (user not
# found)" against "(bad password)", and the kernel shell's su answered an
# unknown name "does not exist" -- before even asking for a password --
# against "authentication failure" for a real one, and "account locked" once
# the lockout tripped. Each told whoever was typing which accounts exist and
# when one had locked. The audit log keeps the reason; the terminal does not.
#
# ASSERTIONS
#   1. LOGIN: the refusal for an unknown name and for root's wrong password
#      are the same line
#   2. SU (as an unprivileged user in the kernel shell): an unknown name is
#      asked for a password like any other, and its refusal, three wrong
#      passwords and the right password on the now-locked account all print
#      the same line
#   3. POSITIVE CONTROL: all five su attempts produced a refusal line
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: authoracle.log (serial), authoracle-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
VICTIM=aovictim
VICTIMPW=aopass1
PROBER=aoprober
PROBERPW=aoprober1
NOSUCH=aonosuch

ISO=dist/tinyos.iso
SERIAL=authoracle.log
TRACE=authoracle-trace.log
RUN_DISK=/tmp/tinyos-authoracle-disk.img
MON_SOCK=/tmp/tinyos-authoracle-mon.sock

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

# `su $NOSUCH` is sent unverified: an unfixed kernel refuses it at once and
# the following "password" runs as a command, a fixed one prompts and
# refuses after. Either way the `id` after it runs only once su is done, so
# it, not the refusal (which may print before the password is typed), is
# what the typist waits for. The trailing `id` waits for the prober's own uid, so every
# refusal (each followed by a 3 s delay) has printed before the verdict.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_PRELOGIN_USERS="$NOSUCH,root" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
useradd $VICTIM=>Enter password for new user;\
!$VICTIMPW=>created;\
useradd $PROBER=>Enter password for new user;\
!$PROBERPW=>created;\
kshell=>Switching to the kernel shell;\
su $PROBER=>Now running as;\
!su $NOSUCH;\
!wrongpw0;\
!id=>uid=10;\
su $VICTIM=>Password for;\
!wrongpw1=>su:;\
su $VICTIM=>Password for;\
!wrongpw2=>su:;\
su $VICTIM=>Password for;\
!wrongpw3=>su:;\
su $VICTIM=>Password for;\
!$VICTIMPW;\
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

FAILS=0

# 1. Login.
LOGIN=$(grep -a "^Login incorrect" "$REJOINED" | tr -d '\r')
NLOGIN=$(printf '%s\n' "$LOGIN" | grep -c .)
echo "  login refusals:"
printf '%s\n' "$LOGIN" | sed 's/^/    /'
if [ "$NLOGIN" -ne 2 ]; then
    echo "RESULT: INCONCLUSIVE — expected 2 login refusals, saw $NLOGIN"
    exit 3
fi
if [ "$(printf '%s\n' "$LOGIN" | sort -u | wc -l)" -ne 1 ]; then
    echo "  FAIL: login names the reason it refused"
    FAILS=$((FAILS + 1))
fi

# 2. su, from the prober's switch onward.
SU_LINE=$(grep -an "Now running as" "$REJOINED" | head -1 | cut -d: -f1)
[ -n "$SU_LINE" ] || { echo "RESULT: INCONCLUSIVE — never became $PROBER"; exit 3; }
REGION=$(tail -n +"$SU_LINE" "$REJOINED" | tr -d '\r')
SU=$(printf '%s\n' "$REGION" | grep -a "^su: ")
NSU=$(printf '%s\n' "$SU" | grep -c .)
echo "  su refusals:"
printf '%s\n' "$SU" | sed 's/^/    /'
if [ "$NSU" -ne 5 ]; then
    echo "RESULT: INCONCLUSIVE — expected 5 su refusals, saw $NSU"
    exit 3
fi
if [ "$(printf '%s\n' "$SU" | sort -u | wc -l)" -ne 1 ]; then
    echo "  FAIL: su names the reason it refused"
    FAILS=$((FAILS + 1))
fi
if ! printf '%s\n' "$REGION" | grep -aq "Password for $NOSUCH"; then
    echo "  FAIL: su refused an unknown user without asking for a password"
    FAILS=$((FAILS + 1))
fi

if grep -aqi "triple fault\|PANIC" "$REJOINED"; then
    echo "  FAIL: kernel panicked during the run"
    FAILS=$((FAILS + 1))
fi
if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS check(s): a refusal tells an unknown user from a known one"
    exit 1
fi
echo "RESULT: PASS — login and su answer unknown, wrong and locked alike"
exit 0
