#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-cred-lock-quiet.sh — locking an account and unlocking it again must
# not print to the console. Both events are already audited.
#
# user_authenticate_for() printed "[USER] Account '%s' locked after %d failed
# attempts" on the failure that locks an account, and user_set_password()
# printed "[USER] Account '%s' unlocked after password set" when a password
# change clears the lock. Each sits next to an audit_log() call recording the
# same event (AUDIT_AUTH_ACCOUNT_LOCKED, AUDIT_AUTH_PASSWORD_CHANGE), on the
# console the ring-3 shell shares. The lock is reachable by any user through
# the kernel shell's `su`, and from a process through SYS_SWITCH_USER in the
# legacy build; the unlock through ring-3 `passwd USER` (SYS_CRED).
#
# Sequence: root creates a victim and a prober. As the prober, three wrong
# `su victim` passwords lock the victim, and the correct one is then refused.
# Root, back in the ring-3 shell, resets the victim's password; the prober then
# su's to the victim with the new one.
#
# ASSERTIONS
#   1. POSITIVE CONTROLS: the correct password was refused with "account
#      locked" (the lock happened); the ring-3 passwd reported success; the
#      new password then worked (the unlock happened)
#   2. zero "[USER] Account" lines in the whole log
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: lockquiet.log (serial), lockquiet-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
VICTIM=lqvictim
VICTIMPW=lqpass1
NEWPW=lqnewpw1
PROBER=lqprober
PROBERPW=lqprober1

ISO=dist/tinyos.iso
SERIAL=lockquiet.log
TRACE=lockquiet-trace.log
RUN_DISK=/tmp/tinyos-lockquiet-disk.img
MON_SOCK=/tmp/tinyos-lockquiet-mon.sock

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

# The lock lasts USER_LOCKOUT_DURATION (60 s) from the third failure; the
# "account locked" control comes right after it. The unlock is the password
# reset, not the timeout: the final su is the only proof it happened.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
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
su $VICTIM=>Password for;\
!wrongpw1=>authentication failure;\
su $VICTIM=>Password for;\
!wrongpw2=>authentication failure;\
su $VICTIM=>Password for;\
!wrongpw3=>su:;\
su $VICTIM=>Password for;\
!$VICTIMPW=>account locked;\
su root=>Password for;\
!$PASSWORD=>Switched to user: root;\
exec /shell.elf=>TinyOS shell (ring 3);\
passwd $VICTIM=>Enter new password;\
!$NEWPW=>Retype new password;\
!$NEWPW=>password updated successfully;\
kshell=>Switching to the kernel shell;\
su $PROBER=>Now running as;\
su $VICTIM=>Password for;\
!$NEWPW=>Switched to user: $VICTIM" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"
cleanup

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

for want in "su: account locked" "passwd: password updated successfully" "Switched to user: $VICTIM"; do
    if ! grep -aq "$want" "$REJOINED"; then
        echo "RESULT: INCONCLUSIVE — never saw '$want', so the lock/unlock was not driven"
        grep -a "su:\|passwd:\|Switched to\|Now running" "$REJOINED" | tail -12 | sed 's/^/    /'
        exit 3
    fi
done
echo "  positive controls: victim locked (correct password refused), reset by root, new password accepted"

PRINTS=$(grep -ac "\[USER\] Account" "$REJOINED")
echo "  [USER] Account lines: $PRINTS"
if [ "$PRINTS" -ne 0 ]; then
    echo "RESULT: FAIL — $PRINTS console line(s) for an audited lock/unlock"
    grep -a "\[USER\] Account" "$REJOINED" | head -4 | sed 's/^/    /'
    exit 1
fi
if grep -aqi "triple fault\|PANIC" "$REJOINED"; then
    echo "RESULT: FAIL — kernel panicked during the run"
    exit 1
fi
echo "RESULT: PASS — an account locked and unlocked with nothing on the console"
exit 0
