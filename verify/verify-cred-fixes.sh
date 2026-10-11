#!/usr/bin/env bash
#
# verify-cred-fixes.sh — five credential bugs, one boot.
#
# F1  `passwd` accepted two empty lines: the lengths matched, the compare
#     passed, and user_set_password() stored the hash of "". Fix: both
#     primitives (user_set_password, user_create) refuse an empty password;
#     passwd and useradd say so.
#
# F2  su's password loop stopped reading once its 64-byte buffer filled. The
#     rest of the typed line stayed in the keyboard ring and the kernel shell
#     read it back as a command line. Fix: one read_line() for every
#     credential prompt, which always consumes the line to its newline.
#
# F3  The login-name loop had the same bug: a name longer than 31 characters
#     logged in as its 31-character prefix and the tail was read as the
#     password. Fix: read_line(), and a name that does not fit is refused.
#
# F4  user_create() checked the FULL name for a duplicate, then truncated it to
#     31 characters: `useradd` of a 32-character name stored a second account
#     under an existing 31-character user's name. Fix: refuse, never truncate.
#
# F5  The IDS spray table stores names truncated to its slot but compared them
#     with strcmp against the full name, so a 32+-character name never matched
#     its own entry: three failed su's of one over-long name raised a
#     "Credential spray" alert for one distinct name.
#
# (The same PR drops /etc/issue's root/root and user/user hints. That text is
# in user_create_etc_structure(), which nothing calls, so no boot can witness
# it and there is no leg for it.)
#
# WHAT IS ASSERTED
#
#   Session 1 (root, ring 3): useradd credu, credx, creds, $LONG31.
#     `passwd creds` with two empty lines must not report success, and
#     `useradd credv` with an empty password must not create it (F1). Then, in the
#     kernel shell, `useradd $LONG32` must not create it (F4) -- the ring-3
#     path cannot reach F4: SYS_CRED copies the name into a 32-byte buffer
#     and refuses it -ENAMETOOLONG at the boundary.
#   Session 2 (credu, kernel shell): three `su $LONG40` with a wrong password
#     must not raise a spray alert (F5). `su credx` with 63 a's then "zzspill"
#     must not run zzspill (F2); control: su reported the failure.
#   Session 3 (login prompt): "$LONG31" + "credpw2" typed as one login name
#     must not log in (F3); control: the refusal is printed.
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem (nothing proven).

set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
ISO=dist/tinyos.iso
SERIAL=cred-fixes.log
TRACE=cred-fixes-trace.log
RUN_DISK=/tmp/tinyos-credfixes-disk.img
MON_SOCK=/tmp/tinyos-credfixes-mon.sock

LONG31=longname$(printf 'q%.0s' $(seq 23))      # 31 chars: fits
LONG32=${LONG31}x                                # 32 chars: does not
LONG40=spray$(printf 'y%.0s' $(seq 35))          # 40 chars
SUPW=$(printf 'a%.0s' $(seq 63))zzspill          # 63 fill the buffer, then a command

guard_fail() { echo "RESULT: INCONCLUSIVE — $*"; exit 2; }

[ ${#LONG31} -eq 31 ] && [ ${#LONG40} -eq 40 ] || guard_fail "name lengths miscomputed"
command -v qemu-system-i386 >/dev/null 2>&1 || guard_fail "qemu-system-i386 not found"
[ -f disk.img ] || guard_fail "disk.img not found"

echo "==> Building kernel + ISO..."
make >/dev/null 2>&1 || guard_fail "build failed"
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || guard_fail "mkrescue failed"

rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
cp disk.img "$RUN_DISK"

echo "==> Launching headless QEMU..."
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none 2>/dev/null &
QEMU_PID=$!
cleanup() {
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "${QEMU_PID:-}" ] && wait "$QEMU_PID" 2>/dev/null
    rm -f "$MON_SOCK" "$RUN_DISK"
    return 0
}
trap cleanup EXIT

# The blank '!=>' items send an empty line and pause 1 s. Where a fixed and an
# unfixed kernel prompt differently (useradd $LONG32 asks for a password only
# when unfixed; fixed, "credpw3" reaches the kernel shell as an unknown
# command), the next lines are unverified pauses, not waits.
PAUSES="!=>;!=>;!=>;!=>;!=>;"
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=300 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
useradd credu=>Enter password for new user;\
!credpw1=>created;\
useradd credx=>Enter password for new user;\
!credxpw1=>created;\
useradd creds=>Enter password for new user;\
!credspw1=>created;\
!useradd $LONG31=>Enter password for new user;\
!credpw2=>created;\
passwd creds=>Enter new password;\
!=>Retype;\
!=>passwd:;\
useradd credv=>Enter password for new user;\
!=>useradd:;\
kshell=>Switching to the kernel shell;\
!useradd $LONG32=>;\
!credpw3=>;\
${PAUSES}\
logout=>TinyOS login:;\
credu=>assword;\
!credpw1=>'help' for builtins;\
!=>\$;\
kshell=>Switching to the kernel shell;\
!su $LONG40=>Password for;\
!nopw1=>authentication failure;\
!su $LONG40=>Password for;\
!nopw1=>authentication failure;\
!su $LONG40=>Password for;\
!nopw1=>authentication failure;\
!su credx=>Password for;\
!$SUPW=>authentication failure;\
${PAUSES}\
!echo FINALLEG=>;\
logout=>TinyOS login:;\
!${LONG31}credpw2=>;\
${PAUSES}${PAUSES}${PAUSES}" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

# A login that does go through still has a PBKDF2 to finish.
sleep 30
cleanup
trap - EXIT

echo ""
echo "================ VERDICT ================"

[ -s "$SERIAL" ] || guard_fail "no serial output at all (typist rc=$TYPIST_RC)"

FAILS=()
note_fail() { FAILS+=("$1"); }

# grep -c, not grep -q: under pipefail grep -q SIGPIPEs on an early match.
count_in() { printf '%s\n' "$1" | grep -ac -- "$2"; }
LOG=$(grep -av Suspicious "$SERIAL")

# --- F4 ------------------------------------------------------------------
[ "$(count_in "$LOG" "user '$LONG31' created")" -gt 0 ] || guard_fail "F4: the 31-character user was never created (typist rc=$TYPIST_RC)"
if [ "$(count_in "$LOG" "user '$LONG32' created")" -gt 0 ]; then
    note_fail "F4: useradd created '$LONG32', stored truncated under the existing '$LONG31'"
fi
[ "$(count_in "$LOG" "user '$LONG32' created\|useradd: username too long")" -gt 0 ] || guard_fail "F4: useradd $LONG32 printed neither verdict"

# --- F1 ------------------------------------------------------------------
PW_OK=$(count_in "$LOG" "passwd: password updated successfully")
PW_REFUSED=$(count_in "$LOG" "passwd: password cannot be empty")
[ $((PW_OK + PW_REFUSED)) -gt 0 ] || guard_fail "F1: passwd creds printed neither verdict"
[ "$PW_OK" -eq 0 ] || note_fail "F1: passwd set creds's password from two empty lines"
UA_OK=$(count_in "$LOG" "user 'credv' created")
UA_REFUSED=$(count_in "$LOG" "useradd: password cannot be empty")
[ $((UA_OK + UA_REFUSED)) -gt 0 ] || guard_fail "F1: useradd credv printed neither verdict"
[ "$UA_OK" -eq 0 ] || note_fail "F1: useradd created credv with an empty password"

# --- F5 ------------------------------------------------------------------
SU_FAILS=$(count_in "$LOG" "su: authentication failure")
[ "$SU_FAILS" -ge 4 ] || guard_fail "F5/F2: only $SU_FAILS su failures; the su legs never ran (typist rc=$TYPIST_RC)"
if [ "$(count_in "$LOG" "Credential spray")" -gt 0 ]; then
    note_fail "F5: one over-long name failing su three times raised a spray alert: $(grep -a 'Credential spray' "$SERIAL" | head -1)"
fi

# --- F2 ------------------------------------------------------------------
if [ "$(count_in "$LOG" "Unknown command: zzspill")" -gt 0 ]; then
    note_fail "F2: the tail of an over-long su password ran as a kernel-shell command"
fi

# --- F3 ------------------------------------------------------------------
MARK=$(grep -na "^FINALLEG" "$SERIAL" | tail -1 | cut -d: -f1)
[ -n "$MARK" ] || guard_fail "F3: never reached the final login leg (typist rc=$TYPIST_RC)"
FINAL_REGION=$(tail -n +"$MARK" "$SERIAL")
LOGGED_IN=$(count_in "$FINAL_REGION" "'help' for builtins")
REFUSED=$(count_in "$FINAL_REGION" "Login name too long")
[ $((LOGGED_IN + REFUSED)) -gt 0 ] || guard_fail "F3: the over-long login name was neither refused nor logged in"
[ "$LOGGED_IN" -eq 0 ] || note_fail "F3: '${LONG31}credpw2' logged in as '$LONG31' (its tail was read as the password)"

if grep -qa "KERNEL PANIC" "$SERIAL" 2>/dev/null; then
    note_fail "the kernel panicked during the run"
fi
if grep -qa "Triple fault\|triple fault" "$TRACE" 2>/dev/null; then
    note_fail "the kernel triple-faulted during the run"
fi

if [ "${#FAILS[@]}" -gt 0 ]; then
    echo "RESULT: FAIL — ${#FAILS[@]} assertion(s)"
    for f in "${FAILS[@]}"; do echo "  - $f"; done
    echo "  --- last 40 serial lines ---"
    tail -40 "$SERIAL"
    exit 1
fi

echo "RESULT: PASS"
echo "  - F1: empty passwords refused by passwd and useradd"
echo "  - F2: an over-long su password was consumed whole; its tail never ran"
echo "  - F3: an over-long login name was refused, not logged in as its prefix"
echo "  - F4: a 32-character useradd was refused, not stored over '$LONG31'"
echo "  - F5: $SU_FAILS su failures, no spray alert for one over-long name"
exit 0
