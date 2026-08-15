#!/usr/bin/env bash
#
# verify-audit-optype.sh — FULLY AUTOMATED check that the audit log records a
# password verification AS THE OPERATION IT ACTUALLY WAS.
#
# WHAT THIS IS ABOUT
#
# user_authenticate() is the LOGIN entry point, and it hardcoded
# AUDIT_AUTH_LOGIN_SUCCESS / AUDIT_AUTH_LOGIN_FAILURE for every outcome. That
# was correct while login was its only caller. It is not any more: `su` and a
# password change also have to verify a password, and they must get exactly the
# same policy (the failed_attempts counter, the lockout expiry, the
# locked/inactive checks) — so they call the same function.
#
# The result was that an `su` wrote "User 'root' (UID 0) logged in
# successfully" into the tamper-evident audit log. No login happened. That is
# worse than having no record at all: the audit log is the artifact an
# investigator trusts precisely because it is append-only and HMAC-chained, and
# a false entry in it is indistinguishable from a true one. An `su` from a
# compromised unprivileged shell would appear in the log as a clean root login.
#
# The fix is user_authenticate_for(username, password, op), which applies
# identical policy and lets the caller name the operation. user_authenticate()
# remains as the login wrapper, so the login path and the ABI are unchanged.
#
# WHY THE SU MUST BE DONE AS A NON-ROOT USER
#
# The part that is easy to get wrong. shell_cmd_su has TWO paths: when euid==0
# it skips the password entirely and goes straight to sys_setgid/sys_setuid,
# never calling user_authenticate at all. A root `su` therefore exercises NONE
# of the changed code and would pass against a completely unfixed kernel.
#
# So the harness logs in as root, creates a user, su's DOWN to that user (root
# fast path — not the thing under test, just how we become unprivileged), and
# then su's BACK to root WITH A PASSWORD. Only that last step reaches the
# non-root branch that authenticates.
#
# THE ASSERTIONS
#
#   - exactly ONE AUTH_LOGIN_SUCCESS  — THE check. One real login happened (the
#                                       root login at boot). The su that
#                                       followed must not have added a second.
#                                       Asserted on the COUNT, not on absence:
#                                       the genuine login record must still be
#                                       there, so "zero" would be just as wrong
#                                       as "two" and a presence check catches
#                                       neither.
#
#   - a USER_SWITCH record exists     — the positive half. Suppressing the false
#                                       login is only half the fix; the su still
#                                       has to be audited AS an su, or the fix
#                                       traded a wrong record for a missing one.
#
#   - USER_SWITCH renders by NAME     — audit_event_type_str had no case for
#                                       AUDIT_USER_SWITCH (or SU_FAILURE,
#                                       PASSWORD_CHANGE_FAILURE,
#                                       USER_PASSWORD_CHANGE, MEMORY_SEAL), so
#                                       they all printed as "UNKNOWN".
#                                       Distinguishing an su from a login in the
#                                       log is pointless if the su then prints
#                                       as UNKNOWN.
#
#   - the su actually succeeded       — a guard. Every assertion above is
#                                       vacuously satisfiable by an su that
#                                       failed and wrote nothing.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: audit-optype.log (serial),
# audit-optype-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

# The unprivileged account the harness creates, and the password it is given.
TESTUSER=auditor
TESTPASS=auditpass1

ISO=dist/tinyos.iso
SERIAL=audit-optype.log
TRACE=audit-optype-trace.log
RUN_DISK=/tmp/tinyos-audit-optype-disk.img
MON_SOCK=/tmp/tinyos-audit-optype-mon.sock

echo "==> Building kernel + ISO..."
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
if [ ! -f disk.img ]; then
    echo "ERROR: disk.img not found"
    exit 1
fi
cp disk.img "$RUN_DISK"

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

# The sequence. Password lines carry the '!' prefix, which sends them without
# the echo check — a password prompt echoes '*' per keystroke, so verifying the
# characters back would always fail. Each password is a follow-up of its own
# because it answers a KERNEL prompt, not the shell's readline.
#
#   useradd            -> one prompt, "Enter password for new user"
#   su $TESTUSER       -> root fast path, no password. We are now uid 1002.
#   su root + password -> THE step under test: the non-root branch that calls
#                         user_authenticate_for(..., USER_AUTH_OP_SU)
#   auditlog -n 100    -> dump the records for inspection
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_EXEC_CMD="useradd $TESTUSER" \
TINYOS_EXPECT="Enter password for new user" \
TINYOS_FOLLOWUP_CMDS="\
!$TESTPASS=>created;\
su $TESTUSER=>Now running as;\
su root=>Password for root;\
!$PASSWORD=>Switched to user: root;\
auditlog -n 100=>AUTH_LOGIN_SUCCESS" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: FAIL — no serial output at all (typist rc=$TYPIST_RC)"
    exit 2
fi

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    echo "  --- audit records seen ---"
    grep -E "^[0-9]+ +[A-Z]+ +" "$SERIAL" | head -15
    echo "  --- last 25 serial lines ---"
    grep -v "Suspicious" "$SERIAL" | tail -25
    exit 2
}

# --- Guard: the audit log was actually dumped -----------------------------
#
# Checked first: every count below reads as "0" against a log that was never
# printed, which would make the central assertion fail for the wrong reason.
grep -q "Audit\|AUDIT\|SYS_BOOT" "$SERIAL" 2>/dev/null || fail_with \
    "the audit log was never dumped" \
    "Nothing below was tested. Check that 'auditlog' ran in the kernel shell."

# --- Guard: the su under test actually happened ---------------------------
#
# The non-root su is the ONLY step that reaches the changed code. If it failed,
# no record of any kind was written and every assertion below passes vacuously.
grep -qi "Switched to user: root" "$SERIAL" 2>/dev/null || fail_with \
    "the non-root 'su root' did not succeed" \
    "That su is the only step that reaches user_authenticate_for(). Without it" \
    "this run proves nothing. Check the password prompts were answered."

# --- THE check: no FALSE login record -------------------------------------
#
# Asserted on the COUNT. Exactly one real login happened (root, at boot). The
# su must not have added a second. Zero would be equally wrong — that would mean
# the genuine login record was suppressed too — so a presence/absence test
# catches neither failure.
# Counted on the audit RECORD shape, not on the bare string: `cmd_auditlog`
# prints a column-aligned table, "SEQ SEVERITY EVENT UID/PID DESCRIPTION", so a
# record is a line whose leading sequence number is followed by a severity and
# then the type. The typed `auditlog` command echoes into the same serial
# stream, and this script's own expect string lands there too — a bare grep -c
# would count those as records.
#
# `grep -c` exits non-zero on zero matches, so the `|| echo 0` fallback would
# APPEND a second line; hence `|| true` and a default, never `|| echo 0`.
record_count() {
    grep -cE "^[0-9]+ +[A-Z]+ +$1( |$)" "$SERIAL" 2>/dev/null || true
}

LOGIN_COUNT=$(record_count AUTH_LOGIN_SUCCESS)
LOGIN_COUNT=${LOGIN_COUNT:-0}

if [ "$LOGIN_COUNT" -eq 0 ]; then
    fail_with \
        "no AUTH_LOGIN_SUCCESS record at all" \
        "The genuine root login must still be audited as a login. The fix was" \
        "meant to stop su/passwd from FORGING login records, not to stop real" \
        "logins from being recorded."
fi

if [ "$LOGIN_COUNT" -gt 1 ]; then
    fail_with \
        "the 'su' forged an AUTH_LOGIN_SUCCESS record ($LOGIN_COUNT found, expected 1)" \
        "Only ONE real login happened in this run (root, at boot). The extra" \
        "record came from the su, which verifies a password but establishes no" \
        "session. A false entry in a tamper-evident log is indistinguishable" \
        "from a true one: an su from a compromised unprivileged shell would" \
        "read as a clean root login." \
        "su must call user_authenticate_for(..., USER_AUTH_OP_SU)."
fi

# --- The positive half: the su WAS audited, as an su -----------------------
#
# Suppressing the false login is only half the fix. If the su now writes no
# record at all, the change traded a wrong record for a missing one.
# Anchored on the record shape, which also proves the rendering: a USER_SWITCH
# whose audit_event_type_str case was missing would print "| UNKNOWN |" here and
# fail this check. audit_event_type_str had no case for AUDIT_USER_SWITCH (nor
# AUTH_SU_FAILURE, AUTH_PASSWORD_CHANGE_FAILURE, USER_PASSWORD_CHANGE,
# MEMORY_SEAL) — distinguishing an su from a login is pointless if the su then
# renders as UNKNOWN.
grep -qE "^[0-9]+ +[A-Z]+ +USER_SWITCH( |$)" "$SERIAL" 2>/dev/null || fail_with \
    "the su produced no USER_SWITCH record (or it rendered as UNKNOWN)" \
    "An su must still be audited — as an su. Suppressing the false login" \
    "record must not suppress the true one, and the record must render by" \
    "name: audit_event_type_str needs a case for AUDIT_USER_SWITCH."

# --- Sanity: no crash ------------------------------------------------------

if grep -qi "triple fault\|PANIC" "$SERIAL" 2>/dev/null; then
    fail_with "kernel panicked or triple-faulted during the run"
fi

echo "RESULT: PASS"
echo "  - a non-root 'su root' authenticated through user_authenticate_for()"
echo "  - exactly $LOGIN_COUNT AUTH_LOGIN_SUCCESS record (the real root login only)"
echo "  - the su did NOT forge a login record"
echo "  - the su WAS audited, as USER_SWITCH"
echo "  - USER_SWITCH renders by name, not as UNKNOWN"
echo "  --- audit records ---"
grep -E "^[0-9]+ +[A-Z]+ +" "$SERIAL" | head -8
exit 0
