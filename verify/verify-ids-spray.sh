#!/usr/bin/env bash
#
# verify-ids-spray.sh — FULLY AUTOMATED check that the IDS detects a HORIZONTAL
# credential attack (password spray) and does NOT fire on the vertical one that
# user.c already handles.
#
# WHAT THIS IS TESTING
#
# user.c locks an account after USER_MAX_LOGIN_ATTEMPTS (3) failures against it.
# That guard counts into user->failed_attempts, i.e. it is keyed on the ACCOUNT.
# It is a complete answer to "many passwords against one username" and
# structurally blind to "one password against many usernames": spraying across
# N accounts leaves each at 1/3 and trips nothing. Worse, an attempt against a
# username that does not exist returns -2 before any counter exists at all.
#
# ids_register_login_failure() closes that gap by keying on how many DISTINCT
# usernames failed inside one window. So the assertion is NOT "a failed login is
# noticed" -- user.c already notices those. The assertion is that the detector
# discriminates:
#
#   3 failures / 3 DIFFERENT usernames  -> ALERT   (positive, run A)
#   3 failures / 1 SAME username        -> NO ALERT (negative, run B)
#
# THE PAIRED NEGATIVE IS THE LOAD-BEARING HALF
#
# "an alert appears after three failed logins" is satisfied by a detector that
# alerts on every failure -- which is not spray detection, it is a duplicate of
# user.c's counter wearing an IDS label, and it would pass a positive-only test
# while adding nothing. Run B is what separates the two, and it is why the two
# runs differ ONLY in whether the usernames repeat. Same count of failures, same
# wrong password, same path.
#
# WHY EACH HALF NEEDS ITS OWN BOOT
#
# shell_login_prompt() allows max_attempts = 3 and then halts the machine
# ("Login failed. System halted."). Three failures is therefore the entire
# budget for a boot -- the runs cannot share one. That same ceiling is why
# IDS_SPRAY_THRESHOLD is 3 and not the network-side IDS_BRUTEFORCE_THRESHOLD
# (5): a threshold of 5 would be unreachable from the only path that calls this,
# i.e. a detector that cannot fire. If max_attempts ever changes, this harness
# and that constant both need revisiting -- the guard below fails loudly if it
# does, rather than silently testing nothing.
#
# WHERE THE MEASUREMENT HAPPENS
#
# At the login prompt, not the shell. Both runs halt at the login screen and
# never reach a shell, so there is no `secstatus` to read -- the verdict comes
# from the serial log. ids_register_login_failure() prints "[IDS] Credential
# spray:" via kprintf precisely because the alert's own audit_log() path is
# AUDIT_WARN, and audit_log_raw() only echoes >= AUDIT_ERROR to serial; without
# that explicit line the detection would be invisible to an operator and to
# this harness alike.
#
# `su` cannot drive this: shell_cmd_su() rejects a nonexistent user in the shell
# before it ever calls user_authenticate_for(), so the login prompt is the only
# vehicle that reaches the not-found branch.
#
# VALIDATED BOTH WAYS: see the VALIDATION LOG at the end of this file.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.
# Logs: spray-pos.log / spray-neg.log (serial).

set -u

ISO=dist/tinyos.iso
MARKER="Credential spray:"

cd "$(dirname "$0")/.." || exit 2

# --------------------------------------------------------------------------
# 0) Source guards.
#
# These fail the run rather than let it pass vacuously. Each one encodes an
# assumption the test depends on; if the assumption breaks, the test would
# otherwise still "pass" while measuring nothing.
# --------------------------------------------------------------------------
attempts=$(grep -oE 'const int max_attempts = [0-9]+' src/shell_user.c | grep -oE '[0-9]+$')
if [ "${attempts:-0}" != "3" ]; then
    echo "INCONCLUSIVE: shell_user.c max_attempts is '${attempts:-unset}', expected 3."
    echo "  The 3-failure budget per boot is what this harness and"
    echo "  IDS_SPRAY_THRESHOLD are both sized against. Re-check both."
    exit 2
fi

thr=$(grep -oE '#define IDS_SPRAY_THRESHOLD +[0-9]+' src/ids.c | grep -oE '[0-9]+$')
if [ "${thr:-0}" != "3" ]; then
    echo "INCONCLUSIVE: IDS_SPRAY_THRESHOLD is '${thr:-unset}', expected 3."
    exit 2
fi

# --------------------------------------------------------------------------
# 1) Build, and prove the binary under test actually contains the detector.
#
# A stale ISO is the classic false PASS/FAIL here. `nm | grep` is NOT a usable
# guard -- it would match any build that merely defines the symbol. Disassembling
# user_authenticate_for and looking for the CALL proves the detector is wired
# into the auth path in THIS binary, which is the property under test.
# --------------------------------------------------------------------------
make -j8 kernel.elf >/dev/null 2>&1 || { echo "FAIL: build failed"; exit 2; }

calls=$(i686-elf-objdump -d kernel.elf --disassemble=user_authenticate_for 2>/dev/null \
        | grep -cE 'call .*<ids_register_login_failure>')
if [ "${calls:-0}" -lt 2 ]; then
    echo "INCONCLUSIVE: user_authenticate_for has ${calls:-0} call(s) to"
    echo "  ids_register_login_failure; expected 2 (the wrong-password branch"
    echo "  AND the user-not-found branch). The not-found branch is the one a"
    echo "  spray against guessed names actually travels."
    exit 2
fi

cp kernel.elf iso/boot/kernel.elf || exit 2
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || { echo "FAIL: ISO build failed"; exit 2; }

# --------------------------------------------------------------------------
# 2) One run. $1 = label, $2 = serial log, $3 = comma-separated usernames.
# --------------------------------------------------------------------------
run_case() {
    label="$1"; serial="$2"; users="$3"

    rm -f "$serial"
    mon=$(mktemp -u /tmp/tinyos-spray-mon.XXXXXX)
    disk=$(mktemp -u /tmp/tinyos-spray-disk.XXXXXX)
    dd if=/dev/zero of="$disk" bs=1m count=16 >/dev/null 2>&1

    qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
        -boot d -m 256M \
        -drive file="$disk",format=raw,if=ide \
        -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
        -serial "file:$serial" \
        -monitor "unix:$mon,server,nowait" \
        -no-reboot -display none >/dev/null 2>&1 &
    qpid=$!

    # The typist drives the pre-login failures and then stops: after three
    # failures the machine halts at the login screen, so there is deliberately
    # no login/exec step. Its non-zero exit on the halt is expected and not a
    # verdict -- the serial log is.
    TINYOS_SERIAL="$serial" \
    TINYOS_MON_SOCK="$mon" \
    TINYOS_PRELOGIN_USERS="$users" \
    TINYOS_PRELOGIN_ONLY=1 \
    timeout 900 python3 tools/qemu_typist.py >/dev/null 2>&1

    sleep 3
    kill "$qpid" 2>/dev/null; wait "$qpid" 2>/dev/null
    rm -f "$mon" "$disk"

    # Sanity: the run must actually have produced three failed logins. Without
    # this, a boot that died early would show no alert and the NEGATIVE half
    # would "pass" for entirely the wrong reason.
    # Same grep -c idiom note as in the verdict block below: no `|| echo 0`.
    fails=$(grep -c "Login incorrect" "$serial" 2>/dev/null)
    echo "${fails:-0}"
}

echo "=== run A (positive): 3 DISTINCT usernames ==="
fails_a=$(run_case "positive" spray-pos.log "ghost1,ghost2,ghost3")
echo "  failed logins observed: $fails_a"

echo "=== run B (negative): 3 failures, SAME username ==="
fails_b=$(run_case "negative" spray-neg.log "ghost1,ghost1,ghost1")
echo "  failed logins observed: $fails_b"

# --------------------------------------------------------------------------
# 3) Verdict. The NEGATIVE is evaluated first: if it fires, the detector is
#    just counting failures and the positive proves nothing.
# --------------------------------------------------------------------------
if [ "${fails_a:-0}" -lt 3 ] || [ "${fails_b:-0}" -lt 3 ]; then
    echo
    echo "INCONCLUSIVE: a run did not produce 3 failed logins (A=$fails_a, B=$fails_b)."
    echo "  Neither half is meaningful without them. Check spray-*.log."
    exit 2
fi

# NOTE the idiom. `grep -c ... || echo 0` is WRONG and was a real bug here:
# grep -c already PRINTS 0 when it matches nothing, and exits 1 while doing so,
# so the `|| echo 0` appends a second line and the variable becomes "0\n0" --
# which then blows up as `[: 0\n0: integer expression expected`. That error goes
# to stderr while the script keeps running, so the verdict can still print PASS.
# A comparison that errors out is not a comparison; use grep -c alone.
neg=$(grep -c "$MARKER" spray-neg.log 2>/dev/null)
pos=$(grep -c "$MARKER" spray-pos.log 2>/dev/null)

echo
if [ "${neg:-0}" -ne 0 ]; then
    echo "FAIL (negative control): the detector alerted on 3 failures against ONE"
    echo "  username. That is the vertical attack user.c's per-account lockout"
    echo "  already handles -- firing here means this is duplicating that counter,"
    echo "  not detecting a spray."
    grep -n "$MARKER" spray-neg.log | head -3
    exit 1
fi
echo "negative control OK: no spray alert for repeated failures on one username"

if [ "${pos:-0}" -eq 0 ]; then
    echo "FAIL (positive): 3 failures across 3 DISTINCT usernames raised no alert."
    echo "  This is the horizontal case user.c cannot see; if it is silent here,"
    echo "  the gap is still open."
    exit 1
fi
if [ "${pos:-0}" -ne 1 ]; then
    echo "FAIL: expected exactly 1 spray alert, got $pos."
    echo "  More than one means the once-per-window latch is broken and a spray"
    echo "  can flood the alert ring, evicting the alerts that identify it."
    grep -n "$MARKER" spray-pos.log | head -5
    exit 1
fi

echo "positive OK: exactly 1 spray alert for 3 distinct usernames"
grep -n "$MARKER" spray-pos.log | head -1
echo
echo "PASS"
exit 0

# =============================================================================
# VALIDATION LOG (2026-08-16)
#
# A harness is only worth its exit code if both outcomes have been observed.
# All three runs below are real.
#
# 1. PASS, correct detector. exit 0.
#      negative control OK: no spray alert for repeated failures on one username
#      positive OK: exactly 1 spray alert for 3 distinct usernames
#      [IDS] Credential spray: 3 distinct usernames failed login within 300s
#            (most recent 'ghost3')
#
# 2. FAIL, deliberately broken detector. exit 1.
#    ids_register_login_failure() was patched to count RAW failures instead of
#    distinct usernames -- i.e. made into a duplicate of user.c's per-account
#    counter, the precise thing this detector must not be. The negative control
#    caught it, and the alert text named its own bug:
#      FAIL (negative control): the detector alerted on 3 failures against ONE
#      [IDS] Credential spray: 1 distinct usernames failed login within 300s
#                              ^ one distinct name should never reach threshold
#    This is the run that proves the negative half can actually fail. Without
#    it, "PASS" would only mean the script ran.
#
# 3. PASS again after restoring src/ids.c from backup, confirming run 2's
#    failure came from the patch and not from run-to-run flakiness.
#
# HARNESS BUG FOUND AND FIXED DURING VALIDATION (worth keeping in mind):
# the idiom `n=$(grep -c PATTERN file || echo 0)` is broken. grep -c already
# prints 0 on no match AND exits 1, so the `|| echo 0` appends a second line and
# n becomes "0\n0". The later `[ "$n" -ne 0 ]` then fails with "integer
# expression expected" -- on stderr, while the script continues and can still
# print PASS. A comparison that errors out is not a comparison. Both call sites
# now use bare grep -c. Run 1 originally passed WITH this bug present, which is
# exactly how a broken guard hides.
# =============================================================================
