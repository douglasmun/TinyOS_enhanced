#!/usr/bin/env bash
#
# verify-cred-deprecation.sh — FULLY AUTOMATED check that the DEPRECATED
# credential syscalls are UNREACHABLE FROM RING 3, and that the ones that
# remain enforce the account-lockout policy.
#
# WHAT THIS IS ABOUT
#
# SYS_CHANGE_PASSWORD (14) and SYS_SWITCH_USER (15) take a PLAINTEXT PASSWORD in
# a syscall argument register. SYS_CRED (32) supersedes them precisely by never
# letting a password reach userspace: the kernel prompts and reads the keystrokes
# itself. A ring-3 caller of the two legacy calls must HOLD the plaintext to make
# the call at all, so the exposure is inherent to the interface and cannot be
# hardened away — only removed. Ring-3 dispatch is therefore refused with
# -ENOSYS unless the kernel is built -DTINYOS_LEGACY_CRED_SYSCALLS.
#
# Underneath that, sys_switch_user() also authenticated with the BARE hash
# comparison (user_verify_password) rather than user_authenticate(), so it kept
# no failed_attempts counter and skipped the locked/inactive checks. That made it
# an unlimited, un-counted password oracle for anything that could reach it.
#
# WHY THE PROBE IS A PROGRAM AND NOT A SHELL COMMAND
#
# This is the part worth being careful about. Neither shell offers `su` through
# these syscalls in a way that reaches the vulnerable code: the KERNEL shell's su
# calls user_authenticate() ITSELF first (shell_user.c) and only then commits the
# switch, so driving an attack through the shell exercises the SHELL's throttling
# and proves nothing whatsoever about the syscall. A harness built that way
# passes identically against fixed and vulnerable kernels — verified, not
# assumed: it was written that way first and passed against a deliberately
# reverted kernel, which is why it was thrown away.
#
# The gate lives at the SYSCALL BOUNDARY, so only a caller that goes straight to
# int 0x80 can test it. /credprobe.elf does exactly that, with a real username
# and a real password string, the way an attacker would.
#
# THE ASSERTIONS
#
#   - both probes return -ENOSYS   — THE check. -38 is the refusal; any other
#                                    value means ring 3 reached a credential
#                                    syscall that takes a plaintext password.
#                                    Asserted on the EXACT errno, not merely
#                                    "non-zero": -EPERM would mean the call was
#                                    dispatched and then declined on policy,
#                                    which is a different (and weaker) property
#                                    than not being dispatched at all.
#
#   - the probe's own VERDICT      — the program computes it independently of
#     line says 'refused'            the harness's grep, so a change to one and
#                                    not the other is visible rather than silent.
#
#   - the probe did NOT become     — the escalation made explicit. The probe runs
#     root                           as uid 1000 and asks to switch to root; if
#                                    the gate failed AND the password guess were
#                                    right, this is what it would look like.
#
#   - the shell SURVIVES the probe — a trailing command whose output we wait on.
#                                    A syscall that faulted or wedged rather than
#                                    returning -ENOSYS fails here.
#
#   - no plaintext password on     — a sweep, not a behaviour. The probe passes
#     the console                    "guessguess" INTO the kernel; the kernel
#                                    must never print it back.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: cred-deprecation.log
# (serial), cred-deprecation-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

# The string the probe hands to the kernel as a password guess. Must match
# credprobe.c, and must never appear in the log.
GUESS=guessguess

# The probe must run as an UNPRIVILEGED user. See the escalation assertion
# below for why running it as root made that leg unfalsifiable.
TESTUSER=creduser
TESTPASS=credpass1

ISO=dist/tinyos.iso
SERIAL=cred-deprecation.log
TRACE=cred-deprecation-trace.log
RUN_DISK=/tmp/tinyos-cred-dep-disk.img
MON_SOCK=/tmp/tinyos-cred-dep-mon.sock

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

# The probe runs as an UNPRIVILEGED user, and that is the whole point of the
# sequencing below. `exec` runs it as a ring-3 process, so the syscalls are
# issued from CPL 3 through int 0x80 either way -- but the ESCALATION leg
# ("the probe must not end up as root") can only be falsified if the probe
# did not START as root. Run from the root shell, `PROBE uid=0` is the
# probe's correct inherited state, so that assertion FAILS on a correct
# kernel and could not pass on a broken one either. It was one-sided in
# both directions, and it stood as a FAIL until this was fixed.
#
# The typist runs TINYOS_EXEC_CMD before the followups, so the account has to
# be created in the followup list and the real probe exec'd after the `su`.
# TINYOS_EXEC_CMD is therefore a throwaway that only gets us to a prompt.
#
# The trailing `whoami` is a barrier as much as a check — a syscall that wedged
# instead of returning would eat these keystrokes. It must report the TEST
# USER now, not root: that is what proves the refused syscalls left the
# session's credentials untouched.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_EXEC_CMD="exec /hello.elf" \
TINYOS_EXPECT="Hello from ELF" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
su $TESTUSER=>Now running as;\
exec /credprobe.elf=>PROBE VERDICT;\
whoami=>$TESTUSER" \
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
    echo "  --- probe output ---"
    grep "PROBE" "$SERIAL" | head -10
    echo "  --- last 25 serial lines ---"
    grep -v "Suspicious" "$SERIAL" | tail -25
    exit 2
}

# --- The probe actually ran ----------------------------------------------
#
# Checked first: every assertion below would vacuously "pass" against a log in
# which the probe never executed.
grep -q "PROBE VERDICT" "$SERIAL" 2>/dev/null || fail_with \
    "the ring-3 probe never ran to completion" \
    "Nothing below was tested. Check that /credprobe.elf is seeded into RAMFS" \
    "at 0755 and that its signature verifies."

# --- THE check: both syscalls refused at the boundary --------------------
#
# -38 is -ENOSYS. Asserted EXACTLY: -EPERM would mean the call was dispatched
# and then declined, which is a weaker property than never being dispatched.
grep -q "PROBE switch_user rc=-38" "$SERIAL" 2>/dev/null || fail_with \
    "SYS_SWITCH_USER was REACHABLE from ring 3" \
    "It takes a plaintext password in a syscall argument register — the exact" \
    "exposure SYS_CRED was built to remove, and it cannot be hardened away" \
    "because the caller must hold the plaintext to make the call at all." \
    "Ring-3 dispatch must return -ENOSYS (-38) unless the kernel was built" \
    "-DTINYOS_LEGACY_CRED_SYSCALLS."

grep -q "PROBE change_password rc=-38" "$SERIAL" 2>/dev/null || fail_with \
    "SYS_CHANGE_PASSWORD was REACHABLE from ring 3" \
    "Same class as SYS_SWITCH_USER above: a plaintext password crosses the" \
    "ring boundary in a register. Must be -ENOSYS (-38)."

# The probe's independent verdict. Computed inside the program, so a drift
# between it and the greps above is visible rather than silent.
grep -q "PROBE VERDICT refused" "$SERIAL" 2>/dev/null || fail_with \
    "the probe itself concluded the syscalls were reachable" \
    "The program computes this independently of the harness's own checks."

# --- Positive control: the probe really was unprivileged ------------------
#
# This guard is what keeps the escalation leg below falsifiable. If the `su`
# silently failed, the probe would run as root, `PROBE uid=0` would be its
# correct inherited state, and the escalation assertion would be grading
# nothing -- exactly the defect this harness shipped with. Assert the switch
# landed BEFORE reading anything into the uid the probe reports.
grep -q "Now running as: $TESTUSER" "$SERIAL" 2>/dev/null || fail_with \
    "the su to $TESTUSER never completed, so the probe ran as root" \
    "The escalation leg below is only meaningful for an unprivileged caller." \
    "This is a harness failure, not a kernel finding."

# --- The negative: no escalation ------------------------------------------
#
# The probe asked to become root. It must still be the unprivileged test user.
# uid 0 is root, so any `PROBE uid=0` here is a committed credential change --
# and the su guard above proves the probe did not simply start there.
if grep -qE "PROBE uid=0" "$SERIAL" 2>/dev/null; then
    fail_with \
        "the ring-3 probe ended up as ROOT" \
        "A refused credential syscall must not commit a credential change." \
        "This is the escalation the gate and switch_user_commit() prevent."
fi

# --- The session survived --------------------------------------------------
#
# Match the OUTPUT of whoami, not the string "whoami" -- the latter matches
# the command echo, which the shell prints before running anything, so it
# survives a shell that wedged on the very next instruction.
grep -qE "^$TESTUSER" "$SERIAL" 2>/dev/null || fail_with \
    "the shell did not survive the probe" \
    "A refused syscall must RETURN an errno, not fault or wedge the caller."

# --- Sweep: the guessed password never reached an output path -------------

if grep -q "$GUESS" "$SERIAL" 2>/dev/null; then
    fail_with \
        "the password string passed to the kernel appeared in the serial log" \
        "The kernel must never print a password it was handed, even a wrong" \
        "one and even on a refusal path." \
        "$(grep -n "$GUESS" "$SERIAL" | head -5)"
fi

# --- Sanity: no crash ------------------------------------------------------

if grep -qi "triple fault\|PANIC" "$SERIAL" 2>/dev/null; then
    fail_with "kernel panicked or triple-faulted during the run"
fi

echo "RESULT: PASS"
echo "  - the ring-3 probe ran and issued both deprecated syscalls via int 0x80"
echo "  - SYS_SWITCH_USER refused at the boundary with -ENOSYS"
echo "  - SYS_CHANGE_PASSWORD refused at the boundary with -ENOSYS"
echo "  - the probe's own verdict agrees: refused"
echo "  - no privilege escalation: the probe never became root"
echo "  - the shell survived; no plaintext password reached the log"
grep "PROBE" "$SERIAL" | head -6
exit 0
