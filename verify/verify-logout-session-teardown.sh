#!/usr/bin/env bash
#
# verify-logout-session-teardown.sh — does logout end the session's processes?
#
# THE BUG
#
# Logging out of the ring-3 shell ended the SHELL and nothing else. Its `&`
# jobs were never torn down: launch_login_shell() waited for the shell's own
# pid and returned to the login prompt, and no code anywhere walked the tasks
# the session had started. A background job therefore outlived its owner's
# session indefinitely -- running as that user, while somebody else logged in.
#
# That is a credential-capture primitive, not untidiness. A ring-3 read(0) on
# the console is keyboard_getchar(), and so are the login prompt, `su` and
# SYS_CRED's password read: there is ONE keyboard ring and ONE wait queue. An
# unprivileged user who backgrounds a stdin reader and logs out leaves it
# blocked on that queue, and the next user's username and password are
# delivered to whichever reader the IRQ wakes.
#
# THE FIX
#
# task_t.session_id: the login task stamps a fresh id after each successful
# login, task_create_user copies the creator's id (so the login shell, its jobs
# and THEIR children all carry it), and the top of shell_task()'s session loop
# -- where both logout paths land -- calls task_kill_session() before the next
# login prompt can read a key. It also drops keystrokes still buffered from the
# old session.
#
# WHAT IS ASSERTED
#
#   1. POSITIVE CONTROL (job alive in-session). The unprivileged user's
#      backgrounded slothold.elf printed "slothold: holding" and appears in that
#      user's own `ps`. Without this, "absent after logout" is satisfied by a
#      job that never started.
#   2. POSITIVE CONTROL (root's ps sees ring-3 tasks). After re-login as root,
#      `ps` prints a table that lists shell.elf. Root sees every task by policy,
#      so this proves the post-logout ps could have shown slothold had it lived.
#   3. THE FINDING. In the region after the final login prompt, slothold must
#      NOT appear -- the session's job died with the session.
#
# The witness is LIVENESS, deliberately, not keystroke theft. Which blocked
# reader the keyboard IRQ wakes is a race, so a harness that asserted "the
# thief got the password" would be flaky in both directions. A surviving task
# is deterministic, and it is the root cause: a reader that does not survive
# logout cannot be woken by the next login. slothold.elf sleeps rather than
# reads so it cannot steal the harness's own keystrokes mid-session; the
# keyboard-blocked case goes through the same task_terminate path
# (wait_queue_remove_task detaches it).
#
# The unprivileged user is reached by `exit` + login, not kshell + su: the
# session boundary under test IS the logout, and su would keep the root
# session alive underneath.
#
# Exit 0 = PASS (the session's job was terminated at logout)
# Exit 1 = FAIL (the job survived into the next user's session)
# Exit 2 = harness/setup problem (nothing proven either way)

set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=sessuser
TESTPASS=sesspass1
ISO=dist/tinyos.iso
SERIAL=logout-teardown.log
TRACE=logout-teardown-trace.log
RUN_DISK=/tmp/tinyos-logoutteardown-disk.img
MON_SOCK=/tmp/tinyos-logoutteardown-mon.sock

guard_fail() { echo "RESULT: INCONCLUSIVE — $*"; exit 2; }

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

# Session 1 (root, ring 3): create the test account, log out.
# Session 2 (sessuser):     background slothold.elf, confirm it in ps, log out.
# Session 3 (root):         ps -- slothold must be gone.
#
# Re-login readiness follows verify-shell-history-logout.sh: "Welcome" is
# printed by the LOGIN code before shell.elf is even loaded, so the wait is on
# the ring-3 shell's own "'help' for builtins" line, and a bare line flushes the
# prompt. Ring-3 commands are sent unverified ('!') because the ring-3 shell
# does not echo per character; each carries an expect on its RESULT instead.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=900 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
!exit=>TinyOS login:;\
$TESTUSER=>assword;\
!$TESTPASS=>'help' for builtins;\
!=>\$;\
!/slothold.elf &=>slothold: holding;\
!ps=>Total:;\
!exit=>TinyOS login:;\
root=>assword;\
!$PASSWORD=>'help' for builtins;\
!=>\$;\
!ps=>Total:" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

# Drain: the typist returns as soon as the last expect matches, and the ps
# table may still be printing.
sleep 3
cleanup
trap - EXIT

echo ""
echo "================ VERDICT ================"

[ -s "$SERIAL" ] || guard_fail "no serial output at all (typist rc=$TYPIST_RC)"

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    echo "  --- last 40 serial lines ---"
    tail -40 "$SERIAL"
    exit 1
}

# grep -c, not grep -q: under pipefail grep -q SIGPIPEs printf on an early
# match and the 141 reads as a miss (see verify-psvisibility.sh).
region_has() {
    local n
    n=$(printf '%s\n' "$1" | grep -c "$2")
    [ "$n" -gt 0 ]
}

# Split the log at the login prompts. Three logins => at least three
# "TinyOS login:" lines after boot; the user session is between the 2nd and
# 3rd, and the final root session is after the last.
LOGIN_LINES=$(grep -na "TinyOS login:" "$SERIAL" | cut -d: -f1)
NLOGIN=$(printf '%s\n' "$LOGIN_LINES" | grep -c .)
[ "$NLOGIN" -ge 3 ] || guard_fail "only $NLOGIN login prompts in the log (typist rc=$TYPIST_RC); the sequence never reached the final root session"

USER_START=$(printf '%s\n' "$LOGIN_LINES" | tail -2 | head -1)
LAST_LOGIN=$(printf '%s\n' "$LOGIN_LINES" | tail -1)
USER_REGION=$(sed -n "${USER_START},${LAST_LOGIN}p" "$SERIAL")
FINAL_REGION=$(tail -n +"$LAST_LOGIN" "$SERIAL")

# --- Positive control 1: the job was alive in its own session -------------
region_has "$USER_REGION" "slothold: holding" || guard_fail \
    "slothold.elf never announced itself in $TESTUSER's session"
USER_PS_ROWS=$(printf '%s\n' "$USER_REGION" | grep -c '^[0-9][0-9]*  *[A-Za-z]*  *.*slothold')
[ "$USER_PS_ROWS" -gt 0 ] || guard_fail \
    "$TESTUSER's own ps never listed slothold.elf, so its absence later proves nothing"

# --- Positive control 2: root's post-logout ps lists ring-3 tasks ---------
region_has "$FINAL_REGION" "Total:" || guard_fail \
    "the final root session never printed a ps table (typist rc=$TYPIST_RC)"
region_has "$FINAL_REGION" '^[0-9][0-9]*  *[A-Za-z]*  *.*shell\.elf' || guard_fail \
    "root's ps did not list shell.elf; it cannot witness a surviving ring-3 job either"

# --- The finding ---------------------------------------------------------
if region_has "$FINAL_REGION" "slothold"; then
    fail_with "$TESTUSER's background job survived logout into root's session" \
        "slothold.elf was started with '&' in $TESTUSER's session and is still" \
        "listed by root's ps after $TESTUSER logged out. A stdin reader left" \
        "this way shares the keyboard ring with the login prompt and su." \
        "--- root's ps rows naming it ---" \
        "$(printf '%s\n' "$FINAL_REGION" | grep 'slothold')"
fi

if grep -qa "KERNEL PANIC" "$SERIAL" 2>/dev/null; then
    fail_with "the kernel panicked during the run" "See $SERIAL."
fi
if grep -qa "Triple fault\|triple fault" "$TRACE" 2>/dev/null; then
    fail_with "the kernel triple-faulted during the run" "See $TRACE."
fi

echo "RESULT: PASS"
echo "  - $TESTUSER's slothold.elf was alive and visible in their own ps"
echo "  - root's ps after re-login listed ring-3 tasks (shell.elf)"
echo "  - slothold.elf was gone: the session's job died at logout"
exit 0
