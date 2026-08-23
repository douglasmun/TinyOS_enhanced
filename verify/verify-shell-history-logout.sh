#!/usr/bin/env bash
#
# verify-shell-history-logout.sh — does logout clear the command history?
#
# THE BUG
#
# history_init() was called once from shell_task(), at task start, not once per
# LOGIN. The history buffer is a single global living in that task, and the task
# outlives the session: `logout` returns to the login prompt without tearing the
# shell task down. So every command the previous user typed stayed in the buffer
# and the NEXT user -- a different account -- read them back by typing `history`.
#
# Command lines carry arguments. `useradd bob`, a path into someone's private
# directory, a password typed into the wrong prompt: all of it persisted across
# the session boundary that is supposed to end it.
#
# WHAT IS ASSERTED
#
#   1. POSITIVE CONTROL. Within ONE session, `history` must actually show a
#      command that was just typed. Without this leg every "not found" below is
#      satisfied by a `history` builtin that prints nothing at all, or by a
#      marker that was never typed -- an empty feature passes an emptiness test
#      perfectly.
#   2. THE FINDING. After logout and login as a DIFFERENT user, that marker must
#      NOT appear in `history`.
#   3. The second session's own history must still work (type a second marker,
#      see it). This separates "cleared on login" from "history is broken now" --
#      a history_init() that ran on every keystroke, or a buffer left in a
#      permanently empty state, would pass leg 2 and is not the fix.
#
# Leg 3 is why this harness types a SECOND marker rather than only checking for
# the first one's absence: leg 2 alone cannot distinguish a cleared buffer from
# a dead one, and those are opposite outcomes.
#
# The markers are distinctive strings, not real commands: the point is to search
# the `history` OUTPUT for them, and a common word would match the boot log, the
# help text, or the command being typed as it echoes.
#
# Exit 0 = PASS (cleared on logout, still functional)
# Exit 1 = FAIL (previous session's command lines leaked to the next user)
# Exit 2 = harness/setup problem (nothing proven either way)

set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
TESTUSER=histuser
TESTPASS=histpass1
MARKER1=ZQMARKERONE
MARKER2=ZQMARKERTWO
ISO=dist/tinyos.iso
SERIAL=hist-logout.log
RUN_DISK=/tmp/tinyos-histlogout-disk.img
MON_SOCK=/tmp/tinyos-histlogout-mon.sock

guard_fail() { echo "HARNESS GUARD FAILED: $*"; exit 2; }

# Source guard. The fix is a CALL SITE move, so grepping shell_history.c proves
# nothing -- history_init() existed before the fix too. What must be true is
# that shell.c calls it from the per-session block, beside env_init().
grep -q "history_init();" src/shell.c \
    || guard_fail "src/shell.c never calls history_init(); the per-session
reset is absent and leg 2 below would be testing a kernel that cannot pass."

command -v qemu-system-i386 >/dev/null 2>&1 || guard_fail "qemu-system-i386 not found"

echo "==> Building kernel + ISO..."
make >/dev/null 2>&1 || guard_fail "build failed"
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || guard_fail "mkrescue failed"

rm -f "$RUN_DISK" "$SERIAL" "$MON_SOCK"
dd if=/dev/zero of="$RUN_DISK" bs=1M count=128 status=none

echo "==> Launching headless QEMU..."
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -display none 2>/dev/null &
QEMU_PID=$!
cleanup() {
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "${QEMU_PID:-}" ] && wait "$QEMU_PID" 2>/dev/null
    rm -f "$MON_SOCK" "$RUN_DISK"
    return 0
}
trap cleanup EXIT

# Session 1 (root): create the second account, type the marker, confirm the
# marker is visible in THIS session, then log out.
# Session 2 (histuser): type a different marker and read history once.
#
# WHICH SHELL. Both steps type `kshell` first, and that is the whole point.
# There are TWO independent histories in this system and only one of them has
# the bug. The ring-3 shell (userspace/shell.c) keeps its history in its own
# process image, and login re-execs shell.elf, so a fresh process ALWAYS starts
# with an empty history no matter what the kernel does -- a harness driving the
# ring-3 shell reports "cleared" against a completely unfixed kernel. It did:
# this harness passed against a deliberately reintroduced bug until the kshell
# steps were added. The buffer the fix is about is the single global in
# src/shell_history.c, reachable only from the kernel shell.
#
# Two steps before session 2's first real command are load-bearing. The second
# login re-execs shell.elf (ECDSA-verified, ~58KB mapped under TCG), and the
# typist's echo-verify starts typing before that shell is reading keystrokes, so
# the very first character is dropped and the run dies on "TIMEOUT waiting for
# 'Z'". Waiting for "Welcome, <user>" is NOT enough -- that banner is printed by
# the LOGIN code, before exec. The readiness signal is the ring-3 shell's own
# startup line ("'help' for builtins"), which only prints once the new process
# is running. The bare unverified line after it flushes the prompt and is
# confirmed by waiting for the prompt's own '$'. Do NOT wait for the username
# here: the ring-3 prompt is the cwd plus '$' ("D:/ $") and never contains it,
# so a username expect burns the whole follow-up timeout while the kernel sits
# perfectly healthy at a prompt.
#
# `echo $MARKER1` is used as the marker command because it is harmless and its
# text lands in the history buffer verbatim.
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
kshell=>Switching to the kernel shell;\
echo $MARKER1=>$MARKER1;\
history=>$MARKER1;\
logout=>TinyOS login:;\
$TESTUSER=>assword;\
!$TESTPASS=>'help' for builtins;\
!=>\$;\
kshell=>Switching to the kernel shell;\
echo $MARKER2=>$MARKER2;\
history=>$MARKER2" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup
trap - EXIT

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: harness problem — no serial output (typist rc=$TYPIST_RC)"
    exit 2
fi

CLEAN=$(mktemp); tr -d '\r' < "$SERIAL" | grep -vE "^\[(EDR|IDS)" > "$CLEAN"

# Split the log at session 2's kshell handoff -- the LAST one, since each
# session performs one.
#
# Do NOT anchor on the marker-2 echo. The kernel shell does not echo typed
# commands to serial, so the first occurrence of "echo ZQMARKERTWO" in the log
# is a ROW OF SESSION 2'S OWN HISTORY OUTPUT, printed after the leaked
# ZQMARKERONE row. Splitting there puts the leak above the split, S2 never
# contains it, and leg 2 reports PASS against a fully reproduced bug. That is
# not hypothetical: this harness did exactly that until the anchor moved here.
SPLIT=$(grep -n "Switching to the kernel shell" "$CLEAN" | tail -1 | cut -d: -f1)
if [ -z "$SPLIT" ]; then
    echo "RESULT: harness problem — session 2's kernel shell was never reached."
    echo "  The logout or the second login did not complete."
    grep -vE "Suspicious" "$CLEAN" | tail -25
    rm -f "$CLEAN"; exit 2
fi

S1=$(sed -n "1,${SPLIT}p" "$CLEAN")
S2=$(sed -n "$((SPLIT)),\$p" "$CLEAN")

FAIL=0

# Leg 1: positive control. In session 1, `history` must have listed MARKER1.
# The marker appears at least twice in session 1 regardless (the echo command
# and its output), so require a line that looks like a history ENTRY: history
# prints numbered rows, so look for a digit before the marker.
if echo "$S1" | grep -qE "^ *[0-9]+ +.*$MARKER1"; then
    echo "PASS leg 1 (positive control): session 1's history listed $MARKER1."
else
    echo "RESULT: INCONCLUSIVE — session 1's own history never showed $MARKER1."
    echo "  Either `history` prints nothing, or the marker was never typed."
    echo "  Leg 2 below cannot mean anything: an always-empty history passes it."
    echo "--- session 1 history region ---"
    echo "$S1" | sed -n '/history/,$p' | head -20
    rm -f "$CLEAN"; exit 2
fi

# Leg 2: THE FINDING. Session 2 must not contain MARKER1 anywhere in a history
# row. Search history rows only -- a bare grep for the marker would match the
# scrollback of session 1 if the log split were off by a line.
if echo "$S2" | grep -qE "^ *[0-9]+ +.*$MARKER1"; then
    echo "FAIL leg 2: $TESTUSER's history still lists root's command:"
    echo "$S2" | grep -E "^ *[0-9]+ +.*$MARKER1" | head -5
    echo "  The previous session's command lines survived logout."
    FAIL=1
else
    echo "PASS leg 2: root's $MARKER1 is absent from $TESTUSER's history."
fi

# Leg 3: history still works in session 2. Distinguishes cleared from dead.
if echo "$S2" | grep -qE "^ *[0-9]+ +.*$MARKER2"; then
    echo "PASS leg 3: session 2's own history is functional ($MARKER2 listed)."
else
    echo "FAIL leg 3: session 2's history did NOT list its own $MARKER2."
    echo "  The buffer is not merely cleared, it is non-functional -- which"
    echo "  would also have passed leg 2. That is not the fix."
    FAIL=1
fi

rm -f "$CLEAN"
echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: PASS — history is cleared at logout and still works after."
    exit 0
fi
echo "RESULT: FAIL — see the legs above.  Serial: $SERIAL"
exit 1

# =============================================================================
# VALIDATION LOG — read this before changing any string matched above.
#
# This harness was validated BOTH WAYS against a deliberately reintroduced bug
# (history_init() moved out of the per-session block and called once before the
# session loop, which is the original defect shape -- the call still exists, so
# the source guard passes and only behaviour separates fixed from broken):
#
#   reverted kernel -> exit 1, leg 2 FAILs, legs 1+3 still PASS
#   fixed kernel    -> exit 0, all three legs PASS
#
# It reported a FALSE PASS twice before that, and both causes are now defended:
#
# 1. WRONG SHELL. The first version drove the ring-3 shell. Its history lives in
#    the shell.elf process image and login re-execs that binary, so session 2
#    always starts empty regardless of the kernel -- "cleared" against a fully
#    unfixed kernel. The buffer the fix is about is the single global in
#    src/shell_history.c, reachable only through `kshell`. Both sessions now
#    type it. This is the "test the boundary the fix lives at" rule: there are
#    two histories in this system and only one of them has the bug.
#
# 2. WRONG SPLIT ANCHOR. The second version split the log at the first
#    "echo ZQMARKERTWO". The kernel shell does not echo typed commands to
#    serial, so that string's first occurrence is a row of session 2's own
#    history OUTPUT -- printed after the leaked ZQMARKERONE row. The leak
#    landed above the split and leg 2 never saw it. The anchor is now the last
#    "Switching to the kernel shell", which each session produces exactly once.
#
# Both failures had the same shape: the harness was reading a region that could
# not contain the evidence, and an empty region satisfies an absence test
# perfectly. That is why leg 1 (a positive control INSIDE session 1) and leg 3
# (session 2's history must still work) are not optional -- neither false pass
# would have been caught by leg 2 alone, but neither survives a negative control.
# =============================================================================
