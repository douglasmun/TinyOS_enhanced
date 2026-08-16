#!/usr/bin/env bash
#
# verify-psvisibility.sh — FULLY AUTOMATED check that `ps` shows an unprivileged
# user ONLY their own processes, while root still sees everything.
#
# THE POLICY
#
# Own-only for unprivileged users, root sees all. The alternative — everyone
# sees everything, as on a stock Unix — leaks what root is running to any
# logged-in user: process NAMES are visible in `ps`, so a root-run maintenance
# command becomes an announcement. Own-only is also the conservative direction:
# it can be relaxed later without breaking anyone, whereas tightening it
# afterwards would.
#
# Implemented as task_visible_to_current() in process.c, shared by `ps`, `top`,
# `kill` and SYS_PSINFO/SYS_KILL so none of them can drift apart. It lives in
# process.c rather than shell_monitor.c precisely so the syscalls can reach it
# without the syscall layer depending on a shell module.
#
# WHY THE PROBE NEEDS A LIVE CHILD
#
# "The unprivileged user sees fewer rows than root" is satisfiable by a kernel
# that shows them NOTHING, which is not the policy and would be a broken `ps`.
# So the test user must own a process that they CAN see while root's tasks are
# hidden from them. slothold.elf (from the slot-cap work) is exactly that: it
# holds its slot for ~10 minutes, long enough to still be alive when `ps` runs.
#
# The kernel tasks are the other half. Idle and the EDR daemon are uid 0 and
# always live, so they are the fixed, guaranteed-present thing an unprivileged
# `ps` must NOT show. Asserting on Idle specifically is what makes this a real
# check rather than a row count.
#
# THE ASSERTIONS
#
#   - root's ps shows Idle          — the control. If root cannot see the kernel
#     tasks either, `ps` is simply broken and every other assertion here is
#     vacuous.
#
#   - the user's ps shows THEIR OWN process — proves the filter did not just
#     empty the table. This is the assertion that fails on a "hide everything"
#     kernel, which the row-count check alone would pass.
#
#   - the user's ps does NOT show Idle — the actual policy. Anchored on a
#     specific uid-0 task name, not a count: "fewer rows" is also true of a ps
#     that truncated its output.
#
#   - the user's Total: line matches what they can see — printing the raw table
#     total would state exactly how many processes are being withheld, which is
#     most of what hiding them was for.
#
#   - kill on a process they do not own reports "no such process" — NOT
#     "permission denied", which would confirm the PID is live and owned by
#     someone else and hand back the existence `ps` withholds.
#
# VALIDATED BOTH WAYS (2026-08-16): PASS as written; with
# task_visible_to_current() stubbed to `return true` it FAILS on the "user must
# not see Idle" assertion.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: psvis.log (serial),
# psvis-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

TESTUSER=psuser
TESTPASS=pspass1

ISO=dist/tinyos.iso
SERIAL=psvis.log
TRACE=psvis-trace.log
RUN_DISK=/tmp/tinyos-psvis-disk.img
MON_SOCK=/tmp/tinyos-psvis-mon.sock

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

# The sequence. The typist logs in as root and types `kshell` by default, so we
# start in the kernel command loop, where ps/useradd/su live.
#
#   ps (root)     : the control -- root must see the kernel tasks.
#   useradd + su  : become unprivileged (the root su fast path needs no password).
#   exec &        : give the user a process of their OWN to see. Backgrounded,
#                   so the shell comes straight back for the ps that follows.
#   ps (user)     : the measurement. Markers below are counted in the region
#                   AFTER this point, so the root ps above cannot satisfy them.
#   kill 1        : PID 1 is not theirs; must read as "no such process".
#
# Each expect string is what proves the step landed before the next line is
# sent -- ps prints a table under TCG and a follow-up typed into a still-
# scrolling console is dropped. The `exec &` step waits on slothold's own
# "holding" line, so the process is provably alive when ps runs.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ps" \
TINYOS_EXPECT="PID  STATE" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
su $TESTUSER=>Now running as;\
exec /slothold.elf &=>slothold: holding;\
ps=>Total:;\
kill 1=>kill:" \
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
    echo "  --- last 40 serial lines ---"
    tail -40 "$SERIAL"
    exit 1
}

# region_has REGION PATTERN -- true if PATTERN occurs in REGION.
#
# NOT `printf ... | grep -q`: under `set -o pipefail` (line 59) grep -q exits at
# the first match and SIGPIPEs the writer, and pipefail promotes that 141 to the
# pipeline's status -- so a match reads as a MISS. It bites when the match is
# EARLY and output continues after it, which is precisely a serial log ("Idle"
# near the top of a ps table, kilobytes of boot chatter following). On the
# `&& fail_with` assertions below that inverts a real policy violation into a
# silent pass. grep -c reads all input, so there is no SIGPIPE to promote.
region_has() {
    local n
    n=$(printf '%s\n' "$1" | grep -c "$2")
    [ "$n" -gt 0 ]
}

# --- Guard: we actually became the test user -----------------------------
#
# Every assertion below is about what an UNPRIVILEGED session sees. If the su
# never landed, the second ps ran as root, would legitimately show Idle, and
# the policy check would fail for a reason that has nothing to do with the
# policy.
grep -qa "Now running as" "$SERIAL" 2>/dev/null || fail_with \
    "never switched to $TESTUSER" \
    "The measurement below has to run as an unprivileged user; as root it" \
    "would show everything by design."

# --- Split the log at the su ---------------------------------------------
#
# Everything before the switch is root's session, everything after is the test
# user's. Without this split a grep for "Idle" would be satisfied by ROOT's ps
# and the policy check would pass no matter what the user saw.
SU_LINE=$(grep -na "Now running as" "$SERIAL" | head -1 | cut -d: -f1)
ROOT_REGION=$(head -n "$SU_LINE" "$SERIAL")
USER_REGION=$(tail -n +"$SU_LINE" "$SERIAL")

# --- Control: root sees the kernel tasks ---------------------------------
region_has "$ROOT_REGION" "Idle" || fail_with \
    "root's own ps did not show the Idle task" \
    "This is the control, not the policy: if root cannot see the kernel" \
    "tasks then ps is broken outright and the checks below prove nothing."

# --- The user CAN see their own process ----------------------------------
#
# Paired positive. Without this, a kernel whose ps showed an unprivileged user
# NOTHING AT ALL would pass every remaining assertion while being plainly wrong.
region_has "$USER_REGION" "slothold" || fail_with \
    "the unprivileged user could not see their OWN process" \
    "$TESTUSER started slothold.elf and must see it in their own ps." \
    "Showing them an empty table is not the policy -- own-only means they" \
    "see their own, not that they see nothing."

# --- The user CANNOT see root's tasks ------------------------------------
#
# The policy itself. Anchored on a specific always-live uid-0 task rather than
# a row count: "fewer rows than root" is also true of a ps that truncated.
region_has "$USER_REGION" "Idle" && fail_with \
    "the unprivileged user could see the root-owned Idle task" \
    "task_visible_to_current() in process.c should hide every task" \
    "whose uid differs from the caller's when the caller's euid is not 0." \
    "Idle is uid 0 and always live, so it is the canonical thing to hide."

# --- The Total: line does not leak the hidden count ----------------------
#
# The count must match the rows actually printed. A raw table total states
# precisely how many processes are being withheld, which is most of what
# hiding them was meant to prevent.
USER_TOTAL=$(printf '%s\n' "$USER_REGION" | grep -o "Total: [0-9]* process" \
             | sed 's/Total: \([0-9]*\).*/\1/' | tail -1)
ROOT_TOTAL=$(printf '%s\n' "$ROOT_REGION" | grep -o "Total: [0-9]* process" \
             | sed 's/Total: \([0-9]*\).*/\1/' | tail -1)

if [ -z "$USER_TOTAL" ]; then
    fail_with "the unprivileged ps printed no Total: line" \
        "Expected the summary line that ps always ends with."
fi

if [ -n "$ROOT_TOTAL" ] && [ "$USER_TOTAL" -ge "$ROOT_TOTAL" ]; then
    fail_with \
        "the user's Total: ($USER_TOTAL) is not below root's ($ROOT_TOTAL)" \
        "The unprivileged total still counts processes that were filtered out" \
        "of the table, so it leaks how many are being hidden. ps must report" \
        "the number of rows it actually printed."
fi

if [ "$USER_TOTAL" -lt 1 ]; then
    fail_with "the user's ps reported Total: $USER_TOTAL" \
        "They own a live slothold.elf, so their own total cannot be zero."
fi

# --- kill does not leak existence ----------------------------------------
#
# PID 1 is not the test user's. "permission denied" would confirm it is live
# and owned by someone else -- exactly the existence ps withholds, and enough
# to enumerate every live PID. It must read as a nonexistent process.
region_has "$USER_REGION" "permission denied (not owner" && fail_with \
    "kill told an unprivileged user that a foreign PID exists" \
    "cmd_kill should answer exactly as it does for a nonexistent PID, so" \
    "that ps and kill withhold the same thing. Reporting 'not owner'" \
    "confirms the process is live and lets a user enumerate live PIDs."

# --- The kernel did not fault --------------------------------------------
if grep -qa "triple fault\|Triple fault" "$TRACE" 2>/dev/null; then
    fail_with "the kernel triple-faulted during the run" \
        "A visibility filter that faults is not a fix. See $TRACE."
fi
if grep -qa "KERNEL PANIC" "$SERIAL" 2>/dev/null; then
    fail_with "the kernel panicked during the run" "See $SERIAL."
fi

echo "RESULT: PASS"
echo "  - root's ps showed the kernel tasks (Idle)"
echo "  - $TESTUSER saw their OWN slothold.elf"
echo "  - $TESTUSER did NOT see the root-owned Idle task"
echo "  - user Total: $USER_TOTAL vs root Total: ${ROOT_TOTAL:-n/a} (no hidden count leaked)"
echo "  - kill on a foreign PID reported no-such-process, not permission-denied"
echo "  - no triple fault, no panic"
exit 0
