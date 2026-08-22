#!/usr/bin/env bash
#
# verify-ring3-ps.sh — FULLY AUTOMATED check that ps/kill/top work from the
# RING-3 shell and enforce the same visibility policy the kernel shell does.
#
# WHAT THIS IS TESTING
#
# SYS_PSINFO (33) and SYS_KILL (34) carry the process listing across the ring
# boundary. The commands themselves are the easy part; the property worth a
# harness is that the FILTER travelled with them. A ring-3 `ps` that showed an
# unprivileged user the whole table would be a regression invisible to any
# "does ps work" test -- it would print a fine-looking listing.
#
# WHY IT RUNS IN THE RING-3 SHELL (TINYOS_STAY_IN_RING3=1)
#
# verify-psvisibility.sh already proves the KERNEL shell filters correctly.
# Running this one in kshell too would re-test that and prove nothing about the
# syscalls -- the kernel shell reads task_t directly and never calls them. The
# boundary the new code lives at is ring 3, so that is where the test runs.
# The sequence does pass THROUGH kshell to reach an unprivileged account (see
# the route comment further down), but every assertion is measured against
# output from a ring-3 shell calling SYS_PSINFO/SYS_KILL.
#
# THE PAIRED POSITIVE, AGAIN
#
# "The user sees fewer rows than root" is satisfied by a ps that shows them
# NOTHING -- which would mean SYS_PSINFO was returning an empty table and every
# policy assertion would pass against thoroughly broken code. So the load-
# bearing assertion is that the user sees their OWN process. slothold.elf holds
# a slot for ~10 minutes, so it is provably alive when ps runs.
#
# ASSERTIONS
#
#   - ring-3 ps prints a table for root, including the kernel tasks (control:
#     if SYS_PSINFO returns nothing at all, everything below is vacuous)
#   - ring-3 ps shows an unprivileged user their OWN process   (paired positive)
#   - ring-3 ps does NOT show that user the root-owned Idle task     (the policy)
#   - the Total: line counts only the rows printed        (no hidden-count leak)
#   - ring-3 kill on a foreign PID says "no such process", never "permission
#     denied" -- otherwise kill re-leaks the existence ps just withheld
#   - ring-3 kill on the user's OWN process SUCCEEDS       (paired positive #2:
#     a kill that refuses everything would satisfy the leak check trivially)
#   - top runs and prints its header                            (smoke, ring 3)
#
# VALIDATED BOTH WAYS (2026-08-16): PASS as written; with
# task_visible_to_current() stubbed to `return true` it FAILS on the "user must
# not see the root-owned Idle task" assertion. Worth doing separately from
# verify-psvisibility.sh's identical stub run: that one proves the KERNEL
# shell's filter, this one proves SYS_PSINFO's, and they are different code.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: ring3ps.log (serial),
# ring3ps-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

TESTUSER=r3user
TESTPASS=r3pass1

ISO=dist/tinyos.iso
SERIAL=ring3ps.log
TRACE=ring3ps-trace.log
RUN_DISK=/tmp/tinyos-ring3ps-disk.img
MON_SOCK=/tmp/tinyos-ring3ps-mon.sock

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1

# The embedded shell must match userspace/shell.c, or this harness tests the
# PREVIOUS shell and silently reports on code that is not being changed. Sign
# and re-embed every run: it is a second of work and the failure it prevents
# looks exactly like a passing test.
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1

make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# Prove the ISO actually carries this build. A stale ISO is the failure mode
# that wasted several runs on the slot-cap work: grub-mkrescue runs after the
# link, so mtimes look plausible even when the payload is old.
# NOTE: `strings | grep -q` is wrong under `set -o pipefail`. grep -q exits at
# the first match, SIGPIPEs `strings` (141), and pipefail makes that the
# pipeline's status -- so the guard fires on a FRESH ISO. Count instead: grep -c
# consumes all input, so no SIGPIPE, and the status reflects the match.
ISO_MARKERS=$(strings "$ISO" | grep -c "one-shot snapshot")
if [ "$ISO_MARKERS" -eq 0 ]; then
    echo "RESULT: INCONCLUSIVE — the ISO does not contain the new ring-3 shell"
    echo "  'one-shot snapshot' (from cmd_top's help text) is absent, so the"
    echo "  embedded shell.elf predates this change and the run would report"
    echo "  on the OLD shell."
    exit 3
fi

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

# TINYOS_STAY_IN_RING3=1 keeps us in the ring-3 shell -- the whole point.
#
# HOW THE UNPRIVILEGED HALF IS REACHED. The ring-3 shell has no `su` builtin
# (its credential commands are passwd/useradd/userdel only). Logging out and
# back in as the test user looked like the obvious route, and it does reach a
# ring-3 shell -- but keystrokes sent to that re-logged-in session never reach
# its readline: the session comes up, prints its prompt, and then ignores input
# entirely. That is a separate defect in the login path, not something this
# harness should work around silently; it is recorded in doc/KERNEL_BUGS.md.
#
# So the route is kshell -> su -> `exec /shell.elf`, which lands in a SECOND
# ring-3 shell that has already inherited the test user's credentials. The
# measurement still happens at ring 3 through SYS_PSINFO/SYS_KILL, which is the
# boundary under test; kshell is only the vehicle for the su.
#
#   ps                : root, ring 3. Control: the syscall returns a real table.
#   useradd           : create the test account (SYS_CRED, root only).
#   kshell            : hand this session to the kernel shell (for su).
#   su <user>         : drop to the unprivileged account.
#   exec /shell.elf   : relaunch the ring-3 shell, which inherits that uid.
#   /slothold.elf &   : `exec` is not a ring-3 builtin; a bare path runs a
#                       program and a trailing & backgrounds it. This gives the
#                       user a process of their OWN to see.
#   ps                : THE MEASUREMENT, as the unprivileged user.
#   kill 1            : PID 1 is not theirs -> must read as "no such process".
#   top               : smoke test that the snapshot path runs at ring 3.
#   kill {MYPID}      : THE SECOND PAIRED POSITIVE. The '&' announcement prints
#                       "[pid] name", which the typist captures as MYPID and
#                       substitutes here. Without this, a sys_kill that refused
#                       EVERY request would satisfy the "does not leak" check
#                       above -- "no such process" is exactly what a totally
#                       broken kill would say. The user must be able to kill
#                       their own process, and it runs last because it does.
#
# The markers below are counted in the region AFTER the second login, so root's
# ps cannot satisfy the unprivileged assertions.
#
# WHY THE RING-3 COMMANDS ARE SENT UNVERIFIED ('!'). The typist's echo check
# looks for each typed character IN ORDER anywhere in the serial stream after
# the mark. The ring-3 shell does not echo keystrokes to serial at all -- the
# kernel echoes them in the keyboard IRQ, which reaches the VGA console only --
# so those checks were passing on COINCIDENTAL matches in the surrounding kernel
# chatter. '/slothold.elf' is simply the first command containing a character
# ('.') rare enough not to occur by luck, which is how this surfaced. Every one
# of these still carries an expect on its RESULT, which is a stronger check than
# a per-character echo that could be satisfied by unrelated output.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ps" \
TINYOS_EXPECT="STATE  NAME" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
kshell=>Switching to the kernel shell;\
su $TESTUSER=>Now running as;\
exec /shell.elf=>TinyOS shell (ring 3);\
!/slothold.elf &=>slothold: holding@MYPID=\\n\\[([0-9]+)\\] /slothold.elf;\
!ps=>Total:;\
!kill 1=>kill:;\
!top=>Tasks:;\
!kill {MYPID}=>kill: terminated {MYPID}" \
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
# NOT `printf ... | grep -q`: under `set -o pipefail` (line 44) grep -q exits at
# the first match and SIGPIPEs the writer, and pipefail promotes that 141 to the
# pipeline's status -- so a match reads as a MISS. It only bites once the region
# outgrows the pipe buffer, which is exactly when a serial log gets interesting,
# and it silently inverts every assertion built on it. grep -c reads all input,
# so there is no SIGPIPE to promote.
region_has() {
    local n
    n=$(printf '%s\n' "$1" | grep -c "$2")
    [ "$n" -gt 0 ]
}

# --- Guard: the second login actually happened ---------------------------
#
# Every unprivileged assertion depends on it. Without this guard, a failed
# re-login would leave the whole measurement running as root, where showing
# Idle is correct -- and the policy check would fail for a reason unrelated to
# the policy (or worse, pass while testing nothing).
SU_LINE=$(grep -na "Now running as" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
if [ -z "$SU_LINE" ]; then
    fail_with "never became $TESTUSER" \
        "The unprivileged half of this test never ran: kshell's \`su\` did not" \
        "report 'Now running as', so everything after it was still root."
fi

# --- Split the log at the SECOND ring-3 shell banner ----------------------
#
# Before it: root's ring-3 session. After it: the test user's. Without this
# split, a grep for 'Idle' would be satisfied by ROOT's ps and the policy
# assertion would pass no matter what the unprivileged user saw.
#
# The banner is the marker rather than the login prompt because the second
# session is reached via kshell + su + `exec /shell.elf`, not a re-login -- see
# the sequence comment above for why.
SHELL2_LINE=$(grep -na "TinyOS shell (ring 3)" "$SERIAL" | sed -n '2p' | cut -d: -f1)
if [ -z "$SHELL2_LINE" ]; then
    fail_with "the second ring-3 shell never started" \
        "\`exec /shell.elf\` after su did not print the ring-3 banner, so the" \
        "measurement would have run in kshell -- the wrong code path entirely."
fi
ROOT_REGION=$(head -n "$SHELL2_LINE" "$SERIAL")
USER_REGION=$(tail -n +"$SHELL2_LINE" "$SERIAL")

# --- Control: the syscall returned a real table to root ------------------
#
# "PID *STATE", not a fixed run of spaces: the PID column is 5 wide because
# task_alloc_pid() draws PIDs from the CSPRNG rather than counting up, and
# pinning the exact spacing here would turn any future column adjustment into a
# harness failure that reads like a policy failure.
region_has "$ROOT_REGION" "PID *STATE" || fail_with \
    "ring-3 ps never printed its table header" \
    "SYS_PSINFO returned nothing usable, so every check below is vacuous." \
    "Look for 'ps: ' followed by an errno string in the log."

region_has "$ROOT_REGION" "Idle" || fail_with \
    "root's ring-3 ps did not show the Idle task" \
    "Control, not policy: root must see the kernel tasks. If this fails the" \
    "syscall is filtering when it should not, or returning an empty table."

# --- The user CAN see their own process ----------------------------------
#
# THE PAIRED POSITIVE. Without it, a SYS_PSINFO returning an empty table to
# every unprivileged caller would pass every remaining assertion while being
# comprehensively broken.
region_has "$USER_REGION" "slothold" || fail_with \
    "the unprivileged user's ring-3 ps did not show their OWN process" \
    "$TESTUSER started slothold.elf and must see it. An empty table is not" \
    "the policy -- own-only means they see their own, not that they see" \
    "nothing. Check that SYS_PSINFO compares task->uid to the CALLER's uid."

# --- The user CANNOT see root's tasks ------------------------------------
#
# ANCHORED ON Idle, NOT on "any kernel task". kshell's `su` calls sys_setuid on
# the task it runs in, which IS the kernel 'Shell' task -- so after the su that
# task genuinely belongs to the test user and correctly appears in their ps.
# Idle is the right anchor precisely because nothing in this sequence can
# re-own it: it stays uid 0 for the whole boot.
region_has "$USER_REGION" "Idle" && fail_with \
    "the unprivileged user's ring-3 ps showed the root-owned Idle task" \
    "The filter did not travel across the ring boundary: SYS_PSINFO must" \
    "apply task_visible_to_current() before copying records out."

# --- Total: counts only the rows printed ---------------------------------
USER_TOTAL=$(printf '%s\n' "$USER_REGION" | grep -o "Total: [0-9]* process" \
             | sed 's/Total: \([0-9]*\).*/\1/' | tail -1)
ROOT_TOTAL=$(printf '%s\n' "$ROOT_REGION" | grep -o "Total: [0-9]* process" \
             | sed 's/Total: \([0-9]*\).*/\1/' | tail -1)

if [ -z "$USER_TOTAL" ]; then
    fail_with "the unprivileged ring-3 ps printed no Total: line" \
        "Expected the summary line cmd_ps always ends with."
fi

if [ -n "$ROOT_TOTAL" ] && [ "$USER_TOTAL" -ge "$ROOT_TOTAL" ]; then
    fail_with \
        "the user's Total: ($USER_TOTAL) is not below root's ($ROOT_TOTAL)" \
        "The total counts records the caller never received, so it leaks how" \
        "many processes are being hidden."
fi

if [ "$USER_TOTAL" -lt 1 ]; then
    fail_with "the user's ring-3 ps reported Total: $USER_TOTAL" \
        "They own a live slothold.elf, so their own total cannot be zero."
fi

# --- top ran at ring 3 ---------------------------------------------------
region_has "$USER_REGION" "Tasks: [0-9]* total" || fail_with \
    "ring-3 top did not print its summary line" \
    "cmd_top should print 'Tasks: N total (...)' before its table."

# --- kill does not leak existence ----------------------------------------
#
# PID 1 is not the test user's. It must read as a nonexistent process, never
# as permission-denied -- that would confirm the PID is live and owned by
# someone else, handing back the existence ps withheld.
region_has "$USER_REGION" "kill: no such process" || fail_with \
    "ring-3 kill on a foreign PID did not report 'no such process'" \
    "sys_kill must answer -ESRCH for a PID the caller cannot see, so kill" \
    "and ps withhold the same set."

region_has "$USER_REGION" "permission denied (not owner" && fail_with \
    "ring-3 kill leaked ownership information" \
    "Naming the owner confirms the PID is live and lets a user enumerate" \
    "every live PID through the error message alone."

# --- ...but kill DOES work on the caller's own process --------------------
#
# Matched WITH a PID argument, not as a bare "kill: terminated". The typist
# already waits on "kill: terminated <MYPID>" as this command's expect, so a
# wrong PID cannot reach here -- but the bash assertion should not be weaker
# than the typist's, or a later edit to the sequence silently loosens it.
region_has "$USER_REGION" "kill: terminated [0-9][0-9]*" || fail_with \
    "the unprivileged user could not kill their OWN process" \
    "This is the paired positive for the leak check above: a sys_kill that" \
    "refused everything would answer 'no such process' to every request and" \
    "pass that check while being completely broken. $TESTUSER owns the" \
    "backgrounded slothold.elf and must be able to terminate it."

# --- The kernel did not fault --------------------------------------------
if grep -qa "triple fault\|Triple fault" "$TRACE" 2>/dev/null; then
    fail_with "the kernel triple-faulted during the run" \
        "A syscall that faults is not a fix. See $TRACE."
fi
if grep -qa "KERNEL PANIC" "$SERIAL" 2>/dev/null; then
    fail_with "the kernel panicked during the run" "See $SERIAL."
fi

echo "RESULT: PASS"
echo "  - ring-3 ps printed a table via SYS_PSINFO (root Total: ${ROOT_TOTAL:-n/a})"
echo "  - root saw the kernel tasks (Idle)"
echo "  - $TESTUSER saw their OWN slothold.elf     (paired positive)"
echo "  - $TESTUSER did NOT see the root-owned Idle task"
echo "  - $TESTUSER's Total: $USER_TOTAL counts only their rows (< root's ${ROOT_TOTAL:-n/a})"
echo "  - ring-3 kill on a foreign PID said 'no such process', leaked no owner"
echo "  - ring-3 kill on their OWN PID succeeded   (paired positive #2)"
echo "  - ring-3 top printed its summary and table"
echo "  - no triple fault, no panic"
exit 0
