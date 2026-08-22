#!/usr/bin/env bash
#
# verify-slotcap.sh — FULLY AUTOMATED check that a non-root user cannot exhaust
# the global task table, and that root stays able to work while they try.
#
# WHAT THIS IS ABOUT
#
# process.c has had task_rate_limit_check() for a long time — a token bucket,
# commented "fork bomb defense". It is real and it works, but it limits the RATE
# of task creation, not the QUANTITY of live tasks one user holds. At 5/sec,
# filling all MAX_TASKS (32) takes about five seconds, and the slots then STAY
# full. Nothing capped concurrent ownership.
#
# The task table is GLOBAL, so an unprivileged user who fills it starves the
# kernel's own tasks and blocks root from logging in to fix it. Recovery needed
# a reboot. Reachable from the ring-3 shell, which supports `&`.
#
# The fix is two limits in task_create_user:
#   USER_MAX_CONCURRENT_TASKS  a per-uid cap on live tasks       -> bounds damage
#   TASK_ROOT_RESERVED_SLOTS   slots non-root may not consume    -> keeps it recoverable
#
# WHY THE PROBE IS A PROGRAM AND NOT A SHELL LOOP
#
# The cap lives at the SYSCALL boundary, in task_create_user. Driving `&` from
# the shell would test the shell's parser on the way there, and is slow enough
# under TCG that the RATE limiter — not the cap — becomes the thing that stops
# it. That harness would pass against a kernel with no cap at all. So the probe
# is /slotbomb.elf, which calls spawn() in a tight loop and never reaps, and the
# only thing that can refuse it is the kernel's own accounting.
#
# WHY THE CHECK MUST BE DONE AS A NON-ROOT USER
#
# The same trap as verify-privcmd-guard.sh. uid 0 is deliberately EXEMPT from
# the per-user cap — capping root would stop the administrator cleaning up the
# mess, which is the opposite of the goal. So a root-side run of slotbomb would
# NOT be refused, and a harness that only ran as root would prove nothing. We
# create a user, su DOWN to it, and run the probe there.
#
# THE ASSERTIONS
#
#   - the probe was refused              — but NOT on its own. "spawn eventually
#     failed" is also true of a kernel that ran out of memory, could not find
#     the binary, or hit the rate limiter. So the refusal is asserted on the
#     EXACT errno -11 (-EAGAIN), which rules out every non-resource failure.
#     This is the same reasoning as verify-cred-deprecation.sh asserting -38.
#
#     But errno ALONE cannot finish the job here, because the rate limiter
#     returns -EAGAIN too. Runs 3-5 of this harness refused at a count that
#     looked exactly right (9) with the right errno, and the RATE LIMITER had
#     done it -- the concurrent cap was never reached. The two guards are
#     therefore separated by MESSAGE: the cap's line must be present AND the
#     rate limiter's must be absent. Neither half is redundant.
#
#   - it was refused at the RIGHT COUNT  — the cap is 10, so the probe must get
#     roughly that far. A refusal at 0 or 1 means something else rejected it
#     (permissions, a missing binary) and the assertion above would still pass.
#     A refusal at 30 would mean the per-user cap is absent and we merely hit
#     the global table. Bounded on both sides.
#
#   - root can still create a task       — THE point of the reserve, and the
#     assertion that distinguishes "the user was capped" from "the machine was
#     saved". Every other check here would pass on a kernel that capped the user
#     at exactly the moment the table was already full.
#
#   - the kernel did not fault           — a cap that engages by page-faulting
#     or panicking is not a fix. No triple fault, no kernel panic.
#
# VALIDATED BOTH WAYS (2026-08-16)
#
#   PASS on the fixed kernel: refused at spawn 8, uid charged correctly, root
#   still created a task while the user sat at their cap.
#
#   FAIL with the cap disabled (`if (0 && limit_creator ...)` in process.c).
#   Worth recording WHY this is the interesting half: with no cap at all, the
#   run STILL produced a refusal, at a plausible count (10), with the right
#   errno (-11) -- the RATE limiter did it. Every assertion except the message
#   check passed against a kernel with no per-user cap whatsoever. That check is
#   the entire harness.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: slotcap.log (serial),
# slotcap-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

TESTUSER=slotter
TESTPASS=slotpass1

# Must match USER_MAX_CONCURRENT_TASKS in src/process.c. If you change the cap,
# change this too -- the count assertion below is what proves the cap engaged
# rather than some unrelated failure.
CAP=10

ISO=dist/tinyos.iso
SERIAL=slotcap.log
TRACE=slotcap-trace.log
RUN_DISK=/tmp/tinyos-slotcap-disk.img
MON_SOCK=/tmp/tinyos-slotcap-mon.sock

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
# start in the kernel command loop, which is where useradd/su live.
#
#   useradd + su : become unprivileged (the root su fast path needs no password).
#   slotbomb     : the probe. Runs as the test user, spawns until refused.
#   su root      : back to root for the counter-check. NOT optional and not
#                  cosmetic: `su` calls sys_setuid on the SHELL TASK ITSELF, so
#                  after the su down there is no root task left. Without this,
#                  the counter-check below would run as the capped user, be
#                  refused correctly, and the harness would report a broken
#                  reserve when the reserve is fine. Needs a password, since
#                  only the root->anyone direction has a fast path.
#   exec hello   : root's counter-check AFTER the bomb -- the reserve is what
#                  makes this still possible. The children are slothold.elf and
#                  hold their slots for minutes, so this really does run while
#                  the table is near-full rather than after everything drained.
#
# slotbomb's expect string is its own refusal line, so the follow-up is not sent
# until the probe has actually finished -- spawning ten ECDSA-verified processes
# under TCG is slow, and a line typed into that window is dropped.
#
# TINYOS_FOLLOWUP_TIMEOUT is raised well above the 240s default because those
# ten spawns all happen inside ONE command: the whole loop has to fit in a
# single expect window. The first attempt at this harness failed on exactly that
# -- the typist gave up mid-probe and the run reported "no refusal" against a
# kernel whose cap was fine.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=900 \
TINYOS_EXEC_CMD="useradd $TESTUSER" \
TINYOS_EXPECT="Enter password for new user" \
TINYOS_FOLLOWUP_CMDS="\
!$TESTPASS=>created;\
su $TESTUSER=>Now running as;\
exec /slotbomb.elf=>slotbomb: refused after;\
su root=>Password for root;\
!$PASSWORD=>Switched to user;\
exec /hello.elf=>Hello from ELF!" \
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
    grep -v "Suspicious" "$SERIAL" | tail -40
    exit 2
}

# --- Guard: we actually became the unprivileged user ----------------------
#
# Checked first. uid 0 is EXEMPT from the per-user cap by design, so if the su
# did not happen the probe runs as root, is never refused, and the failure gets
# reported as a missing cap when the real problem is the harness.
grep -q "Now running as" "$SERIAL" 2>/dev/null || fail_with \
    "never became the unprivileged test user" \
    "root is deliberately exempt from the per-user cap, so the probe below" \
    "would not be refused and nothing would be proven."

# --- Guard: the probe actually ran ---------------------------------------
grep -q "slotbomb: starting" "$SERIAL" 2>/dev/null || fail_with \
    "the probe never started" \
    "/slotbomb.elf did not run — check it is seeded in kernel.c at 0755 and" \
    "that its signature verifies."

# --- The cap must not be absent ------------------------------------------
#
# Checked before the errno so the no-cap case is reported as a missing cap
# rather than as a malformed refusal line.
if grep -q "slotbomb: no refusal after" "$SERIAL" 2>/dev/null; then
    fail_with \
        "the unprivileged user was NEVER refused" \
        "slotbomb ran its full attempt budget without a single -EAGAIN, so" \
        "there is no per-user concurrent cap: one user can still fill the" \
        "global task table and starve root."
fi

REFUSAL=$(grep -o "slotbomb: refused after [0-9]* (err=-[0-9]*)" "$SERIAL" | tail -1)
[ -n "$REFUSAL" ] || fail_with \
    "no refusal line found in the serial log" \
    "The probe neither reported a refusal nor reported running out of" \
    "attempts, so it did not finish — likely a fault or a dropped keystroke."

echo "  probe reported: $REFUSAL"

COUNT=$(printf '%s\n' "$REFUSAL" | sed 's/.*refused after \([0-9]*\) .*/\1/')
ERR=$(printf '%s\n' "$REFUSAL" | sed 's/.*err=\(-[0-9]*\).*/\1/')

# --- THE check: refused with the RIGHT errno -----------------------------
#
# -11 is -EAGAIN. This rules out the failures that are NOT resource limits at
# all -- a missing binary (-2), a permission problem (-13), a malformed ELF
# (-8) -- any of which would satisfy a generic "it failed" assertion.
#
# It does NOT on its own prove the concurrent cap fired: the rate limiter
# returns -EAGAIN too. The message check below is what separates them.
[ "$ERR" = "-11" ] || fail_with \
    "the refusal was errno $ERR, not -11 (-EAGAIN)" \
    "Only the per-user cap returns -EAGAIN. Some OTHER failure stopped the" \
    "probe, so the cap itself is still unproven."

# --- Refused by the CAP, not by the rate limiter -------------------------
#
# The decisive assertion, and the one this harness was rewritten around. BOTH
# limiters in process.c return -EAGAIN, so the errno check above cannot tell
# them apart -- and on the first run of this harness it was the RATE LIMITER
# that fired, at a count that happened to look exactly right. Asserting only
# "refused with -EAGAIN at a plausible count" passed against a kernel whose
# concurrent cap was never reached at all.
#
# The two print different messages, so the message is the only thing that
# actually identifies which one refused.
grep -q "already holds .* tasks (limit" "$SERIAL" 2>/dev/null || fail_with \
    "the refusal did not come from the per-user concurrent cap" \
    "Nothing printed the cap's own message, so some OTHER limiter returned" \
    "-EAGAIN -- most likely the token-bucket RATE limiter, which fires first" \
    "and proves nothing about concurrent ownership. Check for" \
    "'[PROCESS] ERROR: User task creation rate limited' in $SERIAL."

# Paired negative. The check above is satisfied by a run where the cap fired
# for SOME spawn and the rate limiter fired for the one we actually measured --
# both messages present, wrong guard credited. The refusal under test must be
# attributable to the cap alone, so the rate limiter must not have fired at all.
grep -q "User task creation rate limited" "$SERIAL" 2>/dev/null && fail_with \
    "the rate limiter fired during the run" \
    "The cap's message is present, but so is the rate limiter's, so the" \
    "measured refusal cannot be attributed to the concurrent cap. The cap is" \
    "checked FIRST in task_create_user_argv precisely so this cannot happen;" \
    "if both appear, that ordering has regressed."

# --- Charged to the RIGHT uid --------------------------------------------
#
# The cap firing is not enough: it must be charged to the account that actually
# spawned the tasks. Run 6 of this harness passed with the cap reporting
# "uid 1000" in a session where useradd had assigned uid 1002 -- sys_spawn was
# not inheriting the caller's credentials, so every user's children ran as the
# hardcoded uid 1000 and pooled into one quota. See doc/KERNEL_BUGS.md.
#
# The uid is read from useradd's own output rather than hardcoded, since it
# depends on how many accounts precede it.
EXPECT_UID=$(grep -o "user '$TESTUSER' created (uid=[0-9]*" "$SERIAL" \
             | sed 's/.*uid=//' | tail -1)
CHARGED_UID=$(grep -o "uid [0-9]* already holds" "$SERIAL" \
              | sed 's/uid \([0-9]*\).*/\1/' | tail -1)

if [ -n "$EXPECT_UID" ] && [ "$CHARGED_UID" != "$EXPECT_UID" ]; then
    fail_with \
        "the cap was charged to uid $CHARGED_UID, not $EXPECT_UID" \
        "$TESTUSER was created with uid $EXPECT_UID and ran the probe, so the" \
        "tasks must be charged to that uid. Charging a different one means" \
        "credentials are not being inherited (sys_spawn) or the cap is reading" \
        "the child's hardcoded uid instead of the creator's."
fi

# --- Refused at the right COUNT ------------------------------------------
#
# Bounded on both sides. Too low means something rejected the very first spawns
# for an unrelated reason (which the errno check might still pass if that reason
# also returned -EAGAIN). Too high means the per-user cap is absent and we only
# hit the global table -- exactly the state this change is meant to prevent.
if [ "$COUNT" -lt 1 ]; then
    fail_with \
        "refused at spawn $COUNT — before a single child was created" \
        "The cap is meant to allow $CAP tasks per user. Being refused" \
        "immediately means the user cannot start ANY process."
fi
if [ "$COUNT" -gt "$CAP" ]; then
    fail_with \
        "refused only after $COUNT spawns, but the per-user cap is $CAP" \
        "The user got further than their cap should allow, so what stopped" \
        "them was the global table filling up — not the per-user limit."
fi

# --- Guard: we got back to root ------------------------------------------
#
# `su` mutates the shell task's own uid, so after the su DOWN there is no root
# task left. If the su back failed, the counter-check below runs as the still-
# capped user, is refused correctly, and a healthy reserve gets reported as
# broken.
#
# The two directions print DIFFERENT success messages, so this cannot grep for
# one string twice: the root->user fast path prints "Now running as"
# (shell_user.c:202) while the password path prints "Switched to user"
# (shell_user.c:285). Counting only the former saw 1 switch and failed a run in
# which the su back to root had in fact succeeded.
SU_COUNT=$(grep -c -e "Now running as" -e "Switched to user" "$SERIAL" 2>/dev/null)
[ "${SU_COUNT:-0}" -ge 2 ] || fail_with \
    "did not get back to root after the probe (saw $SU_COUNT switches, need 2)" \
    "The counter-check below would run as the capped user and fail for a" \
    "reason that has nothing to do with the root slot reserve."

# --- THE OTHER check: root can still work --------------------------------
#
# The reserve is what makes this DoS recoverable instead of a reboot. Every
# assertion above would pass on a kernel that capped the user at exactly the
# moment the table was already full — which bounds the user without saving the
# machine. The sleeper children are still alive here, so the table really is
# near-full when this runs.
grep -q "Hello from ELF!" "$SERIAL" 2>/dev/null || fail_with \
    "root could NOT create a task while the user sat at their cap" \
    "TASK_ROOT_RESERVED_SLOTS is not holding slots back. The user is capped" \
    "but the machine is still unrecoverable without a reboot, which is the" \
    "actual thing this change exists to prevent."

# --- The cap must not engage by crashing ---------------------------------
if grep -q "Triple fault\|triple fault" "$TRACE" 2>/dev/null; then
    fail_with "triple fault in the trace" \
        "The cap must refuse cleanly, not fault."
fi
if grep -q "KERNEL PANIC" "$SERIAL" 2>/dev/null; then
    fail_with "kernel panic on the serial log" \
        "The cap must refuse cleanly, not panic."
fi

echo ""
echo "RESULT: PASS"
echo "  - unprivileged user refused at spawn $COUNT with -EAGAIN (cap $CAP)"
echo "  - root still created a task while the user sat at their cap"
echo "  - no triple fault, no panic"
exit 0
