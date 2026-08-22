#!/usr/bin/env bash
#
# verify-supervisor.sh — FULLY AUTOMATED check that a killed system task is
# observed dead, restarted, and that networking actually recovers afterwards.
#
# doc/NETDAEMON_DESIGN.md item 4, PR D2.
#
# WHY THIS EXISTS BEFORE ANY RING-3 CODE
#
# PR D1 moves the RX parser to ring 3, where the entire premise is that it CAN
# die. A ring-3 parser with no restart turns every parser crash into a permanent
# loss of networking -- strictly worse than the monolithic arrangement it
# replaces. So the supervisor is built and proven FIRST, against knetd as it
# exists today: a deliberately-killed knetd is a complete test case with no
# ring-3 code involved, and D1 then lands into a kernel that already survives
# the death of the task it is about to make killable.
#
# HOW THE DAEMON IS MADE TO DIE
#
# Not with `kill`. Every kernel task is created with CAP_ALL (process.c), which
# is 0xFFFFFFFF and therefore includes CAP_UNKILLABLE, and both sys_kill and
# task_terminate refuse that flag -- so knetd cannot be killed from outside at
# all. The first draft of this harness did use `kill <pid>` and would have
# graded the entire restart path against a daemon that never died, because the
# refusal is quiet from the shell's point of view.
#
# So the kernel carries a TINYOS_FAULT_INJECT hook (off by default, like every
# other opt-out in this tree): `killknetd` sets a flag, and knetd clears its own
# CAP_UNKILLABLE and terminates itself at the top of its next loop. The
# capability CHECK is left untouched -- the victim opts out of its own
# protection rather than any caller learning to bypass it.
#
# It calls task_terminate(own_pid), NOT task_exit(). task_exit() reads
# process.c's `current_task` static, which only task_switch_to() ever sets and
# which is NULL for scheduler-run tasks -- so the first version of this hook
# returned silently and knetd just kept running. The harness caught it at step
# 1 (no "has died" line), which is precisely what step 1 is for.
#
# WHY "PING STILL WORKS" IS NOT THE ASSERTION
#
# The tempting test is: kill knetd, ping, see a reply. It is close to worthless
# on its own, because it passes in a case that has nothing to do with the fix:
# if the kill silently FAILED (knetd protected, wrong pid, kill refused) then
# networking never broke, ping replies, and the harness reports success against
# a kernel with no supervisor at all. That is the same false-pass shape recorded
# in memory ownership-harness-needs-foreign-object -- an assertion that only
# exercises the healthy branch cannot distinguish a working mechanism from an
# inert one.
#
# So the assertion is four-part, and all four are load-bearing:
#
#   0. BASELINE           before the kill, restarts == 0. Without this, a kernel
#                         whose daemons die spontaneously at boot would supply
#                         the "restarts >= 1" of step 2 for free.
#   1. THE KILL LANDED    the supervisor OBSERVED a death ("has died" on the
#                         console). Without this, steps 2 and 3 are vacuous.
#   2. THE RESTART RAN    ifconfig's "Supervisor:" line reports restarts >= 1
#                         and gave-up == 0, read from the live table, AND the
#                         restarted task has a DIFFERENT pid than the one killed.
#   3. NETWORKING RECOVERED  frames injected AFTER the kill are parsed -- the RX
#                         counter must RISE across the kill. This is the part
#                         that catches a supervisor which re-creates a task that
#                         then fails to do its job: a restarted knetd that never
#                         drains the softirq ring satisfies 1 and 2 completely.
#
# The PIDs compared in step 2 are read from the SUPERVISOR's own console lines,
# never hardcoded -- PIDs here are recycled crypto-random 16-bit values
# (task_alloc_pid), so a hardcoded one would drift onto another task.
#
# NEGATIVE CONTROLS
#
#   NC1 -- comment out the supervisor_watch("knetd", ...) call in kernel.c and
#          rebuild. The supervisor still runs, but nothing is registered. knetd
#          dies and stays dead. Steps 1, 2 and 3 must ALL fail. If any of them
#          still passes, that step is measuring something other than supervision.
#
#   NC2 -- comment out the scheduler_add_task(...pid_supervisor) line. The task
#          is created, registered and CAP_UNKILLABLE, but never scheduled. This
#          control is here because it is a bug that ALREADY HAPPENED during
#          development: `ps` still listed the supervisor and ifconfig still
#          reported "1 watched", so both status surfaces looked healthy while
#          nothing was supervised. Steps 1-3 must fail; a harness that checks
#          only "watched >= 1" passes.
#
#   NC3 -- run NC1 but ignore step 3's DELTA and accept a merely nonzero RX
#          count. It passes, because the pre-kill injection already made the
#          counter nonzero. That is why step 3 asserts a RISE and not a value.
#
# CLOSED GAP: THE GIVE-UP BRANCH (step 5, added as a D1 prerequisite)
#
# Through PR D2 this harness only ever asserted gave-up == 0, which proves the
# rate limiter does not fire SPURIOUSLY and says nothing about whether it fires
# when it should. That branch is the one that matters most after D1: a remote
# host that can crash the ring-3 parser on demand drives an unbounded restart
# loop, and the limiter is the only thing that stops it.
#
# Step 5 now drives knetd past the budget and asserts three things:
#   (a) gave-up becomes 1
#   (b) the "GIVING UP" line reaches the console
#   (c) the daemon STAYS DEAD -- a further injection parses ZERO frames
#
# (c) is the real claim. (a) and (b) are both the supervisor's opinion of
# itself; a give-up that sets the flag, prints the line, and restarts anyway
# passes both and is WORSE than no limiter, because the operator now believes
# the loop has stopped. Only the pinned RX counter is independent evidence.
#
# Note (c) asserts the RX counter does NOT move while step 3 asserts it DOES.
# Same counter, opposite directions, deliberately. Do not reconcile them.
#
# WHY THE DEATHS ARE DRIVEN FROM INSIDE THE GUEST
#
# `killknetd 8` sets a countdown that each restarted knetd decrements before
# dying again, rather than the harness typing the command eight times. The
# budget is 5 deaths within 10 seconds; typing eight commands with echo
# verification under TCG does not reliably fit in that window, and missing it
# fails SILENTLY -- the supervisor restarts each time, the window rolls forward,
# gave-up stays 0, and the run reports exactly what a BROKEN limiter reports.
# 8 > 5 so the burst clears the budget with margin.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: supervisor.log (serial), supervisor-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=supervisor.log
TRACE=supervisor-trace.log
RUN_DISK=/tmp/tinyos-sup-disk.img
MON_SOCK=/tmp/tinyos-sup-mon.sock

FRAME_COUNT=${TINYOS_SUP_FRAMES:-20}
BAD_ETHERTYPE=0x88b5

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

# ---------------------------------------------------------------------------
# SOURCE GUARDS
# ---------------------------------------------------------------------------
[ -f src/supervisor.c ] || guard_fail "src/supervisor.c is missing; tree predates PR D2"
grep -q "supervisor_watch" src/kernel.c \
    || guard_fail "kernel.c never registers anything with the supervisor"
grep -q "task_supervisor" src/kernel.c \
    || guard_fail "kernel.c never starts the supervisor task"

# The supervisor must validate the GENERATION, not just the pid. task_terminate()
# recycles the slot (pid = 0, task_free_slot_for_task), so a bare task_get() can
# match a DIFFERENT task created later in the same slot with the same pid -- which
# would make a dead daemon look alive, the one failure this subsystem exists to
# prevent. Comments stripped first: the rationale comment necessarily names
# task_get_validated, and matching comment text instead of the call is the
# mistake that once made a guard in verify-netd-boundary.sh fire against correct
# code.
if ! grep -v '^\s*\*' src/supervisor.c | grep -v '^\s*/\*' | grep -v '^\s*//' \
     | grep -q "task_get_validated"; then
    guard_fail "supervisor.c does not use task_get_validated(); a bare pid lookup
  aliases a recycled slot and would report a dead task as alive"
fi

# The restart path must be rate limited, or a task that dies on an
# attacker-chosen input restarts forever at the attacker's chosen rate.
grep -q "SUPERVISOR_MAX_RESTARTS" src/supervisor.c \
    || guard_fail "supervisor.c has no restart rate limit"

# The daemon must be reachable by the fault injector.
#
# An earlier draft of this harness tried to kill knetd with `kill <pid>` and
# guarded that by grepping kernel.c for a CAP_UNKILLABLE grant near pid_knetd.
# That guard was WRONG in a way worth recording: task_create_kernel() assigns
# CAP_ALL (0xFFFFFFFF) in process.c, which already includes CAP_UNKILLABLE, so
# EVERY kernel task is protected and the per-task grants in kernel.c are
# redundant. sys_kill and task_terminate both refuse the flag, so the kill was
# silently refused, networking never broke, and every later assertion would have
# been graded against a daemon that never died. Hence TINYOS_FAULT_INJECT: the
# victim clears its own capability and exits, leaving the capability CHECK
# itself untouched so no production path learns to bypass it.
grep -q "TINYOS_FAULT_INJECT" src/test_tasks.c \
    || guard_fail "src/test_tasks.c has no TINYOS_FAULT_INJECT hook; knetd cannot
  be made to die, so the restart path cannot be exercised at all"

# Step 5's repeat-death budget. Guarded separately from the flag above because a
# tree with only the single-death hook runs steps 1-3 perfectly and then reports
# gave-up == 0 at step 5a -- which is indistinguishable from a broken limiter.
grep -q "knetd_die_repeat" src/test_tasks.c \
    || guard_fail "src/test_tasks.c has no knetd_die_repeat countdown; the give-up
  branch cannot be driven and step 5 would report a limiter failure that is
  really a missing hook"
grep -q "knetd_die_repeat" src/shell.c \
    || guard_fail "the kernel shell's killknetd takes no repeat count"

command -v python3 >/dev/null 2>&1 || guard_fail "python3 not found"
[ -f tools/inject_frames.py ] || guard_fail "tools/inject_frames.py is missing"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
# Clean first: EXTRA_CFLAGS is not part of the dependency graph, so a tree left
# over from a default build would relink stale objects that lack the hook.
#
# And clean AFTERWARDS, via the trap below, because the hazard runs both ways and
# the second direction is worse. This harness is the only one that builds with a
# flag, so the object tree it leaves behind is poisoned for every OTHER harness:
# shell.o still references knetd_die_now while a rebuilt test_tasks.o no longer
# defines it, and the next five verify-*.sh runs die at LINK time with an
# undefined reference. That is not a hypothetical -- it happened, and the
# failures look like a broken kernel rather than a dirty tree, which is the
# expensive kind of wrong.
trap 'make clean >/dev/null 2>&1' EXIT
make clean >/dev/null 2>&1
make EXTRA_CFLAGS=-DTINYOS_FAULT_INJECT >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# Verify the ARTIFACT, not the source.
ISO_MARKERS=$(strings "$ISO" | grep -c "SUPERVISOR")
if [ "$ISO_MARKERS" -eq 0 ]; then
    guard_fail "the ISO has no supervisor strings; it predates PR D2"
fi

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

QEMU_MCAST=230.0.0.4:1237

echo "==> Launching headless QEMU (monitor $MON_SOCK, mcast socket $QEMU_MCAST)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev socket,id=net0,mcast="$QEMU_MCAST" \
    -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

INJECT_CMD="python3 tools/inject_frames.py --mcast '$QEMU_MCAST' \
    --count $FRAME_COUNT --ethertype $BAD_ETHERTYPE --dst 52:54:00:12:34:56"

export TINYOS_HOOK_INJECT1="sleep 2; $INJECT_CMD >/dev/null 2>&1; sleep 5; true"
export TINYOS_HOOK_INJECT2="sleep 3; $INJECT_CMD >/dev/null 2>&1; sleep 6; true"

# Give-up control (step 5). No frames -- just time for the 8 requested deaths to
# play out. They land at scheduler speed, so this is generous, but the give-up
# print and the final ifconfig must not race the last restart attempt.
export TINYOS_HOOK_SETTLE="sleep 8; true"

# After the give-up, inject again. This is the load-bearing half of step 5: the
# claim is not "gave-up became 1" but "the daemon STAYS dead", and the only way
# to witness that is to send frames and prove they are NOT parsed. A give-up
# that still restarts is worse than no limiter at all, and the counter alone
# cannot distinguish the two.
export TINYOS_HOOK_INJECT3="sleep 3; $INJECT_CMD >/dev/null 2>&1; sleep 6; true"

# Sequence (in the KERNEL shell -- `killknetd` is a kshell builtin, and the
# default login shell is ring 3, which does not have it):
#   ifconfig              BASELINE -- restarts must be 0 here (step 0)
#   >INJECT1              drive frames pre-kill so the RX counter has a floor
#   ifconfig              record the pre-kill RX ring counts
#   killknetd             THE TEST (step 1)
#   ifconfig              post-kill: restarts must have risen (step 2)
#   >INJECT2              frames AFTER the restart
#   ifconfig              post-recovery: RX ring must have risen (step 3)
#   ps -l                 leave the task list in the log for diagnosis
#
# No PID capture is needed: the fault injector addresses knetd by identity, not
# by pid. The PID comparison in step 2 still happens, but reads both values out
# of the SUPERVISOR's own console lines -- which is the stronger check anyway,
# since it is the supervisor's view of the death and the restart that must
# disagree, not the harness's.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
# Do NOT put `kshell` here. tools/qemu_typist.py ALREADY hands over to the
# kernel shell before it types anything (it prints "sending 'kshell' (switch to
# the kernel shell)" and waits for "shell: exiting"). Naming it again as
# TINYOS_EXEC_CMD types a SECOND `kshell`, this time AT the kernel shell, where
# it is not a hand-over but an unknown builtin:
#
#     D:/ $ kshell
#     Switching to the kernel shell; `logout` there returns to login.
#     shell: exiting
#     $ kshell
#     Unknown command: kshell           <-- the second one
#
# and TINYOS_EXPECT="TinyOS" then waits for a banner that is only printed on the
# hand-over that already happened, so the typist times out BEFORE typing any of
# the killknetd sequence. The harness reported
# "FAIL -- expected at least 2 'Supervisor:' samples, got 0", which reads as a
# dead supervisor; the supervisor was in fact watching knetd normally and the
# boot had zero panics. The first real command is the baseline ifconfig, so
# make that the exec command and let its own expect witness the kernel shell.
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="Supervisor" \
TINYOS_FOLLOWUP_CMDS="\
>INJECT1;\
ifconfig=>RX ring;\
killknetd=>knetd death requested;\
ifconfig=>Supervisor;\
>INJECT2;\
ifconfig=>RX ring;\
ps -l=>knetd;\
killknetd 8=>knetd death requested x8;\
>SETTLE;\
ifconfig=>Supervisor;\
>INJECT3;\
ifconfig=>RX ring;\
ps -l=>PID" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"

[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    echo "  --- last 50 serial lines ---"
    tail -50 "$SERIAL"
    exit 1
}

# --- Preconditions: the supervisor exists and registered knetd -------------
grep -qa "system task supervisor started" "$SERIAL" \
    || fail_with "the supervisor task never announced itself" \
        "Nothing is watching anything, so no restart can occur."

grep -qa "watching 'knetd'" "$SERIAL" \
    || fail_with "the supervisor never registered knetd" \
        "supervisor_watch() either was not called or refused the pid." \
        "This is exactly what NC1 removes, so if you are running NC1 this" \
        "failure is the expected result."

# --- Collect the Supervisor: samples in order ------------------------------
SUP_SAMPLES=()
while IFS= read -r line; do SUP_SAMPLES+=("$line"); done < <(grep -a "Supervisor:" "$SERIAL" \
    | sed -n 's/.*  *\([0-9][0-9]*\) watched, *\([0-9][0-9]*\) restarts, *\([0-9][0-9]*\) gave-up.*/\1 \2 \3/p')

if [ "${#SUP_SAMPLES[@]}" -lt 2 ]; then
    fail_with "expected at least 2 'Supervisor:' samples, got ${#SUP_SAMPLES[@]}" \
        "The run did not reach the post-kill ifconfig, so the restart" \
        "assertion never got a chance to be tested."
fi

# ifconfig prints the 'Supervisor:' line on EVERY invocation, so there is one
# sample per ifconfig and the indices line up exactly with RX_SAMPLES below:
#   [0] baseline, before any injection          -> step 0's subject
#   [1] after INJECT1, before the kill
#   [2] after the single kill and its restart   -> step 2's subject
#   [3] after INJECT2, post-restart
#   [4] after the give-up burst + SETTLE        -> step 5's subject
#   [5] after INJECT3, post-give-up
#
# Indexed by position rather than "last", because the give-up burst deliberately
# drives gave-up to 1: reading step 2's "gave-up must be 0" off the LAST sample
# would make steps 2 and 5 assert opposite things about the same number, and
# whichever ran second would win. Step 2's claim is about the state after ONE
# death; step 5's is about the state after the burst.
if [ "${#SUP_SAMPLES[@]}" -ne 6 ]; then
    fail_with "expected exactly 6 'Supervisor:' samples, got ${#SUP_SAMPLES[@]}" \
        "The command sequence did not complete, so the per-step samples cannot" \
        "be identified by position."
fi

BASE_WATCHED=$(echo "${SUP_SAMPLES[0]}" | awk '{print $1}')
BASE_RESTARTS=$(echo "${SUP_SAMPLES[0]}" | awk '{print $2}')
FINAL_RESTARTS=$(echo "${SUP_SAMPLES[2]}" | awk '{print $2}')
FINAL_GAVEUP=$(echo "${SUP_SAMPLES[2]}" | awk '{print $3}')
GU_WATCHED=$(echo "${SUP_SAMPLES[4]}" | awk '{print $1}')
GU_RESTARTS=$(echo "${SUP_SAMPLES[4]}" | awk '{print $2}')
GU_GAVEUP=$(echo "${SUP_SAMPLES[4]}" | awk '{print $3}')

echo "  baseline:    watched=$BASE_WATCHED restarts=$BASE_RESTARTS"
echo "  post-kill:   restarts=$FINAL_RESTARTS gave-up=$FINAL_GAVEUP"
echo "  post-burst:  watched=$GU_WATCHED restarts=$GU_RESTARTS gave-up=$GU_GAVEUP"

# --- Step 0: baseline ------------------------------------------------------
[ "$BASE_WATCHED" -ge 1 ] \
    || fail_with "supervisor reports 0 watched tasks at baseline" \
        "Registration failed even though the console announced it."

if [ "$BASE_RESTARTS" -ne 0 ]; then
    fail_with "restarts is already $BASE_RESTARTS BEFORE anything was killed" \
        "A system task is dying spontaneously. That both indicates a real bug" \
        "and destroys this harness's ability to attribute a later restart to" \
        "the deliberate kill."
fi
echo "  [step 0] baseline restarts == 0: OK"

# --- Step 1: the kill landed and was observed ------------------------------
if ! grep -qa "\[SUPERVISOR\] 'knetd' (PID .*) has died" "$SERIAL"; then
    fail_with "the supervisor never observed knetd dying" \
        "Either the kill did not land (check that the captured PID was knetd's" \
        "and that 'kill' reported success), or supervisor_run_once() is not" \
        "detecting death. Steps 2 and 3 are meaningless without this."
fi
# head -1, NOT tail -1: after step 5's burst the log holds nine death lines and
# eight restart lines. Step 2's claim is about the FIRST death and the FIRST
# restart -- the deliberate single kill. Taking the last of each would pair a
# burst death with a burst restart, or worse, pair the final death (which was
# NOT restarted, because the supervisor gave up) against a restart line from
# several deaths earlier, and then compare two unrelated PIDs.
DIED_PID=$(grep -a "\[SUPERVISOR\] 'knetd' (PID" "$SERIAL" | head -1 | sed -n 's/.*PID \([0-9]*\).*/\1/p')
echo "  [step 1] supervisor observed knetd (PID $DIED_PID) die: OK"

# --- Step 2: it was restarted, as a DIFFERENT task -------------------------
if [ "$FINAL_RESTARTS" -lt 1 ]; then
    fail_with "supervisor observed the death but restarts is still $FINAL_RESTARTS" \
        "The detection half works and the recovery half does not."
fi

if [ "$FINAL_GAVEUP" -ne 0 ]; then
    fail_with "supervisor GAVE UP on $FINAL_GAVEUP task(s) after a single kill" \
        "One deliberate death must not exhaust a budget of SUPERVISOR_MAX_RESTARTS."
fi

grep -qa "\[SUPERVISOR\] restarted 'knetd' as PID" "$SERIAL" \
    || fail_with "no restart line for knetd on the console" \
        "The counter rose but the restart was never announced, so the two" \
        "sources of truth disagree."

NEW_PID=$(grep -a "\[SUPERVISOR\] restarted 'knetd' as PID" "$SERIAL" | head -1 | sed -n 's/.*as PID \([0-9]*\).*/\1/p')
if [ -n "$DIED_PID" ] && [ "$NEW_PID" = "$DIED_PID" ]; then
    fail_with "the 'restarted' knetd has the SAME pid ($NEW_PID) as the dead one" \
        "That is a recycled-slot alias, not a restart -- the exact failure" \
        "task_get_validated() exists to prevent."
fi
echo "  [step 2] knetd restarted as PID $NEW_PID (was $DIED_PID), gave-up 0: OK"

# --- Step 3: networking actually recovered ---------------------------------
# The RX ring counter must RISE across the kill. A nonzero final value proves
# nothing on its own: the pre-kill injection already made it nonzero, so an
# unsupervised kernel whose knetd died permanently would still show a nonzero
# count here. The DELTA is the assertion.
RX_SAMPLES=()
while IFS= read -r line; do RX_SAMPLES+=("$line"); done < <(grep -a "RX ring:" "$SERIAL" \
    | sed -n 's/.*RX ring: *\([0-9][0-9]*\) cpl0, *\([0-9][0-9]*\) cpl3.*/\1 \2/p')

# The command sequence runs ifconfig SIX times, in this fixed order:
#   [0] baseline, before any injection      -> expected 0
#   [1] after INJECT1, before the kill      -> the PRE value (must be > 0)
#   [2] after the kill                      -> not used for the delta
#   [3] after INJECT2, post-restart         -> the POST value
#   [4] after the give-up burst + SETTLE    -> step 5's pre-value
#   [5] after INJECT3, post-give-up         -> step 5's post-value (must NOT rise)
#
# Indexed explicitly rather than by "first and last", because RX_SAMPLES[0] is a
# pre-injection zero: comparing against it would let step 3 pass on any nonzero
# final count and would stop proving that the RX path recovered. If the sequence
# above ever changes, this count assertion fails loudly instead of silently
# grading the wrong pair.
if [ "${#RX_SAMPLES[@]}" -ne 6 ]; then
    fail_with "expected exactly 6 'RX ring:' samples, got ${#RX_SAMPLES[@]}" \
        "The command sequence did not complete, so the pre/post pairs cannot be" \
        "identified by position and neither recovery nor give-up is proven."
fi

RX_PRE=$(echo "${RX_SAMPLES[1]}" | awk '{print $1}')
RX_POST=$(echo "${RX_SAMPLES[3]}" | awk '{print $1}')
echo "  RX cpl0: pre-kill=$RX_PRE  post-restart=$RX_POST"

if [ "$RX_PRE" -eq 0 ]; then
    fail_with "no frames were parsed BEFORE the kill (RX cpl0 == 0)" \
        "The injector never reached the guest, so the post-kill comparison" \
        "would be measuring a path that never worked in the first place."
fi

if [ "$RX_POST" -le "$RX_PRE" ]; then
    fail_with "RX parse count did not rise across the kill ($RX_PRE -> $RX_POST)" \
        "knetd was restarted but is not parsing frames. The task exists and" \
        "does not do its job -- precisely the case that steps 1 and 2 cannot" \
        "distinguish from a healthy recovery."
fi
echo "  [step 3] RX parsing recovered after the restart: OK"

# ===========================================================================
# STEP 5 — THE GIVE-UP BRANCH ACTUALLY FIRES, AND IS TERMINAL
#
# This is the control doc/NETDAEMON_DESIGN.md required before D1 lands. Until
# now this harness only ever asserted gave-up == 0, which proves the limiter
# does not fire SPURIOUSLY and says nothing about whether it fires when it
# should. That is the weakest possible statement about the one branch standing
# between an attacker-chosen frame and an unbounded restart loop.
#
# THREE PARTS, AND THE THIRD IS THE REAL CLAIM:
#
#   (a) gave-up becomes 1
#   (b) the "GIVING UP" line reaches the console
#   (c) the daemon STAYS DEAD -- frames injected afterwards are NOT parsed
#
# (a) and (b) are both readings of the supervisor's own opinion of itself. Only
# (c) is independent: a give-up that sets the flag, prints the line, and then
# restarts anyway would pass (a) and (b) and is WORSE than no limiter at all,
# because the operator now believes the loop has stopped. Hence the third
# injection and the assertion that the RX counter does NOT move.
#
# Note (c) is the inverse of step 3, which asserts the counter DOES rise. Two
# assertions on the same counter pointing in opposite directions, deliberately.
# ===========================================================================

# (a) the counter
if [ "$GU_GAVEUP" -lt 1 ]; then
    fail_with "the supervisor did NOT give up after 8 back-to-back deaths (gave-up=$GU_GAVEUP)" \
        "SUPERVISOR_MAX_RESTARTS is 5 within SUPERVISOR_WINDOW_MS (10000 ms) and" \
        "the deaths land at scheduler speed, so the budget must have been" \
        "exhausted. Either the rate limiter is not being consulted, or the" \
        "window is rolling forward between deaths and resetting the count --" \
        "in which case a remote host that can crash the parser has an unbounded" \
        "restart loop and the limiter is decorative." \
        "restarts at this point: $GU_RESTARTS"
fi
echo "  [step 5a] supervisor gave up on $GU_GAVEUP task(s): OK"

# (b) the console line. Separate from (a) on purpose: a silently dead network
# daemon is the exact failure NETWORK_ISOLATION.md item 1's "did it run" flag was
# reverted for masking, so the give-up MUST be visible and not merely counted.
grep -qa "\[SUPERVISOR\] GIVING UP on 'knetd'" "$SERIAL" \
    || fail_with "gave-up is $GU_GAVEUP but no 'GIVING UP' line reached the console" \
        "The state changed and the operator was never told. A silently dead" \
        "network daemon is unreportable and undiagnosable -- the counter is" \
        "only visible to someone who already suspected the problem and ran" \
        "ifconfig."
echo "  [step 5b] 'GIVING UP' announced on the console: OK"

# (c) THE REAL CLAIM: it stays dead.
RX_GU_PRE=$(echo "${RX_SAMPLES[4]}" | awk '{print $1}')
RX_GU_POST=$(echo "${RX_SAMPLES[5]}" | awk '{print $1}')
echo "  RX cpl0: post-give-up pre=$RX_GU_PRE post-inject=$RX_GU_POST"

if [ "$RX_GU_POST" -ne "$RX_GU_PRE" ]; then
    fail_with "RX parse count ROSE after the give-up ($RX_GU_PRE -> $RX_GU_POST)" \
        "The supervisor reported that it stopped restarting knetd, and frames" \
        "are still being parsed. Something is still draining the softirq ring:" \
        "either a restart path that bypasses supervisor_restart()'s rate limit" \
        "(the reason that check lives INSIDE the restart function), or the" \
        "give-up state is not actually terminal." \
        "" \
        "This is worse than having no limiter: the operator is told the restart" \
        "loop has stopped while it continues."
fi
echo "  [step 5c] daemon stayed dead; no frames parsed after the give-up: OK"

# Positive control for (c). Without this, 5c passes on a run where the third
# injection never reached the guest at all -- "no frames parsed" and "no frames
# sent" are the same reading, which is the failure mode recorded in memory
# ownership-harness-needs-foreign-object. Step 3 already proved this same
# injector delivers frames to this same guest a few seconds earlier, and that is
# what makes the zero here meaningful rather than vacuous.
if [ "$RX_POST" -le "$RX_PRE" ]; then
    fail_with "internal: step 3 should have caught this already" \
        "The injector is not proven to work, so step 5c's zero is vacuous."
fi

echo ""
echo "RESULT: PASS — restart AND give-up both proven"
echo "  [1-3] knetd killed, observed dead, restarted as PID $NEW_PID (was $DIED_PID),"
echo "        RX cpl0 $RX_PRE -> $RX_POST across the kill; gave-up 0 at that point."
echo "  [5]   8 back-to-back deaths exhausted the budget: gave-up $GU_GAVEUP, announced"
echo "        on the console, and RX stayed pinned at $RX_GU_PRE across a further"
echo "        injection -- the daemon stayed dead."
exit 0
