#!/usr/bin/env bash
#
# verify-waiter-generation.sh -- mutex waiter handoff and ready-queue insertion
# are safe against PID reuse and double-enqueue. Source-level, no guest.
#
# THE BUGS (both found in the 2026-10 memory/scheduler audit)
#
# 1. mutex_unlock() resolved the first waiter by a BARE pid:
#
#        uint32_t waiter_pid = mutex->waiters[0];
#        task_t* waiter = task_get(waiter_pid);        /* wrong */
#        if (waiter) { mutex->owner_pid = waiter_pid; ... }
#
#    PIDs are drawn at random over ~65k values (process.c) and the allocator's
#    collision check SKIPS TASK_STATE_TERMINATED slots, so a waiter that was
#    killed (e.g. by EDR) but not yet reaped can have its PID handed to an
#    unrelated NEW task. task_get(pid) returns the first non-TERMINATED match --
#    that new task -- and unlock transfers mutex ownership to it and wakes it.
#    ramfs_mutex is taken on nearly every ring-3 file syscall, so multi-waiter
#    queues are trivial to create from ring 3. The window is probabilistic
#    (~1/65k), so this is a mutual-exclusion/corruption bug, not a steerable
#    primitive -- but it is exactly the raw-pid/recycling anti-pattern the tree
#    already fixed everywhere else with task_get_validated(pid, generation).
#
#    FIX: store the generation alongside the pid (mutex_t::waiter_gens[],
#    stamped in mutex_lock) and resolve with task_get_validated() in unlock.
#
# 2. scheduler_add_task() unconditionally overwrote task->next with no check
#    that the task was already in the circular ready queue. A double insert
#    breaks the ring and surfaces LATER as a panic in
#    scheduler_remove_task_locked()'s cycle guard. No live double-enqueue
#    caller exists today (scheduler_tick is dead code; the IRQ wake scan runs
#    interrupts-off), so this is defence-in-depth on the queue's single
#    mutator rather than a currently-reachable crash.
#
#    FIX: walk the bounded ring and return early if the task is already linked.
#
# WHY SOURCE-LEVEL. Bug 1 needs a ~1/65k PID collision AND a killed-but-unreaped
# waiter AND a new task in the same window; there is no deterministic way to
# drive it from a booted guest, and no fault-injection hook for it. The property
# the fix changed -- "the waiter is re-found by (pid, generation), not pid" --
# is checked directly at the source, against both the buggy and the fixed shape
# so it cannot pass vacuously against a reverted file. Each leg carries a
# negative control: the OLD form must be ABSENT and the NEW form must be PRESENT.
set -u

cd "$(dirname "$0")/.." || exit 2

PASS=0; FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "=== verify-waiter-generation.sh ==="
echo

echo "== leg 1: mutex waiter handoff resolves by (pid, generation) =="

# 1a. The parallel generation array exists in the struct.
if grep -qE 'waiter_gens\[MUTEX_MAX_WAITERS\]' src/mutex.h; then
    ok "mutex_t carries waiter_gens[] paired with waiters[]"
else
    bad "mutex_t has no waiter_gens[] -- the generation is not stored"
fi

# 1b. mutex_lock stamps the current task's generation when it enqueues.
if grep -qE 'waiter_gens\[mutex->num_waiters\] *= *current->generation' src/mutex.c; then
    ok "mutex_lock stamps current->generation alongside the pid"
else
    bad "mutex_lock does not record the waiter's generation on enqueue"
fi

# 1c. NEGATIVE CONTROL: the waiter must NOT be resolved with a bare task_get.
#     The pre-fix bug was `task_get(waiter_pid)`; the owner-side
#     `task_get(mutex->owner_pid)` on the priority-inheritance path is unrelated
#     and legitimate. Scope the control to the waiter resolution only, excluding
#     comment lines (leading '*' or '/').
if grep -nE '^[^*/]*task_get\(waiter' src/mutex.c | grep -vq 'task_get_validated('; then
    bad "mutex.c resolves a waiter with bare task_get() -- the PID-reuse hazard"
    grep -nE '^[^*/]*task_get\(waiter' src/mutex.c | grep -v 'task_get_validated(' | sed 's/^/       /'
else
    ok "no bare task_get(waiter...) remains -- the waiter is validated"
fi

# 1d. unlock resolves the waiter through task_get_validated with the stored gen.
if grep -qE 'task_get_validated\(waiter_pid, *waiter_gen\)' src/mutex.c; then
    ok "mutex_unlock resolves the waiter via task_get_validated(pid, gen)"
else
    bad "mutex_unlock does not use task_get_validated(waiter_pid, waiter_gen)"
fi

# 1e. the shift loop moves BOTH arrays in lockstep (else gens desync from pids).
if grep -qE 'waiter_gens\[i\] *= *mutex->waiter_gens\[i *\+ *1\]' src/mutex.c; then
    ok "the FIFO shift moves waiters[] and waiter_gens[] together"
else
    bad "the shift loop does not keep waiter_gens[] in step with waiters[]"
fi

echo
echo "== leg 2: scheduler_add_task refuses a double enqueue =="

# 2a. The idempotence guard walks the ring and returns early on a hit. Checked
#     structurally: an early `return` guarded by a `scan == task` test inside
#     scheduler_add_task, before the relink.
add_task_body="$(awk '/^void scheduler_add_task\(/{f=1} f{print} f&&/^}/{exit}' src/scheduler.c)"
if printf '%s\n' "$add_task_body" | grep -qE 'scan *== *task' \
   && printf '%s\n' "$add_task_body" | grep -qE 'already queued'; then
    ok "scheduler_add_task scans for an already-linked task and bails"
else
    bad "scheduler_add_task has no already-queued guard before the relink"
fi

# 2b. NEGATIVE CONTROL: the guard must sit BEFORE the first 'task->next =' write,
#     or it protects nothing. Compare line numbers within the function.
guard_line=$(printf '%s\n' "$add_task_body" | grep -nE 'scan *== *task' | head -1 | cut -d: -f1)
relink_line=$(printf '%s\n' "$add_task_body" | grep -nE 'task->next *=' | head -1 | cut -d: -f1)
if [ -n "$guard_line" ] && [ -n "$relink_line" ] && [ "$guard_line" -lt "$relink_line" ]; then
    ok "the guard precedes the first task->next write (line $guard_line < $relink_line)"
else
    bad "the guard does not precede the relink (guard=$guard_line relink=$relink_line)"
fi

echo
echo "================ VERDICT ================"
echo "  passed: $PASS   failed: $FAIL"
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: PASS -- mutex waiter handoff is generation-validated and"
    echo "  scheduler_add_task is idempotent against a double enqueue."
    exit 0
else
    echo "RESULT: FAIL"
    exit 1
fi
