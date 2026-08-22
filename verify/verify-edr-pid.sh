#!/usr/bin/env bash
#
# verify-edr-pid.sh -- the EDR daemon is found by pid, not guessed.
#
# The bug: kernel.c hardcoded `pid_edr = 3` with the comment "EDR daemon will
# be PID 3 since it's created third". PIDs are crypto-random in 100..65535
# (process.c:361), so 3 can NEVER be allocated. task_get(3) returned NULL on
# every boot that has ever run, and the CAP_UNKILLABLE grant guarded by it
# never executed once.
#
# What made it invisible for the lifetime of the feature: the grant was inside
# `if (edr_task_ptr)` with the kprintf INSIDE the same branch. A dead grant
# therefore prints nothing at all -- and an absent log line reads as a line
# that was never written, not as a failure. Leg 2 is the one that would have
# caught it: it asserts the line is PRESENT, not that no error appeared.
#
# No live hole existed: CAP_ALL (0xFFFFFFFF) already includes CAP_UNKILLABLE,
# so the daemon was unkillable regardless. That is exactly why this needs a
# harness -- the defect is invisible to any test that asks "can I kill it?"
set -u

# Paths below are relative to the repo root; this script lives in verify/.
cd "$(dirname "$0")/.." || exit 2

PASS=0; FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "== leg 1: no hardcoded pid guess in the source =="
if grep -qE 'pid_edr *= *[0-9]+ *;' src/kernel.c; then
    bad "kernel.c assigns pid_edr a literal again"
    grep -nE 'pid_edr *= *[0-9]+ *;' src/kernel.c | sed 's/^/       /'
else
    ok "pid_edr is not a literal"
fi
if grep -q 'int pid_edr = edr_daemon_start();' src/kernel.c; then
    ok "pid_edr comes from edr_daemon_start()'s return value"
else
    bad "pid_edr is no longer taken from edr_daemon_start()"
fi

echo "== leg 2: the EDR protection line is PRESENT at boot =="
# The load-bearing leg. Asserting presence, not absence-of-error, is the whole
# lesson: the dead branch printed nothing and nothing complained for years.
LOG=$(mktemp /tmp/edrpid.XXXXXX.log)
trap 'rm -f "$LOG"' EXIT
make -j8 kernel.elf >/dev/null 2>&1 || { echo "  build failed"; exit 1; }
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o dist/tinyos.iso iso >/dev/null 2>&1
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso -boot d \
    -m 256M -netdev user,id=net0 -device e1000,netdev=net0 \
    -serial file:"$LOG" -display none >/dev/null 2>&1 &
QP=$!; sleep 25; kill $QP 2>/dev/null; wait $QP 2>/dev/null
BOOT=$(tr -d '\r' < "$LOG")

if echo "$BOOT" | grep -q "EDR daemon already protected"; then
    ok "EDR daemon protection line present (the grant actually ran)"
else
    bad "EDR daemon protection line MISSING -- task_get() returned NULL again"
fi
if echo "$BOOT" | grep -q "WARNING: EDR daemon task not found"; then
    bad "kernel reports it could not find the EDR daemon task"
else
    ok "no 'EDR daemon task not found' warning"
fi

echo "== leg 2b: the daemon task actually RUNS =="
# Legs 1-4 all key on strings printed on the BOOT path, before
# scheduler_start(). task_create_kernel() allocates a task but does NOT
# enqueue it, and edr_daemon_start() never called scheduler_add_task() -- so
# the task was created, listed by `ps`, granted PRIORITY_HIGH and
# CAP_UNKILLABLE, and announced as "started successfully", while
# edr_daemon_main() never executed one instruction. Every leg above passes
# identically either way, which is what made this harness a false pass.
#
# This string is the FIRST statement inside edr_daemon_main(), so it can only
# appear if the task was scheduled. "Scan complete" is asserted too: reaching
# the loop body proves the daemon is not merely entered but running, and it is
# what makes the scans_performed counter on the secstatus line non-zero.
if echo "$BOOT" | grep -q "Starting EDR background daemon"; then
    ok "edr_daemon_main() entered (the task was actually scheduled)"
else
    bad "edr_daemon_main() never ran -- task created but never enqueued"
fi
if echo "$BOOT" | grep -q "\[EDR DAEMON\] Scan complete"; then
    ok "the daemon's scan loop is executing (scans_performed advances)"
else
    bad "daemon entered but never completed a scan -- its counters stay 0"
fi

echo "== leg 3: the daemon's real pid is in the allocatable range =="
# Proves 3 was never plausible, so the old code could not have worked.
EPID=$(echo "$BOOT" | grep -o "Created daemon process PID [0-9]*" | grep -o "[0-9]*$" | head -1)
if [ -n "$EPID" ] && [ "$EPID" -ge 100 ] 2>/dev/null; then
    ok "EDR daemon pid is $EPID (>=100; the hardcoded 3 was unreachable)"
else
    bad "could not read a plausible EDR pid (got '${EPID:-none}')"
fi

echo "== leg 4: all four protection lines print, and none overclaims =="
# "protected" implied this OR is what made the task safe; it is a no-op over
# CAP_ALL. The wording must not credit it.
MISSING=""
for t in "Shell" "Idle" "EDR daemon" "Supervisor"; do
    echo "$BOOT" | grep -q "$t already protected (CAP_UNKILLABLE via CAP_ALL)" || MISSING="$MISSING $t"
done
if [ -z "$MISSING" ]; then
    ok "all four tasks report 'already protected ... via CAP_ALL'"
else
    bad "missing or mis-worded protection line for:$MISSING"
fi
if grep -qE 'kprintf\("\[EDR DAEMON\] Process protection enabled' src/edr_daemon.c; then
    bad "edr_daemon.c announces its no-op self-grant as enabling protection"
else
    ok "the daemon's redundant self-grant is not announced as a security step"
fi

echo
echo "================ VERDICT ================"
echo "  passed: $PASS   failed: $FAIL"
if [ $FAIL -eq 0 ]; then
    echo "RESULT: PASS -- the EDR daemon is located by pid and its grant runs"; exit 0
else
    echo "RESULT: FAIL"; exit 1
fi
