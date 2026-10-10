#!/usr/bin/env bash
#
# verify-pipe-fixes.sh — three pipe bugs, one boot.
#
# F1  SYS_PIPE leaked a redirected file. pipe_bind_stream() overwrote a stream
#     that owned a RAMFS ref without closing it; once the type is PIPE neither
#     the reset nor exit-time cleanup knows a file was there. Any process with
#     a redirected stdin/stdout that builds a pipeline (a `/shell.elf < script`)
#     leaked one slot per rebind, and 8 leaks used up the uid's RAMFS quota for
#     good -- every later open, and so every exec, failed until reboot.
#
# F3  The kernel shell's pipes are static and outlive their stage only until
#     pipe_destroy(). A ring-3 `exec` stage's `&` job inherits the stage's
#     stdout as a borrowed pointer to that static, and kept writing to a
#     destroyed pipe (freed wait queues) after the pipeline ended. Its output
#     was silently lost. Fix: pipe_detach_streams() points every task still
#     naming the pipe back at the console before it is destroyed.
#
# F2  The kernel shell drains a stage's output pipe only AFTER the stage
#     returns. A ring-3 `exec` stage that wrote more than PIPE_BUFFER_SIZE
#     blocked on the full pipe while the shell blocked waiting for it: the
#     shell hung for good. Fix: that pipe is a non-blocking capture pipe;
#     overflow is refused and reported in the truncation line.
#
# WHAT IS ASSERTED
#
#   F1  As an unprivileged user (fixed RAMFS quota): `fdprobe.elf count`
#       reports how many files the uid can still open. Run `fdprobe.elf
#       pipebind < in > out` twice -- each run rebinds both owned streams to a
#       pipe and back -- then count again. The two counts must be EQUAL.
#       Controls: the baseline count is > 0, and pipebind reports it really
#       created and bound a pipe.
#   F3  Root, kernel shell: `exec /fdprobe.elf orphan | cat`. The probe
#       spawns sleeper.elf -- which inherits the stage's capture pipe as its
#       stdout -- and exits without waiting. Control: "Sleeper started" (written
#       while the pipe was live) reaches the log through cat. Finding: the
#       sleeper's "Sleeper done", written ~6 s after the pipe was destroyed,
#       must reach the console.
#   F2  `exec /producer.elf 800 | cat` (~9 KB through a 4 KB pipe) must come
#       back with the truncation report. Last, because on an unfixed kernel it
#       hangs the shell for good.
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem (nothing proven).

set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=pipeuser
TESTPASS=pipepass1
ISO=dist/tinyos.iso
SERIAL=pipe-fixes.log
TRACE=pipe-fixes-trace.log
RUN_DISK=/tmp/tinyos-pipefixes-disk.img
MON_SOCK=/tmp/tinyos-pipefixes-mon.sock

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
# Session 2 (pipeuser):     F1.
# Session 3 (root):         kshell, F3, F2.
#
# The blank '!=>' lines are 1 s pauses: after the F3 pipeline, so the orphaned
# sleeper's "Sleeper done" (~6 s later) lands before F2 begins. pipebind's own
# "exited with status" goes into its redirected file, so its wait is on the
# PROBE line plus a pause before the next keystroke.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=300 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
!exit=>TinyOS login:;\
$TESTUSER=>assword;\
!$TESTPASS=>'help' for builtins;\
!=>\$;\
!echo pipein > /scratch/pin=>\$;\
!/fdprobe.elf count=>exited with status;\
!/fdprobe.elf pipebind < /scratch/pin > /scratch/pout=>PROBE pipebind;\
!=>;\
!/fdprobe.elf pipebind < /scratch/pin > /scratch/pout=>PROBE pipebind;\
!=>;\
!/fdprobe.elf count=>exited with status;\
!exit=>TinyOS login:;\
root=>assword;\
!$PASSWORD=>'help' for builtins;\
!=>\$;\
kshell=>Switching to the kernel shell;\
!=>;\
!=>;\
!exec /fdprobe.elf orphan | cat=>PROBE orphan;\
!=>;\
!=>;\
!=>;\
!=>;\
!=>;\
!=>;\
!=>;\
!=>;\
!=>;\
!=>;\
!=>;\
!=>;\
!exec /producer.elf 800 | cat=>output truncated" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup
trap - EXIT

echo ""
echo "================ VERDICT ================"

[ -s "$SERIAL" ] || guard_fail "no serial output at all (typist rc=$TYPIST_RC)"

FAILS=()
note_fail() { FAILS+=("$1"); }

# grep -c, not grep -q: under pipefail grep -q SIGPIPEs printf on an early
# match and the 141 reads as a miss (see verify-psvisibility.sh).
region_has() {
    local n
    n=$(printf '%s\n' "$1" | grep -c "$2")
    [ "$n" -gt 0 ]
}

LOGIN_LINES=$(grep -na "TinyOS login:" "$SERIAL" | cut -d: -f1)
NLOGIN=$(printf '%s\n' "$LOGIN_LINES" | grep -c .)
[ "$NLOGIN" -ge 3 ] || guard_fail "only $NLOGIN login prompts in the log (typist rc=$TYPIST_RC); never reached the root kshell session"
USER_START=$(printf '%s\n' "$LOGIN_LINES" | tail -2 | head -1)
LAST_LOGIN=$(printf '%s\n' "$LOGIN_LINES" | tail -1)
USER_REGION=$(sed -n "${USER_START},${LAST_LOGIN}p" "$SERIAL")
FINAL_REGION=$(tail -n +"$LAST_LOGIN" "$SERIAL")

# --- F1 ------------------------------------------------------------------
COUNTS=$(printf '%s\n' "$USER_REGION" | grep -ao 'PROBE count opened=[0-9]*' | sed 's/.*=//')
NCOUNTS=$(printf '%s\n' "$COUNTS" | grep -c .)
[ "$NCOUNTS" -eq 2 ] || guard_fail "F1: expected 2 count lines, saw $NCOUNTS"
BEFORE=$(printf '%s\n' "$COUNTS" | head -1)
AFTER=$(printf '%s\n' "$COUNTS" | tail -1)
[ "$BEFORE" -gt 0 ] || guard_fail "F1: baseline count is $BEFORE; $TESTUSER could open nothing to begin with"
BINDS=$(printf '%s\n' "$USER_REGION" | grep -ac 'PROBE pipebind id=1 bind=0')
[ "$BINDS" -eq 2 ] || guard_fail "F1: pipebind created+bound a pipe in $BINDS of 2 runs; the rebind never happened"
if [ "$AFTER" -ne "$BEFORE" ]; then
    note_fail "F1: $TESTUSER could open $BEFORE files before two pipebind runs and $AFTER after -- $((BEFORE - AFTER)) RAMFS slot(s) leaked by pipe_bind_stream"
fi

# --- F3 ------------------------------------------------------------------
region_has "$FINAL_REGION" "Switching to the kernel shell" || guard_fail "never reached the kernel shell"
region_has "$FINAL_REGION" "Sleeper started" || guard_fail \
    "F3: sleeper.elf never announced itself; its missing 'done' would prove nothing"
if ! region_has "$FINAL_REGION" "Sleeper done"; then
    note_fail "F3: the stage's orphaned child lost its output once the pipeline ended (\"Sleeper done\" never reached the console)"
fi

# --- F2 ------------------------------------------------------------------
if ! region_has "$FINAL_REGION" "stage 1 output truncated"; then
    note_fail "F2: 'exec /producer.elf 800 | cat' never came back with a truncation report -- the kernel shell hung on a full stage pipe (typist rc=$TYPIST_RC)"
fi

if grep -qa "KERNEL PANIC" "$SERIAL" 2>/dev/null; then
    note_fail "the kernel panicked during the run"
fi
if grep -qa "Triple fault\|triple fault" "$TRACE" 2>/dev/null; then
    note_fail "the kernel triple-faulted during the run"
fi

if [ "${#FAILS[@]}" -gt 0 ]; then
    echo "RESULT: FAIL — ${#FAILS[@]} assertion(s)"
    for f in "${FAILS[@]}"; do echo "  - $f"; done
    echo "  --- last 40 serial lines ---"
    tail -40 "$SERIAL"
    exit 1
fi

echo "RESULT: PASS"
echo "  - F1: $TESTUSER could open $BEFORE files before and after two pipe rebinds of owned streams"
echo "  - F3: the stage's orphaned child printed 'Sleeper done' after its pipe was gone"
echo "  - F2: an oversized exec stage was truncated and reported, not hung"
exit 0
