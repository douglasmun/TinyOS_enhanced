#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-ring3-pipes.sh — FULLY AUTOMATED check of RING-3 PIPELINES (SYS_PIPE).
#
# Distinct from verify-pipes.sh, which drives the KERNEL shell. That pipeline is
# SEQUENTIAL: it runs a stage to completion, copies up to 4 KB out of the pipe,
# then starts the next stage. Fine there — its stages are function calls. Here
# the stages are PROCESSES that run at the same time, connected by a real
# blocking pipe, so PASS proves something the kernel-shell harness cannot:
# two ring-3 processes exchanging an unbounded stream with real backpressure.
#
# The syscall is deliberately NOT POSIX pipe(int fd[2]): the ends a shell needs
# to connect are stdin and stdout, and those are not in the fd table at all (the
# same reason SYS_REDIRECT is not dup2). So a pipe is named by an opaque ID, its
# buffer stays in kernel memory, and the shell binds an end to its OWN stream
# before each spawn — inheritance carries it to the child, exactly as it does
# for redirection.
#
# Each check is chosen so a plausible bug fails it:
#
#   - counter reports lines=N   — the data made the trip between two separate
#                                 ring-3 processes. Nothing else in userspace
#                                 reads fd 0 to EOF, so this is the only way the
#                                 read end is observable at all.
#
#   - N is the FULL count, and  — the decisive check. 800 lines is ~11 KB, far
#     bytes > PIPE_BUFFER_SIZE    more than the 4 KB PIPE_BUFFER_SIZE, so the
#                                 producer MUST fill the pipe, block, and be
#                                 woken by the consumer draining it. A
#                                 sequential implementation (like the kernel
#                                 shell's) would truncate at 4 KB; a broken
#                                 blocking path would deadlock and time out.
#                                 Asserting the exact count is what separates
#                                 "the pipe worked" from "some of it arrived".
#
#   - the run TERMINATES        — proof that PIPE_CLOSE_WRITE reached the pipe
#                                 after the producer was reaped. Without it the
#                                 consumer blocks forever on a drained pipe
#                                 (more data could always still arrive), so a
#                                 timeout here is itself the signal that the
#                                 close step regressed. Nothing in task teardown
#                                 does it: a dying child's inherited streams are
#                                 deliberately marked borrowed.
#
#   - the producer's lines do   — the NEGATIVE. If the shell ignored the pipe
#     NOT reach the console       and simply ran both stages normally, every
#                                 "pipe-line N" would be printed. The whole
#                                 point is that they go to the consumer instead,
#                                 so the console must show the COUNT and not the
#                                 data. A harness with only positive checks
#                                 would pass on a shell that piped nothing.
#
#   - builtin stage is REFUSED  — `echo hi | counter.elf` must be rejected with
#                                 a reason, not mis-run. A builtin executes
#                                 inside the shell process, which cannot also be
#                                 the other stage; silently running one half
#                                 would look like a hang or lose the data.
#
#   - the shell survives it     — after a pipeline the shell's own stdin and
#                                 stdout must be back on the console. If RESTORE
#                                 were missed, the next readline would consume
#                                 the pipe instead of the keyboard and the
#                                 session would wedge. The trailing `id` proves
#                                 the prompt still works.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: ring3-pipes.log (serial),
# ring3-pipes-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=ring3-pipes.log
TRACE=ring3-pipes-trace.log
RUN_DISK=/tmp/tinyos-ring3-pipes-disk.img
MON_SOCK=/tmp/tinyos-ring3-pipes-mon.sock

# Must match the producer.elf invocation below and PIPE_BUFFER_SIZE in
# src/shell_redir.h. 800 lines of "pipe-line N\n" is ~11 KB, so it cannot fit
# in one 4 KB buffer — that is the entire point of the number.
LINES=800
# The producer prints LINES numbered lines and then one "producer: done", so the
# consumer must see LINES+1. Asserting the exact total (not ">= LINES") is what
# catches a pipe that dropped the tail after the last wrap.
EXPECT_LINES=$((LINES + 1))

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

echo "==> Driving the boot flow (slow under TCG; be patient)..."
# The pipeline is the FIRST command deliberately, not a follow-up: it spawns TWO
# processes, each needing ECDSA signature verification and a full address-space
# build, and then moves ~11 KB between them a page at a time under TCG. The
# typist gives the first command's expect 240s and follow-ups only 120s, and
# this is the one command that can plausibly need the longer window.
#
# The `id` at the end is a BARRIER as much as a check — it only echoes if the
# shell got its own streams back after the pipeline, which is the RESTORE path.
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_EXEC_CMD="pwd" \
TINYOS_EXPECT="D:/" \
TINYOS_FOLLOWUP_CMDS="\
/producer.elf $LINES | /counter.elf=>counter: lines=;\
echo hi | /counter.elf=>pipelines connect;\
id=>uid=" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

# The 60-second EDR status report tears whatever line is in flight, at an
# ARBITRARY character, so any witness can be split in two and stop matching.
# Every read below is a POSITION comparison, and a torn witness reports as
# absent -- i.e. as a kernel that never produced it. The tear is PROBABILISTIC
# (it only bites when the burst lands on that particular line), so a green run
# does NOT show the raw read is safe; it shows the burst missed this time.
# Analyse the REJOINED copy. See verify/edr-rejoin.sh (cases: edr-rejoin-test.sh).
REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: FAIL — no serial output at all (typist rc=$TYPIST_RC)"
    exit 2
fi

# The consumer's report. This single line carries both halves of the proof: that
# the data arrived, and how much of it.
report=$(grep -o "counter: lines=[0-9]* bytes=[0-9]*" "$REJOINED" | head -1)
got_lines=$(echo "$report" | sed -n 's/.*lines=\([0-9]*\).*/\1/p')
got_bytes=$(echo "$report" | sed -n 's/.*bytes=\([0-9]*\).*/\1/p')

# The refusal for a builtin stage, and the still-alive console after it all.
l_refusal=$(grep -c "pipelines connect two programs" "$REJOINED" 2>/dev/null)
l_id=$(grep -c "uid=" "$REJOINED" 2>/dev/null)

if [ -z "$report" ]; then
    echo "RESULT: FAIL/INCONCLUSIVE (typist rc=$TYPIST_RC)"
    echo "  counter.elf never reported. Either no data reached it, or it is"
    echo "  still blocked on a pipe whose write end was never closed."
    echo "  refusal=$l_refusal id=$l_id"
    echo "--- tail of $SERIAL ---"
    grep -v "Suspicious" "$REJOINED" | tail -40
    exit 2
fi

# THE decisive assertion. A sequential/buffered pipeline truncates at
# PIPE_BUFFER_SIZE; a partly-broken blocking path loses data at the wrap. Only
# the exact count proves the producer blocked and resumed rather than giving up.
if [ "$got_lines" != "$EXPECT_LINES" ]; then
    echo "RESULT: FAIL — pipe did not carry the whole stream"
    echo "  counter saw $got_lines lines, expected $EXPECT_LINES ($got_bytes bytes)"
    if [ -n "$got_lines" ] && [ "$got_lines" -lt "$EXPECT_LINES" ]; then
        echo "  Short by $((EXPECT_LINES - got_lines)) lines. ~4 KB of data would be"
        echo "  about 290 lines, so a stop near there means the pipe truncated"
        echo "  at PIPE_BUFFER_SIZE instead of blocking the producer."
    fi
    grep -v "Suspicious" "$REJOINED" | tail -30
    exit 2
fi

if [ "$got_bytes" -le 4096 ]; then
    echo "RESULT: FAIL — the stream fit inside one pipe buffer ($got_bytes bytes)"
    echo "  This test is only meaningful above PIPE_BUFFER_SIZE (4096); at or"
    echo "  below it a sequential implementation would pass too. Raise LINES."
    exit 2
fi

# The NEGATIVE: the piped data must not also have gone to the console. The
# producer's own "producer: done" is checked separately below, so grep for the
# numbered lines specifically.
n_console=$(grep -c "pipe-line [0-9]" "$REJOINED" 2>/dev/null)
if [ "$n_console" -gt 0 ]; then
    echo "RESULT: FAIL — piped data reached the console ($n_console lines)"
    echo "  The producer's stdout was not bound to the pipe, so the shell ran"
    echo "  the two stages as ordinary commands instead of connecting them."
    grep "pipe-line" "$REJOINED" | head -5
    exit 2
fi

if [ "$l_refusal" -lt 1 ]; then
    echo "RESULT: FAIL — a builtin pipeline stage was not refused"
    echo "  'echo hi | /counter.elf' must be rejected with a reason: a builtin"
    echo "  runs inside the shell process, which cannot also be the other stage."
    grep -v "Suspicious" "$REJOINED" | tail -20
    exit 2
fi

if [ "$l_id" -lt 1 ]; then
    echo "RESULT: FAIL — the shell did not return to a working console"
    echo "  Nothing echoed after the pipeline, so the shell's own stdin/stdout"
    echo "  were probably left bound to the pipe (missing PIPE_RESTORE)."
    grep -v "Suspicious" "$REJOINED" | tail -20
    exit 2
fi

if grep -q "Triple fault\|PANIC\|triple fault" "$REJOINED" 2>/dev/null; then
    echo "RESULT: FAIL — kernel panic/triple fault during the run"
    grep -n "Triple fault\|PANIC\|triple fault" "$REJOINED" | head -5
    exit 2
fi

echo "RESULT: PASS — two ring-3 processes exchanged $got_bytes bytes" \
     "($got_lines lines) through a real pipe, more than PIPE_BUFFER_SIZE, so" \
     "the producer blocked and resumed; a builtin stage was refused; the" \
     "console was restored"
grep -E "counter: lines=|pipelines connect|uid=" "$REJOINED" | head -10
exit 0
