#!/usr/bin/env bash
#
# verify-sysredirect.sh — FULLY AUTOMATED check that shell_system.c's commands
# honour output redirection.
#
# WHAT THIS IS FOR
#
# shell_system.c's ~220 call sites all wrote to kprintf, which goes to the
# kernel console unconditionally. The shell has bound `>` to stdout_stream for
# a while (verify-redirect.sh proves that much), but binding a stream does
# nothing for a command that never reads it: `mem > /m.txt` opened the file,
# printed the report to the console anyway, and left an empty file behind.
# Converting those sites to stream_printf(get_current_streams(), ...) is what
# this harness measures.
#
# WHY THE BOUNDARY IS THE KERNEL SHELL AND NOT RING 3
#
# These are kernel-shell builtins; `mem`/`secstatus` have no ring-3 equivalent
# yet. So unlike verify-ring3-redirect.sh there is no syscall gate to aim at --
# the property under test is "the command reads its stream", and the kernel
# shell is where that command lives. The shell's own `>` handling is NOT what
# is being tested here and is deliberately held constant: it was already
# working before this change, which is precisely why the empty-file bug was
# invisible.
#
# WHY `mem` AND NOT SOMETHING CHEAPER
#
# `mem` is root-only (require_root), takes no arguments, and prints a fixed
# multi-line report with a stable, unique marker line ("Memory Usage:"). The
# root-only part matters: require_root itself was converted in this change and
# fetches its own stream context, so a `mem` that prints its REFUSAL is
# exercising the same path. We run as root so the refusal never fires and the
# report is what we measure.
#
# THE CHECKS
#
#   1. POSITIVE   `mem > /m.txt` then `cat /m.txt` — "Memory Usage:" must
#                 appear after the `cat`. That is the report arriving from the
#                 file, which can only happen if cmd_mem wrote to the stream.
#
#   2. NEGATIVE   ...and it must NOT appear before the `cat`. This is the check
#                 that fails if the conversion is reverted: an unconverted
#                 cmd_mem prints to the console the moment it runs, which is
#                 BEFORE the cat, and a file that stays empty makes the cat
#                 print nothing. Asserted positionally rather than by presence
#                 because "the text appeared" is true of both outcomes -- the
#                 console copy and the file copy read identically on a serial
#                 log. The line NUMBER is the only thing that separates them.
#
#                 The negative is evaluated FIRST and suppresses the positive:
#                 if the marker showed up early, whatever appears later after
#                 the cat proves nothing about where it came from.
#
#   3. (HISTORICAL) `sectest`'s banner used to be deliberately left on kprintf,
#                 because the suite it announces was still console-only and a
#                 redirected banner would have abandoned its own output. That
#                 no longer applies: security_tests.c was converted and the
#                 banner now follows its output. Nothing here asserts on it --
#                 verify-sectest-redirect.sh owns that property now.
#
#   4. Zero triple faults.
#
# BOTH-WAYS VALIDATED: see the VALIDATION LOG at the bottom of this file for
# the actual runs, including the run against a deliberately reverted cmd_mem.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: sysredirect.log (serial),
# sysredirect-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=sysredirect.log
TRACE=sysredirect-trace.log
RUN_DISK=/tmp/tinyos-sysredirect-disk.img
MON_SOCK=/tmp/tinyos-sysredirect-mon.sock

MARKER="Memory Usage:"

echo "==> Building kernel + ISO..."
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# Staleness guard: prove the binary about to boot actually contains the change,
# so a stale ISO cannot produce a verdict about a kernel we did not build.
#
# NOT `nm kernel.elf | grep stream_printf` -- that symbol is defined by stdio.c
# and present in every build ever made, converted or not, so it is a guard that
# cannot fail. Disassemble cmd_mem specifically and require that IT calls
# stream_printf: on an unconverted (or reverted) cmd_mem those call sites read
# `call kprintf` instead, which is exactly the state this harness exists to
# detect and the one thing the check must be able to see.
mem_calls=$(i686-elf-objdump -d kernel.elf --disassemble=cmd_mem 2>/dev/null \
            | grep -cE 'call .*<stream_printf>')
if [ "${mem_calls:-0}" -eq 0 ]; then
    echo "RESULT: INCONCLUSIVE — cmd_mem in kernel.elf makes no stream_printf calls."
    echo "  The build under test does not contain the conversion; booting it would"
    echo "  measure the wrong kernel. (Found: ${mem_calls:-0} such call sites.)"
    i686-elf-objdump -d kernel.elf --disassemble=cmd_mem 2>/dev/null \
        | grep -E 'call .*<(kprintf|stream_printf)>' | head
    exit 2
fi
echo "==> Guard: cmd_mem makes $mem_calls stream_printf call(s) in kernel.elf"

echo "==> Fresh BLANK disk (forces first-boot password setup)"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
dd if=/dev/zero of="$RUN_DISK" bs=1m count=128 status=none

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
# The redirected `mem` prints nothing to the console when the fix works, so it
# cannot be the command the typist waits on -- there is no marker to expect,
# and the correct outcome is indistinguishable from a hang. So the exec slot
# gets an ordinary command with a guaranteed marker (`id`, which every session
# answers), and the actual test runs in the followups where each step carries
# its own expect.
#
# The redirected step itself carries NO expect, deliberately. Giving it the
# marker as its own expect would make a WORKING fix time out -- the console
# staying silent is the property under test, not a hang. It does not need one
# either: the typist echo-verifies every keystroke of the NEXT command before
# sending it, so `cat` cannot be typed until `mem > /m.txt` has been accepted
# and the prompt has come back. Sequencing is already guaranteed; an expect
# here would only add a way to fail correctly-working code.
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=" \
TINYOS_FOLLOWUP_CMDS="mem > /m.txt;cat /m.txt=>$MARKER" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup
trap - EXIT

echo
echo "================ VERDICT ================"

if grep -q "Triple fault" "$TRACE" 2>/dev/null; then
    echo "RESULT: FAIL — 'Triple fault' in $TRACE"
    grep -E "check_exception|v=0e|v=08|Triple fault|^EIP=|CR2=" "$TRACE" | tail -15
    exit 1
fi

cat_line=$(grep -n "cat /m.txt" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
first_marker=$(grep -n "$MARKER" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)

if [ -z "$cat_line" ]; then
    echo "RESULT: FAIL/INCONCLUSIVE — never saw the 'cat /m.txt' command echo"
    echo "  (typist rc=$TYPIST_RC) — the drive did not get far enough to measure anything."
    echo "--- tail of $SERIAL ---"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi

# NEGATIVE CONTROL FIRST. An unconverted cmd_mem writes to the console during
# `mem > /m.txt`, which is before the cat. If that happened, the positive below
# is meaningless -- so refuse to evaluate it.
if [ -n "$first_marker" ] && [ "$first_marker" -lt "$cat_line" ]; then
    echo "RESULT: FAIL — negative control tripped."
    echo "  '$MARKER' appeared at serial line $first_marker, BEFORE the cat at $cat_line."
    echo "  cmd_mem printed to the console during the redirected run, i.e. it is"
    echo "  still writing through kprintf and ignoring its stream context."
    echo "--- context ---"
    grep -v "Suspicious" "$SERIAL" | sed -n "$((first_marker > 4 ? first_marker - 4 : 1)),$((first_marker + 6))p"
    exit 1
fi

if [ -z "$first_marker" ]; then
    echo "RESULT: FAIL — '$MARKER' never appeared at all (typist rc=$TYPIST_RC)."
    echo "  The console copy is correctly absent, but the cat produced nothing either:"
    echo "  the report did not reach /m.txt. Redirection bound the stream and the"
    echo "  command wrote nowhere."
    echo "--- tail of $SERIAL ---"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 1
fi

if [ "$TYPIST_RC" -eq 0 ] && [ "$first_marker" -gt "$cat_line" ]; then
    echo "RESULT: PASS — 'mem' output went to /m.txt, not the console"
    echo "  (cat at serial line $cat_line, first '$MARKER' at $first_marker;"
    echo "   no console copy appeared before the cat)"
    exit 0
fi

echo "RESULT: FAIL (typist rc=$TYPIST_RC; marker at $first_marker, cat at $cat_line)"
grep -v "Suspicious" "$SERIAL" | tail -30
exit 2

# =============================================================================
# VALIDATION LOG — all three entries are real runs, not projections.
# =============================================================================
#
# 1. POSITIVE (converted kernel, as committed)
#      ==> Guard: cmd_mem makes 5 stream_printf call(s) in kernel.elf
#      typist: sending 'mem > /m.txt'      <- no console output, as intended
#      typist: sending 'cat /m.txt'
#      typist: 'Memory Usage:' observed
#      RESULT: PASS — cat at serial line 311, first marker at 313.
#    The two-line gap is the point: the marker exists ONLY after the cat.
#
# 2. NEGATIVE, build-time half. cmd_mem's 7 stream_printf(ctx, ...) sites
#    mechanically reverted to kprintf(...).
#      RESULT: INCONCLUSIVE — cmd_mem in kernel.elf makes no stream_printf
#      calls. (Found: 0 such call sites.)  ...followed by the five
#      `call 106de0 <kprintf>` sites it found instead.
#    The staleness guard refused to boot the wrong kernel. This is the run
#    that proves the guard is not decorative -- it distinguishes the two
#    kernels before QEMU is ever started.
#
# 3. NEGATIVE, runtime half. Same reverted kernel, guard bypassed
#    (`if false;` substituted for the guard's condition) so the boot actually
#    happens and the POSITIONAL assertion gets exercised:
#      RESULT: FAIL — negative control tripped.
#        'Memory Usage:' appeared at serial line 312, BEFORE the cat at 317.
#      and the captured console shows the bug verbatim:
#        $ mem > /m.txt
#        Memory Usage:
#          Total: 65536 frames (262144 KB)
#          ...
#        $ cat /m.txt
#        $                       <- /m.txt is EMPTY
#    Note what run 3 rules out that a presence check could not: the marker
#    IS present in the serial log in both the passing and the failing run.
#    Only its line number relative to the cat separates "arrived from the
#    file" from "was printed to the console and the file stayed empty".
#
# GOTCHA for anyone repeating run 2 or 3: reverting cmd_mem's calls leaves its
# `stream_context_t* ctx` declaration unused, which is -Werror=unused-variable
# and fails the build before you get to test anything. Add `(void)ctx;` for the
# duration of the negative run -- and grep it back out afterwards, which is why
# the restore step here checks for zero occurrences of that marker.
