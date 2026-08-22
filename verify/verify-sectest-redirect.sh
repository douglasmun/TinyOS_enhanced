#!/usr/bin/env bash
#
# verify-sectest-redirect.sh — FULLY AUTOMATED check that the security test
# suite honours output redirection, INCLUDING the two functions it calls that
# live in other files.
#
# WHAT THIS IS FOR
#
# security_tests.c was the last console-only block in the tree: 161 kprintf
# call sites, so `sectest > report.txt` opened the file, printed the entire
# suite to the kernel console, and left an empty file behind. This is the same
# bug verify-sysredirect.sh measures for shell_system.c, one file later.
#
# WHY THIS HARNESS IS NOT JUST verify-sysredirect.sh WITH A DIFFERENT MARKER
#
# Because the suite is not self-contained. Two of the functions that produce
# its output are defined in OTHER files and have exactly one caller each:
#
#   scheduler_stats()        (scheduler.c) — 10 lines, called by TEST 3
#   arp_security_self_test() (net.c)       —  7 lines, called by TEST 9
#
# Converting only security_tests.c would produce a report that looks complete
# -- banner, nine test headers, nine verdicts -- while 17 lines of the actual
# evidence went to the console instead. Every one of those lines is a security
# RESULT, not decoration. A harness that asserted on the suite's own markers
# alone would pass on exactly that half-done state, so this one asserts on all
# three sources independently:
#
#   MARKER_SUITE  "SECURITY HARDENING TEST SUITE"      security_tests.c
#   MARKER_SCHED  "=== SCHEDULER STATISTICS ==="       scheduler.c
#   MARKER_ARP    "[ARP] Pending gateway reply"        net.c
#
# THE POSITIONAL ASSERTION (the load-bearing idea, inherited from
# verify-sysredirect.sh)
#
# On a serial log the console copy and the file copy of a line are BYTE
# IDENTICAL. "the marker appeared" is therefore true whether the fix works or
# not, and presence is not a usable assertion. What separates them is WHEN:
#
#   converted    -> console silent during `sectest > /s.txt`,
#                   text appears only after `cat /s.txt`   (marker AFTER cat)
#   unconverted  -> text appears the moment sectest runs   (marker BEFORE cat)
#
# So every check below is `first occurrence line number > the cat's line
# number`, and the BEFORE case is evaluated first and suppresses the rest: if
# a marker showed up early, anything appearing after the cat proves nothing
# about where it came from.
#
# WHY scheduler_stats() ALSO GOT RESTRUCTURED, AND WHY THAT IS NOT PARANOIA
#
# It printed seven of its ten lines from INSIDE CRITICAL_SECTION_ENTER/EXIT.
# That was survivable while the target was kprintf. It is not survivable for
# stream_printf, which on a redirected stream reaches ramfs_write -- that
# blocks and can take a mutex, and must not run with interrupts masked. The
# function now snapshots under the lock and prints after it (the env.c
# pattern). This harness exercises exactly that path: `sectest > /s.txt` is a
# REDIRECTED stream, so it is the ramfs_write case, not the console case. A
# hang or fault in TEST 3 is what a bad conversion looks like here.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.
# Logs: sectest-redirect.log (serial), sectest-redirect-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=sectest-redirect.log
TRACE=sectest-redirect-trace.log
RUN_DISK=/tmp/tinyos-sectestredir-disk.img
MON_SOCK=/tmp/tinyos-sectestredir-mon.sock

MARKER_SUITE="SECURITY HARDENING TEST SUITE"
MARKER_SCHED="=== SCHEDULER STATISTICS ==="
MARKER_ARP="\[ARP\] Pending gateway reply"

echo "==> Building kernel + ISO..."
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# --------------------------------------------------------------------------
# Staleness guards: prove the binary about to boot contains the conversion.
#
# `nm | grep stream_printf` is NOT usable -- stdio.c defines that symbol in
# every build ever made, converted or not, so it is a guard that cannot fail.
# Disassemble each converted function and require that IT calls stream_printf.
# On an unconverted or reverted function those sites read `call kprintf`,
# which is precisely the state this harness exists to detect.
#
# All three are checked because they are three separate files that can drift
# apart -- the whole reason the ARP/scheduler assertions exist below.
# --------------------------------------------------------------------------
guard_fn() {
    fn="$1"; want="$2"
    n=$(i686-elf-objdump -d kernel.elf --disassemble="$fn" 2>/dev/null \
        | grep -cE 'call .*<stream_printf>')
    if [ "${n:-0}" -lt "$want" ]; then
        echo "RESULT: INCONCLUSIVE — $fn makes ${n:-0} stream_printf call(s), expected >= $want."
        echo "  The build under test does not contain the conversion for this function;"
        echo "  booting it would measure the wrong kernel."
        i686-elf-objdump -d kernel.elf --disassemble="$fn" 2>/dev/null \
            | grep -E 'call .*<(kprintf|stream_printf)>' | head
        exit 2
    fi
    echo "==> Guard: $fn makes $n stream_printf call(s)"
}

guard_fn run_security_tests 10
guard_fn scheduler_stats 5
guard_fn arp_security_self_test 5

# scheduler_stats() must ALSO no longer print inside its critical section.
# The conversion is only safe because the prints moved out; if someone moves
# one back, this harness could still pass (the text does reach the file) right
# up until ramfs_write blocks with interrupts masked on a slower path. Assert
# the structure directly rather than hoping the runtime catches it.
#
# The check: in the disassembly of scheduler_stats, no call to stream_printf
# may appear between the cli and the popf/sti that bracket the snapshot. We
# approximate that cheaply -- and legibly -- at source level instead, since the
# function is small and the property is a source-level invariant.
sched_body=$(sed -n '/^void scheduler_stats/,/^}/p' src/scheduler.c)
if printf '%s\n' "$sched_body" \
   | awk '/CRITICAL_SECTION_ENTER/{inside=1} /CRITICAL_SECTION_EXIT/{inside=0} inside && /stream_printf/{found=1} END{exit !found}'; then
    echo "RESULT: INCONCLUSIVE — scheduler_stats() calls stream_printf INSIDE its"
    echo "  critical section. stream_printf can reach ramfs_write on a redirected"
    echo "  stream; that blocks and takes a mutex, and must not run with interrupts"
    echo "  masked. Snapshot under the lock and print after it (see env.c)."
    exit 2
fi
echo "==> Guard: scheduler_stats() prints only outside its critical section"

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

echo "==> Driving the boot flow (slow under TCG; sectest is long — be patient)..."
# `sectest > /s.txt` carries NO expect, deliberately. When the fix works the
# console stays silent, so giving it a marker as its own expect would make a
# CORRECT kernel time out -- silence is the property under test, not a hang.
# It does not need one: the typist echo-verifies every keystroke of the next
# command before sending it, so `cat` cannot be typed until the prompt has
# come back from sectest. Sequencing is already guaranteed.
#
# We run as root: sectest is require_root, and a refusal would produce an
# empty file that trivially "passes" the console-silence half while proving
# nothing about the suite.
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=" \
TINYOS_FOLLOWUP_CMDS="sectest > /s.txt;cat /s.txt=>$MARKER_SUITE" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup
trap - EXIT

echo
echo "================ VERDICT ================"

if grep -q "Triple fault" "$TRACE" 2>/dev/null; then
    echo "RESULT: FAIL — 'Triple fault' in $TRACE"
    echo "  If this landed in TEST 3, suspect scheduler_stats(): printing to a"
    echo "  redirected stream inside its critical section is the failure mode."
    grep -E "check_exception|v=0e|v=08|Triple fault|^EIP=|CR2=" "$TRACE" | tail -15
    exit 1
fi

cat_line=$(grep -n "cat /s.txt" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)

if [ -z "$cat_line" ]; then
    echo "RESULT: FAIL/INCONCLUSIVE — never saw the 'cat /s.txt' command echo"
    echo "  (typist rc=$TYPIST_RC) — the drive did not get far enough to measure."
    echo "--- tail of $SERIAL ---"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi

# NOTE the idiom. `grep -c ... || echo 0` is WRONG: grep already prints 0 on no
# match AND exits 1, so the variable becomes "0\n0" and the later comparison
# dies with "integer expression expected" -- on stderr, while the script keeps
# running and can still print PASS. Use bare grep. (Found for real in
# verify-ids-spray.sh; see its VALIDATION LOG.)
check_marker() {
    label="$1"; pat="$2"; origin="$3"
    first=$(grep -nE "$pat" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)

    if [ -z "$first" ]; then
        echo "RESULT: FAIL — $label never appeared at all."
        echo "  Expected it in the file dumped by the cat. Source: $origin"
        return 1
    fi

    # NEGATIVE HALF FIRST: before the cat means it came from the console.
    if [ "$first" -lt "$cat_line" ]; then
        echo "RESULT: FAIL — $label appeared at serial line $first, BEFORE the"
        echo "  cat at line $cat_line. That is the console copy: the command"
        echo "  printed as it ran instead of writing to the redirected stream,"
        echo "  so /s.txt got nothing. Unconverted source: $origin"
        return 1
    fi

    echo "  OK  $label — line $first (after cat at $cat_line) [$origin]"
    return 0
}

rc=0
check_marker "suite body"       "$MARKER_SUITE" "security_tests.c" || rc=1
check_marker "scheduler stats"  "$MARKER_SCHED" "scheduler.c:scheduler_stats" || rc=1
check_marker "ARP self-test"    "$MARKER_ARP"   "net.c:arp_security_self_test" || rc=1

if [ "$rc" -ne 0 ]; then
    echo
    echo "  Reminder: all three must land in the FILE. A conversion that does"
    echo "  security_tests.c alone leaves 17 lines of real security results on"
    echo "  the console while the report looks structurally complete."
    exit 1
fi

echo
echo "All three output sources reached the redirected file."
echo "RESULT: PASS"
exit 0

# =============================================================================
# VALIDATION LOG (2026-08-16)
#
# A harness is only worth its exit code if both outcomes have been observed.
# All runs below are real.
#
# 1. PASS, correct kernel. exit 0.
#      OK  suite body      — line 349 (after cat at 343) [security_tests.c]
#      OK  scheduler stats — line 407 (after cat at 343) [scheduler.c]
#      OK  ARP self-test   — line 507 (after cat at 343) [net.c]
#    The ARP marker landing at 507 matters beyond its own assertion: it is the
#    LAST thing the suite prints, so reaching it proves the whole run survived
#    a redirected (ramfs_write) stream -- including TEST 3, which is where the
#    restructured scheduler_stats() critical section would have hung or
#    faulted if the snapshot-then-print split had been done wrong.
#
# 2. FAIL, half-done conversion. exit 1.  <-- THE RUN THAT JUSTIFIES THE DESIGN
#    scheduler_stats() alone was reverted to kprintf (security_tests.c and
#    net.c left converted) -- i.e. the plausible mistake of converting the
#    file you were asked to convert and missing the two functions it calls
#    from elsewhere. Result:
#      OK    suite body      — line 360 (after cat at 354)
#      FAIL  scheduler stats — line 312, BEFORE the cat at 354
#      OK    ARP self-test   — line 507 (after cat at 354)
#    A harness asserting only on the suite's own marker would have printed
#    PASS here while 10 lines of scheduler evidence went to the console and
#    never reached the report. This is precisely why the two out-of-file
#    reporters get their own independent assertions.
#
#    Note the static guard caught this first (exit 2, "scheduler_stats makes 0
#    stream_printf call(s)") without spending a boot. The run above was
#    produced by lowering that guard on a scratch copy, because a guard firing
#    proves only that the GUARD works -- the runtime assertion is the harness's
#    actual claim and had to be shown to fail on its own.
#
# 3. The -Werror build itself refuses the reverted state: dropping the
#    stream_printf calls from scheduler_stats leaves `ctx` unused, which is
#    -Werror=unused-variable. Free defence in depth, but NOT a substitute for
#    the checks here -- it only fires when a function loses its LAST
#    stream_printf, and says nothing about the other two files.
#
# 4. The critical-section guard was validated both ways separately: clean on
#    the real source, and TRIPPED on a copy with one stream_printf injected
#    between CRITICAL_SECTION_ENTER and EXIT.
# =============================================================================
