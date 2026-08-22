#!/usr/bin/env bash
#
# verify-ring3-date.sh — FULLY AUTOMATED check that `date` works from the
# RING-3 shell via SYS_TIME (39), for an UNPRIVILEGED user.
#
# WHAT THIS IS TESTING
#
# SYS_TIME carries the wall clock and uptime across the ring boundary. Printing
# a date is the easy part; three properties are worth a harness.
#
# 1. THE CLOCK MUST ADVANCE. This is the load-bearing assertion, and the reason
#    the harness reads the clock TWICE with work in between. "date prints
#    something date-shaped" is satisfied by a stub returning a fixed string, by
#    a zeroed struct, and by a copy_to_user that silently wrote nothing into a
#    buffer the shell had already initialised. All three would sail through a
#    presence check. Two readings that DIFFER prove the value came from the
#    kernel's clock and crossed the boundary intact.
#
#    Uptime is the field compared, not wall time: it is monotonic, starts at a
#    known 0, and ticks every second, whereas the RTC's seconds field could
#    legitimately read the same twice if both samples land in one second.
#
# 2. IT MUST WORK UNPRIVILEGED. SYS_TIME is deliberately ungated -- the clock is
#    not a secret. The polarity trap that CLAUDE.md records for
#    SYS_NETSTAT/SYS_TCPSOCK applies in reverse here: for THIS syscall a -EPERM
#    is the bug, not the pass. An `-ENOSYS`/`-EPERM` regression would leave the
#    root path working and only break for real users, so the measurement is
#    taken as an unprivileged account.
#
# 3. MAX_SYSCALL_NUM MUST COVER IT. SYS_TIME is 39 and the bound was 38. If the
#    bump were missed, the dispatcher's range check rejects the call BEFORE
#    dispatch and `date` fails with -ENOSYS while every other syscall keeps
#    working -- exactly the bug that silently disabled SYS_SLEEP and
#    SYS_WAITPID for as long as it went unnoticed (see CLAUDE.md). Assertion 1
#    catches this, since a rejected call prints an error rather than a clock.
#
# WHY NOT COMPARE AGAINST THE KERNEL SHELL'S date
#
# Tempting, and wrong: both shells would be reading the same RTC through the
# same time_get_datetime(), so agreement proves the RTC works, not that
# SYS_TIME does. The kernel shell never calls the syscall. The ring-3 reading
# has to stand on its own.
#
# ASSERTIONS
#
#   - ring-3 `date` prints a well-formed timestamp for root  (control: the call
#     returns at all; if this fails everything below is vacuous)
#   - `date` appears in the ring-3 shell's help              (it is a builtin)
#   - ring-3 `date` works for an UNPRIVILEGED user           (the ungating)
#   - it prints an Uptime: line                              (the second field)
#   - the uptime ADVANCES between two readings          (THE non-vacuity check)
#   - no dispatcher rejection anywhere in the log       (MAX_SYSCALL_NUM bound)
#
# VALIDATED BOTH WAYS (2026-08-17): PASS as written; with MAX_SYSCALL_NUM put
# back to 38 it FAILS on leg 1, with the serial log showing "Invalid syscall
# number 39 (max 38)" and "date: not supported". That run is also what exposed
# leg 2 matching the wrong string -- see the note there.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: ring3date.log (serial),
# ring3date-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

TESTUSER=dtuser
TESTPASS=dtpass1

ISO=dist/tinyos.iso
SERIAL=ring3date.log
TRACE=ring3date-trace.log
RUN_DISK=/tmp/tinyos-ring3date-disk.img
MON_SOCK=/tmp/tinyos-ring3date-mon.sock

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1

# The embedded shell must match userspace/shell.c, or this harness tests the
# PREVIOUS shell and reports on code that is not being changed.
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1

make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# Prove the ISO carries THIS build. grub-mkrescue runs after the link, so
# mtimes look plausible even when the payload is stale.
# NOTE: `strings | grep -q` is wrong under `set -o pipefail` -- grep -q exits at
# the first match, SIGPIPEs `strings` (141), and the guard fires on a FRESH ISO.
# grep -c consumes all input, so no SIGPIPE.
ISO_MARKERS=$(strings "$ISO" | grep -c "print the date, time and uptime")
if [ "$ISO_MARKERS" -eq 0 ]; then
    echo "RESULT: INCONCLUSIVE — the ISO does not contain the new ring-3 shell"
    echo "  The 'date' help line is absent, so the embedded shell.elf predates"
    echo "  this change and the run would report on the OLD shell."
    exit 3
fi

# And prove the KERNEL half is fresh too. The marker above only covers the
# embedded ring-3 shell, so a stale syscall.o passes it and the run then grades
# a kernel that predates the change.
#
# This is not hypothetical: restoring src/syscall.h with `mv` from a .bak
# during the negative control put the OLD mtime back, make saw nothing newer
# than syscall.o, and the "restored" run failed identically to the sabotaged
# one. Two minutes of a real fix looking like no fix at all. `touch` on the
# header cures it; this guard catches it.
# Capture first, then match. `nm | grep -q` is the SIGPIPE trap this file
# warns about for `strings` above: grep -q exits at the first match, SIGPIPEs
# nm (141), and pipefail turns a SUCCESSFUL find into a failed pipeline.
NM_OUT="$(i686-elf-nm kernel.elf 2>/dev/null || true)"
case "$NM_OUT" in
  *sys_time*) : ;;
  *)
    echo "RESULT: INCONCLUSIVE — kernel.elf has no sys_time symbol"
    echo "  The kernel half of this change is not in the binary under test."
    echo "  If you just restored a header from a .bak with mv, its mtime went"
    echo "  backwards and make skipped the rebuild: touch src/syscall.h."
    exit 3
    ;;
esac

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

# Route to the unprivileged account is kshell -> su -> `exec /shell.elf`, the
# same one verify-ring3-ps.sh uses and for the same reason: logging out and
# back in reaches a ring-3 shell whose readline never receives keystrokes (a
# separate defect, recorded in doc/KERNEL_BUGS.md). kshell is only the vehicle
# for the su; every assertion is measured on ring-3 output.
#
# THE GAP BETWEEN THE TWO READINGS. `top` sits between them purely to spend
# wall-clock time -- it is a real command doing real work, and under TCG the
# sequence takes well over a second, so the uptime counter is guaranteed to
# have ticked. A `sleep` builtin would be more direct but the ring-3 shell
# does not have one.
#
# Ring-3 commands are sent unverified ('!') because the ring-3 shell does not
# echo keystrokes to serial (the kernel echoes them in the keyboard IRQ, which
# reaches VGA only), so per-character echo checks pass on coincidental matches
# in kernel chatter. Each still carries an expect on its RESULT, which is the
# stronger check.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="date" \
TINYOS_EXPECT="Uptime:" \
TINYOS_FOLLOWUP_CMDS="\
!help=>print the date, time and uptime;\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
kshell=>Switching to the kernel shell;\
su $TESTUSER=>Now running as;\
exec /shell.elf=>TinyOS shell (ring 3);\
!date=>Uptime:;\
!top=>Tasks:;\
!date=>Uptime:" \
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
    exit 1
}

# ---------------------------------------------------------------------------
# Leg 1 (CONTROL): the ring-3 shell printed a timestamp at all.
#
# Matches the format cmd_date emits: "Dow Mon DD HH:MM:SS YYYY". A stub that
# printed nothing, or a syscall rejected before dispatch, fails here and makes
# every leg below vacuous -- so this runs first.
#
# The {2} on the time fields is load-bearing beyond shape-checking: it also
# pins the '0' flag in userspace/libc.c's printf, which did not exist until
# this change (a leading 0 was being consumed as a width digit, so "%02d"
# printed " 3" for 3). Relaxing these to [ 0-9] to "make the test less
# brittle" would let that regression back in unnoticed. The DAY field is
# genuinely space-padded -- cmd_date uses %2d there, matching `date(1)`.
# ---------------------------------------------------------------------------
DATE_LINES=$(grep -cE "^(Sun|Mon|Tue|Wed|Thu|Fri|Sat) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}" "$SERIAL")
if [ "$DATE_LINES" -lt 1 ]; then
    fail_with "ring-3 \`date\` never printed a well-formed timestamp" \
        "Expected a line like 'Mon Aug 17 09:14:22 2026'." \
        "Nothing matched, so SYS_TIME either never dispatched or returned an error." \
        "See $SERIAL."
fi

# ---------------------------------------------------------------------------
# Leg 2: SYS_TIME dispatched.
#
# TWO DIFFERENT MESSAGES, and matching only one is a real gap -- found by the
# negative control, not by reading the code:
#
#   "Invalid syscall number N (max M)"  -- the RANGE CHECK (syscall.c:2884),
#       which is what a missed MAX_SYSCALL_NUM bump actually trips. This is
#       the failure mode this leg exists for.
#   "Unknown system call number N"      -- the switch DEFAULT (syscall.c:3285),
#       reached when the number is in range but has no case.
#
# The first draft of this leg grepped only for "Unknown system call", so under
# the negative control it reported 0 occurrences and passed while `date` was
# printing "not supported" one line below. Leg 1 caught the regression anyway,
# but a leg that cannot fail for its own stated reason is not doing any work.
# ---------------------------------------------------------------------------
REJECTED=$(grep -Ec "Invalid syscall number|Unknown system call" "$SERIAL")
if [ "$REJECTED" -ne 0 ]; then
    fail_with "the dispatcher rejected a syscall ($REJECTED occurrence(s))" \
        "Either the range check refused the number before dispatch --" \
        "MAX_SYSCALL_NUM must cover SYS_TIME (39), not stop at 38 -- or the" \
        "switch has no case for it. This is the bug that silently disabled" \
        "SYS_SLEEP and SYS_WAITPID for as long as it went unnoticed." \
        "Offending line(s):" \
        "$(grep -Em2 'Invalid syscall number|Unknown system call' "$SERIAL")"
fi

# ---------------------------------------------------------------------------
# Leg 3: `date` is advertised in the ring-3 shell's help.
# ---------------------------------------------------------------------------
HELP_HIT=$(grep -c "print the date, time and uptime" "$SERIAL")
if [ "$HELP_HIT" -lt 1 ]; then
    fail_with "\`date\` is missing from the ring-3 shell's help output"
fi

# ---------------------------------------------------------------------------
# Leg 4 (THE UNGATING): the unprivileged half.
#
# Everything after "Now running as" is the test user's session. SYS_TIME is
# deliberately ungated, so a -EPERM here is the bug -- the opposite polarity to
# the euid-gated raw-frame syscalls. Root's readings above cannot satisfy this
# leg because the region is measured after the su.
# ---------------------------------------------------------------------------
SU_LINE=$(grep -n "Now running as" "$SERIAL" | head -1 | cut -d: -f1)
if [ -z "$SU_LINE" ]; then
    fail_with "never reached the unprivileged account (no 'Now running as')" \
        "The su step did not complete, so the ungating was never exercised."
fi

USER_REGION=$(tail -n +"$SU_LINE" "$SERIAL")

USER_DATES=$(printf '%s\n' "$USER_REGION" \
    | grep -cE "^(Sun|Mon|Tue|Wed|Thu|Fri|Sat) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}")
if [ "$USER_DATES" -lt 2 ]; then
    fail_with "unprivileged \`date\` did not produce two readings (got $USER_DATES)" \
        "SYS_TIME is ungated on purpose: every user may read the clock." \
        "A -EPERM/-ENOSYS here is the regression -- note this is the OPPOSITE" \
        "polarity to SYS_NETRX/SYS_NETTX, which are euid-gated."
fi

# ---------------------------------------------------------------------------
# Leg 5 (NON-VACUITY): the uptime ADVANCED between the two readings.
#
# This is the assertion the whole harness exists for. A hardcoded string, a
# zeroed struct, or a copy_to_user that wrote nothing all print a plausible
# clock; only a real one moves. Uptime rather than wall-clock seconds because
# it is monotonic from a known 0 and cannot legitimately repeat.
#
# Both readings come from the unprivileged region, so this doubles as proof
# that the UNGATED path returns live data rather than a stale buffer.
# ---------------------------------------------------------------------------
uptime_secs() {
    # "Uptime: 3 days, 01:02:03" / "Uptime: 01:02:03" -> total seconds.
    printf '%s\n' "$USER_REGION" | grep -oE "^Uptime: ([0-9]+ days?, )?[0-9]{2}:[0-9]{2}:[0-9]{2}" \
        | sed -n "${1}p" \
        | awk '{
            d = 0; t = $NF;
            if (NF == 4) { d = $2 }
            split(t, p, ":");
            print d*86400 + p[1]*3600 + p[2]*60 + p[3];
          }'
}

UP1=$(uptime_secs 1)
UP2=$(uptime_secs 2)

if [ -z "$UP1" ] || [ -z "$UP2" ]; then
    fail_with "could not parse two Uptime: lines from the unprivileged session" \
        "got first='$UP1' second='$UP2'" \
        "cmd_date prints 'Uptime: [N days, ]HH:MM:SS'; if that format changed," \
        "update uptime_secs() here to match."
fi

if [ "$UP2" -le "$UP1" ]; then
    fail_with "the clock did not advance between readings ($UP1 -> $UP2)" \
        "Two identical or decreasing readings mean SYS_TIME is not returning" \
        "live data: a fixed string, a zeroed struct, or a copy_to_user that" \
        "wrote nothing would all look correct in every other leg." \
        "NOTE: time_get_datetime() had a non-monotonic bug once before (uint8" \
        "truncation of elapsed seconds, src/time.c) -- a DECREASE points there."
fi

echo "RESULT: PASS — ring-3 date works via SYS_TIME"
echo "  timestamps printed        : $DATE_LINES (>=2 unprivileged: $USER_DATES)"
echo "  uptime advanced           : ${UP1}s -> ${UP2}s (+$((UP2 - UP1))s)"
echo "  dispatcher rejections     : $REJECTED (must be 0)"
echo "  help advertises date      : yes"
exit 0
