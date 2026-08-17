#!/usr/bin/env bash
#
# verify-ring3-chmod.sh — FULLY AUTOMATED check that `chmod` works from the
# RING-3 shell via SYS_CHMOD (40), and that its OWNERSHIP rule holds there.
#
# WHAT THIS IS TESTING
#
# SYS_CHMOD is a thin carrier: it copies the path in, rejects non-RAM-disk
# drives, and hands the decision to ramfs_chmod(), where the ownership check
# has lived since PR #69. That placement is the point — CLAUDE.md's rule is
# "enforce permissions in the ramfs primitive, not the command", and this
# syscall is the second caller that rule was written to protect. So the
# interesting question is not "does the syscall exist" but "does a NEW caller
# inherit the refusal", which only a run can answer.
#
# THREE THINGS THAT MAKE A CHMOD HARNESS LIE
#
# 1. "DENIED" AND "ABSENT" ARE THE SAME STRING TO A GREP. Two revisions of
#    verify-chmod-owner.sh passed against a file that never existed. So every
#    refusal here is preceded by a POSITIVE CONTROL at the exact same path:
#    root chmods that file successfully first. If the positive control fails,
#    the file is missing and the refusal below proves nothing — scored
#    INCONCLUSIVE, never PASS.
#
# 2. AN "I CAN CHMOD MY OWN FILE" TEST PASSES AGAINST AN INERT FILTER. The
#    exclusion half needs a live FOREIGN object: a file owned by root that the
#    test user must be refused on. Both halves are measured, because they are
#    the two polarities of the same rule and a filter that refuses EVERYTHING
#    satisfies the first half alone.
#
# 3. A REFUSAL THAT PRINTS BUT DOES NOT REFUSE. "operation not permitted"
#    appearing on serial says the shell reported a refusal; it does not say
#    the mode bits survived. So after the refused chmod the harness re-reads
#    the mode with `stat` and requires it UNCHANGED. This is the assertion
#    that would catch a kernel that printed an error after mutating the node.
#
# HOW THE MODE IS OBSERVED — and why that matters
#
# From ring 3, via `stat`, which now prints `mode=NNN`. dirent_t has always
# carried the mode field and ramfs_vfs_stat has always filled it; cmd_stat
# simply discarded it. That is deliberate here: the observation crosses the
# SAME ring boundary as the mutation, so a chmod that only ever took effect
# in some kernel-side view cannot pass. Reading the mode back through
# `kshell`'s `ls -l` would have graded a different boundary.
#
# The mode is printed as three separate digits because userspace printf has
# no %o (the kernel's kprintf has the same gap — see the chmod-ownership-gap
# note). Nothing here should "fix" that by comparing decimal 420 to 644.
#
# ASSERTIONS
#
#   - `chmod` appears in the ring-3 shell's help          (it is a builtin)
#   - root's four stats read 600 644 600 644, IN ORDER    (POSITIVE CONTROL +
#                                                          non-vacuity: the
#                                                          value must ALTERNATE,
#                                                          leaving a known 644
#                                                          the user can stat)
#   - the unprivileged user is REFUSED on root's file     (the foreign object)
#   - and the mode is STILL 644 afterwards                (the refusal is real,
#                                                          not just printed)
#   - the unprivileged user SUCCEEDS on their OWN file    (ownership-gated, not
#                                                          root-only: a -EPERM
#                                                          HERE is the bug)
#   - no dispatcher rejection anywhere in the log         (MAX_SYSCALL_NUM)
#
# NOTE ON POLARITY. SYS_CHMOD is OWNERSHIP-gated, like SYS_TCPSOCK and unlike
# the euid-gated SYS_NETRX/SYS_NETTX. CLAUDE.md records that copying an
# assertion between two such halves has nearly inverted it three times. The
# two legs below are deliberately adjacent and deliberately opposite: leg 5
# requires a refusal, leg 7 requires a success, both as the SAME unprivileged
# user. Do not reconcile them.
#
# VALIDATED BOTH WAYS (2026-08-17): PASS as written. With ramfs_chmod's
# ownership check made inert (`if (0 && uid != 0 && uid != node->uid)` -- the
# `if (0 &&` form keeps a source-grep guard satisfied while removing the
# behaviour), it FAILS on leg 4, and the serial log shows the unprivileged
# `chmod 666 D:/cmroot.txt` executing with NO output at all where the fixed
# kernel prints a refusal. Expect that run to burn the full
# TINYOS_FOLLOWUP_TIMEOUT: the typist blocks on an expect that never arrives,
# which is itself the signal.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: ring3chmod.log (serial),
# ring3chmod-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

TESTUSER=cmuser
TESTPASS=cmpass1

# Root's file: the FOREIGN object the test user must be refused on.
ROOTFILE=D:/cmroot.txt
# The test user's own file: the half that must SUCCEED.
USERFILE=D:/cmuser.txt

ISO=dist/tinyos.iso
SERIAL=ring3chmod.log
TRACE=ring3chmod-trace.log
RUN_DISK=/tmp/tinyos-ring3chmod-disk.img
MON_SOCK=/tmp/tinyos-ring3chmod-mon.sock

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
# `strings | grep -q` is wrong under pipefail: grep -q exits at the first match,
# SIGPIPEs strings (141), and the guard fires on a FRESH ISO. grep -c consumes
# all input, so no SIGPIPE.
ISO_MARKERS=$(strings "$ISO" | grep -c "change permission bits")
if [ "$ISO_MARKERS" -eq 0 ]; then
    echo "RESULT: INCONCLUSIVE — the ISO does not contain the new ring-3 shell"
    echo "  The 'chmod' help line is absent, so the embedded shell.elf predates"
    echo "  this change and the run would report on the OLD shell."
    exit 3
fi

# And prove the KERNEL half is fresh too. The marker above only covers the
# embedded ring-3 shell, so a stale syscall.o passes it and the run then grades
# a kernel that predates the change. Restoring a header with `mv` from a .bak
# moves its mtime BACKWARDS and make skips the rebuild; `touch` cures it.
# Capture then match — `nm | grep -q` is the SIGPIPE trap described above.
NM_OUT="$(i686-elf-nm kernel.elf 2>/dev/null || true)"
case "$NM_OUT" in
  *sys_chmod*) : ;;
  *)
    echo "RESULT: INCONCLUSIVE — kernel.elf has no sys_chmod symbol"
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
# same one verify-ring3-ps.sh and verify-ring3-date.sh use, and for the same
# reason: logging out and back in reaches a ring-3 shell whose readline never
# receives keystrokes (a separate defect, recorded in doc/KERNEL_BUGS.md).
# kshell is only the vehicle for the su; every assertion is measured on ring-3
# output, which is the boundary SYS_CHMOD lives at.
#
# WHY ROOT LEAVES $ROOTFILE AT 644 rather than 600. The test user has to be
# able to `stat` it after the refusal, and ramfs_vfs_stat requires READ on the
# node — at 600 the post-refusal re-read would fail for lack of read
# permission and the leg could not distinguish "mode survived" from "cannot
# look". 644 is readable by other, un-writable by other, and not owned by the
# user: exactly the conditions the ownership check is about.
#
# Ring-3 commands are sent unverified ('!') because the ring-3 shell does not
# echo keystrokes to serial (the kernel echoes them in the keyboard IRQ, which
# reaches VGA only), so per-character echo checks pass on coincidental matches
# in kernel chatter. Each still carries an expect on its RESULT.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="help" \
TINYOS_EXPECT="change permission bits" \
TINYOS_FOLLOWUP_CMDS="\
!write $ROOTFILE rootowned;\
!stat $ROOTFILE=>mode=600;\
!chmod 644 $ROOTFILE;\
!stat $ROOTFILE=>mode=644;\
!chmod 600 $ROOTFILE;\
!stat $ROOTFILE=>mode=600;\
!chmod 644 $ROOTFILE;\
!stat $ROOTFILE=>mode=644;\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
kshell=>Switching to the kernel shell;\
su $TESTUSER=>Now running as;\
exec /shell.elf=>TinyOS shell (ring 3);\
!chmod 666 $ROOTFILE=>not permitted;\
!stat $ROOTFILE=>mode=;\
!write $USERFILE mine;\
!chmod 640 $USERFILE;\
!stat $USERFILE=>mode=640" \
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

inconclusive_with() {
    echo "RESULT: INCONCLUSIVE — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    exit 3
}

# Split the log at the su. Everything after it is the test user's session;
# everything before it is root's. Root's successes must NOT be allowed to
# satisfy the unprivileged legs, which is the whole reason for the split.
SU_LINE=$(grep -n "Now running as" "$SERIAL" | head -1 | cut -d: -f1)
if [ -z "$SU_LINE" ]; then
    inconclusive_with "never reached the unprivileged account (no 'Now running as')" \
        "The su step did not complete, so neither ownership leg was exercised."
fi

ROOT_REGION=$(head -n "$SU_LINE" "$SERIAL")
USER_REGION=$(tail -n +"$SU_LINE" "$SERIAL")

# ---------------------------------------------------------------------------
# Leg 1: SYS_CHMOD dispatched at all.
#
# TWO messages, both matched. The range check prints "Invalid syscall number N
# (max M)" — which is what a missed MAX_SYSCALL_NUM bump actually trips, and
# SYS_CHMOD is 40 against a previous bound of 39. The switch default prints
# "Unknown system call number N". A leg matching only the second reported 0
# and passed vacuously during the SYS_TIME negative control; don't repeat it.
# ---------------------------------------------------------------------------
REJECTED=$(grep -Ec "Invalid syscall number|Unknown system call" "$SERIAL")
if [ "$REJECTED" -ne 0 ]; then
    fail_with "the dispatcher rejected a syscall ($REJECTED occurrence(s))" \
        "MAX_SYSCALL_NUM must cover SYS_CHMOD (40), not stop at 39." \
        "Offending line(s):" \
        "$(grep -Em2 'Invalid syscall number|Unknown system call' "$SERIAL")"
fi

# ---------------------------------------------------------------------------
# Leg 2: `chmod` is advertised in the ring-3 shell's help.
# ---------------------------------------------------------------------------
HELP_HIT=$(grep -c "change permission bits" "$SERIAL")
if [ "$HELP_HIT" -lt 1 ]; then
    fail_with "\`chmod\` is missing from the ring-3 shell's help output"
fi

# ---------------------------------------------------------------------------
# Leg 3 (POSITIVE CONTROL + NON-VACUITY): root's chmod actually MOVED the mode,
# repeatedly, in both directions.
#
# Scored INCONCLUSIVE rather than FAIL when the file is missing: that is a
# broken harness, not a broken kernel, and the two must not print the same
# verdict.
# ---------------------------------------------------------------------------
if printf '%s\n' "$ROOT_REGION" | grep -q "No such file or directory"; then
    inconclusive_with "root's setup hit 'No such file or directory'" \
        "The positive control never had a file to operate on, so the" \
        "refusal legs below cannot distinguish a denial from an absence." \
        "Check that \`write $ROOTFILE\` succeeded; see $SERIAL."
fi

# The four stats in root's session must read, IN ORDER: 600 (as `write`
# created it), 644, 600, 644. Asserting the SEQUENCE rather than a set of
# counts is deliberate — the file already reads 600 before any chmod runs, so
# "a 600 appeared" is satisfied by a chmod that does nothing at all, and "a
# 644 appeared" would be satisfied by one that fires once and then sticks.
# Only the alternation proves each individual call took effect.
ROOT_SEQ=$(printf '%s\n' "$ROOT_REGION" | grep -oE "^$ROOTFILE  size=[0-9]+  mode=[0-7]{3}" \
    | grep -oE "[0-7]{3}$" | tr '\n' ' ')
case "$ROOT_SEQ" in
  "600 644 600 644 ") : ;;
  *)
    fail_with "root's chmod sequence did not alternate as expected" \
        "expected '600 644 600 644', got '$ROOT_SEQ'" \
        "The file is created 0600 by write(); the harness then chmods it to" \
        "644, back to 600, and to 644 again, statting after each. A chmod" \
        "that is a no-op reads '600 600 600 600'; one that fires once and" \
        "sticks reads '600 644 644 644'. This is the POSITIVE CONTROL —" \
        "without it every refusal below is unfalsifiable."
    ;;
esac

# ---------------------------------------------------------------------------
# Leg 4 (THE FOREIGN OBJECT): the unprivileged user is REFUSED on root's file.
#
# Anchored to chmod's own output line, not a bare "not permitted" grep — the
# log carries other refusals, and a bare match is satisfied by any one of them
# while chmod leaks. errstr() maps -EPERM (-1) to "operation not permitted";
# that mapping did not exist before this change (the default was "operation
# failed"), which is itself why the string is worth anchoring to.
# ---------------------------------------------------------------------------
DENIED=$(printf '%s\n' "$USER_REGION" | grep -cE "^chmod: .*: operation not permitted")
if [ "$DENIED" -lt 1 ]; then
    fail_with "the unprivileged user was NOT refused on root's file" \
        "Expected a line like 'chmod: $ROOTFILE: operation not permitted'." \
        "ramfs_chmod's ownership check (PR #69) must apply to SYS_CHMOD too —" \
        "that is the entire reason the check lives in the primitive rather" \
        "than in cmd_chmod. Its absence here means the new caller re-opened" \
        "the hole the check was written to close." \
        "User-region chmod output:" \
        "$(printf '%s\n' "$USER_REGION" | grep -E '^chmod:' | head -3)"
fi

# ---------------------------------------------------------------------------
# Leg 5 (THE REFUSAL IS REAL): the mode survived the refused chmod.
#
# A kernel that mutated the node and THEN returned -EPERM satisfies leg 4
# completely. Only re-reading the value catches it. The user asked for 666;
# the file must still read 644.
# ---------------------------------------------------------------------------
POST_DENY_MODE=$(printf '%s\n' "$USER_REGION" | grep -oE "^$ROOTFILE  size=[0-9]+  mode=[0-7]{3}" \
    | head -1 | grep -oE "mode=[0-7]{3}")
if [ -z "$POST_DENY_MODE" ]; then
    inconclusive_with "could not read root's file mode back after the refusal" \
        "Expected a stat line for $ROOTFILE in the unprivileged session." \
        "At 644 the test user has read permission, so ramfs_vfs_stat should" \
        "have allowed it; if the mode is not 644 the read itself may have been" \
        "refused, which this leg cannot distinguish from a survived mode." \
        "User-region stat output:" \
        "$(printf '%s\n' "$USER_REGION" | grep -E "^$ROOTFILE" | head -3)"
fi
if [ "$POST_DENY_MODE" != "mode=644" ]; then
    fail_with "the refused chmod CHANGED the mode anyway ($POST_DENY_MODE)" \
        "chmod printed a refusal and mutated the node regardless. The user" \
        "asked for 666; the file must still read 644. This is the failure" \
        "mode leg 4 alone cannot see."
fi

# ---------------------------------------------------------------------------
# Leg 6 (THE OPPOSITE POLARITY): the user SUCCEEDS on their OWN file.
#
# SYS_CHMOD is OWNERSHIP-gated, not root-only. An unprivileged -EPERM HERE is
# the bug — the same relationship SYS_TCPSOCK has, and the opposite of the
# euid-gated SYS_NETRX/SYS_NETTX. Without this leg a filter that refuses
# everything passes legs 4 and 5 perfectly.
#
# Note this also proves the deny in leg 4 was about OWNERSHIP and not about
# the caller's ring or euid: same user, same syscall, different owner, and
# only one of them is refused.
# ---------------------------------------------------------------------------
OWN_OK=$(printf '%s\n' "$USER_REGION" | grep -c "^$USERFILE  size=[0-9]*  mode=640")
if [ "$OWN_OK" -lt 1 ]; then
    fail_with "the unprivileged user could NOT chmod their OWN file" \
        "Expected '$USERFILE  size=N  mode=640' in the user's session." \
        "SYS_CHMOD is ownership-gated: the owner must succeed. A -EPERM here" \
        "is the regression, and it is the OPPOSITE polarity to leg 4 — do not" \
        "reconcile the two assertions." \
        "User-region output for that file:" \
        "$(printf '%s\n' "$USER_REGION" | grep -E "$USERFILE" | head -3)"
fi

echo "RESULT: PASS — ring-3 chmod works via SYS_CHMOD, ownership rule intact"
echo "  root chmod alternated      : $ROOT_SEQ(positive control)"
echo "  foreign file refused       : $DENIED chmod refusal(s) in the user session"
echo "  and the mode survived      : $POST_DENY_MODE (asked for 666)"
echo "  own file succeeded         : mode=640 (ownership-gated, not root-only)"
echo "  dispatcher rejections      : $REJECTED (must be 0)"
exit 0
