#!/usr/bin/env bash
#
# verify-chmod-owner.sh — ramfs_chmod() must refuse a non-root, non-owner caller.
#
# ramfs_chmod() masked setuid/sgid/sticky but had NO ownership check, and
# cmd_chmod (shell_fileops.c) did not check either. Every other ramfs mutation
# goes through ramfs_check_permission(); chmod was the one that did not. Any
# user who typed `kshell` could therefore `chmod 666` a root-owned 0600 file and
# read it -- and the mode bits are load-bearing precisely because permissions
# ARE otherwise enforced, so rewriting them at will defeats the whole scheme.
#
# Sequence: root creates a 0600 file AND proves it can read it back (the
# positive control), then drops to a normal user who tries to chmod and read it.
#
# Exit 0 = ownership enforced (chmod refused with EPERM)     <- the fix works
# Exit 1 = NOT enforced, escalation reproduced               <- the bug is back
# Exit 2 = inconclusive; the check was never reached, so nothing was proven
#
# See the VALIDATION LOG at the bottom before changing any string matched here.

set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
TESTUSER=chmoduser
TESTPASS=chmodpass1
# Use an unqualified absolute path, NOT a drive-qualified one.
#
# cmd_chmod runs its argument through resolve_path(), which has no drive-letter
# awareness: "D:/secret.txt" does not begin with '/', so it is treated as a
# RELATIVE path and the cwd is prepended, yielding "/D:/secret.txt" -- which
# never exists. `cat` goes through the VFS and resolves D: correctly, so the two
# commands disagree about what the same string means. A drive-qualified probe
# therefore shows chmod failing with "No such file or directory" no matter what
# the ownership check does, which looks like a refusal and is not one.
# (That resolve_path/VFS mismatch is a pre-existing chmod limitation, separate
# from the ownership bug this probe is about.)
SECRET="/secret.txt"
ISO=dist/tinyos.iso
SERIAL=chmod-owner.log
RUN_DISK=/tmp/tinyos-chmodowner-disk.img
MON_SOCK=/tmp/tinyos-chmodowner-mon.sock

# Source guard: fail loudly if the check under test is not present at all,
# rather than booting a kernel that cannot possibly pass.
grep -q "uid != 0 && uid != node->uid" src/ramfs.c || {
    echo "FAIL: ramfs_chmod's ownership check is missing from src/ramfs.c"
    exit 2
}

make >/dev/null 2>&1 || { echo "FAIL: build"; exit 2; }
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || { echo "FAIL: ISO"; exit 2; }

rm -f "$RUN_DISK" "$SERIAL" "$MON_SOCK"
dd if=/dev/zero of="$RUN_DISK" bs=1m count=128 status=none

qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -display none &
QEMU_PID=$!
cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# Root creates a 0600 secret, verifies it is private, makes a normal user, then
# `su`s to them. Everything after the `su` runs unprivileged.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
kshell=>Switching to the kernel shell;\
write $SECRET ROOTONLYDATA;\
chmod 600 $SECRET=>chmod:;\
cat $SECRET=>ROOTONLYDATA;\
su $TESTUSER=>Now running as;\
!id=>uid=;\
!cat $SECRET;\
!chmod 666 $SECRET;\
!cat $SECRET" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup
trap - EXIT

echo
# SPLICE the EDR burst out before reading anything. The burst lands mid-line
# and cuts at an ARBITRARY character, so no token of a line is guaranteed to
# survive contiguously -- measured here, at the kernel shell, which echoes per
# keystroke:
#
#     $ w[EDR DAEMON] Starting threat scan...
#     rite /secret.txt ROO[EDR DAEMON] Starting threat scan...
#     TONLYDATA
#
# Deleting the marked lines outright would discard "$ w" and "rite ... ROO"
# along with the noise; rejoining the surviving halves restores the line.
# Lines that START with the marker are pure noise and go whole.
REJOINED="${SERIAL}.rejoined"
tr -d '\r' < "$SERIAL" \
  | awk '/^\[EDR (DAEMON|ADVANCED)\]/ { next }
         /\[EDR (DAEMON|ADVANCED)\]/  { sub(/\[EDR (DAEMON|ADVANCED)\].*$/, "");
                                          buf = buf $0; next }
         { print buf $0; buf = "" }
         END { if (buf != "") print buf }' > "$REJOINED"

echo "================ RESULT ================"
echo "--- transcript from the su onward ---"
sed -n '/su '"$TESTUSER"'/,$p' "$REJOINED" | head -30
echo "-------------------------------------"

# The unprivileged chmod is the whole question. Look at what followed it.
# POSITIVE CONTROL first. Root must have been able to chmod and then read the
# file at this exact path. If root could not, the file is missing or on another
# drive, and every downstream "denied" below is meaningless -- a non-existent
# file refuses everyone equally. This check is what makes the probe able to
# fail honestly rather than pass by absence.
# Anchor the root block's OPEN on "Switching to the kernel shell", not on the
# `chmod 600` echo. That is kernel output on its own line; the echo is typed
# text the burst can tear, and a torn open anchor makes this slice come back
# EMPTY -- which reports INCONCLUSIVE against a kernel that did everything
# right. This harness did exactly that on four consecutive runs.
root_block=$(sed -n "/Switching to the kernel shell/,/su $TESTUSER/p" "$REJOINED")

if ! echo "$root_block" | grep -q "rw-------"; then
    echo "RESULT: INCONCLUSIVE — root's own 'chmod 600' did not succeed."
    echo "  The owner path is broken, or the file was never created."
    exit 2
fi
if ! echo "$root_block" | grep -q "ROOTONLYDATA"; then
    echo "RESULT: INCONCLUSIVE — root could not read $SECRET back."
    echo "  Without this the unprivileged denial below proves nothing:"
    echo "  a file that does not exist is 'denied' to everybody."
    exit 2
fi
echo "positive control OK: root created, chmod'd and read $SECRET"

# Anchor the slice on the `su`, NOT on the `chmod 666` echo.
#
# The EDR daemon's periodic burst lands mid-line and tears the command echo in
# two: the log reads `$ chmod` / three EDR lines / ` 666 /secret.txt`, so the
# pattern "chmod 666 " matches ZERO lines, the slice comes back empty, every
# branch below falls through, and the harness reports INCONCLUSIVE against a
# kernel that refused the chmod correctly. That is what it did until this fix.
#
# "Now running as: $TESTUSER" is safe to anchor on because it is kernel output
# on its own line rather than a typed echo, and because the root-side positive
# control completes entirely BEFORE the su -- so nothing it produced can leak
# into this window and satisfy the escalation checks.
after_chmod=$(sed -n "/Now running as: $TESTUSER/,\$p" "$REJOINED")

# The escalation itself: did the unprivileged user get the contents?
if echo "$after_chmod" | grep -q "ROOTONLYDATA"; then
    echo "RESULT: NOT ENFORCED — privilege escalation CONFIRMED"
    echo "  An unprivileged user chmod'd a root-owned 0600 file and read it."
    exit 1
fi

# Mode rewritten but read failed for some other reason: still the defect.
if echo "$after_chmod" | grep -qE "chmod: '.*' -> rw-rw-rw-"; then
    echo "RESULT: NOT ENFORCED — chmod succeeded for a non-owner"
    echo "  Mode bits were rewritten on a root-owned file."
    exit 1
fi

if echo "$after_chmod" | grep -q "Operation not permitted"; then
    echo "RESULT: ownership IS enforced — chmod refused a non-owner with EPERM"
    exit 0
fi

# Anything else -- including "No such file or directory" -- is NOT a pass.
# That message means the check under test was never reached.
echo "RESULT: INCONCLUSIVE (typist rc=$TYPIST_RC) — the non-root chmod neither"
echo "  succeeded nor returned EPERM; ramfs_chmod's check was likely not reached."
echo "  See $SERIAL"
exit 2

#=============================================================================
# VALIDATION LOG — what each real run proved
#=============================================================================
#
# This harness was built while fixing the bug, and every wording choice below
# came from a run that lied convincingly. Four runs, in order:
#
# RUN 1 (pre-fix, bare /secret.txt) — CONFIRMED the escalation:
#     $ id                     uid=1002(chmoduser)
#     $ cat /secret.txt        No such file or directory   <- 0600 denied, correct
#     $ chmod 666 /secret.txt  chmod: '/secret.txt' -> rw-rw-rw- (%o)
#     $ cat /secret.txt        ROOTONLYDATA                <- escalated
#   Note "(%o)": kprintf implements c s d i u x X p and %% but has NO 'o'
#   conversion, so the old "%03o" printed literally. Fixed separately.
#
# RUN 2 (post-fix) — read as a pass, was not one. chmod said "No such file or
#   directory". That is ramfs_chmod's -1, NOT the ownership refusal, so the
#   check had not been reached. Cause found in RUN 4's analysis below.
#
# RUN 3 (drive-qualified D:/secret.txt) — INCONCLUSIVE, and correctly so.
#   cmd_chmod runs its argument through resolve_path(), which has no drive
#   awareness: "D:/secret.txt" does not start with '/', so it is treated as
#   RELATIVE and the cwd is prepended -> "/D:/secret.txt", which never exists.
#   `cat` resolves D: through the VFS and succeeds. The two commands disagree
#   about the same string. Every chmod therefore failed with "No such file or
#   directory" regardless of ownership -- a refusal-shaped result that is not a
#   refusal. This is a pre-existing chmod limitation, separate from the bug.
#
# RUN 4 (post-fix, bare path) — the real defect in fix v1: the caller tested
#   `result == -1` BEFORE `result == -EPERM`, and EPERM is 1, so -EPERM IS -1.
#   The refusal was indistinguishable from "not found" and the EPERM branch was
#   dead code. Hence RAMFS_CHMOD_EPERM (-3). Final run:
#     positive control OK: root created, chmod'd and read /secret.txt
#     $ chmod 666 /secret.txt  Operation not permitted
#     $ cat /secret.txt        No such file or directory
#
# NEGATIVE CONTROL (required before trusting this harness): stub the check to
#   `if (0)`, rebuild, re-run. The harness must FAIL with the RUN 1 transcript.
#   Verified 2026-08-16 -- it does, printing "(666)" (confirming the %o fix too).
#
# WHY THE POSITIVE CONTROL EXISTS: root must create, chmod AND read the file at
# the same path before privileges are dropped. Without it, "denied" and "absent"
# are the same string, and RUNs 2 and 3 would both have scored as passes. A file
# that does not exist refuses everybody equally.
