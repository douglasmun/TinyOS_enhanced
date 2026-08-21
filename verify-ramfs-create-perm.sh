#!/bin/bash
# =============================================================================
# verify-ramfs-create-perm.sh -- creating a file honours the PARENT's write bit.
#
# WHAT THIS PROVES
#
# Creating a file is a WRITE to the parent directory. Every other ramfs
# mutation that links or unlinks a child runs the identical test against the
# parent -- mkdir, unlink, rmdir and rename all call ramfs_check_permission()
# on it -- and the create path in ramfs_open() did not. So any caller could
# plant a file inside a directory it has no write permission on: a uid-1000
# ring-3 task writing into a root-owned 0755 directory.
#
# The mode bits on that directory are only load-bearing BECAUSE the rest of
# the tree enforces them, which is what made this one exploitable rather than
# merely inconsistent -- the same shape as the ramfs_chmod ownership gap.
#
# WHERE THE CHECK LIVES, AND WHY THAT DECIDES THE HARNESS
#
# The check is in the ramfs PRIMITIVE, not in cmd_touch. That is deliberate:
# a check in the command would leave the primitive open to the next caller
# (SYS_OPEN with O_CREAT already is one). So this harness drives the primitive
# through more than one entry point -- a builtin AND a shell redirection --
# because a fix placed in one command would pass a harness that only used that
# command.
#
# THE TWO LEGS ARE OPPOSITE, AND BOTH ARE REQUIRED
#
#   leg 1  non-root creates in a ROOT-OWNED 0755 dir -> must be REFUSED
#   leg 2  the same user creates in their OWN dir    -> must SUCCEED
#
# Leg 2 is the positive control. A create path that refused EVERYTHING passes
# leg 1 perfectly while making the filesystem read-only for every non-root
# user, and a surface that only checks the refusal reports that as working.
# This is the same adjacent-opposite-legs shape as verify-ring3-chmod.sh.
#
# The refusal must also be EACCES, not ENOENT: collapsing it into "not found"
# would tell an unprivileged caller that a directory it may not write to does
# not exist, and would make the refusal branch unobservable from the shell.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: createperm.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=crperm
TESTPASS=crperm123

ISO=dist/tinyos.iso
SERIAL=createperm.log
TRACE=createperm-trace.log
RUN_DISK=/tmp/tinyos-createperm-disk.img
MON_SOCK=/tmp/tinyos-createperm-mon.sock

ROOTDIR=/rootonly
OWNDIR=/ownplace

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

# ---------------------------------------------------------------------------
# SOURCE GUARD
# ---------------------------------------------------------------------------
grep -q "RAMFS_CREATE_EPERM" src/ramfs.h \
    || guard_fail "src/ramfs.h has no RAMFS_CREATE_EPERM sentinel; tree predates
  the fix"
grep -q "ramfs_check_permission(parent, uid, gid, RAMFS_FLAG_WRITE)" src/ramfs.c \
    || guard_fail "src/ramfs.c's create path does not check the parent's write
  permission; tree predates the fix"
grep -q "RAMFS_CREATE_EPERM) {" src/ramfs_vfs.c \
    || guard_fail "ramfs_vfs.c does not map RAMFS_CREATE_EPERM onto VFS_EACCES,
  so the refusal would surface as 'not found' and read like dead code"

# Sentinel collision check -- the ramfs_chmod lesson. -1 is already ramfs's
# not-found, and -4 is its existing permission-denied for the node itself.
for bad in "(-1)" "(-4)"; do
    if grep -q "#define RAMFS_CREATE_EPERM $bad" src/ramfs.h; then
        guard_fail "RAMFS_CREATE_EPERM is $bad, which collides with an existing
  ramfs sentinel; the refusal would report the wrong condition"
    fi
done

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

echo "==> Launching headless QEMU"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!
cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# Sequence, all in the kernel shell (mkdir/chmod/touch are available there and
# `su` keeps one task, so the uid change is visible to ramfs immediately):
#
#   as root : create $ROOTDIR 0755, root-owned
#   as user : mkdir $OWNDIR -- there is no chown builtin, so the user makes
#             their own directory; alloc_node() stamps the creating uid, which
#             is what makes it theirs
#             touch into $ROOTDIR      -> leg 1, must be refused
#             redirect into $ROOTDIR   -> leg 1b, the OTHER entry point
#             touch into $OWNDIR       -> leg 2, must succeed
#             ls both                  -> the state, independent of messages
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
mkdir $ROOTDIR=>\$;\
chmod 755 $ROOTDIR=>\$;\
su $TESTUSER=>Now running as;\
!id=>uid=;\
mkdir $OWNDIR=>\$;\
touch $ROOTDIR/planted.txt=>\$;\
echo MARKREDIR > $ROOTDIR/redir.txt=>\$;\
touch $OWNDIR/mine.txt=>\$;\
ls $ROOTDIR=>\$;\
echo LSOWNDIR=>LSOWNDIR;\
ls $OWNDIR=>\$" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

CLEAN=/tmp/tinyos-createperm-clean.log
tr -d '\r' < "$SERIAL" | grep -va "EDR DAEMON\|Suspicious" > "$CLEAN"

if ! grep -q "LSOWNDIR" "$CLEAN"; then
    echo "RESULT: INCONCLUSIVE — the command sequence did not complete."
    tail -25 "$CLEAN"
    rm -f "$CLEAN"; exit 3
fi

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    echo "  --- tail ---"
    tail -30 "$CLEAN"
    rm -f "$CLEAN"; exit 1
}

# The listing of $ROOTDIR is everything after the last `ls $ROOTDIR`, up to the
# LSOWNDIR marker. Split on the marker rather than on the typed command: the
# kernel shell does not echo commands to serial, so anchoring on the command
# text finds only its own OUTPUT and puts the evidence on the wrong side of
# the split (the two-histories trap).
SPLIT=$(grep -n "LSOWNDIR" "$CLEAN" | tail -1 | cut -d: -f1)
ROOT_LISTING=$(sed -n "1,${SPLIT}p" "$CLEAN")
OWN_LISTING=$(sed -n "$((SPLIT+1)),\$p" "$CLEAN")

# --- Leg 1: the plant must NOT be there -----------------------------------
if printf '%s\n' "$ROOT_LISTING" | grep -q "planted.txt"; then
    fail_with "an unprivileged user created planted.txt in root-owned $ROOTDIR" \
        "Creating a file is a write to the parent directory. $ROOTDIR is" \
        "root-owned and 0755, so a uid-1000 caller has no write bit on it." \
        "Every other ramfs mutation checks this; the create path did not."
fi
echo "PASS leg 1: touch into a root-owned 0755 directory was refused."

# --- Leg 1b: the OTHER entry point ----------------------------------------
#
# Redirection reaches ramfs_open(O_CREAT) without going through cmd_touch. A
# fix placed in the command rather than the primitive passes leg 1 and fails
# here -- which is the whole reason the check lives in the primitive.
if printf '%s\n' "$ROOT_LISTING" | grep -q "redir.txt"; then
    fail_with "shell redirection created redir.txt in root-owned $ROOTDIR" \
        "touch was refused but redirection was not, so the check is in the" \
        "COMMAND rather than in ramfs's create path. The next caller --" \
        "SYS_OPEN with O_CREAT from ring 3 -- would bypass it the same way."
fi
echo "PASS leg 1b: redirection into the same directory was refused too."

# --- Leg 2: POSITIVE CONTROL ----------------------------------------------
# If $OWNDIR itself was never created, leg 2 is measuring the mkdir refusal
# (root owns /) and not the create path at all. Say so rather than reporting a
# fix failure -- misattributing a setup problem burns a debugging cycle on
# correct kernel code.
if printf '%s\n' "$OWN_LISTING" | grep -qi "No such file\|not found"; then
    echo "RESULT: INCONCLUSIVE — $OWNDIR does not exist, so the user's mkdir was"
    echo "  itself refused (root owns / and the user has no write bit there)."
    echo "  Leg 2 needs a directory the test user owns; give the user a writable"
    echo "  parent, or create $OWNDIR as root and chmod it 0777 before su."
    rm -f "$CLEAN"; exit 3
fi

if ! printf '%s\n' "$OWN_LISTING" | grep -q "mine.txt"; then
    fail_with "the user could not create a file in their OWN directory $OWNDIR" \
        "This is the positive control. Legs 1 and 1b pass identically against" \
        "a create path that refuses EVERY unprivileged create, which would" \
        "make the filesystem read-only for every non-root user while" \
        "reporting a working permission check."
fi
echo "PASS leg 2 (positive control): create in the user's own directory succeeded."

# --- Leg 3: the refusal says EACCES, not ENOENT ---------------------------
#
# Reported rather than asserted when the message is absent: the shell's
# wording is not part of the fix's contract, but a "No such file" for a
# directory that plainly exists is a real information-quality bug and worth
# surfacing.
if grep -qi "denied\|permission" "$CLEAN"; then
    echo "PASS leg 3: the refusal was reported as a permission error."
elif grep -qi "No such file" "$CLEAN"; then
    echo "WARN leg 3: the refusal surfaced as 'No such file or directory'."
    echo "  The refusal works, but ENOENT tells an unprivileged caller that a"
    echo "  directory it may not write to does not exist. Check the"
    echo "  RAMFS_CREATE_EPERM -> VFS_EACCES mapping in ramfs_vfs.c."
else
    echo "NOTE leg 3: no refusal message was printed (silent refusal)."
fi

rm -f "$CLEAN"
echo ""
echo "RESULT: PASS"
echo "  Refused via both touch and redirection in a root-owned directory,"
echo "  allowed in the user's own. The check is in the primitive, so the next"
echo "  caller inherits it."
exit 0
