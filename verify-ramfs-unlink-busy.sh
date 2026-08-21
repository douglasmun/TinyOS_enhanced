#!/bin/bash
# =============================================================================
# verify-ramfs-unlink-busy.sh -- unlinking an OPEN ramfs file is refused.
#
# WHAT THIS PROVES
#
# free_node() releases the ramfs_node_t frame and all of its data pages back
# to the PMM immediately. There is no refcount, and neither ramfs_read nor
# ramfs_write revalidates its cached node pointer -- both check only in_use
# and the flag bits, and the stale pointer is non-NULL. So unlinking a node
# out from under an open descriptor turned every later write through that fd
# into a write of caller-chosen bytes into memory the allocator had already
# handed to something else. No privilege is required: open(), unlink() and
# write() are all ungated ring-3 syscalls, so any user program could do it.
#
# WHY THIS HARNESS SHIPS A PROBE BINARY
#
# No shell builtin holds a descriptor open across an `rm` -- cmd_path_op opens
# nothing, and every builtin that opens a file closes it before returning. So
# nothing in the tree drives the conflicting case, and a shell-driven harness
# would grade an unlink with no descriptor to conflict with: it would pass
# IDENTICALLY against the unfixed kernel. /busyprobe.elf exists to be that
# driver. This is the third instance of the "no driver, so the sites rot"
# condition, after SYS_MSEAL's sixteen kprintfs and the syscall dispatcher's
# three.
#
# WHY THE WITNESS IS THE ERRNO, NOT `ls`
#
# Both a refused unlink and a successful one leave a filesystem you can
# describe; on the unfixed kernel the file is gone and everything LOOKS
# consistent -- the damage is to a PMM frame elsewhere, which no shell command
# reports. `ls` cannot see the difference, exactly as `cat` could not witness
# O_TRUNC. So each leg asserts on the raw return value the probe prints.
#
# THE LEGS ARE OPPOSITE ON PURPOSE
#
#   leg 1  unlink while open   -> must be REFUSED (-16, VFS_EBUSY)
#   leg 2  unlink after close  -> must SUCCEED (0)      [POSITIVE CONTROL]
#   leg 3  reopen after unlink -> must FAIL (file gone) [the unlink was real]
#
# Leg 2 is not optional. A vfs_unlink() that refused EVERY unlink satisfies
# leg 1 perfectly while breaking `rm` for the whole system, and a surface that
# only checks the refusal reports that as a working mechanism.
#
# Runs as a NON-ROOT user: the use-after-free needed no privilege, so the
# refusal must not depend on one either. (An ownership-gated syscall would
# invert this assertion -- see the gating-polarity note in CLAUDE.md.)
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: unlinkbusy.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=busyuser
TESTPASS=busypass1

ISO=dist/tinyos.iso
SERIAL=unlinkbusy.log
TRACE=unlinkbusy-trace.log
RUN_DISK=/tmp/tinyos-unlinkbusy-disk.img
MON_SOCK=/tmp/tinyos-unlinkbusy-mon.sock

EXP_BUSY=-16          # VFS_EBUSY, src/vfs.h:184, passed through verbatim

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

# ---------------------------------------------------------------------------
# SOURCE GUARD
# ---------------------------------------------------------------------------
grep -q "ramfs_node_is_busy" src/ramfs.c \
    || guard_fail "src/ramfs.c has no ramfs_node_is_busy(); tree predates the fix"
grep -q "RAMFS_BUSY" src/ramfs.h \
    || guard_fail "src/ramfs.h has no RAMFS_BUSY sentinel; tree predates the fix"
grep -q "case RAMFS_BUSY: return VFS_EBUSY" src/ramfs_vfs.c \
    || guard_fail "ramfs_vfs.c does not map RAMFS_BUSY onto VFS_EBUSY, so the
  refusal never reaches ring 3 as a distinguishable errno"

# The sentinel must not collide with an existing return value. This is the
# ramfs_chmod lesson: -EPERM is -1, which was already 'file not found', so the
# refusal printed the wrong message and the new branch was dead code while the
# kernel behaved correctly the whole time.
if grep -q "#define RAMFS_BUSY *-1$" src/ramfs.h; then
    guard_fail "RAMFS_BUSY is -1, which collides with ramfs's not-found sentinel"
fi

[ -f userspace/busyprobe.c ] \
    || guard_fail "userspace/busyprobe.c is missing; nothing would hold a
  descriptor open across the unlink and the harness would grade a no-op"
grep -q "busyprobe_elf_data" src/kernel.c \
    || guard_fail "src/kernel.c does not install /busyprobe.elf into ramfs"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
for prog in shell busyprobe; do
    python3 tools/sign_elf.py userspace/$prog.elf >/dev/null 2>&1 || exit 1
done
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
python3 tools/elf_to_c.py userspace/busyprobe.elf.signed \
        src/busyprobe_elf_data.c src/busyprobe_elf_data.h busyprobe_elf_data >/dev/null || exit 1
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# Prove the ISO carries the probe, not just that the source exists.
if [ "$(strings "$ISO" | grep -c 'PROBE open-unlink')" -eq 0 ]; then
    guard_fail "the ISO does not contain busyprobe's output strings, so the
  probe is not actually on the image and every leg would read nothing"
fi

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

# Non-root, because the use-after-free needed no privilege. `su` keeps this in
# the kernel shell, which is where exec of an absolute path is available.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
su $TESTUSER=>Now running as;\
!id=>uid=;\
exec /busyprobe.elf=>PROBE done" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

if ! grep -qa "PROBE done" "$SERIAL"; then
    echo "RESULT: INCONCLUSIVE — /busyprobe.elf did not run to completion."
    echo "  Every leg below would be measuring nothing."
    grep -a "PROBE" "$SERIAL"
    exit 3
fi

probe_rc() {
    grep -a "PROBE $1 rc=" "$SERIAL" | tail -1 \
        | sed -n 's/.*rc=\(-\{0,1\}[0-9][0-9]*\).*/\1/p'
}
OPEN_UNLINK=$(probe_rc "open-unlink")
POST_WRITE=$(probe_rc "post-write")
CLOSED_UNLINK=$(probe_rc "closed-unlink")
REOPEN=$(probe_rc "reopen")

echo "  unlink while open : rc=${OPEN_UNLINK:-none}  (expected $EXP_BUSY)"
echo "  write after that  : rc=${POST_WRITE:-none}   (reported, not asserted)"
echo "  unlink after close: rc=${CLOSED_UNLINK:-none} (expected 0)"
echo "  reopen after that : rc=${REOPEN:-none}       (expected < 0)"

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    grep -a "PROBE" "$SERIAL"
    exit 1
}

[ -n "$OPEN_UNLINK" ] || fail_with "the probe never reported the open-unlink leg"

# --- Leg 1: the refusal ---------------------------------------------------
if [ "$OPEN_UNLINK" -ne "$EXP_BUSY" ]; then
    if [ "$OPEN_UNLINK" -eq 0 ]; then
        fail_with "unlink of an OPEN file SUCCEEDED (rc=0)" \
            "This is the use-after-free itself: free_node() has released the" \
            "node frame and its data pages, the probe still holds an fd whose" \
            "cached node pointer is now stale, and the following write lands" \
            "in whatever the PMM handed that frame to next. Reachable from" \
            "ring 3 with no privilege."
    fi
    fail_with "unlink of an open file returned $OPEN_UNLINK, expected $EXP_BUSY" \
        "The unlink was refused, but not with VFS_EBUSY. Check for a sentinel" \
        "collision: a refusal that returns a value another branch already uses" \
        "reports the wrong condition to the caller while behaving correctly," \
        "which is how the ramfs_chmod -EPERM/-1 collision stayed hidden."
fi
echo "PASS leg 1: unlink of an open file refused with VFS_EBUSY ($EXP_BUSY)."

# --- Leg 2: POSITIVE CONTROL ----------------------------------------------
[ -n "$CLOSED_UNLINK" ] || fail_with "the probe never reported the closed-unlink leg"
if [ "$CLOSED_UNLINK" -ne 0 ]; then
    fail_with "unlink after close returned $CLOSED_UNLINK, expected 0" \
        "This is the positive control. Leg 1 passes perfectly against a" \
        "vfs_unlink() that refuses EVERY unlink -- which would break rm for" \
        "the entire system while reporting a working busy check. The refusal" \
        "must apply to open files ONLY."
fi
echo "PASS leg 2 (positive control): unlink after close succeeded."

# --- Leg 3: the unlink was real -------------------------------------------
[ -n "$REOPEN" ] || fail_with "the probe never reported the reopen leg"
if [ "$REOPEN" -ge 0 ]; then
    fail_with "the file reopened successfully (rc=$REOPEN) after being unlinked" \
        "Leg 2 returned 0, so the unlink CLAIMED success, but the file is" \
        "still there. A busy check that refuses by silently doing nothing and" \
        "returning 0 would pass legs 1 and 2 and fail here."
fi
echo "PASS leg 3: the file is gone, so the successful unlink was real."

echo ""
echo "RESULT: PASS"
echo "  Open file: refused ($EXP_BUSY). Closed file: unlinked (0), and gone."
echo "  The refusal is scoped to open descriptors, driven by an unprivileged"
echo "  ring-3 caller, and the use-after-free path is closed."
exit 0
