#!/usr/bin/env bash
#
# verify-fsyscalls.sh — FULLY AUTOMATED file-syscall check (SYS_OPEN/CLOSE/READDIR).
#
# Same headless first-boot drive as verify-spawn.sh, but runs
#
#     exec /fileio.elf
#
# fileio.elf is a RING-3 program that opens a file, writes to it, reads it back
# and lists a directory — entirely through syscalls. The shell's own `cat`/`ls`
# cannot prove any of this: they run in the kernel and walk ramfs_node_t
# directly, never crossing the ring boundary. Only this path exercises
#
#   - the new syscall numbers actually being dispatched (MAX_SYSCALL_NUM must
#     cover SYS_READDIR=22, or the range check rejects the call), and
#   - copy_string_from_user pulling the path out of user memory, and
#   - the per-task fd table handing out a task-local fd (>= 3) and resolving it
#     back to a global VFS descriptor, and
#   - sys_read/sys_write routing a file fd to the VFS instead of the console
#     streams, and
#   - sys_readdir copying vfs_dirent_t records OUT to a user buffer with a
#     layout userspace agrees on byte-for-byte.
#
# PASS requires the content read back in ring 3 to match what ring 3 wrote, the
# directory listing to contain both of the seeded files, and a stale
# fd to be rejected.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: fsyscalls.log (serial),
# fsyscalls-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=fsyscalls.log
TRACE=fsyscalls-trace.log
RUN_DISK=/tmp/tinyos-fsyscalls-disk.img
MON_SOCK=/tmp/tinyos-fsyscalls-mon.sock

echo "==> Building kernel + ISO..."
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# A REAL FAT32 volume, not a zeroed image: the C: readdir check below needs the
# drive to actually mount, and a dd-zeroed disk has no FAT32 boot sector. The
# credential store lives in the kernel (no /etc/shadow), so a pre-formatted disk
# still gets the first-boot password prompt.
echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
if [ ! -f disk.img ]; then
    echo "ERROR: disk.img not found (needed for the C: drive checks)"
    exit 1
fi
cp disk.img "$RUN_DISK"
if ! dd if="$RUN_DISK" bs=1 skip=82 count=8 status=none | grep -q "FAT32"; then
    echo "ERROR: $RUN_DISK is not a FAT32 volume (no FAT32 signature at 0x52)"
    exit 1
fi

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
# Wait on the program's LAST line: it is only reached after every check has
# passed, including the stale-fd rejection.
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_EXEC_CMD="exec /fileio.elf" \
TINYOS_EXPECT="fileio: done" \
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

# Any of the program's own failure lines is a hard FAIL — it got far enough to
# report, so this is a real defect, not an inconclusive run.
if grep -qE "fileio: (open for write failed|open for read failed|opendir failed|read failed|readdir failed|short write|content MISMATCH|stale fd accepted|marker\.txt NOT|fileio-test\.txt NOT|fat32 opendir failed|fat32 readdir failed|fat32 partial record|fat32 subdir wrongly accepted|getcwd failed|getcwd accepted a short buffer|chdir failed|relative create failed|relative create did not land in the cwd|absolute path broken by cwd|chdir \.\. failed|relative chdir failed|relative unlink failed|chdir to missing dir accepted|failed chdir moved cwd|chdir to a file accepted|chdir to a missing FAT32 directory accepted|chdir to C:/ failed|chdir back to D:/ failed|fat32 mkdir SUBA failed|fat32 nested mkdir failed|fat32 mkdir under missing parent accepted|fat32 create SUBFILE failed|fat32 mkdir under a file accepted|fat32 nested create failed|fat32 nested write short|fat32 nested reopen failed|fat32 nested read got|fat32 nested content|fat32 nested stat failed|fat32 nested stat size|fat32 nested file also visible in root|fat32 subdir open failed|fat32 subdir listing missing|fat32 O_DIRECTORY on a file accepted|fat32 chdir into subdir failed|fat32 cwd is|fat32 relative open in subdir failed|fat32 chdir back to D:/ failed|fat32 rmdir of non-empty parent accepted|fat32 rmdir of non-empty subdir accepted|fat32 nested unlink failed|fat32 nested rmdir failed|fat32 parent rmdir failed)" "$SERIAL" 2>/dev/null; then
    echo "RESULT: FAIL — fileio.elf reported an error"
    grep "fileio:" "$SERIAL" | tail -10
    exit 1
fi

# C: must actually be mounted, or the FAT32 readdir check below would be
# testing nothing and its absence would look like a pass.
if ! grep -q "C: drive mounted as FAT32" "$SERIAL" 2>/dev/null; then
    echo "RESULT: FAIL/INCONCLUSIVE — C: did not mount, FAT32 readdir untested"
    grep -i "fat32\|C: drive" "$SERIAL" | tail -10
    exit 2
fi

# Ordered: a stale or duplicated line must not stand in for a missing one.
l_wfd=$(grep -n "fileio: write fd=" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
# The content read back in ring 3 must be exactly what ring 3 wrote. This is
# the line that proves the write reached the FS and the read came back out.
l_back=$(grep -n "fileio: read back: ring3-file-io-ok" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
l_dir=$(grep -n "fileio: found both entries" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
# The same syscall against the OTHER filesystem. C: had no .readdir at all
# before this change, so an identical call worked on D: and failed on C:.
l_fat=$(grep -n "fileio: fat32 entries=" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
# stat() on both drives: size/type agree with what was written, a directory
# reports as one, a missing path and a short buffer are both refused.
l_stat=$(grep -n "fileio: stat ok" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
# lseek on both drives: SEEK_SET/CUR/END, negative displacement, past-EOF
# clamp, and the rejected cases (before-start, bad whence, directory fd).
# RAMFS had no seek at all before this, so the D: half could not have passed.
l_seek=$(grep -n "fileio: seek ok" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
# mkdir/rmdir/unlink: create a dir, make a file in it, then prove the refusals
# (duplicate mkdir, rmdir of a non-empty dir, unlink of a dir, rmdir of a file,
# and creating/removing inside a root-owned 0755 dir as uid 1000).
# The C: half of the same three syscalls. This is the half that matters most:
# FAT32's mkdir/rmdir/unlink were dead code carrying real corruption bugs
# (rmdir was literally unlink — it freed a directory's chain without checking
# emptiness) until this change wired them into the ops table.
l_fatns=$(grep -n "fileio: fat32 namespace ok" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
l_ns=$(grep -n "fileio: namespace ok" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
# getcwd/chdir, and — the actual point of a cwd — relative paths resolving
# through it: a file created as "cwdfile.txt" must land in the cwd, an absolute
# path must ignore the cwd, ".." must clamp at the drive root, a failed chdir
# must leave the cwd untouched, and a MISSING FAT32 directory must be refused
# rather than silently accepted.
l_cwd=$(grep -n "fileio: cwd ok" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
# FAT32 subdirectories: nested mkdir, I/O through a nested path, that the
# nested file is NOT also visible in the root (the exact failure mode of the
# old path-as-one-filename behaviour), subdirectory listing, chdir into a
# subdir with relative resolution, and the refusals (missing parent, parent
# that is a file, O_DIRECTORY on a file, rmdir of a non-empty directory).
l_sub=$(grep -n "fileio: fat32 subdirs ok" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
l_done=$(grep -n "fileio: done" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)

if [ -z "$l_wfd" ] || [ -z "$l_back" ] || [ -z "$l_dir" ] || [ -z "$l_fat" ] \
   || [ -z "$l_stat" ] || [ -z "$l_seek" ] || [ -z "$l_ns" ] \
   || [ -z "$l_cwd" ] || [ -z "$l_sub" ] || [ -z "$l_done" ]; then
    echo "RESULT: FAIL/INCONCLUSIVE (typist rc=$TYPIST_RC)"
    echo "  write fd=${l_wfd:-none} readback=${l_back:-none}" \
         "readdir=${l_dir:-none} fat32=${l_fat:-none} stat=${l_stat:-none}" \
         "seek=${l_seek:-none} fat32ns=${l_fatns:-none}" \
         "namespace=${l_ns:-none}" "cwd=${l_cwd:-none}" \
         "subdirs=${l_sub:-none}" "done=${l_done:-none}"
    echo "--- tail of $SERIAL ---"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi

# The fd handed to userspace must be a per-task index (3+), NOT a raw global
# VFS descriptor leaked straight through. fd 0/1/2 would mean the file landed
# on a console stream instead of the fd table.
wfd=$(grep -o "fileio: write fd=[0-9]*" "$SERIAL" | head -1 | cut -d= -f2)
if [ "${wfd:-0}" -lt 3 ]; then
    echo "RESULT: FAIL — open() returned fd=$wfd, expected a per-task fd >= 3"
    exit 1
fi

# The size stat() reports must match the string the program actually wrote
# (16 bytes of "ring3-file-io-ok"); a driver that always answers 0 would
# otherwise still satisfy "stat ok".
statsize=$(grep -o "fileio: stat size=[0-9]*" "$SERIAL" | head -1 | cut -d= -f2)
if [ "${statsize:-0}" -ne 16 ]; then
    echo "RESULT: FAIL — stat reported size=$statsize, expected 16"
    exit 1
fi

# SEEK_END on C:/HELLO.ELF must report that file's real size. A driver that
# answered 0 (or echoed the requested offset) would still print "seek ok".
seekend=$(grep -o "fileio: fat32 seek end=[0-9]*" "$SERIAL" | head -1 | cut -d= -f2)
if [ "${seekend:-0}" -ne 14144 ]; then
    echo "RESULT: FAIL — fat32 SEEK_END reported $seekend, expected 14144"
    exit 1
fi

if [ "$TYPIST_RC" -eq 0 ] && [ "$l_back" -gt "$l_wfd" ] && [ "$l_fat" -gt "$l_dir" ] \
   && [ "$l_stat" -gt "$l_fat" ] && [ "$l_seek" -gt "$l_stat" ] \
   && [ "$l_fatns" -gt "$l_seek" ] && [ "$l_ns" -gt "$l_fatns" ] \
   && [ "$l_cwd" -gt "$l_ns" ] && [ "$l_sub" -gt "$l_cwd" ] \
   && [ "$l_done" -gt "$l_sub" ]; then
    echo "RESULT: PASS — ring-3 open/write/read/readdir/stat/lseek/mkdir/rmdir/unlink/getcwd/chdir work on both D: and C:, including nested FAT32 subdirectories (fd=$wfd)"
    grep "fileio:" "$SERIAL" | head -40
    exit 0
else
    echo "RESULT: FAIL (typist rc=$TYPIST_RC; out of order:" \
         "wfd=$l_wfd back=$l_back dir=$l_dir fat32=$l_fat stat=$l_stat" \
         "seek=$l_seek fat32ns=$l_fatns namespace=$l_ns cwd=$l_cwd" \
         "subdirs=$l_sub done=$l_done)"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi
