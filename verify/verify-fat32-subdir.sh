#!/usr/bin/env bash
#
# verify-fat32-subdir.sh — FULLY AUTOMATED FAT32 SUBDIRECTORY persistence check.
#
# Companion to verify-fat32-write.sh. That harness proves a file written in the
# ROOT directory of C: survives a reboot. This one proves the same for a file
# created SEVERAL LEVELS DEEP in a directory tree the test itself builds:
#
#   Boot 1 (ring-3 shell):
#       mkdir C:/SUBDIR
#       mkdir C:/SUBDIR/NESTED
#       write C:/SUBDIR/NESTED/DEEP.TXT tinyos-fat32-subdir-ok
#       cat   C:/SUBDIR/NESTED/DEEP.TXT         <- in-RAM path works
#   (power off, SAME disk file reused)
#   Boot 2 (fresh kernel, same disk — THE decisive check):
#       ls   C:/SUBDIR                          <- NESTED/ dirent survived
#       ls   C:/SUBDIR/NESTED                   <- DEEP.TXT dirent survived
#       cat  C:/SUBDIR/NESTED/DEEP.TXT          <- reached the platter, 3 deep
#
# Why this matters. FAT32 subdirectory support (create at any depth, multi-
# cluster directory scans) landed in commit daface1 ("fat32: support
# subdirectories at any depth"). Before it, creation was root-directory-only:
# `mkdir C:/SUBDIR/NESTED` could not resolve its parent, and a file written
# inside a subdirectory had nowhere to put its dirent. This harness is the
# regression witness for that feature — it must PASS on main, and would FAIL on
# any kernel that reverted to root-only directory handling.
#
# Everything runs in the RING-3 login shell (mkdir/ls/cat/write are all ring-3
# builtins over syscalls); no `kshell` handover is needed, which also sidesteps
# the double-type trap of naming kshell as the exec command.
#
# Note on login: TinyOS keeps credentials in a kernel-only store that is NOT
# persisted, so EVERY boot re-runs first-boot password setup even though the
# FAT32 volume persists. Both boots drive the identical typist login flow.
#
# PASS requires ALL of:
#   - boot 1 reads back the marker after its `cat` of the 3-deep file
#   - boot 2 `ls C:/SUBDIR`        lists NESTED/      (intermediate dir dirent)
#   - boot 2 `ls C:/SUBDIR/NESTED` lists DEEP.TXT     (leaf file dirent)
#   - boot 2 reads back the marker after `cat` of the 3-deep file
#   - zero triple faults in either boot
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.
# Logs: fat32sd-boot1.log / fat32sd-boot2.log (serial),
#       fat32sd-boot1-trace.log / fat32sd-boot2-trace.log (int/cpu_reset).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
RUN_DISK=/tmp/tinyos-fat32sd-disk.img
MARKER=tinyos-fat32-subdir-ok

# The directory tree this test builds. All three names are already uppercase
# 8.3-legal, so the FAT32 driver (which uppercases on create) stores them
# verbatim and `ls` prints them back unchanged.
DIR1="C:/SUBDIR"
DIR2="C:/SUBDIR/NESTED"
DEEPFILE="C:/SUBDIR/NESTED/DEEP.TXT"

# How the entries appear in `ls` output. The ring-3 `ls` prints directories as
# "NAME/\n" and files as "NAME\n" (shell.c cmd_ls), each with a real newline —
# unlike `cat`, which emits no trailing newline. That makes these clean anchors.
NESTED_LS="NESTED/"
DEEP_LS="DEEP.TXT"

echo "==> Building kernel + ISO..."
make >/dev/null || { echo "build failed"; exit 1; }
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || { echo "mkrescue failed"; exit 1; }

# A REAL FAT32 volume is required -- a zeroed image would fail to mount and C:
# would not exist, so the test would be vacuous. disk.img is the project's
# pre-formatted FAT32 image; copy it so the original stays pristine.
if [ ! -f disk.img ]; then
    echo "ERROR: disk.img (formatted FAT32 image) not found"
    exit 2
fi
echo "==> Copying pristine disk.img -> $RUN_DISK (persists across both boots)"
rm -f "$RUN_DISK"
cp disk.img "$RUN_DISK"

# Sanity: confirm the copy really is FAT32 before trusting any verdict.
if ! dd if="$RUN_DISK" bs=1 skip=82 count=8 status=none | grep -q "FAT32"; then
    echo "ERROR: $RUN_DISK is not a FAT32 volume (no FAT32 signature at 0x52)"
    exit 2
fi

# Repair command echoes torn by the EDR bursts. See edr-rejoin.sh for the
# three tear shapes it handles; edr-rejoin-test.sh is the case set.
. "$(dirname "$0")/edr-rejoin.sh"

run_boot() {
    local n="$1" exec_cmd="$2" expect="$3" followups="$4"
    SERIAL="fat32sd-boot${n}.log"
    TRACE="fat32sd-boot${n}-trace.log"
    local mon_sock="/tmp/tinyos-fat32sd-mon${n}.sock"

    rm -f "$SERIAL" "$TRACE" "$mon_sock"

    qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
        -boot d -m 256M \
        -drive file="$RUN_DISK",format=raw,if=ide \
        -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
        -serial "file:$SERIAL" \
        -monitor "unix:$mon_sock,server,nowait" \
        -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
    QEMU_PID=$!

    # STAY_IN_RING3 is LOAD-BEARING, not a convenience. The kernel shell's
    # FAT32 surface is incomplete for this test: its `cmd_mkdir` calls
    # ramfs_mkdir unconditionally (never fat32_mkdir), and its `cmd_ls` routes
    # C: to `fatls` but DROPS the path argument, so `ls C:/SUBDIR` lists the
    # ROOT. Only the ring-3 shell reaches FAT32 subdirectories correctly:
    # mkdir -> SYS_MKDIR -> vfs_mkdir -> fat32_vfs_mkdir -> fat32_mkdir, and
    # ls -> open(O_DIRECTORY)+readdir honoring the full nested path. So the
    # whole flow stays in ring 3; the typist must NOT type `kshell`.
    TINYOS_PASSWORD="$PASSWORD" \
    TINYOS_STAY_IN_RING3=1 \
    TINYOS_SERIAL="$SERIAL" \
    TINYOS_MON_SOCK="$mon_sock" \
    TINYOS_EXEC_CMD="$exec_cmd" \
    TINYOS_EXPECT="$expect" \
    TINYOS_FOLLOWUP_CMDS="$followups" \
    python3 tools/qemu_typist.py
    TYPIST_RC=$?

    # Let the FAT32 dirent flushes reach the image before cutting power. The
    # write path is synchronous (ide_write_sectors); this is belt-and-braces
    # against QEMU's own host-side file buffering.
    sleep 3
    kill "$QEMU_PID" 2>/dev/null
    wait "$QEMU_PID" 2>/dev/null
    QEMU_PID=""
    rm -f "$mon_sock"
    return 0
}

# Kill a still-running QEMU on any early exit.
QEMU_PID=""
cleanup() {
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "$QEMU_PID" ] && wait "$QEMU_PID" 2>/dev/null
    rm -f /tmp/tinyos-fat32sd-mon1.sock /tmp/tinyos-fat32sd-mon2.sock
    return 0
}
trap cleanup EXIT

fail() {
    echo "RESULT: FAIL — $1"
    exit "${2:-2}"
}

check_no_triple_fault() {
    local trace="$1" label="$2"
    if grep -q "Triple fault" "$trace" 2>/dev/null; then
        echo "--- $trace ---"
        grep -E "check_exception|v=0e|v=08|Triple fault|^EIP=|CR2=" "$trace" | tail -15
        fail "'Triple fault' during $label"
    fi
}

# The marker must appear AFTER the `cat` command echo, not merely somewhere in
# the log (the `write` command line echoes the marker as it is typed). TinyOS
# `cat` emits NO newline after the command echo, so a successful readback is:
#
#     $ cat C:/SUBDIR/NESTED/DEEP.TXTtinyos-fat32-subdir-ok$
#
# all on one line. A bare `NR>c` test scores that as "never read back". So also
# accept the marker on the cat line itself, but only in the text FOLLOWING the
# command, which keeps the `write` echo from satisfying the test.
#
# marker_after <serial> <cat_line> <marker> <cmd> [line|text]
marker_after() {
    awk -v c="$2" -v m="$3" -v cmd="$4" -v mode="${5:-line}" '
        NR>c && index($0,m){ print (mode=="text" ? $0 : NR); exit }
        NR==c {
            p=index($0,cmd); if(!p) next
            rest=substr($0, p+length(cmd))
            if(index(rest,m)){ print (mode=="text" ? rest : NR); exit }
        }' "$1"
}

# A directory listing entry (`ls`) DOES end in a newline, so it may land on its
# own line OR be torn onto the command-echo line by an EDR burst. Accept both:
# search the whole post-command region for the entry token. list_has <serial>
# <ls_cmd> <entry> — true if <entry> appears at or after the `ls <cmd>` echo.
list_has() {
    local serial="$1" lscmd="$2" entry="$3"
    local ln
    ln=$(grep -n "$lscmd" "$serial" 2>/dev/null | head -1 | cut -d: -f1)
    [ -z "$ln" ] && return 1
    awk -v c="$ln" -v e="$entry" 'NR>=c && index($0,e){found=1; exit} END{exit !found}' "$serial"
}

# -----------------------------------------------------------------------------
# BOOT 1 — build the nested tree and read the deep file straight back.
# -----------------------------------------------------------------------------
# The exec command creates the first directory; the followups create the nested
# directory, write the 3-deep file, and read it back. mkdir prints NOTHING on
# success, so those steps carry no `=>expect` content token — the typist's
# per-command echo-wait (type_echo_line, which matches the full command echo on
# the EDR-despammed stream) is the real synchronization, and a bogus positive
# token like "$" would only risk matching the prompt prematurely. The write and
# cat steps DO have observable output, so they keep their expects.
#
# TINYOS_EXPECT (the first command's expect) must be a real token too: mkdir has
# no output, so assert on the ring-3 shell banner that is already on screen when
# the shell is ready to take the command.
# The ring-3 `mkdir` and `write` print NOTHING on success, so those steps carry
# no `=>expect` token — type_echo_line (which matches the full command echo on
# the EDR-despammed stream) is the per-command synchronization. Only `cat` has
# observable output, so only it gets an expect. The first command's
# TINYOS_EXPECT must be a real token too; the ring-3 banner is on screen when
# the shell is ready to take the command.
echo "==> BOOT 1: building $DIR2 and writing $DEEPFILE (slow under TCG)..."
run_boot 1 "mkdir $DIR1" "TinyOS shell (ring 3)" \
    "mkdir $DIR2;write $DEEPFILE $MARKER;cat $DEEPFILE=>$MARKER"
BOOT1_RC=$TYPIST_RC
BOOT1_SERIAL="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$BOOT1_SERIAL"
check_no_triple_fault "fat32sd-boot1-trace.log" "boot 1"

if [ "$BOOT1_RC" -ne 0 ]; then
    echo "--- tail of $BOOT1_SERIAL ---"
    grep -v "Suspicious" "$BOOT1_SERIAL" | tail -30
    fail "boot 1 did not complete mkdir/write/cat (typist rc=$BOOT1_RC)" 2
fi

cat1_line=$(grep -n "cat $DEEPFILE" "$BOOT1_SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
marker1_line=$(marker_after "$BOOT1_SERIAL" "${cat1_line:-0}" "$MARKER" "cat $DEEPFILE")

if [ -z "$cat1_line" ] || [ -z "$marker1_line" ]; then
    echo "--- tail of $BOOT1_SERIAL ---"
    grep -v "Suspicious" "$BOOT1_SERIAL" | tail -30
    fail "boot 1: 3-deep file never read back (cat_line=${cat1_line:-none}).
  mkdir of a nested path or write into a subdirectory failed in-RAM." 2
fi
echo "    boot 1 OK — built $DIR2 and read back $DEEPFILE at line $marker1_line"

# -----------------------------------------------------------------------------
# BOOT 2 — same disk, fresh kernel. THE decisive check.
# -----------------------------------------------------------------------------
echo "==> BOOT 2: re-reading the nested tree from the SAME disk..."
run_boot 2 "ls $DIR1" "$NESTED_LS" \
    "ls $DIR2=>$DEEP_LS;cat $DEEPFILE=>$MARKER"
BOOT2_RC=$TYPIST_RC
BOOT2_SERIAL="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$BOOT2_SERIAL"
check_no_triple_fault "fat32sd-boot2-trace.log" "boot 2"

echo
echo "================ VERDICT ================"

if [ "$BOOT2_RC" -ne 0 ]; then
    echo "--- tail of $BOOT2_SERIAL ---"
    grep -v "Suspicious" "$BOOT2_SERIAL" | tail -40
    fail "boot 2 did not list/read the nested tree (typist rc=$BOOT2_RC).
  The subdirectory tree did NOT survive the reboot." 1
fi

# Intermediate-directory dirent survived: ls C:/SUBDIR shows NESTED/
if ! list_has "$BOOT2_SERIAL" "ls $DIR1" "$NESTED_LS"; then
    echo "--- region of $BOOT2_SERIAL after 'ls $DIR1' ---"
    grep -A 8 "ls $DIR1" "$BOOT2_SERIAL" | grep -v "Suspicious" | tail -12
    fail "boot 2: 'ls $DIR1' did not list '$NESTED_LS' — the intermediate
  directory's dirent did not persist (subdirectory create not written back)." 1
fi
echo "    boot 2 OK — '$DIR1' still lists '$NESTED_LS'"

# Leaf-file dirent survived: ls C:/SUBDIR/NESTED shows DEEP.TXT
if ! list_has "$BOOT2_SERIAL" "ls $DIR2" "$DEEP_LS"; then
    echo "--- region of $BOOT2_SERIAL after 'ls $DIR2' ---"
    grep -A 8 "ls $DIR2" "$BOOT2_SERIAL" | grep -v "Suspicious" | tail -12
    fail "boot 2: 'ls $DIR2' did not list '$DEEP_LS' — the leaf file's dirent
  inside the nested directory did not persist." 1
fi
echo "    boot 2 OK — '$DIR2' still lists '$DEEP_LS'"

# Content survived: the 3-deep file reads back its marker on a fresh kernel.
cat2_line=$(grep -n "cat $DEEPFILE" "$BOOT2_SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
marker2_line=$(marker_after "$BOOT2_SERIAL" "${cat2_line:-0}" "$MARKER" "cat $DEEPFILE")

if [ -z "$cat2_line" ] || [ -z "$marker2_line" ]; then
    echo "--- tail of $BOOT2_SERIAL ---"
    grep -v "Suspicious" "$BOOT2_SERIAL" | tail -40
    fail "boot 2: '$MARKER' not read back from $DEEPFILE — the 3-deep file's
  contents did not survive the reboot." 1
fi

echo "RESULT: PASS — FAT32 subdirectories persist across reboot"
echo "  boot 1: built $DIR2 and read back $DEEPFILE (serial line $marker1_line)"
echo "  boot 2: same disk, fresh kernel — '$DIR1' lists '$NESTED_LS'"
echo "  boot 2: '$DIR2' lists '$DEEP_LS'"
echo "  boot 2: $DEEPFILE read back '$MARKER' at line $marker2_line"
exit 0
