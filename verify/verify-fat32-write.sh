#!/usr/bin/env bash
#
# verify-fat32-write.sh — FULLY AUTOMATED FAT32 write-persistence check.
#
# Roadmap item 3 ("FAT32 write support") is only real if a file written on C:
# survives a REBOOT. Anything less is provable with a RAM buffer. So this
# harness boots QEMU TWICE against the SAME disk image:
#
#   Boot 1:  write C:/PERSIST.TXT tinyos-fat32-write-ok
#            cat   C:/PERSIST.TXT          <- proves the in-RAM path works
#   (power off, same disk file reused)
#   Boot 2:  cat   C:/PERSIST.TXT          <- proves it reached the platter
#            fatls                          <- proves the DIRENT carries the size
#
# Boot 2 is the one that matters. Before the dirent writeback, boot 1 passed
# and boot 2 failed: fat32_write updated file_size/first_cluster only in the
# in-RAM fat32_file_t, so the data and FAT chain were on disk but the directory
# entry still said "size 0, no cluster" — the file came back EMPTY.
#
# Note on the login flow: TinyOS keeps credentials in a kernel-only store that
# is NOT persisted to disk, so EVERY boot re-runs first-boot password setup.
# That is why both boots drive the identical typist flow even though the FAT32
# volume itself persists.
#
# PASS requires ALL of:
#   - boot 1 prints the marker after its `cat`   (write + read-back works)
#   - boot 2 prints the marker after its `cat`   (survived the reboot)
#   - boot 2's `fatls` lists PERSIST.TXT with a NON-ZERO size (dirent updated)
#   - zero triple faults in either boot
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.
# Logs: fat32w-boot1.log / fat32w-boot2.log (serial),
#       fat32w-boot1-trace.log / fat32w-boot2-trace.log (int/cpu_reset).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
RUN_DISK=/tmp/tinyos-fat32w-disk.img
MARKER=tinyos-fat32-write-ok
TESTFILE="C:/PERSIST.TXT"

# The 8.3 name as `fatls` prints it (the driver uppercases on create).
FATLS_NAME="PERSIST.TXT"

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

# -----------------------------------------------------------------------------
# run_boot <n> <exec_cmd> <expect> <followups>
#   Boots QEMU headless against $RUN_DISK and drives the shell via the typist.
#   Echoes nothing; sets globals SERIAL/TRACE for the caller to inspect.
# -----------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# rejoin_serial -- repair command echoes torn by the EDR status burst.
#
# The shell writes its prompt with no trailing newline, so anything else
# reaching the serial port in that window terminates the line. The EDR
# daemon's periodic burst does exactly that, at an ARBITRARY character:
#
#     $ cat[EDR DAEMON] Starting threat scan...
#     [EDR DAEMON] Scanning 6 active processes
#     [EDR DAEMON] Scan complete: 6 processes, duration 0 ticks
#      C:/PERSIST.TXT
#     tinyos-fat32-write-ok
#
# `grep -n "cat $TESTFILE"` then matches ZERO lines, cat1_line comes back
# empty, and this harness reported "marker never read back" against a run
# where FAT32 wrote the file AND read it back correctly -- both visible in
# its own serial log.
#
# Stripping the EDR text WITHOUT its preceding newline splices each torn line
# back onto its continuation, after which the ordinary patterns work.
#
# TWO line types, and conflating them LOSES DATA. A line that merely CONTAINS
# the burst carries real output before it ("tinyos-fat32-write-ok$ [EDR..." --
# the marker is printed with no trailing newline, so it fuses with the next
# prompt) and that prefix must be kept. A line that STARTS with the burst is
# pure noise and must be dropped outright. Treating both as "strip and buffer"
# makes consecutive EDR lines append empties to the buffer and the real prefix
# resurfaces glued to the wrong line -- which silently ate this very marker in
# an earlier version of this helper. Hence the separate `^\[EDR` rule, and the
# END flush for a torn line with nothing after it. This is
# preferable to loosening the patterns: the positional checks below are
# load-bearing (the `write` echo contains the marker text, so a non-positional
# match would pass on the echo alone) and rejoining keeps them exact.
rejoin_serial() {
    tr -d '\r' < "$1" \
      | awk '/^\[EDR DAEMON\]/ { next }
             /\[EDR DAEMON\]/  { sub(/\[EDR DAEMON\].*$/, ""); buf = buf $0; next }
             { print buf $0; buf = "" }
             END { if (buf != "") print buf }' > "$2"
}

run_boot() {
    local n="$1" exec_cmd="$2" expect="$3" followups="$4"
    SERIAL="fat32w-boot${n}.log"
    TRACE="fat32w-boot${n}-trace.log"
    local mon_sock="/tmp/tinyos-fat32w-mon${n}.sock"

    rm -f "$SERIAL" "$TRACE" "$mon_sock"

    qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
        -boot d -m 256M \
        -drive file="$RUN_DISK",format=raw,if=ide \
        -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
        -serial "file:$SERIAL" \
        -monitor "unix:$mon_sock,server,nowait" \
        -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
    QEMU_PID=$!

    TINYOS_PASSWORD="$PASSWORD" \
    TINYOS_SERIAL="$SERIAL" \
    TINYOS_MON_SOCK="$mon_sock" \
    TINYOS_EXEC_CMD="$exec_cmd" \
    TINYOS_EXPECT="$expect" \
    TINYOS_FOLLOWUP_CMDS="$followups" \
    python3 tools/qemu_typist.py
    TYPIST_RC=$?

    # Let the FAT32 dirent flush reach the image before cutting power. The
    # write path is synchronous (ide_write_sectors), so this is belt-and-braces
    # against QEMU's own host-side file buffering.
    sleep 3
    kill "$QEMU_PID" 2>/dev/null
    wait "$QEMU_PID" 2>/dev/null
    QEMU_PID=""
    rm -f "$mon_sock"
    return 0
}

# Kill a still-running QEMU on any early exit, so a failed run doesn't leave a
# headless VM holding the disk image.
QEMU_PID=""
cleanup() {
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "$QEMU_PID" ] && wait "$QEMU_PID" 2>/dev/null
    rm -f /tmp/tinyos-fat32w-mon1.sock /tmp/tinyos-fat32w-mon2.sock
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

# -----------------------------------------------------------------------------
# BOOT 1 — create the file on C: and read it straight back.
# -----------------------------------------------------------------------------
echo "==> BOOT 1: writing $TESTFILE (slow under TCG; be patient)..."
run_boot 1 "write $TESTFILE $MARKER" "Written to" "cat $TESTFILE=>$MARKER"
BOOT1_RC=$TYPIST_RC
BOOT1_SERIAL="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$BOOT1_SERIAL"
check_no_triple_fault "fat32w-boot1-trace.log" "boot 1"

if [ "$BOOT1_RC" -ne 0 ]; then
    echo "--- tail of $BOOT1_SERIAL ---"
    grep -v "Suspicious" "$BOOT1_SERIAL" | tail -30
    fail "boot 1 did not complete write+cat (typist rc=$BOOT1_RC)" 2
fi

# The marker must appear AFTER the cat command, not merely somewhere in the log
# (the `write` command line itself echoes the marker text as the user types it).
cat1_line=$(grep -n "cat $TESTFILE" "$BOOT1_SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
marker1_line=$(awk -v c="${cat1_line:-0}" -v m="$MARKER" \
    'NR>c && index($0,m){print NR; exit}' "$BOOT1_SERIAL")

if [ -z "$cat1_line" ] || [ -z "$marker1_line" ]; then
    echo "--- tail of $BOOT1_SERIAL ---"
    grep -v "Suspicious" "$BOOT1_SERIAL" | tail -30
    fail "boot 1: marker never read back (cat_line=${cat1_line:-none})" 2
fi
echo "    boot 1 OK — wrote and read back at serial line $marker1_line"

# -----------------------------------------------------------------------------
# BOOT 2 — same disk, fresh kernel. THE decisive check.
# -----------------------------------------------------------------------------
# Boot 2 also re-writes the file with a SHORTER body. That exercises the
# overwrite path: fat32_create must refuse the duplicate name, O_TRUNC must
# free the old chain, and the dirent must be rewritten with the smaller size.
# Without O_TRUNC the tail of the longer original would still be there, so
# REWRITTEN would be followed by leftover bytes of the original marker.
REWRITE=rewritten-shorter
echo "==> BOOT 2: re-reading $TESTFILE from the SAME disk..."
run_boot 2 "cat $TESTFILE" "$MARKER" \
    "fatls=>$FATLS_NAME;write $TESTFILE $REWRITE=>Written to;cat $TESTFILE=>$REWRITE"
BOOT2_RC=$TYPIST_RC
BOOT2_SERIAL="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$BOOT2_SERIAL"
check_no_triple_fault "fat32w-boot2-trace.log" "boot 2"

echo
echo "================ VERDICT ================"

if [ "$BOOT2_RC" -ne 0 ]; then
    echo "--- tail of $BOOT2_SERIAL ---"
    grep -v "Suspicious" "$BOOT2_SERIAL" | tail -40
    fail "boot 2 did not read the file back (typist rc=$BOOT2_RC).
  The file did NOT survive the reboot — data and/or directory entry lost." 1
fi

# Marker must appear after boot 2's cat echo.
cat2_line=$(grep -n "cat $TESTFILE" "$BOOT2_SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
marker2_line=$(awk -v c="${cat2_line:-0}" -v m="$MARKER" \
    'NR>c && index($0,m){print NR; exit}' "$BOOT2_SERIAL")

if [ -z "$cat2_line" ] || [ -z "$marker2_line" ]; then
    echo "--- tail of $BOOT2_SERIAL ---"
    grep -v "Suspicious" "$BOOT2_SERIAL" | tail -40
    fail "boot 2: '$MARKER' not present after the cat — file did not persist" 1
fi

# The dirent check: fatls must show the file with a NON-ZERO size. This is the
# assertion that specifically catches a missing/incorrect dirent writeback --
# a stale entry reports 0 bytes even when the clusters hold the data.
fatls_size=$(grep "$FATLS_NAME" "$BOOT2_SERIAL" 2>/dev/null \
             | grep -oE '[0-9]+ bytes' | head -1 | grep -oE '[0-9]+')

if [ -z "$fatls_size" ]; then
    echo "--- fatls output region of $BOOT2_SERIAL ---"
    grep -A 10 -i "fatls" "$BOOT2_SERIAL" | grep -v "Suspicious" | tail -20
    fail "boot 2: fatls did not list $FATLS_NAME — directory entry missing" 1
fi

if [ "$fatls_size" -eq 0 ]; then
    fail "boot 2: fatls reports $FATLS_NAME as 0 bytes — DIRENT WRITEBACK BROKEN
  (the data reached the disk but the directory entry was never updated)" 1
fi

# Overwrite check: after rewriting with a SHORTER body, the read-back must be
# the new text with NO tail of the old one. A missing O_TRUNC (or a dirent that
# kept the larger size) shows up as the old marker's remnant trailing the new
# text on the same line.
rewrite_cat_line=$(grep -n "cat $TESTFILE" "$BOOT2_SERIAL" | sed -n '2p' | cut -d: -f1)
if [ -n "$rewrite_cat_line" ]; then
    rewrite_out=$(awk -v c="$rewrite_cat_line" -v m="$REWRITE" \
        'NR>c && index($0,m){print; exit}' "$BOOT2_SERIAL")
    if [ -z "$rewrite_out" ]; then
        echo "--- tail of $BOOT2_SERIAL ---"
        grep -v "Suspicious" "$BOOT2_SERIAL" | tail -30
        fail "boot 2: overwrite did not read back as '$REWRITE'" 1
    fi
    if echo "$rewrite_out" | grep -q "$MARKER"; then
        fail "boot 2: overwrite left the OLD content behind ($rewrite_out)
  O_TRUNC did not free the previous cluster chain / shrink the dirent." 1
    fi
    echo "    boot 2 overwrite OK — '$REWRITE' with no leftover tail"
fi

echo "RESULT: PASS — FAT32 writes persist across reboot"
echo "  boot 1: wrote $TESTFILE and read it back (serial line $marker1_line)"
echo "  boot 2: same disk, fresh kernel — '$MARKER' read back at line $marker2_line"
echo "  boot 2: fatls reports $FATLS_NAME = $fatls_size bytes (dirent updated)"
echo "  boot 2: overwrite with a shorter body truncated correctly"
exit 0
