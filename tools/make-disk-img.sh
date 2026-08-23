#!/usr/bin/env bash
#==============================================================================
# make-disk-img.sh -- build the FAT32 `disk.img` the harness suite needs for C:.
#
# WHY THIS EXISTS
#
# 51 of the harnesses in verify/ reference disk.img, copying it to a scratch
# path and exiting 2 if it is missing. Nothing in the repo built it: it was an
# untracked, gitignored artifact that existed only on the machine where it had
# once been made by hand. That is invisible locally -- the file is just there
# -- and fatal anywhere else. The first full nightly run lost most of the suite
# to "disk.img not found", which reads as a wall of kernel failures.
#
# It is NOT committed to git: a 128 MB binary in a repo, ~99.99% of it zeroes,
# to hold one 14 KB file that is already tracked. Generating it takes under a
# second; storing it does not.
#
# WHAT THE HARNESSES ACTUALLY REQUIRE
#
#   1. A REAL FAT32 volume. verify-ring3-fatls.sh checks the FAT32 signature at
#      offset 0x52 and refuses a zeroed image, because against one C: would not
#      mount and `ls C:/` would fail for a reason unrelated to what it tests --
#      a vacuous run that scores as a kernel bug.
#
#   2. C:/HELLO.ELF, 14144 bytes. userspace/fileio.c opens it O_RDONLY and
#      lseeks to SEEK_END; verify-fsyscalls.sh asserts the result is EXACTLY
#      14144, so the size is load-bearing. It is never executed -- only read --
#      so this is a size-and-content fixture, not a runnable binary.
#
#      We use info.elf.signed, which is 14144 bytes. Do NOT substitute
#      hello.elf.signed just because the names match: it is 14388 bytes and
#      would fail that assertion. (The hand-made image had a stale 14144-byte
#      HELLO.ELF from an older signing run, which is why the name never
#      matched its content.)
#
# Idempotent: rebuilds from scratch every time, so a corrupted image is fixed
# by re-running rather than debugged.
#==============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-disk.img}"
FIXTURE="userspace/info.elf.signed"
FIXTURE_SIZE=14144

command -v mformat >/dev/null 2>&1 || {
    echo "ERROR: mformat not found (install mtools: brew install mtools / apt-get install mtools)" >&2
    exit 1
}

# The fixture is tracked in git, so a checkout has it. If it is missing, say so
# rather than silently producing an image without the one file C: must contain.
if [ ! -f "$FIXTURE" ]; then
    echo "ERROR: $FIXTURE not found (it is tracked -- is this a full checkout?)" >&2
    exit 1
fi

# Assert the size the harness hardcodes. If signing ever changes it, fail HERE
# with the real reason rather than 800 s later inside verify-fsyscalls.sh as a
# confusing "SEEK_END reported N, expected 14144".
actual=$(wc -c < "$FIXTURE" | tr -d ' ')
if [ "$actual" -ne "$FIXTURE_SIZE" ]; then
    echo "ERROR: $FIXTURE is $actual bytes, but verify-fsyscalls.sh asserts" >&2
    echo "       C:/HELLO.ELF is exactly $FIXTURE_SIZE. Update both together." >&2
    exit 1
fi

echo "==> Creating 128 MB FAT32 image: $OUT"
rm -f "$OUT"
# bs=1M, not 1m: GNU dd rejects the lowercase suffix outright, and BSD dd
# accepts both. The suite used 1m and died on every Linux runner.
dd if=/dev/zero of="$OUT" bs=1M count=128 status=none

# Geometry matches the original hand-made image: 63 sectors/track, 16 heads,
# 2 sectors/cluster, 32 reserved. -F forces FAT32 (mformat would otherwise
# pick FAT16 at this size, and the driver under test is the FAT32 one).
mformat -i "$OUT" -F -T 262144 -h 16 -s 63 -c 2 -R 32 ::

mcopy -i "$OUT" "$FIXTURE" ::HELLO.ELF

# Verify what we produced rather than trusting mformat's exit code: check the
# same FAT32 signature verify-ring3-fatls.sh checks, and read the file back.
if ! dd if="$OUT" bs=1 skip=82 count=8 status=none | grep -q "FAT32"; then
    echo "ERROR: produced image has no FAT32 signature at 0x52" >&2
    exit 1
fi
back=$(mdir -i "$OUT" ::HELLO.ELF 2>/dev/null | grep -c "HELLO" || true)
[ "$back" -ge 1 ] || { echo "ERROR: HELLO.ELF not readable back from $OUT" >&2; exit 1; }

echo "==> OK: $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes), C:/HELLO.ELF = $FIXTURE_SIZE bytes"
