#!/usr/bin/env bash
#
# verify-ide-lba28-clamp.sh — an IDE disk larger than 2^28 sectors is clamped
# to its LBA28-addressable prefix, so a high LBA is refused instead of aliasing
# onto a low one.
#
# THE BUG
#
# Every command the driver issues is LBA28 (READ/WRITE SECTORS, 0x20/0x30):
# ide_set_lba_atomic() sends address bits 0-27 and drops bits 28-31. But
# ide_identify() took the capacity from the LBA48 words (100/101) whenever the
# drive reported the LBA28 maximum, so on a disk of >= 128 GiB total_sectors
# exceeded 2^28. The bounds check in ide_read/write_sectors() then let LBA
# 0x10000005 through, and the drive served LBA 5 -- a read returned the wrong
# sector and a write silently overwrote low disk (the FAT32 boot sector and
# FAT live there).
#
# THE FIX
#
# ide_identify() clamps total_sectors to IDE_LBA28_MAX_SECTORS (0x0FFFFFFF),
# so the existing bounds check refuses any LBA the driver cannot address.
#
# THE VEHICLE
#
# `idelba` (TINYOS_FAULT_INJECT kernel-shell command, ide.c) prints
# total_sectors, then reads LBAs 5, 0x0FFFFFF0 and 0x10000005 and prints rc
# plus the first 8 bytes of each. This harness boots a 129 GiB SPARSE raw disk
# (a few KB on the host) with a distinct tag planted at each of those LBAs:
#
#   LBA 5          LOWTAG05   control: an ordinary read works
#   LBA 0x0FFFFFF0 TOPTAG28   control: the clamp still reaches the top of
#                             LBA28 space (a clamp that cut too low FAILs here)
#   LBA 0x10000005 HIGHTAG5   must be refused (rc < 0). The unfixed driver
#                             returns rc=0 with LOWTAG05 -- the alias, witnessed
#                             by content, not by an error code.
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem.
# NB: `make clean`s on exit -- TINYOS_FAULT_INJECT objects must not linger.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=idelba.log
TRACE=idelba-trace.log
MON_SOCK=/tmp/tinyos-idelba-mon.sock
WORK=$(mktemp -d "${TMPDIR:-/tmp}/idelba.XXXXXX")
DISK="$WORK/big.img"

guard_fail() { echo "HARNESS GUARD FAILED: $*"; rm -rf "$WORK"; exit 2; }

grep -q "ide_lba_selftest" src/ide.c || guard_fail "src/ide.c has no ide_lba_selftest()"
grep -q '"idelba"' src/shell.c || guard_fail "src/shell.c has no idelba command"

# 129 GiB = 270532608 sectors: above 2^28 (268435456), below 2^32 so IDENTIFY
# words 102/103 stay zero and the LBA48 capacity fits words 100/101.
truncate -s 129G "$DISK" || guard_fail "truncate failed"
plant() {  # $1 = LBA, $2 = 8-byte tag
    printf '%s' "$2" | dd of="$DISK" bs=512 seek="$1" conv=notrunc 2>/dev/null \
        || guard_fail "dd at LBA $1 failed"
}
plant 5         LOWTAG05
plant 268435440 TOPTAG28
plant 268435461 HIGHTAG5
[ "$(stat -f %z "$DISK" 2>/dev/null || stat -c %s "$DISK")" = 138512695296 ] \
    || guard_fail "disk is not 129 GiB after planting"

echo "==> Building kernel + ISO (TINYOS_FAULT_INJECT)..."
make clean >/dev/null 2>&1
make EXTRA_CFLAGS=-DTINYOS_FAULT_INJECT >/dev/null || guard_fail "build failed"
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || guard_fail "mkrescue failed"

rm -f "$SERIAL" "$TRACE" "$MON_SOCK"

echo "==> Launching headless QEMU with a 129 GiB sparse IDE disk"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() {
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "${QEMU_PID:-}" ] && wait "$QEMU_PID" 2>/dev/null
    rm -f "$MON_SOCK"
    rm -rf "$WORK"
    echo "==> make clean (TINYOS_FAULT_INJECT objects must not linger)"
    make clean >/dev/null 2>&1
    return 0
}
trap cleanup EXIT

# idelba is kernel-shell only; the typist hands over to kshell by itself.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_EXEC_CMD="idelba" \
TINYOS_EXPECT="IDELBA done" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 2
[ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: FAIL — no serial output at all (typist rc=$TYPIST_RC)"
    exit 2
fi
RAW=$(tr -d '\r' < "$SERIAL")
if grep -q "Triple fault" "$TRACE" 2>/dev/null || printf '%s\n' "$RAW" | grep -q "KERNEL PANIC"; then
    echo "RESULT: FAIL — the guest faulted"
    exit 1
fi
if ! printf '%s\n' "$RAW" | grep -q "^IDELBA done"; then
    echo "RESULT: INCONCLUSIVE — idelba never completed (typist rc=$TYPIST_RC); see $SERIAL"
    exit 2
fi

row() {  # $1 = LBA -> "rc tag"
    printf '%s\n' "$RAW" | sed -n "s/^IDELBA lba=$1 rc=\(-\{0,1\}[0-9]*\) tag=\(.*\)$/\1 \2/p" | head -1
}
SECTORS=$(printf '%s\n' "$RAW" | sed -n 's/^IDELBA sectors=\([0-9]*\)$/\1/p' | head -1)
read -r LOW_RC LOW_TAG   <<<"$(row 5)"
read -r TOP_RC TOP_TAG   <<<"$(row 268435440)"
read -r HIGH_RC HIGH_TAG <<<"$(row 268435461)"

echo "  sectors=${SECTORS:-?}"
echo "  lba 5          rc=${LOW_RC:-?} tag=${LOW_TAG:-?}"
echo "  lba 0x0FFFFFF0 rc=${TOP_RC:-?} tag=${TOP_TAG:-?}"
echo "  lba 0x10000005 rc=${HIGH_RC:-?} tag=${HIGH_TAG:-?}"

# Controls first: if these fail, the exclusion below grades nothing.
if [ "${LOW_RC:-x}" != 0 ] || [ "${LOW_TAG:-}" != LOWTAG05 ]; then
    echo "RESULT: INCONCLUSIVE — control read of LBA 5 did not return LOWTAG05"
    exit 2
fi
FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }

if [ "${TOP_RC:-x}" != 0 ] || [ "${TOP_TAG:-}" != TOPTAG28 ]; then
    fail "LBA 0x0FFFFFF0 not readable with its own tag — the clamp cut below the LBA28 limit"
fi
if [ "${HIGH_RC:-x}" = 0 ]; then
    if [ "${HIGH_TAG:-}" = LOWTAG05 ]; then
        fail "LBA 0x10000005 read back LBA 5's sector (LOWTAG05) — bits 28+ dropped, the LBA28 alias"
    else
        fail "LBA 0x10000005 was accepted (rc=0, tag=${HIGH_TAG:-?}) — beyond what LBA28 can address"
    fi
fi
if [ "${SECTORS:-}" != 268435455 ]; then
    fail "total_sectors=${SECTORS:-?}, expected the LBA28 clamp 268435455"
fi

if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS assertion(s); see $SERIAL (typist rc=$TYPIST_RC)"
    exit 1
fi
echo "RESULT: PASS — a 129 GiB disk is clamped to 2^28-1 sectors; LBA 0x10000005 is refused, not aliased onto LBA 5"
exit 0
