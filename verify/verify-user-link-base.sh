#!/usr/bin/env bash
#
# verify-user-link-base.sh — no user image page replaces the kernel's
# identity-map view of RAM, and the loader refuses an image linked inside RAM.
#
# THE BUG
#
# The kernel maps all RAM 1:1 (virt == phys, up to PMM_MAX_BYTES) and every
# user PDPT starts as a copy of those mappings. User programs linked at
# 0x08000000, so loading image page n wrote a user PTE over the kernel's
# identity PTE for physical frame 128 MB + n*4K. While that process's CR3 was
# loaded, a kernel object in such a frame was read from, and written to, the
# process's own image page. The loader's only lower bound was 0x1000, so a
# signed image could be linked over any RAM the kernel uses.
#
# THE FIX
#
# User images link at USER_IMAGE_BASE (0x20000000), above PMM_MAX_BYTES
# (static-asserted in elf.c), and the loader refuses any PT_LOAD segment that
# starts below PMM_MAX_BYTES. See doc/DESIGN_USER_LINK_BASE.md.
#
# THE VEHICLE
#
# `linkbase` (TINYOS_FAULT_INJECT kernel-shell command, elf.c) works on page
# tables only:
#   hello     loads /hello.elf through the real loader without scheduling it,
#             and counts image pages the kernel PDPT maps 1:1 that the process
#             PDPT maps elsewhere ("shadowed"). The unfixed tree shadows all 8.
#   control   maps one page into that PDPT at an identity-mapped address. It
#             must read shadowed=1 on ANY kernel, so the hello leg's 0 cannot
#             come from a probe that is blind to shadows.
#   ramprobe  /ramprobe.elf is signed and linked at 0x0C000000 (inside RAM).
#             The loader must refuse it; the unfixed loader accepts it.
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem.
# NB: `make clean`s on exit -- TINYOS_FAULT_INJECT objects must not linger.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=linkbase.log
TRACE=linkbase-trace.log
MON_SOCK=/tmp/tinyos-linkbase-mon.sock

guard_fail() { echo "HARNESS GUARD FAILED: $*"; exit 2; }

grep -q "elf_linkbase_selftest" src/elf.c || guard_fail "src/elf.c has no elf_linkbase_selftest()"
grep -q '"linkbase"' src/shell.c || guard_fail "src/shell.c has no linkbase command"
[ -f src/ramprobe_elf_data.c ] || guard_fail "src/ramprobe_elf_data.c missing (make -C userspace blobs)"

echo "==> Building kernel + ISO (TINYOS_FAULT_INJECT)..."
make clean >/dev/null 2>&1
make EXTRA_CFLAGS=-DTINYOS_FAULT_INJECT >/dev/null || guard_fail "build failed"
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || guard_fail "mkrescue failed"

rm -f "$SERIAL" "$TRACE" "$MON_SOCK"

# -m 256M: RAM must reach above 128 MB, or the old base shadows nothing and
# the hello leg cannot tell the fixed tree from the unfixed one.
echo "==> Launching headless QEMU (-m 256M)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() {
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "${QEMU_PID:-}" ] && wait "$QEMU_PID" 2>/dev/null
    rm -f "$MON_SOCK"
    echo "==> make clean (TINYOS_FAULT_INJECT objects must not linger)"
    make clean >/dev/null 2>&1
    return 0
}
trap cleanup EXIT

# linkbase is kernel-shell only; the typist hands over to kshell by itself.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_EXEC_CMD="linkbase" \
TINYOS_EXPECT="LINKBASE done" \
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
if ! printf '%s\n' "$RAW" | grep -q "^LINKBASE done"; then
    echo "RESULT: INCONCLUSIVE — linkbase never completed (typist rc=$TYPIST_RC); see $SERIAL"
    exit 2
fi

field() {  # $1 = line prefix regex, $2 = field name -> value
    printf '%s\n' "$RAW" | grep -E "^$1" | head -1 | tr ' ' '\n' | sed -n "s/^$2=//p" | head -1
}
HELLO_LINE=$(printf '%s\n' "$RAW" | grep -E "^LINKBASE hello" | head -1)
BASE=$(field "LINKBASE hello base=" base)
PAGES=$(field "LINKBASE hello base=" pages)
MAPPED=$(field "LINKBASE hello base=" mapped)
SHADOWED=$(field "LINKBASE hello base=" shadowed)
CTRL=$(field "LINKBASE control v=" shadowed)
RP_RC=$(field "LINKBASE ramprobe" rc)

echo "  ${HELLO_LINE:-LINKBASE hello: no line}"
echo "  control shadowed=${CTRL:-?}"
echo "  ramprobe rc=${RP_RC:-?}"

# Controls first: if these fail, the assertions below grade nothing.
if [ -z "$PAGES" ] || [ "$PAGES" -eq 0 ] || [ "${MAPPED:-x}" != "$PAGES" ]; then
    echo "RESULT: FAIL — /hello.elf did not load with every image page mapped (${HELLO_LINE:-no hello line})"
    exit 1
fi
if [ "${CTRL:-x}" != 1 ]; then
    echo "RESULT: INCONCLUSIVE — the control mapping did not read as shadowed; the probe cannot see a shadow"
    exit 2
fi

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }

if [ "${SHADOWED:-x}" != 0 ]; then
    fail "$SHADOWED of $PAGES /hello.elf pages (base $BASE) replace a kernel identity-map PTE"
fi
case "${RP_RC:-x}" in
    -[0-9]*) ;;
    *) fail "/ramprobe.elf, linked at 0x0C000000 inside RAM, was loaded (rc=${RP_RC:-?})" ;;
esac
if ! printf '%s\n' "$RAW" | grep -qiE "SECURITY: Segment [0-9]+ at 0x0*c000000 is inside the kernel RAM map"; then
    fail "no loader refusal line for /ramprobe.elf's segment at 0x0C000000"
fi
if printf '%s\n' "$RAW" | grep -q "RAMPROBE ran"; then
    fail "/ramprobe.elf ran"
fi

if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS assertion(s); see $SERIAL (typist rc=$TYPIST_RC)"
    exit 1
fi
echo "RESULT: PASS — /hello.elf at $BASE shadows 0 of $PAGES pages (control shadows 1); /ramprobe.elf inside RAM is refused"
exit 0
