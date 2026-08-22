#!/usr/bin/env bash
# =============================================================================
# verify-kprintf-zu.sh — kprintf must render %zu as a NUMBER, not as literal
# text, and must not shift the arguments that follow it.
#
# THE BUG
#
# kprintf's length-modifier parser (src/kprintf.c, "STEP 3") handled 'l' and
# 'll' but not 'z'. A "%zu" therefore left c=='z' to reach the conversion
# switch's DEFAULT arm, which prints "%z" literally and -- the half that
# actually bites -- does NOT consume the vararg. Every argument after it then
# shifted by one position.
#
# dns.c:201 shows both halves at once, because its %zu comes first:
#
#   kprintf("[DNS] SECURITY: Domain name too long (%zu > %d bytes)...",
#           domain_len, MAX_DOMAIN_NAME_LEN);
#
# printed "(%zu > 300 bytes)" instead of "(300 > 253 bytes)": the literal
# specifier, and then %d consuming domain_len so the LIMIT field displayed the
# offending LENGTH. Several of the 14 live sites are security-rejection
# messages -- exactly the output someone reads when diagnosing a refusal.
#
# WHY -Wformat DID NOT CATCH IT, AND WHY A COMPILE TEST CANNOT
#
# The format strings are valid C. GCC checks them against real printf
# semantics, where %zu is correct, so it has nothing to report; the defect is
# entirely on the implementation side. That is also why this harness must BOOT:
# the assertion is about what the kernel's own formatter emits at runtime, and
# no build-time check can see it.
#
# WHAT IS MEASURED, AND WHY IT NEEDS NO FAULT INJECTION
#
# elf.c:486 runs on EVERY process load:
#
#   kprintf("[ELF] Loading process '%s' (file size: %zu bytes)...\n", ...)
#
# so a plain boot exercises it several times before the shell even appears
# (shell.elf itself is loaded this way). No injection, no special netdev, no
# typed command is required -- which makes this one of the cheapest harnesses
# in the suite and means it cannot fail for an unrelated environmental reason.
#
# THE TWO LEGS, AND WHY BOTH ARE NEEDED
#
#   1. NEGATIVE: no line in the log contains a literal "%z". This is the
#      symptom the bug prints, and on an unfixed tree it appears on every boot.
#   2. POSITIVE: the ELF loader line reports an actual byte count. Leg 1 alone
#      is satisfied by a kernel that never reaches the site at all -- if the
#      message were deleted, or the load path never ran, "no %z anywhere" is
#      trivially true. Leg 2 is what proves the site was reached AND rendered.
#
# That pairing is the point. A %z-free log is not evidence of a working
# formatter; a %z-free log WITH a rendered number is.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.  Log: kprintfzu.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=kprintfzu.log
TRACE=kprintfzu-trace.log
RUN_DISK=/tmp/tinyos-kprintfzu-disk.img
MON_SOCK=/tmp/tinyos-kprintfzu-mon.sock

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

# ---------------------------------------------------------------------------
# SOURCE GUARDS -- the shape of the fix, not merely that the file changed.
# ---------------------------------------------------------------------------
# Scan the STEP 3 block rather than the whole file: a bare grep for "'z'"
# matches character-class tests like (c >= 'a' && c <= 'z') in half a dozen
# files, and would report a fixed parser on a tree that never touched it.
sed -n "/STEP 3: PARSE LENGTH MODIFIER/,/STEP 4/p" src/kprintf.c \
    | grep -q "\*p == 'z'" \
    || guard_fail "src/kprintf.c's length-modifier parser does not accept 'z',
  so the tree predates the fix and both legs below would report the bug
  correctly -- but as a kernel FAIL rather than as 'this tree is unfixed'."

# The site the positive leg reads must still exist and still use %zu. If it is
# ever reworded, leg 2 fails for a reason that has nothing to do with the
# formatter, and this says so up front.
grep -q "Loading process '%s' (file size: %zu bytes)" src/elf.c \
    || guard_fail "src/elf.c no longer prints the 'Loading process ... file
  size: %zu bytes' line this harness reads, so the positive leg has no
  witness. Re-point it at another live %zu site."

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

echo "==> Booting headless"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 \
    -device e1000,netdev=net0 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!
cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# One exec so a USER-driven load is covered too, not only the boot-time
# shell.elf load. Both go through elf_load_process_argv().
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_EXEC_CMD="exec /hello.elf" \
TINYOS_EXPECT="Hello from ELF" \
python3 tools/qemu_typist.py
RC=$?
sleep 2
cleanup
trap - EXIT

echo ""
echo "================ VERDICT ================"

[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$RC)"; exit 2; }

CLEAN=$(tr -d '\r' < "$SERIAL")

# --- Leg 1 (negative): the symptom must be absent ------------------------
# Match a literal '%z' followed by a conversion letter. Bare '%z' would also
# match this harness's own name if it ever appeared in the log.
ZU_HITS=$(printf '%s\n' "$CLEAN" | grep -c '%z[udixX]')
if [ "$ZU_HITS" -ne 0 ]; then
    echo "RESULT: FAIL — kprintf emitted a literal %z $ZU_HITS time(s)"
    echo "  The length-modifier parser is not consuming 'z', so the specifier"
    echo "  prints as text AND the vararg it should have consumed is left for"
    echo "  the next conversion -- every argument after it is shifted."
    echo "  --- offending lines ---"
    printf '%s\n' "$CLEAN" | grep -n '%z[udixX]' | head -10
    exit 1
fi

# --- Leg 2 (positive control): the site was actually reached -------------
# Without this, leg 1 passes against a kernel that deleted the message or
# never loaded a process at all.
LOADLINE=$(printf '%s\n' "$CLEAN" | grep "\[ELF\] Loading process" | head -1)
if [ -z "$LOADLINE" ]; then
    echo "RESULT: INCONCLUSIVE — no '[ELF] Loading process' line in the log."
    echo "  Leg 1 found no literal %z, but nothing exercised the site, so that"
    echo "  proves nothing about the formatter."
    exit 3
fi

SIZE=$(printf '%s\n' "$LOADLINE" | sed -n 's/.*file size: \([0-9][0-9]*\) bytes.*/\1/p')
if [ -z "$SIZE" ] || [ "$SIZE" -le 0 ]; then
    echo "RESULT: FAIL — the ELF loader line carries no rendered byte count"
    echo "  Line: $LOADLINE"
    echo "  Expected 'file size: <number> bytes'. A %zu that renders as empty"
    echo "  or zero means the argument was consumed with the wrong width."
    exit 1
fi

N_LOADS=$(printf '%s\n' "$CLEAN" | grep -c "\[ELF\] Loading process")
echo "  literal %z occurrences: 0"
echo "  ELF loads seen:         $N_LOADS"
echo "  first rendered size:    $SIZE bytes"
echo ""
echo "RESULT: PASS"
echo "  kprintf rendered %zu as a number across $N_LOADS process load(s) and"
echo "  emitted no literal %z anywhere in the boot."
exit 0

# VALIDATION LOG
#
# Negative control (2026-08-22): against the tree at 44b056c, i.e. BEFORE
# 88258c0 added 'z' to the parser, every boot serial log in the batch carried
#   [ELF] Loading process 'shell.elf' (file size: %zu bytes)...
# so leg 1 fires on real captured output, not on a synthetic case. Both the
# boot-time shell.elf load and the user-driven hello.elf load show it.
