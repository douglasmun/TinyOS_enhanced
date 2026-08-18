#!/usr/bin/env bash
#==============================================================================
# verify-elf-enforce-report.sh -- `secstatus` must report the REAL ELF gate.
#
# THE BUG THIS LOCKS DOWN
#
# `secstatus` printed "ELF signatures ...... ENFORCED (fail-closed)" from
# secure_boot_is_enforced(). That function cannot return false: secure_boot_init()
# ORs SECURE_BOOT_FLAG_ENFORCE in whenever the caller omits it (secure_boot.c),
# and kernel.c omits it. Meanwhile the ACTUAL gate is elf_require_signatures in
# elf_load_process(), set by #ifdef ELF_PERMISSIVE_SIGNATURES in elf.c.
#
# So a -DELF_PERMISSIVE_SIGNATURES build -- which warns and LOADS unsigned
# binaries -- still displayed "ENFORCED (fail-closed)". A status surface that
# structurally cannot report the state it names, the same class of gap as the
# IDS "signatures loaded" count that read as protection.
#
# WHY THIS IS NOT A BOOT HARNESS
#
# The defect is a BUILD-MODE difference. A single boot only ever exercises one
# mode, so it cannot witness the divergence at all -- a boot harness would have
# passed against the broken code for as long as it only ever tested the default
# build. Proving it needs BOTH modes compared, so this asserts on the linked
# kernel's object code, where the constant is unambiguous and no typist,
# keymap, or serial timing can flake.
#
# THE ASSERTION: default build -> accessor returns 1
#                permissive   -> accessor returns 0
#                and secstatus sources its line from THAT accessor, not from
#                secure_boot_is_enforced().
#
# The third leg is the load-bearing one: legs 1-2 alone pass against a kernel
# where the accessor is perfect but secstatus still calls the wrong function.
#==============================================================================
set -uo pipefail
cd "$(dirname "$0")"

OBJDUMP="${OBJDUMP:-i686-elf-objdump}"
FAILED=0

# The permissive build leaves objects compiled with a flag that is NOT in the
# dependency graph; leaving them poisons every other harness at link time.
trap 'make clean >/dev/null 2>&1' EXIT

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; shift; for l in "$@"; do echo "        $l"; done; FAILED=1; }

command -v "$OBJDUMP" >/dev/null 2>&1 || {
    echo "RESULT: INCONCLUSIVE - $OBJDUMP not found"; exit 3; }

# --- Leg 3 first: it is pure source inspection and needs no build -----------
# secstatus must read the elf.c accessor. If it still calls
# secure_boot_is_enforced(), legs 1-2 can both pass while the display lies.
if grep -q 'elf_enforced = elf_signatures_enforced()' src/shell_system.c; then
    pass "secstatus sources its ELF line from elf_signatures_enforced()"
else
    fail "secstatus does NOT call elf_signatures_enforced()" \
         "Expected 'elf_enforced = elf_signatures_enforced();' in shell_system.c." \
         "If it reads secure_boot_is_enforced() again, the line is hardwired" \
         "to ENFORCED and this whole fix has been reverted."
fi

# The #ifdef must exist in exactly ONE file. Two copies drift apart, and the
# drift reintroduces the lie silently.
# Match the PREPROCESSOR TEST, not the string: elf.h and the comments in elf.c
# both name the macro in prose, and counting mentions reported 2 files against
# correct code on this harness's first run.
IFDEF_FILES=$(grep -rlE '^[[:space:]]*#[[:space:]]*(ifdef|if defined\(|ifndef)[[:space:]]*ELF_PERMISSIVE_SIGNATURES' src/ 2>/dev/null | sort | tr '\n' ' ')
IFDEF_COUNT=$(grep -rlE '^[[:space:]]*#[[:space:]]*(ifdef|if defined\(|ifndef)[[:space:]]*ELF_PERMISSIVE_SIGNATURES' src/ 2>/dev/null | wc -l | tr -d ' ')
if [ "$IFDEF_COUNT" -eq 1 ]; then
    pass "ELF_PERMISSIVE_SIGNATURES is #ifdef-tested in exactly one file ($IFDEF_FILES)"
else
    fail "ELF_PERMISSIVE_SIGNATURES appears in $IFDEF_COUNT files: $IFDEF_FILES" \
         "Keep the gate in elf.c only. A second copy is how the status line and" \
         "the real gate drift back apart."
fi

# --- Extract the accessor's return value from a linked kernel --------------
# Reads the actual instruction bytes, not source: this is what the CPU runs.
accessor_returns() {
    local dis
    dis=$("$OBJDUMP" -d kernel.elf --disassemble=elf_signatures_enforced 2>/dev/null)
    [ -z "$dis" ] && { echo "ABSENT"; return; }
    if echo "$dis" | grep -qE 'xor +%eax,%eax'; then echo 0
    elif echo "$dis" | grep -qE 'mov +\$0x1,%eax'; then echo 1
    else echo "UNKNOWN"; fi
}

echo "building default (enforce) ..."
make clean >/dev/null 2>&1
if ! make -j8 kernel.elf >/dev/null 2>&1; then
    echo "RESULT: INCONCLUSIVE - default build failed"; exit 3
fi
DEFAULT_RET=$(accessor_returns)
if [ "$DEFAULT_RET" = "1" ]; then
    pass "default build: elf_signatures_enforced() returns 1 (ENFORCED)"
else
    fail "default build: accessor returned '$DEFAULT_RET', expected 1" \
         "A default build MUST be fail-closed."
fi

echo "building -DELF_PERMISSIVE_SIGNATURES ..."
make clean >/dev/null 2>&1
if ! make -j8 kernel.elf EXTRA_CFLAGS="-DELF_PERMISSIVE_SIGNATURES" >/dev/null 2>&1; then
    echo "RESULT: INCONCLUSIVE - permissive build failed"; exit 3
fi
PERM_RET=$(accessor_returns)
if [ "$PERM_RET" = "0" ]; then
    pass "permissive build: elf_signatures_enforced() returns 0 (PERMISSIVE)"
else
    fail "permissive build: accessor returned '$PERM_RET', expected 0" \
         "This is the original bug: the opt-out is set, unsigned binaries load," \
         "and the status surface still claims ENFORCED (fail-closed)."
fi

# The two must DIFFER. A constant-true and a constant-false accessor are each
# individually plausible; only the divergence proves the flag is wired.
echo ""
if [ "$DEFAULT_RET" = "1" ] && [ "$PERM_RET" = "0" ]; then
    pass "the two builds DISAGREE (1 vs 0) -- the flag is actually wired"
else
    fail "the builds did not diverge (default=$DEFAULT_RET permissive=$PERM_RET)" \
         "If both agree, the accessor ignores ELF_PERMISSIVE_SIGNATURES and" \
         "secstatus is reporting a constant again."
fi

echo ""
echo "================ VERDICT ================"
if [ "$FAILED" -eq 0 ]; then
    echo "RESULT: PASS - secstatus reports the real ELF signature gate"
    exit 0
else
    echo "RESULT: FAIL - the ELF enforcement readout does not track the real gate"
    exit 1
fi
