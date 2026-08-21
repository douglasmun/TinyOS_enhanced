#!/usr/bin/env bash
#==============================================================================
# verify-shell-path-overflow.sh
#
# Covers the one-byte path-append overflow in the kernel shell's three
# path-building sites (src/shell_fileops.c): cmd_cd, cmd_cat, cmd_exec. Each
# copies the cwd into a MAX_PATH buffer, appends a separator, appends the
# argument, then writes the terminator. Reserving only 1 byte for the cwd copy
# lets the separator consume it, so the terminator lands at buf[MAX_PATH] --
# one byte past the array, on the kernel task stack.
#
# WHY THIS HARNESS IS NOT A QEMU BOOT
# -----------------------------------
# Every other harness in this tree drives the kernel and reads a counter or a
# console line. This one deliberately does not, and that is the finding about
# the finding: a single byte written past a local array lands on whatever the
# compiler placed next. Often that is alignment padding, in which case the
# kernel boots, cd works, nothing faults, and a boot-based harness reports PASS
# against the completely unfixed kernel. The overflow is real and the fix is
# real, but the *symptom* is not reliably observable from outside, so a boot
# harness here would be decoration -- it would pass for reasons unrelated to
# whether the bug is present.
#
# So this harness proves the property at the level the bug actually lives at:
#
#   Leg 1 (source guard)  -- all three sites still reserve 2 bytes for the cwd
#                            copy. Cheap, and it is what actually regresses:
#                            the fix is a single character per site, trivially
#                            undone by a later edit that "tidies" the constant.
#   Leg 2 (boundary proof) -- tools/path_bound_test.c replays the loop shape
#                            with a canary immediately after the array, built
#                            with the HOST compiler so the canary is readable.
#                            Run with both constants: the pre-fix arm MUST
#                            clobber it and the post-fix arm MUST NOT. The
#                            pre-fix arm is the negative control -- without it,
#                            "canary intact" is satisfied by a test that never
#                            writes anything, and by padding absorbing the
#                            write. path_bound_test.c reports INCONCLUSIVE
#                            (exit 2) in that second case rather than passing.
#
# Leg 1 without leg 2 asserts a constant with no evidence the constant matters.
# Leg 2 without leg 1 proves the arithmetic while the kernel ships something
# else. Both, or neither is worth much.
#==============================================================================
set -u

REPO="$(cd "$(dirname "$0")" && pwd)"
SRC="$REPO/src/shell_fileops.c"
TEST_C="$REPO/tools/path_bound_test.c"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tinyos-pathovf.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

RC=0
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; RC=1; }
info() { printf '        %s\n' "$1"; }

echo "=== verify-shell-path-overflow.sh ==="
echo

for f in "$SRC" "$TEST_C"; do
    [ -r "$f" ] || { echo "FATAL: missing $f"; exit 2; }
done

#-----------------------------------------------------------------------------
# Leg 1: source guard -- the cwd-copy loop at each site reserves 2 bytes.
#
# Matched per-site rather than by one repo-wide grep: cmd_cat's buffer has a
# different name (full_path) and its separator write is conditional, so a
# single pattern would either miss it or match too loosely. The counts are
# exact -- "at least one" would pass with one site reverted.
#-----------------------------------------------------------------------------
echo "Leg 1: source guard (all three cwd-copy loops reserve 2 bytes)"

check_site() {
    local label="$1" pattern="$2" want="$3"
    local n
    n=$(grep -cE "$pattern" "$SRC")
    if [ "$n" -eq "$want" ]; then
        pass "$label: reserve-2 cwd copy present ($n)"
    else
        fail "$label: expected $want reserve-2 cwd copy, found $n"
        info "pattern: $pattern"
    fi
}

# cmd_cd and cmd_exec: identical shape, distinct buffers.
check_site "cmd_cd"   'current_dir\[i\] != .\\0. && pos < sizeof\(new_path\) - 2' 1
check_site "cmd_exec" 'current_dir\[i\] != .\\0. && pos < sizeof\(abs_path\) - 2' 1
# cmd_cat: while-loop over current_dir[j], buffer full_path.
check_site "cmd_cat"  'current_dir\[j\] != .\\0. && offset < sizeof\(full_path\) - 2' 1

# The absolute-path branches of cmd_cd/cmd_exec also reserve 2 (they append a
# terminator after their own loop). Guarded so a revert there is caught too.
check_site "cmd_cd abs"   'path\[i\] != .\\0. && i < sizeof\(new_path\) - 2' 1
check_site "cmd_exec abs" 'path\[i\] != .\\0. && i < sizeof\(abs_path\) - 2' 1

# Negative: no cwd-copy loop anywhere still reserves only 1.
if grep -nE '(current_dir\[[ij]\] != .\\0.).*(sizeof\([a-z_]*path\) - 1)' "$SRC" >/dev/null; then
    fail "a cwd-copy loop still reserves only 1 byte:"
    grep -nE '(current_dir\[[ij]\] != .\\0.).*(sizeof\([a-z_]*path\) - 1)' "$SRC" | sed 's/^/        /'
else
    pass "no cwd-copy loop reserves only 1 byte"
fi
echo

#-----------------------------------------------------------------------------
# Leg 2: boundary proof, both arms.
#-----------------------------------------------------------------------------
echo "Leg 2: boundary proof (canary replay, pre-fix arm as negative control)"

CC_BIN="${CC:-cc}"
if ! command -v "$CC_BIN" >/dev/null 2>&1; then
    fail "no host compiler ($CC_BIN) -- cannot run the boundary proof"
    info "leg 1 alone asserts a constant with no evidence it matters"
    echo; echo "RESULT: FAIL"; exit 1
fi

# -O0: the canary is only observable if the compiler does not reorder or
# register-allocate it away. Optimisation is free to do both.
if ! "$CC_BIN" -O0 -o "$WORK/pbt" "$TEST_C" 2>"$WORK/cc.err"; then
    fail "boundary test failed to compile"
    sed 's/^/        /' "$WORK/cc.err"
    echo; echo "RESULT: FAIL"; exit 1
fi

"$WORK/pbt" >"$WORK/pbt.out" 2>&1
PBT_RC=$?
sed 's/^/        /' "$WORK/pbt.out"

case "$PBT_RC" in
    0)
        pass "pre-fix reserve overflows; post-fix reserve does not"
        ;;
    1)
        fail "post-fix reserve STILL writes past the array"
        ;;
    2)
        fail "INCONCLUSIVE: neither arm clobbered the canary"
        info "padding absorbed the write, so this build cannot witness the bug."
        info "Not scored as a pass: a silent-padding run is exactly the case"
        info "that makes a boot-based harness report a false PASS."
        ;;
    *)
        fail "boundary test exited $PBT_RC (unexpected)"
        ;;
esac
echo

if [ "$RC" -eq 0 ]; then
    echo "RESULT: PASS"
else
    echo "RESULT: FAIL"
fi
exit "$RC"
