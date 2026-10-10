#!/usr/bin/env bash
#
# verify-protected-path-match.sh -- vfs_path_is_protected() matches a protected
# entry as "exact-equal OR entry-followed-by-'/'", never a bare prefix.
# Source-level + host-compiled truth table, no guest.
#
# WHY THIS MATTERS. vfs_path_is_protected() is the CAP_SYS_ADMIN gate for
# create/open(write)/mkdir/rmdir/unlink and redirect under /bin /sbin /etc /boot
# and the /kernel file (syscall.c + vfs.c callers all pass the CANONICAL path).
# The pre-fix shape was a bare strncmp against slash-suffixed entries:
#
#     protected_paths[] = { "/bin/", "/sbin/", "/etc/", "/boot/", "/kernel", ... }
#     if (strncmp(canonical, protected_paths[i], strlen(protected_paths[i])) == 0)
#
# That had two boundary bugs:
#   - UNDER-match: the canonical form of the directory node itself is "/etc"
#     (no trailing slash), which differs from "/etc/" at the NUL -- so a root
#     node literally named "/etc" was NOT seen as protected and dodged the gate.
#   - OVER-match: "/kernel" as a bare prefix also flagged "/kernelfoo" (fails
#     safe -- it denies -- but is still wrong).
#
# The fix drops the trailing slashes and requires the char after the match to be
# end-of-string or '/'. This harness proves the boundary two ways and refuses to
# pass vacuously.
#
# WHY HOST-COMPILED. The function is pure (strncmp/strlen over a static list),
# so the strongest proof is to compile the SHIPPING body with a host cc and
# drive the full truth table -- /etc and /etc/passwd protected, /etcfoo and
# /kernelfoo NOT. tools/protected_path_test.c holds the harness; this script
# extracts the real vfs_path_is_protected() body from src/vfs.c and injects it,
# so the test exercises the shipping logic, not a copy. The test's own pre-fix
# arm replays the bare-prefix shape as a negative control and returns exit 2
# (INCONCLUSIVE) unless that shape demonstrably gets the two boundary cases
# wrong -- the same discipline as verify-shell-path-overflow.sh.
set -u

cd "$(dirname "$0")/.." || exit 2

PASS=0; FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "=== verify-protected-path-match.sh ==="
echo

CC="${CC:-cc}"
if ! command -v "$CC" >/dev/null 2>&1; then
    echo "  SKIP: no host C compiler ($CC) -- cannot run the boundary proof" >&2
    echo "RESULT: FAIL"; exit 1
fi

# --- 1. source-level: the shipping match shape is exact-or-slash, not a bare
#        prefix. Assert both the entry-char guard and that no slash-suffixed
#        entry survives in the list (the pre-fix shape is gone). ----------------
fn="$(awk '
    /^bool vfs_path_is_protected\(/ { f=1 }
    f { print }
    f && /^}/ { exit }
' src/vfs.c)"

if [ -z "$fn" ]; then
    bad "could not locate vfs_path_is_protected() in src/vfs.c"
    echo "RESULT: FAIL"; exit 1
fi

if printf '%s\n' "$fn" | grep -qE "canonical\[len\] == '\\\\0'" \
   && printf '%s\n' "$fn" | grep -qE "canonical\[len\] == '/'"; then
    ok "match requires the next char to be end-of-string or '/' (exact-or-slash)"
else
    bad "match does not guard the char after the entry -- bare prefix shape"
    printf '%s\n' "$fn" | sed 's/^/       /'
fi

# NEGATIVE CONTROL (source): a slash-suffixed entry like "/etc/" as a LIST
# ELEMENT is the pre-fix under-matching shape. Match only an array element
# (optional leading whitespace, the quoted string, then a comma), so the "/etc/"
# that appears in the explanatory comment prose above does not trip it.
if printf '%s\n' "$fn" | grep -qE '^[[:space:]]*"/(bin|sbin|etc|boot)/"[[:space:]]*,'; then
    bad "a slash-suffixed protected entry survives (pre-fix under-match shape)"
    printf '%s\n' "$fn" | grep -nE '^[[:space:]]*"/(bin|sbin|etc|boot)/"[[:space:]]*,' | sed 's/^/       /'
else
    ok "no slash-suffixed entry in the list (the under-matching shape is gone)"
fi

# --- 2. host-compiled truth table against the REAL extracted body. ------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Inject the extracted body in place of the stand-alone fallback: define the
# guard macro so the fallback is compiled out, then append the real function.
{
    echo "#define PROTECTED_FN_INJECTED 1"
    cat tools/protected_path_test.c
    echo
    echo "/* --- injected verbatim from src/vfs.c by verify-protected-path-match.sh --- */"
    printf '%s\n' "$fn"
} > "$tmp/test.c"

if ! "$CC" -O0 -std=c11 -Wall -o "$tmp/t" "$tmp/test.c" 2>"$tmp/cc.err"; then
    bad "could not compile the boundary proof with the extracted body"
    sed -n '1,8p' "$tmp/cc.err" | sed 's/^/       /'
    echo "RESULT: FAIL"; exit 1
fi

set +e
"$tmp/t" > "$tmp/out" 2>&1
rc=$?
set -e
sed 's/^/       /' "$tmp/out"

case "$rc" in
    0) ok "truth table holds AND the pre-fix bare-prefix shape is demonstrably wrong" ;;
    1) bad "the shipping vfs_path_is_protected() gets a truth-table case wrong" ;;
    2) bad "INCONCLUSIVE: the pre-fix negative control is not discriminating" ;;
    *) bad "boundary proof exited with unexpected status $rc" ;;
esac

echo
echo "================ VERDICT ================"
echo "  passed: $PASS   failed: $FAIL"
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: PASS -- the protected-path gate matches exact-or-slash; the"
    echo "  directory node itself is protected and a same-prefix sibling is not."
    exit 0
else
    echo "RESULT: FAIL"
    exit 1
fi
