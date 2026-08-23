#!/usr/bin/env bash
# Unit tests for verify/preserve-serial.sh.
#
# The bug these exist for: an EXIT trap's $? is only intact until the trap's
# FIRST command runs. All three real call sites run cleanup_qemu first, which
# succeeds and resets $? to 0 -- so a helper reading $? itself preserves nothing
# on failing runs. Tests 1 and 2 therefore use the REAL trap shape (a preceding
# successful command), not the simplified one.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0; FAIL=0
TMP="$(mktemp -d "${TMPDIR:-/tmp}/preserve-serial-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

check() { # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  ok   $1"
    else FAIL=$((FAIL+1)); echo "  FAIL $1: expected '$2' got '$3'"; fi
}

run_case() { # run_case <exit-code> <preceding-cmd> <dest> [--empty]
    local rc="$1" pre="$2" dest="$3" empty="${4:-}"
    cat > "$TMP/case.sh" <<CASE
set -e
WORK=\$(mktemp -d "$TMP/work.XXXXXX")
SERIAL="\$WORK/serial.log"
. "$HERE/preserve-serial.sh"
$pre
trap 'rc=\$?; noise; preserve_serial "\$SERIAL" "$dest" "\$rc"; rm -rf "\$WORK"' EXIT
CASE
    if [ "$empty" = "--empty" ]; then
        echo ': > "$SERIAL"' >> "$TMP/case.sh"
    else
        echo 'printf "PAGE FAULT\nTask: PID=3 edr_daemon\n" > "$SERIAL"' >> "$TMP/case.sh"
    fi
    echo "exit $rc" >> "$TMP/case.sh"
    bash "$TMP/case.sh" 2>/dev/null
    return $?
}

echo "preserve-serial.sh unit tests"

# 1. Failure with a SUCCEEDING command ahead of preserve_serial (the real shape).
rm -f "$TMP/d1.log"
run_case 1 'noise() { :; }' "$TMP/d1.log"
got=$?
check "failing run preserves the log" "yes" "$([ -s "$TMP/d1.log" ] && echo yes || echo no)"
check "failing run keeps its exit code" "1" "$got"
check "preserved content is the serial log" "yes" \
    "$(grep -q 'PAGE FAULT' "$TMP/d1.log" 2>/dev/null && echo yes || echo no)"

# 2. Success must leave nothing behind.
rm -f "$TMP/d2.log"
run_case 0 'noise() { :; }' "$TMP/d2.log"
got=$?
check "passing run preserves nothing" "no" "$([ -e "$TMP/d2.log" ] && echo yes || echo no)"
check "passing run keeps exit 0" "0" "$got"

# 3. An empty serial log is not worth copying.
rm -f "$TMP/d3.log"
run_case 2 'noise() { :; }' "$TMP/d3.log" --empty
check "empty log is skipped" "no" "$([ -e "$TMP/d3.log" ] && echo yes || echo no)"

# 4. A missing source file must not break the rest of the trap.
rm -f "$TMP/d4.log"
cat > "$TMP/case4.sh" <<CASE
. "$HERE/preserve-serial.sh"
trap 'rc=\$?; preserve_serial "$TMP/nonexistent.log" "$TMP/d4.log" "\$rc"; echo TRAP_COMPLETED' EXIT
exit 5
CASE
out="$(bash "$TMP/case4.sh" 2>/dev/null)"; got=$?
check "missing source does not abort the trap" "TRAP_COMPLETED" "$out"
check "missing source keeps the exit code" "5" "$got"

# 5. Negative control: a helper reading $? itself would fail test 1. Prove the
#    preceding-command clobber is real, so test 1 cannot silently stop testing it.
rm -f "$TMP/d5.log"
cat > "$TMP/case5.sh" <<CASE
. "$HERE/preserve-serial.sh"
noise() { :; }
trap 'noise; preserve_serial "$TMP/src5.log" "$TMP/d5.log"; :' EXIT
printf 'x\n' > "$TMP/src5.log"
exit 1
CASE
bash "$TMP/case5.sh" >/dev/null 2>&1
check "control: \$?-reading form is clobbered by a preceding command" "no" \
    "$([ -e "$TMP/d5.log" ] && echo yes || echo no)"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "RESULT: PASS"
