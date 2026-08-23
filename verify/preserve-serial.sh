# preserve-serial.sh -- keep a failing run's serial log instead of deleting it.
#
# Source this, then replace a trap that unconditionally removes $WORK, e.g.
#
#     trap 'cleanup_qemu; rm -rf "$WORK"' EXIT
# with
#     trap 'rc=$?; cleanup_qemu; preserve_serial "$SERIAL" "" "$rc"; rm -rf "$WORK"' EXIT
#
# preserve_serial copies the log out of $WORK to a stable path and prints where,
# but ONLY when the script is exiting non-zero -- a passing run still leaves no
# litter behind.
#
# CAPTURE $? AS THE FIRST THING THE TRAP DOES, and pass it in. Any command that
# runs earlier in the trap -- cleanup_qemu in all three call sites -- succeeds
# and overwrites $?, so a helper that reads $? itself sees 0 and silently
# preserves nothing on exactly the runs that needed it. This was caught by an
# end-to-end test; the unit tests missed it because they called preserve_serial
# first in the trap.
#
# WHY THIS EXISTS
# ---------------
# Three QEMU harnesses put their serial log inside a mktemp -d work dir and
# rm -rf'd it from an EXIT trap. That trap fires on FAILURE too, so the one
# artifact that explains a failure was destroyed before anyone could read it.
#
# That is not hypothetical. Issue #126 is a boot panic that reproduces only
# under some harnesses, and PR #128 added exactly the diagnostics (faulting
# PID/name, kernel ESP, stack words) needed to identify it. Those diagnostics
# are printed to the serial log -- the file these traps deleted. A harness that
# discards its own evidence turns a diagnosable panic back into a mystery.
#
# Keyed on the exit status, not on a parsed verdict: a harness that dies on
# set -e, a QEMU timeout, or a typist TIMEOUT never prints a verdict at all,
# and those are precisely the runs whose log is worth keeping.
preserve_serial() {
    local rc="${3:-$?}"
    local src="$1"
    local dest="${2:-}"

    [ "$rc" -eq 0 ] && return 0
    [ -n "$src" ] && [ -s "$src" ] || return 0

    if [ -z "$dest" ]; then
        dest="${TMPDIR:-/tmp}/tinyos-failed-$(basename "$0" .sh).serial.log"
    fi

    if cp "$src" "$dest" 2>/dev/null; then
        echo "serial log preserved (exit $rc): $dest" >&2
    fi
    return 0
}
