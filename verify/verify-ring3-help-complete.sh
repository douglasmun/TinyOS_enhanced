#!/usr/bin/env bash
#
# verify-ring3-help-complete.sh — every builtin the ring-3 shell dispatches is
# listed by its `help`.
#
# WHY: eight builtins (clear, history, jobs, grep, find, man, unalias, whoami)
# were added to dispatch() without a help line, so `help` -- the only way a
# user discovers what this shell runs -- under-reported it for several
# releases. Nothing booted catches that: verify-ring3-builtins.sh runs each
# builtin, it does not read help.
#
# HOW (no guest needed): collect every name dispatch() compares `cmd` against,
# then require a help line that starts with that name ("  name" followed by a
# space, or "exit / logout" for the pair). Source-only, so CI can run it.
#
# Exit 0 = PASS, 1 = FAIL, 3 = INCONCLUSIVE (could not parse the source).
set -uo pipefail
cd "$(dirname "$0")/.."

SRC=userspace/shell.c
[ -f "$SRC" ] || { echo "RESULT: INCONCLUSIVE — $SRC not found"; exit 3; }

# The help text: the string literals inside cmd_help(), one per line.
HELP=$(tr -d '\r' < "$SRC" | awk '/^static void cmd_help\(void\)/{on=1} on{print} on&&/^}/{exit}')
[ -n "$HELP" ] || { echo "RESULT: INCONCLUSIVE — cmd_help() not found in $SRC"; exit 3; }

# The builtins: strcmp(cmd, "name") inside dispatch's region. The credential
# predicate (is_cred_cmd) repeats passwd/useradd/userdel; they are builtins too.
NAMES=$(tr -d '\r' < "$SRC" | grep -o 'strcmp(cmd, "[a-z]*")' | sed 's/.*"\(.*\)".*/\1/' | sort -u)
COUNT=$(printf '%s\n' "$NAMES" | grep -c .)
[ "$COUNT" -ge 30 ] || { echo "RESULT: INCONCLUSIVE — parsed only $COUNT builtin names"; exit 3; }

MISSING=""
for n in $NAMES; do
    if printf '%s\n' "$HELP" | grep -qE "^[[:space:]]*\"  $n( |\\\\n)"; then
        continue
    fi
    # "exit / logout" documents both on one line.
    if printf '%s\n' "$HELP" | grep -qE "^[[:space:]]*\"  exit / logout " &&
       { [ "$n" = exit ] || [ "$n" = logout ]; }; then
        continue
    fi
    MISSING="$MISSING $n"
done

if [ -n "$MISSING" ]; then
    echo "RESULT: FAIL — dispatched but not in help:$MISSING"
    exit 1
fi
echo "RESULT: PASS — all $COUNT dispatched builtins are listed by help"
exit 0
