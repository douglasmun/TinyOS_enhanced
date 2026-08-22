#!/usr/bin/env bash
#
# verify-env-pertask.sh — FULLY AUTOMATED check that the env/alias subsystem is
# LIVE and that its storage is PER-TASK.
#
# WHAT THIS IS TESTING
#
# Two separate claims, which fail in different ways and so need different
# assertions:
#
#   (A) THE SUBSYSTEM RUNS AT ALL. env_init() sat commented out in kernel.c
#       ("TEMPORARILY DISABLED FOR TESTING") from the initial public release
#       onward. Every consumer was wired the whole time -- alias substitution
#       in shell.c, $VAR expansion, all six builtins dispatched -- so the
#       commands existed, ran, and reported "(no variables)" / "(no aliases)"
#       forever. Nothing errored. A harness that only checks "the env command
#       exists" passes against that dead build, which is exactly how this
#       survived so long.
#
#   (B) THE TABLES ARE PER-TASK. Storage moved from two file-scope arrays into
#       a pmm_alloc()'d page hanging off task_t. This is the part a shell-level
#       test CANNOT see, and the reason leg 6 delegates to a kernel self-test.
#
# THE FALSE PASS THIS IS BUILT TO AVOID
#
# "I set FOO=bar and then read FOO=bar back" is the obvious test and it proves
# almost nothing here -- it passes against the global table this PR replaced,
# and it would pass against per-uid storage too. Witnessing isolation needs a
# SECOND TASK, and nothing reachable from the shell in this build provides one:
#
#   - `su otheruser` changes credentials on the SAME task, so both "users" share
#     one env page. A "the other user cannot see my variable" leg written that
#     way would FAIL against correct per-task code and pass against per-uid.
#   - a logout/login pair needs the typist to re-drive the login sequence, which
#     it does not do -- the followup list simply ends.
#   - ring 3 has no env syscall yet. That is PR B.
#
# So leg 6 asserts on env_pertask_self_test() (TEST 10 of `sectest`), which
# creates a real second kernel task. Its verdict is three-way on purpose: the
# child must not see the parent's variable, the child MUST set one of its own,
# and the parent's must survive. The middle clause is the non-vacuity control --
# a child whose page allocation failed also "sees nothing", and would otherwise
# pass the isolation check for entirely the wrong reason.
#
# WHY THE DEFAULTS ARE CHECKED BY EXPANSION, NOT BY `env`
#
# `env` listing HOME=/ proves the table has a row. Expanding $HOME through the
# command line proves the row is reachable from the path that actually
# consumes it (env_expand at shell.c:564), which is the half that was dead.
# Both are checked; the expansion one is the stronger.
#
# ALIAS CAPACITY
#
# env_init() installs ALIAS_DEFAULT_COUNT (12) of ALIAS_MAX_COUNT (16). The
# previous list was 16 of 16, which filled the table exactly to capacity and
# made every user `alias` fail with "table full" against a table holding
# nothing of theirs. Leg 4 sets a user alias and requires it to WORK, which is
# what catches a regression back to a full default list.
#
# ASSERTIONS
#
#   - $HOME expands to a non-empty value            (subsystem is live; this
#                                                    was empty before the fix)
#   - `env` lists PATH and SHELL                    (defaults installed)
#   - `alias` lists ll, and NOT the dropped `please`(default list is the new 12)
#   - a user-set alias works when invoked           (free slots remain)
#   - a user-set variable expands                   (writes reach the table)
#   - the per-task self-test reports PASS           (PER-TASK -- the whole PR)
#     with its own three-way verdict                 (the absence is non-vacuous)
#   - the inheritance self-test reports PASS        (exported crosses on spawn,
#                                                    un-exported does not)
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.
# Logs: envpertask.log (serial), envpertask-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=envpertask.log
TRACE=envpertask-trace.log
RUN_DISK=/tmp/tinyos-envpertask-disk.img
MON_SOCK=/tmp/tinyos-envpertask-mon.sock

echo "==> Building kernel + ISO..."
make >/dev/null 2>&1 || { echo "RESULT: INCONCLUSIVE — kernel build failed"; exit 3; }
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# Prove the KERNEL half is fresh. env_free_for_task() exists only in this
# change, so its absence means the binary predates the edit and every leg
# below would grade the old kernel. Capture-then-match, never `nm | grep -q`:
# grep -q exits at the first match and SIGPIPEs nm (141), which under pipefail
# fires this guard against a kernel that DOES contain the symbol.
NM_OUT="$(i686-elf-nm kernel.elf 2>/dev/null || true)"
case "$NM_OUT" in
  *env_free_for_task*) : ;;
  *)
    echo "RESULT: INCONCLUSIVE — kernel.elf has no env_free_for_task symbol"
    echo "  The per-task storage change is not in the binary under test."
    echo "  If you just restored a file with mv/git stash, its mtime moved"
    echo "  backwards and make skipped the rebuild: touch src/env.c src/env.h."
    exit 3
    ;;
esac

# And prove the GLOBAL tables are actually gone, not merely supplemented. A
# build that kept env_table[] alongside the new page would pass every runtime
# leg here (one shell still sees its own writes) while per-task storage was
# doing nothing. This is a source-independent check on the linked image.
if printf '%s\n' "$NM_OUT" | grep -qE ' [bB] (env_table|alias_table)$'; then
    echo "RESULT: FAIL — kernel.elf still defines a global env_table/alias_table"
    echo "  Per-task storage is not actually replacing the globals."
    exit 1
fi

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
if [ ! -f disk.img ]; then
    echo "RESULT: INCONCLUSIVE — disk.img not found"
    exit 3
fi
cp disk.img "$RUN_DISK"

echo "==> Launching headless QEMU (monitor on $MON_SOCK)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# Everything is measured in the KERNEL shell. That is the correct boundary for
# THIS PR: env storage is kernel-side and the ring-3 shell has no env builtins
# yet (that is the follow-up PR). TINYOS_STAY_IN_RING3 is deliberately NOT set
# -- the typist's `kshell` handover is the vehicle, and the kernel shell is
# where env/set/alias actually live today.
#
# The shell legs cover defaults, expansion and alias capacity; `sectest` at the
# end carries the per-task isolation check, which needs a second task and so
# cannot be driven from here (see leg 6).
#
# stderr from the typist is NOT discarded below: it aborts with "no keymap for
# char" on an unmapped punctuation character, which otherwise looks exactly like
# a shell that ignored the command -- half a command lands in the log and the
# legs blame the kernel. Cost one debugging round already.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="echo HOMEIS:\$HOME" \
TINYOS_EXPECT="HOMEIS:/" \
TINYOS_FOLLOWUP_CMDS="\
env=>PATH=/bin;\
env=>SHELL=/bin/shell;\
alias=>alias ll=;\
alias myll=whoami;\
myll=>root;\
set SESSVAR=firstsession;\
echo SESS1:\$SESSVAR=>SESS1:firstsession;\
sectest=>per-task self-test;\
" \
python3 tools/qemu_typist.py >/dev/null

TYPIST_RC=$?

echo "==> Typist finished (rc=$TYPIST_RC); analysing $SERIAL"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: INCONCLUSIVE — serial log is empty (QEMU never booted?)"
    exit 3
fi

fail=0
pass() { echo "  PASS: $1"; }
bad()  { echo "  FAIL: $1"; fail=1; }

# ---------------------------------------------------------------------------
# Leg 1: the subsystem is LIVE — $HOME expands to something.
# Before this change env_expand() found no table and expanded $HOME to the
# empty string, so the line read "HOMEIS:" with nothing after it. That is the
# exact string this leg must not accept.
# ---------------------------------------------------------------------------
if grep -qE '^HOMEIS:/' "$SERIAL"; then
    pass "\$HOME expands (subsystem is live)"
elif grep -qE '^HOMEIS:[[:space:]]*$' "$SERIAL"; then
    bad  "\$HOME expanded to EMPTY — env_init() is not populating the table"
else
    bad  "no HOMEIS: line on serial — the echo never ran"
fi

# ---------------------------------------------------------------------------
# Leg 2: defaults are installed and listed by `env`.
# ---------------------------------------------------------------------------
if grep -q 'PATH=/bin' "$SERIAL"; then
    pass "env lists PATH=/bin"
else
    bad  "env did not list PATH=/bin"
fi
if grep -q 'SHELL=/bin/shell' "$SERIAL"; then
    pass "env lists SHELL=/bin/shell"
else
    bad  "env did not list SHELL=/bin/shell"
fi
if grep -q '(no variables)' "$SERIAL"; then
    bad  "env reported '(no variables)' — the table is still empty"
else
    pass "env did not report '(no variables)'"
fi
# USER is present. NOTE THE LIMIT OF THIS LEG: env_init() also defaults USER to
# "root", and this harness logs in as root, so "USER=root" does NOT distinguish
# the per-session lookup in shell_task() from the static default. It only proves
# the row exists. Witnessing the lookup needs a non-root login, which this
# harness does not drive (see leg 6 on why re-login is not available here).
# Do not upgrade this comment to claim more than it checks.
if grep -q 'USER=root' "$SERIAL"; then
    pass "env lists USER=root (row present; does not isolate the per-session set)"
else
    bad  "env did not list USER at all"
fi

# ---------------------------------------------------------------------------
# Leg 3: the default ALIAS list is the new 12, not the old 16.
# `ll` must be present (it survived) and `please` must be absent (it was one
# of the four dropped to leave the user free slots). Checking only the
# presence of `ll` would pass against the old 16-entry list.
# ---------------------------------------------------------------------------
if grep -q "alias ll=" "$SERIAL"; then
    pass "alias lists the default 'll'"
else
    bad  "alias did not list 'll' — defaults not installed"
fi
if grep -q "alias please=" "$SERIAL"; then
    bad  "alias still lists 'please' — the default list is the old 16-entry one"
else
    pass "alias does not list the dropped 'please' (list trimmed to 12)"
fi

# ---------------------------------------------------------------------------
# Leg 4: a USER alias can still be created and invoked.
# This is the capacity assertion: with 16 defaults in a 16-slot table this
# fails, because alias_set() has no free slot. Invoking it (not just listing
# it) also proves the substitution path in shell.c still resolves.
#
# The alias VALUE is a single word (`whoami`) on purpose. cmd_alias reads only
# argv[1], so `alias x='echo HI'` tokenizes into argv[1]="x='echo" and stores
# x -> "echo": the alias is created, prints a blank line, and a grep for "HI"
# fails while looking like a capacity failure. That is PRE-EXISTING shell
# behaviour, not something this PR changed -- do not "fix" the harness by
# re-adding quotes.
#
# `root` appears throughout the log, so this is POSITIONAL: it must appear on
# the line after the `$ myll` prompt, not merely somewhere in the file.
#
# The serial log uses CRLF, so `^root$` silently fails to match "root\r" and
# reports a capacity failure that is really a line-ending mismatch. Strip the
# CRs with tr rather than writing \r into the pattern: `grep` on this machine is
# ugrep, which rejects the $'...\r\?' form outright, and BSD grep does not
# support GNU's \? in a BRE either. tr is portable across all three.
# ---------------------------------------------------------------------------
# REJOIN the torn echo instead of trying to match its fragments.
#
# The shell writes its prompt with no trailing newline, so anything else
# reaching the serial port in that window terminates the line. The EDR
# daemon's periodic status burst does exactly that -- and it lands at an
# ARBITRARY character, not at a word boundary. One run split this very
# command as:
#
#     $ m[EDR DAEMON] Starting threat scan...
#     [EDR DAEMON] Scanning 6 active processes
#     [EDR DAEMON] Scan complete: 6 processes, duration 0 ticks
#     yll
#     root
#
# The residue is "yll", which matches neither `^myll$` nor `^\$ myll$`. An
# earlier fix here anchored at column 0 to catch the whole-token case; that is
# not enough, because the tear point is wherever the timer happened to fire.
# Any pattern that reconstructs the typed text is fragile by construction.
#
# So repair the log first: strip the EDR text WITHOUT its preceding newline,
# which splices each torn line back onto its own continuation. Verified on a
# real capture -- all 7 torn echoes in that log reassemble, 0 residual tears,
# and untorn lines are untouched. Ordinary anchors then work, and the -A1
# adjacency (which is the real assertion) still carries the weight.
#
# awk rather than perl -0pe: no whole-file slurp, and no perl dependency in
# a script that CI runs.
#
# The serial log uses CRLF, so `^root$` silently fails to match "root\r" and
# reports a capacity failure that is really a line-ending mismatch. Strip the
# CRs with tr rather than writing \r into the pattern: `grep` on this machine
# is ugrep, which rejects the $'...\r\?' form outright, and BSD grep does not
# support GNU's \? in a BRE either. tr is portable across all three.
if tr -d '\r' < "$SERIAL" \
     | awk '/\[EDR DAEMON\]/ { sub(/\[EDR DAEMON\].*$/, ""); buf = buf $0; next }
            { print buf $0; buf = "" }' \
     | grep -A1 -E '^\$ myll$' | grep -q '^root$'; then
    pass "user-defined alias was created AND invoked (free slots remain)"
else
    bad  "user alias did not resolve — alias table may be full (defaults >= max)"
fi

# ---------------------------------------------------------------------------
# Leg 5: a user-set variable reaches the table and expands.
# Positive control for leg 6: if this fails, the isolation verdict below is
# about a shell that could not set variables at all.
# ---------------------------------------------------------------------------
if grep -q '^SESS1:firstsession' "$SERIAL"; then
    pass "a user-set variable expands (writes reach the table)"
else
    bad  "could not set/read a variable — leg 6 would prove nothing"
fi

# ---------------------------------------------------------------------------
# Leg 6: PER-TASK STORAGE. The load-bearing leg, and the reason this PR exists.
#
# Delegated to env_pertask_self_test() (TEST 10 in `sectest`) because NOTHING
# ELSE IN THIS BUILD CAN WITNESS IT. Two candidate shell-level approaches were
# tried and rejected, both of which would have produced a green harness that
# tested nothing:
#
#   - `su otheruser` changes credentials on the SAME task, so it keeps the same
#     env page. A "the other user cannot see my variable" test written that way
#     measures nothing and would FAIL against correct per-task code.
#   - a logout/login pair needs the typist to re-run the login sequence, which
#     it does not do; the followups simply stop.
#
# So the check runs in the kernel, where a second real task can be created.
# The self-test's own three-way verdict is what matters: the child must not see
# the parent's variable, the child MUST be able to set its own (a child whose
# page allocation failed sees nothing either -- that is the vacuous pass this
# guards against), and the parent's variable must survive.
#
# NEGATIVE-CONTROLLED against a kernel rebuilt with one shared page for all
# tasks (the pre-PR global table): leg 6 FAILS while every other leg here still
# passes, so it isolates exactly the property under test.
#
# Getting that control right took two attempts, and the first one is the
# instructive part. Redirecting only env_state_alloc() -- the ALLOCATING path --
# left the reader env_state() returning the child's own NULL, so the child
# "saw nothing" for the wrong reason and only clause 3 fired. A shared-storage
# regression must redirect BOTH paths, or the control quietly tests less than it
# claims. Same failure mode the three-way verdict itself guards against.
# ---------------------------------------------------------------------------
if grep -q 'per-task self-test:.*=> PASS' "$SERIAL"; then
    pass "per-task isolation self-test PASSED (child has its own table)"
elif grep -q 'per-task self-test:.*=> FAIL' "$SERIAL"; then
    bad  "per-task isolation self-test FAILED — tables are shared between tasks"
    grep 'per-task self-test:' "$SERIAL" | sed 's/^/        /'
elif grep -q 'self-test INCONCLUSIVE' "$SERIAL"; then
    bad  "per-task isolation self-test could not run (see line below)"
    grep 'self-test INCONCLUSIVE' "$SERIAL" | sed 's/^/        /'
else
    bad  "per-task isolation self-test produced no verdict — did sectest run?"
fi

# ---------------------------------------------------------------------------
# Leg 7: INHERITANCE, the other half of the storage decision.
#
# "Per-task" and "inherited on spawn" pull in opposite directions against the
# same storage, and each hides the other's failure: a build that hands every
# task one shared page passes inheritance trivially while failing leg 6, and a
# build that never copies passes leg 6 while failing this. Neither leg alone
# describes the design that was actually chosen.
#
# The self-test's own two clauses matter for the same reason: the heir must see
# the EXPORTED variable and must NOT see the un-exported one. A copy that
# ignored the export flag and cloned the whole table satisfies the first clause
# perfectly.
# ---------------------------------------------------------------------------
if grep -q 'inheritance self-test:.*=> PASS' "$SERIAL"; then
    pass "export inheritance self-test PASSED (exported crossed, private did not)"
elif grep -q 'inheritance self-test:.*=> FAIL' "$SERIAL"; then
    bad  "export inheritance self-test FAILED"
    grep 'inheritance self-test:' "$SERIAL" | sed 's/^/        /'
elif grep -q 'inheritance self-test INCONCLUSIVE' "$SERIAL"; then
    bad  "export inheritance self-test could not run (see line below)"
    grep 'inheritance self-test INCONCLUSIVE' "$SERIAL" | sed 's/^/        /'
else
    bad  "export inheritance self-test produced no verdict"
fi

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
echo
if [ "$fail" -eq 0 ]; then
    echo "RESULT: PASS — env subsystem is live and storage is per-task"
    exit 0
else
    echo "RESULT: FAIL — see the failing legs above (serial log: $SERIAL)"
    exit 1
fi
