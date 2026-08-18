#!/usr/bin/env bash
#
# verify-ring3-env.sh — FULLY AUTOMATED check that the env/set/export/unset/
# alias group works from the RING-3 shell via SYS_ENV (41), that $VAR
# expansion and alias substitution happen CLIENT-SIDE, and that an exported
# variable crosses into a spawned child.
#
# WHAT THIS IS TESTING, AND WHY IT IS NOT "DOES env PRINT SOMETHING"
#
# PR A woke the subsystem and made storage per-task; the kernel shell already
# populates PATH/HOME/USER/SHELL at login. So a ring-3 `env` that merely
# PRINTS ROWS proves almost nothing: those four defaults are set by the kernel
# at session start, and a SYS_ENV that returned a hardcoded table, or one that
# read some other task's page, would print exactly the same four lines. The
# only assertion that separates "the syscall carries THIS task's table" from
# "something printed four plausible rows" is a ROUND TRIP: set a value from
# ring 3 that no kernel default could produce, then read it back through a
# DIFFERENT code path than the one that wrote it.
#
# Hence leg 4 sets ENVMARK=r3only and leg 5 reads it back with `echo $ENVMARK`
# — the write goes through ENV_OP_SET and the read through ENV_OP_GET inside
# expand_vars(), so a stub that faked either one alone fails.
#
# THE TRAP THIS HARNESS EXISTS TO CATCH
#
# SYS_ENV alone is NOT enough to make the group work. Alias substitution and
# $VAR expansion live at src/shell.c:542 and :565 — in the KERNEL shell only.
# A ring-3 shell that gained the builtins but not the client-side expansion
# would still print a literal "$HOME" for `echo $HOME`, and its aliases would
# never fire, while `env` and `alias` both listed their tables perfectly. That
# is PR A's failure mode wearing a different hat: a subsystem that looks wired
# and observably does nothing. Legs 3, 5 and 7 are the ones that would catch
# it, and they are the reason this PR carries userspace/shell.c changes at all.
#
# POLARITY — READ THIS BEFORE COPYING AN ASSERTION
#
# SYS_ENV is UNGATED, like SYS_TIME and UNLIKE the ownership-gated SYS_CHMOD
# whose harness this one is modelled on. Storage is per-task, so a caller can
# only ever reach its own table: there is no foreign object, no refusal to
# assert, and an unprivileged -EPERM from ANY leg here is THE BUG. CLAUDE.md
# records that copying an assertion between two such halves has nearly
# inverted it three times. Do NOT add a "user is refused" leg here by analogy
# with verify-ring3-chmod.sh — there is nothing for it to be refused ON.
#
# That is also why the whole run is measured as an UNPRIVILEGED user (legs 3-9
# all execute after the su). Running them as root would pass against a kernel
# that had accidentally made SYS_ENV root-only — and leg 8, which asserts $USER
# is NOT root, is impossible to state at all from a root session.
#
# WHY THE INHERITANCE LEG USES A SPAWNED BINARY
#
# Leg 9 exports a variable and then runs /hello.elf, which spawns as a child of
# the ring-3 shell. env_inherit_exported() copies EXPORTED vars into a child at
# creation time, so this is the only leg that crosses a process boundary rather
# than staying inside one shell's page. It asserts the child STARTS, not the
# variable's value — hello.elf does not print the environment — so it is a
# smoke test for "spawn still works with env inheritance wired in", not a proof
# of inheritance itself. The PROOF of inheritance is sectest TEST 10, in the
# kernel, where both halves are witnessed directly (PR A). Don't upgrade this
# leg's claim beyond what it measures.
#
# ASSERTIONS
#
#   - no dispatcher rejection anywhere in the log      (MAX_SYSCALL_NUM 40->41)
#   - `env` appears in the ring-3 shell's help         (it is a builtin)
#   - env lists PATH as an UNPRIVILEGED user           (ungated: -EPERM = bug)
#   - `set ENVMARK=r3only` then `env` shows it         (ring-3 WRITE reached
#                                                       the table)
#   - `echo $ENVMARK` prints r3only                    (client-side EXPANSION,
#                                                       a different path than
#                                                       the write)
#   - `unset ENVMARK` then `echo $ENVMARK` is EMPTY    (an unset var expands to
#                                                       NOTHING, not its name)
#   - `alias envll=id` then `envll` prints uid=        (client-side alias
#                                                       SUBSTITUTION fired)
#   - $USER reads the su'd-to user, NOT root           (env_init seeds root, so
#                                                       su must refresh it)
#   - `export` + spawn a child still works             (smoke test; see above)
#
# THE UNSET LEG IS THE SUBTLE ONE. "echo $ENVMARK printed nothing" is also what
# a completely broken expander prints, so it is asserted as a PAIR with leg 5
# on the SAME variable: leg 5 requires r3only to appear, leg 6 requires it to
# be GONE afterwards. Neither alone is meaningful; together they prove the
# expander both reads and re-reads.
#
# Ring-3 commands are sent unverified ('!') because the ring-3 shell does not
# echo keystrokes to serial (the kernel echoes them in the keyboard IRQ, which
# reaches VGA only), so per-character echo checks pass on coincidental matches
# in kernel chatter. Each still carries an expect on its RESULT.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: ring3env.log (serial),
# ring3env-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

TESTUSER=envuser
TESTPASS=envpass1

ISO=dist/tinyos.iso
SERIAL=ring3env.log
TRACE=ring3env-trace.log
RUN_DISK=/tmp/tinyos-ring3env-disk.img
MON_SOCK=/tmp/tinyos-ring3env-mon.sock

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1

# The embedded shell must match userspace/shell.c, or this harness tests the
# PREVIOUS shell and reports on code that is not being changed. That matters
# more here than usual: the expansion legs live entirely in userspace/shell.c,
# so a stale embedded shell would fail them while the source was correct.
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1

make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# Prove the ISO carries THIS build. grub-mkrescue runs after the link, so
# mtimes look plausible even when the payload is stale.
# `strings | grep -q` is wrong under pipefail: grep -q exits at the first match,
# SIGPIPEs strings (141), and the guard fires on a FRESH ISO. grep -c consumes
# all input, so no SIGPIPE.
ISO_MARKERS=$(strings "$ISO" | grep -c "list environment variables")
if [ "$ISO_MARKERS" -eq 0 ]; then
    echo "RESULT: INCONCLUSIVE — the ISO does not contain the new ring-3 shell"
    echo "  The 'env' help line is absent, so the embedded shell.elf predates"
    echo "  this change and the run would report on the OLD shell."
    exit 3
fi

# And prove the KERNEL half is fresh too. The marker above only covers the
# embedded ring-3 shell, so a stale syscall.o passes it and the run then grades
# a kernel that predates the change. Capture then match — `nm | grep -q` is the
# SIGPIPE trap described above.
NM_OUT="$(i686-elf-nm kernel.elf 2>/dev/null || true)"
case "$NM_OUT" in
  *sys_env*) : ;;
  *)
    echo "RESULT: INCONCLUSIVE — kernel.elf has no sys_env symbol"
    echo "  The kernel half of this change is not in the binary under test."
    echo "  If you just restored a header from a .bak with mv, its mtime went"
    echo "  backwards and make skipped the rebuild: touch src/syscall.h."
    exit 3
    ;;
esac

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
if [ ! -f disk.img ]; then
    echo "ERROR: disk.img not found"
    exit 1
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

# Route to the unprivileged account is kshell -> su -> `exec /shell.elf`, the
# same one verify-ring3-ps.sh, -date.sh and -chmod.sh use, and for the same
# reason: logging out and back in reaches a ring-3 shell whose readline never
# receives keystrokes (a separate defect, recorded in doc/KERNEL_BUGS.md).
# kshell is only the vehicle for the su; every assertion below is measured on
# ring-3 output, which is the boundary SYS_ENV lives at.
#
# NOTE the ordering: the useradd/su happen FIRST, and every env assertion runs
# in the unprivileged ring-3 shell that follows. This is deliberate and is the
# opposite of the chmod harness, where root had to stage a file first. SYS_ENV
# is ungated, so measuring it as root would pass against a root-only kernel.
#
# Single-word alias value: TinyOS's tokeniser splits on spaces and the kernel
# shell's cmd_alias reads argv[1] only. The ring-3 cmd_alias added in this PR
# reassembles the remaining argv, but this harness deliberately uses a
# single-word value so the leg tests SUBSTITUTION, not quote handling.
#
# The alias target is `id`. When this leg was written the reason was that
# `whoami` did not exist in ring 3 and aliasing to it would fail with "not
# found" even though substitution had worked -- blaming the alias for a missing
# target. whoami HAS existed in ring 3 since PR #95, so that specific hazard is
# gone, but `id` stays: it prints "uid=<n> gid=<n>", and that uid= string cannot
# appear in the `alias` listing line, which is what keeps the leg self-checking.
# whoami's output is a bare username that DOES appear elsewhere in the log.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="help" \
TINYOS_EXPECT="list environment variables" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
kshell=>Switching to the kernel shell;\
su $TESTUSER=>Now running as;\
exec /shell.elf=>TinyOS shell (ring 3);\
!env=>PATH=;\
!set ENVMARK=r3only;\
!env=>ENVMARK=r3only;\
!echo MARKER1 \$ENVMARK=>MARKER1 r3only;\
!unset ENVMARK;\
!echo MARKER2 \$ENVMARK=>MARKER2;\
!alias envll=id;\
!alias=>envll;\
!envll=>uid=;\
!unalias envll;\
!alias=>(no aliases);\
!envll=>not found;\
!unalias envll=>not found;\
!export PATH;\
!/hello.elf=>Hello from ELF" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: FAIL — no serial output at all (typist rc=$TYPIST_RC)"
    exit 2
fi

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    exit 1
}

inconclusive_with() {
    echo "RESULT: INCONCLUSIVE — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    exit 3
}

# The serial log is CRLF. A positional assertion like grep '^root$' silently
# fails against "root\r" and reports a kernel failure that is really a line
# ending mismatch. Do NOT fix that with '\r\?' — grep here is ugrep, which
# rejects it as an empty subexpression. Strip once, up front, and work on the
# stripped copy for every content assertion.
CLEAN=$(tr -d '\r' < "$SERIAL")

# Split at the su. Everything after it is the unprivileged session, and every
# env assertion must be measured THERE: root's own ring-3 shell ran the same
# builtins before the su, so an unsplit grep would let root's output satisfy a
# leg whose entire point is that an unprivileged user can do this.
SU_LINE=$(printf '%s\n' "$CLEAN" | grep -n "Now running as" | head -1 | cut -d: -f1)
if [ -z "$SU_LINE" ]; then
    inconclusive_with "never reached the unprivileged account (no 'Now running as')" \
        "The su step did not complete, so nothing below was measured as an" \
        "unprivileged user — which is the only polarity that matters here."
fi

USER_REGION=$(printf '%s\n' "$CLEAN" | tail -n +"$SU_LINE")

# Confirm the unprivileged ring-3 shell actually started. Without this, every
# leg below would fail identically whether the shell died at exec or the env
# code was broken, and the report would blame env.
if ! printf '%s\n' "$USER_REGION" | grep -q "TinyOS shell (ring 3)"; then
    inconclusive_with "the unprivileged ring-3 shell never started" \
        "exec /shell.elf did not reach its banner, so no env leg was exercised."
fi

PASSES=0
note_pass() { echo "  PASS: $1"; PASSES=$((PASSES + 1)); }

# ---------------------------------------------------------------------------
# Leg 1: SYS_ENV dispatched at all.
#
# TWO messages, both matched. The range check prints "Invalid syscall number N
# (max M)" — which is what a missed MAX_SYSCALL_NUM bump actually trips, and
# SYS_ENV is 41 against a previous bound of 40. The switch default prints
# "Unknown system call number N". A leg matching only the second reported 0 and
# passed vacuously during the SYS_TIME negative control; don't repeat it.
# ---------------------------------------------------------------------------
REJECTED=$(printf '%s\n' "$CLEAN" | grep -Ec "Invalid syscall number|Unknown system call")
if [ "$REJECTED" -ne 0 ]; then
    fail_with "the dispatcher rejected a syscall ($REJECTED occurrence(s))" \
        "MAX_SYSCALL_NUM must cover SYS_ENV (41), not stop at 40." \
        "Offending line(s):" \
        "$(printf '%s\n' "$CLEAN" | grep -Em2 'Invalid syscall number|Unknown system call')"
fi
note_pass "no dispatcher rejection (MAX_SYSCALL_NUM covers SYS_ENV)"

# ---------------------------------------------------------------------------
# Leg 2: `env` is advertised in the ring-3 shell's help.
# ---------------------------------------------------------------------------
if ! printf '%s\n' "$CLEAN" | grep -q "list environment variables"; then
    fail_with "\`env\` is missing from the ring-3 shell's help output"
fi
note_pass "env is a documented ring-3 builtin"

# ---------------------------------------------------------------------------
# Leg 3 (POLARITY): an UNPRIVILEGED user can list the environment.
#
# This is the leg that would catch a SYS_ENV accidentally gated on euid. A
# -EPERM here is the bug, not a policy. Measured strictly after the su.
# ---------------------------------------------------------------------------
if ! printf '%s\n' "$USER_REGION" | grep -q "PATH="; then
    fail_with "an unprivileged \`env\` did not list PATH" \
        "SYS_ENV is UNGATED by design: the table is the caller's own task's," \
        "so there is nothing to authorize. If this leg fails with a permission" \
        "error, a uid check has been added where none belongs."
fi
note_pass "unprivileged env lists PATH (ungated, correct polarity)"

# ---------------------------------------------------------------------------
# Leg 4: a ring-3 WRITE reached the table.
#
# ENVMARK=r3only cannot come from any kernel default, so unlike PATH/HOME/USER
# this row proves the write path specifically. Still only half the round trip:
# a SYS_ENV that stored into some scratch buffer and listed the same buffer
# would pass this and fail leg 5.
# ---------------------------------------------------------------------------
if ! printf '%s\n' "$USER_REGION" | grep -q "ENVMARK=r3only"; then
    fail_with "\`set ENVMARK=r3only\` did not appear in a subsequent \`env\`" \
        "The ring-3 write did not reach the task's table (ENV_OP_SET)."
fi
note_pass "a ring-3 set reached the table (ENV_OP_SET)"

# ---------------------------------------------------------------------------
# Leg 5 (THE ROUND TRIP): client-side $VAR expansion read the value back.
#
# Different code path from leg 4: the write went through ENV_OP_SET from
# cmd_set, this read goes through ENV_OP_GET from expand_vars(). The MARKER1
# prefix is there so the assertion cannot be satisfied by the `set` command's
# own echo or by the env listing above — it appears only on the echo line.
#
# This is also the leg that catches "SYS_ENV shipped without client-side
# expansion": with the builtins alone, this prints a literal "$ENVMARK".
# ---------------------------------------------------------------------------
# Same prompt-echo exclusion as leg 6. This leg passes either way (the echoed
# command line reads "echo MARKER1 $ENVMARK", which does NOT contain "MARKER1
# r3only"), but matching the RESULT line rather than relying on that coincidence
# keeps the two legs symmetric and stops a future edit to the echo format from
# silently making this one vacuous.
if ! printf '%s\n' "$USER_REGION" | grep -v '\$ echo' | grep -q "MARKER1 r3only"; then
    fail_with "\`echo \$ENVMARK\` did not expand to its value" \
        "Expected 'MARKER1 r3only'. If the log shows a literal 'MARKER1 \$ENVMARK'," \
        "then SYS_ENV works but expand_vars() in userspace/shell.c is missing or" \
        "not being called — the builtins alone do NOT make \$VAR work." \
        "Observed:" \
        "$(printf '%s\n' "$USER_REGION" | grep -m2 'MARKER1' || echo '    (no MARKER1 line at all)')"
fi
note_pass "\$VAR expanded client-side (round trip: set -> expand)"

# ---------------------------------------------------------------------------
# Leg 6 (PAIRED WITH LEG 5): after unset, the same variable expands to NOTHING.
#
# Asserted as a pair on the SAME variable, because "printed nothing" is also
# what a totally broken expander prints. Leg 5 required the value to appear;
# this requires it to be gone. The pair proves the expander re-reads rather
# than caching, and that an unset variable expands to empty rather than to its
# own name (a shell that printed "$ENVMARK" back would fail this).
# ---------------------------------------------------------------------------
# EXCLUDE THE PROMPT-ECHO LINE. The shell echoes the command it is about to
# run, so the log holds BOTH "D:/ $ echo MARKER2 $ENVMARK" (the echo, which
# contains the literal '$ENVMARK' by construction and always will) and the
# result line below it. A bare `grep -m1 MARKER2` takes the echo, and the
# "expanded to its own NAME" assertion below then fires on EVERY run, including
# correct ones -- it did, on this harness's first run, against a shell whose
# output was right. Drop any line containing a prompt before matching.
MARKER2_LINE=$(printf '%s\n' "$USER_REGION" | grep 'MARKER2' | grep -v '\$ echo' | head -1)
if [ -z "$MARKER2_LINE" ]; then
    fail_with "the \`echo MARKER2 \$ENVMARK\` line never appeared" \
        "Cannot tell whether unset worked; the command did not run."
fi
if printf '%s\n' "$MARKER2_LINE" | grep -q "r3only"; then
    fail_with "\`unset ENVMARK\` did not remove the variable" \
        "After unset, \$ENVMARK still expanded to its old value." \
        "Observed: $MARKER2_LINE"
fi
if printf '%s\n' "$MARKER2_LINE" | grep -q 'ENVMARK'; then
    fail_with "an unset variable expanded to its own NAME, not to nothing" \
        "POSIX shells expand an unset variable to the empty string. Printing" \
        "'\$ENVMARK' back makes a typo look like a literal." \
        "Observed: $MARKER2_LINE"
fi
note_pass "unset removed it and it expands to empty (paired with leg 5)"

# ---------------------------------------------------------------------------
# Leg 7: client-side ALIAS SUBSTITUTION fired.
#
# Two parts: the alias is listed (so ENV_OP_ALIAS_SET/LIST work), and invoking
# it actually RUNS the aliased command. The second is the one that needs
# expand_aliases() in userspace/shell.c — the kernel shell's substitution at
# src/shell.c:542 is not on this path.
#
# whoami prints the username, so the expected output is the test user's name.
# That also makes the leg self-checking: a substitution that fired but ran the
# wrong command would not print this exact string.
# ---------------------------------------------------------------------------
if ! printf '%s\n' "$USER_REGION" | grep -q "envll"; then
    fail_with "the alias was never listed after being set" \
        "ENV_OP_ALIAS_SET or ENV_OP_ALIAS_LIST did not carry it."
fi

# The alias listing line is "alias envll='id'", which does NOT contain "uid=",
# so this cannot be satisfied by the listing that leg 7a already matched. That
# separation is the point of aliasing to `id` rather than to something whose
# name appears in its own output.
if ! printf '%s\n' "$USER_REGION" | grep -q "uid="; then
    fail_with "invoking the alias \`envll\` did not run \`id\`" \
        "The alias exists in the table but typing it did not substitute." \
        "This is expand_aliases() in userspace/shell.c: SYS_ENV alone does" \
        "NOT make aliases fire, because the kernel shell's substitution at" \
        "src/shell.c:542 is not on the ring-3 path."
fi
note_pass "alias substituted client-side and ran (envll -> id)"

# ---------------------------------------------------------------------------
# Leg 7b: unalias DELETED it -- witnessed by the alias no longer FIRING.
#
# ENV_OP_ALIAS_UNSET (8) is the ninth SYS_ENV subcommand and the only piece of
# new kernel surface in this group; the other eight could not express deletion.
#
# The witness is deliberately NOT "the name vanished from `alias`". A deletion
# that cleared the listing while leaving the entry live, and a LISTING bug that
# hid a still-present alias, produce the identical empty listing -- so that
# assertion cannot tell a working unalias from a broken alias_list. Typing the
# name again can: if the entry is really gone the shell finds no substitution
# and reports "not found", and if it is still there the alias fires and `id`
# prints "uid=" one more time.
#
# So this leg counts "uid=" occurrences AFTER the unalias and requires zero.
# Leg 7 above already proved the alias fired BEFORE it, which is what makes the
# count meaningful -- a zero here with no prior positive would also be produced
# by an alias that never worked at all.
UNALIAS_REGION=$(printf '%s\n' "$USER_REGION" | sed -n '/\$ unalias envll/,$p')

if [ -z "$UNALIAS_REGION" ]; then
    fail_with "the unalias command never appeared in the log" \
        "The typist did not reach it; this is a harness/timing failure," \
        "not a kernel result. Re-run before investigating."
fi

# The region must actually CONTAIN the post-unalias `envll` attempt before a
# zero count means anything. Without this the leg passes vacuously on a
# truncated log: if the typist stalls at the `alias` step -- which is exactly
# what a BROKEN unalias causes, since `alias` then prints the surviving entry
# instead of the expected "(no aliases)" and the typist waits for a string that
# never arrives -- the region holds no `envll` invocation at all and "zero
# uid=" is trivially true. The first negative control of this leg passed for
# precisely that reason. Assert the command was reached, THEN assert it did
# not fire.
if ! printf '%s\n' "$UNALIAS_REGION" | grep -q '\$ envll'; then
    fail_with "the post-unalias \`envll\` was never typed" \
        "The log stops before it, so 'the alias did not fire' cannot be" \
        "concluded -- nothing was asked of it. A stall at the preceding" \
        "\`alias\` step is itself a symptom: a surviving alias makes that" \
        "listing non-empty and the typist waits for '(no aliases)' forever."
fi

# Drop the shell's own echo lines and history's numbered listing before
# counting -- both replay the command text, and `$ envll` contains the alias
# name by construction. Same trap documented in verify-ring3-builtins.sh leg 5.
FIRED=$(printf '%s\n' "$UNALIAS_REGION" \
    | grep -v '\$ ' \
    | grep -vE '^ *[0-9]+  ' \
    | grep -c "uid=")
if [ "$FIRED" -ne 0 ]; then
    fail_with "the alias still FIRED after unalias ($FIRED run(s) of \`id\`)" \
        "ENV_OP_ALIAS_UNSET returned success but alias_unset() did not clear" \
        "the slot, or cmd_unalias called the wrong op. Note the listing may" \
        "look empty while this is broken -- that is why this leg tests" \
        "firing rather than listing."
fi
note_pass "unalias deleted the alias -- it no longer fires (paired with leg 7)"

# ---------------------------------------------------------------------------
# Leg 7c: deleting an ABSENT alias is reported, not silently accepted.
#
# The second `unalias envll` runs when the alias is already gone, so
# alias_unset() returns -1, sys_env maps it to -ENOENT, and cmd_unalias prints
# "unalias: envll: not found". A kernel that returned 0 unconditionally would
# pass leg 7b -- nothing fires either way -- so this is the leg that separates
# "deleted it" from "reported success without looking".
#
# Two "not found" lines are expected in this region: one from typing the dead
# alias (leg 7b) and one from this second unalias. Requiring BOTH is what pins
# the errno path; requiring only one would pass on either alone.
NOTFOUND=$(printf '%s\n' "$UNALIAS_REGION" \
    | grep -v '\$ ' \
    | grep -vE '^ *[0-9]+  ' \
    | grep -c "not found")
if [ "$NOTFOUND" -lt 2 ]; then
    fail_with "deleting an absent alias was not reported ($NOTFOUND/2 lines)" \
        "Expected a 'not found' from invoking the dead alias AND one from" \
        "the second unalias. If only one is present, sys_env probably" \
        "returned 0 for a missing name instead of -ENOENT."
fi
note_pass "unalias on an absent alias reports -ENOENT (not silent success)"

# ---------------------------------------------------------------------------
# Leg 8: $USER reflects the CURRENT identity, not the one env_init() seeded.
#
# env_init() seeds USER="root" because it runs before anyone has logged in, and
# every path that establishes or CHANGES an identity has to correct it. Login
# always did. `su` did NOT -- it changes credentials on the SAME task, so the
# per-task env page survives the switch untouched, and the post-su shell went on
# reporting USER=root. This harness's first run caught exactly that.
#
# It was cosmetic while env was kernel-only. SYS_ENV makes it reachable from
# ring 3, where a script can branch on $USER, so the fix (env_refresh_identity()
# called from BOTH su branches) ships with this PR -- the CLAUDE.md rule about
# exposing a path turning a latent bug into a real one, in miniature.
#
# Asserted on the env listing in the UNPRIVILEGED region, and asserted BOTH
# ways: the new name must be present AND root must be gone. Presence alone
# passes against a table holding both.
# ---------------------------------------------------------------------------
if ! printf '%s\n' "$USER_REGION" | grep -q "USER=$TESTUSER"; then
    fail_with "\$USER did not follow the su (expected USER=$TESTUSER)" \
        "env_init() seeds USER=root; su changes credentials on the same task" \
        "and so must call env_refresh_identity() to re-point \$USER/\$HOME." \
        "Observed:" \
        "$(printf '%s\n' "$USER_REGION" | grep -m2 'USER=' || echo '    (no USER= line at all)')"
fi
if printf '%s\n' "$USER_REGION" | grep -q "USER=root"; then
    fail_with "\$USER still reads root in the unprivileged session" \
        "The refresh added the new name without replacing the seeded one."
fi
note_pass "\$USER follows the su (env_refresh_identity on both branches)"

# ---------------------------------------------------------------------------
# Leg 9 (SMOKE TEST, deliberately weak): export + spawn a child still works.
#
# env_inherit_exported() runs at sys_spawn, so this exercises the path with
# inheritance wired in. It asserts the CHILD STARTS, not that the variable
# arrived — hello.elf does not print the environment. The proof of inheritance
# is sectest TEST 10 in the kernel (PR A), where both halves are witnessed
# directly. Do not upgrade this leg's claim beyond what it measures.
# ---------------------------------------------------------------------------
# /hello.elf, NOT /info.elf: kernel.c seeds only hello.elf, sleeper.elf and
# shell.elf into RAMFS, so info.elf fails with "no such file or directory" and
# the leg reads as a spawn failure when nothing is wrong. Check what is
# actually seeded before picking a child.
#
# Anchor on a string only the child prints. A bare "uid" match would be
# satisfied by leg 7's `id` output ("uid=1002 gid=100") and pass without the
# child ever starting. "Hello from ELF!" is documented load-bearing in
# userspace/hello.c for exactly this reason.
if ! printf '%s\n' "$USER_REGION" | grep -q "Hello from ELF"; then
    fail_with "spawning /hello.elf after an \`export\` produced no output" \
        "The child did not start. env_inherit_exported() runs on the spawn" \
        "path, so a fault there presents as a child that never runs."
fi
note_pass "export + spawn works (smoke test; inheritance proof is sectest 10)"

echo ""
if [ "$PASSES" -eq 11 ]; then
    echo "RESULT: PASS — the env group works from ring 3 via SYS_ENV ($PASSES/11)"
    exit 0
fi

echo "RESULT: FAIL — only $PASSES/11 legs passed"
exit 1
