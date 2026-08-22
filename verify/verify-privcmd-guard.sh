#!/usr/bin/env bash
#
# verify-privcmd-guard.sh — FULLY AUTOMATED check that the kernel shell's
# information-disclosure commands are refused for a NON-ROOT user.
#
# WHAT THIS IS ABOUT
#
# shell_system.c has had a require_root() helper for a long time, but only three
# commands called it: shutdown, reboot, shred — the ones that BREAK something.
# The ones that merely TELL you something were left open, and they tell you a
# lot:
#
#   pae       page-directory / page-table PHYSICAL addresses
#   mem       heap/stack bases and region layout
#   aslr      the entropy and randomized bases of the running system
#   wxaudit   pages that are both writable and executable, i.e. where shellcode
#             would go, ranked
#   auditlog  who logged in and when, which accounts exist, which are locked;
#             -v additionally says whether the HMAC chain is intact, which tells
#             a tamperer whether they were caught
#   sectest   exercises kernel internals and reports what it found
#
# Read together, the first four are an ASLR defeat: this kernel randomizes
# layout and then had a command that printed the answer to any logged-in user.
# The gap was reachable because `kshell` has no privilege check of its own — any
# user can reach the kernel command loop — which is the right design, PROVIDED
# the commands behind it enforce their own policy. This harness is what makes
# that proviso true.
#
# WHY THE CHECK MUST BE DONE AS A NON-ROOT USER
#
# The trap. Every one of these commands SUCCEEDS for root, both before and after
# the fix. A harness that logs in as root and runs them passes identically
# against a completely unguarded kernel — it proves the command exists, not that
# it is guarded. So the harness creates a user, su's DOWN to it, and asserts the
# REFUSAL. The refusal is the whole test.
#
# THE ASSERTIONS
#
#   - each command refused for non-root  — the central check, one per command.
#     require_root prints "<cmd>: permission denied (must be root)", so the
#     refusal is asserted on that exact string ANCHORED TO THE COMMAND NAME.
#     A bare grep for "permission denied" would be satisfied by ONE command
#     refusing while the other five leaked.
#
#   - no disclosure markers in the output — the negative half, and the one that
#     catches a command that prints its payload and THEN refuses. Checking only
#     for the refusal string cannot distinguish "refused" from "leaked, then
#     refused": both contain it.
#
#   - `auditlog --help` still works    — the guard is placed after option
#     parsing on purpose, so usage text (which discloses nothing) stays
#     available. Asserting this stops a later "simplification" from hoisting the
#     check to function entry.
#
#   - root still gets real output      — the counter-check. A guard that refuses
#     EVERYONE would satisfy every assertion above while breaking the commands.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: privcmd-guard.log (serial),
# privcmd-guard-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

TESTUSER=probe
TESTPASS=probepass1

ISO=dist/tinyos.iso
SERIAL=privcmd-guard.log
TRACE=privcmd-guard-trace.log
RUN_DISK=/tmp/tinyos-privcmd-disk.img
MON_SOCK=/tmp/tinyos-privcmd-mon.sock

echo "==> Building kernel + ISO..."
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

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

# The sequence. The typist logs in as root and types `kshell` by default, so we
# start in the kernel command loop.
#
#   ROOT SIDE (counter-check): run two of the commands and see real output.
#   useradd + su: become unprivileged. The root `su` fast path needs no password.
#   NON-ROOT SIDE: every command must be refused.
#   auditlog --help: must still work while unprivileged.
#
# Each step's expect string is what proves the step landed before the next line
# is sent -- these commands print pages of output under TCG, and a follow-up
# typed into a still-scrolling console is dropped.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_EXEC_CMD="pae" \
TINYOS_EXPECT="PAE (Physical Address Extension) Status" \
TINYOS_FOLLOWUP_CMDS="\
auditlog -n 5=>SEQ;\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
su $TESTUSER=>Now running as;\
pae=>pae: permission denied;\
mem=>mem: permission denied;\
aslr=>aslr: permission denied;\
wxaudit=>wxaudit: permission denied;\
auditlog=>auditlog: permission denied;\
sectest=>sectest: permission denied;\
auditlog --help=>Usage: auditlog" \
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
    echo "  --- last 30 serial lines ---"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
}

# --- Guard: we actually became the unprivileged user ----------------------
#
# Checked first. If the su did not happen we are still root, every command
# below SUCCEEDS, and the refusal assertions fail for the wrong reason --
# reporting a guard regression when the real problem is the harness.
grep -q "Now running as" "$SERIAL" 2>/dev/null || fail_with \
    "never became the unprivileged test user" \
    "The su did not complete, so the refusal checks below would be testing" \
    "root, not an unprivileged user. Nothing was proven."

# --- Counter-check: the commands still WORK for root ----------------------
#
# A guard that refuses everyone would satisfy every refusal assertion while
# breaking the commands outright. Run before the refusals so a total breakage
# is reported as breakage rather than as a passing guard.
grep -q "PAE (Physical Address Extension) Status" "$SERIAL" 2>/dev/null || fail_with \
    "root did not get real 'pae' output" \
    "require_root must permit root. If this fails, the guard refuses everyone" \
    "and the refusal checks below are passing for the wrong reason."

# --- THE check: each command refused for the non-root user ----------------
#
# Anchored to the command NAME, not a bare "permission denied": one command
# refusing while five leak would satisfy an unanchored grep.
for c in pae mem aslr wxaudit auditlog sectest; do
    grep -q "$c: permission denied (must be root)" "$SERIAL" 2>/dev/null || fail_with \
        "'$c' was NOT refused for the unprivileged user" \
        "require_root(\"$c\") is missing or placed after the command already" \
        "printed. Every one of these discloses kernel layout, account state, or" \
        "W^X violations to any logged-in user."
done

# --- The negative half: nothing leaked before the refusal -----------------
#
# The refusal string alone cannot distinguish "refused" from "printed the
# payload, then refused" -- both contain it. These markers appear ONLY in the
# commands' real output, so after the su there must be none.
#
# Bounded to the post-su region of the log by line number: the same markers
# legitimately appear earlier, from the root-side counter-check.
SU_LINE=$(grep -n "Now running as" "$SERIAL" | tail -1 | cut -d: -f1)
if [ -n "${SU_LINE:-}" ]; then
    POST=$(tail -n "+$SU_LINE" "$SERIAL")

    # One marker per guarded command, chosen to be unique to its real output.
    while IFS='|' read -r marker label; do
        if printf '%s\n' "$POST" | grep -q "$marker"; then
            fail_with \
                "'$label' leaked its output to the unprivileged user" \
                "Found the marker '$marker' AFTER the su. The command printed" \
                "its payload and only then refused, so the guard is placed too" \
                "late to matter -- the disclosure already happened."
        fi
    done <<'MARKERS'
Page Directory Pointer Table|pae
=== Memory Statistics|mem
ASLR Statistics|aslr
W^X violations detected|wxaudit
Verifying audit log integrity|auditlog
Starting security test suite|sectest
MARKERS
fi

# --- auditlog --help must still work while unprivileged -------------------
#
# The guard sits AFTER option parsing on purpose: usage text discloses nothing,
# and a user who cannot read the log can still learn what the command is.
# Asserting it stops a later refactor from hoisting the check to entry.
printf '%s\n' "${POST:-}" | grep -q "Usage: auditlog" || fail_with \
    "'auditlog --help' was refused for the unprivileged user" \
    "The guard belongs AFTER the option-parsing loop. Usage text discloses" \
    "nothing and should stay available; only the log data is privileged."

# --- Sanity: no crash ------------------------------------------------------

if grep -qi "triple fault\|PANIC" "$SERIAL" 2>/dev/null; then
    fail_with "kernel panicked or triple-faulted during the run"
fi

echo "RESULT: PASS"
echo "  - root still gets real output from the guarded commands"
echo "  - all 6 refused for the unprivileged user (pae mem aslr wxaudit auditlog sectest)"
echo "  - none of them leaked their payload before refusing"
echo "  - 'auditlog --help' still works unprivileged"
exit 0
