#!/usr/bin/env bash
#
# verify-ring3-redirect.sh — FULLY AUTOMATED check of RING-3 redirection.
#
# Distinct from verify-redirect.sh, which drives the KERNEL shell: there `>` is
# handled entirely inside the kernel, which owns both the parser and the
# streams. Here the shell is a ring-3 process that can only ask, so PASS proves
# the new SYS_REDIRECT syscall works — a user process rebinding its own stdout,
# and that rebinding surviving into a child it spawns.
#
# Redirection here is deliberately NOT dup2: fds 0/1/2 are not in the per-
# process fd table at all (they are the kernel's stream_context_t), so there is
# no fd to duplicate. sys_redirect rebinds a standard stream to a path, and the
# shell applies it to itself around each command. That is what makes ONE
# mechanism cover builtins and programs alike, which is what this harness
# checks on both sides.
#
# Each check is chosen so a plausible bug fails it:
#
#   - `echo > f` then `cat f`  — a BUILTIN's output reached the file. Builtins
#                                write through write(1,..), so this proves the
#                                stream really moved, not that some special
#                                case in `echo` opened a file.
#   - the NEGATIVE for it      — the redirected text must NOT appear before the
#                                `cat`. Without this, a shell that ignored `>`
#                                entirely and printed to the console would
#                                still satisfy the check above.
#   - `>>` appends             — the text written by the earlier `>` is STILL
#                                THERE afterwards. Asserted by counting marker
#                                occurrences, because "the new text appeared"
#                                is also true of a `>>` that truncated. Both
#                                halves of this were broken before this PR:
#                                append was a literal `(void)append;` TODO.
#   - `>` truncates            — and the converse. RAMFS has no truncate flag
#                                and ramfs_write only ever grows node->size, so
#                                `>` onto a longer existing file used to
#                                overwrite from offset 0 and leave the old tail
#                                readable. Checked positionally: no marker from
#                                before the overwrite may appear after it.
#   - `cat < f`                — stdin redirection, via the no-operand `cat`.
#                                Nothing else in the shell reads fd 0 on
#                                demand, so this is the only way `<` is
#                                observable.
#   - `/hello.elf > f`         — the child INHERITED the redirected stdout.
#                                This is the property that makes the design
#                                worth having: the shell redirects itself and
#                                spawns, and sys_spawn's streams_inherit does
#                                the rest.
#   - `echo > C:/x`            — the REFUSAL. STREAM_TYPE_FILE is hard-wired to
#                                RAMFS, so a C: target must be rejected rather
#                                than silently written to D:. A harness with
#                                only success paths would miss a shell that
#                                wrote the file to the wrong drive.
#   - prompt still on console  — after all of the above, the shell is not stuck
#                                redirected. `id` output on the console proves
#                                the restore path ran.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: ring3-redirect.log
# (serial), ring3-redirect-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=ring3-redirect.log
TRACE=ring3-redirect-trace.log
RUN_DISK=/tmp/tinyos-ring3-redirect-disk.img
MON_SOCK=/tmp/tinyos-ring3-redirect-mon.sock

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

echo "==> Driving the boot flow (slow under TCG; be patient)..."
# /scratch is 0777, the one RAMFS directory a uid-1000 process may write, and
# the ring-3 shell runs as uid 1000 — so everything happens there.
#
# The marker strings are chosen to be unforgeable: "r3-alpha"/"r3-beta" are text
# this shell wrote through a redirected stdout and read back, so they cannot
# appear unless the redirection worked in both directions.
#
# Commands that produce no output of their own are given no expect string; the
# command after them proves they worked. Redirected commands MUST have no
# expect, since by construction they print nothing to the console — waiting on
# output that will never arrive would hang the typist.
#
# But "no expect" means the typist sends the NEXT command immediately, without
# waiting for the shell to be ready for it. That is harmless after a builtin,
# which has already finished by the time the keystrokes land. It is NOT
# harmless after `/hello.elf > h.txt`: spawning a process means signature
# verification and a full address-space build (hundreds of ms under TCG) while
# the shell sits in waitpid and nothing is in read(), so the following
# keystrokes are simply dropped. The `pwd` after it is a BARRIER, not a check —
# its console output is the only evidence the shell has returned to its prompt.
# This is the same failure the "[EXEC] Process completed" comment in
# verify-redirect.sh describes, reached from the other side.
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_EXEC_CMD="pwd" \
TINYOS_EXPECT="D:/" \
TINYOS_FOLLOWUP_CMDS="\
cd /scratch=>D:/scratch;\
echo r3-alpha > r.txt;\
cat r.txt=>r3-alpha;\
echo r3-beta >> r.txt;\
cat r.txt=>r3-beta;\
cat < r.txt=>r3-beta;\
echo r3-gamma > r.txt;\
cat r.txt=>r3-gamma;\
echo r3-delta>d.txt;\
cat d.txt=>r3-delta;\
/hello.elf > h.txt;\
pwd=>D:/scratch;\
cat h.txt=>Hello from ELF;\
echo nope > C:/nope.txt=>cannot;\
id=>uid=" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup
trap - EXIT

echo
echo "================ VERDICT ================"

if grep -q "Triple fault" "$TRACE" 2>/dev/null; then
    echo "RESULT: FAIL — 'Triple fault' in $TRACE"
    grep -E "check_exception|v=0e|v=08|Triple fault|^EIP=|CR2=" "$TRACE" | tail -15
    exit 1
fi

if grep -q "not found (try 'help')" "$SERIAL" 2>/dev/null; then
    echo "RESULT: FAIL — the shell did not recognise a command it should have"
    grep "not found (try" "$SERIAL" | tail -5
    exit 1
fi

# A redirection the shell could not apply. The C: case is EXPECTED to fail and
# is checked separately below, so exclude it here by matching only D: targets.
if grep -qE "^(>|>>|<): .*(no such file|permission denied|invalid)" "$SERIAL" 2>/dev/null; then
    if grep -qE "^(>|>>|<): [^C]" "$SERIAL" 2>/dev/null; then
        echo "RESULT: FAIL — a redirection onto D: was refused"
        grep -E "^(>|>>|<): " "$SERIAL" | tail -10
        exit 1
    fi
fi

# COUNTS, not just presence. Each marker's number of occurrences is what
# separates working redirection from several plausible bugs, because every
# marker appears once for free as the echoed command line:
#
#   r3-alpha: 1 command echo
#           + 1 from `cat r.txt`                       (the `>` round-trip)
#           + 1 from `cat r.txt` after the append      (it SURVIVED `>>`)
#           + 1 from `cat < r.txt`                     (the `<` round-trip)
#           = 4.  A `>>` implemented as `>` gives 2 — this is the check that
#                 catches it, and the one an earlier version of this harness
#                 was missing.
#
#   r3-beta:  1 command echo + 1 after append + 1 from `cat <`  = 3
#   r3-gamma: 1 command echo + 1 from `cat r.txt`               = 2.  If `>`
#             failed to truncate, the alpha/beta text would still be in the
#             file afterwards, which the alpha count below would catch.
n_alpha=$(grep -c "r3-alpha" "$SERIAL" 2>/dev/null)
n_beta=$(grep -c "r3-beta" "$SERIAL" 2>/dev/null)
n_gamma=$(grep -c "r3-gamma" "$SERIAL" 2>/dev/null)
#   r3-delta: the GLUED-operator case, `echo r3-delta>d.txt` with no spaces.
#             The word must split at `>` the way the kernel shell splits it. If
#             it does not, `echo` prints the whole "r3-delta>d.txt" to the
#             console and nothing reaches a file, so `cat d.txt` fails — the
#             count stays at the command echo alone instead of reaching 2.
n_delta=$(grep -c "r3-delta" "$SERIAL" 2>/dev/null)

# Line numbers where ORDER is the point.
l_cd=$(grep -n "D:/scratch" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
# hello.elf's output, which must appear only when the file is cat'd — proving
# the CHILD inherited the redirected stdout rather than printing to the console.
l_hello=$(grep -n "Hello from ELF" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
l_catcmd=$(grep -n "cat h\.txt" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
# The refusal for a non-RAMFS target.
l_xdev=$(grep -n "^>: C:/nope.txt" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
# The console still works after all the redirecting — the restore path ran.
l_id=$(grep -n "uid=" "$SERIAL" 2>/dev/null | tail -1 | cut -d: -f1)

if [ -z "$l_cd" ] || [ -z "$l_hello" ] || [ -z "$l_catcmd" ] \
   || [ -z "$l_xdev" ] || [ -z "$l_id" ]; then
    echo "RESULT: FAIL/INCONCLUSIVE (typist rc=$TYPIST_RC)"
    echo "  cd=${l_cd:-none} hello=${l_hello:-none} catcmd=${l_catcmd:-none}" \
         "xdev=${l_xdev:-none} id=${l_id:-none}" \
         "counts: alpha=$n_alpha beta=$n_beta gamma=$n_gamma"
    echo "--- tail of $SERIAL ---"
    grep -v "Suspicious" "$SERIAL" | tail -40
    exit 2
fi

# The append assertion, stated on its own so a failure names the actual bug
# rather than showing up as a generic ordering mismatch.
if [ "$n_alpha" -lt 4 ]; then
    echo "RESULT: FAIL — '>>' did not append: r3-alpha appeared $n_alpha times, expected 4"
    echo "  (the text written with '>' did not survive the following '>>',"
    echo "   i.e. the append truncated the file instead of seeking to its end)"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi

if [ "$n_beta" -lt 3 ] || [ "$n_gamma" -lt 2 ]; then
    echo "RESULT: FAIL — a redirected round-trip did not come back"
    echo "  counts: alpha=$n_alpha beta=$n_beta (want >=3) gamma=$n_gamma (want >=2)"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi

# The GLUED-OPERATOR assertion. Counting r3-delta is not enough on its own: a
# shell that never split `r3-delta>d.txt` still echoes that whole string, so the
# marker appears either way. What distinguishes them is an occurrence with the
# operator NOT attached — that can only come from `cat d.txt` reading the file.
n_delta_bare=$(grep -c "r3-delta[^>]" "$SERIAL" 2>/dev/null)
if [ "$n_delta_bare" -lt 1 ]; then
    echo "RESULT: FAIL — 'echo r3-delta>d.txt' did not redirect (glued operator)"
    echo "  r3-delta seen $n_delta times, but never without '>' attached, so the"
    echo "  tokenizer treated 'r3-delta>d.txt' as one argument and printed it"
    echo "  instead of writing d.txt. The kernel shell splits at '>' mid-word;"
    echo "  the ring-3 shell must agree."
    grep -v "Suspicious" "$SERIAL" | grep "r3-delta" | head -10
    exit 2
fi

# The TRUNCATE assertion. `echo r3-gamma > r.txt` must REPLACE the file, so
# nothing after that command may still show alpha or beta. Counting cannot say
# this — it needs the position of the last occurrence of each. RAMFS has no
# truncate flag and ramfs_write only grows node->size, so a `>` that merely
# overwrote from offset 0 would leave the longer old tail readable, and every
# other check in this harness would still pass.
l_gammacmd=$(grep -n "echo r3-gamma > r\.txt" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
l_lastalpha=$(grep -n "r3-alpha" "$SERIAL" 2>/dev/null | tail -1 | cut -d: -f1)
l_lastbeta=$(grep -n "r3-beta" "$SERIAL" 2>/dev/null | tail -1 | cut -d: -f1)

if [ -n "$l_gammacmd" ] && { [ "$l_lastalpha" -gt "$l_gammacmd" ] \
                          || [ "$l_lastbeta" -gt "$l_gammacmd" ]; }; then
    echo "RESULT: FAIL — '>' did not truncate: old contents still readable after the overwrite"
    echo "  ('echo r3-gamma > r.txt' at line $l_gammacmd, but r3-alpha last seen at" \
         "$l_lastalpha and r3-beta at $l_lastbeta)"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi

# THE decisive negative: hello.elf's greeting must appear only AFTER the `cat
# h.txt` command echoes. If it shows up earlier, the child wrote to the console
# and the inheritance did not happen — every positive check above would still
# pass in that case.
if [ "$l_hello" -lt "$l_catcmd" ]; then
    echo "RESULT: FAIL — hello.elf printed to the console; the child did not inherit the redirected stdout"
    echo "  ('Hello from ELF' at line $l_hello, 'cat h.txt' at $l_catcmd)"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi

if [ "$TYPIST_RC" -eq 0 ] && [ "$l_xdev" -gt "$l_hello" ] \
   && [ "$l_id" -gt "$l_xdev" ]; then
    echo "RESULT: PASS — ring-3 '>' truncates, '>>' appends, '<' feeds stdin, a spawned child inherited the redirected stdout, a C: target was refused, and the console was restored"
    echo "  (marker counts: alpha=$n_alpha beta=$n_beta gamma=$n_gamma)"
    grep -E "r3-alpha|r3-beta|r3-gamma|Hello from ELF|^>: C:|uid=" "$SERIAL" | head -25
    exit 0
else
    echo "RESULT: FAIL (typist rc=$TYPIST_RC; out of order:" \
         "cd=$l_cd hello=$l_hello catcmd=$l_catcmd xdev=$l_xdev id=$l_id)"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi
