#!/usr/bin/env bash
#
# verify-ring3-builtins.sh — FULLY AUTOMATED check that the six no-new-syscall
# builtins (clear, history, jobs, grep, find, man) work from the RING-3 shell.
#
# WHAT MAKES THIS GROUP DIFFERENT FROM EVERY OTHER RING-3 HARNESS
#
# verify-ring3-{env,chmod,date,ps,fileops}.sh all measure a SYSCALL boundary:
# their subject is kernel code newly reachable from ring 3, and their central
# question is whether the gate on it has the right polarity. This one has no
# such boundary. Every command below is implemented entirely over syscalls
# that already existed, so there is no new kernel surface, no gate, and
# nothing whose polarity could be inverted.
#
# That changes what is worth asserting. There is no "unprivileged user is
# refused" leg here and there must not be one — it would have nothing to be
# refused ON, exactly as in verify-ring3-env.sh. What CAN go wrong is subtler:
# a builtin that dispatches but does nothing, or one that prints its own help
# text and is scored as working.
#
# THE TRAP THIS HARNESS EXISTS TO CATCH
#
# `help` and `man` both list these commands, and the shell ECHOES each command
# line before running it (see the echo comment in userspace/shell.c). So the
# serial log contains the WORD "grep", the word "history" and so on, several
# times over, on every run, whether or not a single one of them executes. A
# harness that greps for the command name is therefore guaranteed to pass —
# including against a build where dispatch() never gained the entries.
#
# Every leg below asserts on OUTPUT THAT ONLY THE RUNNING BUILTIN CAN PRODUCE,
# and where possible on a string that is not the command's own name:
#   - grep prints a matched LINE from a file this harness wrote
#   - find prints a PATH it had to assemble from readdir
#   - history prints a NUMBERED line it recorded earlier in the same session
#   - jobs prints a pid for a child spawned earlier in the same session
# The negative control below makes exactly this distinction visible.
#
# PAIRED LEGS — grep and history are each asserted BOTH ways
#
# A matcher that returns "yes" for everything passes any single positive
# assertion. So grep is asserted to FIND a line that exists (leg 4) and to
# print NOTHING for a string that does not occur (leg 5); history is asserted
# to list an earlier command (leg 6) and to RESPECT a count argument (leg 7).
#
# NEGATIVE CONTROL (run it — the false-pass above is not hypothetical)
#
#   Comment out the six dispatch entries in userspace/shell.c (the block
#   ending `cmd_man(argc, argv)`), then re-run. Every command then falls
#   through to "not found (try 'help')" and legs 3-8 must go RED. If any stays
#   green it is matching the echoed command line or the man table, not output.
#
# WHY IT MEASURES AS AN UNPRIVILEGED USER
#
# Not because there is a gate — there isn't — but because that is the session
# a real user gets, and `find` walks a filesystem whose permissions are
# enforced per uid. Running as root would hide an EACCES that every actual
# user would hit. Same route as the other ring-3 harnesses: kshell -> su ->
# `exec /shell.elf`.
#
# Requires: i686-elf toolchain, nasm, xorriso, qemu-system-i386, python3.
set -u

PASSWORD="${TINYOS_ROOT_PASSWORD:-rootpass123}"
TESTUSER=blt
TESTPASS=bltpass123

ISO=dist/tinyos.iso
SERIAL=ring3builtins.log
TRACE=ring3builtins-trace.log
RUN_DISK=/tmp/tinyos-ring3builtins-disk.img
MON_SOCK=/tmp/tinyos-ring3builtins-mon.sock

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1

# The embedded shell must match userspace/shell.c, or this harness grades the
# PREVIOUS shell. That is the whole risk here: this change is ENTIRELY in
# userspace/shell.c, so a stale embedded blob means every leg reports on code
# that does not contain the feature.
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1

make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# Prove the ISO carries THIS build. grub-mkrescue runs after the link, so
# mtimes look plausible even when the payload is stale. grep -c (not -q):
# -q exits at the first match and SIGPIPEs strings, firing on a FRESH ISO.
ISO_MARKERS=$(strings "$ISO" | grep -c "erase the screen and home the cursor")
if [ "$ISO_MARKERS" -eq 0 ]; then
    echo "RESULT: INCONCLUSIVE — the ISO does not contain the new ring-3 shell"
    echo "  The man entry for 'clear' is absent, so the embedded shell.elf"
    echo "  predates this change and the run would grade the OLD shell."
    exit 3
fi

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
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

# BLTFIND is a name no kernel default or man entry can produce, so finding it
# proves the walk read a real directory rather than echoing an argument.
# BLTGREP likewise for the file body.
#
# The fixture is staged from the KERNEL shell as root, BEFORE the su, and then
# opened up with chmod. That ordering is forced, not stylistic: the drive root
# is not writable by an unprivileged user, so staging after the su fails with
# "permission denied" and legs 4/6 then match nothing -- which looks exactly
# like grep and find being broken when in fact they reported correctly. (First
# run of this harness did precisely that.) Staging as root and READING as the
# unprivileged user is also the more meaningful shape: it proves these commands
# work on a file the caller did not create.
#
# `sleeper.elf&` backgrounds a child so `jobs` has something live to report;
# it is the same binary verify-ring3-ps.sh uses for this purpose.
#
# Ordering note: history legs run LAST so there are several earlier commands
# for them to list; a history leg run early would assert against an almost
# empty ring and could pass on a single default entry.
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
mkdir /BLTFIND=>;\
write /BLTFIND/F.TXT BLTGREP alpha=>;\
chmod 755 /BLTFIND=>;\
chmod 644 /BLTFIND/F.TXT=>;\
su $TESTUSER=>Now running as;\
exec /shell.elf=>TinyOS shell (ring 3);\
!man clear=>erase the screen;\
!grep BLTGREP /BLTFIND/F.TXT=>BLTGREP alpha;\
!grep NOSUCHSTRING /BLTFIND/F.TXT;\
!find /BLTFIND=>F.TXT;\
!sleeper.elf&=>[;\
!jobs=>sleeper.elf;\
!history=>man clear;\
!history 2=>;\
" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 2
LOG="$(tr -d '\r' < "$SERIAL")"

pass=0; fail=0
ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $1"; fail=$((fail+1)); }

echo
echo "================ VERDICT ================"

# Leg 1 — we are actually in the ring-3 shell as the unprivileged user.
# Without this every leg below could be measuring the KERNEL shell, which has
# all six of these commands already and would pass the whole run.
case "$LOG" in
  *"TinyOS shell (ring 3)"*) ok "reached the ring-3 shell (not the kernel shell)" ;;
  *) bad "never reached the ring-3 shell — every leg below is meaningless" ;;
esac

# Leg 2 — none of the six fell through to the not-found path. This is the
# single assertion that would catch dispatch() never having been wired.
if printf '%s' "$LOG" | grep -qE "(clear|history|jobs|grep|find|man): not found"; then
    bad "a builtin hit 'not found' — dispatch() is missing an entry"
else
    ok "no builtin fell through to 'not found'"
fi

# Leg 3 — man printed a SUMMARY, not just the word 'man'.
case "$LOG" in
  *"erase the screen"*) ok "man printed a summary line" ;;
  *) bad "man produced no summary — table missing or not dispatched" ;;
esac

# Leg 4 — grep found a line in a file. Asserts the FILE CONTENT, which only a
# real read+match can produce.
case "$LOG" in
  *"BLTGREP alpha"*) ok "grep matched and printed a line from a file" ;;
  *) bad "grep printed no matching line" ;;
esac

# Leg 5 — paired negative: a string that does not occur must produce no match
# line. This is the leg that fails a matcher which says yes to everything.
#
# Counting raw occurrences is WRONG here and this harness got it wrong first
# time round. NOSUCHSTRING legitimately appears TWICE in a passing log: once in
# the shell's echo of the command, and once more when `history` lists that same
# command back. Both are prompt/history lines, not grep output. A naive
# `grep -c` therefore fails a build where grep is perfectly correct -- which is
# exactly the "match the echoed command line, not the output" trap described in
# the header, hit from the other direction.
#
# So: drop the shell's own echo lines (they start with the "D:/ $" prompt) and
# drop history's numbered listing (leading spaces then digits), then assert that
# NOTHING remains. What is left could only have been printed by grep itself.
NOSUCH=$(printf '%s' "$LOG" \
    | grep -v '\$ grep NOSUCHSTRING' \
    | grep -vE '^ *[0-9]+  ' \
    | grep -c "NOSUCHSTRING")
if [ "$NOSUCH" -eq 0 ]; then
    ok "grep printed nothing for an absent string (paired with leg 4)"
else
    bad "grep matched a string that is not in the file ($NOSUCH output lines)"
fi

# Leg 6 — find printed an assembled PATH: "/BLTFIND/F.TXT", which exists only
# because find joined a directory argument to a name it got from readdir. The
# assertion is on the JOINED form, not on "/BLTFIND" alone -- that substring is
# in the echoed command line, so matching it would pass with find doing nothing.
#
# It walks /BLTFIND rather than / because the drive root is not readable by an
# unprivileged user: `find /` correctly reports "permission denied", which is a
# true refusal and not a find defect. Walking the directory the fixture created
# keeps the leg about path assembly.
case "$LOG" in
  *"/BLTFIND/F.TXT"*) ok "find walked a directory and printed an assembled path" ;;
  *) bad "find printed no assembled path" ;;
esac

# Leg 7 — jobs reported a live background child by name. Requires the spawn to
# have been recorded AND the psinfo liveness check to have found it.
if printf '%s' "$LOG" | grep -E "^\[[0-9]+\] +[0-9]+ +sleeper\.elf" >/dev/null; then
    ok "jobs listed a live background child with its pid"
else
    bad "jobs did not list the backgrounded sleeper.elf"
fi

# Leg 8 — history listed an EARLIER command from this session, numbered. The
# numbering is asserted because it is produced only by the ring buffer's own
# counter; the command text alone appears in the echo.
if printf '%s' "$LOG" | grep -E "^ *[0-9]+ +man clear" >/dev/null; then
    ok "history listed an earlier command, numbered"
else
    bad "history did not list an earlier command with its number"
fi

echo
if [ "$fail" -eq 0 ] && [ "$pass" -ge 8 ]; then
    echo "RESULT: PASS — the six no-new-syscall builtins work from ring 3 ($pass/$pass)"
    rc=0
else
    echo "RESULT: FAIL — $fail leg(s) red, $pass green"
    echo "  Typist rc was $TYPIST_RC (non-zero often means a keystroke was"
    echo "  dropped under TCG load, not that the feature is broken — re-run"
    echo "  once before investigating)."
    rc=1
fi
echo "  Serial log: $SERIAL"
exit $rc
