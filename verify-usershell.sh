#!/usr/bin/env bash
#
# verify-usershell.sh — FULLY AUTOMATED check of the RING-3 shell (roadmap 4).
#
# Boots, logs in, and drives the ring-3 shell interactively through the QEMU
# monitor. The shell under test is a USER process at ring 3, and every builtin
# it runs reaches the filesystem only through the syscalls added in PRs
# #43-#47.
#
# The ring-3 shell is now the DEFAULT LOGIN SHELL, so no `exec` is typed to
# reach it: logging in must land straight in it. The first command below is an
# ordinary ring-3 builtin (`pwd`), and the fact that it works at all is the
# proof — under the old arrangement the kernel shell would have answered, and
# the marker assertions below would not match its output.
#
# The kernel shell remains reachable as a fallback (`kshell`) because the
# ring-3 shell does not yet cover the privileged commands.
#
# What makes this different from verify-fsyscalls.sh: fileio.elf is a fixed
# program running a scripted sequence. Here the commands arrive as KEYSTROKES
# into a ring-3 read() on stdin, so PASS additionally proves the interactive
# path works — prompt, line editing, argv splitting, and dispatch — not just
# that the syscalls return the right numbers.
#
# Each check below is chosen so a plausible bug fails it:
#
#   - `pwd` after `cd`     — the cwd is per-process and really moved.
#   - `write` then `cat`   — content written in ring 3 comes back out.
#   - `ls` on a subdir     — readdir works where the file actually is.
#   - `mkdir`/`rmdir`      — namespace mutation from ring 3.
#   - `rmdir` non-empty    — the REFUSAL path, not just the success path.
#   - `/hello.elf`         — spawn + waitpid: a ring-3 shell starting a ring-3
#                            child and being woken when it exits.
#   - `exit`               — the loop terminates and the process is reaped.
#   - `kshell` + `whoami`  — the fallback works. This is the safety property
#                            of making a 13-builtin shell the default: the
#                            ~70-command kernel shell must stay reachable.
#                            `whoami` exists ONLY there, so its output proves
#                            the handover landed in the kernel shell.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: usershell.log (serial),
# usershell-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=usershell.log
TRACE=usershell-trace.log
RUN_DISK=/tmp/tinyos-usershell-disk.img
MON_SOCK=/tmp/tinyos-usershell-mon.sock

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
# /scratch is 0777, the one RAMFS directory a uid-1000 process may write. The
# ring-3 shell runs as uid 1000, so the whole FS sequence happens there.
#
# The marker strings are chosen to be unforgeable by an inert shell: "rs-ok" is
# text this shell wrote and read back, and "usdir/" can only appear if readdir
# returned a DIRECTORY type for something mkdir created.
#
# Expects match distinctive OUTPUT, never the prompt: the prompt is written
# without a trailing newline and the next command's echo lands on the same
# line, so matching on it is unreliable. Commands with no output of their own
# (mkdir, rm) are followed by one that proves they worked.
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_EXEC_CMD="pwd" \
TINYOS_EXPECT="D:/" \
TINYOS_FOLLOWUP_CMDS="\
cd /scratch=>D:/scratch;\
mkdir usdir;\
write usdir/f.txt rs-ok;\
cat usdir/f.txt=>rs-ok;\
ls usdir=>f.txt;\
ls=>usdir/;\
stat usdir/f.txt=>size=;\
rmdir usdir=>directory not empty;\
rm usdir/f.txt;\
rmdir usdir;\
/hello.elf shellarg=>argv[1]=shellarg;\
kshell=>Switching to the kernel shell;\
whoami=>root;\
logout=>login" \
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

# The shell's own error strings. Any of these means a builtin ran and FAILED,
# which is a real defect rather than an inconclusive run. Matched with the
# leading command name so ordinary text containing these words cannot trip it.
if grep -qE "^(cd|ls|cat|stat|write|mkdir|rm|pwd): .*(no such file|permission denied|not a directory|is a directory|invalid argument|operation failed)" "$SERIAL" 2>/dev/null; then
    echo "RESULT: FAIL — a shell builtin reported an error"
    grep -E "^(cd|ls|cat|stat|write|mkdir|rmdir|rm|pwd): " "$SERIAL" | tail -10
    exit 1
fi

if grep -q "not found (try 'help')" "$SERIAL" 2>/dev/null; then
    echo "RESULT: FAIL — the shell did not recognise a command it should have"
    grep "not found (try" "$SERIAL" | tail -5
    exit 1
fi

# Ordered: a stale or duplicated line must not stand in for a missing one.
l_start=$(grep -n "TinyOS shell (ring 3)" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
# The prompt carries the cwd, so this line alone proves chdir moved the
# process AND getcwd read it back.
l_cd=$(grep -n "D:/scratch" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
# Content this shell wrote through open(O_CREAT)+write and read back with
# open+read. An inert shell cannot produce it.
l_cat=$(grep -n "rs-ok" "$SERIAL" 2>/dev/null | tail -1 | cut -d: -f1)
# readdir found the file inside the directory the shell created...
l_ls=$(grep -n "f\.txt" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
# ...and reported the directory itself AS a directory (the trailing slash is
# emitted only for DT_DIR).
l_lsdir=$(grep -n "usdir/" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
l_stat=$(grep -n "f\.txt  size=" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
# The REFUSAL. rmdir on a non-empty directory must fail; a driver that
# removed it anyway would still satisfy every success check above.
l_busy=$(grep -n "directory not empty" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
# spawn + waitpid from ring 3, with argv reaching the child's main().
l_spawn=$(grep -n "argv\[1\]=shellarg" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
l_exit=$(grep -n "shell: exiting" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)
# The kernel shell answered after `kshell`. `whoami` is a KERNEL-shell command
# the ring-3 shell does not have, so its output proves the handover really
# landed there rather than the ring-3 shell continuing to run.
# Anchored at the start only: serial lines carry a trailing CR, so "^root$"
# would never match.
l_kshell=$(grep -n "^root[[:space:]]*$" "$SERIAL" 2>/dev/null | head -1 | cut -d: -f1)

# The ring-3 shell must have appeared with NO `exec` typed. The typist's first
# command is an ordinary builtin, so if the banner shows up before any exec of
# shell.elf, login went straight into it. A stray "exec /shell.elf" in the log
# would mean the harness, not the kernel, put us there.
if grep -q "exec /shell.elf" "$SERIAL" 2>/dev/null; then
    echo "RESULT: FAIL — shell.elf was exec'd explicitly; this harness must prove it is the DEFAULT login shell"
    exit 1
fi

if [ -z "$l_start" ] || [ -z "$l_cd" ] || [ -z "$l_cat" ] || [ -z "$l_ls" ] \
   || [ -z "$l_lsdir" ] || [ -z "$l_stat" ] || [ -z "$l_busy" ] \
   || [ -z "$l_spawn" ] || [ -z "$l_exit" ] || [ -z "$l_kshell" ]; then
    echo "RESULT: FAIL/INCONCLUSIVE (typist rc=$TYPIST_RC)"
    echo "  start=${l_start:-none} cd=${l_cd:-none} cat=${l_cat:-none}" \
         "ls=${l_ls:-none} lsdir=${l_lsdir:-none} stat=${l_stat:-none}" \
         "rmdir-refused=${l_busy:-none} spawn=${l_spawn:-none}" \
         "exit=${l_exit:-none} kshell=${l_kshell:-none}"
    echo "--- tail of $SERIAL ---"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi

if [ "$TYPIST_RC" -eq 0 ] && [ "$l_cd" -gt "$l_start" ] \
   && [ "$l_busy" -gt "$l_cat" ] && [ "$l_spawn" -gt "$l_busy" ] \
   && [ "$l_exit" -gt "$l_spawn" ] && [ "$l_kshell" -gt "$l_exit" ]; then
    echo "RESULT: PASS — login landed directly in the ring-3 shell, which ran builtins, refused rmdir on a non-empty dir, spawned a child with argv, and handed over to the kernel shell on 'kshell'"
    grep -E "TinyOS shell \(ring 3\)|D:/scratch|rs-ok|usdir|argv\[1\]=|shell: exiting|Switching to the kernel shell" "$SERIAL" | head -25
    exit 0
else
    echo "RESULT: FAIL (typist rc=$TYPIST_RC; out of order:" \
         "start=$l_start cd=$l_cd cat=$l_cat busy=$l_busy" \
         "spawn=$l_spawn exit=$l_exit kshell=$l_kshell)"
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
fi
