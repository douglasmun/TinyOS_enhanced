#!/usr/bin/env bash
#
# verify-legacy-cred-quiet.sh — in the opt-out -DTINYOS_LEGACY_CRED_SYSCALLS
# build, SYS_SWITCH_USER and SYS_CHANGE_PASSWORD must not print to the console.
#
# The two legacy syscalls carried 19 kprintf sites, one on every exit: a ring-3
# caller picked when they fired, at syscall rate, on the serial stream the
# ring-3 shell shares with the user's own output. Two echoed caller-chosen
# text ("User '%s' not found" printed the argument verbatim -- up to 31 bytes
# of attacker text, escape sequences included -- and "Authentication failed for
# '%s'"), and the not-found line made username enumeration visible to anyone
# watching the console. audit_log already records every outcome that matters;
# the not-found refusal gains an audit record so removing its print loses
# nothing.
#
# The default build refuses both syscalls with -ENOSYS, so this harness builds
# with the opt-out flag (plus TINYOS_FAST_KDF so PBKDF2 does not dominate the
# run) and drives every reachable exit through credprobe.elf:
#
#   root     : credprobe creduser          root switch (no password), then a
#                                          wrong old password as creduser
#   creduser : credprobe                   wrong password for root, wrong old
#                                          password
#   creduser : credprobe nosuchuser x credpass1
#                                          unknown user, then a correct change
#   creduser : credprobe creduser newpassword newpassword
#                                          authenticated switch, correct change
#
# Positive control: each leg's PROBE rc pair must match the path it targets,
# so a run in which the syscalls were never reached cannot pass.
# Assertion: zero "[SYSCALL]" lines naming either syscall's messages.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output / probe never ran.
# Logs: legacycred.log (serial), legacycred-trace.log.
. "$(dirname "$0")/edr-rejoin.sh"
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=creduser
TESTPASS=credpass1

ISO=dist/tinyos.iso
SERIAL=legacycred.log
TRACE=legacycred-trace.log
RUN_DISK=/tmp/tinyos-legacycred-disk.img
MON_SOCK=/tmp/tinyos-legacycred-mon.sock

echo "==> Building credprobe blob + LEGACY_CRED kernel + ISO..."
(cd userspace && make credprobe.elf ../src/credprobe_elf_data.c) >/dev/null || exit 1
make clean >/dev/null
make EXTRA_CFLAGS="-DTINYOS_LEGACY_CRED_SYSCALLS -DTINYOS_FAST_KDF" kernel.elf >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

# The legacy flag is not in make's dependency graph: leave plain objects
# behind or every later harness links a kernel with the syscalls reachable.
cleanup() {
    kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null
    rm -f "$MON_SOCK"
    make clean >/dev/null 2>&1
}
trap cleanup EXIT

TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="useradd $TESTUSER" \
TINYOS_EXPECT="Enter password for new user" \
TINYOS_FOLLOWUP_CMDS="\
!$TESTPASS=>created;\
exec /credprobe.elf $TESTUSER=>PROBE VERDICT;\
su $TESTUSER=>Now running as;\
exec /credprobe.elf=>PROBE VERDICT;\
exec /credprobe.elf nosuchuser x $TESTPASS=>PROBE VERDICT;\
exec /credprobe.elf $TESTUSER newpassword newpassword=>PROBE VERDICT;\
whoami=>$TESTUSER" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"

PAIRS=$(awk '/PROBE switch_user rc=/ { sub(/.*rc=/, ""); su=$1 }
             /PROBE change_password rc=/ { sub(/.*rc=/, ""); print su "/" $1 }' "$REJOINED" \
        | tr '\n' ' ')
echo "  probe rc pairs (switch/change): $PAIRS"

# root->creduser 0, then creduser's wrong old password -EPERM(-1)
# creduser: root wrong password -1, wrong old password -1
# creduser: unknown user -EPERM(-1) -- the same answer as a wrong password, so
#           the name's existence is not revealed (verify-legacy-su-oracle.sh);
#           then a correct change 0
# creduser: authenticated switch 0, correct change 0
EXPECT="0/-1 -1/-1 -1/0 0/0 "
if [ "$PAIRS" != "$EXPECT" ]; then
    echo "RESULT: FAIL — probe legs did not take the intended paths (want '$EXPECT')"
    echo "  Nothing below is graded; check the typist reached every leg."
    grep -a "PROBE\|Unknown command\|Now running" "$REJOINED" | tail -20
    exit 2
fi

PRINTS=$(grep -acE "\[SYSCALL\] (sys_switch_user|sys_change_password|Root changing|Root switching|Password changed|User uid=)" "$REJOINED")
echo "  [SYSCALL] credential lines: $PRINTS"
if [ "$PRINTS" -ne 0 ]; then
    echo "RESULT: FAIL — $PRINTS console line(s) from the legacy credential syscalls"
    grep -aE "\[SYSCALL\] (sys_switch_user|sys_change_password|Root changing|Root switching|Password changed|User uid=)" "$REJOINED" | head -12 | sed 's/^/    /'
    exit 1
fi
if grep -aq "guessguess" "$REJOINED"; then
    echo "RESULT: FAIL — a password passed to the kernel reached the log"
    exit 1
fi
if grep -aqi "triple fault\|PANIC" "$REJOINED"; then
    echo "RESULT: FAIL — kernel panicked during the run"
    exit 1
fi
echo "RESULT: PASS — all four legs reached their paths; no credential-syscall console lines"
exit 0
