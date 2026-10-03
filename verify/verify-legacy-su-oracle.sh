#!/usr/bin/env bash
#
# verify-legacy-su-oracle.sh — in the opt-out -DTINYOS_LEGACY_CRED_SYSCALLS
# build, SYS_SWITCH_USER must not tell a non-root caller whether a username
# exists, by errno or by time.
#
# Two oracles, both at syscall rate:
#   errno: an unknown name returned -EINVAL before any password was checked;
#          a wrong password returned -EPERM.
#   time:  every refusal before the password check (no such user, no password,
#          locked, inactive) returned in microseconds; a wrong password costs a
#          full PBKDF2. rdtsc is readable from ring 3, so the gap is visible to
#          the caller even when the errno is not.
#
# A non-root user (orprober) times three kinds of refusal with
# `credprobe -t`, against a second account (orvictim):
#   unknown : a name that does not exist                       x3
#   wrong   : orvictim, wrong password (attempts 1-2)          x2
#   lockit  : orvictim, wrong password (attempt 3 locks it)    x1, not graded
#   locked  : orvictim while locked                            x3
#
# ASSERTIONS
#   1. POSITIVE CONTROL: every leg printed its calls and "wrong" cost
#      something measurable, so the KDF ran and the clock works
#   2. every graded call returned -1 (EPERM)
#   3. min(unknown) and min(locked) are each within 2x of min(wrong)
#
# The build uses TINYOS_FAST_KDF (1000 iterations) so the run is quick; the
# equalizer uses the same PBKDF2_ITERATIONS a stored hash does, so the ratio
# holds at either setting.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output / probe never ran.
# Logs: suoracle.log (serial), suoracle-trace.log.
. "$(dirname "$0")/edr-rejoin.sh"
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
PROBER=orprober
PROBERPW=proberpw1
VICTIM=orvictim
VICTIMPW=victimpw1

ISO=dist/tinyos.iso
SERIAL=suoracle.log
TRACE=suoracle-trace.log
RUN_DISK=/tmp/tinyos-suoracle-disk.img
MON_SOCK=/tmp/tinyos-suoracle-mon.sock

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

PROBE="exec /credprobe.elf -t"
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="useradd $PROBER" \
TINYOS_EXPECT="Enter password for new user" \
TINYOS_FOLLOWUP_CMDS="\
!$PROBERPW=>created;\
useradd $VICTIM=>Enter password for new user;\
!$VICTIMPW=>created;\
su $PROBER=>Now running as;\
$PROBE unknown nosuchuser wrongpw1 3=>PROBE TIMING DONE unknown;\
$PROBE wrong $VICTIM wrongpw1 2=>PROBE TIMING DONE wrong;\
$PROBE lockit $VICTIM wrongpw1 1=>PROBE TIMING DONE lockit;\
$PROBE locked $VICTIM wrongpw1 3=>PROBE TIMING DONE locked" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"

# "PROBE t LABEL rc=N kc=M" -> "LABEL N M"
CALLS=$(grep -aoE "PROBE t [a-z]+ rc=-?[0-9]+ kc=[0-9]+" "$REJOINED" \
        | sed -E 's/PROBE t ([a-z]+) rc=(-?[0-9]+) kc=([0-9]+)/\1 \2 \3/')
echo "$CALLS" | sed 's/^/    /'

count() { echo "$CALLS" | awk -v l="$1" '$1 == l' | wc -l | tr -d ' '; }
minkc() { echo "$CALLS" | awk -v l="$1" '$1 == l { if (m == "" || $3 < m) m = $3 } END { print m + 0 }'; }

N_UNK=$(count unknown); N_WRONG=$(count wrong); N_LOCK=$(count lockit); N_LOCKED=$(count locked)
if [ "$N_UNK" -ne 3 ] || [ "$N_WRONG" -ne 2 ] || [ "$N_LOCK" -ne 1 ] || [ "$N_LOCKED" -ne 3 ]; then
    echo "RESULT: FAIL — legs incomplete (unknown $N_UNK/3, wrong $N_WRONG/2, lockit $N_LOCK/1, locked $N_LOCKED/3)"
    echo "  Nothing below is graded; check the typist reached every leg."
    grep -a "PROBE\|Unknown command\|Now running" "$REJOINED" | tail -20
    exit 2
fi

M_UNK=$(minkc unknown); M_WRONG=$(minkc wrong); M_LOCKED=$(minkc locked)
echo "  min cost (x1024 cycles): unknown=$M_UNK wrong=$M_WRONG locked=$M_LOCKED"
if [ "$M_WRONG" -lt 1 ]; then
    echo "RESULT: FAIL — a wrong password cost nothing measurable; the clock or the KDF is not being witnessed"
    exit 2
fi

FAILS=0
BAD_RC=$(echo "$CALLS" | awk '$1 != "lockit" && $2 != -1 { print $1 " rc=" $2 }' | sort | uniq -c)
if [ -n "$BAD_RC" ]; then
    echo "  FAIL: refusals do not share one errno (want -1 everywhere):"
    echo "$BAD_RC" | sed 's/^/      /'
    FAILS=$((FAILS + 1))
fi
for leg in unknown locked; do
    m=$([ "$leg" = unknown ] && echo "$M_UNK" || echo "$M_LOCKED")
    if ! awk -v a="$m" -v b="$M_WRONG" 'BEGIN { r = a / b; exit !(r >= 0.5 && r <= 2.0) }'; then
        echo "  FAIL: '$leg' costs $(awk -v a="$m" -v b="$M_WRONG" 'BEGIN { printf "%.3f", a / b }')x a wrong password (want 0.5..2)"
        FAILS=$((FAILS + 1))
    fi
done
if grep -aqi "triple fault\|PANIC" "$REJOINED"; then
    echo "  FAIL: kernel panicked during the run"
    FAILS=$((FAILS + 1))
fi
if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — SYS_SWITCH_USER distinguishes refusals ($FAILS check(s))"
    exit 1
fi
echo "RESULT: PASS — unknown user, wrong password and locked account refuse with one errno at one cost"
exit 0
