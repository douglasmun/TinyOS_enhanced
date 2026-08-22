#!/usr/bin/env bash
#
# verify-syscall-reject-counters.sh — are rejected syscalls COUNTED, not printed?
#
# THE BUG
#
# Three kprintf sites sat in the syscall dispatcher (src/syscall.c):
#
#   syscall_num > MAX_SYSCALL_NUM   -> "Invalid syscall number %d"
#   case SYS_CRYPTO                 -> unimplemented
#   default                         -> unimplemented
#
# The first is the one that matters. The syscall NUMBER is entirely the
# caller's own byte: no privilege, no mapped memory, no setup, no prior state.
# So any ring-3 program produced one kernel console line per call, at whatever
# rate it chose, into the same serial stream the ring-3 shell writes the user's
# own output to -- and because the number was formatted back out with %d, the
# unprivileged caller also chose the text of those lines.
#
# WHY IT SURVIVED. There is no libc wrapper for an invalid syscall and no shell
# builtin that makes one, so nothing in the tree ever drove the site and no
# harness ever saw it fire. That is the same "no driver, so the sites rot"
# condition that hid sixteen kprintfs on SYS_MSEAL. This harness therefore
# ships its own ring-3 driver, /callprobe.elf, exactly as the mseal audit had
# to ship /msealprobe.elf.
#
# WHAT IS ASSERTED
#
#   1. EXACT deltas, per attacker position. out-of-range must rise by exactly
#      the number of out-of-range calls (8 = 3 at 42 + 5 at 200, deliberately
#      split across two values because a range check written with the wrong
#      comparison can admit one and not the other), and unimplemented by
#      exactly 7. Not ">= 1": a counter incremented once per int 0x80 rather
#      than once per rejection passes a >= test and fails this one.
#   2. SELECTIVITY. The two counters are separate and their expected deltas
#      differ (8 vs 7), so a single counter catching both cannot match either.
#   3. POSITIVE CONTROL. `accepted` must rise by AT LEAST the 11 SYS_GETPID
#      calls the probe makes. This leg is not optional: a dispatcher that
#      refused every call would satisfy legs 1 and 2 perfectly -- both reject
#      counters would read exactly right -- while nothing worked at all.
#      This one is >= rather than ==, and deliberately so: `accepted` also
#      counts the shell's own syscalls (readline costs one per keystroke), so
#      an exact assertion here would be asserting the shell's behaviour, not
#      the dispatcher's.
#   4. SILENCE. The console must gain no "Invalid syscall" line while the
#      probe runs. This is the actual finding; legs 1-3 only establish that
#      the replacement counters are honest.
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem.

set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
TESTUSER=callus
TESTPASS=callpass1
ISO=dist/tinyos.iso
SERIAL=syscall-reject.log
RUN_DISK=/tmp/tinyos-sysrej-disk.img
MON_SOCK=/tmp/tinyos-sysrej-mon.sock

# Must match callprobe.c exactly.
EXP_RANGE=8      # N_RANGE_LOW 3 + N_RANGE_HIGH 5
EXP_UNIMPL=7     # N_UNIMPL
EXP_ACCEPT=11    # N_ACCEPTED (asserted as a floor, see leg 3)

guard_fail() { echo "HARNESS GUARD FAILED: $*"; exit 2; }

# Source guards. Without these the run below "passes" every numeric assertion
# by reading 0 == 0 twice.
grep -q "syscall_reject_range++" src/syscall.c \
    || guard_fail "src/syscall.c does not increment syscall_reject_range; the
site under test still prints and every delta below would read 0."
grep -q "Syscall dispatch" src/shell_system.c \
    || guard_fail "secstatus does not surface the syscall counters; nothing to parse."
grep -q "callprobe_elf_data" src/kernel.c \
    || guard_fail "/callprobe.elf is not installed by kernel.c; no ring-3 driver
exists for an out-of-range syscall number and nothing would drive the counters."

command -v qemu-system-i386 >/dev/null 2>&1 || guard_fail "qemu-system-i386 not found"

echo "==> Building kernel + ISO..."
make >/dev/null 2>&1 || guard_fail "build failed"
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || guard_fail "mkrescue failed"

rm -f "$RUN_DISK" "$SERIAL" "$MON_SOCK"
dd if=/dev/zero of="$RUN_DISK" bs=1m count=128 status=none

echo "==> Launching headless QEMU..."
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -display none 2>/dev/null &
QEMU_PID=$!
cleanup() {
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "${QEMU_PID:-}" ] && wait "$QEMU_PID" 2>/dev/null
    rm -f "$MON_SOCK" "$RUN_DISK"
    return 0
}
trap cleanup EXIT

# Run the probe as an UNPRIVILEGED user, not root. The whole point of the
# finding is that the syscall number is the caller's own byte and needs no
# privilege; measuring as root would leave that unproven. (See the gating
# note in CLAUDE.md: copying an assertion between polarities inverts it.)
#
# No `kshell` step: without TINYOS_STAY_IN_RING3 the typist already hands over
# to the kernel shell at login, so an explicit one is a SECOND switch and the
# kernel shell answers "Unknown command: kshell" -- after which every following
# expect burns the full timeout against a healthy prompt.
#
#   secstatus  : BASELINE
#   callprobe  : drives 8 out-of-range, 7 unimplemented, 11 accepted
#   secstatus  : AFTER
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=900 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
su $TESTUSER=>Now running as;\
!id=>uid=;\
secstatus=>Syscall dispatch;\
exec /callprobe.elf=>PROBE done;\
secstatus=>Syscall dispatch" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup
trap - EXIT

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: harness problem — no serial output (typist rc=$TYPIST_RC)"
    exit 2
fi

CLEAN=$(mktemp); tr -d '\r' < "$SERIAL" > "$CLEAN"

# The probe must actually have run. Without this, two identical baselines
# produce deltas of 0 and leg 1 reports a broken counter when the real
# problem is that nothing drove it.
if ! grep -q "PROBE done" "$CLEAN"; then
    echo "RESULT: harness problem — /callprobe.elf did not run to completion."
    echo "  Deltas below would be measuring nothing."
    grep -vE "Suspicious|EDR DAEMON" "$CLEAN" | tail -25
    rm -f "$CLEAN"; exit 2
fi

# Two "Syscall dispatch" readings, in order. Portable read loop, not mapfile:
# macOS ships bash 3.2 and an unset array under `set -u` kills the verdict
# before it prints, making a PASSING kernel look like a broken harness.
ACC=""; RNG=""; UNI=""
while read -r n; do ACC="$ACC $n"; done < <(
    grep -oE "[0-9]+ accepted" "$CLEAN" | grep -oE "^[0-9]+")
while read -r n; do RNG="$RNG $n"; done < <(
    grep -oE "[0-9]+ out-of-range" "$CLEAN" | grep -oE "^[0-9]+")
while read -r n; do UNI="$UNI $n"; done < <(
    grep -oE "[0-9]+ unimplemented" "$CLEAN" | grep -oE "^[0-9]+")

set -- $ACC; A_N=$#; A_B="${1:-}"; eval A_A=\"\${$A_N:-}\"
set -- $RNG; R_N=$#; R_B="${1:-}"; eval R_A=\"\${$R_N:-}\"
set -- $UNI; U_N=$#; U_B="${1:-}"; eval U_A=\"\${$U_N:-}\"

if [ "$A_N" -lt 2 ] || [ "$R_N" -lt 2 ] || [ "$U_N" -lt 2 ]; then
    echo "RESULT: harness problem — need two readings of each counter"
    echo "  got $A_N accepted, $R_N out-of-range, $U_N unimplemented"
    grep -E "Syscall dispatch" "$CLEAN"
    rm -f "$CLEAN"; exit 2
fi

A_D=$(( A_A - A_B )); R_D=$(( R_A - R_B )); U_D=$(( U_A - U_B ))

echo "  out-of-range  : $R_B -> $R_A  (delta $R_D, expected $EXP_RANGE)"
echo "  unimplemented : $U_B -> $U_A  (delta $U_D, expected $EXP_UNIMPL)"
echo "  accepted      : $A_B -> $A_A  (delta $A_D, expected >= $EXP_ACCEPT)"
echo ""

FAIL=0

# Leg 1a: out-of-range, exact.
if [ "$R_D" -ne "$EXP_RANGE" ]; then
    echo "FAIL leg 1: out-of-range delta $R_D != $EXP_RANGE."
    if [ "$R_D" -eq 0 ]; then
        echo "  Zero: the range check is not counting. Still printing?"
    fi
    FAIL=1
else
    echo "PASS leg 1: both out-of-range values (42 and 200) counted, exactly once each."
fi

# Leg 2: unimplemented, exact -- and a DIFFERENT expected number, so a single
# counter catching both positions cannot satisfy leg 1 and leg 2 together.
if [ "$U_D" -ne "$EXP_UNIMPL" ]; then
    echo "FAIL leg 2: unimplemented delta $U_D != $EXP_UNIMPL."
    echo "  In-range-but-unimplemented is a different attacker position from"
    echo "  out-of-range and must not share a counter with it."
    FAIL=1
else
    echo "PASS leg 2: in-range unimplemented counted separately and exactly."
fi

# Leg 3: POSITIVE CONTROL. Floor, not equality -- see the header.
if [ "$A_D" -lt "$EXP_ACCEPT" ]; then
    echo "FAIL leg 3 (positive control): accepted rose by only $A_D, expected >= $EXP_ACCEPT."
    echo "  The probe made $EXP_ACCEPT successful SYS_GETPID calls. Without this,"
    echo "  a dispatcher that refused EVERYTHING would pass legs 1 and 2."
    FAIL=1
else
    echo "PASS leg 3 (positive control): accepted rose by $A_D (>= $EXP_ACCEPT)."
fi

# Leg 4: THE FINDING. Between the two secstatus readings only, for the same
# reason the tcp harness brackets its window: boot legitimately prints syscall
# lines, and a whole-log grep would need an exclusion list that quietly grows
# until it hides the thing under test.
FIRST=$(grep -n "Syscall dispatch" "$CLEAN" | head -1 | cut -d: -f1)
LAST=$(grep -n "Syscall dispatch" "$CLEAN" | tail -1 | cut -d: -f1)
if [ -n "$FIRST" ] && [ -n "$LAST" ] && [ "$LAST" -gt "$FIRST" ]; then
    NOISE=$(sed -n "$((FIRST+1)),$((LAST-1))p" "$CLEAN" \
            | grep -iE "invalid syscall|unknown syscall|not implemented" || true)
    if [ -n "$NOISE" ]; then
        echo "FAIL leg 4: console gained syscall-rejection lines while the probe ran:"
        echo "$NOISE" | head -10
        echo "  An unprivileged program chose both the rate and the text of those."
        FAIL=1
    else
        echo "PASS leg 4: console stayed silent across $((EXP_RANGE + EXP_UNIMPL)) rejected syscalls."
    fi
else
    echo "FAIL leg 4: could not bracket the two secstatus readings."
    FAIL=1
fi

rm -f "$CLEAN"
echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: PASS — rejected syscalls are counted by attacker position,"
    echo "        exactly, and print nothing to the shared console."
    exit 0
fi
echo "RESULT: FAIL — see the legs above.  Serial: $SERIAL"
exit 1
