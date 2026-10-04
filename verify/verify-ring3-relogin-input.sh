#!/usr/bin/env bash
#
# verify-ring3-relogin-input.sh -- does a ring-3 session reached through
# `logout` + login receive keyboard input?
#
# THE REPORT. doc/KERNEL_BUGS.md recorded (2026-08-16, while building
# verify-ring3-ps.sh) that after `logout` from the ring-3 shell and a login as
# another user, the new shell printed its prompt and then ignored every
# keystroke. It was never diagnosed. On main 0e3e610 it no longer reproduces
# (3/3 boots); this harness keeps it that way.
#
# WHAT IS ASSERTED
#   1. CONTROL. Session 1 (root) runs `echo ZQFIRST`; its output must appear.
#      This proves the typist and the first shell work at all.
#   2. THE CLAIM. After `logout` from the RING-3 shell (not kshell -- that is a
#      different path, and verify-shell-history-logout.sh already covers it)
#      and login as a fresh user, session 2 must run `echo ZQSECOND` and `id`,
#      and `id` must report the NEW user's uid. Both outputs are searched only
#      AFTER the second user's "Welcome" line, so session 1 cannot satisfy them.
#
# Session 2's readiness wait is on the ring-3 shell's own startup line, not the
# login banner (see verify-shell-history-logout.sh for why the banner is too
# early). Commands are sent unverified (`!`): the ring-3 shell echoes per line,
# never per keystroke.
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
TESTUSER=reluser
TESTPASS=relpass12
ISO=dist/tinyos.iso
SERIAL=relogin-input.log
MON_SOCK=/tmp/tinyos-relogin-mon.sock

guard_fail() { echo "HARNESS GUARD FAILED: $*"; exit 2; }
command -v qemu-system-i386 >/dev/null 2>&1 || guard_fail "qemu-system-i386 not found"

echo "==> Building kernel + ISO..."
make >/dev/null 2>&1 || guard_fail "build failed"
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || guard_fail "mkrescue failed"

rm -f "$SERIAL" "$MON_SOCK"

echo "==> Launching headless QEMU..."
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -display none 2>/dev/null &
QEMU_PID=$!
cleanup() {
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "${QEMU_PID:-}" ] && wait "$QEMU_PID" 2>/dev/null
    rm -f "$MON_SOCK"
    return 0
}
trap cleanup EXIT

TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=300 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
!echo ZQFIRST=>ZQFIRST;\
!logout=>TinyOS login:;\
$TESTUSER=>assword;\
!$TESTPASS=>'help' for builtins;\
!=>\$;\
!echo ZQSECOND=>ZQSECOND;\
!id=>uid=" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 2
cleanup
trap - EXIT

echo ""
echo "================ VERDICT ================"

[ -s "$SERIAL" ] || { echo "RESULT: harness problem — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

CLEAN=$(tr -d '\r' < "$SERIAL" | grep -vE "^\[(EDR|IDS)")

if echo "$CLEAN" | grep -q "KERNEL PANIC"; then
    echo "RESULT: FAIL — kernel panic during the run"
    exit 1
fi

# Leg 1: control, in session 1.
if ! echo "$CLEAN" | grep -qx "ZQFIRST"; then
    echo "RESULT: harness problem — session 1 never ran echo; the typist or first shell is broken."
    echo "$CLEAN" | tail -20
    exit 2
fi
echo "PASS leg 1 (control): session 1 ran a command."

UID2=$(echo "$CLEAN" | sed -n "s/^useradd: user '$TESTUSER' created (uid=\([0-9]*\),.*/\1/p" | head -1)
[ -n "$UID2" ] || { echo "RESULT: harness problem — useradd never reported a uid."; exit 2; }

WELCOME=$(echo "$CLEAN" | grep -n "Welcome, $TESTUSER!" | tail -1 | cut -d: -f1)
if [ -z "$WELCOME" ]; then
    echo "RESULT: harness problem — the second login never completed."
    echo "$CLEAN" | tail -20
    exit 2
fi
S2=$(echo "$CLEAN" | sed -n "${WELCOME},\$p")

if echo "$S2" | grep -qx "ZQSECOND" && echo "$S2" | grep -q "^uid=$UID2 "; then
    echo "PASS leg 2: the re-logged-in session ran echo and id (uid=$UID2)."
    echo "RESULT: PASS — a ring-3 session reached through logout + login receives input."
    exit 0
fi
echo "FAIL leg 2: session 2 (from line $WELCOME) shows no command output:"
echo "$S2" | tail -15
echo "RESULT: FAIL — the re-logged-in ring-3 session ignored input."
exit 1
