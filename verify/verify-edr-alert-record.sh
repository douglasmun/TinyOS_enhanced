#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-edr-alert-record.sh — an EDR alert is RECORDED even when the console
# rate limit keeps it off the console, and one task's alert never hides
# another's.
#
# THE BUG
#
# Both alert paths rate-limited by returning BEFORE they touched the record:
#
#   edr_raise_alert (behavioral): per task, 100 ticks. An alert inside the
#     window never reached alert_count or last_signature, so a trivially
#     triggered WARNING (a syscall flood) erased the CRITICAL that followed it
#     -- from the count edr_daemon scores threats by, and from last_signature.
#
#   edr_advanced_raise_alert: ONE GLOBAL 50-tick window, so any task's alert
#     erased every other task's advanced_alert_count bump for 50 ticks.
#
# THE VEHICLE
#
# `edralert` (TINYOS_FAULT_INJECT kernel-shell command, edr_advanced.c) raises
# a fixed burst against static task_t shells that are never in the task table,
# all inside one rate-limit window:
#
#   PID 9999 behavioral: WARNING x4, then CRITICAL x2
#   PID 9998 advanced  : non-terminating x4, then terminating x1
#   PID 9997 advanced  : non-terminating x1
#
# and prints one EDRALERT line per task with the RECORD. The hook touches only
# fields that exist on both sides of the fix, so it builds on the unfixed tree
# (where it reads count=1 / last_sig=SYSCALL_FLOOD / count=1 / count=0).
#
# ASSERTIONS
#
#   record   : 9999 count=6 last_sig=SHELLCODE_EXEC; 9998 count=5; 9997 count=1
#   console  : 9999 printed exactly 2 lines, WARNING then CRITICAL (the
#              escalation pierces the window; repeats do not)
#              9998 printed exactly 2, the second with terminate=1
#              9997 printed exactly 1 (per-task window, not global)
#   surfaced : secstatus "Alerts" line shows >= 4 behavioral and >= 3
#              advanced unprinted (the synthetic burst alone produces that)
#
# NB: `make clean`s on exit -- TINYOS_FAULT_INJECT objects must not linger.
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=edralert.log
TRACE=edralert-trace.log
MON_SOCK=/tmp/tinyos-edralert-mon.sock

guard_fail() { echo "HARNESS GUARD FAILED: $*"; exit 2; }

grep -q "edr_alert_selftest" src/edr_advanced.c \
    || guard_fail "src/edr_advanced.c has no edr_alert_selftest()"
grep -q '"edralert"' src/shell.c \
    || guard_fail "src/shell.c has no edralert command"

echo "==> Building kernel + ISO (TINYOS_FAULT_INJECT)..."
make clean >/dev/null 2>&1
make EXTRA_CFLAGS=-DTINYOS_FAULT_INJECT >/dev/null || { echo "build failed"; exit 2; }
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || { echo "mkrescue failed"; exit 2; }

rm -f "$SERIAL" "$TRACE" "$MON_SOCK"

echo "==> Launching headless QEMU (monitor on $MON_SOCK)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() {
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "${QEMU_PID:-}" ] && wait "$QEMU_PID" 2>/dev/null
    rm -f "$MON_SOCK"
    echo "==> make clean (TINYOS_FAULT_INJECT objects must not linger)"
    make clean >/dev/null 2>&1
    return 0
}
trap cleanup EXIT

# Kernel-shell command: the typist's default route to kshell is the right one.
# The secstatus expect is a string BOTH trees print, so the unfixed run reaches
# its verdict instead of burning the timeout on a line it cannot produce.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="edralert" \
TINYOS_EXPECT="EDRALERT adv pid=9997" \
TINYOS_FOLLOWUP_CMDS="\
secstatus=>Endpoint detection" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
[ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null

REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: FAIL — no serial output at all (typist rc=$TYPIST_RC)"
    exit 2
fi
if grep -q "Triple fault" "$TRACE" 2>/dev/null || tr -d '\r' < "$REJOINED" | grep -q "KERNEL PANIC"; then
    echo "RESULT: FAIL — the guest faulted"
    exit 1
fi

LOG=$(tr -d '\r' < "$REJOINED")
# The rejoin filter DELETES every "[EDR ADVANCED]" line (it treats them as the
# periodic burst it repairs around), so the advanced alert lines this harness
# counts exist only in the raw log. Whole kprintf lines are not what the tear
# splits; the raw copy is the right source for them.
RAW=$(tr -d '\r' < "$SERIAL")
BEH=$(printf '%s\n' "$LOG" | grep -m1 "^EDRALERT beh pid=9999 ")
ADV_A=$(printf '%s\n' "$LOG" | grep -m1 "^EDRALERT adv pid=9998 ")
ADV_B=$(printf '%s\n' "$LOG" | grep -m1 "^EDRALERT adv pid=9997 ")
if [ -z "$BEH" ] || [ -z "$ADV_A" ] || [ -z "$ADV_B" ]; then
    echo "RESULT: FAIL — edralert did not report all three tasks (typist rc=$TYPIST_RC)"
    printf '%s\n' "$LOG" | grep "^EDRALERT" | sed 's/^/  /'
    exit 2
fi

BEH_LINES=$(printf '%s\n' "$LOG" | grep -E "^\[EDR (INFO|WARNING|CRITICAL)\] PID 9999: selftest")
BEH_N=$(printf '%s\n' "$BEH_LINES" | grep -c .)
BEH_SEQ=$(printf '%s\n' "$BEH_LINES" | sed -E 's/^\[EDR ([A-Z]+)\].*/\1/' | tr '\n' ' ')
A_LINES=$(printf '%s\n' "$RAW" | grep -E "^\[EDR ADVANCED\] PID 9998: selftest")
A_N=$(printf '%s\n' "$A_LINES" | grep -c .)
A_LAST=$(printf '%s\n' "$A_LINES" | tail -1)
B_N=$(printf '%s\n' "$RAW" | grep -cE "^\[EDR ADVANCED\] PID 9997: selftest")
ALERTS=$(printf '%s\n' "$LOG" | grep -m1 -E "^ +Alerts \.+ ")

echo "  record  : $BEH"
echo "            $ADV_A"
echo "            $ADV_B"
echo "  console : 9999 printed $BEH_N ($BEH_SEQ); 9998 printed $A_N; 9997 printed $B_N"
echo "  secstatus: ${ALERTS:-<no Alerts line>}"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }

case "$BEH" in *" count=6 last_sig=SHELLCODE_EXEC") : ;;
  *) fail "behavioral record should read count=6 last_sig=SHELLCODE_EXEC (suppressed alerts were dropped from the record)" ;; esac
case "$ADV_A" in *" count=5") : ;;
  *) fail "advanced record for 9998 should read count=5" ;; esac
case "$ADV_B" in *" count=1") : ;;
  *) fail "advanced record for 9997 should read count=1 (another task's alert hid it: the window is global)" ;; esac
[ "$BEH_SEQ" = "WARNING CRITICAL " ] \
    || fail "9999 should print exactly WARNING then CRITICAL (got '$BEH_SEQ')"
[ "$A_N" -eq 2 ] || fail "9998 should print exactly 2 lines (got $A_N)"
case "$A_LAST" in *"terminate=1)") : ;;
  *) fail "9998's last printed line should be the terminating alert (got '$A_LAST')" ;; esac
[ "$B_N" -eq 1 ] || fail "9997 should print exactly 1 line (got $B_N)"

if [ -z "$ALERTS" ]; then
    fail "secstatus has no Alerts line"
else
    BQ=$(printf '%s\n' "$ALERTS" | sed -nE 's/.* behavioral \(([0-9]+) unprinted\).*/\1/p')
    AQ=$(printf '%s\n' "$ALERTS" | sed -nE 's/.* advanced \(([0-9]+) unprinted\).*/\1/p')
    [ "${BQ:-0}" -ge 4 ] || fail "secstatus behavioral unprinted should be >= 4 (got '${BQ:-?}')"
    [ "${AQ:-0}" -ge 3 ] || fail "secstatus advanced unprinted should be >= 3 (got '${AQ:-?}')"
fi

if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS assertion(s); see $SERIAL"
    exit 1
fi
echo "RESULT: PASS — every alert is recorded; the console limit is per task and an escalation always prints"
exit 0
