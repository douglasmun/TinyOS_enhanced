#!/usr/bin/env bash
#
# verify-dispatch-block-quiet.sh — the dispatcher's two block paths count,
# they do not print, and the EDR block is audited once per task, not once per
# call.
#
# THE BUG (latent)
#
# syscall_dispatch() printed a line for every call it blocked:
#
#   [SYSCALL FILTER] PID n: Blocked syscall s      (per-task filter)
#   [EDR BEHAVIORAL] PID n: Blocked suspicious...  (EDR verdict)
#
# and the EDR block also wrote an AUDIT_CRITICAL record, which audit_log
# echoes to the console as well. Both sit on the ring-3 syscall path: a
# blocked task that keeps calling drives two console lines per syscall and
# churns the volatile audit ring until the forensic record of everything else
# is gone. Neither path has a live trigger today -- edr_detect_shellcode() is
# a placeholder returning false and nothing enables a filter -- which is
# exactly how a per-operation print survives until the day a detector goes
# live.
#
# THE VEHICLE
#
# `edrblock` (TINYOS_FAULT_INJECT kernel-shell command, syscall.c): on
# hello.elf's first SYS_WRITE it installs a filter denying SYS_YIELD and
# forces that write and the next four through the EDR block path. hello
# yields 3 times and writes 8 lines, so it still exits normally.
#
# ASSERTIONS
#
#   vehicle   : "Hello from ELF!" absent (its write was blocked) and
#               "ELF program exiting." present (it lived)   -- POSITIVE CONTROL
#   quiet     : 0 "[EDR BEHAVIORAL] PID" and 0 "[SYSCALL FILTER] PID" lines
#   audit     : exactly 1 "EDR blocked syscall" audit line (first per task)
#   surfaced  : secstatus reports >= 3 filter-blocked and >= 5 edr-blocked
#
# NB: `make clean`s on exit -- TINYOS_FAULT_INJECT objects must not linger.
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=dispblock.log
TRACE=dispblock-trace.log
MON_SOCK=/tmp/tinyos-dispblock-mon.sock

guard_fail() { echo "HARNESS GUARD FAILED: $*"; exit 2; }

grep -q "edr_block_point" src/syscall.c \
    || guard_fail "src/syscall.c has no edr_block_point()"
grep -q '"edrblock"' src/shell.c \
    || guard_fail "src/shell.c has no edrblock command"

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

# Kernel shell throughout: `exec` there runs hello.elf as a ring-3 process,
# so every blocked call still enters through int 0x80 from CPL 3.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="edrblock" \
TINYOS_EXPECT="edrblock armed" \
TINYOS_FOLLOWUP_CMDS="\
exec /hello.elf=>ELF program exiting;\
secstatus=>Endpoint detection" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
[ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: FAIL — no serial output at all (typist rc=$TYPIST_RC)"
    exit 2
fi
if grep -q "Triple fault" "$TRACE" 2>/dev/null || tr -d '\r' < "$SERIAL" | grep -q "KERNEL PANIC"; then
    echo "RESULT: FAIL — the guest faulted"
    exit 1
fi

# Raw log: every line counted here is a whole kprintf line, and the EDR rejoin
# filter would delete nothing relevant but buys nothing either.
LOG=$(tr -d '\r' < "$SERIAL")
AFTER=$(printf '%s\n' "$LOG" | sed -n '/edrblock armed/,$p')

HELLO=$(printf '%s\n' "$AFTER" | grep -c "Hello from ELF!")
EXITING=$(printf '%s\n' "$AFTER" | grep -c "ELF program exiting.")
if [ "$EXITING" -lt 1 ] || [ "$HELLO" -ne 0 ]; then
    echo "RESULT: FAIL — the vehicle did not run as designed (CONTROL-DEAD)"
    echo "  'Hello from ELF!' lines: $HELLO (want 0: its write is blocked)"
    echo "  'ELF program exiting.'   : $EXITING (want 1: hello survives the blocks)"
    exit 2
fi

EDR_N=$(printf '%s\n' "$AFTER" | grep -c "\[EDR BEHAVIORAL\] PID")
FLT_N=$(printf '%s\n' "$AFTER" | grep -c "\[SYSCALL FILTER\] PID")
AUD_N=$(printf '%s\n' "$AFTER" | grep -c "EDR blocked syscall")
DISP=$(printf '%s\n' "$AFTER" | grep -m1 -E "^ +Syscall blocks \.+ ")
FB=$(printf '%s\n' "$DISP" | sed -nE 's/.* ([0-9]+) filter-blocked.*/\1/p')
EB=$(printf '%s\n' "$DISP" | sed -nE 's/.* ([0-9]+) edr-blocked.*/\1/p')

echo "  vehicle   : Hello=$HELLO (blocked)  exiting=$EXITING (survived)"
echo "  console   : $EDR_N [EDR BEHAVIORAL], $FLT_N [SYSCALL FILTER] lines"
echo "  audit     : $AUD_N 'EDR blocked syscall' line(s)"
echo "  secstatus : ${DISP:-<no Syscall blocks line>}"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
[ "$EDR_N" -eq 0 ] || fail "the EDR block printed per call ($EDR_N lines)"
[ "$FLT_N" -eq 0 ] || fail "the syscall filter printed per call ($FLT_N lines)"
[ "$AUD_N" -eq 1 ] || fail "the EDR block should be audited once per task (got $AUD_N)"
[ "${FB:-0}" -ge 3 ] || fail "secstatus filter-blocked should be >= 3 (got '${FB:-?}')"
[ "${EB:-0}" -ge 5 ] || fail "secstatus edr-blocked should be >= 5 (got '${EB:-?}')"

if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS assertion(s); see $SERIAL"
    exit 1
fi
echo "RESULT: PASS — dispatcher blocks are counted, not printed; the EDR block is audited once per task"
exit 0
