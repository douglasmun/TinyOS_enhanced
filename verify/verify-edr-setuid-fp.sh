#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-edr-setuid-fp.sh — EDR's privilege-escalation signature kills a reach
# for root, not ordinary credential handling.
#
# edr_behavioral_check() set EDR_FLAG_PRIVILEGE_CHANGE on any setuid/setgid/
# seteuid/setegid BEFORE running the signature, and the signature fired on
# "flag already set" -- so the very first credential call of any ring-3
# process raised a CRITICAL alert and the task was terminated (threat 90 is
# over the response threshold). Even setgid(getgid()) was fatal. The
# documented indicators are a change TO uid/gid 0 and a change after a high
# anomaly score; the signature now matches those.
#
# Legs (ring-3 root shell, /setuidprobe.elf -- see userspace/setuidprobe.c):
#   benign  setgid/setegid/setuid to self, seteuid(1000) then seteuid(0):
#           a temporary drop and its legal return. Must run to the end.
#   esc     POSITIVE CONTROL: setuid(1000) for good, then setuid(0). EDR must
#           kill it inside the second call.
#
# ASSERTIONS
#   1. POSITIVE CONTROL: esc dropped to uid 1000, was terminated by EDR, and
#      never printed "PROBE UNREACHED"
#   2. benign printed "PROBE benign done uid=0 euid=0"
#   3. exactly one EDR termination names setuidprobe (the esc leg's)
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: edrsetuid.log (serial), edrsetuid-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=edrsetuid.log
TRACE=edrsetuid-trace.log
RUN_DISK=/tmp/tinyos-edrsetuid-disk.img
MON_SOCK=/tmp/tinyos-edrsetuid-mon.sock

echo "==> Building userspace (incl. setuidprobe.elf)..."
(cd userspace && make) >/dev/null || exit 1

# Re-sign and re-embed BOTH the probe and the ring-3 shell, or this run grades
# a previous build of either.
python3 tools/sign_elf.py userspace/setuidprobe.elf userspace/setuidprobe.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/setuidprobe.elf.signed \
        src/setuidprobe_elf_data.c src/setuidprobe_elf_data.h setuidprobe_elf_data >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1

echo "==> Building kernel + ISO..."
make >/dev/null || exit 1
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

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# Each run waits for the shell's "exited with status" line: the probe never
# exits 0 (benign 3, esc 1, killed 137), so that line marks the end of a run
# whether or not EDR killed it. Typing the next command while a probe still
# runs loses it.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=300 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
!/setuidprobe.elf=>setuidprobe.elf: exited with status;\
!/setuidprobe.elf esc=>setuidprobe.elf: exited with status" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"
cleanup

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

CLEAN=$(tr -d '\r' < "$REJOINED")
printf '%s\n' "$CLEAN" | grep -aE '^PROBE |EDR RESPONSE\] Terminating|setuidprobe.elf: exited|setuidprobe.elf esc: exited' | sed 's/^/    /'

KILLS=$(printf '%s\n' "$CLEAN" | grep -ac "EDR RESPONSE\] Terminating PID [0-9]* (.*setuidprobe")

FAILS=0
# 2. Benign leg survived.
if ! printf '%s\n' "$CLEAN" | grep -aq "^PROBE benign done uid=0 euid=0"; then
    echo "  FAIL: ordinary credential calls did not run to completion"
    FAILS=$((FAILS + 1))
fi
# 3. Only the escalation was killed.
if [ "$KILLS" -gt 1 ]; then
    echo "  FAIL: EDR terminated $KILLS setuidprobe runs, expected 1"
    FAILS=$((FAILS + 1))
fi

# 1. Positive control. An unfixed kernel kills the esc leg at its first
# (benign) call too, so it never drops -- that is the defect above, already
# counted, not a broken harness. Only on an otherwise clean run does a missing
# drop leave the escalation check ungraded.
if ! printf '%s\n' "$CLEAN" | grep -aq "^PROBE dropped uid=1000"; then
    if [ "$FAILS" -eq 0 ]; then
        echo "RESULT: INCONCLUSIVE — the esc leg never dropped to uid 1000"
        exit 3
    fi
    echo "  (esc leg killed before its drop, so the escalation check is ungraded)"
else
    if printf '%s\n' "$CLEAN" | grep -aq "^PROBE UNREACHED"; then
        echo "  FAIL: setuid(0) after a full drop was not stopped"
        FAILS=$((FAILS + 1))
    fi
    if [ "$KILLS" -lt 1 ]; then
        echo "  FAIL: EDR terminated no setuidprobe run (the escalation went undetected)"
        FAILS=$((FAILS + 1))
    fi
fi

if grep -aqi "triple fault\|PANIC" "$REJOINED"; then
    echo "  FAIL: kernel panicked during the run"
    FAILS=$((FAILS + 1))
fi
if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS check(s)"
    exit 1
fi
echo "RESULT: PASS — benign credential calls survive; setuid(0) after a drop is killed"
exit 0
