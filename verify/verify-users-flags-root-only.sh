#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-users-flags-root-only.sh — `users` shows account flags to root only.
#
# The kernel shell's `users` is ungated (any user reaches it through `kshell`)
# and printed every account's flags byte, which carries USER_FLAG_LOCKED: a
# login sprayer could watch an account lock and learn exactly when to stop.
# Names, uids and home directories are public (they are in every listing);
# the flags are not.
#
# ASSERTIONS
#   1. POSITIVE CONTROL: both listings name the prober account, so both legs
#      ran `users` and it printed the table
#   2. the root listing still shows flags=
#   3. the non-root listing (after `su` to the prober) shows no flags=
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: usersflags.log (serial), usersflags-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
PROBER=ufprober
PROBERPW=ufprober1

ISO=dist/tinyos.iso
SERIAL=usersflags.log
TRACE=usersflags-trace.log
RUN_DISK=/tmp/tinyos-usersflags-disk.img
MON_SOCK=/tmp/tinyos-usersflags-mon.sock

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

# Each listing is bracketed by echo markers; the trailing `id` waits for the
# prober's uid so the second listing has printed before the verdict.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=300 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
useradd $PROBER=>Enter password for new user;\
!$PROBERPW=>created;\
kshell=>Switching to the kernel shell;\
!echo ufrootbegin;\
!users;\
!echo ufrootend;\
su $PROBER=>Now running as;\
!echo ufuserbegin;\
!users;\
!echo ufuserend;\
!id=>uid=10" \
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
# Lines strictly between the echo output lines (not the typed "echo X" lines).
between() {
    printf '%s\n' "$CLEAN" | awk -v b="$1" -v e="$2" '
        $0 == b { on = 1; buf = ""; next }
        $0 == e { if (on) out = buf; on = 0; next }
        on { buf = buf $0 "\n" }
        END { printf "%s", out }'
}
ROOTLIST=$(between ufrootbegin ufrootend)
USERLIST=$(between ufuserbegin ufuserend)

echo "  root listing:"; printf '%s\n' "$ROOTLIST" | sed 's/^/      /'
echo "  non-root listing:"; printf '%s\n' "$USERLIST" | sed 's/^/      /'

if ! printf '%s\n' "$ROOTLIST" | grep -aq "$PROBER .*uid=" ||
   ! printf '%s\n' "$USERLIST" | grep -aq "$PROBER .*uid="; then
    echo "RESULT: INCONCLUSIVE — a listing is missing or does not name $PROBER"
    exit 3
fi

FAILS=0
if ! printf '%s\n' "$ROOTLIST" | grep -aq "flags="; then
    echo "  FAIL: root no longer sees account flags"
    FAILS=$((FAILS + 1))
fi
if printf '%s\n' "$USERLIST" | grep -aq "flags="; then
    echo "  FAIL: a non-root user sees account flags (lock state)"
    FAILS=$((FAILS + 1))
fi
if grep -aqi "triple fault\|PANIC" "$REJOINED"; then
    echo "  FAIL: kernel panicked during the run"
    FAILS=$((FAILS + 1))
fi
if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS check(s)"
    exit 1
fi
echo "RESULT: PASS — users shows flags to root only"
exit 0
