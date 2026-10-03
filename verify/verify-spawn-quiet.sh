#!/bin/bash
# =============================================================================
# verify-spawn-quiet.sh -- a ring-3 SYS_SPAWN prints one verdict line, and
# nothing that leaks an address, to the kernel console.
#
# WHAT THIS PROVES
#
# The kernel console is the stream ring-3 output shares. Every successful
# SYS_SPAWN used to print about 24 lines into it: the file size, the hash and
# signature PASS lines, the signer's public key, a 12-line ELF header dump,
# "[PROCESS] Created user task" with the child's ASLR-randomized stack address
# and private /tmp name, a scheduler "not found in ready queue" WARNING that
# fires on every normal exit, and the page-table teardown with physical
# addresses. Any unprivileged loop drove it.
#
# Now the load trace is kdbg (`loglevel debug` brings it back) and each load
# prints exactly one verdict line, which kprintf.h requires stay visible:
#
#   [ELF] Signature verification: PASS ('fdprobe.elf')
#
# `/fdprobe.elf quiet`, run unprivileged, spawns 5 children (4 exit, 1 is
# killed). Between "PROBE quiet start" and "PROBE quiet exits=" the harness
# requires:
#
#   verdicts = 5     POSITIVE CONTROL: the five loads happened and were checked
#   other    = 0     no other spawn-path kernel line ([ELF] [EXEC] [PROCESS]
#                    [SCHEDULER] [PAGING] [PAE], the header dump) landed in the
#                    user's output
#   leaks    = 0     no "User stack:" and no "phys=" anywhere in the window
#
# secstatus before and after brackets the run:
#
#   ELF loads verified +6        the 5 children plus /fdprobe.elf itself
#   refused +1, bad-signature +0 a 6-byte text file exec'd as a program is
#                                refused (too small for an ELF header) and is
#                                counted, not a signature refusal
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: spawnquiet.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=spuser
TESTPASS=sppass12

ISO=dist/tinyos.iso
SERIAL=spawnquiet.log
TRACE=spawnquiet-trace.log
RUN_DISK=/tmp/tinyos-spawnquiet-disk.img
MON_SOCK=/tmp/tinyos-spawnquiet-mon.sock

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

grep -q '"quiet"' userspace/fdprobe.c \
    || guard_fail "userspace/fdprobe.c has no quiet mode; nothing would be spawned"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
for prog in shell fdprobe; do
    python3 tools/sign_elf.py userspace/$prog.elf >/dev/null 2>&1 || exit 1
    python3 tools/elf_to_c.py userspace/$prog.elf.signed \
        src/${prog}_elf_data.c src/${prog}_elf_data.h ${prog}_elf_data >/dev/null || exit 1
done
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

echo "==> Launching headless QEMU"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!
( while kill -0 "$QEMU_PID" 2>/dev/null; do
      if grep -qa "KERNEL PANIC" "$SERIAL" 2>/dev/null; then
          sleep 2; kill "$QEMU_PID"; pkill -P $$ -f qemu_typist; break
      fi
      sleep 1
  done ) &
WATCH_PID=$!
cleanup() { kill "$QEMU_PID" "$WATCH_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# The refused leg runs BETWEEN the two secstatus calls, after the quiet run,
# so its one line falls outside the PROBE window the noise count reads.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
su $TESTUSER=>Now running as;\
!id=>uid=;\
secstatus=>ELF signatures;\
exec /fdprobe.elf quiet=>PROBE done;\
echo hello > /scratch/sq.elf;\
!id=>uid=;\
exec /scratch/sq.elf;\
!id=>uid=;\
secstatus=>ELF signatures" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

if grep -qa "KERNEL PANIC" "$SERIAL"; then
    echo "RESULT: FAIL — the kernel panicked"
    grep -a -A12 "KERNEL PANIC" "$SERIAL" | head -30
    exit 1
fi

grep -qa "PROBE quiet exits=" "$SERIAL" \
    || { echo "RESULT: INCONCLUSIVE — /fdprobe.elf quiet did not report."; grep -a PROBE "$SERIAL"; exit 3; }

. verify/edr-rejoin.sh
WINDOW=$(rejoin_edr < "$SERIAL" | awk '/PROBE quiet start/{on=1} on{print} /PROBE quiet exits=/{exit}')
# Unanchored on purpose: the EDR burst can tear any line at any character
# (verify/CLAUDE.md), so neither count may depend on a line start or end.
# OTHER names the spawn path's own prefixes rather than "anything else",
# for the same reason: an EDR alert in the window is not spawn noise.
VERDICT="Signature verification: PASS ('fdprobe.elf')"
SPAWN_NOISE='\[(ELF|EXEC|PROCESS|SCHEDULER|PAGING|PAE)\]|=== ELF HEADER|Prog Hdr:|Sect Hdr:'
VERDICTS=$(printf '%s\n' "$WINDOW" | grep -cF "$VERDICT")
OTHER=$(printf '%s\n' "$WINDOW" | grep -vF "$VERDICT" | grep -cE "$SPAWN_NOISE")
LEAKS=$(printf '%s\n' "$WINDOW" | grep -c -e 'User stack:' -e 'phys=')

# The two "ELF loads" lines secstatus printed, in order.
STATS=$(grep -a "ELF loads \.\.\." "$SERIAL" | tr -d '\r')
NSTATS=$(printf '%s\n' "$STATS" | grep -c .)
field() { printf '%s\n' "$STATS" | sed -n "${1}p" | sed -n "s/.* \([0-9][0-9]*\) $2.*/\1/p"; }
V0=$(field 1 verified); V1=$(field 2 verified)
R0=$(field 1 refused);  R1=$(field 2 refused)
B0=$(printf '%s\n' "$STATS" | sed -n 1p | sed -n 's/.*(\([0-9][0-9]*\) bad-signature).*/\1/p')
B1=$(printf '%s\n' "$STATS" | sed -n 2p | sed -n 's/.*(\([0-9][0-9]*\) bad-signature).*/\1/p')

echo "  window: verdicts=$VERDICTS other=$OTHER leaks=$LEAKS (expected 5, 0, 0)"
echo "  secstatus: verified ${V0:-?} -> ${V1:-?}, refused ${R0:-?} -> ${R1:-?}, bad-signature ${B0:-?} -> ${B1:-?}"
echo "             (expected +6, +1, +0)"

if [ "$OTHER" -ne 0 ] || [ "$LEAKS" -ne 0 ]; then
    echo "RESULT: FAIL — $OTHER other kernel line(s), $LEAKS address leak(s) in the user's output"
    printf '%s\n' "$WINDOW" | grep -vF "$VERDICT" | grep -E "$SPAWN_NOISE|User stack:|phys=" | head -15
    exit 1
fi
[ "$VERDICTS" -eq 5 ] \
    || { echo "RESULT: FAIL — expected 5 verdict lines, saw $VERDICTS"; exit 1; }
[ "$NSTATS" -eq 2 ] && [ -n "$V0" ] && [ -n "$V1" ] && [ -n "$R0" ] && [ -n "$R1" ] \
    && [ -n "$B0" ] && [ -n "$B1" ] \
    || { echo "RESULT: INCONCLUSIVE — did not read two secstatus 'ELF loads' lines"; exit 3; }
if [ $((V1 - V0)) -ne 6 ] || [ $((R1 - R0)) -ne 1 ] || [ $((B1 - B0)) -ne 0 ]; then
    echo "RESULT: FAIL — the load counters did not move as expected"
    exit 1
fi

echo "RESULT: PASS — 5 spawns printed 5 verdict lines and nothing else; loads and a refusal were counted"
exit 0
