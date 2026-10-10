#!/bin/bash
# =============================================================================
# verify-fat32-fd-cap.sh -- one uid cannot take all of fat32's open-file table,
# and the driver's ring-3-reachable error paths stay off the console.
#
# WHAT THIS PROVES
#
# fat32's open_files[32] is one table for the whole system and C: has no
# ownership model, so one uid could hold all 32 slots and lock everyone,
# root included, out of C:. fat32_open() now refuses a non-root uid holding
# FAT32_USER_MAX_FDS (8) or reaching into the last 4 free slots, with -EAGAIN
# (-11) -- and fat32_vfs_open() must not read that as "not found" and go on to
# O_CREAT the file it refused to open.
#
# The driver also printed a console line for errors any user triggers at will
# ("Not a directory: <user path component>", "Cannot read/write directory",
# "Too many open files", "Disk full"): per-op prints on the serial stream the
# ring-3 shell shares. They are kdbg() now.
#
# /fatprobe.elf cap, run TWICE as a NON-ROOT user:
#
#   run 1 (loglevel normal)
#     cap    8 opens of one file succeed and the 9th returns -11; an O_CREAT
#            open at the cap returns <0 and leaves no file (stat <0); after
#            closing all 8 an open works again (the count did not drift).
#            The 8 successful opens are the POSITIVE CONTROL for the refusal.
#     quiet  opening through a file, and reading/writing a directory opened
#            as a file, all fail -- and print NONE of the driver's lines.
#   run 2 (loglevel debug)
#            the same lines MUST appear: the positive control that run 1's
#            silence is demotion to kdbg, not deletion, and that the probe
#            really reached those paths. Also "open refused: uid", which shows
#            the 9th open was refused by the cap and not by something else.
#
# Not witnessed here: the root reserve (needs several uids holding slots at
# once) and "Disk full" (needs the 128 MB volume filled through 512-byte
# writes). Both share the code paths above.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: fat32cap.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=fatcuser
TESTPASS=fatcpass1

ISO=dist/tinyos.iso
SERIAL=fat32cap.log
TRACE=fat32cap-trace.log
RUN_DISK=/tmp/tinyos-fat32cap-disk.img
MON_SOCK=/tmp/tinyos-fat32cap-mon.sock

# Old text (kprintf "ERROR: ...") and new (kdbg) both match.
QUIET_RE='Not a directory: |Cannot read from directory|Cannot write to directory|\[FAT32\] open refused|Too many open files'

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

[ -f userspace/fatprobe.c ] && grep -q '"cap"' userspace/fatprobe.c \
    || guard_fail "userspace/fatprobe.c has no cap mode"
grep -q "fatprobe_elf_data" src/kernel.c \
    || guard_fail "src/kernel.c does not install /fatprobe.elf into ramfs"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
for prog in shell fatprobe; do
    python3 tools/sign_elf.py userspace/$prog.elf >/dev/null 2>&1 || exit 1
    python3 tools/elf_to_c.py userspace/$prog.elf.signed \
        src/${prog}_elf_data.c src/${prog}_elf_data.h ${prog}_elf_data >/dev/null || exit 1
done
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

if [ "$(strings "$ISO" | grep -c 'PROBE cap opens=')" -eq 0 ]; then
    guard_fail "the ISO does not contain fatprobe's cap output strings"
fi

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
exec /fatprobe.elf cap=>PROBE done;\
su root=>Password for root;\
!$PASSWORD=>Switched to user: root;\
loglevel debug=>trace: debug;\
su $TESTUSER=>Now running as;\
!id=>uid=;\
exec /fatprobe.elf cap=>PROBE done" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

RAW=$(tr -d '\r' < "$SERIAL")
if printf '%s\n' "$RAW" | grep -q "KERNEL PANIC"; then
    echo "RESULT: FAIL — the kernel panicked"
    printf '%s\n' "$RAW" | grep -A12 "KERNEL PANIC" | head -30
    exit 1
fi

# Run n = the lines after the (n-1)th "PROBE done" up to the nth, so a line
# from the debug run cannot be counted against the normal one.
slice_run() {
    printf '%s\n' "$RAW" | awk -v want="$1" '
        n == want - 1 { print }
        /PROBE done/ { n++ }'
}
RUN1=$(slice_run 1)
RUN2=$(slice_run 2)
printf '%s\n' "$RUN2" | grep -q "PROBE done" \
    || { echo "RESULT: INCONCLUSIVE — the probe did not complete twice (typist rc=$TYPIST_RC)"; printf '%s\n' "$RAW" | grep PROBE; exit 3; }

if printf '%s\n' "$RAW" | grep -qE "PROBE (open|mkdir) .* failed"; then
    echo "RESULT: INCONCLUSIVE — the probe could not set up its files"
    printf '%s\n' "$RAW" | grep PROBE
    exit 3
fi

field() {  # $1 = run text, $2 = line selector, $3 = key
    printf '%s\n' "$1" | grep "PROBE cap $2" | tail -1 \
        | sed -n "s/.* $3=\(-\{0,1\}[0-9][0-9]*\).*/\1/p"
}
OPENS=$(field "$RUN1" "opens=" opens); ERR=$(field "$RUN1" "opens=" err)
NEW=$(field "$RUN1" "opens=" new);     REOPEN=$(field "$RUN1" "opens=" reopen)
OPENS2=$(field "$RUN2" "opens=" opens)
NOTDIR=$(field "$RUN1" quiet notdir); DREAD=$(field "$RUN1" quiet dirread); DWRITE=$(field "$RUN1" quiet dirwrite)

echo "  cap   (run 1): opens=${OPENS:-none} err=${ERR:-none} new=${NEW:-none} reopen=${REOPEN:-none}   (expected 8, -11, <0, 0)"
echo "  cap   (run 2): opens=${OPENS2:-none}   (expected = run 1: the slots came back across processes)"
echo "  quiet (run 1): notdir=${NOTDIR:-none} dirread=${DREAD:-none} dirwrite=${DWRITE:-none}   (expected all <0)"

for v in OPENS ERR NEW REOPEN OPENS2 NOTDIR DREAD DWRITE; do
    [ -n "${!v}" ] || { echo "RESULT: INCONCLUSIVE — the probe never reported $v"; printf '%s\n' "$RAW" | grep PROBE; exit 3; }
done

QUIET1=$(printf '%s\n' "$RUN1" | grep -E "$QUIET_RE")
has2() { printf '%s\n' "$RUN2" | grep -qE "$1"; }
echo "  run 1 console lines matching the driver's error prints: $(printf '%s' "$QUIET1" | grep -c .)"
for p in "Not a directory: " "Cannot read from directory" "Cannot write to directory" "open refused: uid"; do
    echo "  run 2 (debug) '$p': $(has2 "$p" && echo present || echo ABSENT)"
done

# Positive controls first.
[ "$OPENS" -ge 1 ] || { echo "RESULT: INCONCLUSIVE — no open of C:/CAP/F.BIN succeeded"; exit 3; }
for p in "Not a directory: " "Cannot read from directory" "Cannot write to directory"; do
    has2 "$p" || { echo "RESULT: INCONCLUSIVE — '$p' never printed even at loglevel debug: the probe did not reach that path, or the line was deleted"; exit 3; }
done

FAILED=""
mark() { case " $FAILED " in *" $1 "*) ;; *) FAILED="$FAILED $1" ;; esac; }

if [ "$OPENS" -ne 8 ] || [ "$ERR" -ne -11 ]; then
    mark cap
    echo "FAIL cap: $OPENS opens before refusal $ERR (expected 8 then -11)"
fi
if [ "$NEW" -ge 0 ]; then
    mark cap
    echo "FAIL cap: the refused O_CREAT open created C:/CAP/NEW.BIN"
fi
if [ "$REOPEN" -ne 0 ] || [ "$OPENS2" -ne "$OPENS" ]; then
    mark cap
    echo "FAIL cap: slots did not come back (reopen=$REOPEN, run 2 opens=$OPENS2)"
fi
if ! has2 "open refused: uid"; then
    mark cap
    echo "FAIL cap: no 'open refused: uid' trace at loglevel debug — the 9th open was not refused by the cap"
fi
case " $FAILED " in *" cap "*) ;; *) echo "PASS cap: a uid holds at most 8 C: files; the refusal is -EAGAIN and creates nothing." ;; esac

if [ "$NOTDIR" -ge 0 ] || [ "$DREAD" -ge 0 ] || [ "$DWRITE" -ge 0 ]; then
    mark quiet
    echo "FAIL quiet: an error path succeeded (notdir=$NOTDIR dirread=$DREAD dirwrite=$DWRITE)"
fi
if [ -n "$QUIET1" ]; then
    mark quiet
    echo "FAIL quiet: the driver printed at loglevel normal:"
    printf '%s\n' "$QUIET1" | sed 's/^/    /'
fi
case " $FAILED " in *" quiet "*) ;; *) echo "PASS quiet: the error paths are silent by default and traced at loglevel debug." ;; esac

if [ -n "$FAILED" ]; then
    echo "RESULT: FAIL —$FAILED"
    printf '%s\n' "$RAW" | grep PROBE
    exit 1
fi
echo ""
echo "RESULT: PASS"
exit 0
