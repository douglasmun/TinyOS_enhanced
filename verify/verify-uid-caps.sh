#!/bin/bash
# =============================================================================
# verify-uid-caps.sh -- one uid cannot take all of the pipe table or the VFS
# descriptor table.
#
# WHAT THIS PROVES
#
# Both tables are system-wide. pipe_table[8] had no per-uid share, so one user
# holding all 8 made every other user's PIPE_OP_CREATE fail. The VFS
# descriptor table (64, the last 6 root's) had no per-uid share either, and a
# ramfs directory open takes no ramfs fd, so it met no cap at all: one user's
# processes could fill the primary pool and starve every other user's opens.
#
#   sys_pipe CREATE   a non-root uid holding PIPE_USER_MAX (4), or reaching
#                     into the last PIPE_ROOT_RESERVED (2) free slots, gets
#                     -EAGAIN (-11)
#   vfs_alloc_fd      a non-root uid holding VFS_USER_MAX_FDS (24) gets
#                     -EAGAIN (-11)
#
# /capprobe.elf, run TWICE as a NON-ROOT user:
#
#   run 1 (loglevel normal)
#     pipes  4 creates succeed, the 5th returns -11; after destroying them a
#            create works again. The 4 creates are the positive control.
#     dirs   the parent opens D:/scratch until its own 16-slot table stops it (-24,
#            the same on both trees: the POSITIVE CONTROL that the probe can
#            open directories at all); a same-uid child then gets the rest of
#            the 24 and -11. Unfixed, the child gets a full 16 again. After
#            both close, an open works again.
#     Neither refusal may print a console line.
#   run 2 (loglevel debug)
#            the same counts (no slot drifted across processes or runs), and
#            the "create refused: uid" / "open refused: uid" traces MUST
#            appear: the refusals came from the caps, not from something else.
#
# Not witnessed here: the pipe root reserve (needs two uids holding slots at
# once). It shares the counting loop with the per-uid share.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: uidcaps.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=capuser
TESTPASS=cappass1

ISO=dist/tinyos.iso
SERIAL=uidcaps.log
TRACE=uidcaps-trace.log
MON_SOCK=/tmp/tinyos-uidcaps-mon.sock

PIPE_USER_MAX=4
VFS_USER_MAX=24
QUIET_RE='create refused: uid|open refused: uid'

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

[ -f userspace/capprobe.c ] || guard_fail "userspace/capprobe.c is missing"
grep -q "capprobe_elf_data" src/kernel.c \
    || guard_fail "src/kernel.c does not install /capprobe.elf into ramfs"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
for prog in shell capprobe; do
    python3 tools/sign_elf.py userspace/$prog.elf >/dev/null 2>&1 || exit 1
    python3 tools/elf_to_c.py userspace/$prog.elf.signed \
        src/${prog}_elf_data.c src/${prog}_elf_data.h ${prog}_elf_data >/dev/null || exit 1
done
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

if [ "$(strings "$ISO" | grep -c 'PROBE pipes made=')" -eq 0 ]; then
    guard_fail "the ISO does not contain capprobe's output strings"
fi

rm -f "$SERIAL" "$TRACE" "$MON_SOCK"

echo "==> Launching headless QEMU"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
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
exec /capprobe.elf=>PROBE done;\
su root=>Password for root;\
!$PASSWORD=>Switched to user: root;\
loglevel debug=>trace: debug;\
su $TESTUSER=>Now running as;\
!id=>uid=;\
exec /capprobe.elf=>PROBE done" \
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

# Run n = the lines after the (n-1)th "PROBE done" up to the nth.
slice_run() {
    printf '%s\n' "$RAW" | awk -v want="$1" '
        n == want - 1 { print }
        /PROBE done/ { n++ }'
}
RUN1=$(slice_run 1)
RUN2=$(slice_run 2)
printf '%s\n' "$RUN2" | grep -q "PROBE done" \
    || { echo "RESULT: INCONCLUSIVE — the probe did not complete twice (typist rc=$TYPIST_RC)"; printf '%s\n' "$RAW" | grep PROBE; exit 3; }
if printf '%s\n' "$RAW" | grep -q "PROBE dirs spawn rc="; then
    echo "RESULT: INCONCLUSIVE — the probe could not spawn its child"
    printf '%s\n' "$RAW" | grep PROBE
    exit 3
fi

field() {  # $1 = run text, $2 = line selector, $3 = key
    printf '%s\n' "$1" | grep "PROBE $2" | tail -1 \
        | sed -n "s/.* $3=\(-\{0,1\}[0-9][0-9]*\).*/\1/p"
}
for r in 1 2; do
    eval "T=\$RUN$r"
    eval "MADE$r=\$(field \"\$T\" 'pipes made=' made)"
    eval "PERR$r=\$(field \"\$T\" 'pipes made=' err)"
    eval "PAGAIN$r=\$(field \"\$T\" 'pipes made=' again)"
    eval "PAR$r=\$(field \"\$T\" 'dirs parent=' parent)"
    eval "PARERR$r=\$(field \"\$T\" 'dirs parent=' err)"
    eval "CHILD$r=\$(field \"\$T\" 'dirs child=' child)"
    eval "CERR$r=\$(field \"\$T\" 'dirs child=' err)"
    eval "DAGAIN$r=\$(field \"\$T\" 'dirs again=' again)"
done

echo "  pipes (run 1): made=${MADE1:-none} err=${PERR1:-none} again=${PAGAIN1:-none}   (expected $PIPE_USER_MAX, -11, >0)"
echo "  pipes (run 2): made=${MADE2:-none} err=${PERR2:-none} again=${PAGAIN2:-none}"
echo "  dirs  (run 1): parent=${PAR1:-none} err=${PARERR1:-none} child=${CHILD1:-none} err=${CERR1:-none} again=${DAGAIN1:-none}   (expected parent+child=$VFS_USER_MAX, child err -11, again >=0)"
echo "  dirs  (run 2): parent=${PAR2:-none} err=${PARERR2:-none} child=${CHILD2:-none} err=${CERR2:-none} again=${DAGAIN2:-none}"

for v in MADE1 PERR1 PAGAIN1 PAR1 PARERR1 CHILD1 CERR1 DAGAIN1 \
         MADE2 PERR2 PAGAIN2 PAR2 PARERR2 CHILD2 CERR2 DAGAIN2; do
    [ -n "${!v}" ] || { echo "RESULT: INCONCLUSIVE — the probe never reported $v"; printf '%s\n' "$RAW" | grep PROBE; exit 3; }
done

QUIET1=$(printf '%s\n' "$RUN1" | grep -E "$QUIET_RE")
has2() { printf '%s\n' "$RUN2" | grep -qE "$1"; }
echo "  run 1 console lines matching the refusal traces: $(printf '%s' "$QUIET1" | grep -c .)"
for p in "\[PIPE\] create refused: uid" "\[VFS\] open refused: uid"; do
    echo "  run 2 (debug) '$p': $(has2 "$p" && echo present || echo ABSENT)"
done

# Positive controls first: the probe could create pipes and open directories.
[ "$MADE1" -ge 1 ] || { echo "RESULT: INCONCLUSIVE — no pipe create succeeded"; exit 3; }
[ "$PAR1" -ge 1 ] || { echo "RESULT: INCONCLUSIVE — the parent could not open D:/scratch as a directory"; exit 3; }

FAILED=""
mark() { case " $FAILED " in *" $1 "*) ;; *) FAILED="$FAILED $1" ;; esac; }

for r in 1 2; do
    eval "M=\$MADE$r E=\$PERR$r A=\$PAGAIN$r"
    if [ "$M" -ne "$PIPE_USER_MAX" ] || [ "$E" -ne -11 ]; then
        mark pipes
        echo "FAIL pipes (run $r): $M creates before refusal $E (expected $PIPE_USER_MAX then -11)"
    fi
    if [ "$A" -le 0 ]; then
        mark pipes
        echo "FAIL pipes (run $r): a create after destroying them all returned $A"
    fi
done
if ! has2 "\[PIPE\] create refused: uid"; then
    mark pipes
    echo "FAIL pipes: no 'create refused: uid' trace at loglevel debug"
fi
case " $FAILED " in *" pipes "*) ;; *) echo "PASS pipes: a uid holds at most $PIPE_USER_MAX pipes; the refusal is -EAGAIN and the slots come back." ;; esac

for r in 1 2; do
    eval "P=\$PAR$r C=\$CHILD$r E=\$CERR$r A=\$DAGAIN$r"
    if [ $((P + C)) -ne "$VFS_USER_MAX" ] || [ "$E" -ne -11 ]; then
        mark dirs
        echo "FAIL dirs (run $r): parent $P + child $C directory opens, child refused with $E (expected $VFS_USER_MAX in all, then -11)"
    fi
    if [ "$A" -lt 0 ]; then
        mark dirs
        echo "FAIL dirs (run $r): an open after closing everything returned $A"
    fi
done
if ! has2 "\[VFS\] open refused: uid"; then
    mark dirs
    echo "FAIL dirs: no 'open refused: uid' trace at loglevel debug"
fi
case " $FAILED " in *" dirs "*) ;; *) echo "PASS dirs: a uid holds at most $VFS_USER_MAX VFS descriptors across its processes, directory opens included." ;; esac

if [ -n "$QUIET1" ]; then
    mark quiet
    echo "FAIL quiet: a refusal printed at loglevel normal:"
    printf '%s\n' "$QUIET1" | sed 's/^/    /'
else
    echo "PASS quiet: the refusals are silent by default."
fi

if [ -n "$FAILED" ]; then
    echo "RESULT: FAIL —$FAILED"
    printf '%s\n' "$RAW" | grep PROBE
    exit 1
fi
echo ""
echo "RESULT: PASS"
exit 0
