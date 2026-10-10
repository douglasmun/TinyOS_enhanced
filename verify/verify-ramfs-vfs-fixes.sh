#!/usr/bin/env bash
#
# verify-ramfs-vfs-fixes.sh — three RAMFS/VFS bugs, one boot.
#
# F1  The kernel shell's `ls` and `find` walked node->children themselves,
#     past every check ring 3's open/stat make: any user could list root's
#     0711 `/` (and so every name hidden from them there), and `ls -l` showed
#     the mode, owner and size of a file stat refuses them. Fix: one listing
#     primitive, ramfs_list(), which requires READ on the directory listed
#     and on a file described; both commands go through it.
#
# F2  ramfs_write() at the 64 KB per-file cap returned 0 for a nonzero count
#     -- a write() loop on the return value retries forever -- and printed a
#     kernel warning on every write that crossed the cap, console output any
#     ring-3 program could drive at will. Fix: the short write is silent and
#     a write that cannot land a byte fails with -EFBIG.
#
# F3  vfs_alloc_fd() panicked when a privileged caller found the reserved
#     pool empty. Root's ring-3 processes reach that: directory opens count
#     against no per-uid cap and a process may hold 16, so five processes
#     opening D:/ until refused took the kernel down. Fix: -ENFILE.
#
# WHAT IS ASSERTED
#
#   F1  Root creates /zzsecret (0600 in the 0711 root) and /scratch/rootfile
#       (0600 in the 0777 /scratch), then `su`s the kernel shell to an
#       unprivileged user, who runs `ls /`, `ls /scratch`,
#       `ls -l /scratch/rootfile` and `find /`. The name zzsecret and
#       rootfile's mode line must not appear. Controls: both refusals are
#       printed (the commands ran), and `ls /scratch` still lists rootfile --
#       a readable directory hides nothing.
#   F2  The same user, `exec /fdprobe.elf capwrite`: 100 bytes, then 4 KB
#       chunks to the cap, then one more. Must read total=65536 short=3996
#       next=-27, and no "Short write" warning may reach the console.
#   F3  Root, ring 3: `/fdprobe.elf dirfill` (4 children + itself open D:/
#       until refused). Some open must be refused -23 (ENFILE), the kernel
#       must not panic, and `id` must still answer afterwards. Last, because
#       on an unfixed kernel it panics.
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem (nothing proven).

set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=lsuser
TESTPASS=lspass1
ISO=dist/tinyos.iso
SERIAL=ramfs-vfs-fixes.log
TRACE=ramfs-vfs-fixes-trace.log
RUN_DISK=/tmp/tinyos-ramfsvfs-disk.img
MON_SOCK=/tmp/tinyos-ramfsvfs-mon.sock

guard_fail() { echo "RESULT: INCONCLUSIVE — $*"; exit 2; }

command -v qemu-system-i386 >/dev/null 2>&1 || guard_fail "qemu-system-i386 not found"
[ -f disk.img ] || guard_fail "disk.img not found"

echo "==> Building kernel + ISO..."
make >/dev/null 2>&1 || guard_fail "build failed"
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || guard_fail "mkrescue failed"

rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
cp disk.img "$RUN_DISK"

echo "==> Launching headless QEMU..."
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none 2>/dev/null &
QEMU_PID=$!
cleanup() {
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "${QEMU_PID:-}" ] && wait "$QEMU_PID" 2>/dev/null
    rm -f "$MON_SOCK" "$RUN_DISK"
    return 0
}
trap cleanup EXIT

# Session 1 (root): fixtures, the test account, kshell su'd to it (F1, F2),
#                   logout.
# Session 2 (root): F3, then `id` to show the kernel is still alive.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=300 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
!write /zzsecret s;\
!write /scratch/rootfile r;\
!stat /scratch/rootfile=>mode=600;\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
kshell=>Switching to the kernel shell;\
su $TESTUSER=>Now running as;\
!ls /;\
!ls /scratch;\
!ls -l /scratch/rootfile;\
!find /;\
!=>;\
!=>;\
!exec /fdprobe.elf capwrite=>PROBE capwrite;\
!=>;\
!=>;\
logout=>TinyOS login:;\
root=>assword;\
!$PASSWORD=>'help' for builtins;\
!=>\$;\
!/fdprobe.elf dirfill=>exited with status;\
!id=>uid=0" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup
trap - EXIT

echo ""
echo "================ VERDICT ================"

[ -s "$SERIAL" ] || guard_fail "no serial output at all (typist rc=$TYPIST_RC)"

FAILS=()
note_fail() { FAILS+=("$1"); }

# grep -c, not grep -q: under pipefail grep -q SIGPIPEs printf on an early
# match and the 141 reads as a miss (see verify-psvisibility.sh).
count_in() { printf '%s\n' "$1" | grep -ac -- "$2"; }

SU_LINE=$(grep -na "Now running as" "$SERIAL" | head -1 | cut -d: -f1)
[ -n "$SU_LINE" ] || guard_fail "the kernel shell never su'd to $TESTUSER (typist rc=$TYPIST_RC)"
LOGIN_LINES=$(grep -na "TinyOS login:" "$SERIAL" | cut -d: -f1)
LAST_LOGIN=$(printf '%s\n' "$LOGIN_LINES" | tail -1)
[ "$LAST_LOGIN" -gt "$SU_LINE" ] || guard_fail "never logged out of the $TESTUSER kernel shell (typist rc=$TYPIST_RC)"
USER_REGION=$(sed -n "${SU_LINE},${LAST_LOGIN}p" "$SERIAL")
FINAL_REGION=$(tail -n +"$LAST_LOGIN" "$SERIAL")

# --- F1 ------------------------------------------------------------------
# Typed lines contain "/scratch/rootfile", never "zzsecret" and
# never a mode string, so neither pattern can match the echo of a command.
if [ "$(count_in "$USER_REGION" "zzsecret")" -gt 0 ]; then
    note_fail "F1: $TESTUSER's kernel shell named /zzsecret -- \`ls /\` or \`find\` listed root's 0711 directory"
fi
if [ "$(count_in "$USER_REGION" "rw-------.*rootfile")" -gt 0 ]; then
    note_fail "F1: $TESTUSER's \`ls -l\` showed the metadata of root's 0600 /scratch/rootfile, which stat refuses"
fi
ROOT_REFUSED=$(count_in "$USER_REGION" "ls: cannot open '/': Permission denied")
FILE_REFUSED=$(count_in "$USER_REGION" "ls: cannot open '/scratch/rootfile': Permission denied")
FIND_REFUSED=$(count_in "$USER_REGION" "find: cannot read '/': Permission denied")
if [ "${#FAILS[@]}" -eq 0 ] && { [ "$ROOT_REFUSED" -eq 0 ] || [ "$FILE_REFUSED" -eq 0 ] || [ "$FIND_REFUSED" -eq 0 ]; }; then
    guard_fail "F1: refusals ls/=$ROOT_REFUSED ls-l=$FILE_REFUSED find=$FIND_REFUSED -- a command never ran, so its silence proves nothing"
fi
# Positive control: a listing line naming rootfile that is not a typed command.
LISTED=$(printf '%s\n' "$USER_REGION" | grep -av "ls -l\|cannot open" | grep -ac "rootfile")
[ "$LISTED" -gt 0 ] || guard_fail "F1: \`ls /scratch\` did not list rootfile -- the primitive refuses readable directories too"

# --- F2 ------------------------------------------------------------------
CAP=$(printf '%s\n' "$USER_REGION" | grep -ao 'PROBE capwrite total=[-0-9]* short=[-0-9]* next=[-0-9]*' | tail -1)
[ -n "$CAP" ] || guard_fail "F2: no capwrite line"
case "$CAP" in
    *"total=65536 short=3996 "*) ;;
    *) guard_fail "F2: the probe never reached the cap: $CAP" ;;
esac
case "$CAP" in
    *"next=-27") ;;
    *) note_fail "F2: a write at the 64 KB cap returned ${CAP##*next=}, not -27 (EFBIG) -- a write loop never terminates" ;;
esac
WARNS=$(grep -ac "Short write" "$SERIAL")
if [ "$WARNS" -gt 0 ]; then
    note_fail "F2: ring 3 drove $WARNS \"Short write\" kernel warning(s) onto the console"
fi

# --- F3 ------------------------------------------------------------------
if grep -qa "KERNEL PANIC\|Critical resource exhaustion" "$SERIAL" 2>/dev/null; then
    note_fail "F3: the kernel panicked (VFS descriptor exhaustion: $(grep -ac 'Critical resource exhaustion' "$SERIAL") hit)"
else
    DIRLINES=$(printf '%s\n' "$FINAL_REGION" | grep -ao 'PROBE dir[a-z]* opened=[0-9]* refused=[-0-9]*')
    NDIR=$(printf '%s\n' "$DIRLINES" | grep -c .)
    [ "$NDIR" -ge 2 ] || guard_fail "F3: only $NDIR dirfill/dirhold line(s); the children never ran"
    TOTAL=$(printf '%s\n' "$DIRLINES" | sed 's/.*opened=\([0-9]*\).*/\1/' | awk '{s+=$1} END {print s+0}')
    if [ "$(count_in "$DIRLINES" "refused=-23")" -eq 0 ]; then
        note_fail "F3: $TOTAL directory opens and nobody was refused -ENFILE: $(printf '%s ' $DIRLINES)"
    fi
    if [ "$(count_in "$FINAL_REGION" "uid=0")" -eq 0 ]; then
        note_fail "F3: \`id\` never answered after the descriptor table filled"
    fi
fi
if grep -qa "Triple fault\|triple fault" "$TRACE" 2>/dev/null; then
    note_fail "the kernel triple-faulted during the run"
fi

if [ "${#FAILS[@]}" -gt 0 ]; then
    echo "RESULT: FAIL — ${#FAILS[@]} assertion(s)"
    for f in "${FAILS[@]}"; do echo "  - $f"; done
    echo "  --- last 40 serial lines ---"
    tail -40 "$SERIAL"
    exit 1
fi

echo "RESULT: PASS"
echo "  - F1: $TESTUSER's kernel shell was refused \`ls /\`, \`ls -l\` of a 0600 file and \`find\`, and still listed /scratch"
echo "  - F2: $CAP, and no short-write warning"
echo "  - F3: $TOTAL directory opens filled the table; the next was refused -ENFILE and the kernel lived"
exit 0
