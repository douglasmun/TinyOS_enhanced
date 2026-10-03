#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-ramfs-hidden-names.sh — in a directory the caller cannot read, a name
# the caller has no rights on must answer every operation exactly as a name
# that does not exist.
#
# THE RULE (hidden_from_caller in ramfs.c)
#
# D:/ is 0711: search, not list. Before this rule each operation answered a
# guessed name differently when it existed -- stat EACCES, write ENOENT, chmod
# EPERM, rm EACCES, against ENOENT (or write's EACCES) when it did not -- so
# any one of them told an unprivileged user which of root's files exist.
# Lookups now treat such a node as absent unless the caller owns it or holds
# any permission bit on it, and each operation gives its own absence answer.
#
# ASSERTIONS (an UNPRIVILEGED user in the ring-3 shell, the boundary the
# syscalls live at)
#
#   1. PAIRS: for each operation, the refusal for root's hidden name and for
#      an absent name in the same directory read identically once the path is
#      removed (stat, cat, write, chmod, rm, ls, cd, mkdir, rmdir, and a create
#      THROUGH a hidden directory vs through an absent one)
#   2. SELECTIVITY: root's 0600 file in a READABLE directory is still refused
#      with "permission denied" -- the rule hides only what the directory
#      already hides, and stat's read requirement stands on its own there
#   3. OWNER: in root's write-but-not-read drop box (0733) the user creates a
#      file, chmods it 000, and can still chmod it back and stat it -- a
#      caller's own file is never hidden from them
#   4. POSITIVE CONTROLS: root stat'ed every hidden object first, so absence
#      is not why the pairs agree; every pair produced both lines
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: hiddennames.log (serial), hiddennames-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=hnuser
TESTPASS=hnpass1

HF=D:/hnsecret.txt          # root, 0600, in the 0711 root: hidden
AF=D:/hnabsent.txt          # does not exist
HD=D:/hnpriv                # root, 0700 dir, in the 0711 root: hidden
AD=D:/hnnodir               # does not exist
PUBDIR=D:/hnpub             # root, 0755: readable
PUBSECRET=D:/hnpub/sec.txt  # root, 0600, in a readable directory: visible
BOX=D:/hnbox                # root, 0733: writable, not readable
OWN=D:/hnbox/own.txt        # the user's, chmod 000 by the user

ISO=dist/tinyos.iso
SERIAL=hiddennames.log
TRACE=hiddennames-trace.log
RUN_DISK=/tmp/tinyos-hiddennames-disk.img
MON_SOCK=/tmp/tinyos-hiddennames-mon.sock

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
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

# Root sets up in the ring-3 shell, then kshell -> su -> exec /shell.elf for
# the unprivileged legs (the route verify-stat-unreadable.sh uses). The final
# command waits for "mode=600", which only the owner leg's stat OUTPUT
# carries, so every earlier refusal has drained before the verdict.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="help" \
TINYOS_EXPECT="change permission bits" \
TINYOS_FOLLOWUP_CMDS="\
!write $HF topsecret;\
!stat $HF=>mode=600;\
!mkdir $HD;\
!chmod 700 $HD;\
!stat $HD=>mode=700;\
!mkdir $PUBDIR;\
!chmod 755 $PUBDIR;\
!write $PUBSECRET pubsecret;\
!stat $PUBSECRET=>mode=600;\
!mkdir $BOX;\
!chmod 733 $BOX;\
!stat $BOX=>mode=733;\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
kshell=>Switching to the kernel shell;\
su $TESTUSER=>Now running as;\
exec /shell.elf=>TinyOS shell (ring 3);\
!stat $HF;\
!stat $AF;\
!cat $HF;\
!cat $AF;\
!write $HF x;\
!write $AF x;\
!chmod 644 $HF;\
!chmod 644 $AF;\
!rm $HF;\
!rm $AF;\
!ls $HD;\
!ls $AD;\
!cd $HD;\
!cd $AD;\
!mkdir $HD;\
!mkdir $AD;\
!rmdir $HD;\
!rmdir $AD;\
!write $HD/f x;\
!write $AD/f x;\
!stat $HD;\
!stat $AD;\
!stat $PUBSECRET;\
!write $OWN mine;\
!chmod 000 $OWN;\
!chmod 600 $OWN;\
!stat $OWN=>mode=600" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"
cleanup

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

SU_LINE=$(grep -an "Now running as" "$REJOINED" | head -1 | cut -d: -f1)
[ -n "$SU_LINE" ] || { echo "RESULT: INCONCLUSIVE — never reached the unprivileged account"; exit 3; }
ROOT_REGION=$(head -n "$SU_LINE" "$REJOINED")
USER_REGION=$(tail -n +"$SU_LINE" "$REJOINED")

# Positive controls: every hidden object exists, at the mode the rule needs.
for want in "$HF  size=[0-9]*  mode=600" "$HD  size=[0-9]*  mode=700" \
            "$PUBSECRET  size=[0-9]*  mode=600" "$BOX  size=[0-9]*  mode=733"; do
    printf '%s\n' "$ROOT_REGION" | grep -aq "^$want" \
        || { echo "RESULT: INCONCLUSIVE — root's setup never showed '$want'"; exit 3; }
done

# The refusal text after "cmd: path: ", for the user's first such line.
refusal() {
    printf '%s\n' "$USER_REGION" | grep -a "^$1: $2: " | head -1 | sed "s|^$1: $2: ||"
}

FAILS=0
MISSING=0
pair() {  # cmd hidden-path absent-path
    local h a
    h=$(refusal "$1" "$2"); a=$(refusal "$1" "$3")
    if [ -z "$h" ] || [ -z "$a" ]; then
        printf '  %-6s MISSING  hidden=[%s] absent=[%s]\n' "$1" "$h" "$a"
        MISSING=$((MISSING + 1))
    elif [ "$h" = "$a" ]; then
        printf '  %-6s same     [%s]\n' "$1" "$h"
    else
        printf '  %-6s DIFFER   hidden=[%s] absent=[%s]\n' "$1" "$h" "$a"
        FAILS=$((FAILS + 1))
    fi
}

echo "  hidden vs absent:"
pair stat  "$HF" "$AF"
pair cat   "$HF" "$AF"
pair write "$HF" "$AF"
pair chmod "$HF" "$AF"
pair rm    "$HF" "$AF"
pair ls    "$HD" "$AD"
pair cd    "$HD" "$AD"
pair mkdir "$HD" "$AD"
pair rmdir "$HD" "$AD"
pair write "$HD/f" "$AD/f"
pair stat  "$HD" "$AD"

if [ "$MISSING" -ne 0 ]; then
    echo "RESULT: INCONCLUSIVE — $MISSING pair(s) did not produce both refusal lines"
    exit 3
fi

# Selectivity: a visible name is still refused for what it is.
PUB=$(refusal stat "$PUBSECRET")
echo "  stat of root's 0600 file in a readable dir: [${PUB:-<none>}]"
if [ "$PUB" != "permission denied" ]; then
    echo "  FAIL: a name the directory lists must still get EACCES, not be hidden"
    FAILS=$((FAILS + 1))
fi

# Owner: the user's own 000 file in an unreadable directory stays reachable.
if ! printf '%s\n' "$USER_REGION" | grep -aq "^$OWN  size=[0-9]*  mode=600"; then
    echo "  FAIL: the user could not chmod and stat their OWN 000 file in the drop box"
    printf '%s\n' "$USER_REGION" | grep -a "own.txt" | head -4 | sed 's/^/      /'
    FAILS=$((FAILS + 1))
else
    echo "  owner leg: own 000 file chmod'ed back and stat'ed"
fi

if printf '%s\n' "$USER_REGION" | grep -aq "topsecret"; then
    echo "  FAIL: root's file content reached the user"
    FAILS=$((FAILS + 1))
fi
if grep -aqi "triple fault\|PANIC" "$REJOINED"; then
    echo "  FAIL: kernel panicked during the run"
    FAILS=$((FAILS + 1))
fi

if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS check(s): a hidden name is distinguishable from an absent one"
    exit 1
fi
echo "RESULT: PASS — 11 operations answer root's hidden names as absent; visible and owned names unchanged"
exit 0
