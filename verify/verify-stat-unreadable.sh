#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-stat-unreadable.sh — `stat` requires READ on the file itself, not
# only search on the path. Deliberately stricter than POSIX.
#
# THE RULE (ramfs_vfs_stat)
#
# POSIX stat needs search (x) on every ancestor and nothing on the file. In a
# directory the caller can search but not list -- the RAMFS root D:/ is 0711
# -- that turns stat into an oracle for any name the caller can guess: it
# returns the size and mode of files whose existence readdir would not even
# reveal. TinyOS refuses stat on a node the caller cannot read. This harness
# pins that decision so a later "POSIX cleanup" cannot quietly undo it.
#
# ASSERTIONS (all measured as an UNPRIVILEGED user in the ring-3 shell, the
# boundary SYS_STAT lives at)
#
#   1. stat of root's 0600 file in the x-only D:/ is REFUSED, and no size or
#      mode for it reaches the user's output
#   2. cat of the same file is REFUSED and its content never appears
#   3. stat of a 0644 file behind root's 0700 dir is REFUSED (ancestor gate)
#   4. SELECTIVITY: stat of root's 0644 file in the same D:/ SUCCEEDS, so leg
#      1 grades the read rule, not a stat that refuses every foreign file
#   5. POSITIVE CONTROLS: root stats the files first, so a refusal cannot be
#      an absence; the user stats a file of their own.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: statunread.log (serial), statunread-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

TESTUSER=stuser
TESTPASS=stpass1

SECRET=D:/stsecret.txt        # root-owned, 0600 (write() creates 0600)
PUBLIC=D:/stpublic.txt        # root-owned, 0644, same x-only directory
PRIVDIR=D:/stpriv             # root-owned, 0700
HIDDEN=D:/stpriv/inner.txt    # root-owned, 0644, behind PRIVDIR
USERDIR=D:/stplace            # 0777 so the user can create (root is 0711)
USERFILE=D:/stplace/mine.txt

ISO=dist/tinyos.iso
SERIAL=statunread.log
TRACE=statunread-trace.log
RUN_DISK=/tmp/tinyos-statunread-disk.img
MON_SOCK=/tmp/tinyos-statunread-mon.sock

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
if [ ! -f disk.img ]; then
    echo "ERROR: disk.img not found"
    exit 1
fi
cp disk.img "$RUN_DISK"

echo "==> Launching headless QEMU (monitor on $MON_SOCK)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# Same route to an unprivileged ring-3 shell as verify-ring3-chmod.sh:
# kshell -> su -> exec /shell.elf. Ring-3 commands are sent unverified ('!')
# because the ring-3 shell echoes per line, not per keystroke.
#
# The refusal legs expect only the command name: if the rule regresses, leg 1
# prints mode= instead of a refusal, and a typist blocked on an expect that
# cannot arrive burns the whole timeout before the verdict.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="help" \
TINYOS_EXPECT="change permission bits" \
TINYOS_FOLLOWUP_CMDS="\
!write $SECRET topsecret;\
!stat $SECRET=>mode=600;\
!write $PUBLIC public;\
!chmod 644 $PUBLIC;\
!stat $PUBLIC=>mode=644;\
!mkdir $PRIVDIR;\
!chmod 700 $PRIVDIR;\
!write $HIDDEN hidden;\
!chmod 644 $HIDDEN;\
!stat $HIDDEN=>mode=644;\
!mkdir $USERDIR;\
!chmod 777 $USERDIR;\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
kshell=>Switching to the kernel shell;\
su $TESTUSER=>Now running as;\
exec /shell.elf=>TinyOS shell (ring 3);\
!stat $SECRET=>stat;\
!stat $PUBLIC=>mode=644;\
!cat $SECRET=>cat;\
!stat $HIDDEN=>stat;\
!write $USERFILE mine;\
!stat $USERFILE=>mode=600" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"
cleanup

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: FAIL — no serial output at all (typist rc=$TYPIST_RC)"
    exit 2
fi

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    exit 1
}

inconclusive_with() {
    echo "RESULT: INCONCLUSIVE — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    exit 3
}

SU_LINE=$(grep -n "Now running as" "$REJOINED" | head -1 | cut -d: -f1)
if [ -z "$SU_LINE" ]; then
    inconclusive_with "never reached the unprivileged account (no 'Now running as')"
fi
ROOT_REGION=$(head -n "$SU_LINE" "$REJOINED")
USER_REGION=$(tail -n +"$SU_LINE" "$REJOINED")

# Positive controls: both root-owned files exist, with the modes the legs
# below depend on. Without them a refusal could be an absence.
printf '%s\n' "$ROOT_REGION" | grep -q "^$SECRET  size=[0-9]*  mode=600" \
    || inconclusive_with "root never stat'ed $SECRET at mode=600 (setup failed)"
printf '%s\n' "$ROOT_REGION" | grep -q "^$PUBLIC  size=[0-9]*  mode=644" \
    || inconclusive_with "root never stat'ed $PUBLIC at mode=644 (setup failed)"
printf '%s\n' "$ROOT_REGION" | grep -q "^$HIDDEN  size=[0-9]*  mode=644" \
    || inconclusive_with "root never stat'ed $HIDDEN at mode=644 (setup failed)"
# And the user's own stat works at all, so leg 1 grades the permission rule
# and not a broken ring-3 stat.
printf '%s\n' "$USER_REGION" | grep -q "^$USERFILE  size=[0-9]*  mode=600" \
    || inconclusive_with "the user could not stat their OWN file" \
       "$(printf '%s\n' "$USER_REGION" | grep -E "mine.txt" | head -3)"

# Leg 1: the read rule. Any refusal line, and no metadata line at all.
SECRET_STAT=$(printf '%s\n' "$USER_REGION" | grep -E "^($SECRET  size=|stat: $SECRET:)" | head -1)
case "$SECRET_STAT" in
  "stat: $SECRET: "*) : ;;
  *)
    fail_with "the unprivileged user could stat root's 0600 file" \
        "got: '${SECRET_STAT:-<no stat line>}'" \
        "D:/ is 0711: the user cannot list it, so stat must not hand out the" \
        "size and mode of a guessed name the user cannot read."
    ;;
esac
if printf '%s\n' "$USER_REGION" | grep -q "^$SECRET  size="; then
    fail_with "a size/mode line for root's 0600 file reached the user"
fi

# Leg 4 (selectivity): a READABLE foreign file in the same directory stats.
PUBLIC_STAT=$(printf '%s\n' "$USER_REGION" | grep -E "^($PUBLIC  size=|stat: $PUBLIC:)" | head -1)
case "$PUBLIC_STAT" in
  "$PUBLIC  size="*"  mode=644"*) : ;;
  *)
    fail_with "the user could not stat root's READABLE 0644 file" \
        "got: '${PUBLIC_STAT:-<no stat line>}'" \
        "Leg 1's refusal must come from the read rule, not from a stat" \
        "that refuses every file the caller does not own."
    ;;
esac

# Leg 2: metadata did not become content. Any refusal counts: ramfs_open
# reports an existing-but-unreadable file as -1, which ramfs_vfs_open maps to
# ENOENT, so today this reads "no such file or directory" -- the wrong errno,
# but a refusal, and the errno is not what this harness is about.
CAT_DENY=$(printf '%s\n' "$USER_REGION" | grep -cE "^cat: $SECRET: ")
if [ "$CAT_DENY" -lt 1 ] || printf '%s\n' "$USER_REGION" | grep -q "topsecret"; then
    fail_with "cat of root's 0600 file was not refused" \
        "$(printf '%s\n' "$USER_REGION" | grep -E "^cat:|topsecret" | head -3)"
fi

# Leg 3: the ancestor gate still hides a file behind a 0700 directory. The
# refusal is ENOENT ("as if absent"), which is what ramfs_find_locked returns
# when may_search() fails.
HIDDEN_STAT=$(printf '%s\n' "$USER_REGION" | grep -E "^($HIDDEN  size=|stat: $HIDDEN:)" | head -1)
case "$HIDDEN_STAT" in
  "stat: $HIDDEN: "*) : ;;
  *)
    fail_with "stat reached a file behind root's 0700 directory" \
        "got: '${HIDDEN_STAT:-<no stat line>}'" \
        "The ancestor search gate must hide a file behind a 0700 directory" \
        "even when the file itself is world-readable."
    ;;
esac

echo "RESULT: PASS — stat requires read on the file; readable files still stat; the 0700 gate hides"
echo "  root's 0600 file    : $SECRET_STAT"
echo "  root's 0644 file    : $PUBLIC_STAT"
echo "  cat of the 0600 one : refused ($CAT_DENY)"
echo "  behind 0700 dir     : $HIDDEN_STAT"
exit 0
