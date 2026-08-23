#!/usr/bin/env bash
. "$(dirname "$0")/edr-rejoin.sh"
#
# verify-ring3-fatls.sh — does ring 3 already reach FAT32 through the generic
# `ls`, with no `fatls` builtin and no new syscall?
#
# WHY THIS HARNESS EXISTS. `fatls` was carried on the roadmap as one of item
# 4's two open DESIGN calls: the questions recorded were its gating polarity
# and the cross-drive behaviour in doc/CROSS_DRIVE_ACCESS_ANALYSIS.md. Both
# questions presume the capability has to be MIGRATED. It does not. The chain
#
#     cmd_ls  ->  open(path, O_RDONLY|O_DIRECTORY)   [SYS_OPEN 20]
#             ->  syscall_copy_path -> task_resolve_path
#                    (a drive-qualified path is returned VERBATIM — the
#                     `drive_qualified` branch in process.c copies and returns
#                     before any cwd prefix can be joined on)
#             ->  vfs_open -> vfs_resolve_drive('C')
#             ->  fat32_file_ops.readdir == fat32_vfs_readdir   [SYS_READDIR 22]
#
# is already complete and already compiled in. FAT32 registers the FULL
# file_operations_t (open/close/read/write/readdir/stat/seek/mkdir/rmdir/
# unlink/access_dir — src/fat32_vfs.c), C: is mounted at boot (kernel.c), and
# the VFS dispatches on the drive letter rather than on a hardcoded driver.
# So the ring-3 shell needs no `fatls` at all: `ls C:/` IS `fatls`.
#
# This is the same error shape that mis-deferred `whoami`, and it is worth
# naming because it has now happened twice. Both times the question asked was
# "does THIS component carry the capability across the boundary?" (there:
# psinfo_t and SYS_CRED; here: a fatls builtin) when the question that decides
# it is "is the capability REACHABLE AT ALL from ring 3?" Checking components
# one at a time cannot answer that, because the answer lives in a path that
# runs through none of them in particular.
#
# WHAT WOULD MAKE THIS HARNESS LIE. Three things, each guarded below:
#
#   1. `ls C:/` returning EMPTY and being scored as success. An empty listing
#      is exactly what a driver with no readdir, an unmounted C:, or a
#      cwd-mangled path all produce. So the test WRITES A FILE FIRST and
#      requires that specific name back — a positive control that fails if the
#      enumeration is inert. (verify-chmod-owner.sh needed this for the same
#      reason: "denied" and "absent" print the same.)
#   2. Measuring as ROOT. Every ring-3 gating bug in this tree has been found
#      by a non-root leg; root fast paths hide them. FAT32 has no per-file uid
#      of its own, which makes the polarity question real rather than academic
#      — so the listing legs run as an UNPRIVILEGED user, and the roadmap's
#      "what is the gating polarity" question is answered by observation here
#      rather than by assertion.
#   3. Matching a name in the COMMAND ECHO instead of in the output. The shell
#      echoes what is typed, so `write D:/RAMONLY.TXT` puts that name in the
#      log whether or not any listing ever produces it. The first version of
#      leg 4 did exactly this and reported PASS while `ls D:/` was in fact
#      printing "permission denied". Every name assertion now excludes prompt
#      lines (" $ ").
#   4. Grading the KERNEL shell's `fatls` by accident. That command exists and
#      works; if the typist drops to kshell the log fills with FAT32 names that
#      have nothing to do with ring 3. TINYOS_STAY_IN_RING3=1 is set, AND the
#      listing assertions are scoped to the region of the log AFTER the ring-3
#      shell announces itself, so kernel-shell output cannot satisfy them.
#
# PASS requires ALL of:
#   - the ring-3 shell is the one running (banner present)
#   - no syscall was rejected by the dispatcher
#   - an UNPRIVILEGED `ls C:/` lists the file just written  (reachability +
#     ungated-for-read polarity, with a live positive control)
#   - an UNPRIVILEGED `cat C:/<file>` returns the marker    (the fd is real,
#     not just a name in a dirent)
#   - a D:-only file lists on D: and is NOT reachable as a C: path
#     (the drive letter is actually dispatching; a single-driver VFS would
#     satisfy every other leg here perfectly happily)
#   - zero triple faults
#
# Exit 0 = PASS, 1 = FAIL, 2 = harness/setup problem, 3 = INCONCLUSIVE.
# Logs: ring3fatls.log (serial), ring3fatls-trace.log (int/cpu_reset).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=ring3fatls.log
TRACE=ring3fatls-trace.log
MON_SOCK=/tmp/tinyos-ring3fatls-mon.sock
RUN_DISK=/tmp/tinyos-ring3fatls-disk.img

TESTUSER=fluser
TESTPASS=flpass1

# Written from ring 3, then listed from ring 3. The FAT32 driver uppercases on
# create, so the name asserted back is the 8.3 form.
FATFILE="C:/RING3LS.TXT"
FATNAME="RING3LS.TXT"
MARKER=tinyos-ring3-fatls-ok

# A RAMFS-only name on D:, used to prove C: and D: are different filesystems
# rather than the same one listed twice.
#
# It lives in D:/scratch, NOT in D:'s root, and not in a directory the test
# user creates. Two ramfs facts force that choice, and both were learned by
# this harness failing against them rather than by reading:
#
#   - D:'s root is mode 0711 root-owned by deliberate design (src/ramfs.c):
#     every process starts its cwd there, so a uid-1000 process must be able to
#     SEARCH it, but the read bit is off for other so its contents stay
#     UNLISTABLE to non-root. An unprivileged `ls D:/` is therefore CORRECTLY
#     "permission denied" — a leg expecting it to enumerate asserts against the
#     intended policy.
#   - 0711 also denies WRITE to other, so the test user cannot `mkdir` its own
#     directory in D:/ either. The second attempt at this leg did exactly that
#     and got "permission denied", then "no such file or directory" downstream.
#
# D:/scratch is created at boot as 0777 precisely so a uid-1000 process has
# somewhere on RAMFS it can create entries (kernel.c, next to the 0755 /fio).
# It is the writable, listable D: object this comparison needs.
RAMDIR="D:/scratch"
RAMFILE="D:/scratch/RAMONLY.TXT"
RAMNAME="RAMONLY.TXT"

echo "==> Building kernel + ISO..."
make >/dev/null || { echo "build failed"; exit 2; }
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || { echo "mkrescue failed"; exit 2; }

# A REAL FAT32 volume is required. Against a zeroed image C: would not mount,
# `ls C:/` would fail for a reason that has nothing to do with ring 3, and the
# whole run would be vacuous — so check the signature rather than assume it.
if [ ! -f disk.img ]; then
    echo "ERROR: disk.img (formatted FAT32 image) not found"
    exit 2
fi
rm -f "$RUN_DISK"
cp disk.img "$RUN_DISK"
if ! dd if="$RUN_DISK" bs=1 skip=82 count=8 status=none | grep -q "FAT32"; then
    echo "ERROR: $RUN_DISK is not a FAT32 volume (no FAT32 signature at 0x52)"
    exit 2
fi

rm -f "$SERIAL" "$TRACE" "$MON_SOCK"

echo "==> Launching headless QEMU (monitor on $MON_SOCK)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() {
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "${QEMU_PID:-}" ] && wait "$QEMU_PID" 2>/dev/null
    rm -f "$MON_SOCK"
    return 0
}
trap cleanup EXIT

# Route to the unprivileged account is kshell -> su -> `exec /shell.elf`, the
# same one verify-ring3-chmod.sh / -ps.sh / -date.sh use, and for the same
# reason: logging out and back in reaches a ring-3 shell whose readline never
# receives keystrokes (a separate defect, recorded in doc/KERNEL_BUGS.md).
# kshell is ONLY the vehicle for the su. Every listing assertion below is
# scoped to the post-`exec /shell.elf` region, so the kernel shell's own
# `fatls` — which works, and would print the same names — cannot satisfy them.
#
# Ring-3 commands are sent unverified ('!') because the ring-3 shell does not
# echo keystrokes to serial (the kernel echoes them in the keyboard IRQ, which
# reaches VGA only), so per-character echo checks pass on coincidental matches
# in kernel chatter. Each still carries an expect on its RESULT.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="help" \
TINYOS_EXPECT="list a directory" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
kshell=>Switching to the kernel shell;\
su $TESTUSER=>Now running as;\
exec /shell.elf=>TinyOS shell (ring 3);\
!write $FATFILE $MARKER;\
!write $RAMFILE ramonly;\
!ls C:/=>$FATNAME;\
!cat $FATFILE=>$MARKER;\
!ls $RAMDIR=>$RAMNAME;\
!cat C:/$RAMNAME=>o such file" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

# The 60-second EDR status report tears whatever line is in flight, at an
# ARBITRARY character, so any witness can be split in two and stop matching.
# Every read below is a POSITION comparison, and a torn witness reports as
# absent -- i.e. as a kernel that never produced it. The tear is PROBABILISTIC
# (it only bites when the burst lands on that particular line), so a green run
# does NOT show the raw read is safe; it shows the burst missed this time.
# Analyse the REJOINED copy. See verify/edr-rejoin.sh (cases: edr-rejoin-test.sh).
REJOINED="${SERIAL}.rejoined"
rejoin_serial "$SERIAL" "$REJOINED"

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"

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

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: FAIL — no serial output at all (typist rc=$TYPIST_RC)"
    exit 2
fi

if grep -q "Triple fault" "$TRACE" 2>/dev/null; then
    echo "--- $TRACE ---"
    grep -E "check_exception|v=0e|v=08|Triple fault|^EIP=|CR2=" "$TRACE" | tail -15
    fail_with "'Triple fault' during the run"
fi

# ---------------------------------------------------------------------------
# Scope every listing assertion to the UNPRIVILEGED RING-3 session.
#
# Two cuts, in order, and both are load-bearing. The su line separates root's
# session from the test user's; the ring-3 banner AFTER it separates the
# kernel shell from the ring-3 one. Without the second cut the kernel shell's
# `fatls` output (and its `ls`, which routes to cmd_fatls for C:) sits in the
# same log and satisfies the FAT32 legs while proving nothing about ring 3.
# ---------------------------------------------------------------------------
SU_LINE=$(grep -n "Now running as" "$REJOINED" | head -1 | cut -d: -f1)
if [ -z "$SU_LINE" ]; then
    inconclusive_with "never reached the unprivileged account (no 'Now running as')" \
        "Every leg below is about what a NON-ROOT ring-3 caller can do," \
        "so root's own output must not be allowed to stand in for it."
fi

R3_REL=$(tail -n +"$SU_LINE" "$REJOINED" | grep -n "TinyOS shell (ring 3)" | head -1 | cut -d: -f1)
if [ -z "$R3_REL" ]; then
    inconclusive_with "the unprivileged account never reached a ring-3 shell" \
        "'exec /shell.elf' did not announce itself after the su, so the" \
        "listing legs would have been measured against the KERNEL shell."
fi

R3_LINE=$((SU_LINE + R3_REL - 1))
USER_R3=$(tail -n +"$R3_LINE" "$REJOINED")

# ---------------------------------------------------------------------------
# Leg 1: nothing was rejected by the dispatcher.
#
# Both messages are matched, not just one. The range check prints "Invalid
# syscall number N (max M)" and the switch default prints "Unknown system call
# number N"; a leg matching only the second passed vacuously once already
# during the SYS_TIME negative control. Nothing here bumps MAX_SYSCALL_NUM —
# SYS_OPEN (20) and SYS_READDIR (22) are long-standing — which is precisely
# the point being proven, so a rejection would mean the premise is wrong.
# ---------------------------------------------------------------------------
REJECTED=$(grep -Ec "Invalid syscall number|Unknown system call" "$REJOINED")
if [ "$REJECTED" -ne 0 ]; then
    fail_with "the dispatcher rejected a syscall ($REJECTED occurrence(s))" \
        "This test asserts NO new syscall is needed; a rejection refutes that." \
        "$(grep -Em2 'Invalid syscall number|Unknown system call' "$REJOINED")"
fi

# ---------------------------------------------------------------------------
# Leg 2 (POSITIVE CONTROL): an unprivileged `ls C:/` lists the file that was
# just written from ring 3.
#
# The write comes first so this cannot pass against an inert enumeration. An
# empty `ls C:/` is what an unmounted C:, a missing .readdir, and a
# cwd-mangled path ALL produce, and "(empty)" is not an error the shell
# reports as one — so requiring a specific, freshly created name is the only
# assertion that separates "enumerated FAT32" from "returned successfully".
# ---------------------------------------------------------------------------
if ! printf '%s\n' "$USER_R3" | grep -q "$FATNAME"; then
    echo "--- ring-3 region of $SERIAL ---"
    printf '%s\n' "$USER_R3" | grep -v "Suspicious" | tail -40
    fail_with "unprivileged \`ls C:/\` did not list $FATNAME" \
        "Either the write failed, or ring 3 cannot enumerate FAT32 —" \
        "check whether fat32_file_ops.readdir is still wired up and C: mounted."
fi

# ---------------------------------------------------------------------------
# Leg 3: the dirent is backed by a readable file, not just a name.
#
# readdir and open/read are different fat32_file_ops entries; a name can list
# while the fd path is broken. The marker was written from ring 3 in this same
# session, so matching it proves the round trip end to end.
# ---------------------------------------------------------------------------
if ! printf '%s\n' "$USER_R3" | grep -q "$MARKER"; then
    echo "--- ring-3 region of $SERIAL ---"
    printf '%s\n' "$USER_R3" | grep -v "Suspicious" | tail -40
    fail_with "unprivileged \`cat $FATFILE\` did not return '$MARKER'" \
        "The name listed but the contents did not come back: readdir works" \
        "and the open/read path does not."
fi

# ---------------------------------------------------------------------------
# Leg 4 (NON-VACUITY): C: and D: are genuinely different filesystems.
#
# Every leg above would pass just as happily against a VFS that ignored the
# drive letter and sent everything to one driver — the file was written
# through the same path it was read back through, so a single-filesystem
# kernel is perfectly self-consistent. Two independent checks break that
# symmetry: a name must be listable on D:, and that same name must NOT be
# reachable as a C: path.
#
# THE ECHO TRAP, found by this harness passing when it should not have. The
# first version asserted `grep -q "$RAMNAME"` over the whole ring-3 region.
# That matched — but it matched the TYPED COMMAND (`write D:/RAMONLY.TXT`),
# which the shell echoes, not any listing. The leg reported PASS while the
# actual `ls` printed "permission denied". A name appears in the log for two
# unrelated reasons, so an assertion that does not exclude the echo is not an
# assertion at all. Everything below matches on a line that is NOT a prompt
# line: the shell echoes commands as "<cwd> $ <command>", so requiring the
# absence of " $ " separates output from input.
# ---------------------------------------------------------------------------
ram_listed=$(printf '%s\n' "$USER_R3" | grep -F "$RAMNAME" | grep -cv ' \$ ')
if [ "$ram_listed" -lt 1 ]; then
    echo "--- ring-3 region of $SERIAL ---"
    printf '%s\n' "$USER_R3" | grep -v "Suspicious" | tail -40
    inconclusive_with "\`ls $RAMDIR\` did not list $RAMNAME as OUTPUT" \
        "(occurrences on non-prompt lines: $ram_listed)" \
        "The C:/D: comparison needs both sides; without D: the drive-letter" \
        "dispatch is untested and legs 2-3 alone cannot distinguish FAT32" \
        "from a single-driver VFS. Note D:'s ROOT is 0711 root-owned by" \
        "design and is correctly unlistable to a non-root user — this leg" \
        "uses a user-created subdirectory for exactly that reason."
fi

# The decisive half: a D:-only name must NOT resolve as a C: path. If the VFS
# ignored the drive letter, this cat would have succeeded and printed the file
# instead of an error.
if ! printf '%s\n' "$USER_R3" | grep -q "o such file"; then
    echo "--- ring-3 region of $SERIAL ---"
    printf '%s\n' "$USER_R3" | grep -v "Suspicious" | tail -40
    fail_with "\`cat C:/$RAMNAME\` did not fail" \
        "A file created on D: was reachable through a C: path, so the drive" \
        "letter is not dispatching and every FAT32 claim above is suspect."
fi

echo "RESULT: PASS"
echo ""
echo "  Ring 3 reaches FAT32 through the GENERIC ls — no fatls, no new syscall."
echo ""
echo "    unprivileged \`ls C:/\`  listed $FATNAME      (written from ring 3)"
echo "    unprivileged \`cat\`     returned $MARKER"
echo "    unprivileged \`ls $RAMDIR\` listed $RAMNAME   (D: side, as output)"
echo "    unprivileged \`cat C:/$RAMNAME\` failed       (drive letter dispatches)"
echo "    dispatcher rejections: 0     triple faults: 0"
echo ""
echo "  Path exercised: cmd_ls -> open(O_DIRECTORY) [SYS_OPEN 20]"
echo "                  -> task_resolve_path (drive-qualified, returned verbatim)"
echo "                  -> vfs_resolve_drive('C') -> fat32_vfs_readdir [SYS_READDIR 22]"
echo ""
echo "  Serial: $SERIAL"
exit 0
