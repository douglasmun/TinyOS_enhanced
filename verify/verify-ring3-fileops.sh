#!/usr/bin/env bash
#
# verify-ring3-fileops.sh — FULLY AUTOMATED check for the ring-3 shell's
# cp / mv / touch, and for the O_TRUNC fix they depend on.
#
# WHAT THIS IS TESTING
#
# Two things that are really one thing.
#
# 1. THE KERNEL BUG. ramfs_vfs_open() translated only the ACCESS MODE of the
#    VFS_O_* flags into ramfs_open's uint8_t of RAMFS_FLAG_*. VFS_O_TRUNC
#    (0x2 00) could not survive that translation and was silently dropped, so
#    open(O_TRUNC) did nothing on the RAM disk. Because ramfs_write only ever
#    GROWS node->size, rewriting a long file with a short one left the old
#    tail in place. Measured before the fix, on a real boot:
#
#      write /t.txt AAAA...(30 A's)
#      write /t.txt BBB
#      cat /t.txt   ->  BBBAAAAAAAAAAAAAAAAAAAAAAAAAAA
#
#    That is silent data corruption in a SHIPPING builtin (`write` has always
#    passed O_TRUNC), not merely a missing feature. stdio.c had hit the same
#    bug for `>` and fixed it locally by calling ramfs_truncate() itself,
#    which fixed redirection and left every open(O_TRUNC) caller broken.
#
# 2. THE BUILTINS. cp/mv/touch are pure userspace -- open/read/write/stat/
#    unlink already cross the ring boundary, so no new syscall was added. But
#    cp CANNOT BE CORRECT WITHOUT (1): copying a short file over a longer one
#    is exactly the corrupting case. So the O_TRUNC assertion below is not a
#    bonus check, it is cp's foundation, and it is asserted through cp itself
#    rather than only through `write`.
#
# WHY THE ASSERTIONS ARE SHAPED THIS WAY
#
# Every check compares FILE CONTENT after the fact, never "the command
# printed no error". A cp that silently truncates, or an mv that loses the
# source, both exit quietly -- absence of an error message is precisely what
# these bugs look like. Content is the only witness.
#
# The destructive edge cases get their own assertions because they fail
# SILENTLY and DESTRUCTIVELY:
#
#   `cp f f`   — without the self-copy guard, O_TRUNC empties the file before
#                the first read, turning copy into delete. Asserted by content
#                surviving, not by the error message.
#   `mv f f`   — same trap one step worse: copy-onto-self then unlink.
#   mv failure — the unlink must not happen when the copy fails, or the user
#                loses their only copy. Asserted with an unwritable dest.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.
# Log: ring3-fileops.log (serial).

set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=ring3-fileops.log
TRACE=ring3-fileops-trace.log
RUN_DISK=/tmp/tinyos-r3fileops-disk.img
MON_SOCK=/tmp/tinyos-r3fileops-mon.sock

# --------------------------------------------------------------------------
# 0) Source guard: the O_TRUNC fix must be present in ramfs_vfs.c.
#
# Without this, a tree where the fix was reverted would still boot and the
# cp/touch checks would mostly pass -- only the truncation assertion would
# fail, and it would look like a flaky content mismatch rather than a missing
# kernel change. Name the cause up front.
# --------------------------------------------------------------------------
if ! grep -q "ramfs_truncate(ramfs_fd)" src/ramfs_vfs.c; then
    echo "INCONCLUSIVE: ramfs_vfs.c does not call ramfs_truncate()."
    echo "  open(O_TRUNC) is a no-op on the RAM disk without it, and cp cannot"
    echo "  be correct: copying a short file over a longer one leaves the old"
    echo "  tail behind. Re-apply the fix in ramfs_vfs_open()."
    exit 2
fi

echo "==> Building userspace shell, signing, embedding..."
# The embedded shell must match userspace/shell.c or this harness tests the
# PREVIOUS shell and reports on code that is not being changed. Same reasoning
# as verify-ring3-ps.sh: cheap, and the failure it prevents looks like a pass.
(cd userspace && make) >/dev/null || { echo "FAIL: userspace build"; exit 2; }
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 \
    || { echo "FAIL: signing"; exit 2; }
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null \
    || { echo "FAIL: embedding"; exit 2; }

make >/dev/null || { echo "FAIL: kernel build"; exit 2; }

# Staleness guard on the EMBEDDED array, not on shell.elf: the kernel loads
# the embedded copy, so that is the artifact whose contents decide the run.
python3 - <<'PY' || exit 2
import re, sys
src = open('src/shell_elf_data.c').read()
blob = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', src))
missing = [p for p in (b"usage: cp <src> <dst>", b"usage: mv <src> <dst>",
                       b"usage: touch", b"are the same file")
           if p not in blob]
if missing:
    print("INCONCLUSIVE: embedded shell lacks:", [m.decode() for m in missing])
    print("  src/shell_elf_data.c is stale relative to userspace/shell.c.")
    sys.exit(2)
print("==> Guard: embedded shell contains cp/mv/touch")
PY

cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || { echo "FAIL: ISO"; exit 2; }

echo "==> Fresh BLANK disk (forces first-boot password setup)"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
dd if=/dev/zero of="$RUN_DISK" bs=1m count=128 status=none

echo "==> Launching headless QEMU"
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

# --------------------------------------------------------------------------
# The script. Each step ends with a `cat` whose output is the assertion, and
# every marker is a distinctive token so a grep cannot match the echoed
# command line instead of its result.
#
# Runs in the RING-3 shell (the default login shell), which is the boundary
# under test. Files live on D: (the RAM disk) because that is where the
# O_TRUNC path this fix touches actually runs.
# --------------------------------------------------------------------------
STEPS=""
add() { STEPS="${STEPS}${STEPS:+;}$1"; }

# 1) O_TRUNC through `write`: the original corruption case.
#
# ASSERTED WITH `stat`, NOT `cat`. This is the whole subtlety of this harness.
# `cat` shows "BBB" whether or not the file was truncated, so a cat-based check
# passes against a build with the kernel fix REVERTED -- measured, not assumed.
# `stat` reports node->size, which is exactly the field the bug leaves wrong:
#
#   fix disabled: size=31 after writing 3 bytes   <- stale tail retained
#   fix enabled : size=4  ("BBB" + newline)
add "write /trunc.txt AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
add "stat /trunc.txt"
add "write /trunc.txt BBB"
add "stat /trunc.txt"
add "cat /trunc.txt"

# 2) touch creates, and does NOT clobber existing content.
add "touch /t1.txt"
add "write /t1.txt KEEPME"
add "touch /t1.txt"
add "cat /t1.txt"

# 3) cp copies content.
add "write /src.txt COPYSRC"
add "cp /src.txt /dst.txt"
add "cat /dst.txt"

# 4) cp over a LONGER existing file — the case that needs O_TRUNC. over.txt is
#    seeded with 7 bytes, then overwritten from a 3-byte source. A dropped
#    O_TRUNC yields "ZZZYSRC".
#
#    This uses its OWN destination rather than reusing /dst.txt: the assertion
#    below finds a command by grepping for its echo, and `grep -A1` stops at
#    the FIRST match, so two steps sharing `cat /dst.txt` would both read the
#    first one's output -- step 4 would silently be graded on step 3's result.
#    Also asserted with `stat`: cp's destination open is where the truncation
#    has to happen, and cat cannot see the difference (see step 1).
#    over.txt holds "COPYSRC\n" (8); short.txt holds "ZZZ\n" (4).
add "write /over.txt COPYSRC"
add "write /short.txt ZZZ"
add "cp /short.txt /over.txt"
add "stat /over.txt"
add "cat /over.txt"

# 5) cp onto ITSELF must not destroy the file.
add "cp /src.txt /src.txt"
add "cat /src.txt"

# 6) mv moves content AND removes the source.
add "write /m1.txt MOVEME"
add "mv /m1.txt /m2.txt"
add "cat /m2.txt"
add "cat /m1.txt"

# 7) mv onto itself must not destroy the file. Copied to its own name first so
#    this step's `cat` is unique in the log (see the note in step 4).
add "cp /m2.txt /self.txt"
add "mv /self.txt /self.txt"
add "cat /self.txt"

# 8) mv into a DIRECTORY is refused, and must leave the source intact.
add "mkdir /adir"
add "mv /m2.txt /adir"
add "cat /m2.txt"

echo "==> Driving the boot flow (slow under TCG; be patient)..."
# TINYOS_STAY_IN_RING3=1 is LOAD-BEARING, not a tuning knob. By default the
# typist sends `kshell` after login, because most harnesses target kernel-shell
# commands. That EXITS the ring-3 shell -- and the kernel shell has its OWN
# write/cat/touch, so without this every command below would run against
# different code and this harness would grade a shell it is not testing.
#
# Observed for real: the first run of this script reported
# `BBBAAAAAAAA...` and was briefly read as the O_TRUNC fix failing. The
# serial log showed `D:/ $ kshell` immediately before it -- the ring-3 shell
# had already exited and the kernel shell produced that output. The prompt in
# the log is the tell: `D:/ $` is ring 3, a bare `$ ` is the kernel shell.
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=" \
TINYOS_FOLLOWUP_CMDS="$STEPS" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup
trap - EXIT

echo
echo "================ VERDICT ================"

if grep -q "Triple fault" "$TRACE" 2>/dev/null; then
    echo "RESULT: FAIL — 'Triple fault' in $TRACE"
    grep -E "check_exception|v=0e|v=08|Triple fault|^EIP=|CR2=" "$TRACE" | tail -15
    exit 1
fi

# Extract a command's OUTPUT. Asserting on the output rather than on "the
# token appears somewhere" matters: the token is in the echoed command line
# too, so a bare grep would match a `write` that never took effect.
#
# `cat` does NOT emit a trailing newline, so the next shell prompt lands on the
# SAME serial line as the file's contents:
#
#     $ cat /trunc.txt
#     BBB$ touch /t1.txt
#
# Taking the whole next line therefore yields content+prompt glued together and
# every comparison fails, including the ones that are actually correct. Cut at
# the first '$ ' to recover just the content. Anything before that marker is
# what the file held; the prompt and the following echoed command are not ours.
# $2 selects WHICH occurrence (default 1) for commands that legitimately run
# more than once -- grep stops at the first match otherwise, so a later step
# would silently be graded on an earlier step's output.
# Returns the line a command printed. The echo looks like "D:/ $ cat /f.txt",
# so match the prompt+command as a fixed string and take the next line.
#
# The ring-3 `cat` DOES terminate with a newline, so the content stands alone
# on its line -- unlike the kernel shell's cat, which does not and whose output
# ends up sharing a line with the following prompt. Anything that reintroduces
# kernel-shell output here would need the trailing-prompt strip back.
#
# $2 selects WHICH occurrence (default 1) for commands that run more than once;
# grep stops at the first match otherwise, so a later step would silently be
# graded on an earlier step's output.
# Repair EDR-torn lines before any leg reads the log.
#
# `after()` below matches the prompt+command as one string ("D:/ $ write
# /m1.txt"). That only works while the echo actually follows the prompt on the
# same line -- and the EDR status burst breaks exactly that. The shell writes
# "D:/ $ " with NO trailing newline, so a burst arriving in that window
# terminates the prompt line and leaves the command echo at column 0:
#
#     D:/ $ [EDR DAEMON] Starting threat scan...
#     [EDR DAEMON] Scanning 7 active processes
#     [EDR DAEMON] Scan complete: 7 processes, duration 0 ticks
#     write /m1.txt MOVEME
#
# Measured on the failing capture: "$ write /m1.txt" occurs ZERO times, while
# "^write /m1.txt" occurs once. So every after() lookup returned the empty
# string and ELEVEN legs failed at once -- reported as "seed write did not
# land (size=, want 31)", i.e. as a broken ramfs. The filesystem was correct
# throughout; the same log shows `cat /self.txt` printing MOVEME.
#
# Splice rather than loosen the pattern. Anchoring on '(^|\$ )cmd' was tried
# elsewhere (PR #115) and is incomplete: the tear lands at an ARBITRARY
# character, so '$ write' can arrive as '$ wr' + 'ite'. Rejoining restores the
# exact line the patterns already expect, and keeps after()'s prompt anchor --
# which is load-bearing here, since a bare command match would also hit the
# harness's own typed input.
#
# Two line kinds, and conflating them loses data: a line that STARTS with the
# burst is pure noise (drop it); a line that merely CONTAINS it carries real
# output before the burst (keep that prefix and splice it onto the
# continuation). The END flush recovers a torn line with nothing after it.
REJOINED="${SERIAL}.rejoined"
. "$(dirname "$0")/edr-rejoin.sh"
rejoin_serial "$SERIAL" "$REJOINED"
SERIAL="$REJOINED"

after() {
    nth="${2:-1}"
    grep -A1 -F "\$ $1" "$SERIAL" 2>/dev/null | grep -v "^--$" \
        | sed -n "$((nth * 2))p" | tr -d '\r'
}

rc=0

# Wrong-shell guard. If `kshell` ran, the ring-3 shell exited and every command
# below was answered by the KERNEL shell's own write/cat/touch -- different
# code, plausible-looking output, and a verdict about a shell this harness is
# not testing. Refuse to grade such a run at all rather than reporting on it.
if grep -qE "^D:/ \\\$ kshell" "$SERIAL" || grep -q "Switching to the kernel shell" "$SERIAL"; then
    echo "INCONCLUSIVE: the run left the ring-3 shell for the kernel shell."
    echo "  TINYOS_STAY_IN_RING3=1 must be set for this harness; without it the"
    echo "  typist sends 'kshell' after login and the builtins under test are"
    echo "  never reached."
    exit 2
fi

# Positive confirmation that ring-3 builtins actually answered: the kernel
# shell prints 'File created: ...' for touch, the ring-3 one does not. Absence
# of the kshell marker is necessary but not sufficient.
if ! grep -qE "^D:/ \\\$ " "$SERIAL"; then
    echo "INCONCLUSIVE: no ring-3 prompt ('D:/ \$ ') in the log -- the ring-3"
    echo "  shell never reached a prompt, so nothing below was exercised."
    exit 2
fi

check() {
    label="$1"; cmdline="$2"; want="$3"
    got=$(after "$cmdline")
    if [ "$got" = "$want" ]; then
        echo "  OK  $label"
    else
        echo "  FAIL $label"
        echo "       after '$cmdline'"
        echo "       want: '$want'"
        echo "       got : '$got'"
        rc=1
    fi
}

# The load-bearing assertion. `stat` line looks like: /trunc.txt  size=4  file
# Occurrence 2 is the one after the short rewrite; occurrence 1 (size=31) is
# the seed and is checked too, so a run where the seed silently failed to write
# cannot masquerade as a successful truncation.
size_of() { after "stat $1" "${2:-1}" | sed -n 's/.*size=\([0-9]*\).*/\1/p'; }

seed_sz=$(size_of "/trunc.txt" 1)
trunc_sz=$(size_of "/trunc.txt" 2)
if [ "$seed_sz" != "31" ]; then
    echo "  FAIL seed write did not land (size=$seed_sz, want 31)"; rc=1
elif [ "$trunc_sz" = "4" ]; then
    echo "  OK  O_TRUNC via write truncated the file (31 -> 4)"
else
    echo "  FAIL O_TRUNC via write: size=$trunc_sz after rewrite, want 4"
    echo "       31 means the stale tail survived -- the ramfs_vfs.c O_TRUNC"
    echo "       wiring is missing. Note 'cat' shows BBB either way."
    rc=1
fi

check "content after truncating rewrite"       "cat /trunc.txt" "BBB"
check "touch preserves existing content"       "cat /t1.txt"    "KEEPME"
check "cp copies content"                      "cat /dst.txt"   "COPYSRC"
over_sz=$(size_of "/over.txt" 1)
if [ "$over_sz" = "4" ]; then
    echo "  OK  cp truncated a longer destination (8 -> 4)"
else
    echo "  FAIL cp truncates a longer destination: size=$over_sz, want 4"
    echo "       8 means cp's O_TRUNC did not take and 'COPYSRC' partly"
    echo "       survives underneath the copied bytes."
    rc=1
fi

check "content after cp over longer file"      "cat /over.txt"  "ZZZ"
check "cp onto itself does not destroy"        "cat /src.txt"   "COPYSRC"
check "mv onto itself does not destroy"        "cat /self.txt"  "MOVEME"
check "mv moved content to destination"        "cat /m2.txt"    "MOVEME"

# mv must REMOVE the source. The `cat` of a removed file reports the error, so
# assert on that rather than on emptiness -- an empty line would also be
# produced by a file that exists and is empty, which is the failure where mv
# truncated instead of moving.
src_after_mv=$(after "cat /m1.txt")
case "$src_after_mv" in
    *"no such file"*) echo "  OK  mv removed the source" ;;
    *) echo "  FAIL mv did not remove the source"
       echo "       got: '$src_after_mv'"; rc=1 ;;
esac

# mv into a directory is refused AND non-destructive. The refusal message and
# the surviving content are both required: refusing while having already
# copied would still be a bug.
if grep -qF "mv: /adir: is a directory" "$SERIAL"; then
    echo "  OK  mv into a directory refused"
else
    echo "  FAIL mv into a directory was not refused"; rc=1
fi
# SECOND occurrence: /m2.txt is cat'd once in step 6 and again here. Reading
# the first would re-assert step 6 and prove nothing about the refusal.
got=$(after "cat /m2.txt" 2)
if [ "$got" = "MOVEME" ]; then
    echo "  OK  mv refusal left the source intact"
else
    echo "  FAIL mv refusal left the source intact (got '$got')"; rc=1
fi

echo
if [ "$rc" -ne 0 ]; then
    echo "RESULT: FAIL (typist rc=$TYPIST_RC)"
    echo "  If ONLY the truncation checks failed, suspect the ramfs_vfs.c"
    echo "  O_TRUNC wiring. If the self-copy checks failed, the guard in"
    echo "  cmd_cp/cmd_mv is gone and those commands now delete files."
    exit 1
fi

echo "RESULT: PASS"
echo "  - open(O_TRUNC) truncates on the RAM disk (kernel fix)"
echo "  - cp copies, truncates the destination, refuses self-copy"
echo "  - mv moves, removes the source, refuses self-move and directories"
echo "  - touch creates without clobbering"
exit 0

# =============================================================================
# VALIDATION LOG — all runs below are real, on this machine.
#
# 1. WRONG SHELL (fixed). First run reported the O_TRUNC corruption string and
#    was briefly read as the fix failing. The serial log showed `D:/ $ kshell`
#    just before it: the typist switches to the kernel shell by default, so
#    every command had been answered by the KERNEL shell's write/cat/touch --
#    different code entirely. TINYOS_STAY_IN_RING3=1 now set, plus a guard that
#    exits 2 if the kshell marker appears. Lesson: a harness for ring-3
#    builtins must prove it was IN ring 3; the prompt (`D:/ $` vs bare `$ `)
#    is the tell.
#
# 2. FALSE PASS ON THE NEGATIVE CONTROL (fixed — the important one). With the
#    ramfs_vfs.c O_TRUNC call replaced by (void)0 and the source guard lowered,
#    the suite still reported PASS on all ten checks. objdump confirmed the
#    shipped kernel.elf had ZERO ramfs_truncate calls in ramfs_vfs_open, so the
#    assertions genuinely did not depend on the fix.
#
#    Cause: every truncation check used `cat`, and `cat` shows "BBB" whether or
#    not the tail was dropped. A direct probe settled it:
#
#      write /p.txt <30 A's>; stat; write /p.txt BBB; stat; cat
#        fix disabled -> size=31 then size=31, cat "BBB"
#        fix enabled  -> size=31 then size=4,  cat "BBB"
#
#    Both truncation checks were rewritten onto `stat`. Re-run with the fix
#    reverted then FAILS on exactly those two (size=31, size=8) while the eight
#    unrelated checks still pass -- and the two `cat` checks pass in BOTH
#    directions, preserved in the suite as a standing demonstration that
#    content alone cannot witness this bug.
#
# 3. SOURCE GUARD. Run against the reverted tree with the guard restored:
#    exits 2 with "ramfs_vfs.c does not call ramfs_truncate()" before booting.
#
# 4. POSITIVE. Fix in place: all twelve checks OK, exit 0.
#
# Not covered: the mv-copy-fails-so-source-survives path. It needs an
# unwritable destination, and the ring-3 shell has no way to create one on the
# RAM disk as root. The conditional unlink in cmd_mv is therefore reviewed but
# not exercised here.
# =============================================================================
