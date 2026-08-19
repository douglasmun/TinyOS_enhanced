#!/usr/bin/env bash
#
# verify-mseal-counters.sh — FULLY AUTOMATED check that SYS_MSEAL (16) COUNTS
# its ring-3-driven rejections instead of PRINTING them, and that it still
# actually seals memory.
#
# WHAT THIS IS TESTING, AND WHY IT EXISTS
#
# SYS_MSEAL had sixteen kprintf sites on its path: seven in sys_mseal() and
# nine in pae_seal_memory_in(). Every one of them was driven by a ring-3
# caller's OWN argument, on the console the ring-3 shell shares. This is the
# same class CLAUDE.md closed for the RX path in PR #101 — "count, don't
# print" — reached here through a syscall instead of a frame.
#
# The cheapest instance needs NO privilege and NO memory: pass size 0, get
# rejected in sys_mseal above any page walk, print a line, repeat at syscall
# rate. Two of the nine sat INSIDE pae_seal_memory_in's page loop, so a single
# call over a large unmapped region printed from within the walk itself.
#
# It survived unnoticed because SYS_MSEAL has no libc wrapper and no shell
# builtin: nothing in the tree could reach it. /msealprobe.elf exists solely
# to be that driver — see userspace/msealprobe.c.
#
# WHAT WOULD MAKE THIS HARNESS LIE — and what is done about each
#
# 1. A COUNTER THAT COUNTS EVERYTHING passes a "did it go up?" assertion
#    perfectly. So every leg asserts an EXACT DELTA, and the probe drives each
#    counter a DISTINCT number of times (3/5/7 bounds, 11+13 size, 4 unmapped).
#    No single miscounting site produces all of those numbers at once.
#
# 2. "NOTHING PRINTED" IS ALSO WHAT A PROBE THAT NEVER RAN LOOKS LIKE. The
#    silence assertion is worthless without proof the path executed, so it is
#    paired with the delta assertions above and with the probe's own PROBE
#    lines. If the probe did not run, this scores INCONCLUSIVE, never PASS.
#
# 3. AN ALL-REJECTIONS HARNESS PASSES AGAINST A sys_mseal THAT REFUSES
#    EVERYTHING — the four rejection counters would read exactly right. Leg 5
#    is the POSITIVE CONTROL: the probe seals a page of its own writable data
#    and `sealed` must rise by exactly 1, with `pages` rising too. Do not
#    "simplify" this leg away.
#
# 4. GRADING ROOT. The probe is run as an UNPRIVILEGED user, because the whole
#    complaint is that an unprivileged caller drives these sites. SYS_MSEAL is
#    ungated by design (it seals the CALLER'S OWN address space — cur->
#    page_directory — so the blast radius is self-inflicted), which means an
#    -EPERM in leg 5 is THE BUG, not the pass. That is the same polarity trap
#    CLAUDE.md records for SYS_ENV: measure as non-root.
#
# HOW THE COUNTERS ARE READ
#
# Through `secstatus` in the KERNEL shell, before and after the ring-3 probe
# run. secstatus is the reading instrument only; every counted event is
# produced from ring 3. Reading them kernel-side is deliberate: these are
# kernel-internal counters with no ring-3 accessor, and adding one would be
# new attack surface for a test's convenience.
#
# NOTE ON THE INTERRUPT-LATENCY HYPOTHESIS. This audit began from a different
# concern: pae_seal_memory_in walks an attacker-chosen page count (up to
# 16384) twice inside ONE critical section. That concern was MEASURED and
# DISPROVED — with total work held constant the tick delta FELL as region size
# grew (140us/page at 16 pages down to 0.6us/page at 16384), worst case ~10ms
# under TCG. Per-call overhead dominates; there is no interrupt stall. The
# kprintf class is the defect that survived. Recorded here so nobody re-opens
# the latency question from the function's shape alone.
#
# ASSERTIONS
#
#   - the probe ran and printed all seven PROBE lines     (non-vacuity)
#   - bounds rises by exactly 15   (3 + 5 + 7, all crossing into kernel space)            (exact delta)
#   - size   rises by exactly 24   (11 + 13)              (exact delta)
#   - pae unmapped rises by exactly 4                     (the in-loop pair)
#   - `failed` and pae `unmapped` agree                   (layering)
#   - sealed rises by exactly 1 and pages by >= 1         (POSITIVE CONTROL)
#   - NO "[MSEAL]" text anywhere in the serial log        (the actual fix)
#   - no dispatcher rejection anywhere                    (MAX_SYSCALL_NUM)
#
# VALIDATED BOTH WAYS (2026-08-19). PASS as written: deltas bounds=15 size=24
# unmapped=4 failed=4 sealed=1 pages=1, and 0 '[MSEAL]' lines. With
# sys_mseal's `mseal_reject_size++` changed to `mseal_reject_bounds++` -- the
# exact "one counter catches everything" regression the exact-delta design
# exists to catch -- it FAILS on leg 2 with bounds=39 size=0, and names which
# counter absorbed which. A ">= 1" assertion would have passed that build.
#
# Exit 0 = PASS, 1 = FAIL, 3 = INCONCLUSIVE.
# Logs: mseal.log (serial), mseal-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

TESTUSER=msuser
TESTPASS=mspass1

# Must match the #defines in userspace/msealprobe.c.
EXP_BOUNDS=15    # 3 kernel-addr + 5 high-crossing + 7 cross
EXP_SIZE=24      # 11 zero + 13 huge
EXP_UNMAPPED=4
EXP_SEALED=1

ISO=dist/tinyos.iso
SERIAL=mseal.log
TRACE=mseal-trace.log
RUN_DISK=/tmp/tinyos-mseal-disk.img
MON_SOCK=/tmp/tinyos-mseal-mon.sock

echo "==> Building userspace (incl. msealprobe.elf)..."
(cd userspace && make) >/dev/null || exit 1

# Re-sign and re-embed BOTH the probe and the ring-3 shell, or this run grades
# a previous build of either.
python3 tools/sign_elf.py userspace/msealprobe.elf userspace/msealprobe.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/msealprobe.elf.signed \
        src/msealprobe_elf_data.c src/msealprobe_elf_data.h msealprobe_elf_data >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1

make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# GUARD: the counter accessors must be in the binary under test. A stale
# syscall.o would grade a kernel that predates this change entirely.
# Capture then match; `nm | grep -q` SIGPIPEs under pipefail.
NM_OUT="$(i686-elf-nm kernel.elf 2>/dev/null || true)"
case "$NM_OUT" in
  *syscall_get_mseal_stats*) : ;;
  *) echo "RESULT: INCONCLUSIVE — kernel.elf has no syscall_get_mseal_stats symbol"
     echo "  The kernel half of this change is not in the binary under test."
     exit 3 ;;
esac
case "$NM_OUT" in
  *pae_get_mseal_stats*) : ;;
  *) echo "RESULT: INCONCLUSIVE — kernel.elf has no pae_get_mseal_stats symbol"
     exit 3 ;;
esac

# GUARD: the ISO must carry the new secstatus line, or the counters cannot be
# read and every delta below would come back empty.
ISO_MARKERS=$(strings "$ISO" | grep -c "Memory sealing")
if [ "$ISO_MARKERS" -eq 0 ]; then
    echo "RESULT: INCONCLUSIVE — the ISO has no 'Memory sealing' secstatus line"
    echo "  The reading instrument is absent, so no delta can be measured."
    exit 3
fi

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

# Sequence: root reads the BEFORE counters, creates the unprivileged user, sus
# to it, runs the probe from ring 3, returns to the kernel shell and reads the
# AFTER counters. `exit` from the ring-3 shell drops back to kshell.
#
# The probe is exec'd from the RING-3 shell so the calls originate at ring 3
# as an unprivileged uid — running it from kshell would still reach ring 3 via
# exec, but from a root-owned session, and leg 5's polarity is about the
# unprivileged case.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_FOLLOWUP_TIMEOUT=900 \
TINYOS_EXEC_CMD="help" \
TINYOS_EXPECT="TinyOS shell (ring 3)" \
TINYOS_FOLLOWUP_CMDS="\
kshell=>Switching to the kernel shell;\
secstatus=>Memory sealing;\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
su $TESTUSER=>Now running as;\
exec /shell.elf=>TinyOS shell (ring 3);\
!/msealprobe.elf=>PROBE VERDICT;\
!exit=>shell: exiting;\
secstatus=>Memory sealing" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: FAIL — no serial output at all (typist rc=$TYPIST_RC)"
    exit 2
fi

fail_with() {
    echo "RESULT: FAIL — $1"; shift
    for line in "$@"; do echo "  $line"; done
    exit 1
}
inconclusive_with() {
    echo "RESULT: INCONCLUSIVE — $1"; shift
    for line in "$@"; do echo "  $line"; done
    exit 3
}

CLEAN=$(tr -d '\r' < "$SERIAL")

# ---------------------------------------------------------------------------
# Leg 0: dispatcher accepted SYS_MSEAL at all.
# Both messages matched — the range check and the switch default print
# different text, and a leg matching only one has passed vacuously before.
# ---------------------------------------------------------------------------
REJECTED=$(printf '%s\n' "$CLEAN" | grep -Ec "Invalid syscall number|Unknown system call")
if [ "$REJECTED" -ne 0 ]; then
    fail_with "the dispatcher rejected a syscall ($REJECTED occurrence(s))" \
        "$(printf '%s\n' "$CLEAN" | grep -Em2 'Invalid syscall number|Unknown system call')"
fi

# ---------------------------------------------------------------------------
# Leg 1 (NON-VACUITY): the probe ran and reached every leg.
#
# Without this, "no [MSEAL] output" and "no probe at all" are the same log.
# ---------------------------------------------------------------------------
for tag in bounds_kernel bounds_high bounds_cross size_zero size_huge unmapped seal_own; do
    if ! printf '%s\n' "$CLEAN" | grep -q "PROBE $tag"; then
        inconclusive_with "the probe never printed 'PROBE $tag'" \
            "msealprobe.elf did not run to completion, so the counter deltas" \
            "below have nothing to measure. Check that /msealprobe.elf exists" \
            "and that exec succeeded; see $SERIAL."
    fi
done

# ---------------------------------------------------------------------------
# Read the BEFORE and AFTER counter lines. Two 'Memory sealing' lines must
# exist: one from each secstatus.
# ---------------------------------------------------------------------------
SEAL_LINES=$(printf '%s\n' "$CLEAN" | grep "Memory sealing")
SEAL_N=$(printf '%s\n' "$SEAL_LINES" | grep -c "Memory sealing")
if [ "$SEAL_N" -ne 2 ]; then
    inconclusive_with "expected 2 'Memory sealing' lines, found $SEAL_N" \
        "Both secstatus readings are needed to form a delta." \
        "$SEAL_LINES"
fi

ARG_LINES=$(printf '%s\n' "$CLEAN" | grep "Seal arg rejects")
ARG_N=$(printf '%s\n' "$ARG_LINES" | grep -c "Seal arg rejects")
if [ "$ARG_N" -ne 2 ]; then
    inconclusive_with "expected 2 'Seal arg rejects' lines, found $ARG_N" "$ARG_LINES"
fi

# Line shape:
#   Memory sealing ...... N regions / M pages sealed, R rejected (B bounds, S size, ...)
#   Seal arg rejects .... A bad-args, U unmapped-page
# Each pattern must be anchored on BOTH sides. `sed`'s leading `.*` is greedy
# and backtracks to the LAST match, so an unanchored `\(N\) size` on the line
#   "43 rejected (15 bounds, 24 size, 0 nospace, 4 failed)"
# returns 4 (from "4 failed") rather than 24 -- which is exactly how the first
# run of this harness reported a correct kernel as broken. Every pattern below
# carries the punctuation on each side of the number for that reason.
# Patterns must also avoid `/` and `.`: `/` closes sed's s/// delimiter, and a
# literal `.` needs escaping that then collides with the delimiter check.
field() {   # field <line> <regex-with-one-group, anchored both sides>
    printf '%s\n' "$1" | sed -n "s/.*$2.*/\1/p" | head -1
}

B_SEAL=$(printf '%s\n' "$SEAL_LINES" | head -1)
A_SEAL=$(printf '%s\n' "$SEAL_LINES" | tail -1)
B_ARG=$(printf '%s\n' "$ARG_LINES" | head -1)
A_ARG=$(printf '%s\n' "$ARG_LINES" | tail -1)

B_SEALED=$(field "$B_SEAL" ' \([0-9][0-9]*\) regions')
A_SEALED=$(field "$A_SEAL" ' \([0-9][0-9]*\) regions')
B_PAGES=$(field "$B_SEAL" ' \([0-9][0-9]*\) pages sealed,')
A_PAGES=$(field "$A_SEAL" ' \([0-9][0-9]*\) pages sealed,')
B_BOUNDS=$(field "$B_SEAL" '(\([0-9][0-9]*\) bounds')
A_BOUNDS=$(field "$A_SEAL" '(\([0-9][0-9]*\) bounds')
B_SIZE=$(field "$B_SEAL" ', \([0-9][0-9]*\) size,')
A_SIZE=$(field "$A_SEAL" ', \([0-9][0-9]*\) size,')
B_FAILED=$(field "$B_SEAL" ', \([0-9][0-9]*\) failed')
A_FAILED=$(field "$A_SEAL" ', \([0-9][0-9]*\) failed')
B_UNMAP=$(field "$B_ARG" ', \([0-9][0-9]*\) unmapped-page')
A_UNMAP=$(field "$A_ARG" ', \([0-9][0-9]*\) unmapped-page')

for v in B_SEALED A_SEALED B_PAGES A_PAGES B_BOUNDS A_BOUNDS B_SIZE A_SIZE \
         B_FAILED A_FAILED B_UNMAP A_UNMAP; do
    eval "val=\$$v"
    if [ -z "$val" ]; then
        inconclusive_with "could not parse $v from the secstatus lines" \
            "BEFORE seal: $B_SEAL" "AFTER  seal: $A_SEAL" \
            "BEFORE arg : $B_ARG"  "AFTER  arg : $A_ARG"
    fi
done

D_SEALED=$((A_SEALED - B_SEALED))
D_PAGES=$((A_PAGES - B_PAGES))
D_BOUNDS=$((A_BOUNDS - B_BOUNDS))
D_SIZE=$((A_SIZE - B_SIZE))
D_FAILED=$((A_FAILED - B_FAILED))
D_UNMAP=$((A_UNMAP - B_UNMAP))

echo "  deltas: bounds=$D_BOUNDS size=$D_SIZE unmapped=$D_UNMAP failed=$D_FAILED sealed=$D_SEALED pages=$D_PAGES"

# ---------------------------------------------------------------------------
# Legs 2-4: EXACT deltas on the rejection counters.
#
# Exact, not ">= 1": a single counter bumped by every rejection would read
# 15+24+4 = 43 on all three and satisfy any "did it rise" test.
# ---------------------------------------------------------------------------
if [ "$D_BOUNDS" -ne "$EXP_BOUNDS" ]; then
    fail_with "bounds counter rose by $D_BOUNDS, expected exactly $EXP_BOUNDS" \
        "The probe makes 3 kernel-address + 5 high-crossing + 7 cross-into-kernel calls." \
        "A value of $((EXP_BOUNDS + EXP_SIZE + EXP_UNMAPPED)) would mean ONE counter is" \
        "catching every rejection — the grouping by caller intent is gone."
fi

if [ "$D_SIZE" -ne "$EXP_SIZE" ]; then
    fail_with "size counter rose by $D_SIZE, expected exactly $EXP_SIZE" \
        "The probe makes 11 size-0 + 13 oversize calls. These are the cheapest" \
        "rejections in the kernel — no memory, no privilege, no page walk — and" \
        "are the ones an unprivileged flood would use."
fi

if [ "$D_UNMAP" -ne "$EXP_UNMAPPED" ]; then
    fail_with "pae unmapped counter rose by $D_UNMAP, expected exactly $EXP_UNMAPPED" \
        "These two sites live INSIDE pae_seal_memory_in's page loop — they are" \
        "the pair that could print from within the walk itself."
fi

# ---------------------------------------------------------------------------
# Leg 4b (LAYERING): the syscall's `failed` and the PAE layer's `unmapped`
# describe the SAME four calls from two different heights, so they must agree.
#
# Each layer counting its own view is deliberate, not double-counting:
# pae_seal_memory_in refuses (unmapped), sys_mseal observes the refusal
# (failed). If these ever diverge, either a refusal is being invented at one
# layer or swallowed at the other -- and the surface would be reporting a
# rejection reason that never happened.
# ---------------------------------------------------------------------------
if [ "$D_FAILED" -ne "$D_UNMAP" ]; then
    fail_with "failed rose by $D_FAILED but pae unmapped rose by $D_UNMAP" \
        "These count the same four calls from two layers and must agree." \
        "A divergence means a refusal is invented at one layer or swallowed" \
        "at the other."
fi

# ---------------------------------------------------------------------------
# Leg 5 (POSITIVE CONTROL): sealing still WORKS, for an unprivileged caller.
#
# Everything above is satisfied by a sys_mseal that refuses every call. This
# is the leg that distinguishes "correctly rejects bad input" from "rejects
# everything". An -EPERM here is the bug: SYS_MSEAL is ungated because it
# seals the caller's own address space.
# ---------------------------------------------------------------------------
if ! printf '%s\n' "$CLEAN" | grep -q "PROBE VERDICT sealed"; then
    VERDICT=$(printf '%s\n' "$CLEAN" | grep "PROBE VERDICT" | head -1)
    fail_with "the positive control did not seal ($VERDICT)" \
        "$(printf '%s\n' "$CLEAN" | grep 'PROBE seal_own' | head -1)" \
        "SYS_MSEAL is UNGATED by design — it seals cur->page_directory, the" \
        "caller's OWN address space. An unprivileged refusal here is the bug," \
        "not the pass. Without this leg, every assertion above is satisfied by" \
        "a kernel that refuses everything."
fi

if [ "$D_SEALED" -ne "$EXP_SEALED" ]; then
    fail_with "sealed counter rose by $D_SEALED, expected exactly $EXP_SEALED" \
        "The probe seals exactly one region successfully."
fi

if [ "$D_PAGES" -lt 1 ]; then
    fail_with "pages-sealed counter rose by $D_PAGES, expected at least 1" \
        "The regions counter moved but the page counter did not, which means" \
        "the success path is being counted without any page being walked."
fi

# ---------------------------------------------------------------------------
# Leg 6 (THE ACTUAL FIX): the console stayed silent.
#
# Measured LAST on purpose. Silence only means anything once the legs above
# have proven the path executed 44 times and sealed once — otherwise this is
# the assertion that a probe which never ran would pass most convincingly.
# ---------------------------------------------------------------------------
MSEAL_PRINTS=$(printf '%s\n' "$CLEAN" | grep -c "\[MSEAL\]")
if [ "$MSEAL_PRINTS" -ne 0 ]; then
    fail_with "$MSEAL_PRINTS '[MSEAL]' line(s) reached the console" \
        "These are driven by a ring-3 caller's own arguments on a console the" \
        "ring-3 shell shares. Count, don't print — see CLAUDE.md." \
        "First few:" \
        "$(printf '%s\n' "$CLEAN" | grep '\[MSEAL\]' | head -5)"
fi

echo "RESULT: PASS"
echo "  $((EXP_BOUNDS + EXP_SIZE + EXP_UNMAPPED)) rejections counted with exact per-intent deltas,"
echo "  1 region / $D_PAGES page(s) sealed by an UNPRIVILEGED ring-3 caller,"
echo "  and 0 '[MSEAL]' lines on the console."
exit 0
