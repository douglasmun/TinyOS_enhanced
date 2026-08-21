#!/usr/bin/env bash
#
# verify-guard-page-release.sh — is a freed guard-page frame safe to reuse?
#
# THE CLAIM. A kernel task's guard page is identity-mapped NOT PRESENT in the
# kernel identity map, which EVERY address space shares. Teardown used to hand
# that frame straight back with pmm_free(). The PMM then owns a frame whose
# identity mapping still says not-present, so the next pmm_alloc() to hand it
# out gives its new owner a page that faults on first touch — a task with no
# relationship to the one that died. guard_page_release() (process.c:937) is
# the fix: re-map present+RW+NX and flush the TLB BEFORE freeing.
#
# WHY THE FRAME-LEAK HARNESS'S METHOD DOES NOT WORK HERE. This looks like a
# sibling of verify-exec-frame-leak.sh — same subsystem, same `mem` surface —
# and copying it would be the mistake. A LEAK changes the free-frame count, so
# `mem` before/after witnesses it directly. POISONING DOES NOT: pmm_free()
# succeeds either way, the count returns to baseline either way, and a
# before/after `mem` delta of zero is exactly what BOTH the fixed and the
# broken kernel print. An exact-equality assertion on free frames would pass
# against the completely unfixed kernel. The frame accounting is not the
# property under test — the MAPPING STATE of the recycled frame is.
#
# WHAT ACTUALLY WITNESSES IT. The fault lands on whoever allocates the frame
# next, and it is not that task's stack or guard, so it falls past both guard
# checks in idt.c and reaches the generic handler:
#
#     *** PAGE FAULT ***          <- the signature we hunt
#
# as opposed to "*** STACK OVERFLOW DETECTED ***", which is a guard page being
# hit legitimately by its OWN task and is NOT this bug.
#
# METHOD. Churn user processes so guard frames are freed and recycled, then
# drive allocation hard enough that a poisoned frame is handed out and touched:
#
#     mem                         <- baseline
#     exec /hello.elf   x8        <- 8 create/destroy cycles, 2 guard frames each
#     ls / cat / mem              <- allocation + touch pressure after the churn
#     mem                         <- accounting cross-check
#
# TIMING IS THE WHOLE DIFFICULTY. The poisoned frame must be RE-ALLOCATED and
# TOUCHED for the fault to appear; if the PMM never hands it back out during
# the run, a broken kernel stays silent. That makes a quiet log WEAK evidence,
# and this harness says so rather than converting it into a green PASS. The
# churn count and the post-churn pressure exist to shorten those odds, not to
# guarantee them.
#
# So there are two legs, and only the first is decisive:
#
#   Leg 1 (source guard, DECISIVE)  — every kernel-guard free goes through
#                                     guard_page_release(), and that function
#                                     re-maps before freeing. This is what
#                                     actually regresses.
#   Leg 2 (runtime, CORROBORATING)  — churn the kernel and look for the fault
#                                     signature. Finding one FAILS. Not finding
#                                     one is reported as "no fault observed",
#                                     never as proof of correctness.
#
# Exit 0 = leg 1 holds and leg 2 saw no fault. 1 = a leg failed. 2 = setup.
# Logs: guardpg.log (serial), guardpg-trace.log (int/cpu_reset).
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=guardpg.log
TRACE=guardpg-trace.log
MON_SOCK=/tmp/tinyos-guardpg-mon.sock
SRC=src/process.c

RC=0
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; RC=1; }
info() { printf '        %s\n' "$1"; }

echo "=== verify-guard-page-release.sh ==="
echo

#-----------------------------------------------------------------------------
# Leg 1: source guard.
#
# Two separate properties. (a) guard_page_release() re-maps and flushes before
# it frees — checked as an ordered sequence, because a version that frees first
# and re-maps after would still contain all three calls. (b) No KERNEL guard
# page is freed by a bare pmm_free() that bypasses the helper.
#
# On (b), three bare pmm_free() sites are CORRECT and must not be flagged:
#   process.c:660, 1095  — failure paths ABOVE the map_page() that creates the
#                          not-present PTE, so there is no mapping to restore.
#   process.c:1212, 1751 — the USER guard page, which lives in the per-task
#                          PAE address space, not the shared identity map;
#                          pae_free_user_pdpt() tears that mapping down whole.
# The check is therefore scoped to task->guard_page_phys, the field that names
# the kernel guard, rather than grepping every "guard" free in the file.
#-----------------------------------------------------------------------------
echo "Leg 1: source guard (kernel guard frees re-map before freeing)"

if [ ! -r "$SRC" ]; then
    echo "FATAL: missing $SRC"; exit 2
fi

# (a) ordering inside guard_page_release()
BODY=$(awk '/^static void guard_page_release\(uint32_t guard_phys\)/,/^}/' "$SRC")
if [ -z "$BODY" ]; then
    fail "guard_page_release() not found — the fix is gone entirely"
else
    L_MAP=$(printf '%s\n' "$BODY" | grep -n "map_page(guard_phys, guard_phys" | head -1 | cut -d: -f1)
    L_FLUSH=$(printf '%s\n' "$BODY" | grep -n "flush_tlb_single(guard_phys)" | head -1 | cut -d: -f1)
    L_FREE=$(printf '%s\n' "$BODY" | grep -n "pmm_free(guard_phys)" | head -1 | cut -d: -f1)

    if [ -z "$L_MAP" ] || [ -z "$L_FLUSH" ] || [ -z "$L_FREE" ]; then
        fail "guard_page_release() is missing map_page / flush_tlb_single / pmm_free"
        info "map=${L_MAP:-absent} flush=${L_FLUSH:-absent} free=${L_FREE:-absent}"
    elif [ "$L_MAP" -lt "$L_FLUSH" ] && [ "$L_FLUSH" -lt "$L_FREE" ]; then
        pass "guard_page_release(): map_page -> flush_tlb_single -> pmm_free, in order"
    else
        fail "guard_page_release() has the calls in the WRONG ORDER"
        info "map=$L_MAP flush=$L_FLUSH free=$L_FREE (need map < flush < free)"
        info "freeing before re-mapping poisons the frame just as surely."
    fi

    # PAGE_PRESENT is the bit that matters: re-mapping without it restores
    # nothing. NX is asserted too so the repair does not quietly hand back an
    # executable frame.
    if printf '%s\n' "$BODY" | grep -q "PAGE_PRESENT"; then
        pass "guard_page_release(): re-maps with PAGE_PRESENT"
    else
        fail "guard_page_release(): re-map does not set PAGE_PRESENT"
    fi
    if printf '%s\n' "$BODY" | grep -q "PAE_NX"; then
        pass "guard_page_release(): re-maps NX"
    else
        fail "guard_page_release(): re-map is not NX (frame returns executable)"
    fi
fi

# (b) no kernel guard freed outside the helper
# Exemption is CONTENT-based, not line-based: the two legitimate bare frees
# sit on failure paths ABOVE the map_page() that creates the not-present PTE,
# and each is marked with the comment below. Keying on line numbers would let
# any edit that shifts the file silently re-exempt a real site (and did, until
# a negative control shifted process.c by 8 lines).
# One awk pass: a bare free is exempt only if the line directly above it is the
# /* GUARD-UNMAPPED-OK */ tag. Content-based, so it survives edits that shift
# line numbers (a line-number exemption silently re-exempted a real site once).
# A single-line tag on purpose: keying on prose would break on rewrapping.
BARE=$(awk '
    /pmm_free\(task->guard_page_phys\)|pmm_free\(guard_page_phys\)/ {
        if (prev !~ /GUARD-UNMAPPED-OK/) printf "%d:%s\n", NR, $0
    }
    { prev = $0 }
' "$SRC")
if [ -n "$BARE" ]; then
    # 660/1095 are pre-map failure paths; anything else bypasses the helper.
    fail "a kernel guard page is freed without re-mapping:"
    printf '%s\n' "$BARE" | sed 's/^/        /'
    info "these must call guard_page_release() instead."
else
    pass "no kernel guard page freed outside guard_page_release()"
fi

# Teardown must actually call it.
if grep -q "guard_page_release(task->guard_page_phys)" "$SRC"; then
    pass "task_free_resources() releases the kernel guard via the helper"
else
    fail "task_free_resources() does not call guard_page_release()"
fi
echo

if [ "$RC" -ne 0 ]; then
    echo "RESULT: FAIL (source guard) — skipping the runtime leg, it corroborates only"
    exit 1
fi

#-----------------------------------------------------------------------------
# Leg 2: runtime corroboration.
#-----------------------------------------------------------------------------
echo "Leg 2: runtime churn (recycle guard frames, watch for a stray fault)"

echo "  building kernel + ISO..."
make >/dev/null 2>&1 || { echo "  build failed"; exit 2; }
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || { echo "  mkrescue failed"; exit 2; }

rm -f "$SERIAL" "$TRACE" "$MON_SOCK"

qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
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

# Kernel shell on purpose: `mem` is root-only and machine-state, so
# TINYOS_STAY_IN_RING3 is deliberately NOT set. Same exception as
# verify-exec-frame-leak.sh — the subject is kernel teardown, not a ring-3
# boundary.
#
# Each exec is verified on "Process exited" so the next is not typed until the
# previous task is reaped and its guard frames are actually back in the PMM.
# The trailing ls/cat/mem are ALLOCATION PRESSURE: they exist to get a recycled
# frame handed out and touched while we are still watching.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=900 \
TINYOS_EXEC_CMD="mem" \
TINYOS_EXPECT="Free:" \
TINYOS_FOLLOWUP_CMDS="\
exec /hello.elf=>Process exited;\
exec /hello.elf=>Process exited;\
exec /hello.elf=>Process exited;\
exec /hello.elf=>Process exited;\
exec /hello.elf=>Process exited;\
exec /hello.elf=>Process exited;\
exec /hello.elf=>Process exited;\
exec /hello.elf=>Process exited;\
ls /=>hello.elf;\
ps=>PID;\
mem=>Free:" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup
echo

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: harness problem — no serial output (typist rc=$TYPIST_RC)"
    exit 2
fi

CLEAN=$(mktemp "${TMPDIR:-/tmp}/guardpg.XXXXXX")
tr -d '\r' < "$SERIAL" | grep -v Suspicious > "$CLEAN"

CYCLES=$(grep -c "Process exited" "$CLEAN")
echo "  exec cycles completed: $CYCLES (requested 8)"

if [ "$CYCLES" -lt 4 ]; then
    echo "  RESULT: harness problem — too few cycles to recycle guard frames"
    info "typist rc=$TYPIST_RC; the churn never happened, so nothing was tested."
    tail -20 "$CLEAN"
    rm -f "$CLEAN"; exit 2
fi

# The signature. Note "STACK OVERFLOW DETECTED" is explicitly NOT this bug —
# that is a task hitting its own guard, which is the guard working.
if grep -q "\*\*\* PAGE FAULT \*\*\*" "$CLEAN"; then
    fail "a page fault occurred during guard-frame churn:"
    grep -A6 "\*\*\* PAGE FAULT \*\*\*" "$CLEAN" | head -20 | sed 's/^/        /'
    info "this is the poisoned-frame signature: a fault on a recycled frame,"
    info "landing on a task unrelated to the one that died."
elif grep -q "Triple fault" "$TRACE" 2>/dev/null; then
    fail "triple fault during the run:"
    grep -E "check_exception|v=0e|v=08|Triple fault|^EIP=|CR2=" "$TRACE" | tail -12 | sed 's/^/        /'
else
    pass "no stray page fault across $CYCLES churn cycles"
fi

# Accounting cross-check. NOT the property under test (see the header) — a
# poisoned frame is freed correctly and balances perfectly. Reported because a
# guard frame that went MISSING is a different bug worth seeing.
FREES=""
while read -r n; do FREES="$FREES $n"; done \
    < <(grep -oE "Free:[[:space:]]+[0-9]+ frames" "$CLEAN" | grep -oE "[0-9]+")
set -- $FREES
if [ $# -ge 2 ]; then
    B="$1"; eval A=\"\$$#\"
    echo "  free frames: $B -> $A (delta $(( B - A )))"
    info "informational only: poisoning does not move this number."
fi
rm -f "$CLEAN"
echo

if [ "$RC" -eq 0 ]; then
    echo "RESULT: PASS"
    echo "  Leg 1 (decisive) holds: every kernel guard free re-maps first."
    echo "  Leg 2 saw no fault. That CORROBORATES; it does not prove — the"
    echo "  poisoned frame must be re-allocated and touched to fault at all."
else
    echo "RESULT: FAIL"
fi
exit "$RC"
