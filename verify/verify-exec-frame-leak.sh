#!/usr/bin/env bash
#
# verify-exec-frame-leak.sh — does every process exit leak its ELF image frames?
#
# THE CLAIM. A user process's address space is torn down by
# task_free_resources() (process.c) plus pae_free_user_pdpt() (pae.c). Between
# them they free:
#
#   - the kernel stack pages          (task->stack_pages_phys[])
#   - the user stack pages            (task->user_stack_pages_phys[])
#   - both guard pages                (task->guard_page_phys, user_guard_page_phys)
#   - the EDR state page, the env page
#   - the user PAGE TABLES and the 4 PDs   (pae_free_user_pdpt)
#
# Every one of those is freed from a BOOKKEEPING FIELD on task_t. Nothing walks
# the PTEs to free what they point AT, and `grep image_pages|elf_frames` over
# process.h finds no field tracking the ELF image at all. elf_load_process()
# allocates the segment frames into a `static uint32_t allocated_frames[]`
# local, whose only pmm_free() calls are FAILURE-PATH rollback — on the success
# path that array is simply overwritten by the next exec.
#
# So the frames holding a process's text/rodata/data appear to be leaked on
# every successful exec+exit -- roughly 15 frames a run, per the segment sizes
# below.
#
# WHY MEASURE RATHER THAN READ. A leak argued from code review is a hypothesis:
# the frames could be reclaimed by some path not named in task_free_resources
# (a PT walk inside pae_free_user_pt, a PMM generation sweep, an exec-time
# reuse of the same frames). All of those would show up the same way — as free
# frames NOT dropping. `mem` reports pmm_free_frames() directly, so the kernel
# can be asked instead of guessed.
#
# METHOD. Boot once, then in the KERNEL shell (mem is root-only, and it is a
# machine-state command that is kernel-shell-only by design):
#
#     mem                     <- baseline free-frame count
#     exec /hello.elf   x5    <- five full load/run/exit cycles
#     mem                     <- after
#
# and compare. Five runs rather than one because a single exec's delta is
# indistinguishable from ordinary allocator noise (EDR state pages, audit
# buffers, the ramfs page the ELF is read through); a leak is LINEAR in the run
# count while noise is not.
#
# WHAT THE VERDICT MEANS. This harness DOCUMENTS behaviour; it does not assert
# a fix. It exits 0 in both directions and prints which one it observed, so it
# is useful before and after any repair:
#
#   LEAK CONFIRMED    free frames fell by roughly 5 x image_pages and did not
#                     come back. The teardown does not free image frames.
#   NO LEAK           free frames returned to (or near) baseline. The frames
#                     are reclaimed by a path not visible in task_free_resources
#                     — find it before "fixing" anything.
#
# A THIRD OUTCOME IS THE INTERESTING ONE: if the delta is large but NOT close
# to a multiple of the image size, something else is leaking too, and the
# number is the lead. That is why the raw before/after counts are always
# printed rather than just a pass/fail.
#
# Exit 0 = measurement taken (read the verdict), 2 = harness/setup problem.
# Logs: framelk.log (serial), framelk-trace.log (int/cpu_reset).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
ISO=dist/tinyos.iso
SERIAL=framelk.log
TRACE=framelk-trace.log
MON_SOCK=/tmp/tinyos-framelk-mon.sock

# /hello.elf's LOAD segments, as the loader itself reports them at run time:
#   seg0 vaddr=0x08000000 memsz=0x0bd3 flags=5 (R E) -> 1 page
#   seg1 vaddr=0x08001000 memsz=0x00ad flags=4 (R  ) -> 1 page
#   seg2 vaddr=0x08002000 memsz=0x5004 flags=6 (RW ) -> 6 pages
# = 8 pages of image per exec. Measured leak is 8 frames per exec: exactly the
# image and nothing else. Don't hardcode a different binary's page count here
# -- C:/info.elf is a much larger image and would move the expected figure.
RUNS=5

echo "==> Building kernel + ISO..."
make >/dev/null || { echo "build failed"; exit 2; }
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1 || { echo "mkrescue failed"; exit 2; }

rm -f "$SERIAL" "$TRACE" "$MON_SOCK"

echo "==> Launching headless QEMU (monitor on $MON_SOCK)"
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

# `mem` and `exec` are both KERNEL-shell commands (mem is require_root and
# machine-state, kernel-shell-only by design), so this harness deliberately
# does NOT set TINYOS_STAY_IN_RING3 — the typist's default route to kshell is
# the correct one here. This is the exception to the ring-3 harness rule, not
# a violation of it: the thing under test is the kernel's page teardown, not a
# ring-3 boundary.
#
# Each `exec` is verified on "Process exited" so the next one is not typed
# until the previous process has actually been reaped — otherwise the final
# `mem` could be read while frames are still held by a live task and the
# measurement would understate or overstate at random.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="mem" \
TINYOS_EXPECT="Free:" \
TINYOS_FOLLOWUP_CMDS="\
exec /hello.elf=>Process exited;\
exec /hello.elf=>Process exited;\
exec /hello.elf=>Process exited;\
exec /hello.elf=>Process exited;\
exec /hello.elf=>Process exited;\
mem=>Free:" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: harness problem — no serial output at all (typist rc=$TYPIST_RC)"
    exit 2
fi

if grep -q "Triple fault" "$TRACE" 2>/dev/null; then
    echo "--- $TRACE ---"
    grep -E "check_exception|v=0e|v=08|Triple fault|^EIP=|CR2=" "$TRACE" | tail -15
    echo "RESULT: harness problem — triple fault during the run"
    exit 2
fi

# Pull every "Free:  N frames" line in order. The first is the baseline, the
# last is after the exec cycles.
# NB: no `mapfile` here. macOS ships bash 3.2, where mapfile does not exist;
# combined with `set -u` that made FREES unset and killed the verdict before it
# printed a single line -- i.e. a PASSING kernel looked like a broken harness.
# A plain read loop works on both.
FREES=""
while read -r n; do
    FREES="$FREES $n"
done < <(tr -d '\r' < "$SERIAL" | grep -oE "Free:[[:space:]]+[0-9]+ frames" | grep -oE "[0-9]+")
set -- $FREES
NREAD=$#

if [ "$NREAD" -lt 2 ]; then
    echo "RESULT: harness problem — need two 'Free: N frames' readings, got $NREAD"
    echo "  'mem' is root-only and kernel-shell-only; check the typist reached kshell as root."
    tr -d '\r' < "$SERIAL" | grep -v Suspicious | tail -25
    exit 2
fi

BEFORE="$1"
eval AFTER=\"\$$NREAD\"
DELTA=$(( BEFORE - AFTER ))

# How many execs actually completed? If the typist missed one, the per-run
# figure must be divided by what really ran, not by the number requested.
#
# Count "Process exited" ONLY AFTER the baseline `mem`, not over the whole log.
# The ring-3 login shell exits with status 70 when `kshell` hands over, and
# that exit is printed by the same kprintf -- counting it would inflate the
# divisor and shrink the apparent per-run leak toward zero. Everything before
# the first `mem` reading is pre-baseline by definition.
BASELINE_OFF=$(tr -d '\r' < "$SERIAL" | grep -n "Memory Usage" | head -1 | cut -d: -f1)
COMPLETED=$(tr -d '\r' < "$SERIAL" | tail -n +"${BASELINE_OFF:-1}" | grep -c "Process exited")
[ "$COMPLETED" -eq 0 ] && COMPLETED=1

PER_RUN=$(( DELTA / COMPLETED ))

echo "  free frames before : $BEFORE"
echo "  free frames after  : $AFTER"
echo "  exec cycles completed: $COMPLETED (requested $RUNS)"
echo "  net frames lost    : $DELTA  (~$PER_RUN per exec, ~$(( PER_RUN * 4 )) KB)"
echo ""

if [ "$DELTA" -le 2 ]; then
    echo "RESULT: NO LEAK — free frames returned to baseline."
    echo ""
    echo "  On a FIXED kernel this is the expected result: task_free_resources()"
    echo "  frees task_t::image_pages_phys[], which elf_load_process_argv()"
    echo "  populates on the success path. Exact equality (not merely a smaller"
    echo "  delta) is the point — it says the freed set is precisely the"
    echo "  allocated set, with nothing double-freed and nothing left behind."
    echo ""
    echo "  On a kernel WITHOUT that field, this same result would instead mean"
    echo "  some other path reclaims the image — find it before changing"
    echo "  teardown, because two paths freeing the same frame is worse than"
    echo "  the leak."
elif [ "$PER_RUN" -ge 4 ]; then
    echo "RESULT: LEAK CONFIRMED — ~$PER_RUN frames lost per exec, and they do not come back."
    echo ""
    echo "  /hello.elf's three LOAD segments span exactly 8 pages. Neither"
    echo "  task_free_resources() nor pae_free_user_pdpt() frees the frames a"
    echo "  user PTE points AT — both free only bookkeeping-tracked pages and"
    echo "  the page tables themselves. elf_load_process()'s allocated_frames[]"
    echo "  is a static local whose pmm_free() calls are failure-path rollback."
    echo ""
    echo "  Impact: exec is reachable from ring 3 via SYS_SPAWN, so this is an"
    echo "  unprivileged, repeatable memory-exhaustion primitive, not just an"
    echo "  untidy teardown."
else
    echo "RESULT: INCONCLUSIVE — $DELTA frames lost over $COMPLETED execs (~$PER_RUN each)."
    echo "  Too small to be the ~9-page image, too large to be nothing. Something"
    echo "  else is being retained; the per-run figure is the lead worth chasing."
fi

echo ""
echo "  Serial: $SERIAL"
exit 0
