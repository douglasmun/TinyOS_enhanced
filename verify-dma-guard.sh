#!/usr/bin/env bash
#
# verify-dma-guard.sh — FULLY AUTOMATED check that the e1000 DMA region lives
# in its own page-aligned allocation with UNMAPPED guard pages either side, and
# that the NIC still bus-masters into it correctly.
#
# WHAT THIS IS TESTING
#
# doc/NETWORK_ISOLATION.md item 3. rx_bufs/tx_bufs/rx_ring/tx_ring used to be
# .bss arrays, which put 145 KB of attacker-influenced DMA target immediately
# adjacent to unrelated kernel data, at addresses the linker chose. A
# descriptor-driven overrun corrupted whatever was placed next, silently.
#
# They now sit in one pmm_alloc_contiguous() region with an unmapped guard page
# at each end.
#
# BE HONEST ABOUT WHAT THIS PROVES
#
# It does NOT prove the region is safe from a malicious bus master. Nothing
# short of an IOMMU constrains a NIC that chooses its own target addresses, and
# TinyOS has no IOMMU support -- guard pages are not in such a NIC's way at all.
# What item 3 converts is the realistic case: a length/index bug on our side, or
# a NIC writing past a descriptor it was handed, becomes an immediate page fault
# at the boundary instead of silent corruption of a neighbour. This harness
# asserts that boundary exists and that normal DMA still works across it.
#
# THE ASSERTION IS THREE-SIDED
#
#   PLACEMENT  the four objects are no longer sized in .bss -- checked against
#              the LINKED BINARY with nm, not against the source
#   GUARDS     both guard pages report `unmapped` in ifconfig, which reads the
#              live PTE rather than a "we called unmap" flag
#   FUNCTION   frames still DMA into the relocated buffers and are parsed
#
# Why all three. PLACEMENT alone passes a build that moved the arrays somewhere
# equally exposed. GUARDS alone passes a build where the guards are unmapped but
# the NIC was never repointed -- i.e. the region is guarded and unused, while the
# real buffers sit back in .bss. FUNCTION alone is what the pre-item-3 kernel
# already passed. The interesting failure is the middle one, because it looks
# exactly like success in the ifconfig output.
#
# WHY THE GUARD CHECK READS THE PAGE TABLES RATHER THAN FAULTING ON PURPOSE
#
# The direct test would be to dereference a guard address and confirm a #PF.
# That needs a shell command that reads an arbitrary kernel address, which is a
# kernel-memory read primitive reachable from the shell -- precisely the class
# of command PR #58 gated behind root because together they defeat ASLR. Adding
# one to test a hardening feature would be a poor trade, so ifconfig queries the
# PTE with pae_get_pte() and reports present/absent. That is one inference step
# short of a fault, and this comment is here so nobody later mistakes it for the
# stronger claim.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: dmaguard.log (serial), dmaguard-trace.log.
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=dmaguard.log
TRACE=dmaguard-trace.log
RUN_DISK=/tmp/tinyos-dmaguard-disk.img
MON_SOCK=/tmp/tinyos-dmaguard-mon.sock

FRAME_COUNT=${TINYOS_DMAGUARD_FRAMES:-20}
BAD_ETHERTYPE=0x88b5

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

# ---------------------------------------------------------------------------
# SOURCE GUARD
# ---------------------------------------------------------------------------
grep -q "e1000_dma_region_init" src/e1000.c \
    || guard_fail "src/e1000.c has no e1000_dma_region_init; tree predates item 3"
grep -q "pae_unmap_page(dma_guard_lo)" src/e1000.c \
    || guard_fail "src/e1000.c never unmaps the low guard page"
grep -q "pae_unmap_page(dma_guard_hi)" src/e1000.c \
    || guard_fail "src/e1000.c never unmaps the high guard page"

# TDLEN/RDLEN must be computed from the element count. This caught a real bug
# while item 3 was being written: with the rings converted from arrays to
# pointers, the original `sizeof(tx_ring)` silently became 4, which would have
# told the NIC its descriptor ring was one dword long. The build stayed clean
# and the source still read plausibly, so it is asserted here permanently.
if grep -qE "E1000_(TDLEN|RDLEN) / 4\] = sizeof\((tx|rx)_ring\)" src/e1000.c; then
    guard_fail "TDLEN/RDLEN still use sizeof(ring), which is now a POINTER (4
  bytes). The NIC would be told the descriptor ring is one dword long."
fi

command -v python3 >/dev/null 2>&1 || guard_fail "python3 not found"
command -v i686-elf-nm >/dev/null 2>&1 || guard_fail "i686-elf-nm not found"
[ -f tools/inject_frames.py ] || guard_fail "tools/inject_frames.py is missing"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || exit 1

# ---------------------------------------------------------------------------
# PLACEMENT: assert against the LINKED BINARY, not the source.
#
# Per harness-design-principles: verify the artifact. A source grep would pass
# on a tree where the declarations changed but something else reintroduced a
# large .bss buffer. nm reports the actual symbol sizes the linker emitted.
#
# Post-item-3 these four symbols are POINTERS (4 bytes each). Anything larger
# means an array is still being reserved in .bss.
# ---------------------------------------------------------------------------
echo "==> Checking DMA symbol placement in the linked kernel..."
PLACEMENT_FAIL=0
for sym in rx_bufs tx_bufs rx_ring tx_ring; do
    # nm -S prints "<addr> <size> <type> <name>", both hex. Converted with
    # printf rather than awk's strtonum, which is a gawk extension and is
    # absent from the macOS awk this repo is developed on.
    SIZE_HEX=$(i686-elf-nm -S kernel.elf 2>/dev/null \
               | awk -v s="$sym" '$4 == s { print $2 }' | head -1)
    SIZE=""
    [ -n "$SIZE_HEX" ] && SIZE=$((16#$SIZE_HEX))
    if [ -z "$SIZE" ]; then
        guard_fail "symbol '$sym' not found in kernel.elf; this harness has gone
  stale and would silently stop checking placement"
    fi
    echo "  $sym: $SIZE bytes"
    if [ "$SIZE" -gt 8 ]; then
        echo "  ^^ still a bulk .bss array, not a pointer into the DMA region"
        PLACEMENT_FAIL=1
    fi
done
if [ "$PLACEMENT_FAIL" -ne 0 ]; then
    echo "RESULT: FAIL — DMA buffers are still reserved in .bss"
    exit 1
fi

cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

ISO_MARKERS=$(strings "$ISO" | grep -c "DMA guards")
if [ "$ISO_MARKERS" -eq 0 ]; then
    guard_fail "the ISO predates item 3 (ifconfig has no DMA guard line), so the
  run would measure a kernel with no guard reporting at all"
fi

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

QEMU_MCAST=230.0.0.3:1236

echo "==> Launching headless QEMU (monitor $MON_SOCK, mcast socket $QEMU_MCAST)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev socket,id=net0,mcast="$QEMU_MCAST" \
    -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

export TINYOS_HOOK_BADETH="sleep 2; python3 tools/inject_frames.py \
    --mcast '$QEMU_MCAST' --count $FRAME_COUNT --ethertype $BAD_ETHERTYPE \
    --dst 52:54:00:12:34:56 >/dev/null 2>&1; sleep 5; true"

TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="DMA guards" \
TINYOS_FOLLOWUP_CMDS="\
>BADETH;\
ifconfig=>DMA guards" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"

[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    echo "  --- last 40 serial lines ---"
    tail -40 "$SERIAL"
    exit 1
}

# --- The region was actually allocated ------------------------------------
if ! grep -qa "\[E1000\] DMA region:" "$SERIAL"; then
    fail_with "the kernel never announced a DMA region allocation" \
        "e1000_dma_region_init() did not run, or pmm_alloc_contiguous failed."
fi
grep -a "\[E1000\] DMA region:" "$SERIAL" | head -1 | sed 's/^/  /'

# --- GUARDS: both must read `unmapped` at every ifconfig ------------------
GUARD_LINES=$(grep -ac "DMA guards:" "$SERIAL")
if [ "$GUARD_LINES" -lt 2 ]; then
    fail_with "expected 2 ifconfig readings, got $GUARD_LINES" \
        "The command sequence did not complete."
fi
grep -a "DMA guards:" "$SERIAL" | sed 's/^/  /'

# "MAPPED(!)" is what ifconfig prints when a guard PTE is present.
MAPPED_HITS=$(grep -a "DMA guards:" "$SERIAL" | grep -c "MAPPED(!)")
if [ "$MAPPED_HITS" -ne 0 ]; then
    fail_with "a guard page is PRESENT in $MAPPED_HITS reading(s)" \
        "The guard pages are mapped, so an overrun off the end of the DMA" \
        "region corrupts whatever physical memory follows it instead of" \
        "faulting. Either pae_unmap_page was not called, or something" \
        "remapped the address afterwards."
fi

UNMAPPED_HITS=$(grep -a "DMA guards:" "$SERIAL" | grep -c "unmapped, .*unmapped")
if [ "$UNMAPPED_HITS" -ne "$GUARD_LINES" ]; then
    fail_with "only $UNMAPPED_HITS of $GUARD_LINES readings show BOTH guards unmapped" \
        "One end of the region is unguarded. Check that both dma_guard_lo and" \
        "dma_guard_hi are unmapped, not just one."
fi

# --- FUNCTION: the NIC still DMAs into the relocated buffers --------------
#
# Without this the harness would pass on a kernel whose guarded region is
# never used -- guards intact, real buffers still in .bss, NIC never repointed.
THREAD_LIST=$(grep -a "irq-ctx" "$SERIAL" \
              | sed -n 's/.*  *\([0-9][0-9]*\) thread-ctx.*/\1/p')
TB=$(printf '%s\n' "$THREAD_LIST" | sed -n '1p')
TA=$(printf '%s\n' "$THREAD_LIST" | sed -n '2p')
if [ -z "$TB" ] || [ -z "$TA" ]; then
    fail_with "could not read the parse counters, so DMA function is unverified" \
        "This harness requires the item 1 'RX parsed' line to confirm frames" \
        "actually landed in the relocated buffers."
fi
DELTA=$((TA - TB))
echo "  frames parsed: before=$TB after=$TA delta=$DELTA (injected $FRAME_COUNT)"
if [ "$DELTA" -lt "$FRAME_COUNT" ]; then
    fail_with "only $DELTA of $FRAME_COUNT frames were received" \
        "The NIC is not DMAing correctly into the relocated buffers. A wrong" \
        "RDBAL/RDLEN, or descriptors pointing at the old .bss addresses, look" \
        "exactly like this."
fi

# --- No fault was taken during the run ------------------------------------
for bad in "PAGE FAULT" "TRIPLE FAULT" "PANIC"; do
    if grep -qa "$bad" "$SERIAL"; then
        fail_with "the kernel reported \"$bad\" during the run" \
            "The guarded region is faulting in normal operation, which means" \
            "the payload is overrunning into a guard rather than being" \
            "contained by it."
    fi
done

echo "RESULT: PASS"
echo "  DMA buffers are out of .bss, both guard pages are unmapped, and"
echo "  $DELTA frames DMA'd through the relocated region without a fault."
exit 0

# =============================================================================
# VALIDATION LOG — validated BOTH WAYS on 2026-08-16
#
# RUN 0 (item 3 present, first attempt) -> INCONCLUSIVE, harness bug
#   awk's strtonum() is a gawk extension and does not exist in the macOS awk
#   this repo is developed on, so every symbol size came back empty. The
#   staleness check caught it correctly ("symbol 'rx_bufs' not found ... this
#   harness has gone stale") rather than silently skipping the placement
#   assertion, which is exactly why that check is there. Hex conversion now
#   uses $((16#...)).
#
# RUN 1 (item 3 present) -> PASS
#   DMA region: 148 KB at 0x00357000, guards 0x00356000 / 0x0037c000.
#   Both guards unmapped at both readings; rx_bufs/tx_bufs/rx_ring/tx_ring all
#   4 bytes in the linked kernel (pointers, not arrays); 20/20 frames DMA'd
#   through the relocated region with no fault.
#
# RUN 2 (negative control: both pae_unmap_page calls removed, region still
#        allocated and used, source guard bypassed) -> FAIL, as required:
#   "a guard page is PRESENT in 2 reading(s)"
#   with ifconfig showing `0x00356000 MAPPED(!), 0x0037c000 MAPPED(!)`.
#
#   Note what this control deliberately leaves working: the region is still
#   carved out of the PMM, still page-aligned, still away from .bss, and the
#   NIC still DMAs into it correctly (the PLACEMENT and FUNCTION halves both
#   pass). Only the guards are gone. A harness asserting "the buffers moved"
#   would have PASSED this build, and the ifconfig output would still have
#   looked healthy at a glance -- the guard addresses are printed either way,
#   and only the mapping state distinguishes them.
#
# NOT proven, by design (stated in the header): that touching a guard address
# actually faults. ifconfig reads the PTE via pae_get_pte() rather than
# dereferencing, because a shell command that reads arbitrary kernel addresses
# is a read primitive of the sort PR #58 gated behind root. This is one
# inference step short of a demonstrated #PF.
# =============================================================================
