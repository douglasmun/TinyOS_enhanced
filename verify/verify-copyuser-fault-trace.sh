#!/usr/bin/env bash
#
# verify-copyuser-fault-trace.sh -- the copy_*_user() page-fault line in the
# #PF handler is a kdbg TRACE, not a plain kprintf. Source-level, no guest.
#
# WHY THIS MATTERS. page_fault_handler() (src/idt.c) special-cases a fault that
# lands while copy_from_user()/copy_to_user() is active: it returns -EFAULT to
# the caller instead of killing the task. That -EFAULT is the real signal. The
# console line next to it is pure diagnostic -- and it is RING-3-REACHABLE: a
# user task hands a syscall an in-bounds pointer whose page faults on access
# (a genuine present-then-faulting page, since a plain unmapped pointer is
# rejected silently upstream by pae_user_range_accessible() before any
# dereference). A plain kprintf there is a log-spam primitive on the serial
# stream the kernel console and the ring-3 shell share -- the same
# "no per-operation kprintf on a path ring 3 can reach" rule that the SYS_MSEAL
# and RX sweeps enforce. kprintf.h reserves kdbg() for exactly this: a
# per-event trace, not a security verdict (the verdict is the -EFAULT return).
#
# WHY SOURCE-LEVEL. Driving the line needs a present-but-faulting user page
# reached mid-copy -- a TOCTOU window that is closed on this single-CPU kernel
# by the CRITICAL_SECTION the copy primitive holds across validate+copy, so
# there is no deterministic guest input that fires it. The property changed is
# structural (which emitter the line uses), so it is asserted at the source,
# against both the fixed and the pre-fix shape so no leg passes vacuously.
set -u

cd "$(dirname "$0")/.." || exit 2

PASS=0; FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "=== verify-copyuser-fault-trace.sh ==="
echo

# Extract the is_copy_user_active() block from page_fault_handler(): from the
# `if (is_copy_user_active())` line through the handle_copy_user_fault() call.
blk="$(awk '
    /if \(is_copy_user_active\(\)\)/ { f=1 }
    f { print }
    f && /handle_copy_user_fault\(\)/ { exit }
' src/idt.c)"

if [ -z "$blk" ]; then
    bad "could not locate the is_copy_user_active() block in src/idt.c"
    echo "RESULT: FAIL"; exit 1
fi

# 1. The fault line must be emitted with kdbg().
if printf '%s\n' "$blk" | grep -qE 'kdbg\("\[PAGE FAULT\] Caught during copy_\*_user\(\)'; then
    ok "the copy_*_user fault line is emitted with kdbg() (a recoverable trace)"
else
    bad "the copy_*_user fault line is not a kdbg() trace"
    printf '%s\n' "$blk" | sed 's/^/       /'
fi

# 2. NEGATIVE CONTROL: the pre-fix shape used a bare kprintf() for this line.
#    Assert no kprintf() survives inside the block -- otherwise the demotion
#    is only half-done and the log-spam primitive is still live.
if printf '%s\n' "$blk" | grep -qE 'kprintf\('; then
    bad "a kprintf() survives in the copy-user fault block -- the spam path is still live"
    printf '%s\n' "$blk" | grep -nE 'kprintf\(' | sed 's/^/       /'
else
    ok "no kprintf() remains in the copy-user fault block (pre-fix shape is gone)"
fi

# 3. The -EFAULT return (the real signal) is unchanged: handle_copy_user_fault()
#    is still the action the block takes. A demotion that also dropped the
#    recovery call would turn a handled fault into a kill.
if printf '%s\n' "$blk" | grep -qE 'handle_copy_user_fault\(\)'; then
    ok "the block still calls handle_copy_user_fault() (the -EFAULT recovery is intact)"
else
    bad "the block no longer recovers via handle_copy_user_fault()"
fi

echo
echo "================ VERDICT ================"
echo "  passed: $PASS   failed: $FAIL"
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: PASS -- the copy-user fault line is a recoverable kdbg trace, not"
    echo "  a ring-3-reachable kprintf, and the -EFAULT recovery is intact."
    exit 0
else
    echo "RESULT: FAIL"
    exit 1
fi
