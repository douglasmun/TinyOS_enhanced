#!/bin/bash
#=============================================================================
# verify-netd-boundary.sh — SYS_NETRX / SYS_NETTX carry real frames
#
# doc/NETDAEMON_DESIGN.md item 4, PR B.
#
# WHAT THIS PROVES, AND WHY THE OBVIOUS TEST WOULD NOT
#
# PR B adds the two packet-path syscalls but does NOT move the parser to ring 3.
# So on a stock boot nothing calls them and both counters read zero, while
# networking works perfectly — which is exactly what a build with the boundary
# bypassed, or with the dispatcher cases missing entirely, also shows. "Ping
# still works" cannot distinguish those, so this harness does not test it.
#
# Instead it runs /netprobe.elf, a ring-3 program that goes straight to int 0x80,
# and asserts on the syscall-boundary counters surfaced by `ifconfig`:
#
#   POSITIVE  as root: netprobe transmits one 60-byte frame; the netd tx-frames
#             counter must advance by exactly 1. Exactly, not "> 0" — an
#             increment placed per-interrupt or per-retry rather than per-call
#             is the failure this catches, and it is invisible to any
#             presence check.
#
#   NEGATIVE  as an unprivileged user: BOTH calls must be refused with -EPERM
#             and BOTH counters must be unmoved. Raw TX forges any source MAC
#             or IP it likes (ARP poisoning, DHCP spoofing) and raw RX hands
#             over traffic addressed to every other service on the host, so the
#             gate is the entire reason these syscalls are safe to add at all.
#             A counter that moves here is a worse outcome than one that never
#             moves: it means the boundary works AND it is open to everyone.
#
# The two halves run in ONE boot, root first then `su`, so the unprivileged
# reading is taken against a kernel that has just been shown to count properly.
# Split across two runs, a zero in the second half would be indistinguishable
# from a build where the counters never work.
#
# Argument validation is asserted from the probe's own PROBE lines rather than
# from a counter, because a rejected call must leave no trace in the counters
# by definition — the assertion is that nothing happened, plus the exact errno.
#
# The probe's frame is EtherType 0x88B5 (IEEE local-experimental) to a broadcast
# destination from a locally-administered source MAC: it leaves the NIC and is
# ignored by every listener, so the run cannot perturb ARP or DHCP state.
#
# Usage: ./verify-netd-boundary.sh
# Exit:  0 PASS   1 FAIL   2 no serial output   3 INCONCLUSIVE (guard)
#=============================================================================
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
TESTUSER=netuser
TESTPASS=netpass1

ISO=dist/tinyos.iso
SERIAL=netdb.log
RUN_DISK=/tmp/tinyos-netdb-disk.img
MON_SOCK=/tmp/tinyos-netdb-mon.sock

PROBE_FRAME_LEN=60

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

#---------------------------------------------------------------------------
# SOURCE GUARD
#
# Shape of the change, not merely that files moved. Each piece alone passes
# against a tree that cannot work: syscall numbers without dispatcher cases are
# -ENOSYS, a dispatcher case with MAX_SYSCALL_NUM left behind is rejected by the
# range check before it is reached (the exact bug that silently disabled
# SYS_SLEEP and SYS_WAITPID — see CLAUDE.md), and counters with no probe to
# drive them can only ever read zero.
#---------------------------------------------------------------------------
grep -q "define SYS_NETRX" src/syscall.h \
    || guard_fail "src/syscall.h has no SYS_NETRX; tree predates PR B"
grep -q "define SYS_NETTX" src/syscall.h \
    || guard_fail "src/syscall.h has no SYS_NETTX; tree predates PR B"

# MAX_SYSCALL_NUM must actually cover SYS_NETTX. Compared numerically, not by
# eye: this is the range check every syscall passes through first, and when it
# is stale the dispatcher case below is simply unreachable.
MAXNUM=$(sed -n 's/^#define MAX_SYSCALL_NUM *\([0-9][0-9]*\).*/\1/p' src/syscall.h | tail -1)
NETTX=$(sed -n 's/^#define SYS_NETTX *\([0-9][0-9]*\).*/\1/p' src/syscall.h | tail -1)
[ -n "$MAXNUM" ] && [ -n "$NETTX" ] \
    || guard_fail "could not read MAX_SYSCALL_NUM / SYS_NETTX from src/syscall.h"
[ "$MAXNUM" -ge "$NETTX" ] \
    || guard_fail "MAX_SYSCALL_NUM=$MAXNUM does not cover SYS_NETTX=$NETTX;
  the range check rejects both new syscalls before the dispatcher sees them,
  so every call would return -ENOSYS with the dispatcher cases present"

grep -q "case SYS_NETRX" src/syscall.c \
    || guard_fail "src/syscall.c has no SYS_NETRX dispatcher case"
grep -q "case SYS_NETTX" src/syscall.c \
    || guard_fail "src/syscall.c has no SYS_NETTX dispatcher case"
grep -q "e1000_rx_dequeue" src/e1000.c \
    || guard_fail "src/e1000.c has no e1000_rx_dequeue; RX has no way to leave the ring"
grep -q "net_get_syscall_stats" src/shell_network.c \
    || guard_fail "ifconfig does not report the netd syscall counters"
[ -f userspace/netprobe.c ] \
    || guard_fail "userspace/netprobe.c is missing; nothing can drive the boundary"

# The gate itself. Without an euid check these syscalls are a privilege
# escalation dressed as a feature, and the negative half below would pass
# trivially against a kernel that simply never wired the counters.
grep -q "euid != 0" src/syscall.c \
    || guard_fail "src/syscall.c has no euid check at all; the root-only gate is absent"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1

# Re-sign and re-embed BOTH the shell and the probe every run. The probe is the
# entire instrument here: a stale netprobe.elf would exercise the previous
# boundary while the source guard above reported on the new one.
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
python3 tools/sign_elf.py userspace/netprobe.elf userspace/netprobe.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/netprobe.elf.signed \
        src/netprobe_elf_data.c src/netprobe_elf_data.h netprobe_elf_data >/dev/null || exit 1

make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# The ARTIFACT must carry this build, not just the source tree. grep -c, not
# grep -q: under pipefail grep -q SIGPIPEs `strings` and the guard fires on a
# FRESH ISO.
ISO_MARKERS=$(strings "$ISO" | grep -c "netd sysc")
if [ "$ISO_MARKERS" -eq 0 ]; then
    guard_fail "the ISO predates PR B (ifconfig's 'netd sysc' line is absent),
  so the run would measure a kernel with no syscall counters at all"
fi
PROBE_MARKERS=$(strings "$ISO" | grep -c "PROBE VERDICT")
if [ "$PROBE_MARKERS" -eq 0 ]; then
    guard_fail "the ISO does not contain netprobe.elf; nothing would drive the
  boundary and both counters would read zero for the wrong reason"
fi

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

echo "==> Launching headless QEMU (monitor $MON_SOCK)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -display none &
QEMU_PID=$!
cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# One boot, both halves.
#
#   ifconfig            BASELINE          (reading 1)
#   exec /netprobe.elf  as root
#   ifconfig            AFTER ROOT        (reading 2)
#   su netuser
#   exec /netprobe.elf  unprivileged
#   ifconfig            AFTER UNPRIV      (reading 3)
#
# NO `kshell` line here, and TINYOS_STAY_IN_RING3 is deliberately left unset.
# The typist ALREADY types `kshell` for you unless that variable is 1, so this
# sequence starts in the kernel shell -- which is where it needs to be, since
# `ifconfig`, `exec` and `su` are all kernel-shell commands.
#
# The first version of this harness typed `kshell` itself and hung: the typist
# had already switched, the kernel shell has no `kshell` builtin, and the run
# sat at "Unknown command: kshell" until it timed out. The failure looked like a
# boundary problem rather than a script problem, because the counters it prints
# never appeared.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=900 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
useradd $TESTUSER=>Enter password for new user;\
!$TESTPASS=>created;\
ifconfig=>netd sysc;\
exec /netprobe.elf=>PROBE VERDICT;\
ifconfig=>netd sysc;\
su $TESTUSER=>Now running as;\
!id=>uid=;\
!exec /netprobe.elf=>PROBE VERDICT;\
!ifconfig=>netd sysc" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup
trap - EXIT

echo ""
echo "================ VERDICT ================"

[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    echo "  --- last 50 serial lines ---"
    tail -50 "$SERIAL" | tr -d '\r'
    exit 1
}

# --- Extract the syscall counters, in order --------------------------------
#
# The ifconfig line reads:
#   netd sysc:    0 rx-frames, 0 tx-frames
# Anchored on each field NAME so a counter added alongside does not shift what
# this reads.
extract() { grep -a "netd sysc:" "$SERIAL" | sed -n "s/.*[ ,]\([0-9][0-9]*\) $1.*/\1/p"; }

TX_LIST=$(extract "tx-frames")
RX_LIST=$(extract "rx-frames")
READINGS=$(printf '%s\n' "$TX_LIST" | grep -c '[0-9]')

if [ "$READINGS" -lt 3 ]; then
    fail_with "expected 3 ifconfig readings, got $READINGS" \
        "The command sequence did not complete, so there is no baseline or no" \
        "unprivileged reading. Readings seen: ${TX_LIST:-none}"
fi

TX_B=$(printf '%s\n' "$TX_LIST" | sed -n '1p')
TX_R=$(printf '%s\n' "$TX_LIST" | sed -n '2p')
TX_U=$(printf '%s\n' "$TX_LIST" | sed -n '3p')
RX_B=$(printf '%s\n' "$RX_LIST" | sed -n '1p')
RX_R=$(printf '%s\n' "$RX_LIST" | sed -n '2p')
RX_U=$(printf '%s\n' "$RX_LIST" | sed -n '3p')

TX_ROOT_D=$((TX_R - TX_B))
TX_UNPRIV_D=$((TX_U - TX_R))
RX_UNPRIV_D=$((RX_U - RX_R))

echo "  tx-frames:  baseline=$TX_B  after-root=$TX_R  after-unpriv=$TX_U"
echo "  rx-frames:  baseline=$RX_B  after-root=$RX_R  after-unpriv=$RX_U"
echo "  deltas:     root tx=+$TX_ROOT_D   unpriv tx=+$TX_UNPRIV_D  unpriv rx=+$RX_UNPRIV_D"

# --- BASELINE: the boundary is genuinely unused before the probe runs ------
#
# PR B does not move the parser, so nothing in the kernel may be calling these.
# A nonzero baseline would mean the counters are being driven by something
# other than the probe, and every delta below would be measuring that instead.
if [ "$TX_B" -ne 0 ] || [ "$RX_B" -ne 0 ]; then
    fail_with "the syscall counters are nonzero before netprobe ran (tx=$TX_B rx=$RX_B)" \
        "PR B adds the boundary but does not route the in-kernel parser through" \
        "it, so nothing should reach these syscalls until a ring-3 caller does." \
        "A nonzero baseline means the deltas below measure something else."
fi

# --- POSITIVE: root's transmit crossed the boundary, exactly once ----------
if [ "$TX_ROOT_D" -eq 0 ]; then
    fail_with "netprobe's transmit did not move the tx-frames counter" \
        "Either the dispatcher never reached sys_nettx (check MAX_SYSCALL_NUM" \
        "and the case labels), or the counter is not incremented on the" \
        "success path. Networking working is not evidence here: nothing else" \
        "in this kernel calls these syscalls."
fi
if [ "$TX_ROOT_D" -ne 1 ]; then
    fail_with "tx-frames advanced by $TX_ROOT_D, expected exactly 1" \
        "netprobe makes exactly one successful SYS_NETTX call (a second one is" \
        "deliberately too short and must be rejected before the counter). An" \
        "inexact count means the increment is not once-per-successful-call," \
        "which under-reports or double-counts precisely under the burst load" \
        "the daemon will generate."
fi

# --- The probe's own verdicts ----------------------------------------------
#
# Read from the probe rather than the counters because a REFUSED call must by
# definition leave the counters untouched — "nothing moved" is the same
# observation as "the syscall does not exist", and only the errno separates
# them.
ROOT_VERDICT=$(grep -a "PROBE VERDICT" "$SERIAL" | tr -d '\r' | sed -n '1p')
UNPRIV_VERDICT=$(grep -a "PROBE VERDICT" "$SERIAL" | tr -d '\r' | sed -n '2p')
echo "  probe verdicts: root='${ROOT_VERDICT:-none}' unpriv='${UNPRIV_VERDICT:-none}'"

case "$ROOT_VERDICT" in
    *ok) ;;
    *) fail_with "root's netprobe verdict was '${ROOT_VERDICT:-none}', expected 'ok'" \
        "It asserts SYS_NETTX returned exactly $PROBE_FRAME_LEN (the frame length) and that" \
        "a 4-byte frame was refused with -EINVAL rather than padded. A frame" \
        "silently shortened or lengthened at the boundary is a corrupt frame" \
        "on the wire that the caller has no way to detect." ;;
esac

# --- NEGATIVE: unprivileged is refused, and moves nothing ------------------
case "$UNPRIV_VERDICT" in
    *denied) ;;
    *leaked)
        fail_with "the unprivileged netprobe was NOT refused" \
            "Raw frame access from ring 3 without a privilege check is ARP" \
            "poisoning and DHCP spoofing available to any local account, plus" \
            "read access to traffic addressed to every other service on the" \
            "host. This is the finding, not a test failure." ;;
    *) fail_with "unprivileged netprobe verdict was '${UNPRIV_VERDICT:-none}'" \
            "Expected 'denied'. Without a second verdict line the unprivileged" \
            "half did not run, so the gate is untested — the zero deltas below" \
            "would then prove nothing." ;;
esac

if [ "$TX_UNPRIV_D" -ne 0 ] || [ "$RX_UNPRIV_D" -ne 0 ]; then
    fail_with "the unprivileged probe moved the counters (tx=+$TX_UNPRIV_D rx=+$RX_UNPRIV_D)" \
        "The euid check must reject before any frame is copied or sent. A" \
        "counter that advances here means the refusal happens after the work," \
        "or does not happen at all."
fi

# --- NEGATIVE: no per-call console output on the new path ------------------
#
# These syscalls are reachable from ring 3, and PR D will have the daemon
# calling them once per frame. A kprintf on either is the RX-path flood
# reintroduced one layer up (CLAUDE.md's rule).
for dead in "sys_netrx" "sys_nettx" "NETRX" "NETTX"; do
    HITS=$(grep -ca "$dead" "$SERIAL")
    if [ "$HITS" -ne 0 ]; then
        fail_with "the console printed \"$dead\" $HITS time(s)" \
            "A per-call print on a path ring 3 reaches is the flood these" \
            "counters exist to replace, and the daemon will call it once per" \
            "frame at a remote host's chosen rate."
    fi
done

echo ""
echo "RESULT: PASS"
echo "  Root's ring-3 SYS_NETTX crossed the boundary exactly once (tx +1) from a"
echo "  zero baseline, with a short frame refused as -EINVAL; the unprivileged"
echo "  caller was refused with both counters unmoved, and neither syscall"
echo "  printed to the console."
exit 0
