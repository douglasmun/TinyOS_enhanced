#!/bin/bash
#=============================================================================
# verify-netd-boundary.sh — the ring-3 network boundary
#
# doc/NETDAEMON_DESIGN.md item 4: PR B (SYS_NETRX/SYS_NETTX carry real frames)
# and PR C1 (SYS_NETSTAT answers read-only queries, filtered by socket owner).
#
# Both halves share one boot and one probe binary, so they live in one harness.
# Their polarities are OPPOSITE, which is the thing to keep straight when
# editing: SYS_NETRX/SYS_NETTX are root-only, so an unprivileged -EPERM is the
# pass. SYS_NETSTAT is ownership-gated, so an unprivileged caller must be
# SERVED and what must be empty is the set of sockets it can see. Copying an
# assertion from one half to the other inverts it.
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

#---------------------------------------------------------------------------
# SOURCE GUARD — PR C1 (SYS_NETSTAT)
#
# The read-only query half. Its gate is ownership rather than euid, so the
# checks here are about the PRIMITIVE holding the policy: an owner field that
# tcp_socket actually stamps, and one predicate the syscall consults. A
# SYS_NETSTAT that compiles without those is a read oracle over every user's
# sockets, and the runtime half below would still pass as root.
#---------------------------------------------------------------------------
grep -q "define SYS_NETSTAT" src/syscall.h \
    || guard_fail "src/syscall.h has no SYS_NETSTAT; tree predates PR C1"

NETSTAT_NUM=$(sed -n 's/^#define SYS_NETSTAT *\([0-9][0-9]*\).*/\1/p' src/syscall.h | tail -1)
[ -n "$NETSTAT_NUM" ] \
    || guard_fail "could not read SYS_NETSTAT from src/syscall.h"
[ "$MAXNUM" -ge "$NETSTAT_NUM" ] \
    || guard_fail "MAX_SYSCALL_NUM=$MAXNUM does not cover SYS_NETSTAT=$NETSTAT_NUM;
  the range check rejects it before the dispatcher, so every query returns
  -ENOSYS while the dispatcher case sits there looking correct"

grep -q "case SYS_NETSTAT" src/syscall.c \
    || guard_fail "src/syscall.c has no SYS_NETSTAT dispatcher case"

# The ownership field and the single predicate. Checked in the primitive
# (tcp.c), not in the syscall: a check written only in sys_netstat leaves the
# next caller of tcp_snapshot() ungated, which is the chmod lesson in CLAUDE.md.
grep -q "owner_uid" src/tcp.h \
    || guard_fail "tcp_connection_t has no owner_uid; sockets are unowned and a
  bare sockfd index would let any caller read every other user's connections"
grep -q "conn->owner_uid = tcp_current_owner_uid()" src/tcp.c \
    || guard_fail "tcp_socket() does not stamp owner_uid; the field exists but
  every socket would carry uid 0 and the ownership filter would be inert"
grep -q "bool tcp_owner_visible" src/tcp.c \
    || guard_fail "src/tcp.c has no tcp_owner_visible predicate"

# The predicate must actually COMPARE the owner against the caller. This exact
# check was added because a negative control proved the runtime half cannot
# catch its absence: replacing the comparison with `return true` left every
# call site intact, so all the other source guards passed, the probe printed
# the same two lines, and the harness returned PASS against a build where any
# user could read every socket. With the socket table empty on a stock boot, an
# inert filter and a working one are indistinguishable at runtime -- this line
# is the only thing standing between that regression and a green run.
grep -q "owner_uid == (uint32_t)self->uid" src/tcp.c \
    || guard_fail "tcp_owner_visible() never compares owner_uid to the caller's
  uid. The predicate exists and is called, but it does not discriminate, so
  every socket is visible to every user. NOTE: the runtime half of this
  harness CANNOT catch this -- the TCP table is empty on a stock boot, so an
  inert filter produces byte-identical probe output. Do not weaken this guard."

# tcp_snapshot must consult it. Without this line the struct is filled for any
# sockfd the caller names, and the bitmap below would be the only thing
# filtering -- which a caller can simply ignore by asking for sockets directly.
grep -q "tcp_owner_visible(sockfd)" src/tcp.c \
    || guard_fail "tcp_snapshot() does not call tcp_owner_visible(); the
  per-socket query is unfiltered even though the socket list is filtered"

# The errno must not distinguish "not yours" from "not there".
grep -q "EBADF" src/syscall.c \
    || guard_fail "sys_netstat does not return -EBADF; if a foreign socket
  answers -EPERM while an absent one answers -EBADF, the error code alone
  enumerates other users' live sockets"

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
# The probe embedded in the ISO must be the one that knows about SYS_NETSTAT.
# A stale netprobe.elf still prints PROBE VERDICT, so the check above passes
# while every C1 assertion below silently finds no line to match.
NETSTAT_MARKERS=$(strings "$ISO" | grep -c "PROBE NETSTAT VERDICT")
if [ "$NETSTAT_MARKERS" -eq 0 ]; then
    guard_fail "the embedded netprobe.elf predates PR C1 (no 'PROBE NETSTAT
  VERDICT' string), so the SYS_NETSTAT half would be silently untested"
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

#===========================================================================
# PR C1 — SYS_NETSTAT: the read-only query half
#
# The polarity here is the OPPOSITE of the RX/TX half above, and that is the
# point. Those two are root-only, so an unprivileged -EPERM is the pass. These
# are ownership-gated: an unprivileged caller MUST be served, and what must be
# empty is the set of sockets it can see. A -EPERM here would be a bug.
#===========================================================================
NS_ROOT=$(grep -a "PROBE NETSTAT VERDICT" "$SERIAL" | tr -d '\r' | sed -n '1p')
NS_UNPRIV=$(grep -a "PROBE NETSTAT VERDICT" "$SERIAL" | tr -d '\r' | sed -n '2p')
echo "  netstat verdicts: root='${NS_ROOT:-none}' unpriv='${NS_UNPRIV:-none}'"

case "$NS_ROOT" in
    *ok) ;;
    *) fail_with "root's SYS_NETSTAT verdict was '${NS_ROOT:-none}', expected 'ok'" \
        "The query syscall did not answer correctly for root. Check the" \
        "dispatcher case and MAX_SYSCALL_NUM: a stale bound returns -ENOSYS" \
        "for every subcommand while the code below looks complete." ;;
esac

case "$NS_UNPRIV" in
    *scoped) ;;
    *leaked_mask)
        fail_with "an unprivileged caller could see sockets it does not own" \
            "tcp_socket() stamps owner_uid and tcp_owner_visible() is meant to" \
            "filter on it. A nonzero visible_mask means a bare sockfd index is" \
            "once again a read oracle: peer address, connection state, and" \
            "rx_available as a traffic side channel on another user's session." \
            "This is the finding, not a test failure." ;;
    *leaked_errno*)
        fail_with "a foreign socket answered with an errno other than -EBADF ($NS_UNPRIV)" \
            "The socket is correctly hidden from the listing, but the" \
            "per-socket query distinguishes 'exists but not yours' from" \
            "'does not exist'. That difference alone enumerates the live" \
            "socket table for an unprivileged caller -- the same leak closed" \
            "in cmd_kill and sys_waitpid. Return -EBADF for both." ;;
    *) fail_with "unprivileged SYS_NETSTAT verdict was '${NS_UNPRIV:-none}'" \
            "Expected 'scoped'. Note the polarity: unlike SYS_NETRX/NETTX," \
            "this syscall must SUCCEED for an unprivileged caller and return" \
            "an empty socket set. A refusal here means it was euid-gated by" \
            "mistake, which makes the ring-3 shell unable to see its own" \
            "connections." ;;
esac

# --- The socket bitmap: WHAT THIS DOES AND DOES NOT PROVE ------------------
#
# READ THIS BEFORE STRENGTHENING THE ASSERTION BELOW.
#
# The first version of this harness asserted "unprivileged mask == 0" and
# called that proof of the ownership filter. It is not. Both masks read 0 on
# this boot because the TCP socket table is EMPTY at probe time -- DHCP and DNS
# use raw UDP and never call tcp_socket(), and tcp_tests.c is compiled but
# reachable from no shell command. An unowned, entirely ungated build produces
# exactly the same two lines. That assertion passed against the hypothesis it
# was meant to test, which is the same false pass as the cat-based O_TRUNC
# harness in CLAUDE.md.
#
# Creating a socket from ring 3 needs SYS_NETSTAT's write-side counterpart
# (tcp_socket/connect/close), which is deliberately PR C2 -- this PR adds no
# write surface at all. So the runtime evidence available here is:
#
#   - both masks are 0, consistent with an empty table (asserted below), and
#   - the per-socket query refuses every descriptor identically.
#
# The filter's LOGIC is covered by the source guard above (owner_uid stamped in
# tcp_socket, tcp_owner_visible consulted by tcp_snapshot) and its truth table
# was checked directly: root sees all, a user sees only its own, kernel-owned
# sockets are invisible to non-root. What is NOT covered end-to-end is a live
# foreign socket being hidden from a real unprivileged caller. PR C2 can prove
# that, because it can open one; until then this is stated rather than implied.
NS_MASK_ROOT=$(grep -a "PROBE netstat_socklist" "$SERIAL" | tr -d '\r' \
    | sed -n '1s/.*mask=\(-\{0,1\}[0-9][0-9]*\).*/\1/p')
NS_MASK_UNPRIV=$(grep -a "PROBE netstat_socklist" "$SERIAL" | tr -d '\r' \
    | sed -n '2s/.*mask=\(-\{0,1\}[0-9][0-9]*\).*/\1/p')
echo "  socket bitmaps: root=${NS_MASK_ROOT:-none} unpriv=${NS_MASK_UNPRIV:-none} (table is empty this boot)"

# An unprivileged caller must never see MORE than root. That much is real
# regardless of how many sockets exist, and it is the direction the leak would
# go if the filter were inverted or absent.
if [ -n "$NS_MASK_ROOT" ] && [ -n "$NS_MASK_UNPRIV" ]; then
    if [ "$NS_MASK_UNPRIV" -gt "$NS_MASK_ROOT" ]; then
        fail_with "the unprivileged socket bitmap ($NS_MASK_UNPRIV) exceeds root's ($NS_MASK_ROOT)" \
            "A non-root caller can see sockets root cannot, so the ownership" \
            "comparison is inverted."
    fi
fi
if [ -n "$NS_MASK_UNPRIV" ] && [ "$NS_MASK_UNPRIV" -ne 0 ]; then
    fail_with "the unprivileged socket bitmap was $NS_MASK_UNPRIV, expected 0" \
        "No task-owned socket exists on this boot, so a non-root caller must" \
        "see an empty set. A nonzero value means the filter is reporting" \
        "sockets that either do not exist or belong to the kernel."
fi

# --- Argument validation, from the probe's own lines -----------------------
#
# A wrong-sized buffer must be refused rather than short-filled: a truncated
# copy hands back a struct whose tail is whatever the caller left there, and
# the caller cannot tell. Asserted on the exact errno.
NS_BADLEN=$(grep -a "PROBE netstat_badlen" "$SERIAL" | tr -d '\r' \
    | sed -n '1s/.*rc=\(-\{0,1\}[0-9][0-9]*\).*/\1/p')
if [ "${NS_BADLEN:-0}" != "-22" ]; then
    fail_with "a wrong-sized SYS_NETSTAT buffer returned rc=${NS_BADLEN:-none}, expected -22 (-EINVAL)" \
        "The length must match the subcommand's struct exactly. Accepting a" \
        "short buffer means copying fewer bytes than the caller believes it" \
        "received; accepting a long one means the tail is uninitialised."
fi

NS_BADCMD=$(grep -a "PROBE netstat_badcmd" "$SERIAL" | tr -d '\r' \
    | sed -n '1s/.*rc=\(-\{0,1\}[0-9][0-9]*\).*/\1/p')
if [ "${NS_BADCMD:-0}" != "-22" ]; then
    fail_with "an unknown SYS_NETSTAT subcommand returned rc=${NS_BADCMD:-none}, expected -22 (-EINVAL)" \
        "An unrecognised subcommand must fall through to a default that" \
        "refuses, not to a branch that copies out whatever the staging union" \
        "happens to hold."
fi

# --- Out-of-range and foreign sockets answer identically -------------------
NS_OOB=$(grep -a "PROBE netstat_sock_oob" "$SERIAL" | tr -d '\r' \
    | sed -n '2s/.*rc=\(-\{0,1\}[0-9][0-9]*\).*/\1/p')
NS_SOCK0=$(grep -a "PROBE netstat_sock0" "$SERIAL" | tr -d '\r' \
    | sed -n '2s/.*rc=\(-\{0,1\}[0-9][0-9]*\).*/\1/p')
if [ -n "$NS_OOB" ] && [ -n "$NS_SOCK0" ] && [ "$NS_OOB" != "$NS_SOCK0" ]; then
    fail_with "a nonexistent socket (rc=$NS_OOB) and a foreign one (rc=$NS_SOCK0) gave different errnos" \
        "The two must be indistinguishable. If a live socket owned by another" \
        "user answers differently from one that was never allocated, a caller" \
        "enumerates the socket table through the error code alone -- the same" \
        "leak closed in cmd_kill and sys_waitpid."
fi

# --- No per-call console output on the query path either -------------------
#
# Matched against the probe's OWN lines removed first: netprobe prints
# "PROBE NETSTAT VERDICT" and "PROBE netstat_*" by design, and grepping for a
# bare "netstat" would count those and fail every run regardless of the kernel.
for dead in "sys_netstat" "netstat_query" "NETSTAT:"; do
    HITS=$(grep -av "^PROBE " "$SERIAL" | grep -ca "$dead")
    if [ "$HITS" -ne 0 ]; then
        fail_with "the console printed \"$dead\" $HITS time(s)" \
            "The ring-3 shell will call this once per netstat invocation, and" \
            "CLAUDE.md rules out per-operation prints on any path ring 3" \
            "reaches -- the shell's output and the kernel console are one" \
            "serial stream."
    fi
done

echo ""
echo "RESULT: PASS"
echo "  PR B: root's ring-3 SYS_NETTX crossed the boundary exactly once (tx +1)"
echo "  from a zero baseline, with a short frame refused as -EINVAL; the"
echo "  unprivileged caller was refused with both counters unmoved."
echo "  PR C1: SYS_NETSTAT served the unprivileged caller (not euid-gated) while"
echo "  showing it an empty socket set; wrong lengths and unknown subcommands"
echo "  were refused as -EINVAL, and absent and foreign sockets answered alike."
echo "  Neither path printed to the console."
exit 0
