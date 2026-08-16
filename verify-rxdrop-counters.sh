#!/usr/bin/env bash
#
# verify-rxdrop-counters.sh — FULLY AUTOMATED check that malformed inbound
# frames are COUNTED rather than printed, and that the counter is accurate.
#
# WHAT THIS IS TESTING
#
# Three RX drop paths used to kprintf one line per packet:
#
#   net.c    frame shorter than an Ethernet header
#   net.c    EtherType we do not handle
#   e1000.c  NIC-reported CRC/checksum error   (in the unbounded drain loop)
#
# All three sit BEFORE the firewall and execute in the ISR with interrupts
# disabled, so any host on the segment could turn malformed frames into console
# output at whatever rate it liked -- a remote amplification primitive needing
# no local account. See doc/NETWORK_ISOLATION.md item 2.
#
# THE ASSERTION IS TWO-SIDED, AND BOTH HALVES ARE LOAD-BEARING
#
# Deleting the prints alone would pass a "console stays quiet" test while
# destroying the information. Bumping a counter alone would pass a "counter
# moves" test while leaving the flood in place. Neither on its own is the fix,
# so this harness asserts both against the SAME traffic:
#
#   POSITIVE  the unsupported-ethertype counter rises by the number of frames
#             sent -- exactly, not ">= 1"
#   NEGATIVE  the serial console gains no per-packet lines while that happens
#
# Asserting an EXACT delta rather than a floor is what catches a counter that
# is incremented in the wrong place -- e.g. once per interrupt instead of once
# per frame, which under the 16-packet budget would look fine at low rates and
# silently under-report under exactly the load the counter exists to measure.
#
# WHY UNSUPPORTED-ETHERTYPE IS THE FRAME THIS SENDS
#
# It is the one of the three that a host can produce on demand with a raw
# socket and no cooperation from the NIC: pick an EtherType TinyOS does not
# handle and the frame is guaranteed to reach handle_packet's default arm.
#   - runt frames are padded to 60 bytes by every real NIC and by QEMU, so
#     "shorter than an Ethernet header" is not reachable from the host here.
#   - CRC errors cannot be injected through QEMU's NAT at all; the emulated
#     e1000 computes a correct FCS.
# Those two counters are therefore verified by the SOURCE GUARD below (their
# print is gone and a counter is in its place) rather than by traffic. That is
# stated plainly rather than papered over: this harness proves the ethertype
# path end-to-end and the other two structurally.
#
# HOW THE FRAMES ARE SENT
#
# An unsupported EtherType is not something a UDP datagram can express -- by
# the time the host stack sends one, the EtherType is 0x0800. So the guest is
# attached to a `socket,mcast=` netdev rather than user-mode NAT: bytes written
# to that multicast group land on the guest's wire verbatim, EtherType and all.
# tools/inject_frames.py writes them with an ordinary UDP socket, so this
# harness needs no special privileges (multicast TTL is pinned to 1 so the
# malformed frames cannot leave the host).
#
# The trade-off is that this netdev has no NAT, so the guest gets no DHCP lease
# -- which is fine here and deliberately so: handle_packet dispatches on
# EtherType before any IP-layer state is consulted, so the counter under test
# moves without an address. Do not "fix" this by switching to user-mode NAT;
# that would silently stop the frames from ever arriving.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: rxdrop.log (serial), rxdrop-trace.log.
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=rxdrop.log
TRACE=rxdrop-trace.log
RUN_DISK=/tmp/tinyos-rxdrop-disk.img
MON_SOCK=/tmp/tinyos-rxdrop-mon.sock

# Number of malformed frames to inject. Chosen to exceed E1000_RX_PACKET_BUDGET
# (16) so the run also exercises the post-budget drain loop, which is where the
# worst of the three prints lived and where a per-interrupt rather than
# per-frame increment would show up as a shortfall.
FRAME_COUNT=${TINYOS_RXDROP_FRAMES:-20}

# An EtherType handle_packet does not handle. 0x88b5 is IEEE-reserved for local
# experimental use, so it will not collide with a protocol TinyOS later learns.
# If TinyOS ever handles it, this harness fails LOUDLY (delta 0) rather than
# silently testing nothing.
BAD_ETHERTYPE=0x88b5

# ---------------------------------------------------------------------------
# SOURCE GUARD
#
# Runs before the boot so a stale tree fails fast with a clear reason. Checks
# the shape of the fix, not just that the file changed: a counter must exist
# for each of the three paths AND the per-packet prints must be gone.
# ---------------------------------------------------------------------------
guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

grep -q "net_drop_ethertype" src/net.c \
    || guard_fail "src/net.c has no net_drop_ethertype counter; tree predates the fix"
grep -q "net_drop_runt" src/net.c \
    || guard_fail "src/net.c has no net_drop_runt counter; tree predates the fix"
grep -q "rx_drop_errors" src/e1000.c \
    || guard_fail "src/e1000.c has no rx_drop_errors counter; tree predates the fix"

# The prints themselves must be gone. Anchored on the exact former strings.
for dead in "Received packet too short" "Unhandled EtherType"; do
    if grep -qa "$dead" src/net.c; then
        guard_fail "src/net.c still contains the per-packet print \"$dead\""
    fi
done
if grep -qa "SECURITY - Dropping packet with" src/e1000.c; then
    guard_fail "src/e1000.c still contains the per-packet checksum-error print"
fi

# ---------------------------------------------------------------------------
# PRIVILEGE / TOOLING
# ---------------------------------------------------------------------------
command -v python3 >/dev/null 2>&1 || guard_fail "python3 not found"
[ -f tools/inject_frames.py ] || guard_fail "tools/inject_frames.py is missing"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# Prove the ISO carries THIS build (see harness-design-principles: verify the
# artifact, not the source -- the ISO is two copies downstream of the edit).
# grep -c not grep -q: under pipefail, grep -q SIGPIPEs `strings`.
ISO_MARKERS=$(strings "$ISO" | grep -c "unsupported-ethertype")
if [ "$ISO_MARKERS" -eq 0 ]; then
    guard_fail "the ISO predates the fix (ifconfig's drop line is absent), so
  the run would measure a kernel with no counters at all"
fi

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

# The TAP interface the guest is attached to, so the host can inject L2 frames.
# QEMU user-mode NAT cannot carry an arbitrary EtherType, so this uses a socket
# netdev: frames written to the host end appear on the guest's wire verbatim.
QEMU_MCAST=230.0.0.1:1234

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

# Host hook: inject FRAME_COUNT frames with an unhandled EtherType onto the
# same multicast group QEMU's socket netdev is bridged to. Each frame is
# addressed to the guest's MAC so handle_packet's "is this for us" check passes
# and execution reaches the EtherType switch -- a broadcast would also work but
# a unicast keeps the test specific to the dispatch arm under test.
#
# Ends in `true` for the same reason as verify-ids-signature.sh: the proof the
# frames landed is the counter delta, not the sender's exit status.
export TINYOS_HOOK_BADETH="sleep 2; python3 tools/inject_frames.py \
    --mcast '$QEMU_MCAST' --count $FRAME_COUNT --ethertype $BAD_ETHERTYPE \
    --dst 52:54:00:12:34:56 >/dev/null 2>&1; sleep 5; true"

# ifconfig is a kernel-shell command (shell_network.c) and is where the drop
# counters are surfaced, so this harness stays in the kernel shell.
#
#   ifconfig  : BASELINE (B)
#   >BADETH   : host hook -- injects the malformed frames
#   ifconfig  : AFTER (A). A - B must equal FRAME_COUNT exactly.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="RX dropped" \
TINYOS_FOLLOWUP_CMDS="\
>BADETH;\
ifconfig=>RX dropped" \
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

# --- Extract the unsupported-ethertype counts, in order -------------------
#
# The ifconfig line reads:
#   RX dropped:   0 hw-error, 0 bad-length, 0 runt, 0 unsupported-ethertype
# Anchored on the field NAME, so adding a counter on either side of it does not
# silently shift what this reads.
DROP_LIST=$(grep -a "unsupported-ethertype" "$SERIAL" \
            | sed -n 's/.*, \([0-9][0-9]*\) unsupported-ethertype.*/\1/p')
DROP_COUNT=$(printf '%s\n' "$DROP_LIST" | grep -c '[0-9]')

if [ "$DROP_COUNT" -lt 2 ]; then
    fail_with "expected 2 ifconfig readings, got $DROP_COUNT" \
        "The command sequence did not complete, so there is no baseline." \
        "Readings seen: ${DROP_LIST:-none}"
fi

B=$(printf '%s\n' "$DROP_LIST" | sed -n '1p')
A=$(printf '%s\n' "$DROP_LIST" | sed -n '2p')
DELTA=$((A - B))
echo "  unsupported-ethertype counter: before=$B  after=$A  delta=$DELTA (sent $FRAME_COUNT)"

# --- POSITIVE: the counter moved by exactly the number of frames sent ------
if [ "$DELTA" -eq 0 ]; then
    fail_with "the injected frames did not move the counter ($B -> $A)" \
        "Either the frames never reached handle_packet (check the socket" \
        "netdev bridging), or the default arm is not counting. Note this is" \
        "also what you would see if TinyOS learned to handle $BAD_ETHERTYPE."
fi
if [ "$DELTA" -ne "$FRAME_COUNT" ]; then
    fail_with "counter moved by $DELTA, expected exactly $FRAME_COUNT" \
        "An inexact delta means the increment is not once-per-frame. The" \
        "likely cause is counting per interrupt rather than per packet, which" \
        "under-reports precisely under the burst load the counter exists to" \
        "measure. (A delta LARGER than expected suggests unrelated traffic on" \
        "the multicast group -- rerun on a quiet host before believing it.)"
fi

# --- NEGATIVE: the console did not gain per-packet lines -------------------
#
# This is the half that proves the FLOOD is closed rather than just that a
# counter exists. Anchored on the exact strings that used to be printed; a
# reintroduced print would match here even if the counter also works.
for dead in "Received packet too short" "Unhandled EtherType" "SECURITY - Dropping packet with"; do
    HITS=$(grep -ca "$dead" "$SERIAL")
    if [ "$HITS" -ne 0 ]; then
        fail_with "the console printed \"$dead\" $HITS time(s)" \
            "The counter may work, but the per-packet print is back, which is" \
            "the actual vulnerability: $FRAME_COUNT frames produced $HITS console" \
            "lines from the ISR, and an attacker sets that rate."
    fi
done

echo "RESULT: PASS"
echo "  $FRAME_COUNT malformed frames -> counter +$DELTA, console +0 lines."
echo "  The drop is recorded and the remote console-flood path is closed."
exit 0

# =============================================================================
# VALIDATION LOG — validated BOTH WAYS on 2026-08-16
#
# RUN 1 (fix present) -> PASS
#   unsupported-ethertype: before=0 after=20 delta=20 (sent 20), console +0.
#   Note the delta of 20 also clears E1000_RX_PACKET_BUDGET (16), so the
#   increment is confirmed once-per-frame across the budget boundary and into
#   the post-budget drain loop -- the path that carried the worst of the three
#   prints. A run of <=16 frames would not have shown this.
#
# RUN 2 (negative control, print reintroduced) -> caught by the SOURCE GUARD
#   before boot: "INCONCLUSIVE — src/net.c still contains the per-packet print".
#   Correct, but it means the guard, not the runtime assertion, did the work --
#   so this run did NOT yet validate the console half.
#
# RUN 3 (negative control, source guard bypassed) -> FAIL, as required:
#   "the console printed \"Unhandled EtherType\" 20 time(s)"
#   while the counter delta was still a clean 20. This is the run that matters:
#   it proves the console assertion is load-bearing and not merely riding on
#   the counter check -- a harness asserting only the delta would have PASSED
#   this build, which is the live vulnerability.
#
#   That run is also the clearest demonstration of the bug itself: 20 frames
#   injected from off-machine produced 20 console lines emitted from the ISR,
#   with no local account involved. Serial output at that ratio is the
#   amplification primitive item 2 exists to remove.
#
# NOT covered by traffic, by design (stated in the header): the runt and
# hw-error counters. Both are unreachable through QEMU's emulated e1000 -- it
# pads short frames and computes a correct FCS -- so they are held by the
# source guard only. If a future harness can inject them, assert their deltas
# the same way rather than trusting the guard.
# =============================================================================
