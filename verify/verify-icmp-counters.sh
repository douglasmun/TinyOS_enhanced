#!/usr/bin/env bash
#
# verify-icmp-counters.sh — FULLY AUTOMATED check that inbound ICMP is COUNTED
# rather than printed, and that the counters are accurate.
#
# WHAT THIS IS TESTING
#
# Three ICMP sites used to kprintf one line per received packet, all on the RX
# path and all driven by a remote host with no local account:
#
#   icmp.c  "64 bytes from ..."             echo REPLY received  (NOT limited)
#   icmp.c  "Echo Request from ..."         echo REQUEST received
#   icmp.c  "Echo Reply sent to ..."        echo REQUEST answered
#
# This is the class item 2 closed in the e1000/net RX loops. Those five sites
# were found by sweeping the RX loops; these three live in icmp.c and were
# missed by that sweep. See doc/NETDAEMON_DESIGN.md finding A1.
#
# WHY THE ECHO-REPLY SITE IS THE SERIOUS ONE
#
# The two echo-REQUEST prints sat below the ICMP_RATE_LIMIT_TICKS check, so a
# flood produced ~10 console lines/second -- bounded, and bounded only by
# accident, since that limiter exists to cap reply GENERATION and the prints
# were downstream of it by placement rather than design.
#
# The echo-REPLY print had no such luck: its branch returns before reaching the
# limiter, so it was one console line per packet at whatever rate the attacker
# chose. TinyOS accepts a reply only if the 16-bit identifier matches its
# CSPRNG-chosen ping_identifier -- 1-in-65536 for an off-path attacker, but
# FREE for an on-path one, because that identifier travels in cleartext in
# every outbound ping.
#
# WHAT IS DRIVEN, AND WHAT IS WITNESSED ON THE WIRE
#
# The guest sits on a unicast dgram netdev with tools/net_peer.py capturing
# every frame it sends (on macOS the mcast netdev never emits guest frames;
# see the header of net_peer.py). That capture is what makes both halves
# end-to-end:
#
#   ECHO REQUEST  20 injected requests; the counters must account for every
#                 frame, AND the wire must carry exactly as many echo replies
#                 to the requester as the "answered" counter claims. The
#                 counter bumps BEFORE an e1000_send whose result is ignored,
#                 so on its own it proves acceptance, not a reply.
#   ECHO REPLY    The guest pings a link-local peer (net_peer answers its ARP,
#                 never its ping). The capture shows the outbound request's
#                 identifier -- exactly what an on-path attacker learns -- and
#                 the harness injects replies carrying it, plus replies with
#                 the identifier inverted. The echo-reply counter must move by
#                 the matching replies only, with no console line.
#
# Until 2026-10 this harness ran on the mcast netdev and could prove the
# echo-REPLY branch only structurally (the source guard below), because the
# identifier is CSPRNG-chosen and was never observable.
#
# WHY THE DELTA IS NOT SIMPLY FRAME_COUNT FOR EVERY COUNTER
#
# The rate limiter means only the FIRST request in a burst is answered; the
# rest increment the rate-limited counter. So the assertion is:
#
#   echo-request counter  +  rate-limited counter  ==  FRAME_COUNT   (exactly)
#
# Asserting the SUM rather than either half is what makes this robust to the
# limiter's timing without weakening it into a ">= 1" test: every frame must be
# accounted for in exactly one bucket, which is precisely the property that a
# per-interrupt rather than per-frame increment would break.
#
# VALIDATION LOG (filled in from actual runs, not written in advance)
#
#   POSITIVE, fixed build, 20 frames
#     echo-request delta 1, rate-limited delta 19, total 20 of 20 -> PASS
#     The 1/19 split is the limiter working: only the first request in the
#     burst is answered. This is why the assertion is on the SUM -- a
#     "delta == FRAME_COUNT" check on the request counter alone would fail
#     spuriously here, and weakening it to ">= 1" would stop catching a
#     per-interrupt increment.
#
#   NEGATIVE 1, echo-REPLY print restored (finding A1), counters left intact
#     -> INCONCLUSIVE at the source guard.
#     This is the correct and ONLY possible outcome for A1: injected traffic
#     cannot reach that branch without knowing ping_identifier, so the guard
#     is the sole mechanism that can catch it. Recorded plainly because a
#     guard-only proof is weaker than an end-to-end one and should not be
#     read as more.
#
#   (The three entries above predate the capture; they ran on mcast.)
#
#   NEGATIVE 2, echo-REQUEST print restored, source guard deliberately
#     bypassed so the runtime half is tested in isolation
#     -> FAIL: 'the console printed "Echo Request from" 1 time(s)'.
#     Run because negative 1 stops at the guard and therefore proves nothing
#     about the runtime assertions. Note the flood was ONE line for 20 frames
#     -- the rate limiter throttling it, which is exactly the "bounded by
#     accident" property finding A2 describes.
#
#   TWO EARLIER VERSIONS OF THIS HARNESS PASSED NOTHING AND LOOKED HEALTHY:
#     v1 addressed packets to net.c's compiled-in 192.168.0.80. This netdev
#     has no DHCP so the guest self-assigns 169.254.x.x; all 20 frames died at
#     the destination-IP check.
#     v2 read the guest IP at runtime but used a link-local SOURCE; all 20
#     died one layer later in the firewall's bogon filter.
#     Both runs showed "RX packets: 20, RX parsed: 20 thread-ctx" -- healthy
#     by every reading except the counter under test. A ">= 1" assertion would
#     have hidden both. The drop point was found by temporarily instrumenting
#     each early return in handle_ip, not by reading the code harder.
#
#   ON THE WIRE (dgram netdev + tools/net_peer.py, 2026-10-03)
#   POSITIVE, fixed build
#     request delta 1 + rate-limited 19 = 20 of 20; 1 echo reply on the wire
#     to 203.0.113.99 (= answered); echo-reply delta 5 of 8 injected -> PASS
#   NEGATIVE 3, the echo-reply e1000_send() in handle_icmp removed
#     -> FAIL: 'the wire carried 0 echo replies; the counter claims 1
#     answered'. The counters alone read exactly as in the positive run --
#     this leg is the only thing that sees it.
#   NEGATIVE 4, the identifier check forced true ("1 ||" -- a plain
#     self-compare is -Werror)
#     -> FAIL: 'echo-reply counted 8, expected exactly 5'.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: icmpctr.log (serial), icmpctr-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=icmpctr.log
TRACE=icmpctr-trace.log
RUN_DISK=/tmp/tinyos-icmpctr-disk.img
MON_SOCK=/tmp/tinyos-icmpctr-mon.sock

# Exceeds E1000_RX_PACKET_BUDGET (16) so the run also crosses the post-budget
# drain loop, where a per-interrupt increment would show up as a shortfall.
FRAME_COUNT=${TINYOS_ICMP_FRAMES:-20}

GUEST_MAC=52:54:00:12:34:56

# Source IP for the injected packets. This must be a PUBLIC address: the
# firewall's bogon filter (firewall.c is_bogon_ip) drops 0/8, 127/8,
# 169.254/16, 10/8, 172.16/12, 192.168/16, 224/4 and 240/4 -- which is every
# range a lab setup would reach for by instinct. 203.0.113.0/24 is TEST-NET-3
# (RFC 5737), reserved for documentation, so it is not a bogon and cannot
# collide with a real host.
#
# The first version of this harness used 169.254.1.99 to match the guest's
# link-local subnet and every packet was dropped by the firewall, one layer
# after the destination check that had already eaten the version before it.
SRC_IP=203.0.113.99

# The peer the guest pings to reveal its identifier. Link-local like the
# guest, so the ping goes out directly after one ARP, which net_peer answers.
PEER_IP=169.254.77.77
PEER_MAC=52:54:00:11:11:11
REPLY_MATCH=5      # injected echo replies carrying the guest's identifier
REPLY_FOREIGN=3    # ...and carrying it inverted: must not be counted

GUEST_EP=127.0.0.1:41245
PEER_EP=127.0.0.1:41246
PEER_LOG=icmpctr-peer.log
PEER_PID_FILE=/tmp/tinyos-icmpctr-peer.pid

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

# ---------------------------------------------------------------------------
# SOURCE GUARD
#
# Checks the SHAPE of the fix, not merely that the file changed: each counter
# must exist AND each per-packet print must be gone. Either half alone passes
# against a broken tree -- deleting the prints destroys the information, and
# adding counters while leaving the prints leaves the flood in place.
# ---------------------------------------------------------------------------
grep -q "icmp_echo_replies_rx" src/icmp.c \
    || guard_fail "src/icmp.c has no icmp_echo_replies_rx counter; tree predates the fix"
grep -q "icmp_echo_requests_rx" src/icmp.c \
    || guard_fail "src/icmp.c has no icmp_echo_requests_rx counter; tree predates the fix"
grep -q "icmp_get_rx_stats" src/shell_network.c \
    || guard_fail "ifconfig does not report the ICMP counters; tree predates the fix"

# The prints must be gone. Anchored on the exact former strings. The first is
# the unthrottled one (A1) and is the whole reason this harness exists -- it is
# ALSO the one traffic cannot reach, so this guard is its only proof.
for dead in "64 bytes from %d" "Echo Request from" "Echo Reply sent to"; do
    if grep -qa "$dead" src/icmp.c; then
        guard_fail "src/icmp.c still contains the per-packet print \"$dead\""
    fi
done

command -v python3 >/dev/null 2>&1 || guard_fail "python3 not found"
[ -f tools/inject_frames.py ] || guard_fail "tools/inject_frames.py is missing"
python3 tools/inject_frames.py --help 2>&1 | grep -q "mode" \
    || guard_fail "tools/inject_frames.py has no --mode flag; it predates the ICMP injector"
grep -q "id=0x" tools/net_peer.py 2>/dev/null \
    || guard_fail "tools/net_peer.py does not log ICMP identifiers"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || { echo "RESULT: harness problem — build failed"; exit 2; }
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# Verify the ARTIFACT carries this build, not just the source tree (see
# harness-design-principles: the ISO is two copies downstream of the edit).
# grep -c not grep -q: under pipefail, grep -q SIGPIPEs `strings`.
ISO_MARKERS=$(strings "$ISO" | grep -c "echo-reply")
if [ "$ISO_MARKERS" -eq 0 ]; then
    guard_fail "the ISO predates the fix (ifconfig's ICMP line is absent), so
  the run would measure a kernel with no ICMP counters at all"
fi

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK" "$PEER_LOG" "$PEER_PID_FILE"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

# dgram, not socket,mcast= and not user-mode NAT: NAT cannot deliver injected
# frames, and on macOS the mcast netdev never emits the guest's frames, so
# neither the echo replies nor the guest's ping identifier could be seen.
echo "==> Launching headless QEMU (monitor $MON_SOCK, dgram $GUEST_EP <-> $PEER_EP)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev dgram,id=net0,local.type=inet,local.host=127.0.0.1,local.port=${GUEST_EP##*:},remote.type=inet,remote.host=127.0.0.1,remote.port=${PEER_EP##*:} \
    -device e1000,netdev=net0,mac="$GUEST_MAC" \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() {
    [ -f "$PEER_PID_FILE" ] && kill "$(cat "$PEER_PID_FILE")" 2>/dev/null
    rm -f "$PEER_PID_FILE"
    kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"
}
trap cleanup EXIT

# PEERUP: the capture runs for the rest of the boot and answers the guest's
# ARP for PEER_IP, so `ping PEER_IP` puts an echo request on the wire.
export TINYOS_HOOK_PEERUP="
    nohup python3 tools/net_peer.py --listen $PEER_EP --send $GUEST_EP \
        --guest $GUEST_MAC --duration 300 --out '$PEER_LOG' \
        --arp-reply '$PEER_IP=$PEER_MAC' >/dev/null 2>&1 &
    echo \$! > '$PEER_PID_FILE'
    sleep 1; true"

# The destination IP must be the guest's ACTUAL address, discovered at runtime
# from the baseline ifconfig rather than assumed.
#
# This is not defensive padding -- the first version of this harness hardcoded
# net.c's compiled-in default (192.168.0.80) and every one of the 20 frames was
# dropped at handle_packet's destination check, before reaching icmp.c. This
# netdev has no DHCP, so the guest does NOT keep the compiled-in default: it
# self-assigns a link-local 169.254.x.x. The run looked healthy (20 RX packets,
# 20 parsed in thread context) while measuring nothing at all, which is exactly
# the failure a "counter >= 1" assertion would have hidden.
#
# Ends in `true` for the same reason as verify-rxdrop-counters.sh: the proof
# the frames landed is the counter delta, not the sender's exit status.
export TINYOS_HOOK_ICMPFLOOD="
    GUEST_IP=\$(grep -a 'IP Address:' '$SERIAL' | tail -1 \
                | sed -n 's/.*IP Address:  *\([0-9.][0-9.]*\).*/\1/p')
    if [ -z \"\$GUEST_IP\" ]; then
        echo 'ICMPFLOOD: could not read guest IP from serial log' >&2
    else
        python3 tools/inject_frames.py \
            --mcast '$GUEST_EP' --mode icmp --icmp-type 8 --count $FRAME_COUNT \
            --dst $GUEST_MAC --dst-ip \"\$GUEST_IP\" --src-ip $SRC_IP \
            >/dev/null 2>&1
    fi
    sleep 5; true"

# REPLIES: read the identifier of the guest's own ping off the wire and inject
# echo replies carrying it, then the same number with it inverted (selectivity:
# a counter that counted every reply would move by both).
export TINYOS_HOOK_REPLIES="
    GUEST_IP=\$(grep -a 'IP Address:' '$SERIAL' | tail -1 \
                | sed -n 's/.*IP Address:  *\([0-9.][0-9.]*\).*/\1/p')
    PING_ID=\$(grep 'icmp type=8 ' '$PEER_LOG' | grep 'dst=$PEER_IP ' | tail -1 \
                | sed -n 's/.* id=\(0x[0-9a-f]*\).*/\1/p')
    if [ -z \"\$GUEST_IP\" ] || [ -z \"\$PING_ID\" ]; then
        echo 'REPLIES: no guest IP or no captured ping identifier' >&2
    else
        FOREIGN_ID=\$(python3 -c \"print(hex(int('\$PING_ID', 16) ^ 0xffff))\")
        python3 tools/inject_frames.py --mcast '$GUEST_EP' --mode icmp \
            --icmp-type 0 --icmp-id \$PING_ID --count $REPLY_MATCH \
            --dst $GUEST_MAC --dst-ip \"\$GUEST_IP\" --src-ip $SRC_IP >/dev/null 2>&1
        python3 tools/inject_frames.py --mcast '$GUEST_EP' --mode icmp \
            --icmp-type 0 --icmp-id \$FOREIGN_ID --count $REPLY_FOREIGN \
            --dst $GUEST_MAC --dst-ip \"\$GUEST_IP\" --src-ip $SRC_IP >/dev/null 2>&1
    fi
    sleep 3; true"

# ifconfig is a kernel-shell command and is where the counters surface, so this
# harness stays in the kernel shell.
#
#   ifconfig      : BASELINE (B)
#   >PEERUP       : capture + ARP responder up
#   ping PEER 1   : puts the guest's identifier on the wire
#   >ICMPFLOOD    : host hook -- injects the echo requests
#   >REPLIES      : echo replies with the captured / inverted identifier
#   ifconfig      : AFTER (A)
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="ICMP rx" \
TINYOS_FOLLOWUP_CMDS="\
>PEERUP;\
ping $PEER_IP 1=>ping statistics;\
>ICMPFLOOD;\
>REPLIES;\
ifconfig=>ICMP rx" \
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
    echo "  --- peer log (guest frames) ---"
    head -40 "$PEER_LOG" 2>/dev/null
    echo "  --- last 40 serial lines ---"
    tail -40 "$SERIAL"
    exit 1
}

# --- Extract the ICMP counters, in order ----------------------------------
#
# The ifconfig line reads:
#   ICMP rx:      0 echo-reply, 0 echo-request, 0 rate-limited
# Anchored on each field NAME, so adding a counter alongside does not silently
# shift what this reads.
extract() { grep -a "ICMP rx:" "$SERIAL" | sed -n "s/.*[ ,]\([0-9][0-9]*\) $1.*/\1/p"; }

REQ_LIST=$(extract "echo-request")
LIM_LIST=$(extract "rate-limited")
REP_LIST=$(extract "echo-reply")
READINGS=$(printf '%s\n' "$REQ_LIST" | grep -c '[0-9]')

if [ "$READINGS" -lt 2 ]; then
    fail_with "expected 2 ifconfig readings, got $READINGS" \
        "The command sequence did not complete, so there is no baseline." \
        "Readings seen: ${REQ_LIST:-none}"
fi

REQ_B=$(printf '%s\n' "$REQ_LIST" | sed -n '1p')
REQ_A=$(printf '%s\n' "$REQ_LIST" | sed -n '2p')
LIM_B=$(printf '%s\n' "$LIM_LIST" | sed -n '1p')
LIM_A=$(printf '%s\n' "$LIM_LIST" | sed -n '2p')
REP_B=$(printf '%s\n' "$REP_LIST" | sed -n '1p')
REP_A=$(printf '%s\n' "$REP_LIST" | sed -n '2p')

REQ_D=$((REQ_A - REQ_B))
LIM_D=$((LIM_A - LIM_B))
TOTAL=$((REQ_D + LIM_D))

echo "  echo-request:  before=$REQ_B  after=$REQ_A  delta=$REQ_D"
echo "  rate-limited:  before=$LIM_B  after=$LIM_A  delta=$LIM_D"
REP_D=$((REP_A - REP_B))
echo "  echo-reply:    before=$REP_B  after=$REP_A  delta=$REP_D  (want $REPLY_MATCH of $((REPLY_MATCH + REPLY_FOREIGN)) injected)"
echo "  accounted for: $TOTAL of $FRAME_COUNT frames sent"

# --- POSITIVE: every injected frame landed in exactly one bucket -----------
if [ "$TOTAL" -eq 0 ]; then
    fail_with "the injected frames moved neither ICMP counter" \
        "Either the frames never reached the ICMP handler or the handler is" \
        "not counting. Check the captured guest IP printed above: on this" \
        "mcast netdev there is no DHCP, so the guest self-assigns a" \
        "link-local 169.254.x.x and does NOT keep net.c's compiled-in" \
        "192.168.0.80 -- addressing the frames to that default is what made" \
        "the first version of this harness measure nothing. A malformed IP" \
        "header would also do this: the packet is dropped at handle_ip()'s" \
        "address gate, before ever reaching icmp.c."
fi
if [ "$TOTAL" -ne "$FRAME_COUNT" ]; then
    fail_with "counters account for $TOTAL frames, expected exactly $FRAME_COUNT" \
        "Every received echo request must land in exactly one bucket: either" \
        "answered (echo-request) or dropped by the limiter (rate-limited)." \
        "An inexact total means the increment is not once-per-frame -- most" \
        "likely per interrupt, which under-reports precisely under the burst" \
        "load these counters exist to measure."
fi

# --- ON THE WIRE: one echo reply per request the counter says it answered --
[ -s "$PEER_LOG" ] || fail_with "the host-side capture never ran (no $PEER_LOG)"
WIRE_REPLIES=$(grep "icmp type=0 " "$PEER_LOG" | grep -c "ip src=[0-9.]* dst=$SRC_IP ")
echo "  echo replies on the wire to $SRC_IP: $WIRE_REPLIES (want $REQ_D, the answered count)"
if [ "$REQ_D" -lt 1 ]; then
    fail_with "no echo request was answered (echo-request delta $REQ_D)" \
        "The first request of a burst must get the limiter's reply slot."
fi
if [ "$WIRE_REPLIES" -ne "$REQ_D" ]; then
    fail_with "the wire carried $WIRE_REPLIES echo replies; the counter claims $REQ_D answered" \
        "The counter increments before e1000_send(), whose result is ignored." \
        "Fewer on the wire means replies were counted but never sent."
fi

# --- ECHO REPLY: driven with the identifier the guest itself revealed -------
PING_LINES=$(grep "icmp type=8 " "$PEER_LOG" | grep -c "dst=$PEER_IP ")
if [ "$PING_LINES" -eq 0 ]; then
    echo "RESULT: INCONCLUSIVE — the guest's ping to $PEER_IP never reached the wire,"
    echo "  so no identifier was learned and the echo-reply leg graded nothing."
    exit 3
fi
if [ "$REP_D" -ne "$REPLY_MATCH" ]; then
    fail_with "echo-reply counted $REP_D, expected exactly $REPLY_MATCH" \
        "$REPLY_MATCH replies carried the guest's identifier and $REPLY_FOREIGN carried" \
        "it inverted. 0 means matching replies are not counted (or never" \
        "arrived); $((REPLY_MATCH + REPLY_FOREIGN)) means the identifier is not checked."
fi

# --- NEGATIVE: the console gained no per-packet ICMP lines -----------------
#
# This is the half that proves the FLOOD is closed rather than merely that
# counters exist. Anchored on the exact strings that used to be printed.
for dead in "64 bytes from" "Echo Request from" "Echo Reply sent to"; do
    HITS=$(grep -ca "$dead" "$SERIAL")
    if [ "$HITS" -ne 0 ]; then
        fail_with "the console printed \"$dead\" $HITS time(s)" \
            "The counters may work, but the per-packet print is back, which" \
            "is the actual vulnerability: $FRAME_COUNT frames produced $HITS console" \
            "lines from the RX path, and a remote host sets that rate."
    fi
done

echo ""
echo "RESULT: PASS"
echo "  $FRAME_COUNT injected echo requests were fully accounted for"
echo "  ($REQ_D answered, $LIM_D rate-limited) with no per-packet console output."
echo "  Each answered request put one reply on the wire, and of the injected echo"
echo "  replies exactly the $REPLY_MATCH carrying the guest's own identifier were counted."
exit 0
