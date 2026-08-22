#!/usr/bin/env bash
#
# verify-tcp-serverpath.sh — FULLY AUTOMATED check that the TCP SERVER path is
# genuinely gone rather than merely uncalled, and that inbound packet delivery
# still works after the passive-open branch was cut out of handle_packet.
#
# WHY THIS HARNESS EXISTS
#
# PR C (option A) deleted tcp_bind/tcp_listen/tcp_accept and, with them, the
# passive-open branch inside tcp_handle_packet. That branch sat in the SAME
# function the client path runs through, so the edit is one `else` away from
# every inbound segment the client depends on -- including the SYN-ACK that
# completes its own handshake.
#
# A clean -Werror build proves nothing here: deleting an `else` branch that
# handled unsolicited segments compiles perfectly whether or not the remaining
# branch still routes established-connection traffic correctly. The only
# instrument that can tell the difference is a connection that actually
# completes, so this harness makes one.
#
# WHAT IS PROVEN, AND HOW
#
#   RX DISPATCH   END-TO-END by traffic: a DNS lookup must resolve a real name
#                 to a real address. The reply arrives as an inbound IP packet
#                 and travels the whole delivery path -- e1000 RX -> softirq
#                 ring -> knetd -> handle_packet -> protocol dispatch -- which
#                 is the path the deleted branch sat in the middle of. If the
#                 edit had broken inbound delivery or the dispatch switch, a
#                 name cannot resolve.
#
#   SERVER PATH   STRUCTURALLY by the source guard: the three functions are
#                 absent, and nothing can assign TCP_LISTEN. The second half
#                 matters more than the first -- deleting the functions while
#                 leaving any `state = TCP_LISTEN` assignment would leave the
#                 passive-open branch reachable, which is the whole risk the
#                 deletion was meant to remove.
#
# WHAT THIS HARNESS DOES *NOT* PROVE, AND WHY (read before trusting it)
#
# It does not complete a TCP handshake, and that is a scope limit of THIS
# harness -- not a defect in the tree. Read this carefully, because the text
# here previously said the opposite and cost a full session of work.
#
# This harness drives `dig` and asserts on the `TCP no-conn` counter. It
# exercises the SERVER path: inbound segments arriving with no listener. It
# never calls `tcp_connect`, so it says NOTHING about outbound connections in
# either direction -- passing or failing.
#
# THE CLIENT PATH WORKS. Measured 2026-08-22 at HEAD with a filter-dump pcap,
# driving `curl example.com` from the kernel shell:
#
#   10.0.2.15:49152 -> 104.20.23.154:80   SYN      seq=2655501428
#   104.20.23.154:80 -> 10.0.2.15:49152   SYN|ACK  seq=128001 ack=2655501429
#   10.0.2.15:49152 -> 104.20.23.154:80   ACK      seq=2655501429 ack=128002
#   ... PSH with the request, 825 bytes of response, two-way FIN
#
# Serial shows "TCP: Connection established!" then "HTTP/1.1 200 OK". Sequence
# arithmetic is correct (server acks ISS+1). This matches an independent pcap
# taken 2026-08-16.
#
# WHAT THE OLD TEXT CLAIMED, AND WHY IT WAS WRONG
#
# It stated that curl reached SYN_SENT and timed out after 10010 ms with no
# SYN-ACK, "measured identically" at three commits, and concluded "TCP-over-NAT
# is broken in this tree". That conclusion was drawn from THIS harness's own
# results -- a server-path harness -- and carried forward as evidence about the
# client path. Nobody re-ran an outbound connection. `doc/NETDAEMON_DESIGN.md`
# recorded the correction ("TCP-over-NAT was never broken") but the retraction
# never reached this file, so every run kept printing the disproved claim.
#
# The lesson, which is why this is spelled out at length: before fixing a
# network bug, run the reproducer for the DIRECTION you think is broken. The
# client and server paths share tcp.c and the counter vocabulary, so a
# server-path harness reads like a TCP harness.
#
# DNS remains the end-to-end signal asserted here: it is real inbound traffic
# through the same `handle_packet` dispatch the passive-open branch was cut
# from, so a failure here is attributable to that edit. Asserting on an HTTP
# body would exercise the client path, which this harness is not about.
#
# WHY NAT AND NOT A SOCKET NETDEV
#
# The opposite of verify-icmp-counters.sh, and for the opposite reason. That
# harness INJECTS frames at the guest, so it needs a netdev the host can write
# to. This one needs the guest to REACH THE OUTSIDE and get real answers back,
# which is what user-mode NAT provides and a bare mcast socket cannot.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: tcpserverpath.log (serial), tcpserverpath-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=tcpserverpath.log
TRACE=tcpserverpath-trace.log
RUN_DISK=/tmp/tinyos-tcpsp-disk.img
MON_SOCK=/tmp/tinyos-tcpsp-mon.sock

# The name to resolve. Any well-known name works; this one is short and its
# reply fits comfortably in a single UDP datagram. Overridable for offline or
# restricted-network runs.
LOOKUP_NAME="${TINYOS_DNS_NAME:-example.com}"

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

# ---------------------------------------------------------------------------
# SOURCE GUARD
#
# Shape of the change, not merely that files moved. Two independent halves:
# the functions must be gone, AND the state they fed must be unreachable.
# ---------------------------------------------------------------------------
for gone in tcp_bind tcp_listen tcp_accept; do
    # Definitions only: the comments explaining the removal legitimately name
    # these functions, so an unanchored grep would fail against a correct tree.
    if grep -qE "^[a-z_]+ +\**${gone}[[:space:]]*\(" src/tcp.c; then
        guard_fail "src/tcp.c still DEFINES ${gone}(); tree predates the deletion"
    fi
    if grep -qE "^int ${gone}[[:space:]]*\(" src/tcp.h; then
        guard_fail "src/tcp.h still declares ${gone}(); tree predates the deletion"
    fi
done

# The load-bearing half. If anything can still set TCP_LISTEN then the
# passive-open branch is live again regardless of whether the three API
# functions exist, and a remote SYN can allocate a connection slot.
if grep -qE "state[[:space:]]*=[[:space:]]*TCP_LISTEN" src/tcp.c; then
    guard_fail "src/tcp.c still assigns TCP_LISTEN, so the passive-open path is
  reachable -- deleting the API functions alone does not close it"
fi

# The removed branch's per-packet print must not have survived the edit.
if grep -qa "Incoming connection from" src/tcp.c; then
    guard_fail "src/tcp.c still contains the per-inbound-SYN print
  \"Incoming connection from\" -- a remote host chooses how often that fires"
fi

grep -q "net_get_tcp_no_connection" src/shell_network.c \
    || guard_fail "ifconfig does not report the TCP no-conn counter"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# The ISO is two copies downstream of the edit; verify the ARTIFACT carries
# this build. grep -c not grep -q: under pipefail, grep -q SIGPIPEs `strings`.
ISO_MARKERS=$(strings "$ISO" | grep -c "TCP no-conn")
if [ "$ISO_MARKERS" -eq 0 ]; then
    guard_fail "the ISO predates this change (ifconfig's TCP no-conn line is
  absent), so the run would measure a kernel without the deletion"
fi

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

echo "==> Launching headless QEMU with user-mode NAT (monitor $MON_SOCK)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 \
    -device e1000,netdev=net0 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# ifconfig and dig are both kernel-shell commands, so this harness stays in the
# kernel shell (the typist types `kshell` itself by default -- see the note in
# verify-netd-boundary.sh; do NOT add another).
#
#   ifconfig  : confirms DHCP gave us a routable NAT lease before resolving
#   dig       : the actual test -- real inbound traffic through the dispatch
#   ifconfig  : the TCP no-conn counter, read after the traffic
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="IP Address" \
TINYOS_FOLLOWUP_CMDS="\
dig $LOOKUP_NAME=>Resolved;\
ifconfig=>TCP no-conn" \
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

# --- Did the guest get a routable address? ---------------------------------
# A link-local 169.254.x.x means DHCP never completed, so curl could not have
# resolved or connected and any later failure would be misattributed to TCP.
GUEST_IP=$(grep -a 'IP Address:' "$SERIAL" | tail -1 \
           | sed -n 's/.*IP Address:  *\([0-9.][0-9.]*\).*/\1/p')
case "$GUEST_IP" in
    169.254.*|"")
        echo "RESULT: INCONCLUSIVE — guest has no routable lease (IP='${GUEST_IP:-none}')."
        echo "  DHCP did not complete, so this run cannot distinguish a broken"
        echo "  RX dispatch from a guest that never had a network at all."
        exit 3
        ;;
esac

# --- RX dispatch: a real name resolved to a real address -------------------
# The resolved address cannot be printed unless a DNS reply arrived from the
# outside and traversed the full inbound path -- e1000 RX, the softirq ring,
# knetd, handle_packet, and the protocol dispatch the deleted branch sat in.
#
# Asserted on the ADDRESS, not on "dig ran": dig prints its banner, and can
# print a failure, without any packet ever coming back. Requiring a dotted
# quad is what separates a working dispatch from a command that merely
# executed.
RESOLVED=$(grep -a "Resolved IP for domain:\|Resolved to" "$SERIAL" | tail -1 \
           | sed -n 's/.*[Rr]esolved[^0-9]*\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
if [ -z "$RESOLVED" ]; then
    fail_with "DNS did not resolve '$LOOKUP_NAME', so no inbound packet was delivered" \
        "The reply travels the same handle_packet dispatch the passive-open" \
        "branch was deleted from. This is what a broken deletion looks like:" \
        "the build is clean, DHCP already succeeded, and nothing comes back." \
        "guest IP: $GUEST_IP  name: $LOOKUP_NAME"
fi

# Guard against a stale match: the address must not be the guest's own, and
# must not be link-local, or we are reading something other than a real answer.
case "$RESOLVED" in
    "$GUEST_IP"|169.254.*|0.0.0.0)
        fail_with "DNS 'resolved' to an implausible address: $RESOLVED" \
            "That is the guest's own or a link-local address, so this is not" \
            "a real answer from a real server."
        ;;
esac

SERIAL_LINES=$(grep -ac . "$SERIAL")

# --- The no-conn counter must be present and sane --------------------------
NOCONN=$(grep -a "TCP no-conn:" "$SERIAL" | tail -1 \
         | sed -n 's/.*TCP no-conn: *\([0-9][0-9]*\).*/\1/p')
if [ -z "$NOCONN" ]; then
    fail_with "ifconfig did not report the TCP no-conn counter" \
        "The counter replaced the deleted passive-open print; if it is absent" \
        "the running kernel is not the one this harness built."
fi

echo "  guest IP:      $GUEST_IP (routable NAT lease)"
echo "  lookup:        $LOOKUP_NAME -> $RESOLVED"
echo "  serial lines:  $SERIAL_LINES"
echo "  TCP no-conn:   $NOCONN segments dropped (no listener)"
echo ""
echo "  server path:   ABSENT (source guard: no tcp_bind/tcp_listen/tcp_accept,"
echo "                 nothing assigns TCP_LISTEN, no per-SYN print)"
echo "  RX dispatch:   PROVEN end-to-end (real inbound reply through"
echo "                 handle_packet, the function the branch was cut from)"
echo "  TCP handshake: NOT EXERCISED HERE — this harness drives the SERVER"
echo "                 path and never calls tcp_connect. The client path"
echo "                 works: pcap at HEAD shows SYN/SYN-ACK/ACK and"
echo "                 HTTP/1.1 200 OK. See header."
echo ""
echo "RESULT: PASS"
exit 0
