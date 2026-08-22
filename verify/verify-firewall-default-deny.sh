#!/bin/bash
# =============================================================================
# verify-firewall-default-deny.sh -- default-deny is reachable, and replies
# to our own traffic still get in.
#
# WHAT THIS PROVES
#
# firewall_allow_outgoing() and firewall_allow_established() each used to add
# a firewall_rule_t whose every match field was left zero. match_rule() reads
# zero as "any" on all of them, and firewall_add_rule() sets enabled = true
# unconditionally, so the zeroed `enabled` in {0} did not hold them back. The
# result was two rules matching EVERY inbound packet, at priorities 100 and
# 10 -- the two lowest numbers scanned first -- which made the "Default: DENY
# ALL" at the bottom of firewall_check_packet() UNREACHABLE for anything that
# cleared the bogon and rate-limit checks.
#
# The priority-10 one also shadowed firewall_block_ip(), which uses the same
# priority band and is appended at a higher array index, so the insertion-
# order inner loop found the wildcard ACCEPT first. That is the IDS's only
# enforcement action, so a matched BLOCK signature blocked nothing.
#
# THE TWO LEGS MUST BOTH RUN, AND THEY ARE OPPOSITE
#
# Either one alone is satisfied by a broken firewall:
#
#   ARM A (deny)   -- an unsolicited inbound TCP SYN must be DROPPED.
#                     Passes trivially against a firewall that drops
#                     EVERYTHING, including our own DNS replies.
#   ARM B (admit)  -- a DNS reply to our own query must be ADMITTED, i.e. the
#                     guest must still resolve a name. This is the POSITIVE
#                     CONTROL, and it is what the deleted wildcard rules were
#                     covering for. Passes trivially against a firewall that
#                     accepts everything -- which is precisely the bug.
#
# Only a firewall that denies unsolicited inbound traffic WHILE admitting
# replies to flows we initiated passes both. That pairing is the whole test.
#
# WHY THIS HARNESS BOOTS TWICE
#
# The two arms need different netdevs and cannot share a boot:
#   - Arm A injects a raw TCP SYN from an arbitrary source, which QEMU's
#     user-mode NAT will not carry, so it needs `socket,mcast=`.
#   - Arm B needs a real DHCP lease and real DNS, which the mcast netdev has
#     no NAT to provide.
# Do not "simplify" this into one boot by dropping an arm; a single arm is
# exactly the unfalsifiable half described above.
#
# Egress tracking currently covers UDP only (the single call site is
# net.c:2035, in the UDP send path), so arm B is a UDP/DNS flow by necessity
# rather than by preference. A TCP reply-admission leg is NOT available today
# and is deliberately not faked with a UDP one wearing a TCP label.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: fwdeny-a.log, fwdeny-b.log.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL_A=fwdeny-a.log
SERIAL_B=fwdeny-b.log
TRACE_A=fwdeny-a-trace.log
TRACE_B=fwdeny-b-trace.log
GUEST_MAC=52:54:00:12:34:56
QEMU_MCAST=230.0.0.1:1234
N_SYN=12          # unsolicited inbound SYNs injected in arm A

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

# ---------------------------------------------------------------------------
# SOURCE GUARD -- the shape of the fix, not merely that the file changed.
# ---------------------------------------------------------------------------
grep -q "firewall_track_outgoing" src/firewall.c \
    || guard_fail "src/firewall.c has no firewall_track_outgoing(); tree predates
  the fix. Without egress tracking, arm B can only pass via a wildcard rule."
grep -q "firewall_track_outgoing" src/net.c \
    || guard_fail "src/net.c never calls firewall_track_outgoing(), so no egress
  flow is ever recorded and arm B would fail for the wrong reason"

# The wildcard rules must be GONE. Anchored on the exact descriptions they
# carried: a re-added rule would match here even if tracking also works.
for dead in "Allow all outgoing" "Allow established/related"; do
    if grep -qa "safe_strcpy(rule.description, \"$dead\"" src/firewall.c; then
        guard_fail "src/firewall.c still installs the wildcard rule \"$dead\".
  Every match field is zero, which match_rule() reads as 'any', so the
  default-deny arm is unreachable and arm A would pass only by accident."
    fi
done

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
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }

# ===========================================================================
# ARM A -- unsolicited inbound SYN must be DROPPED
# ===========================================================================
echo ""
echo "==> ARM A: unsolicited inbound TCP SYN (mcast netdev, no NAT)"
RUN_DISK_A=/tmp/tinyos-fwdeny-a.img
MON_A=/tmp/tinyos-fwdeny-a.sock
rm -f "$RUN_DISK_A" "$SERIAL_A" "$TRACE_A" "$MON_A"
cp disk.img "$RUN_DISK_A"

qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK_A",format=raw,if=ide \
    -netdev socket,id=net0,mcast="$QEMU_MCAST" \
    -device e1000,netdev=net0,mac=$GUEST_MAC \
    -serial "file:$SERIAL_A" \
    -monitor "unix:$MON_A,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE_A" -display none &
QEMU_A=$!
cleanup_a() { kill "$QEMU_A" 2>/dev/null; wait "$QEMU_A" 2>/dev/null; rm -f "$MON_A"; }
trap cleanup_a EXIT

# data_offset 5 = a well-formed TCP header. That matters: a malformed one is
# rejected by tcp_handle_packet's header validation, which runs in a different
# file for a different reason, and the firewall would never see it -- the leg
# would pass while measuring the wrong subsystem entirely.
#
# --dst-ip {GIP} is captured from the guest's own ifconfig below. On this
# mcast netdev there is no DHCP server, so the guest self-assigns a per-boot
# link-local 169.254.x.y rather than taking the 10.0.2.15 NAT lease the
# injector defaults to. handle_ip's address gate runs BEFORE
# firewall_check_packet(), so a frame addressed to 10.0.2.15 never reaches
# the firewall at all and the dropped counter -- the thing this arm measures
# -- would not move. That fails the leg rather than passing it, but for the
# wrong reason entirely: it would read as "a wildcard ACCEPT is matching",
# the exact bug this harness exists to detect.
#
# --src-ip is TEST-NET-3 (RFC 5737). It must NOT be RFC1918: is_bogon_ip()
# drops 10/8 and friends earlier in firewall_check_packet(), which does
# increment dropped -- so a bogon source would satisfy this arm's assertion
# without the default-deny arm ever being reached. That is the same
# unfalsifiable shape the two-arm structure above exists to rule out.
export TINYOS_HOOK_SYNINJ="sleep 2; python3 tools/inject_frames.py \
    --mcast '$QEMU_MCAST' --dst $GUEST_MAC --mode tcp --tcp-data-offset 5 \
    --dst-ip {GIP} --src-ip 203.0.113.9 \
    --tcp-dst-port 80 --count $N_SYN >/dev/null 2>&1; sleep 6; true"

TINYOS_SERIAL="$SERIAL_A" \
TINYOS_MON_SOCK="$MON_A" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="secstatus" \
TINYOS_EXPECT="Firewall" \
TINYOS_FOLLOWUP_CMDS="\
ifconfig=>IP Address:@GIP=IP Address: +([0-9.]+);\
>SYNINJ;\
secstatus=>Firewall" \
python3 tools/qemu_typist.py
RC_A=$?
sleep 3
cleanup_a
trap - EXIT

[ -s "$SERIAL_A" ] || { echo "RESULT: FAIL — arm A produced no serial output (rc=$RC_A)"; exit 2; }

# secstatus line:
#   Firewall ............ 41 pkts (12 dropped, 0 rejected)
FW_LIST=$(grep -a "Firewall \.\+" "$SERIAL_A" \
          | sed -n 's/.*(\([0-9][0-9]*\) dropped.*/\1/p')
FW_N=$(printf '%s\n' "$FW_LIST" | grep -c '[0-9]')
if [ "$FW_N" -lt 2 ]; then
    echo "RESULT: FAIL — arm A: expected 2 secstatus readings, got $FW_N"
    grep -a "Firewall" "$SERIAL_A"
    exit 1
fi
D_B=$(printf '%s\n' "$FW_LIST" | sed -n '1p')
D_A=$(printf '%s\n' "$FW_LIST" | sed -n '2p')
D_D=$((D_A - D_B))
echo "  dropped: $D_B -> $D_A  (delta $D_D, sent $N_SYN unsolicited SYNs)"

if [ "$D_D" -lt "$N_SYN" ]; then
    echo "RESULT: FAIL — arm A: dropped rose by only $D_D, expected >= $N_SYN"
    echo "  $N_SYN unsolicited inbound SYNs were injected from an address the"
    echo "  guest never contacted. Each must hit the default-deny arm at the"
    echo "  bottom of firewall_check_packet(). A short delta means a wildcard"
    echo "  ACCEPT is matching them first -- which is the bug this fix removed."
    exit 1
fi
echo "PASS arm A: unsolicited inbound SYNs dropped (default-deny reachable)."

# ===========================================================================
# ARM B -- POSITIVE CONTROL: a reply to our own query must be ADMITTED
# ===========================================================================
echo ""
echo "==> ARM B: DNS reply to our own query (user-mode NAT, real lease)"
RUN_DISK_B=/tmp/tinyos-fwdeny-b.img
MON_B=/tmp/tinyos-fwdeny-b.sock
rm -f "$RUN_DISK_B" "$SERIAL_B" "$TRACE_B" "$MON_B"
cp disk.img "$RUN_DISK_B"

qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK_B",format=raw,if=ide \
    -netdev user,id=net0 \
    -device e1000,netdev=net0,mac=$GUEST_MAC \
    -serial "file:$SERIAL_B" \
    -monitor "unix:$MON_B,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE_B" -display none &
QEMU_B=$!
cleanup_b() { kill "$QEMU_B" 2>/dev/null; wait "$QEMU_B" 2>/dev/null; rm -f "$MON_B"; }
trap cleanup_b EXIT

TINYOS_SERIAL="$SERIAL_B" \
TINYOS_MON_SOCK="$MON_B" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="UDP rx:" \
TINYOS_FOLLOWUP_CMDS="\
dig google.com=>google.com;\
ifconfig=>DNS rx:" \
python3 tools/qemu_typist.py
RC_B=$?
sleep 3
cleanup_b
trap - EXIT

[ -s "$SERIAL_B" ] || { echo "RESULT: FAIL — arm B produced no serial output (rc=$RC_B)"; exit 2; }

# The lease must have happened, or "DNS did not resolve" would be a NETWORK
# failure misreported as a firewall failure.
if ! grep -qa "DHCP.*\(Lease\|BOUND\|Configured\|ACK\)" "$SERIAL_B"; then
    echo "RESULT: INCONCLUSIVE — arm B never got a DHCP lease, so a DNS failure"
    echo "  here says nothing about the firewall. Check user-mode NAT."
    grep -a "DHCP" "$SERIAL_B" | tail -10
    exit 3
fi

DNS_RESOLVED=$(grep -a "DNS rx:" "$SERIAL_B" | tail -1 \
               | sed -n 's/.*[^0-9]\([0-9][0-9]*\) resolved.*/\1/p')
DNS_RESOLVED=${DNS_RESOLVED:-0}
echo "  DNS resolved counter: $DNS_RESOLVED"

if [ "$DNS_RESOLVED" -lt 1 ]; then
    echo "RESULT: FAIL — arm B (positive control): no DNS response was accepted."
    echo "  The guest sent a query, so firewall_track_outgoing() should have"
    echo "  recorded the flow and the connection-tracking branch should have"
    echo "  admitted the reply. Zero resolutions means default-deny is now"
    echo "  eating our OWN replies -- arm A would still pass in that state,"
    echo "  which is exactly why this arm exists."
    grep -a "DNS\|dig" "$SERIAL_B" | tail -15
    exit 1
fi
echo "PASS arm B (positive control): reply to our own query admitted."

echo ""
echo "RESULT: PASS"
echo "  Unsolicited inbound dropped ($D_D >= $N_SYN), own replies admitted"
echo "  ($DNS_RESOLVED resolved). Default-deny is reachable AND stateful"
echo "  reply admission works without a wildcard ACCEPT."
exit 0
