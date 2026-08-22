#!/bin/bash
# =============================================================================
# verify-ids-block-leg.sh -- firewall_block_ip() actually blocks, and blocks
# only the source that attacked.
#
# WHAT THIS PROVES, AND WHY THE OTHER HARNESS COULD NOT
#
# verify-firewall-default-deny.sh proved the default-DENY arm is reachable and
# that replies to our own flows still get in. It did NOT drive
# firewall_block_ip() -- the IDS's only enforcement action -- so the priority-0
# fix in that function was verified by the source change and by arm A's
# reachability result, never end to end. This harness closes that gap.
#
# The fix under test (firewall.c, firewall_block_ip):
#
#     rule.priority = 0;      /* ahead of every ACCEPT this file installs */
#
# plus match_rule()'s deny-before-accept pass within one priority band. Before
# both, a block added by the IDS lost to an ACCEPT installed earlier at the
# same priority, decided by array order -- so a matched BLOCK signature blocked
# nothing at all.
#
# THE VEHICLE IS ICMP, AND THAT IS FORCED -- NOT A PREFERENCE
#
# The attack frame has to reach ids_analyze_packet(), which in handle_ip() sits
# BELOW firewall_check_packet(). So the frame must first be ACCEPTED by the
# firewall, and the accept must come from a RULE, not from a short-circuit:
#
#   - The DHCP exception (ports 67<->68) returns true BEFORE match_rule() is
#     ever consulted. verify-udp-rx-counters.sh leans on exactly that to move
#     the UDP counters, but it is useless here: a priority-0 block rule can
#     never be reached for a DHCP-port frame, so leg 2 below would be admitted
#     whether the block works or not. That is unfalsifiable, and it is the trap
#     this comment exists to stop the next person walking into.
#   - Established-connection tracking also returns true above the rules. ICMP
#     creates no connection entry, so it cannot short-circuit that way.
#
# firewall_allow_icmp() installs ACCEPT at priority 50 at boot (kernel.c:704).
# firewall_block_ip() installs DROP at priority 0. So an ICMP frame is admitted
# by a real rule, and the block genuinely has to outrank a live ACCEPT -- which
# is the collision the fix is about. Nothing else in the tree gives us that.
#
# THE SIGNATURE
#
# ids_load_default_signatures() loads exactly one: 90 90 90 90 31 c0
# ("Shellcode NOP Sled"), CRITICAL, action BLOCK. ids_generate_alert() blocks
# the source when severity >= HIGH and src_ip != 0, so CRITICAL triggers
# firewall_block_ip(). The bytes are injected verbatim with --payload-hex; the
# generated filler payload would never match a signature.
#
# THREE LEGS, AND THEY FAIL IN DIFFERENT DIRECTIONS
#
#   LEG 1 (attack)      -- ICMP carrying the signature, from ATTACKER_IP.
#                          Must raise IDS matches AND "IPs blocked".
#                          This is the trigger, and also the positive control
#                          for the IDS itself: no match here means legs 2 and 3
#                          are measuring nothing.
#   LEG 2 (block)       -- CLEAN ICMP, no signature, same ATTACKER_IP.
#                          Must be DROPPED by the priority-0 rule.
#                          Carries no signature ON PURPOSE: the only thing that
#                          can drop it is the block rule, so a pass cannot be
#                          explained by the IDS dropping it again. If the
#                          priority fix is reverted, the boot-time ICMP ACCEPT
#                          at priority 50 wins and these frames are ACCEPTED.
#   LEG 3 (selectivity) -- CLEAN ICMP, no signature, from INNOCENT_IP.
#                          Must be ACCEPTED. Without this leg, legs 1+2 are
#                          satisfied perfectly by a firewall that blocks
#                          EVERYTHING after any alert -- the same
#                          count-everything failure that
#                          verify-tcp-rx-counters.sh had to add a selectivity
#                          leg for.
#
# Only a firewall that drops the attacker while admitting the innocent source
# passes all three. Legs 2 and 3 are deliberately IDENTICAL frames differing
# only in source IP, so nothing but the source can explain the difference.
#
# ADDRESSING (the three upstream gates -- see doc/NETWORK_ISOLATION.md)
#
#   - --dst-ip {GIP} is captured from the guest's own ifconfig. On the mcast
#     netdev there is no DHCP server, so the guest self-assigns a per-boot
#     link-local 169.254.x.y, not the 10.0.2.15 the injector defaults to.
#     handle_ip's address gate runs above everything here.
#   - Sources are TEST-NET-3 (RFC 5737), never RFC1918: is_bogon_ip() drops
#     10/8 and friends above the rule engine, and it increments `dropped`, so a
#     bogon source would satisfy leg 2 without the block rule ever being
#     consulted.
#
# COUNTER READINGS
#
# secstatus is read FOUR times: a baseline, then once after each leg. The
# extractors take the last four numeric readings; do not add another secstatus
# without updating them. verify-udp-rx-counters.sh failed for exactly this
# reason -- a capture step added a third reading and an nth-1/2 parser was
# left comparing two pre-injection baselines.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Log: idsblock.log
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"
ISO=dist/tinyos.iso
SERIAL=idsblock.log
TRACE=idsblock-trace.log
GUEST_MAC=52:54:00:12:34:56
QEMU_MCAST=230.0.0.1:1234

ATTACKER_IP=203.0.113.9
INNOCENT_IP=203.0.113.77

N_ATTACK=4        # signature-bearing frames from ATTACKER_IP
N_BLOCKED=10      # clean frames from ATTACKER_IP, must all be dropped
N_INNOCENT=10     # clean frames from INNOCENT_IP, must all be accepted

SIG_HEX=9090909031c0     # the "Shellcode NOP Sled" pattern, verbatim

guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

# ---------------------------------------------------------------------------
# SOURCE GUARDS -- the shape of the fix, not merely that the file changed.
# ---------------------------------------------------------------------------
# Scan the whole function body, not a fixed -A window: the explanatory comment
# above the assignment is long and grows, so -A3 misses a priority that IS 0 and
# reports a correct kernel broken.
sed -n '/^void firewall_block_ip/,/^}/p' src/firewall.c \
    | grep -q 'rule.priority = 0;' \
    || guard_fail "firewall_block_ip() no longer sets priority 0. The boot-time
  ICMP ACCEPT sits at priority 50, so the block cannot outrank it and leg 2
  would fail -- correctly, but this guard names the cause up front."

# Both halves of the tie-break: the two-pass loop AND the deny test inside it.
# A substring grep for the condition alone survives `if (0 && ...)`, so the
# loop header is checked too. This guard is weaker than the priority one by
# nature -- it reads text, not behaviour -- and leg 2 is what actually decides.
grep -q 'for (int pass = 0; pass < 2; pass++)' src/firewall.c \
    || guard_fail "match_rule() has lost its two-pass deny-before-accept loop."
grep -q 'pass == 0) != is_deny' src/firewall.c \
    || guard_fail "match_rule() has lost its deny-before-accept pass. That is
  the tie-break half of the fix; without it a same-priority ACCEPT wins by
  array order."

grep -q 'firewall_allow_icmp' src/kernel.c \
    || guard_fail "kernel.c no longer calls firewall_allow_icmp(), so ICMP is
  refused by default-deny and NO leg here can distinguish a working block from
  a broken one -- legs 2 and 3 would both show drops."

grep -q '0x90, 0x90, 0x90, 0x90, 0x31, 0xc0' src/ids.c \
    || guard_fail "the NOP-sled signature is gone from ids_load_default_signatures();
  leg 1 cannot trigger and the whole harness measures nothing."

grep -q 'firewall_block_ip(src_ip)' src/ids.c \
    || guard_fail "ids_generate_alert() no longer calls firewall_block_ip(), so
  a signature match enforces nothing."

grep -q 'payload-hex' tools/inject_frames.py \
    || guard_fail "tools/inject_frames.py has no --payload-hex; the signature
  bytes cannot be placed in the frame and leg 1 cannot trigger."

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

RUN_DISK=/tmp/tinyos-idsblock.img
MON=/tmp/tinyos-idsblock.sock
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON"
cp disk.img "$RUN_DISK"

echo ""
echo "==> Booting (mcast netdev: no NAT, link-local address)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev socket,id=net0,mcast="$QEMU_MCAST" \
    -device e1000,netdev=net0,mac=$GUEST_MAC \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU=$!
cleanup() { kill "$QEMU" 2>/dev/null; wait "$QEMU" 2>/dev/null; rm -f "$MON"; }
trap cleanup EXIT

INJ="python3 tools/inject_frames.py --mcast '$QEMU_MCAST' --dst $GUEST_MAC --mode icmp"

# Leg 1: the attack. --icmp-type 8 (echo request) is a frame the guest will
# parse; the payload is what matters.
export TINYOS_HOOK_ATTACK="sleep 2; $INJ --dst-ip {GIP} --src-ip $ATTACKER_IP \
    --icmp-type 8 --payload-hex $SIG_HEX --count $N_ATTACK >/dev/null 2>&1; sleep 5; true"

# Leg 2: clean frames, same source. No --payload-hex, so no signature.
export TINYOS_HOOK_BLOCKED="$INJ --dst-ip {GIP} --src-ip $ATTACKER_IP \
    --icmp-type 8 --payload-len 32 --count $N_BLOCKED >/dev/null 2>&1; sleep 5; true"

# Leg 3: the same clean frame from a source that never attacked.
export TINYOS_HOOK_INNOCENT="$INJ --dst-ip {GIP} --src-ip $INNOCENT_IP \
    --icmp-type 8 --payload-len 32 --count $N_INNOCENT >/dev/null 2>&1; sleep 5; true"

TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=900 \
TINYOS_EXEC_CMD="secstatus" \
TINYOS_EXPECT="Firewall" \
TINYOS_FOLLOWUP_CMDS="\
ifconfig=>IP Address:@GIP=IP Address: +([0-9.]+);\
secstatus=>Firewall;\
>ATTACK;\
secstatus=>Firewall;\
>BLOCKED;\
secstatus=>Firewall;\
>INNOCENT;\
secstatus=>Firewall" \
python3 tools/qemu_typist.py
RC=$?
sleep 3
cleanup
trap - EXIT

[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (rc=$RC)"; exit 2; }

# ---------------------------------------------------------------------------
# EXTRACT. Four secstatus readings: baseline, post-attack, post-blocked,
# post-innocent. Anchored on the TAIL so the TINYOS_EXEC_CMD reading that
# precedes the follow-ups cannot shift the indices.
#
#   Firewall ............ 41 pkts (12 dropped, 0 rejected)
#   IDS ................. 1 signatures, 3 matches, 3 alerts, 3 IPs blocked
# ---------------------------------------------------------------------------
last4() { printf '%s\n' "$1" | grep '[0-9]' | tail -4; }

FW_TOT_LIST=$(grep -a "Firewall \.\+" "$SERIAL" | sed -n 's/.*\.\.\. *\([0-9][0-9]*\) pkts.*/\1/p')
FW_DROP_LIST=$(grep -a "Firewall \.\+" "$SERIAL" | sed -n 's/.*(\([0-9][0-9]*\) dropped.*/\1/p')
IDS_MATCH_LIST=$(grep -a "IDS \.\+" "$SERIAL" | sed -n 's/.*signatures, *\([0-9][0-9]*\) matches.*/\1/p')
IDS_BLOCK_LIST=$(grep -a "IDS \.\+" "$SERIAL" | sed -n 's/.*alerts, *\([0-9][0-9]*\) IPs blocked.*/\1/p')

for nm in FW_TOT FW_DROP IDS_MATCH IDS_BLOCK; do
    eval "n=\$(printf '%s\n' \"\$${nm}_LIST\" | grep -c '[0-9]')"
    if [ "$n" -lt 4 ]; then
        echo "RESULT: INCONCLUSIVE — only $n readings of $nm (need 4)."
        echo "  Typed commands drop under TCG load; re-run before believing this."
        echo "  --- tail ---"; tail -25 "$SERIAL" | tr -d '\r'
        exit 3
    fi
done

r() { last4 "$1" | sed -n "$2p"; }
FW_TOT_0=$(r "$FW_TOT_LIST" 1);   FW_TOT_1=$(r "$FW_TOT_LIST" 2)
FW_TOT_2=$(r "$FW_TOT_LIST" 3);   FW_TOT_3=$(r "$FW_TOT_LIST" 4)
FW_DR_0=$(r "$FW_DROP_LIST" 1);   FW_DR_1=$(r "$FW_DROP_LIST" 2)
FW_DR_2=$(r "$FW_DROP_LIST" 3);   FW_DR_3=$(r "$FW_DROP_LIST" 4)
M_0=$(r "$IDS_MATCH_LIST" 1);     M_1=$(r "$IDS_MATCH_LIST" 2)
B_0=$(r "$IDS_BLOCK_LIST" 1);     B_1=$(r "$IDS_BLOCK_LIST" 2)

D_MATCH=$(( M_1 - M_0 ))
D_BLOCK=$(( B_1 - B_0 ))
D_DROP_BLOCKED=$(( FW_DR_2 - FW_DR_1 ))
D_DROP_INNOCENT=$(( FW_DR_3 - FW_DR_2 ))
D_TOT_INNOCENT=$(( FW_TOT_3 - FW_TOT_2 ))

echo ""
echo "================ VERDICT ================"
echo "  leg 1 attack   : IDS matches ${M_0}->${M_1} (delta $D_MATCH), IPs blocked ${B_0}->${B_1} (delta $D_BLOCK)"
echo "  leg 2 blocked  : firewall dropped ${FW_DR_1}->${FW_DR_2} (delta $D_DROP_BLOCKED) of $N_BLOCKED sent"
echo "  leg 3 innocent : firewall dropped ${FW_DR_2}->${FW_DR_3} (delta $D_DROP_INNOCENT) of $N_INNOCENT sent"
echo ""

FAILED=0

# --- LEG 1: the trigger, and the IDS positive control ---------------------
if [ "$D_MATCH" -ge 1 ]; then
    echo "PASS leg 1: the NOP-sled signature matched ($D_MATCH matches)."
else
    echo "FAIL leg 1: signature never matched. ids_inspect_payload() saw no"
    echo "  match, so nothing was blocked and legs 2-3 measure nothing."
    FAILED=1
fi
if [ "$D_BLOCK" -ge 1 ]; then
    echo "PASS leg 1b: the source was blocked ($D_BLOCK IPs blocked)."
else
    echo "FAIL leg 1b: matched but never blocked -- ids_generate_alert() did"
    echo "  not reach firewall_block_ip() (severity < HIGH, or src_ip == 0)."
    FAILED=1
fi

# --- LEG 2: the block leg -------------------------------------------------
# These frames carry NO signature, so the block rule is the only thing that
# can drop them.
if [ "$D_DROP_BLOCKED" -ge "$N_BLOCKED" ]; then
    echo "PASS leg 2: all $N_BLOCKED clean frames from the attacker were dropped."
elif [ "$D_DROP_BLOCKED" -gt 0 ]; then
    echo "FAIL leg 2: only $D_DROP_BLOCKED of $N_BLOCKED dropped -- the block is"
    echo "  not holding for every frame."
    FAILED=1
else
    echo "FAIL leg 2: NONE of $N_BLOCKED clean frames from the blocked source"
    echo "  were dropped. firewall_block_ip()'s rule is losing to the"
    echo "  priority-50 ICMP ACCEPT -- exactly the priority collision the"
    echo "  priority-0 fix exists to close."
    FAILED=1
fi

# --- LEG 3: selectivity ---------------------------------------------------
# Same frame, different source. Must get through.
if [ "$D_DROP_INNOCENT" -eq 0 ] && [ "$D_TOT_INNOCENT" -ge 1 ]; then
    echo "PASS leg 3 (selectivity): frames from the innocent source were"
    echo "  accepted ($D_TOT_INNOCENT counted, 0 dropped) while the attacker"
    echo "  stayed blocked."
elif [ "$D_TOT_INNOCENT" -eq 0 ]; then
    echo "FAIL leg 3: the innocent source's frames never reached the firewall"
    echo "  at all (packets_total did not move). Addressing problem, not a"
    echo "  policy result -- this does NOT show selectivity either way."
    FAILED=1
else
    echo "FAIL leg 3 (selectivity): $D_DROP_INNOCENT frames from a source that"
    echo "  never attacked were dropped. The block is not source-specific --"
    echo "  a firewall that blocks EVERYTHING after an alert passes legs 1-2"
    echo "  perfectly, which is why this leg exists."
    FAILED=1
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "RESULT: PASS"
    echo "  A BLOCK signature match installed a firewall rule that outranks the"
    echo "  boot-time ICMP ACCEPT, dropped every subsequent frame from that"
    echo "  source, and left an unrelated source untouched."
    exit 0
else
    echo "RESULT: FAIL"
    echo "  --- tail ---"; tail -30 "$SERIAL" | tr -d '\r'
    exit 1
fi
