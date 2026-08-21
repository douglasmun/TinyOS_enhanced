#!/bin/bash
# =============================================================================
# verify-dhcp-rx-counters.sh -- handle_dhcp()'s RX counters, driven remotely.
#
# WHAT THIS PROVES
#
# handle_dhcp() (src/dhcp.c) sits on the firewall-EXEMPT inbound path: ports
# 67/68 are allowed above the bogon filter and above any rule lookup, because
# a host without a lease has no address to filter on. That exemption is what
# makes these counters interesting -- the frames reach the parser regardless
# of firewall state, so every site is remote-driven and must be counted, never
# printed (doc/NETWORK_ISOLATION.md).
#
#   dhcp_drop_short   -- tested FIRST, before the op and xid checks, so ANY
#                        host on the segment drives it with a truncated frame.
#                        Genuinely remote-driven.
#   dhcp_drop_cookie  -- NOT equally reachable, and that asymmetry is the
#                        point of this harness. It sits behind an
#                        op==BOOTREPLY test and an xid match against the
#                        guest's own in-flight transaction, so it is a
#                        same-segment RACE signal, not an off-path one.
#   dhcp_replies_ok   -- the POSITIVE CONTROL. Incremented on a valid
#                        BOOTREPLY for our xid, immediately BEFORE the cookie
#                        test -- so a frame that reaches the cookie counter
#                        has already moved this one. That ordering is load-
#                        bearing for leg 3 below.
#
# WHY THE XID IS READ FROM THE GUEST, NEVER GUESSED
#
# dhcp_client.xid comes from csprng_random_bytes() (src/dhcp.c:80). A guessed
# value does not fail loudly -- it vanishes into the silent-ignore arm at
# src/dhcp.c:415, well before the cookie test, and the leg then measures
# NOTHING while still looking like it ran. So the host hook scrapes the xid
# out of the guest's own serial log, which prints it on every DHCP send
# ("[DHCP] Sent DISCOVER (XID: 0x...)", src/dhcp.c:343), and refuses to inject
# if it cannot find one. An unreachable leg must be INCONCLUSIVE, not a pass.
#
# HOW THE FRAMES ARE SENT
#
# A `socket,mcast=` netdev, same as verify-rxdrop-counters.sh: bytes written
# to the group land on the guest's wire verbatim. This netdev has NO NAT, so
# the guest never gets a real lease -- it retransmits DISCOVER and stays in
# SELECTING with a live xid, which is exactly the state this harness needs.
# A user-mode NAT netdev would hand out a lease, move the client to BOUND, and
# the injected replies would be ignored as stale. Do not "fix" the missing
# lease.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: dhcprx.log (serial), dhcprx-trace.log.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=dhcprx.log
TRACE=dhcprx-trace.log
RUN_DISK=/tmp/tinyos-dhcprx-disk.img
MON_SOCK=/tmp/tinyos-dhcprx-mon.sock

# Distinct counts per attacker position, so no single miscounted site can
# satisfy two assertions at once.
N_SHORT=9          # truncated below the 240-byte header -> drop_short
N_COOKIE=5         # valid xid, corrupted magic cookie   -> drop_cookie

GUEST_MAC=52:54:00:12:34:56
QEMU_MCAST=230.0.0.1:1234

# ---------------------------------------------------------------------------
# SOURCE GUARD
# ---------------------------------------------------------------------------
guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

grep -q "dhcp_replies_ok" src/dhcp.c \
    || guard_fail "src/dhcp.c has no dhcp_replies_ok counter; tree predates the fix.
  Without the positive control, the drop legs pass identically against a
  handle_dhcp() that refuses every frame."
grep -q "dhcp_drop_short" src/dhcp.c \
    || guard_fail "src/dhcp.c has no dhcp_drop_short counter; tree predates the fix"
grep -q "dhcp_drop_cookie" src/dhcp.c \
    || guard_fail "src/dhcp.c has no dhcp_drop_cookie counter; tree predates the fix"
grep -q "DHCP rx:" src/shell_network.c \
    || guard_fail "ifconfig does not surface the DHCP counters (shell_network.c)"

# The xid print this harness scrapes must still exist. If it is ever removed
# the cookie leg becomes unreachable, and it must say so rather than quietly
# measuring nothing.
grep -q "XID:" src/dhcp.c \
    || guard_fail "src/dhcp.c no longer prints the transaction ID, so the host
  hook cannot learn the in-flight xid. The cookie leg would be unreachable and
  would silently read delta 0 -- which is what a BROKEN counter reads too."

command -v python3 >/dev/null 2>&1 || guard_fail "python3 not found"
[ -f tools/inject_frames.py ] || guard_fail "tools/inject_frames.py is missing"
python3 tools/inject_frames.py --help 2>&1 | grep -q "dhcp-xid" \
    || guard_fail "tools/inject_frames.py has no DHCP mode (--dhcp-xid)"

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

ISO_MARKERS=$(strings "$ISO" | grep -c "replies")
if [ "$ISO_MARKERS" -eq 0 ]; then
    guard_fail "the ISO predates the fix (ifconfig's DHCP line is absent)"
fi

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

echo "==> Launching headless QEMU (monitor $MON_SOCK, mcast socket $QEMU_MCAST)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev socket,id=net0,mcast="$QEMU_MCAST" \
    -device e1000,netdev=net0,mac=$GUEST_MAC \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# The host hook, written to a file because it is too long to keep readable in
# an env var -- and because the ';' separator in TINYOS_FOLLOWUP_CMDS would
# tear an inline version into fragments.
#
# It scrapes the LAST xid the guest printed. Last, not first: dhcp_start()
# generates a fresh xid on every retransmit, and an early one is stale by the
# time the frames land -- a stale xid is silently ignored, so this would
# under-report with no error anywhere.
HOOK=/tmp/tinyos-dhcprx-hook.sh
cat > "$HOOK" <<HOOKEOF
#!/bin/bash
set -uo pipefail
cd "$(pwd)"
sleep 3

XID=\$(grep -a "XID:" "$SERIAL" | tail -1 \
      | sed -n 's/.*XID: \(0x[0-9a-fA-F][0-9a-fA-F]*\).*/\1/p')

INJ="python3 tools/inject_frames.py --mcast $QEMU_MCAST --dst $GUEST_MAC"

# The truncated leg needs no xid: drop_short is tested before the xid match.
\$INJ --mode dhcp --dhcp-truncate --count $N_SHORT >/dev/null 2>&1

if [ -z "\$XID" ]; then
    # Do NOT silently skip. An unreachable leg that reads delta 0 is
    # indistinguishable from a broken counter.
    echo "HOOK-ERROR: no XID found in $SERIAL; cookie leg unreachable" \
        > /tmp/tinyos-dhcprx-hook.err
else
    echo "HOOK-XID: \$XID" > /tmp/tinyos-dhcprx-hook.err
    \$INJ --mode dhcp --dhcp-xid "\$XID" --dhcp-bad-cookie \
         --count $N_COOKIE >/dev/null 2>&1
fi

sleep 6
exit 0
HOOKEOF
chmod +x "$HOOK"
rm -f /tmp/tinyos-dhcprx-hook.err
export TINYOS_HOOK_DHCPINJ="$HOOK"

TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="DHCP rx:" \
TINYOS_FOLLOWUP_CMDS="\
>DHCPINJ;\
ifconfig=>DHCP rx:" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"

[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

if [ -f /tmp/tinyos-dhcprx-hook.err ]; then
    echo "  hook: $(cat /tmp/tinyos-dhcprx-hook.err)"
fi

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    echo "  --- DHCP rx lines seen ---"
    grep -a "DHCP rx:" "$SERIAL"
    exit 1
}

# The ifconfig line reads:
#   DHCP rx:      2 replies, 0 short, 0 cookie
# Anchored per field name; `^[0-9]+` because the number PRECEDES the name.
extract() { grep -aoE "[0-9]+ $1" "$SERIAL" | grep -oE "^[0-9]+"; }
OK_LIST=$(extract "replies")
SHORT_LIST=$(extract "short")
COOKIE_LIST=$(extract "cookie")

nth() { printf '%s\n' "$2" | sed -n "$1p"; }
COUNT=$(printf '%s\n' "$SHORT_LIST" | grep -c '[0-9]')
if [ "$COUNT" -lt 2 ]; then
    fail_with "expected 2 ifconfig readings, got $COUNT" \
        "The command sequence did not complete, so there is no baseline."
fi

OK_B=$(nth 1 "$OK_LIST");         OK_A=$(nth 2 "$OK_LIST")
SH_B=$(nth 1 "$SHORT_LIST");      SH_A=$(nth 2 "$SHORT_LIST")
CK_B=$(nth 1 "$COOKIE_LIST");     CK_A=$(nth 2 "$COOKIE_LIST")
OK_D=$((OK_A - OK_B)); SH_D=$((SH_A - SH_B)); CK_D=$((CK_A - CK_B))

echo "  replies : $OK_B -> $OK_A  (delta $OK_D)"
echo "  short   : $SH_B -> $SH_A  (delta $SH_D, expected $N_SHORT)"
echo "  cookie  : $CK_B -> $CK_A  (delta $CK_D, expected $N_COOKIE)"

# --- Leg 1: truncated frames, exact, and reachable by ANY host ------------
if [ "$SH_D" -ne "$N_SHORT" ]; then
    fail_with "short delta $SH_D != $N_SHORT" \
        "A frame below the 240-byte DHCP header is rejected before the op and" \
        "xid tests, so this leg needs no knowledge of guest state -- any host" \
        "on the segment drives it. An inexact delta means the length test is" \
        "missing or counting per interrupt rather than per frame."
fi
echo "PASS leg 1: truncated frames counted, exactly once each."

# --- Leg 2: bad cookie, exact ---------------------------------------------
#
# Reaching this counter at all is the interesting part: it required a live
# xid scraped from the guest. A delta of 0 here most often means the xid was
# stale, NOT that the counter is broken -- the message says so, because a
# harness that misattributes its own unreachability wastes a debugging cycle
# on correct kernel code.
if [ "$CK_D" -ne "$N_COOKIE" ]; then
    fail_with "cookie delta $CK_D != $N_COOKIE" \
        "This counter sits behind an op==BOOTREPLY test and an xid match. If" \
        "the delta is 0, check the hook line above: a stale or missing xid" \
        "makes the frames vanish into the silent-ignore arm at dhcp.c:415," \
        "which reads exactly like a broken counter but is not one."
fi
echo "PASS leg 2: bad-cookie frames counted, exactly once each."

# --- Leg 3: POSITIVE CONTROL, and it is structural ------------------------
#
# dhcp_replies_ok is incremented immediately BEFORE the cookie test, so every
# frame that reached the cookie counter must also have moved this one. That
# makes replies >= N_COOKIE a control the drop counters cannot fake: a
# handle_dhcp() that refused everything would show cookie 0 too, and a
# handle_dhcp() that accepted everything would show cookie 0 with replies
# high. Only a parser that validates in the right ORDER shows both.
if [ "$OK_D" -lt "$N_COOKIE" ]; then
    fail_with "replies rose by only $OK_D, expected >= $N_COOKIE" \
        "dhcp_replies_ok is incremented just before the cookie test, so every" \
        "frame counted as bad-cookie must have passed through it. Seeing" \
        "cookie +$CK_D but replies +$OK_D means the two counters disagree" \
        "about the same frames, which points at the validation ORDER rather" \
        "than at either counter."
fi
echo "PASS leg 3 (positive control): replies +$OK_D covers the $CK_D cookie drops."

# --- Leg 4: SELECTIVITY ---------------------------------------------------
#
# The truncated frames must NOT have reached the cookie counter, and the
# bad-cookie frames must NOT have been counted as short. Distinct expected
# values make a shared counter impossible to hide.
if [ "$SH_D" -eq "$CK_D" ] && [ "$N_SHORT" -ne "$N_COOKIE" ]; then
    fail_with "short and cookie moved by the same amount ($SH_D)" \
        "$N_SHORT truncated and $N_COOKIE bad-cookie frames were sent --" \
        "different numbers on purpose. Equal deltas mean one counter is" \
        "counting both signatures, and one 'dropped' total hides which" \
        "attack is underway."
fi
echo "PASS leg 4 (selectivity): the two signatures land on separate counters."

# --- Leg 5: console silence -----------------------------------------------
TOTAL_SENT=$((N_SHORT + N_COOKIE))
for dead in "Received packet (" "Invalid magic cookie" "DHCP packet too short" \
            "Dropping DHCP"; do
    HITS=$(grep -ca "$dead" "$SERIAL")
    if [ "$HITS" -ne 0 ]; then
        fail_with "the console printed \"$dead\" $HITS time(s)" \
            "DHCP is firewall-EXEMPT inbound, so these frames reach the parser" \
            "regardless of firewall state. $TOTAL_SENT frames produced $HITS" \
            "console lines, and a remote host sets that rate."
    fi
done
echo "PASS leg 5: $TOTAL_SENT injected frames produced 0 console lines."

echo ""
echo "RESULT: PASS"
echo "  short +$SH_D, cookie +$CK_D, replies +$OK_D, console +0."
echo "  Both signatures are counted separately, the cookie path was reached"
echo "  with a live xid, and the remote flood path is closed."
exit 0
