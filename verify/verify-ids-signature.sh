#!/usr/bin/env bash
#
# verify-ids-signature.sh — FULLY AUTOMATED check that the IDS actually compares
# inbound packet payloads against its loaded signatures (AUDIT-8E).
#
# WHAT THIS IS TESTING
#
# The IDS loaded one signature (a six-byte x86 NOP sled, 90 90 90 90 31 c0) and
# reported "Signatures loaded: 1" for as long as the gap existed -- while never
# comparing a single byte of traffic against it. That is the failure mode this
# harness exists to make impossible to reintroduce, and it is a nasty one
# precisely because the system LOOKS defended: every counter moves, packets are
# analyzed, the signature count is right, and nothing is ever detected.
#
# So "the IDS is running" is NOT the assertion. The assertion is that a packet
# carrying the signature bytes moves the MATCH counter, and that one not
# carrying them does not.
#
# WHERE THE MEASUREMENT HAPPENS
#
# At the packet path, not the shell: the fix lives in ids_inspect_payload(),
# called from ids_analyze_packet(), called from handle_ip() in net.c. handle_ip
# runs for every inbound IP frame BEFORE any L4 demultiplexing, so the guest
# does not need a listening socket -- an unsolicited UDP datagram to a closed
# port still traverses the matcher. That is deliberate: binding a socket would
# drag the UDP stack into a test about pattern matching.
#
# `secstatus` is only the readout. It is the one command that surfaces
# stats.signature_matches, which is why the count was added there.
#
# THE PAIRED NEGATIVE (this is the load-bearing half)
#
# "matches >= 1 after sending the sled" is satisfied by an inspector that
# alerts on EVERYTHING -- which is not detection, it is a broken counter, and
# it would pass a positive-only test while making the IDS useless. So the run
# sends TWO datagrams and reads secstatus THREE times:
#
#   secstatus  -> baseline B      (before either packet)
#   send benign payload           (same length, no signature bytes)
#   secstatus  -> N               (MUST still equal B -- the negative control)
#   send sled payload
#   secstatus  -> M               (MUST be > N -- the positive)
#
# Asserting a DELTA rather than a presence matters here: the guest talks to the
# NAT gateway on its own (DHCP, ARP, DNS), so some packets always flow, and a
# bare "matches > 0" could in principle be satisfied by unrelated traffic. B/N/M
# are read from the same counter in one boot, so the deltas are attributable.
#
# WHY THE PACKETS ARE ICMP ECHO REQUESTS, INJECTED ON A MCAST NETDEV
#
# This harness originally sent UDP datagrams through a QEMU `hostfwd` with
# `nc -u`. That vehicle DIED on 2026-08-22 with c5fa987 ("net: default-deny
# firewall"): nothing installs a rule for the test port, firewall_check_packet()
# now refuses it, and net.c:1605 returns one line ABOVE the IDS hook at
# net.c:1615. Both datagrams arrived and both were dropped -- the run reported
# "the NOP-sled packet did NOT move the match counter" while the matcher was
# never handed a byte. The counter readings were 0/0/0 with the firewall's own
# total climbing 0 -> 1 -> 2, all dropped, which is what identified it.
#
# ICMP is the vehicle that survives, and the reason is specific (see CLAUDE.md
# and doc/NETWORK_ISOLATION.md): firewall_allow_icmp() installs a REAL ACCEPT
# rule at priority 50 at boot, so echo requests are admitted by rule rather
# than by exception. The standing DHCP 68->67 exception would also get a frame
# through, but it `return true`s ABOVE match_rule(), which makes it useless
# here. ICMP also creates no connection entry, so established-flow tracking
# cannot short-circuit above the rules either.
#
# ids_analyze_packet() scans the L4 payload after the IP header and is
# protocol-agnostic -- it never inspects ip_hdr->protocol -- so an ICMP echo
# payload reaches ids_inspect_payload() exactly as a UDP one did. The
# assertion is unchanged; only the transport is.
#
# ADDRESSING (the three upstream gates, all of which fail as delta 0):
#
#   - --dst-ip {GIP} is captured from the guest's own ifconfig. On the mcast
#     netdev there is no DHCP server, so the guest self-assigns a per-boot
#     link-local 169.254.x.y -- NOT the 10.0.2.15 the injector defaults to.
#   - The source is TEST-NET-3 (RFC 5737), never RFC1918: is_bogon_ip() drops
#     10/8 and friends above the rule engine.
#
# The DHCP guard the UDP version needed is therefore GONE, replaced by an
# ifconfig address guard: on this netdev a lease is never offered, so waiting
# for one would hang and "Offered IP" would be absent on a perfectly good run.
#
# VALIDATED BOTH WAYS (2026-08-16): see the block at the end of this file.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: idssig.log (serial),
# idssig-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=idssig.log
TRACE=idssig-trace.log
RUN_DISK=/tmp/tinyos-idssig-disk.img
MON_SOCK=/tmp/tinyos-idssig-mon.sock
GUEST_MAC=52:54:00:12:34:56
QEMU_MCAST=230.0.0.2:1235
SRC_IP=203.0.113.9

# The signature from ids_load_default_signatures(): "Shellcode NOP Sled".
# Kept as an explicit byte list rather than a printf escape so that a change to
# the signature table shows up here as an obvious mismatch rather than as a
# mysteriously failing positive.
SLED_HEX=9090909031c0
# Same length, no signature bytes, and deliberately containing 0x90-adjacent
# values (0x8f, 0x91) so a matcher with an off-by-one on the pattern compare
# does not sail through the negative control.
BENIGN_HEX=8f918f9130c1

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1

make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# Prove the ISO carries THIS build. grep -c, not grep -q: under `set -o
# pipefail` grep -q SIGPIPEs `strings` at the first match and the 141 becomes
# the pipeline status, so the staleness guard would fire on a fresh ISO.
# The marker is the new secstatus IDS line, which only this change produces.
ISO_MARKERS=$(strings "$ISO" | grep -c "signatures, %llu matches")
if [ "$ISO_MARKERS" -eq 0 ]; then
    echo "RESULT: INCONCLUSIVE — the ISO predates the AUDIT-8E fix"
    echo "  secstatus's '%u signatures, %llu matches' line is absent, so the"
    echo "  run would report on a kernel with no match counter at all and the"
    echo "  negative control would 'pass' against code that cannot detect."
    exit 3
fi

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
if [ ! -f disk.img ]; then
    echo "ERROR: disk.img not found"
    exit 1
fi
cp disk.img "$RUN_DISK"

echo "==> Launching headless QEMU (monitor on $MON_SOCK, mcast $QEMU_MCAST)"
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

# Host hooks, run by the typist at the ">NAME" steps in the sequence below.
# They fire BETWEEN two secstatus readings rather than racing them, which is
# what makes the before/after deltas attributable to these frames and not to
# the guest's own background traffic.
#
# The sleeps bracket each send so the e1000 RX path can deliver and handle_ip
# can run before the next secstatus snapshots the counter. Generous on purpose:
# this is TCG, and an under-tight wait shows up as an intermittently failing
# POSITIVE -- the worst failure mode for a security harness, because the
# natural reading of it is "the fix is flaky" rather than "the test is".
#
# {GIP} is substituted by the typist with the address captured from ifconfig.
# --count 3 rather than 1: a single frame lost to a full RX ring would fail the
# positive for a reason unrelated to matching. The matcher breaks on first hit
# per signature per packet, so N frames give N matches, and the assertion is
# still a strict delta.
INJ="python3 tools/inject_frames.py --mcast '$QEMU_MCAST' --dst $GUEST_MAC --mode icmp"

export TINYOS_HOOK_BENIGN="sleep 2; $INJ --dst-ip {GIP} --src-ip $SRC_IP \
    --icmp-type 8 --payload-hex $BENIGN_HEX --count 3 >/dev/null 2>&1; sleep 5; true"
export TINYOS_HOOK_SLED="sleep 2; $INJ --dst-ip {GIP} --src-ip $SRC_IP \
    --icmp-type 8 --payload-hex $SLED_HEX --count 3 >/dev/null 2>&1; sleep 5; true"

# This harness stays in the KERNEL shell: secstatus is a kernel-shell command
# (shell_system.c) and has not been migrated to ring 3. That is the correct
# place to measure from -- the counter it reads is kernel state, and routing
# the read through a ring-3 syscall would add a second thing that could be
# broken without telling us anything about pattern matching.
#
#   ifconfig  : capture the guest's self-assigned link-local into {GIP}. There
#               is no DHCP server on a mcast netdev, so this replaces the
#               `dhcp` step the hostfwd version needed.
#   secstatus : BASELINE (B).
#   >BENIGN   : host hook -- injects the benign frames.
#   secstatus : NEGATIVE CONTROL (N). Must equal B.
#   >SLED     : host hook -- injects the NOP-sled frames.
#   secstatus : POSITIVE (M). Must exceed N.
#
# ">NAME" is a typist host-hook step: it runs $TINYOS_HOOK_NAME on the HOST
# instead of typing into the guest (see tools/qemu_typist.py). The guest cannot
# generate this traffic itself -- asking it to send itself attack bytes would
# be testing the transmit path, not the inspector.
#
# The expect is "Security Status" rather than the full "=== TinyOS Security
# Status ===" banner: the '===' would have to survive shell quoting and the
# typist's own splitting for no benefit, and the short form is already unique
# to secstatus.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=900 \
TINYOS_EXEC_CMD="secstatus" \
TINYOS_EXPECT="Security Status" \
TINYOS_FOLLOWUP_CMDS="\
ifconfig=>IP Address:@GIP=IP Address: +([0-9.]+);\
secstatus=>Security Status;\
>BENIGN;\
secstatus=>Security Status;\
>SLED;\
secstatus=>Security Status" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: FAIL — no serial output at all (typist rc=$TYPIST_RC)"
    exit 2
fi

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    echo "  --- firewall readings (hint 1 above) ---"
    grep -a "Firewall \.\+" "$SERIAL" | tr -d '\r'
    echo "  --- last 40 serial lines ---"
    tail -40 "$SERIAL"
    exit 1
}

# --- Guard: the guest actually has an address ----------------------------
#
# Without an address handle_ip()'s destination gate drops the injected frames,
# every reading is zero, and the negative control passes trivially while the
# positive fails for a reason that has nothing to do with pattern matching.
# Distinguishing those two situations is the entire point of this guard.
#
# NOT "Offered IP": on the mcast netdev there is no DHCP server and no lease is
# ever offered, so the old check would fire on a perfectly good run.
if ! grep -qa "IP Address:" "$SERIAL"; then
    echo "RESULT: INCONCLUSIVE — the guest never reported an address"
    echo "  No 'IP Address:' in the serial log, so the injected frames could"
    echo "  not have cleared handle_ip()'s destination gate and neither"
    echo "  reading means anything."
    exit 3
fi

# --- Extract the three match counts in order -----------------------------
#
# The secstatus IDS line reads:
#   IDS ................. 1 signatures, 0 matches, 0 alerts, 0 IPs blocked
# Anchoring on "signatures, N matches" rather than a column position keeps this
# working if a field is added to either side of it later.
#
# TAIL-anchored to the LAST THREE: TINYOS_EXEC_CMD is itself a secstatus, so
# there are FOUR readings in the log and a head-anchored parser would compare
# two pre-injection baselines against the benign one -- the exact mistake
# verify-udp-rx-counters.sh made. Do not add another secstatus without
# updating this.
#
# NOT `mapfile`: this runs under macOS's bash 3.2, where mapfile does not
# exist. It is not a syntax error either -- bash reports "command not found",
# leaves the array EMPTY, and with `set -u` unset the script would then compare
# empty strings and fail in a way that reads like a broken fix.
MATCH_ALL=$(grep -a "signatures, .* matches" "$SERIAL" \
             | sed -n 's/.*signatures, \([0-9][0-9]*\) matches.*/\1/p')
MATCH_COUNT=$(printf '%s\n' "$MATCH_ALL" | grep -c '[0-9]')

if [ "$MATCH_COUNT" -lt 4 ]; then
    fail_with "expected 4 secstatus readings, got $MATCH_COUNT" \
        "The command sequence did not complete, so there is no baseline to" \
        "compare against. Readings seen: ${MATCH_ALL:-none}"
fi

MATCH_LIST=$(printf '%s\n' "$MATCH_ALL" | grep '[0-9]' | tail -3)

B=$(printf '%s\n' "$MATCH_LIST" | sed -n '1p')
N=$(printf '%s\n' "$MATCH_LIST" | sed -n '2p')
M=$(printf '%s\n' "$MATCH_LIST" | sed -n '3p')
echo "  match counter: baseline=$B  after-benign=$N  after-sled=$M"

# --- The negative control ------------------------------------------------
#
# Checked BEFORE the positive on purpose: if this fails, the positive below is
# meaningless (a matcher that fires on everything would satisfy it), and
# reporting "the IDS detects shellcode!" from such a run would be worse than
# reporting nothing.
if [ "$N" -ne "$B" ]; then
    fail_with "the benign packet moved the match counter ($B -> $N)" \
        "ids_inspect_payload() matched a payload containing none of the" \
        "signature bytes. Either the bounds are wrong (a pattern_len that" \
        "reads past the payload can match anything) or the compare is not" \
        "comparing what it claims to. The positive assertion below is" \
        "meaningless while this holds, so it was not evaluated."
fi

# --- The positive --------------------------------------------------------
if [ "$M" -le "$N" ]; then
    fail_with "the NOP-sled packet did NOT move the match counter ($N -> $M)" \
        "A datagram whose payload is exactly signatures[0].pattern reached the" \
        "guest and produced no match. This is AUDIT-8E itself: signatures are" \
        "loaded and reported but never compared against traffic." \
        "Check in this order:" \
        "  1. did the firewall drop the frame before the IDS hook? net.c:1605" \
        "     returns one line ABOVE the IDS call at net.c:1615, and this is" \
        "     what killed the previous UDP vehicle. Read the Firewall line in" \
        "     the tail below: a total that climbs while 'dropped' climbs with" \
        "     it means the matcher was never handed a byte, and the ICMP" \
        "     ACCEPT rule (priority 50) is gone or outranked." \
        "  2. is ids_inspect_payload() called at the end of ids_analyze_packet()?" \
        "  3. did the frames reach the guest at all? A zero Firewall total" \
        "     means they died at handle_ip's address gate or is_bogon_ip()."
fi

# --- The alert actually fired -------------------------------------------
#
# The counter and the alert are separate paths: a match that increments
# stats.signature_matches but never calls ids_generate_alert() would satisfy
# both assertions above while producing an IDS that detects silently -- which
# operationally is not detecting.
if ! grep -qa "IDS ALERT\|Shellcode\|NOP" "$SERIAL"; then
    fail_with "the match produced no alert" \
        "signature_matches moved ($N -> $M) but nothing resembling an alert" \
        "reached the log, so ids_generate_alert() is not being called on a" \
        "hit. A silent detection is not a detection."
fi

echo "RESULT: PASS"
echo "  benign payload: no match ($B -> $N), sled payload: matched ($N -> $M),"
echo "  and the hit generated an alert."
exit 0

# VALIDATION LOG
#
# 2026-08-16, UDP/hostfwd vehicle, both ways. All three runs were real.
#   PASS as written:  baseline=0  after-benign=0  after-sled=1
#   (Superseded: that vehicle no longer reaches the IDS at all -- see below.)
#
# 2026-08-22: FAILED as "the NOP-sled packet did NOT move the match counter",
# baseline=0 after-benign=0 after-sled=0, with the firewall total climbing
# 0 -> 1 -> 2 and ALL dropped. Root cause was c5fa987 (default-deny firewall,
# landed 2026-08-22, six days after the validation above): nothing installs a
# rule for the test UDP port, so firewall_check_packet() refused both datagrams
# at net.c:1605, one line above the IDS hook at net.c:1615. NOT a kernel
# defect -- verify-ids-block-leg.sh drove the IDENTICAL signature (9090909031c0)
# over ICMP in the same batch and got 0 -> 1 matches, 1 alerts, independently
# proving the matcher, the alert path and the counter all work.
#
# Migrated to the ICMP/mcast vehicle on 2026-08-22 for the reasons in the
# header block.
