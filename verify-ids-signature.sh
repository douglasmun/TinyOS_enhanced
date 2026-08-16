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
# WHY THE PACKETS ARE SENT WITH `nc -u` FROM THE HOST
#
# QEMU user-mode NAT has no inbound path to the guest without an explicit
# hostfwd, so this run adds `hostfwd=udp::$UDP_PORT-:9999`. The guest must have
# an address first, hence the `dhcp` in the command sequence -- without it the
# frame is dropped before handle_ip and both halves of the test read zero,
# which is a PASS-shaped failure for the negative control and a FAIL for the
# positive. The DHCP guard below exists for exactly that reason.
#
# VALIDATED BOTH WAYS (2026-08-16): see the block at the end of this file.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: idssig.log (serial),
# idssig-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=idssig.log
TRACE=idssig-trace.log
RUN_DISK=/tmp/tinyos-idssig-disk.img
MON_SOCK=/tmp/tinyos-idssig-mon.sock
UDP_PORT=${TINYOS_IDS_UDP_PORT:-15999}

# The signature from ids_load_default_signatures(): "Shellcode NOP Sled".
# Kept as an explicit byte list rather than a printf escape so that a change to
# the signature table shows up here as an obvious mismatch rather than as a
# mysteriously failing positive.
SLED_BYTES='\x90\x90\x90\x90\x31\xc0'
# Same length, no signature bytes, and deliberately containing 0x90-adjacent
# values (0x8f, 0x91) so a matcher with an off-by-one on the pattern compare
# does not sail through the negative control.
BENIGN_BYTES='\x8f\x91\x8f\x91\x30\xc1'

command -v nc >/dev/null 2>&1 || {
    echo "RESULT: INCONCLUSIVE — nc(1) not found; this harness needs it to"
    echo "  inject the test datagrams."
    exit 3
}

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

echo "==> Launching headless QEMU (monitor on $MON_SOCK, udp hostfwd $UDP_PORT)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0,hostfwd=udp::"$UDP_PORT"-:9999 \
    -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# Host hooks, run by the typist at the ">NAME" steps in the sequence below.
# They fire BETWEEN two secstatus readings rather than racing them, which is
# what makes the before/after deltas attributable to these packets and not to
# the guest's own background NAT traffic.
#
# The sleeps bracket each send so the e1000 RX path can deliver and handle_ip
# can run before the next secstatus snapshots the counter. Generous on purpose:
# this is TCG, and an under-tight wait shows up as an intermittently failing
# POSITIVE -- the worst failure mode for a security harness, because the
# natural reading of it is "the fix is flaky" rather than "the test is".
#
# Each ends in `true`: `nc -u -w1` exits nonzero on some platforms even when
# the datagram went out (there is nothing to connect to and nothing to read
# back), and the typist treats a nonzero hook as fatal -- correctly, since a
# hook that did not fire leaves the following assertion measuring nothing. The
# proof that the packet arrived is the counter delta, not nc's exit status.
export TINYOS_HOOK_BENIGN="sleep 2; printf '$BENIGN_BYTES' | nc -u -w1 127.0.0.1 $UDP_PORT >/dev/null 2>&1; sleep 4; true"
export TINYOS_HOOK_SLED="sleep 2; printf '$SLED_BYTES' | nc -u -w1 127.0.0.1 $UDP_PORT >/dev/null 2>&1; sleep 4; true"

# This harness stays in the KERNEL shell: secstatus is a kernel-shell command
# (shell_system.c) and has not been migrated to ring 3. That is the correct
# place to measure from -- the counter it reads is kernel state, and routing
# the read through a ring-3 syscall would add a second thing that could be
# broken without telling us anything about pattern matching.
#
#   dhcp      : the guest needs 10.0.2.15 before any inbound frame reaches
#               handle_ip. Guarded below -- without a lease both readings are
#               zero, which the negative control would happily call a pass.
#   secstatus : BASELINE (B).
#   >BENIGN   : host hook -- sends the benign datagram.
#   secstatus : NEGATIVE CONTROL (N). Must equal B.
#   >SLED     : host hook -- sends the NOP-sled datagram.
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
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="dhcp" \
TINYOS_EXPECT="Offered IP" \
TINYOS_FOLLOWUP_CMDS="\
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
    echo "  --- last 40 serial lines ---"
    tail -40 "$SERIAL"
    exit 1
}

# --- Guard: the guest actually has an address ----------------------------
#
# Without a lease the injected datagrams never reach handle_ip, every reading
# is zero, and the negative control passes trivially while the positive fails
# for a reason that has nothing to do with pattern matching. Distinguishing
# those two situations is the entire point of this guard.
if ! grep -qa "Offered IP" "$SERIAL"; then
    echo "RESULT: INCONCLUSIVE — the guest never got a DHCP lease"
    echo "  No 'Offered IP' in the serial log, so the injected packets could"
    echo "  not have reached handle_ip() and neither reading means anything."
    exit 3
fi

# --- Extract the three match counts in order -----------------------------
#
# The secstatus IDS line reads:
#   IDS ................. 1 signatures, 0 matches, 0 alerts, 0 IPs blocked
# Anchoring on "signatures, N matches" rather than a column position keeps this
# working if a field is added to either side of it later.
# NOT `mapfile`: this runs under macOS's bash 3.2, where mapfile does not
# exist. It is not a syntax error either -- bash reports "command not found",
# leaves the array EMPTY, and with `set -u` unset the script would then compare
# empty strings and fail in a way that reads like a broken fix.
MATCH_LIST=$(grep -a "signatures, .* matches" "$SERIAL" \
             | sed -n 's/.*signatures, \([0-9][0-9]*\) matches.*/\1/p')
MATCH_COUNT=$(printf '%s\n' "$MATCH_LIST" | grep -c '[0-9]')

if [ "$MATCH_COUNT" -lt 3 ]; then
    fail_with "expected 3 secstatus readings, got $MATCH_COUNT" \
        "The command sequence did not complete, so there is no baseline to" \
        "compare against. Readings seen: ${MATCH_LIST:-none}"
fi

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
        "  1. is ids_inspect_payload() called at the end of ids_analyze_packet()?" \
        "  2. did the firewall drop the datagram before the IDS hook in" \
        "     handle_ip()? (the IDS check sits AFTER firewall_check_packet)" \
        "  3. did the payload survive NAT to arrive byte-identical?"
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

# VALIDATION LOG — both ways, 2026-08-16. All three runs were real.
#
# PASS as written:  baseline=0  after-benign=0  after-sled=1
#
# NEGATIVE VALIDATION #1 -- the fix is what makes it pass. The
# `return ids_inspect_payload(...)` at the end of ids_analyze_packet() was
# replaced with `return true;`, i.e. the pre-fix AUDIT-8E state. Result:
#   baseline=0  after-benign=0  after-sled=0
#   FAIL — the NOP-sled packet did NOT move the match counter (0 -> 0)
# It failed on the positive and NOT on the negative control, which is the
# discrimination that matters: the harness fails for the right reason, and only
# when the matcher is actually absent.
#
# (Note for anyone repeating this: a bare `return true;` will not COMPILE --
# -Werror=unused-function then fires on ids_inspect_payload. Keep a dead
# reference, e.g. `if (0) { (void)ids_inspect_payload(...); }`, or the negative
# validation stops at the build and never reaches the assertion it was meant to
# exercise.)
#
# NEGATIVE VALIDATION #2 -- the negative control can actually fire. The compare
# was forced to always match (`if (0 && memcmp(...) != 0)`). Result:
#   baseline=0  after-benign=1  after-sled=2
#   FAIL — the benign packet moved the match counter (0 -> 1)
# and it reported that the positive was not evaluated. Without this second run
# a negative control that could never fail would be indistinguishable from one
# that works -- which is the AUDIT-8E lesson restated at the level of the test.
