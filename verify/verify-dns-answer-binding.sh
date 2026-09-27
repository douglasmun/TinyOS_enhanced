#!/bin/bash
#==============================================================================
# verify-dns-answer-binding.sh — an A record is used only if it answers the
# question asked
#==============================================================================
#
# WHAT THIS IS TESTING (network audit finding 6)
#
# handle_dns_response() checked the question section and then took the FIRST
# A record in the answer section, whatever name it was for and whatever its
# class. A response that cleared every binding check (source, port, TID,
# question) could therefore hand over an address for some other name, or a
# CHAOS-class record, and have it used as the answer. Now an A record must be
# class IN and owned by the queried name or the end of a CNAME chain starting
# at it; a response whose only A records fail that lands on "answer-mismatch".
#
# METHOD
#
# `dnsforge` (TINYOS_FAULT_INJECT) builds a response that passes every other
# check and varies the answer section only. Every forged address is in
# 203.0.113.0/24, and after each injection the forger prints the address the
# resolver now holds, so an accepted forgery is witnessed directly, not only
# through a counter.
#
#   dig example.com         a real resolution first: the forger echoes its
#                           name and TID, and the held address is the real one
#   dnsforge ansname        x.<qname> A 203.0.113.8          -> refused
#   dnsforge ansclass       <qname> A, CLASS CH              -> refused
#   dnsforge cnamebad       <qname> CNAME x.<qname>,
#                           y.<qname> A 203.0.113.8           -> refused
#   dnsforge cname          <qname> CNAME x.<qname>,
#                           x.<qname> A 203.0.113.8           -> ACCEPTED
#
# `cname` is the positive control, and the only one that matters: a resolver
# that refused every answer, or never followed a CNAME, passes all three
# refusal legs. Without it CNAME'd names (most of the web) would stop
# resolving while this harness reported PASS.
#
# Legs:
#   1  after each refused case the held address is NOT in 203.0.113.0/24
#   2  resolved pinned across the refused cases; answer-mismatch +3 exactly;
#      no-answer pinned (selectivity: a mismatch is not an empty answer)
#   3  cname: held address is 203.0.113.8; resolved +1; answer-mismatch pinned
#
# VALIDATION LOG (filled in from actual runs, not written in advance)
#
#   2026-09-28, QEMU 11.1.1 TCG, -netdev user:
#   - fixed tree: PASS. resolved 1 -> 1 -> 2, answer-mismatch 0 -> 3 -> 3,
#     no-answer 0 -> 0; the refused cases left the real dig answer held and
#     cname held 203.0.113.8.
#   - owner/class binding disabled (the unfixed behaviour, first A taken):
#     FAIL, 5 legs -- all three forgeries' addresses held, resolved +3.
#   - negative control, class check removed (name check kept): FAIL, exactly
#     ansclass accepted and answer-mismatch +2.
#   - negative control, CNAME following removed: FAIL on exactly the positive
#     control (cname refused, counted as a mismatch).
#
# Exit: 0 PASS, 1 FAIL, 2 no serial, 3 INCONCLUSIVE.
#==============================================================================
set -uo pipefail

note() { echo "$@"; }
guard_fail() { note "GUARD: $1"; note "RESULT: INCONCLUSIVE"; exit 3; }

cd "$(dirname "$0")/.."

grep -q '"cnamebad"' src/dns.c \
    || guard_fail "dnsforge has no answer-section cases; tree predates the harness"
grep -q "dnsforge" src/shell.c || guard_fail "the dnsforge command is gone from shell.c"

note "== Building with -DTINYOS_FAULT_INJECT =="
make clean >/dev/null 2>&1
BUILD_LOG="$(mktemp -t dnsans-build.XXXXXX)"
if ! make -j8 EXTRA_CFLAGS=-DTINYOS_FAULT_INJECT kernel.elf >"$BUILD_LOG" 2>&1; then
    tail -20 "$BUILD_LOG"; rm -f "$BUILD_LOG"
    guard_fail "build failed"
fi
rm -f "$BUILD_LOG"
cp kernel.elf iso/boot/kernel.elf 2>/dev/null || guard_fail "cannot stage kernel.elf"
i686-elf-grub-mkrescue -o dist/tinyos.iso iso >/dev/null 2>&1 \
    || guard_fail "grub-mkrescue failed (need xorriso)"

WORK=$(mktemp -d -t dnsans.XXXXXX)
SERIAL="$WORK/serial.log"
. "$(dirname "${BASH_SOURCE[0]}")/preserve-serial.sh"
MON_SOCK="$WORK/mon.sock"
PASSWORD="${TINYOS_PASSWORD:-rootpass123}"

qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso \
    -boot d -m 256M \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -display none &
QEMU_PID=$!
cleanup_qemu() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; }
# make clean on EXIT: EXTRA_CFLAGS is not in the dependency graph (see
# verify-dns-rx-counters.sh).
trap 'rc=$?; cleanup_qemu; preserve_serial "$SERIAL" "" "$rc"; rm -rf "$WORK"; make clean >/dev/null 2>&1' EXIT

TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=900 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="DNS rx:" \
TINYOS_FOLLOWUP_CMDS="!dig example.com;ifconfig=>DNS rx:;dnsforge ansname=>dnsforge ansname injected;dnsforge ansclass=>dnsforge ansclass injected;dnsforge cnamebad=>dnsforge cnamebad injected;ifconfig=>DNS rx:;dnsforge cname=>dnsforge cname injected;ifconfig=>DNS rx:" \
python3 tools/qemu_typist.py >/dev/null 2>&1
TYPIST_RC=$?

sleep 3
cleanup_qemu

if [ ! -s "$SERIAL" ]; then
    note "  no serial output (typist rc=$TYPIST_RC)"
    note "RESULT: FAIL (boot/output failure, not an assertion failure)"
    exit 2
fi

LOG="$(tr -d '\r' < "$SERIAL")"
nth_rx() { printf '%s\n' "$LOG" | grep -o "DNS rx:.*" | sed -n "${1}p"; }
field()  { nth_rx "$1" | sed -E "s/.*[^0-9]([0-9]+) $2.*/\1/"; }
held()   { printf '%s\n' "$LOG" | sed -n "s/.*dnsforge $1 holds \([0-9.]*\).*/\1/p" | tail -1; }

READINGS=$(printf '%s\n' "$LOG" | grep -c "DNS rx:")
note ""
note "== DNS rx readings: $READINGS =="
printf '%s\n' "$LOG" | grep -o "DNS rx:.*" | sed 's/^/    /'
printf '%s\n' "$LOG" | grep -o "dnsforge [a-z]* holds.*" | sed 's/^/    /'

# 1 = boot, 2 = after dig, 3 = after the refused cases, 4 = after cname.
[ "$READINGS" -ge 4 ] || { note "RESULT: INCONCLUSIVE — expected 4 ifconfig readings, got $READINGS (typist rc=$TYPIST_RC)"; exit 3; }

FAILS=()
num() { case "${1:-}" in ''|*[!0-9]*) return 1;; esac; }

# --- Leg 1: nothing refused was taken -------------------------------------
for c in ansname ansclass cnamebad; do
    h=$(held "$c")
    note "  held after $c: ${h:-<none>}"
    case "$h" in
        203.0.113.*) FAILS+=("dnsforge $c: the resolver took the forged address $h") ;;
        "")          FAILS+=("dnsforge $c: no 'holds' line; did the real dig resolve?") ;;
    esac
done

# --- Leg 2: counters across the refused cases -----------------------------
OK2=$(field 2 resolved); OK3=$(field 3 resolved); OK4=$(field 4 resolved)
NA2=$(field 2 no-answer); NA3=$(field 3 no-answer)
MM2=$(field 2 answer-mismatch); MM3=$(field 3 answer-mismatch); MM4=$(field 4 answer-mismatch)
note "  resolved $OK2 -> $OK3 -> $OK4; no-answer $NA2 -> $NA3; answer-mismatch $MM2 -> $MM3 -> $MM4"
if ! num "$OK2" || ! num "$OK3" || ! num "$OK4" || ! num "$NA2" || ! num "$NA3"; then
    FAILS+=("resolved/no-answer counters unreadable")
else
    [ "$OK3" -eq "$OK2" ] || FAILS+=("resolved rose $OK2 -> $OK3 across the refused cases: a forged answer was ACCEPTED")
    [ "$NA3" -eq "$NA2" ] || FAILS+=("no-answer moved $NA2 -> $NA3: mismatches are being counted as empty answers")
    [ "$OK4" -eq $((OK3 + 1)) ] || FAILS+=("resolved went $OK3 -> $OK4 across dnsforge cname, expected +1 (positive control)")
fi
if ! num "$MM2" || ! num "$MM3" || ! num "$MM4"; then
    FAILS+=("ifconfig has no answer-mismatch counter")
else
    [ "$MM3" -eq $((MM2 + 3)) ] || FAILS+=("answer-mismatch went $MM2 -> $MM3, expected exactly +3")
    [ "$MM4" -eq "$MM3" ] || FAILS+=("answer-mismatch moved $MM3 -> $MM4 on the valid CNAME chain")
fi

# --- Leg 3: the CNAME chain resolves --------------------------------------
H=$(held cname)
note "  held after cname: ${H:-<none>} (expected 203.0.113.8)"
[ "$H" = "203.0.113.8" ] || FAILS+=("dnsforge cname: held ${H:-nothing}, expected 203.0.113.8 -- CNAME chains no longer resolve (positive control)")

note ""
if [ ${#FAILS[@]} -eq 0 ]; then
    note "RESULT: PASS — answers for another name, another class, or off the CNAME"
    note "  chain were refused and counted; the CNAME chain resolved"
    exit 0
fi
note "RESULT: FAIL — ${#FAILS[@]} leg(s) failed"
for f in "${FAILS[@]}"; do note "  $f"; done
exit 1
