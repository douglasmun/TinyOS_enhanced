#!/bin/bash
#==============================================================================
# verify-dns-rx-counters.sh — handle_dns_response() counts, it does not print
#==============================================================================
#
# WHAT THIS PROVES
#
# handle_dns_response() had 20 kprintf sites. Every one sat on a path a remote
# host drives, with no local account required, and the spoof/TID/injection
# branches are exactly the ones an off-path attacker spraying forged responses
# reaches -- so each forged packet bought several lines on a console the ring-3
# shell shares with the user's own output. One branch printed the attacker's own
# `question_domain` bytes. This harness asserts they are gone AND that the
# counters replacing them actually move, per branch.
#
# WHY A FORGER AND NOT REAL TRAFFIC
#
# A friendly network never produces these packets: a passing `dig` reaches none
# of the drop branches. Without injection the only honest verdict would be "all
# drop counters read 0", which is equally true of a build where the counters are
# never incremented at all. `dnsforge` (TINYOS_FAULT_INJECT) injects one
# synthetic response per signature, each differing from a VALID response in
# exactly ONE respect, so a rise in one counter identifies which branch ran.
#
# THE POSITIVE CONTROL IS LOAD-BEARING (leg 2). `dnsforge valid` must land on
# `resolved`. Without it, every drop leg would also pass against a forger that
# builds malformed garbage -- the packets would be dropped for the wrong reason
# while the counters moved exactly as expected. Proving the forger can produce
# an ACCEPTED packet is what makes the rejections attributable.
#
# NEGATIVE CONTROL (run, not assumed): restoring any kprintf in
# handle_dns_response fails leg 1 while every counter leg still passes -- the
# counters are correct and the print is still there, which is the whole bug.
#
#==============================================================================
set -uo pipefail

note() { echo "$@"; }
PASS=0; FAIL=0
ok()  { note "  [$1] $2: OK";   PASS=$((PASS+1)); }
bad() { note "  [$1] $2: FAIL"; FAIL=$((FAIL+1)); }
guard_fail() { note "GUARD: $1"; note "RESULT: INCONCLUSIVE"; exit 3; }

cd "$(dirname "$0")/.."

#==============================================================================
# SOURCE GUARDS — the things a later edit could silently remove
#==============================================================================

grep -q "dns_forge_response" src/dns.c \
    || guard_fail "dns_forge_response missing from dns.c; every counter leg
below would drive nothing and report 0 -> 0, which a broken build also reports."

grep -q "dnsforge" src/shell.c \
    || guard_fail "the \`dnsforge\` command is gone from shell.c, so the typed
commands below would be rejected by the shell and this harness would grade the
boot output instead of the injection."

grep -q "dns_get_rx_stats" src/shell_network.c \
    || guard_fail "ifconfig no longer reports the DNS counters; there is nothing
to read."

#==============================================================================
# LEG 1 — the prints are gone (asserted on SOURCE, and only for this function)
#==============================================================================
#
# Scoped to handle_dns_response's body, NOT the whole file: send_dns_query and
# domain_to_dns_label legitimately keep their prints. Those are driven by a
# local user typing `dig`/`curl`, which is bounded by local action -- the rule
# is about paths a REMOTE host drives. A file-wide grep would fail on correct
# code and push someone into "fixing" the outbound path.
#
# Commented-out lines do not count; the file has one, and a naive grep sees it.

RESP_BODY="$(awk '/^void handle_dns_response/,/^}$/' src/dns.c)"
RESP_PRINTS="$(printf '%s\n' "$RESP_BODY" \
    | grep -E "kprintf|stream_printf" \
    | grep -vE "^\s*(//|\*|/\*)" \
    | wc -l | tr -d ' ')"

if [ "$RESP_PRINTS" -eq 0 ]; then
    ok "leg 1" "no kprintf/stream_printf on the DNS RX path"
else
    bad "leg 1" "handle_dns_response still has $RESP_PRINTS print site(s).
      Any host on the segment drives these. Count, don't print:
$(printf '%s\n' "$RESP_BODY" | grep -nE "kprintf|stream_printf" | grep -vE "^\s*[0-9]+:\s*(//|\*)" | sed 's/^/        /')"
fi

#==============================================================================
# BUILD
#==============================================================================

note ""
note "== Building with -DTINYOS_FAULT_INJECT =="
make clean >/dev/null 2>&1
BUILD_LOG="$(mktemp -t dnsrx-build.XXXXXX)"
if ! make -j8 EXTRA_CFLAGS=-DTINYOS_FAULT_INJECT kernel.elf >"$BUILD_LOG" 2>&1; then
    note "---- build output (tail) ----"
    tail -20 "$BUILD_LOG"
    rm -f "$BUILD_LOG"
    guard_fail "build failed"
fi
rm -f "$BUILD_LOG"

[ -f kernel.elf ] || guard_fail "kernel.elf missing after a successful build"

# Capture-then-match, never `nm | grep -q`: under `set -o pipefail` grep -q
# exits at the first match, SIGPIPEs nm, and the pipeline reports 141 on a
# kernel that DOES contain the symbol. Measured 4-in-5 on this tree.
command -v i686-elf-nm >/dev/null 2>&1 \
    || guard_fail "i686-elf-nm not on PATH (looked in: $PATH). Without it the
symbol check cannot distinguish 'not built' from 'cannot look'."

NM_OUT="$(i686-elf-nm kernel.elf 2>/dev/null || true)"
case "$NM_OUT" in
  *dns_forge_response*) : ;;
  *) guard_fail "dns_forge_response not in the linked image (kernel.elf is
$(wc -c < kernel.elf) bytes, nm emitted $(printf '%s' "$NM_OUT" | wc -l) symbols).
nm's output was captured whole rather than piped, so this is neither a missing
nm nor a SIGPIPE'd pipeline: the symbol is genuinely absent." ;;
esac

cp kernel.elf iso/boot/kernel.elf 2>/dev/null || guard_fail "cannot stage kernel.elf"
i686-elf-grub-mkrescue -o dist/tinyos.iso iso >/dev/null 2>&1 \
    || guard_fail "grub-mkrescue failed (need xorriso)"

#==============================================================================
# BOOT AND DRIVE
#==============================================================================

WORK=$(mktemp -d -t dnsrx.XXXXXX)
SERIAL="$WORK/serial.log"
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
# make clean on EXIT: EXTRA_CFLAGS is not in the dependency graph, so leaving
# fault-inject objects behind breaks the NEXT harness at LINK time, which reads
# as a broken kernel rather than a dirty tree.
trap 'cleanup_qemu; rm -rf "$WORK"; make clean >/dev/null 2>&1' EXIT

# `dig` first: the forger echoes the last queried domain and transaction ID, so
# without a prior real query it has nothing to build a matching packet from and
# refuses. That ordering is a property of the forger, not an accident.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=900 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="DNS rx:" \
TINYOS_FOLLOWUP_CMDS="!dig example.com;ifconfig=>DNS rx:;dnsforge valid=>dnsforge valid injected;ifconfig=>DNS rx:;dnsforge srcip=>dnsforge srcip injected;dnsforge tid=>dnsforge tid injected;dnsforge question=>dnsforge question injected;dnsforge malformed=>dnsforge malformed injected;dnsforge noanswer=>dnsforge noanswer injected;ifconfig=>DNS rx:" \
python3 tools/qemu_typist.py >/dev/null 2>&1
TYPIST_RC=$?

sleep 3
cleanup_qemu

if [ ! -s "$SERIAL" ]; then
    note "  no serial output (typist rc=$TYPIST_RC)"
    note "RESULT: FAIL (boot/output failure, not an assertion failure)"
    exit 2
fi

#==============================================================================
# EXTRACT
#==============================================================================

nth_rx()    { grep -o "DNS rx:.*"    "$SERIAL" | sed -n "${1}p"; }
nth_drops() { grep -o "DNS drops:.*" "$SERIAL" | sed -n "${1}p"; }

field_rx()    { nth_rx "$1"    | sed -E "s/.*[^0-9]([0-9]+) $2.*/\1/"; }
field_drops() { nth_drops "$1" | sed -E "s/.*[^0-9]([0-9]+) $2.*/\1/"; }

READINGS=$(grep -c "DNS rx:" "$SERIAL")
note ""
note "== Readings captured: $READINGS =="
grep -o "DNS rx:.*"    "$SERIAL" | sed 's/^/    /'
grep -o "DNS drops:.*" "$SERIAL" | sed 's/^/    /'

# FOUR readings, not three: TINYOS_EXEC_CMD="ifconfig" fires its own reading
# BEFORE the followup list runs, so the followups' three are readings 2-4.
# Getting this off by one does not fail loudly -- it silently compares the
# pre-dig baseline against the post-valid reading, which made every drop leg
# report "did not move" on a kernel whose counters were all correct.
if [ "$READINGS" -lt 4 ]; then
    note "RESULT: INCONCLUSIVE — expected 4 ifconfig readings, got $READINGS."
    note "  The typist did not complete its command sequence."
    exit 3
fi

# 2 = after dig, 3 = after `dnsforge valid`, 4 = after all drop cases.
OK1=$(field_rx 2 resolved);  OK2=$(field_rx 3 resolved);  OK3=$(field_rx 4 resolved)
NA1=$(field_rx 2 no-answer); NA3=$(field_rx 4 no-answer)
SRC1=$(field_drops 2 src-ip);    SRC3=$(field_drops 4 src-ip)
TID1=$(field_drops 2 tid);       TID3=$(field_drops 4 tid)
QUE1=$(field_drops 2 question);  QUE3=$(field_drops 4 question)
MAL1=$(field_drops 2 malformed); MAL3=$(field_drops 4 malformed)

note ""
note "================ VERDICT ================"
note "  resolved:  $OK1 -> $OK2 -> $OK3"
note "  drops:     src-ip $SRC1->$SRC3, tid $TID1->$TID3, question $QUE1->$QUE3, malformed $MAL1->$MAL3"
note "  no-answer: $NA1 -> $NA3"

rose() {  # name label before after
    if [ -z "${3:-}" ] || [ -z "${4:-}" ]; then
        bad "$1" "$2: counter unreadable ('${3:-unset}' -> '${4:-unset}')"
    elif [ "$4" -gt "$3" ]; then
        ok "$1" "$2 rose $3 -> $4"
    else
        bad "$1" "$2 did not move ($3 -> $4). Either the branch was not reached
      or the counter is not incremented -- both read as a healthy build."
    fi
}

#==============================================================================
# LEG 2 — POSITIVE CONTROL: the forger can build an ACCEPTED response
#==============================================================================
# Load-bearing. Without this, every drop leg below also passes against a forger
# emitting malformed garbage: the packets would be rejected for a reason other
# than the one named, while the counters moved exactly as expected.
rose "leg 2" "resolved (dnsforge valid)" "$OK1" "$OK2"

#==============================================================================
# LEGS 3-7 — one per drop signature
#==============================================================================
rose "leg 3" "src-ip drops (spoofed sender)"       "$SRC1" "$SRC3"
rose "leg 4" "tid drops (cache poisoning)"         "$TID1" "$TID3"
rose "leg 5" "question drops (response injection)" "$QUE1" "$QUE3"
rose "leg 6" "malformed drops"                     "$MAL1" "$MAL3"
rose "leg 7" "no-answer count"                     "$NA1"  "$NA3"

#==============================================================================
# LEG 8 — the drop cases did NOT get accepted
#==============================================================================
# The counters could all rise while the resolver ALSO accepted the forged
# answers, which would be the security failure wearing the metrics of a fix.
# Between reading 2 and 3 only drop cases were injected, so `resolved` must be
# pinned. Note this asserts the OPPOSITE direction to leg 2 on the SAME counter
# -- do not reconcile them.
if [ -z "${OK2:-}" ] || [ -z "${OK3:-}" ]; then
    bad "leg 8" "resolved counter unreadable"
elif [ "$OK3" -eq "$OK2" ]; then
    ok "leg 8" "no forged response was accepted (resolved pinned at $OK2)"
else
    bad "leg 8" "resolved rose $OK2 -> $OK3 across the DROP-ONLY window.
      A forged response was ACCEPTED. This is the spoofing/poisoning defence
      failing, not a counter bug."
fi

#==============================================================================
note ""
if [ "$FAIL" -eq 0 ]; then
    note "RESULT: PASS — $PASS assertions; the DNS RX path counts and never prints"
    exit 0
else
    note "RESULT: FAIL — $FAIL of $((PASS+FAIL)) assertions failed"
    exit 1
fi
