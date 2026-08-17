#!/usr/bin/env bash
#
# verify-netd-arbitration.sh — FULLY AUTOMATED check that knetd and SYS_NETRX
# never consume the same frame, and that the routing switch is inert until
# claimed.
#
# WHAT THIS IS TESTING
#
# doc/NETDAEMON_DESIGN.md, PR D1a. Before this change, e1000_rx_softirq_run()
# (knetd, ring 0) and e1000_rx_dequeue() (the SYS_NETRX half) both popped
# rx_softirq_tail. That ring is single-consumer. PR B got away with it because
# netprobe runs on demand and knetd is never draining at the same instant, but
# a real ring-3 netd polling SYS_NETRX would have raced knetd for every frame:
# each one delivered to whichever consumer reached the tail first. A TCP segment
# handed to the daemon that does not parse TCP is simply lost, intermittently
# and under load.
#
# D1a keeps knetd as the sole consumer of rx_softirq_ring and gives it a
# classify step: ICMP/UDP go to a separate netd ring that only SYS_NETRX pops;
# everything else it parses itself.
#
# WHY THE ASSERTIONS ARE COUNTER PAIRS, NOT "NETWORKING STILL WORKS"
#
# "ping still replies" passes against a build where the claim never takes
# effect, which is the single most likely way for this change to be wrong --
# a routing switch that silently does nothing looks exactly like a healthy
# kernel. Every leg below therefore pins one counter while another moves, so a
# no-op build fails on the pinned one.
#
#   LEG 1  UNCLAIMED   routed stays 0 while RX parsing RISES.
#                      (The pre-D1a behaviour, unchanged. This is also the
#                      negative control for leg 2: same traffic, opposite
#                      routing outcome, and the only difference is the claim.)
#   LEG 2  CLAIMED     routed RISES while ICMP/UDP parsing STOPS. Frames go to
#                      the netd ring instead of handle_packet(). Nothing drains
#                      that ring in D1a, so this deliberately breaks ping --
#                      that IS the observation.
#   LEG 3  TCP UNMOVED tcp_cpl0 keeps rising while claimed. TCP must never be
#                      routed, because TCP_LOCK is `cli` and ring 3 has IOPL=0.
#                      This is the leg that catches a classifier that claims
#                      the whole IP protocol space instead of ICMP/UDP.
#   LEG 4  RELEASE     unclaiming restores ring-0 parsing. Proves the switch is
#                      reversible, which the supervisor restart path needs.
#
# Exit codes: 0 pass, 1 assertion failed, 2 no output/boot failure,
#             3 build or guard failure.
#
# Needs -DTINYOS_FAULT_INJECT for the `netdclaim` lever. That flag is NOT in the
# dependency graph, so this script `make clean`s on EXIT -- leaving its objects
# behind breaks every other harness at link time (CLAUDE.md records this costing
# five consecutive runs).

set -uo pipefail

cd "$(dirname "$0")" || exit 3

FAIL=0
note()  { printf '%s\n' "$*"; }
ok()    { printf '  [%s] %s: OK\n' "$1" "$2"; }
bad()   { printf '  [%s] %s: FAIL\n' "$1" "$2"; FAIL=1; }
guard_fail() { printf 'GUARD: %s\n' "$*" >&2; exit 3; }

trap 'make clean >/dev/null 2>&1' EXIT

#==============================================================================
# GUARDS
#==============================================================================

grep -q "netd_claims_frame" src/e1000.c \
    || guard_fail "src/e1000.c has no netd_claims_frame(); the classifier this
harness exists to verify is gone or renamed."

grep -q "cmd_curl" src/shell_network.c \
    || guard_fail "cmd_curl not found. Leg 3 drives TCP through \`curl\` inside the
claimed window; without it tcp_cpl0 stays 0 on both readings and leg 3 passes by
comparing zero to zero, testing nothing."

grep -q "netdclaim" src/shell.c \
    || guard_fail "the netdclaim command is missing from src/shell.c. Leg 2
cannot take the claim without it, and every leg would report the unclaimed
reading -- which is a PASS for leg 1 and a vacuous pass for the rest."

# The single most important guard: e1000_rx_dequeue must read the netd ring.
# If someone points it back at rx_softirq_ring, the two-consumer race returns
# and every leg here still passes, because no leg drives SYS_NETRX.
grep -A25 "^int e1000_rx_dequeue" src/e1000.c | grep -q "netd_ring_tail" \
    || guard_fail "e1000_rx_dequeue no longer reads netd_ring_tail. That is the
race this PR exists to close, and NO leg in this harness would catch it --
these legs drive the knetd side, not the syscall side. Fix the code or, if the
design genuinely changed, rewrite this harness deliberately."

#==============================================================================
# BUILD
#==============================================================================

note "== Building with -DTINYOS_FAULT_INJECT =="
make clean >/dev/null 2>&1
BUILD_LOG="$(mktemp -t netdarb-build.XXXXXX)"
if ! make -j8 EXTRA_CFLAGS=-DTINYOS_FAULT_INJECT kernel.elf >"$BUILD_LOG" 2>&1; then
    note "---- build output (tail) ----"
    tail -20 "$BUILD_LOG"
    rm -f "$BUILD_LOG"
    guard_fail "build failed"
fi
rm -f "$BUILD_LOG"

# Re-run make to a fixed point before inspecting the image. `make -j8` returning
# 0 does not guarantee the link is flushed and complete by the time the next
# command stats the file, and an nm against a half-written kernel.elf reports the
# symbol missing -- which reads as "the feature is not built" and is the most
# misleading possible guard failure. A second make is a no-op when the tree is
# genuinely up to date, so this costs nothing and removes the race.
make EXTRA_CFLAGS=-DTINYOS_FAULT_INJECT kernel.elf >/dev/null 2>&1

[ -f kernel.elf ] || guard_fail "kernel.elf missing after a successful build"

# Check the TOOL before trusting its output. `i686-elf-nm` lives in
# /opt/homebrew/bin, which a non-interactive shell does not necessarily have on
# PATH -- and when it is absent, `nm | grep -q` produces no output and fails
# exactly as it would if the symbol were missing. That misreads a missing
# toolchain as a missing feature, which is the same class of misdiagnosis this
# harness exists to prevent, so the two cases get separate messages.
command -v i686-elf-nm >/dev/null 2>&1 \
    || guard_fail "i686-elf-nm not on PATH (looked for it in: $PATH).
It is normally at /opt/homebrew/bin/i686-elf-nm. Without it the symbol check
below cannot distinguish 'not built' from 'cannot look'."

# NOT `nm ... | grep -q`. Under `set -o pipefail` (on, above) `grep -q` exits at
# the first match and SIGPIPEs nm, so the pipeline reports 141 and the guard
# fires on a kernel that DOES contain the symbol. Measured on this tree: 4 of 5
# identical runs returned 141, 1 returned 0 -- which is why every by-hand
# reproduction passed and three separate theories (link race, PATH, stale copy)
# were chased instead. Capture first, match second: no short-circuit, no SIGPIPE.
NM_OUT="$(i686-elf-nm kernel.elf 2>/dev/null || true)"
case "$NM_OUT" in
  *net_netd_set_claimed*) : ;;
  *) guard_fail "net_netd_set_claimed not in the linked image (kernel.elf is
$(wc -c < kernel.elf) bytes, nm emitted $(printf '%s' "$NM_OUT" | wc -l) symbols).
The toolchain check above passed and nm's output was captured whole rather than
piped, so this is neither a missing nm nor a SIGPIPE'd pipeline: the symbol is
genuinely absent." ;;
esac

cp kernel.elf iso/boot/kernel.elf 2>/dev/null || guard_fail "cannot stage kernel.elf"
i686-elf-grub-mkrescue -o dist/tinyos.iso iso >/dev/null 2>&1 \
    || guard_fail "grub-mkrescue failed (need xorriso)"

#==============================================================================
# RUN
#==============================================================================

# Leg 3's TCP driver must reach a host by RAW IP, resolved here on the HOST.
# Why not a hostname: under the claim, UDP is routed to netd_ring and nothing
# drains it, so the guest's own DNS lookup never completes -- `curl example.com`
# inside the claimed window therefore never resolves, never sends a SYN, and
# leg 3 reads tcp 0 -> 0. That is the design working correctly, and it makes any
# name-based driver structurally unable to test this leg. (Measured: the same
# command in an UNCLAIMED probe boot gives tcp 5/0 and udp 2->5; in the claimed
# window, tcp 0/0 with udp pinned.)
# Why not a hardcoded literal: example.com sits behind a CDN whose address
# changes, and a stale constant would fail as a kernel bug years from now.
TCP_TARGET_HOST="${TINYOS_TCP_TARGET_HOST:-example.com}"
TCP_TARGET_IP="$(dscacheutil -q host -a name "$TCP_TARGET_HOST" 2>/dev/null \
    | awk '/^ip_address:/ {print $2; exit}')"
if [ -z "$TCP_TARGET_IP" ]; then
    note "RESULT: INCONCLUSIVE — cannot resolve $TCP_TARGET_HOST on the HOST, so"
    note "  leg 3 has no reachable TCP target. This is a host-network problem,"
    note "  not a kernel finding; it would otherwise surface as a leg-3 FAIL."
    note "  Override with TINYOS_TCP_TARGET_HOST=<name> or fix host DNS."
    exit 3
fi
note "== Leg 3 TCP target: $TCP_TARGET_HOST -> $TCP_TARGET_IP =="

WORK=$(mktemp -d -t netdarb.XXXXXX)
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
trap 'cleanup_qemu; rm -rf "$WORK"; make clean >/dev/null 2>&1' EXIT

# Sequence, in one typist run so the ordering is guaranteed:
#   ifconfig                 -> baseline
#   ping 10.0.2.2 / ifconfig -> leg 1 (unclaimed: parse rises, routed pinned)
#   netdclaim                -> take the claim
#   ping 10.0.2.2 / ifconfig -> leg 2+3 (claimed: routed rises, icmp parse
#                               pinned, tcp still parses in ring 0)
#   netdclaim off / ping / ifconfig -> leg 4 (restored)
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=900 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="netd route:" \
TINYOS_FOLLOWUP_CMDS="ping 10.0.2.2;ifconfig=>netd route:;netdclaim=>netd claim taken;ping 10.0.2.2;!curl $TCP_TARGET_IP;ifconfig=>netd route:;netdclaim off=>netd claim released;ping 10.0.2.2;ifconfig=>netd route:" \
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

# Nth occurrence of each counter. Reading by ordinal rather than by "last"
# matters: the legs differ only in WHICH reading they compare, so collapsing
# them to a final value would make every leg assert the same thing.
nth_routed()  { grep -o "netd route:.*" "$SERIAL" | sed -n "${1}p" | sed -E 's/.*claimed=[a-z]+, ([0-9]+) routed.*/\1/'; }
nth_claimed() { grep -o "netd route:.*" "$SERIAL" | sed -n "${1}p" | sed -E 's/.*claimed=([a-z]+),.*/\1/'; }
nth_icmp()    { grep -o "RX proto-ring:.*" "$SERIAL" | sed -n "${1}p" | sed -E 's/.*icmp ([0-9]+)\/([0-9]+).*/\1/'; }
nth_tcp()     { grep -o "RX proto-ring:.*" "$SERIAL" | sed -n "${1}p" | sed -E 's/.*tcp ([0-9]+)\/([0-9]+).*/\1/'; }

READINGS=$(grep -c "netd route:" "$SERIAL")
note ""
note "== Readings captured: $READINGS =="
grep -o "netd route:.*" "$SERIAL" | sed 's/^/    /'
grep -o "RX proto-ring:.*" "$SERIAL" | sed 's/^/    /'

if [ "$READINGS" -lt 4 ]; then
    note ""
    note "  Expected 4 ifconfig readings, saw $READINGS -- the typed sequence did"
    note "  not complete. Scoring INCONCLUSIVE rather than pass or fail:"
    note "  a short run cannot distinguish a broken switch from a dropped keystroke."
    note "RESULT: FAIL (incomplete run)"
    exit 2
fi

R1=$(nth_routed 1); R2=$(nth_routed 2); R3=$(nth_routed 3); R4=$(nth_routed 4)
C1=$(nth_claimed 1); C3=$(nth_claimed 3); C4=$(nth_claimed 4)
I2=$(nth_icmp 2);   I3=$(nth_icmp 3)
T2=$(nth_tcp 2);    T3=$(nth_tcp 3)

note ""
note "================ VERDICT ================"
note "  routed:  $R1 -> $R2 -> $R3 -> $R4"
note "  claimed: $C1 / ... / $C3 / $C4"
note "  icmp cpl0: $I2 -> $I3    tcp cpl0: $T2 -> $T3"

#==============================================================================
# LEG 1 — unclaimed: routing inert
#==============================================================================

[ "$C1" = "no" ] && ok "leg 1a" "stock boot reports claimed=no" \
                 || bad "leg 1a" "stock boot should report claimed=no, got '$C1'"

if [ "${R2:-x}" = "0" ]; then
    ok "leg 1b" "routed pinned at 0 while unclaimed"
else
    bad "leg 1b" "routed rose to $R2 with no claim taken -- the switch is not gated"
fi

# Pin-vs-rise pair: parsing must be happening, or leg 1b passes vacuously
# (a kernel receiving no frames at all has routed==0 too).
if [ -n "${I2:-}" ] && [ "${I2:-0}" -gt 0 ]; then
    ok "leg 1c" "ICMP parsed at cpl0 while unclaimed (icmp_cpl0=$I2)"
else
    bad "leg 1c" "no ICMP parsed in ring 0 before the claim (icmp_cpl0=${I2:-unset}).
      Without this, leg 1b proves only that no traffic arrived."
fi

#==============================================================================
# LEG 2 — claimed: frames divert
#==============================================================================

[ "$C3" = "yes" ] && ok "leg 2a" "claim taken (claimed=yes)" \
                  || bad "leg 2a" "claim not reflected, got '$C3'"

if [ -n "${R3:-}" ] && [ -n "${R2:-}" ] && [ "$R3" -gt "$R2" ]; then
    ok "leg 2b" "routed rose $R2 -> $R3 under the claim"
else
    bad "leg 2b" "routed did not rise under the claim ($R2 -> $R3).
      The classifier is not diverting, so the claim is decorative."
fi

if [ -n "${I3:-}" ] && [ -n "${I2:-}" ] && [ "$I3" -eq "$I2" ]; then
    ok "leg 2c" "ICMP ring-0 parsing STOPPED under the claim (pinned at $I2)"
else
    bad "leg 2c" "ICMP kept parsing in ring 0 while claimed ($I2 -> $I3).
      Frames are being both routed AND parsed -- the two-consumer bug in a new
      shape, and the exact failure this PR exists to prevent."
fi

#==============================================================================
# LEG 3 — TCP is never routed
#==============================================================================

# TCP must keep parsing in ring 0 while claimed. The subtlety: `T3 >= T2` is
# satisfied by 0 >= 0, so on a run with no TCP traffic this leg passes without
# testing anything -- the one-sided-assertion failure recorded in the D1
# baseline work. The claimed window therefore drives a real TCP connection
# (curl), and the leg fails if the counter did not move.
#
# THE TARGET IS LOAD-BEARING, and it must be a RAW IP resolved on the host
# (see TCP_TARGET_IP above). Measured against this ISO, drivers tried:
#     curl 10.0.2.2     -> tcp 0/0   (gateway drops the SYN, no RST comes back)
#     curl 10.0.2.2:9   -> tcp 0/0   (same)
#     curl example.com  -> tcp 5/0   UNCLAIMED, but tcp 0/0 INSIDE the claim,
#                                    because netd swallows the DNS response
#     curl <literal ip> -> the only driver that works in the claimed window
# The first two make the leg vacuous (0 >= 0 passes); the third makes it depend
# on the very UDP path the claim disables. Only a raw IP isolates TCP.
if [ -z "${T3:-}" ] || [ -z "${T2:-}" ]; then
    bad "leg 3" "tcp counters unreadable (T2='${T2:-unset}' T3='${T3:-unset}')"
elif [ "$T3" -lt "$T2" ]; then
    bad "leg 3" "tcp_cpl0 went backwards ($T2 -> $T3), which cannot happen unless
      the counter was reset -- or TCP is being routed to netd, which must never
      happen: TCP_LOCK is cli and ring 3 runs with IOPL=0."
elif [ "$T3" -eq "$T2" ]; then
    bad "leg 3" "tcp_cpl0 did not move under the claim ($T2 -> $T3), so this leg
      proved nothing: '>= ' is satisfied by 0 >= 0. Either the TCP driver in the
      claimed window failed to connect, or TCP frames ARE being routed away.
      Both need eyes -- scored FAIL rather than passing vacuously."
else
    ok "leg 3" "TCP still parsing at cpl0 while claimed ($T2 -> $T3)"
fi

#==============================================================================
# LEG 4 — release restores ring 0
#==============================================================================

[ "$C4" = "no" ] && ok "leg 4a" "claim released (claimed=no)" \
                 || bad "leg 4a" "claim not released, got '$C4'"

if [ -n "${R4:-}" ] && [ -n "${R3:-}" ] && [ "$R4" -eq "$R3" ]; then
    ok "leg 4b" "routing stopped after release (pinned at $R3)"
else
    bad "leg 4b" "routed kept rising after release ($R3 -> $R4).
      The supervisor needs this to be reversible: a netd that dies must hand
      its protocols back, or its death takes ICMP and UDP down permanently."
fi

#==============================================================================

note ""
if [ "$FAIL" -eq 0 ]; then
    note "RESULT: PASS — one consumer per ring, routing gated and reversible"
    exit 0
fi
note "RESULT: FAIL"
exit 1
