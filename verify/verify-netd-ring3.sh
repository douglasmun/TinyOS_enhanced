#!/usr/bin/env bash
#
# verify-netd-ring3.sh — FULLY AUTOMATED check of the RING the inbound parser
# executes in, via the CPL witness added by doc/NETDAEMON_DESIGN.md item 4 PR D.
#
# READ THIS FIRST: WHAT THIS HARNESS PROVES
#
#     cpl3 == 0   and   cpl0 rises by the number of frames injected
#
# ORIGINALLY a pre-move baseline, landed deliberately BEFORE a parser move so
# the move would have to SWAP two numbers pinned in the opposite direction --
# a build merely claiming to have moved the parser cannot produce that swap.
#
# THE MOVE WAS WITHDRAWN (2026-08-17), so this is now a STANDING INVARIANT.
# Scoping D1's DNS step found that DNS, DHCP and ARP each produce a result ring
# 0 acts on (a resolved address, the four interface globals, the ARP cache).
# Moving those parsers relocates the parse and then hands the trust back across
# a syscall, which is a net loss. See doc/NETDAEMON_DESIGN.md, "D1 re-scoped".
#
# The assertion is UNCHANGED; only what a failure means has changed. A nonzero
# cpl3 used to mean "not yet" and now means the witness is broken or something
# moved that should not have. There is no flag to flip and no PR coming to flip
# it -- EXPECT_CPL3 is pinned to 0 below.
#
# The paragraphs below about TCP staying in ring 0 still stand, and are now the
# general case rather than an exception.
#
# WITH ONE KNOWN EXCEPTION, DECIDED 2026-08-17 -- READ BEFORE FLIPPING THE FLAG
#
# The first parser move (D1) carries ICMP/DNS/DHCP to ring 3 and deliberately
# leaves TCP in ring 0, because tcp_connections[] has a THIRD mutator besides the
# RX path and the socket API: tcp_tick() (interrupts.c:111) forcibly closes
# connections on the SYN_SENT/SYN_RECEIVED timeout. A ring-3 parser holding a
# reference to a record that a ring-0 timer can free is not fixable with a wider
# lock -- TCP_LOCK() is a kernel critical section and ring 3 cannot take it.
#
# So after D1, TCP frames legitimately keep parsing at CPL 0, and a post-move
# branch that fails whenever cpl0 is nonzero would be WRONG.
#
# THAT REPLACEMENT HAS LANDED (this PR, before the move). The post-move branch
# now reads PER-PROTOCOL counters and asserts three things, two of which point in
# OPPOSITE directions:
#
#     icmp_cpl0 == 0  and  udp_cpl0 == 0     the moved set really moved
#     tcp_cpl3  == 0                          TCP really did NOT move
#     icmp_cpl3 + udp_cpl3 > 0                the zeros above are not vacuous
#
# The opposite polarity is deliberate and is the thing most likely to be
# "cleaned up" by someone making the three checks look consistent. TCP appearing
# at CPL 3 is not extra progress; it is a use-after-free hazard, because
# tcp_tick() can free a connection record in ring 0 while a ring-3 parser holds a
# reference to it. verify-netd-boundary.sh records that copying an assertion
# between two opposite-polarity halves has nearly inverted it three times.
#
# The global cpl0/cpl3 pair stays as a running total, so the PR #74 baseline
# remains comparable; the per-protocol counters supplement it rather than
# replacing it.
#
# DNS and DHCP are NOT counted separately, on purpose: both ride UDP, and the
# witness sits at the L4 dispatch switch, which is the seam the move actually
# falls on. Counting them apart would mean instrumenting the port demux inside
# handle_udp() -- a later, different seam that would classify a frame by its
# destination port rather than by which ring executed the switch.
#
# See doc/NETDAEMON_DESIGN.md, "Settled: what moves first".
#
# WHY A SEPARATE COUNTER FROM irq-ctx AT ALL
#
# verify-rx-thread-context.sh already asserts the parser runs in TASK context
# with IF=1. It is tempting to treat that as covering PR D too. It does not, and
# the distinction is the entire reason this file exists:
#
#     knetd runs with IF=1 AND at CPL 0.
#
# So a build in which nothing whatsoever has moved reports a perfectly healthy
# "RX parsed: N thread-ctx, 0 irq-ctx". Interrupt state and privilege level are
# independent axes; item 1 pinned the first and says nothing about the second.
# doc/NETDAEMON_DESIGN.md names the weak version of this harness -- "ping still
# works" -- as something that passes against a kernel where the parser never
# moved. "thread-ctx is healthy" is the same false pass wearing a better
# disguise, and it is the more dangerous one precisely because it looks like
# evidence.
#
# HOW THE RING IS WITNESSED
#
# handle_packet() reads the low two bits of %cs at the top of the function, on
# the same "counted before any early return" rule as the context pair, and bumps
# one of two buckets surfaced by ifconfig as:
#
#     RX ring:      N cpl0, M cpl3
#
# Read from %cs, NOT from a software flag such as "am I on the knetd task" or a
# daemon-side boolean. A flag records what the code BELIEVES about itself; the
# whole purpose of this counter is to catch a build whose belief is wrong. %cs
# is the hardware's own answer and cannot be desynchronised from reality.
#
# THE ASSERTION IS TWO-SIDED, AND BOTH HALVES ARE LOAD-BEARING
#
#   POSITIVE  cpl0 RISES by at least the injected frame count -- the frames
#             really did reach the parser, so the ring reading has a subject
#   NEGATIVE  cpl3 is 0 at EVERY reading, including the boot baseline
#
# Neither half alone is sufficient, for the same reason as the sibling harness:
#
#   * cpl3 == 0 alone passes trivially on a build where no frame ever arrives.
#     Zero of nothing is zero. The positive half is what gives the zero meaning.
#   * cpl0 rising alone passes on a build that parses in BOTH rings -- which is
#     the realistic shape of a partial PR D, where some protocols moved and
#     others did not. Only the cpl3 half distinguishes that from a clean state.
#
# Both halves still matter with the move withdrawn. The second one especially:
# "cpl0 rose" alone would pass on a build parsing in both rings, which is the
# shape an accidental partial move would take.
#
# NEGATIVE CONTROL (run it; the counters are new and therefore unproven)
#
# The instrument being new is exactly the argument for controlling it. Two
# controls, both of which MUST fail this harness:
#
#   NC1 -- hollow the witness. Replace net_current_cpl()'s body with
#          `return 3;`. The source guard below does not read the function body,
#          so it stays green, and every frame lands in cpl3. This harness must
#          report cpl3 != 0. If it passes, the runtime assertion is decorative.
#          (This is the control that matters: it is the mirror of the PR C1/C2
#          failure recorded in memory ownership-harness-needs-foreign-object --
#          an assertion that only exercises one branch cannot tell a working
#          witness from a constant.)
#
#   NC2 -- delete the increment block in handle_packet() entirely. Both counters
#          freeze at 0 and the POSITIVE half must fail with delta == 0, proving
#          the positive half is not decorative either.
#
# Bypass the source guard deliberately when running either -- verify-rxdrop-
# counters.sh run 2 recorded that a firing guard can MASK the runtime assertion
# under test by exiting 3 before the boot.
#
# HOW THE FRAMES ARE SENT
#
# Identical mechanism to verify-rx-thread-context.sh: a `socket,mcast=` netdev
# and tools/inject_frames.py, so no privileges are needed. An unhandled
# EtherType (0x88b5) is used on purpose -- it reaches handle_packet(), which is
# where the counter lives, then exits down the cheapest arm without perturbing
# protocol state. What is measured is the RING of the call, not its outcome.
#
# Inherited trade-off: this netdev has no NAT, so the guest takes no DHCP lease
# and boot generates no inbound traffic. The baseline therefore reads 0/0 and is
# not load-bearing on this netdev; it is retained for the DHCP-carrying case.
# verify-firewall-default-deny.sh is the harness that actually requires a lease
# -- its arm B boots on the NAT netdev and guards on the lease explicitly.
# (Was verify-ids-signature.sh, which no longer takes a lease at all since it
# moved to the mcast netdev on 2026-08-22.)
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: ring3.log (serial), ring3-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=ring3.log
TRACE=ring3-trace.log
RUN_DISK=/tmp/tinyos-ring3-disk.img
MON_SOCK=/tmp/tinyos-ring3-mon.sock

# cpl3 == 0 is a STANDING INVARIANT, not a pre-move baseline any more.
#
# This was a flip: set TINYOS_EXPECT_CPL3=1 in the PR that moves the parser to
# ring 3. That PR is not coming. D1's parser move was withdrawn after scoping --
# DNS, DHCP and ARP all produce results ring 0 acts on, so moving them relocates
# the parse and hands the trust straight back across a syscall. See
# doc/NETDAEMON_DESIGN.md, "D1 re-scoped".
#
# The consequence for this harness is a polarity change, not a rewrite: a nonzero
# cpl3 used to mean "not yet", and now means "something is wrong". Kept as a
# variable rather than inlined so the assertion below reads the same way, but
# nothing sets it and nothing should.
EXPECT_CPL3=0

# Exceeds E1000_RX_PACKET_BUDGET (16) so the run crosses into the post-budget
# drain loop as well as the primary loop.
FRAME_COUNT=${TINYOS_RING3_FRAMES:-20}

BAD_ETHERTYPE=0x88b5

# ---------------------------------------------------------------------------
# SOURCE GUARD
#
# Checks the SHAPE of the witness before boot so a stale tree fails fast with a
# reason rather than producing a meaningless zero.
#
# Deliberately does NOT assert on net_current_cpl()'s body: NC1 above works by
# hollowing exactly that, and a guard that catches NC1 would prevent the control
# from ever reaching the runtime assertion it is meant to test.
# ---------------------------------------------------------------------------
guard_fail() { echo "RESULT: INCONCLUSIVE — $1"; exit 3; }

grep -q "net_parse_cpl3" src/net.c \
    || guard_fail "src/net.c has no ring accounting; tree predates item 4 PR D"
grep -q "net_get_parse_ring_stats" src/net.h \
    || guard_fail "src/net.h does not export net_get_parse_ring_stats()"
grep -q "net_get_parse_ring_stats" src/shell_network.c \
    || guard_fail "ifconfig does not report the ring counters, so nothing is readable"

# The witness must read %cs, not a software flag. This is the one shape
# assertion worth making: a flag-based implementation would be a plausible
# "simplification" that silently destroys the property (see header).
if ! grep -q 'mov %%cs' src/net.c; then
    guard_fail "src/net.c does not read %cs; the ring witness has been replaced by
  a software flag, which records what the code believes rather than what the
  hardware is doing"
fi

# The increment must sit in handle_packet(), before the early returns. Comments
# are stripped first -- the comment block there necessarily names the counters,
# and matching comment text instead of code is how the tcp_recv guard in
# verify-netd-boundary.sh once fired against the very code it protected.
HP_BODY=$(awk '/^void handle_packet\(/,/^}/' src/net.c \
          | grep -v '^\s*\*' | grep -v '^\s*/\*' | grep -v '^\s*//')
if [ -z "$HP_BODY" ]; then
    guard_fail "could not locate handle_packet() in src/net.c; this guard has gone stale"
fi
printf '%s\n' "$HP_BODY" | grep -q "net_parse_cpl3++" \
    || guard_fail "handle_packet() does not bump the ring counters; the witness is
  not on the path that parses frames"

# Per-protocol witness (this PR). Guarded the same way and for the same reason:
# a stale tree should fail with a reason rather than silently skip the half of
# the assertion that only the per-protocol counters can express.
grep -q "net_parse_proto_cpl" src/net.c \
    || guard_fail "src/net.c has no per-protocol ring counters (net_parse_proto_cpl*);
  the D1-shaped post-move assertion cannot be expressed without them"
grep -q "net_get_parse_proto_cpl_stats" src/shell_network.c \
    || guard_fail "ifconfig does not report the per-protocol ring counters"

# The per-protocol increments must sit in the L4 dispatch switch in handle_ip(),
# which is the seam the move falls on. Comments stripped first, same rule as the
# handle_packet() guard below.
HI_BODY=$(awk '/^static void handle_ip\(/,/^}/' src/net.c \
          | grep -v '^\s*\*' | grep -v '^\s*/\*' | grep -v '^\s*//')
if [ -z "$HI_BODY" ]; then
    guard_fail "could not locate handle_ip() in src/net.c; this guard has gone stale"
fi
for f in icmp_cpl3 udp_cpl3 tcp_cpl3; do
    printf '%s\n' "$HI_BODY" | grep -q "$f" \
        || guard_fail "handle_ip()'s dispatch switch does not bump $f; the
  per-protocol witness is not on the path it claims to measure"
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

# Verify the ARTIFACT, not the source -- the ISO is two copies downstream of the
# edit (harness-design-principles). grep -c not -q: under pipefail, -q SIGPIPEs
# `strings`.
ISO_MARKERS=$(strings "$ISO" | grep -c "cpl3")
if [ "$ISO_MARKERS" -eq 0 ]; then
    guard_fail "the ISO has no ring-counter string, so it predates the witness and
  the run would measure a kernel with no ring accounting at all"
fi

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

# Distinct from the sibling harness's 230.0.0.2:1235 so the two can run
# concurrently without cross-feeding each other's frames.
QEMU_MCAST=230.0.0.3:1236

echo "==> Launching headless QEMU (monitor $MON_SOCK, mcast socket $QEMU_MCAST)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev socket,id=net0,mcast="$QEMU_MCAST" \
    -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

# Ends in `true`: the proof the frames landed is the counter delta, not the
# sender's exit status.
export TINYOS_HOOK_BADETH="sleep 2; python3 tools/inject_frames.py \
    --mcast '$QEMU_MCAST' --count $FRAME_COUNT --ethertype $BAD_ETHERTYPE \
    --dst 52:54:00:12:34:56 >/dev/null 2>&1; sleep 5; true"

# ifconfig is a kernel-shell command, so this harness stays in the kernel shell.
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="RX ring" \
TINYOS_FOLLOWUP_CMDS="\
>BADETH;\
ifconfig=>RX ring" \
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

# --- knetd must have started ----------------------------------------------
# Without it the softirq ring is never drained, so any cpl0 count could only
# have come from the boot-time explicit drain -- which would make the delta
# below measure something other than the deferred path.
if ! grep -qa "KNETD" "$SERIAL"; then
    fail_with "task_knetd never announced itself on the console" \
        "The bottom half is not running, so the ring reading does not describe" \
        "the path PR D is about to move."
fi

# --- Extract both fields, in order ----------------------------------------
# The ifconfig line reads:
#   RX ring:      12 cpl0, 0 cpl3
# Anchored on the field NAMES, so adding a counter nearby cannot shift what
# this reads (assert positions/counts, not presence).
CPL0_LIST=$(grep -a "cpl3" "$SERIAL" \
            | sed -n 's/.*  *\([0-9][0-9]*\) cpl0.*/\1/p')
CPL3_LIST=$(grep -a "cpl3" "$SERIAL" \
            | sed -n 's/.*, *\([0-9][0-9]*\) cpl3.*/\1/p')
READINGS=$(printf '%s\n' "$CPL3_LIST" | grep -c '[0-9]')

if [ "$READINGS" -lt 2 ]; then
    fail_with "expected 2 ifconfig readings, got $READINGS" \
        "The command sequence did not complete, so there is no baseline." \
        "cpl0 seen: ${CPL0_LIST:-none}   cpl3 seen: ${CPL3_LIST:-none}"
fi

CB=$(printf '%s\n' "$CPL0_LIST" | sed -n '1p')
CA=$(printf '%s\n' "$CPL0_LIST" | sed -n '2p')
C3B=$(printf '%s\n' "$CPL3_LIST" | sed -n '1p')
C3A=$(printf '%s\n' "$CPL3_LIST" | sed -n '2p')
DELTA0=$((CA - CB))
DELTA3=$((C3A - C3B))
echo "  cpl0: before=$CB after=$CA delta=$DELTA0   cpl3: before=$C3B after=$C3A delta=$DELTA3"
echo "  (injected $FRAME_COUNT frames; EXPECT_CPL3=$EXPECT_CPL3)"

if [ "$EXPECT_CPL3" -eq 0 ]; then
    # ---------------- PRE-MOVE BASELINE (today) ----------------
    #
    # NEGATIVE: nothing was EVER parsed at CPL 3. Checked across every reading,
    # not just the last, so the boot window is covered too. This is the half NC1
    # (hollowed witness returning 3) must break.
    IDX=0
    while IFS= read -r c3; do
        IDX=$((IDX + 1))
        [ -n "$c3" ] || continue
        if [ "$c3" -ne 0 ]; then
            fail_with "reading #$IDX shows $c3 frame(s) parsed at CPL 3" \
                "The parser has not moved to ring 3 in this tree, so a nonzero" \
                "cpl3 means the WITNESS is wrong, not that the parser moved." \
                "Most likely net_current_cpl() no longer reads %cs correctly," \
                "or the counters were transposed at the increment site." \
                "No parser is scheduled to move, so there is no legitimate way" \
                "for this to be nonzero -- see doc/NETDAEMON_DESIGN.md, 'D1" \
                "re-scoped'. Do not silence this by editing the assertion."
        fi
    done <<< "$CPL3_LIST"

    # POSITIVE: the frames actually reached the parser. Without this, the cpl3
    # zero above passes trivially on a build where nothing arrived. This is the
    # half NC2 (deleted increment) must break.
    if [ "$DELTA0" -eq 0 ]; then
        fail_with "cpl0 did not rise; no frame reached the parser" \
            "The CPL-3 zero above is therefore vacuous -- zero of nothing is" \
            "zero. Either the injected frames never arrived (check the mcast" \
            "netdev and tools/inject_frames.py) or the increment site in" \
            "handle_packet() is gone."
    fi
    if [ "$DELTA0" -lt "$FRAME_COUNT" ]; then
        echo "  NOTE: cpl0 delta ($DELTA0) is below the injected count ($FRAME_COUNT)."
        echo "        Not a failure -- the socket netdev drops frames under load and"
        echo "        the assertion is that the parser ran in ring 0, not that every"
        echo "        frame survived the wire."
    fi

    # PER-PROTOCOL BASELINE (this PR). Pre-move, every protocol's cpl3 field
    # must be 0 across every reading -- the same claim as the global cpl3 zero
    # above, but expressed per-protocol so that D1 has to invert THESE numbers
    # specifically. Asserting only the global pair here would leave the
    # per-protocol counters completely ungraded until the move, which is the
    # failure this whole "instrument before the move" ordering exists to avoid:
    # a counter first exercised by the PR it is meant to grade is not evidence.
    if grep -qa "RX proto-ring:" "$SERIAL"; then
        PIDX=0
        while IFS= read -r line; do
            PIDX=$((PIDX + 1))
            for proto in icmp udp tcp; do
                V=$(printf '%s\n' "$line" \
                    | sed -n "s/.*$proto [0-9][0-9]*\/\([0-9][0-9]*\).*/\1/p")
                [ -n "$V" ] || continue
                if [ "$V" -ne 0 ]; then
                    fail_with "reading #$PIDX shows $V $proto frame(s) at CPL 3" \
                        "The parser has not moved in this tree, so a nonzero" \
                        "per-protocol cpl3 means the WITNESS is wrong -- most" \
                        "likely the cpl0/cpl3 fields were transposed at the" \
                        "increment site in handle_ip()'s dispatch switch."
                fi
            done
        done <<< "$(grep -a 'RX proto-ring:' "$SERIAL")"
        echo "  per-protocol cpl3 = 0 across $PIDX reading(s)"
    else
        fail_with "ifconfig printed no 'RX proto-ring:' line" \
            "The per-protocol counters passed the source guard but produced no" \
            "output, so the ISO is stale relative to the source tree."
    fi

    echo "RESULT: PASS — ring invariant holds"
    echo "  Parser runs at CPL 0 ($DELTA0 frames), never at CPL 3 across $READINGS readings."
    echo "  The parser move was withdrawn (doc/NETDAEMON_DESIGN.md, 'D1 re-scoped'),"
    echo "  so this is a standing invariant, not a baseline awaiting inversion."
    echo "  Run NC1 (hollow net_current_cpl to 'return 3;') and NC2 (delete the"
    echo "  increment block) to confirm both halves can actually fail."
    exit 0
else
    # ---------------- POST-MOVE (after PR D's parser move) ----------------
    #
    # Refuse to grade a D1-shaped move with a whole-parser-shaped assertion.
    # D1 leaves TCP in ring 0 on purpose, so a global "cpl0 must be 0" would fail
    # a correct build -- and worse, someone would then "fix" it by deleting the
    # assertion, leaving nothing. The per-protocol counters are what make the
    # post-move claim expressible; without them this branch has gone stale
    # relative to the decided design. See the header.
    if ! grep -q "net_parse_proto_cpl" src/net.c 2>/dev/null; then
        echo "RESULT: INCONCLUSIVE — EXPECT_CPL3=1 but src/net.c has no"
        echo "  per-protocol ring counters (net_parse_proto_cpl*)."
        echo ""
        echo "  A global cpl0 == 0 describes a move that carried the WHOLE parser."
        echo "  The decided first move (D1) carries ICMP/DNS/DHCP and deliberately"
        echo "  leaves TCP in ring 0, so TCP frames legitimately keep parsing at"
        echo "  CPL 0 and that assertion would fail a correct build."
        echo ""
        echo "  Land the per-protocol counters BEFORE the move. See"
        echo "  doc/NETDAEMON_DESIGN.md, 'Settled: what moves first'."
        exit 3
    fi

    # -----------------------------------------------------------------------
    # POST-MOVE ASSERTION, D1 SHAPE
    #
    # The claim is NOT "the parser is in ring 3". It is two one-sided claims in
    # OPPOSITE directions, which together cannot be satisfied by a partial move:
    #
    #   MOVED     icmp_cpl0 == 0 and udp_cpl0 == 0
    #             -- no frame of a protocol that was supposed to move was parsed
    #             in ring 0. A ring-0 fallback serving some ICMP frames shows up
    #             here and nowhere else.
    #   NOT MOVED tcp_cpl3 == 0
    #             -- TCP must NOT have moved. tcp_connections[] has a ring-0
    #             timer mutator (tcp_tick) that can free a record out from under
    #             a ring-3 parser, so a nonzero tcp_cpl3 is a use-after-free
    #             hazard, not an over-achievement.
    #
    # Plus the positive half, unchanged in spirit from the pre-move branch: the
    # moved protocols must actually have been parsed SOMEWHERE, or every zero
    # above is vacuous.
    #
    # Note the polarity trap this mirrors: verify-netd-boundary.sh records that
    # copying an assertion between two halves with opposite polarity has nearly
    # inverted it three times. The tcp_cpl3 check is the opposite polarity to
    # the two above it. Do not "make them consistent".
    # -----------------------------------------------------------------------
    read_proto() {
        # $1 = protocol name, $2 = reading index (1 = before, 2 = after)
        # Line: "RX proto-ring: icmp 3/0, udp 12/0, tcp 0/0 (cpl0/cpl3)"
        # $3 = 1 for the cpl0 field, 2 for the cpl3 field.
        grep -a "RX proto-ring:" "$SERIAL" \
            | sed -n "${2}p" \
            | sed -n "s/.*$1 \([0-9][0-9]*\)\/\([0-9][0-9]*\).*/\\$3/p"
    }

    PROTO_READINGS=$(grep -ac "RX proto-ring:" "$SERIAL")
    if [ "$PROTO_READINGS" -lt 2 ]; then
        fail_with "expected 2 per-protocol readings, got $PROTO_READINGS" \
            "ifconfig is not reporting the per-protocol ring counters, so the" \
            "D1-shaped assertion has nothing to read."
    fi

    for proto in icmp udp; do
        B=$(read_proto "$proto" 1 1); A=$(read_proto "$proto" 2 1)
        D=$((A - B))
        echo "  ${proto}_cpl0: before=$B after=$A delta=$D  (must be 0)"
        if [ "$D" -ne 0 ]; then
            fail_with "$D $proto frame(s) parsed at CPL 0 after the move" \
                "$proto is in the moving set, so every one of its frames must be" \
                "parsed in ring 3. A nonzero count here is a ring-0 fallback" \
                "still serving part of the traffic -- the full-privilege attack" \
                "surface D1 exists to remove, still present and still reachable."
        fi
    done

    TCP3B=$(read_proto tcp 1 2); TCP3A=$(read_proto tcp 2 2)
    TCP3D=$((TCP3A - TCP3B))
    echo "  tcp_cpl3:  before=$TCP3B after=$TCP3A delta=$TCP3D  (must be 0 -- OPPOSITE polarity)"
    if [ "$TCP3D" -ne 0 ]; then
        fail_with "$TCP3D TCP frame(s) parsed at CPL 3; TCP moved and must not have" \
            "tcp_connections[] is mutated by tcp_tick() in ring 0, which forcibly" \
            "closes connections on the SYN_SENT/SYN_RECEIVED timeout. A ring-3" \
            "parser holding a reference to a record a ring-0 timer can free is a" \
            "use-after-free, and it is NOT fixable with a wider lock: TCP_LOCK()" \
            "is a kernel critical section that ring 3 cannot take." \
            "This is a failure even though it looks like more progress."
    fi

    # POSITIVE half: the moved protocols were actually exercised. Without this,
    # all three zeros above pass on a build where no ICMP or UDP frame arrived.
    ICMP3=$(( $(read_proto icmp 2 2) - $(read_proto icmp 1 2) ))
    UDP3=$(( $(read_proto udp 2 2) - $(read_proto udp 1 2) ))
    if [ $((ICMP3 + UDP3)) -eq 0 ]; then
        fail_with "no ICMP or UDP frame was parsed at CPL 3 in this run" \
            "The three zero-assertions above are therefore vacuous -- zero of" \
            "nothing is zero. Drive real ICMP/UDP traffic (the injected frames" \
            "use an unhandled EtherType and never reach the L4 switch, so this" \
            "branch needs a netdev that carries a DHCP lease and a ping)."
    fi

    echo "RESULT: PASS — D1-shaped move witnessed"
    echo "  ICMP/UDP parsed at CPL 3 only ($ICMP3 icmp, $UDP3 udp); TCP never at CPL 3."
    exit 0
fi
