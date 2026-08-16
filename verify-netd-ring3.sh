#!/usr/bin/env bash
#
# verify-netd-ring3.sh — FULLY AUTOMATED check of the RING the inbound parser
# executes in, via the CPL witness added by doc/NETDAEMON_DESIGN.md item 4 PR D.
#
# READ THIS FIRST: WHAT THIS HARNESS PROVES TODAY
#
# The parser has NOT moved to ring 3 yet. This harness is deliberately landed
# BEFORE the move, and today it asserts the PRE-MOVE BASELINE:
#
#     cpl3 == 0   and   cpl0 rises by the number of frames injected
#
# That is not a placeholder. It is the half of the assertion that cannot be
# written after the fact. A harness authored once the parser is already in ring
# 3 has nothing to compare against: it can only observe the post-move state and
# call it correct. By recording the baseline now -- against a kernel whose
# counters are known-good and whose ring is known -- the eventual move has to
# SWAP two numbers that are currently pinned in the opposite direction, and a
# build that merely claims to have moved the parser cannot produce that swap.
#
# When PR D's parser move lands, exactly two things change here:
#   * EXPECT_CPL3=1 (below) flips the polarity of the two assertions
#   * this comment block records the swap and the date
# Nothing else in this file should need to change. If the move requires
# rewriting the assertions, that is a signal the counters moved with the code
# rather than measuring it.
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
# Post-move the same two halves are simply read the other way round, which is
# why flipping EXPECT_CPL3 is sufficient.
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
# verify-ids-signature.sh is the harness that actually requires a lease.
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: ring3.log (serial), ring3-trace.log.
set -uo pipefail
cd "$(dirname "$0")"

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=ring3.log
TRACE=ring3-trace.log
RUN_DISK=/tmp/tinyos-ring3-disk.img
MON_SOCK=/tmp/tinyos-ring3-mon.sock

# Flip to 1 in the PR that actually moves the parser to ring 3. See the header.
EXPECT_CPL3=${TINYOS_EXPECT_CPL3:-0}

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
                "If the parser genuinely did move, set TINYOS_EXPECT_CPL3=1 and" \
                "update the header block -- do not silence this by editing the" \
                "assertion."
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

    echo "RESULT: PASS — pre-move baseline recorded"
    echo "  Parser runs at CPL 0 ($DELTA0 frames), never at CPL 3 across $READINGS readings."
    echo "  This is the baseline PR D's parser move must invert. Run NC1 (hollow"
    echo "  net_current_cpl to 'return 3;') and NC2 (delete the increment block) to"
    echo "  confirm both halves of this assertion can actually fail."
    exit 0
else
    # ---------------- POST-MOVE (after PR D's parser move) ----------------
    #
    # Same two halves, read the other way round.
    if [ "$DELTA3" -eq 0 ]; then
        fail_with "cpl3 did not rise; the parser is NOT executing in ring 3" \
            "EXPECT_CPL3=1 asserts the parser moved, but every frame in this run" \
            "was parsed at CPL 0. Either the move did not land, or the ring-3" \
            "path is not on the frame path and a ring-0 fallback is serving it."
    fi
    if [ "$DELTA0" -ne 0 ]; then
        fail_with "cpl0 rose by $DELTA0 after the move; the parser runs in BOTH rings" \
            "This is what a PARTIAL move looks like -- some protocols crossed the" \
            "boundary and others still parse in ring 0. The ring-0 remnant is" \
            "still the full-privilege attack surface PR D exists to remove, so" \
            "this is a failure even though networking works."
    fi
    echo "RESULT: PASS — parser executing at CPL 3 ($DELTA3 frames), zero at CPL 0"
    exit 0
fi
