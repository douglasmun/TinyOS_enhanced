#!/usr/bin/env bash
#==============================================================================
# run-all.sh -- batch runner for the verify/ harness suite.
#
# WHY THIS EXISTS
#
# Until PR #113 this repo had 63 harnesses, no runner, and no CI. The harnesses
# were written, committed, and their verdicts trusted -- but most had never been
# run end to end. That is not a hypothetical: a single batch of six turned up
# SIX standing failures across five files (PR #115), every one a defect in the
# harness rather than the kernel, and one (verify-ring3-chmod.sh) whose
# positive control had never passed since the day it was written.
#
# An unrun harness reports PASS and proves nothing. This runner exists so the
# suite can actually be run.
#
# WHAT IT IS NOT
#
# Not a required PR check. 57 guest boots is ~2.7 h serially (median 169 s/run,
# n=36 measured), so this belongs in a nightly non-blocking job or a manual
# invocation -- see .github/workflows/nightly-harnesses.yml.
#
# The old justification for leaving these ungated was that the typist "drops
# keystrokes under TCG load". That was measured and is FALSE: zero drops across
# ~45 boots. The obstacle is runtime, not flake, so this runner does NOT retry
# failures -- a retry would hide exactly the deterministic breakage that the
# first batch found. A failure here means something is wrong; re-run it by hand.
#
# EXIT: 0 all passed, 1 some failed, 2 nothing ran.
#==============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

TIMEOUT_SECS="${TIMEOUT_SECS:-900}"
OUTDIR="${OUTDIR:-verify-results}"
FILTER="${FILTER:-}"

# EXCLUDED, and why each one:
#
#   verify-exec.sh      -- the only harness without `-display none`. It opens a
#                          GUI and waits for a human to type; batched, it blocks
#                          forever. auto-verify-exec.sh is its headless twin and
#                          IS included.
#   firstexec-trial.sh  -- a wrapper that invokes verify-exec.sh once per trial,
#                          so it inherits the same block.
#   run-all.sh          -- this file.
EXCLUDE="verify-exec.sh firstexec-trial.sh run-all.sh"

# These build with -DTINYOS_FAULT_INJECT, which is NOT in the make dependency
# graph. Objects compiled with it linger and break every LATER harness at link
# time with an error that points at the innocent harness. Most clean up after
# themselves, but as a plain statement rather than a trap -- so a timeout or a
# kill leaves the tree poisoned. The runner therefore `make clean`s after every
# harness unconditionally; it costs one rebuild and removes the whole class.
FAULT_INJECT="verify-editor-rowfail.sh verify-dns-rx-counters.sh
              verify-netd-arbitration.sh verify-supervisor.sh"

mkdir -p "$OUTDIR"
: > "$OUTDIR/summary.tsv"

is_excluded() {
    case " $EXCLUDE " in *" $1 "*) return 0 ;; esac
    return 1
}

HARNESSES=()
for f in verify/*.sh; do
    n=$(basename "$f")
    is_excluded "$n" && continue
    [ -n "$FILTER" ] && case "$n" in $FILTER) ;; *) continue ;; esac
    HARNESSES+=("$n")
done

TOTAL=${#HARNESSES[@]}
if [ "$TOTAL" -eq 0 ]; then
    echo "run-all: no harnesses matched FILTER='$FILTER'"
    exit 2
fi

echo "run-all: $TOTAL harness(es), timeout ${TIMEOUT_SECS}s each, results in $OUTDIR/"
echo ""

# Record the expected total BEFORE running anything.
#
# If the CI job hits its own timeout-minutes cap mid-suite, this script is
# killed outright: no summary block is printed, and the uploaded artifact is a
# summary.tsv that simply stops early -- indistinguishable, to anyone skimming
# it, from a suite that ran to completion with fewer harnesses. Writing the
# expected count first makes truncation detectable from the artifact alone.
echo "$TOTAL" > "$OUTDIR/expected-total"

PASS=0; FAIL=0; INCONCL=0
START_ALL=$(date +%s)

for n in "${HARNESSES[@]}"; do
    start=$(date +%s)
    timeout "$TIMEOUT_SECS" bash "verify/$n" > "$OUTDIR/$n.log" 2>&1
    rc=$?
    dur=$(( $(date +%s) - start ))

    # Preserve the guest's serial log next to the harness output. Without it a
    # failure is unreadable after the fact: the harness prints its verdict, but
    # the evidence for that verdict is in the serial capture, which the NEXT
    # harness overwrites.
    # Capture by MTIME, not by parsing a SERIAL= assignment out of the script.
    # The parse only ever found a top-level `SERIAL=...`, so it silently
    # skipped harnesses that set it per boot inside a function --
    # verify-fat32-write.sh does exactly that (SERIAL="fat32w-boot${n}.log"),
    # and its logs were the ones actually needed to diagnose a failure. Take
    # every *.log this harness just wrote, and keep the trace logs out (they
    # are QEMU -d int dumps, megabytes each, and say nothing about a verdict).
    for f in *.log; do
        [ -f "$f" ] || continue
        case "$f" in *trace*) continue ;; esac
        # `find -newermt` PRINTS the match; its exit status is success either
        # way, so test the output. Guarding on the status alone captured a
        # stale log from a previous year in testing.
        [ -n "$(find "$f" -newermt "@$start" 2>/dev/null)" ] &&
            cp "$f" "$OUTDIR/$n.$f" 2>/dev/null
    done

    # A harness reports INCONCLUSIVE when it cannot grade the run at all -- a
    # stale ISO, a missing symbol, an absent tool. That is neither a pass nor a
    # kernel failure, and collapsing it into either one is how a suite starts
    # lying.
    #
    # Classify on the PRINTED VERDICT first, falling back to rc. The exit code
    # alone is not enough: the suite has no single INCONCLUSIVE code. Most use
    # 3, but verify-chmod-owner.sh and auto-verify-exec.sh use 2, so an rc-only
    # rule reports them as FAIL and sends someone hunting a kernel bug that the
    # harness has already said it could not test for. The verdict line is the
    # harness's own considered statement; the code is an afterthought.
    verdict=$(grep -a '^RESULT:' "$OUTDIR/$n.log" | head -1 | cut -c1-64)
    if [ "$rc" -eq 124 ]; then
        cls=TIMEOUT; FAIL=$((FAIL+1)); verdict="killed after ${TIMEOUT_SECS}s"
    elif printf '%s' "$verdict" | grep -q 'INCONCLUSIVE'; then
        cls=INCONCL; INCONCL=$((INCONCL+1))
    elif [ "$rc" -eq 0 ]; then
        cls=PASS; PASS=$((PASS+1))
    elif [ "$rc" -eq 3 ]; then
        cls=INCONCL; INCONCL=$((INCONCL+1))
    else
        cls=FAIL; FAIL=$((FAIL+1))
    fi

    printf '%s\t%s\t%s\t%s\t%s\n' "$n" "$rc" "$dur" "$cls" "$verdict" >> "$OUTDIR/summary.tsv"
    printf '%-7s %4ds  %-38s %s\n' "$cls" "$dur" "$n" "$verdict"

    case " $FAULT_INJECT " in
        *" $n "*) make clean >/dev/null 2>&1 ;;
    esac
done

ELAPSED=$(( $(date +%s) - START_ALL ))
echo ""
echo "================ SUMMARY ================"
printf 'pass %d  fail %d  inconclusive %d  of %d   (%dm %ds)\n' \
       "$PASS" "$FAIL" "$INCONCL" "$TOTAL" $((ELAPSED/60)) $((ELAPSED%60))

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "FAILED:"
    awk -F'\t' '$4=="FAIL"||$4=="TIMEOUT" {printf "  %-38s %s\n", $1, $5}' "$OUTDIR/summary.tsv"
fi
if [ "$INCONCL" -gt 0 ]; then
    echo ""
    echo "INCONCLUSIVE (graded nothing -- not a pass):"
    awk -F'\t' '$4=="INCONCL" {printf "  %-38s %s\n", $1, $5}' "$OUTDIR/summary.tsv"
fi

[ "$FAIL" -gt 0 ] && exit 1
exit 0
