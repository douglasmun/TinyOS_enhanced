#!/usr/bin/env bash
#
# verify-entropy-pool-stir.sh -- the entropy pool is actually stirred.
#
# THE BUG
#
# pool_get_random() incremented pool_counter INSIDE the `need_stir` branch:
#
#     if (++pool_counter >= POOL_STIR_THRESHOLD) { ... }   /* wrong */
#
# so the counter could only advance once it had ALREADY reached the threshold.
# Starting at 0 it never did. The pool was therefore never re-stirred after
# boot, however many values were drawn.
#
# WHY IT LOOKED HEALTHY
#
# stats.pool_stirs reported 0, and 0 is exactly what a pool that has not yet
# NEEDED stirring reports. The surface could not distinguish "not due yet"
# from "structurally unable to ever stir" -- the status-surface lie class.
#
# WHY THE RUNTIME LEG IS UNREACHABLE ON THIS KERNEL (measured, not assumed)
#
# entropy_get_random32() returns from RDRAND before pool_get_random() is
# reached at all:
#
#     if (stats.rdrand_available) { if (rdrand32(&value)) return value; }
#     return pool_get_random();
#
# On the project's standard `-cpu Broadwell,+rdrand,+rdseed` line the pool
# path is therefore DEAD: pool_counter never moves and pool_stirs reads 0 on
# a fixed and a broken kernel alike, so a runtime assertion there would pass
# vacuously against the unfixed code.
#
# The obvious fix -- clear the CPUID bit with `-cpu Broadwell,-rdrand,-rdseed`
# (a NEGATION; Broadwell carries RDRAND in its base set, so merely omitting
# `+rdrand` changes nothing) -- was tried and does make the pool live:
# `[ASLR] Entropy quality: MEDIUM (Pool)`. But the boot then PANICS before any
# shell exists:
#
#     *** KERNEL PANIC *** Insufficient entropy for cryptographic operations
#
# crypto_collect_entropy() runs validate_entropy_quality() over the pool, and
# under TCG the TSC has too little jitter to pass. That is correct, deliberate,
# fail-closed behaviour: crypto.c:1061 records that the
# -DTINYOS_ALLOW_WEAK_ENTROPY bypass was REMOVED on purpose (Issue #2), so
# there is no opt-out. The panic text points at a keystroke-entropy prompt
# "entropy_init() should have prompted"; grep finds no such prompt in
# entropy.c, and the message's own closing line ("If you see this message,
# contact kernel developers") shows the state is not expected to be reachable.
#
# So the pool path can be driven only by an RDRAND that is PRESENT and then
# FAILS at runtime, and entropy.c has no fault-injection hook for that.
# Adding one would put new code in the crypto path to test a LOW-severity
# counter fix -- against CLAUDE.md's standing rule not to disturb that area.
#
# WHAT THIS HARNESS THEREFORE ASSERTS
#
# Leg 1 only, at the SOURCE level: pool_counter is incremented
# unconditionally and the stir decision is latched from that increment under
# the same lock. That is exactly the property the fix changed, and it is
# checked against both the buggy form and the fixed one so it cannot pass
# against either a reverted file or a rewritten-but-wrong one.
#
# Leg 2 (runtime pool_stirs advance) is reported UNREACHABLE, with the reason,
# rather than silently dropped -- a harness that quietly tests less than its
# name claims is the failure mode this file is trying to avoid.
set -u

# Paths below are relative to the repo root; this script lives in verify/.
cd "$(dirname "$0")/.." || exit 2

PASS=0; FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

SERIAL=entropy-stir.log
rm -f "$SERIAL"

echo "== leg 1: the increment is unconditional in the source =="
# The defect is a one-character-class change (++ inside vs outside the `if`),
# so guard the shape directly as well as the behaviour.
if grep -qE 'if *\( *\+\+pool_counter *>=' src/entropy.c; then
    bad "pool_counter is incremented INSIDE the if -- the original bug"
    grep -nE 'if *\( *\+\+pool_counter *>=' src/entropy.c | sed 's/^/       /'
else
    ok "no 'if (++pool_counter >= ...)' form present"
fi
if grep -qE 'bool +need_stir *= *\( *\+\+pool_counter *>= *POOL_STIR_THRESHOLD *\)' src/entropy.c; then
    ok "the draw is counted unconditionally, then the decision is latched"
else
    bad "the unconditional-count form is gone from pool_get_random()"
fi

echo "== leg 2: runtime pool_stirs advance =="
echo "  UNREACHABLE on this kernel -- reported, not silently skipped."
echo "  entropy_get_random32() returns from RDRAND before pool_get_random(),"
echo "  so the pool is dead whenever RDRAND is present. Clearing the CPUID bit"
echo "  (-cpu Broadwell,-rdrand,-rdseed) does make the pool live -- measured:"
echo "  '[ASLR] Entropy quality: MEDIUM (Pool)' -- but the boot then PANICS in"
echo "  crypto_collect_entropy() ('Insufficient entropy for cryptographic"
echo "  operations') before any shell exists, because validate_entropy_quality()"
echo "  rejects the TSC jitter available under TCG. That fail-closed path is"
echo "  deliberate: crypto.c:1061 records the -DTINYOS_ALLOW_WEAK_ENTROPY bypass"
echo "  was REMOVED on purpose, so there is no opt-out. Driving the pool would"
echo "  need an RDRAND that is present and fails at runtime; entropy.c has no"
echo "  fault-injection hook for that, and adding one to the crypto path to test"
echo "  a LOW-severity counter fix is not a trade this harness should make."
echo "  Leg 1 above checks the changed property directly, at the source."
echo
echo "================ VERDICT ================"
echo "  passed: $PASS   failed: $FAIL"
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: PASS (source-level only) -- pool_counter is incremented"
    echo "  unconditionally and the stir decision is latched from that same"
    echo "  increment under one lock. The RUNTIME advance of pool_stirs is NOT"
    echo "  covered; see leg 2 above for why it is unreachable on this kernel."
    exit 0
else
    echo "RESULT: FAIL"
    exit 1
fi
