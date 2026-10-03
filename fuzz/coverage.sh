#!/usr/bin/env bash
# Line-coverage report for one target over a corpus directory.
# Usage: fuzz/coverage.sh <target> <corpus_dir> [function-regex]
set -euo pipefail
FUZZ_DIR=$(cd "$(dirname "$0")" && pwd)
t=$1 corpus=$2 filt=${3:-}
LLVM_BIN=$(dirname "${FUZZ_CC:-/opt/homebrew/opt/llvm/bin/clang}")
COVERAGE=1 "$FUZZ_DIR/build.sh" "$t" >/dev/null
out="$FUZZ_DIR/build/$t-cov"
rm -f "$out"/*.profraw
LLVM_PROFILE_FILE="$out/%p.profraw" "$out/fuzz_$t" -runs=0 "$corpus" >/dev/null 2>&1
"$LLVM_BIN/llvm-profdata" merge -o "$out/merged.profdata" "$out"/*.profraw
"$LLVM_BIN/llvm-cov" report "$out/fuzz_$t" -instr-profile="$out/merged.profdata" \
    -show-functions $(ls "$FUZZ_DIR/build/src/"*.c) 2>/dev/null |
    awk -v f="$filt" 'NR<=2 || f=="" || $1 ~ f'
