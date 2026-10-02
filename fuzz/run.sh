#!/usr/bin/env bash
# Run one fuzz target. Usage: fuzz/run.sh <target> <seconds> [workers]
# Corpus grows in fuzz/runs/<target>/corpus (seeded from fuzz/seeds/<target>);
# crashes land in fuzz/runs/<target>/crashes.
set -euo pipefail
FUZZ_DIR=$(cd "$(dirname "$0")" && pwd)
t=$1 secs=$2 workers=${3:-1}
run="$FUZZ_DIR/runs/$t"
mkdir -p "$run/corpus" "$run/crashes"
bin="$FUZZ_DIR/build/$t/fuzz_$t"
[[ -x "$bin" ]] || "$FUZZ_DIR/build.sh" "$t"
# A disk image needs room for a boot sector, a FAT and a few clusters.
case "$t" in
    fat32) max_len=65536 ;;
    *)     max_len=4096 ;;
esac
args=(-max_total_time="$secs" -artifact_prefix="$run/crashes/" -print_final_stats=1
      -max_len="$max_len" -timeout=10 -rss_limit_mb=4096)
[[ -f "$FUZZ_DIR/dict/$t.dict" ]] && args+=(-dict="$FUZZ_DIR/dict/$t.dict")
if (( workers > 1 )); then
    args+=(-fork="$workers" -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1)
fi
exec "$bin" "${args[@]}" "$run/corpus" "$FUZZ_DIR/seeds/$t"
