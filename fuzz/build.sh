#!/usr/bin/env bash
# Build TinyOS libFuzzer targets on the host.  Usage: fuzz/build.sh [target...]
#
# Needs a clang with libFuzzer: Homebrew `llvm` on macOS (Apple clang ships
# none), distro clang on Linux. Override with FUZZ_CC=/path/to/clang.
#
# Each target compiles the REAL kernel sources it names (via the host copy
# prep_hostsrc.py makes) plus its harness. Whatever the link still lacks gets
# a weak stub from gen_weak_stubs.py; behaviour a harness relies on lives in
# common/stubs.c or the harness itself.
set -euo pipefail

FUZZ_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$FUZZ_DIR")
BUILD="$FUZZ_DIR/build"
HOSTSRC="$BUILD/src"

if [[ -z "${FUZZ_CC:-}" ]]; then
    if [[ -x /opt/homebrew/opt/llvm/bin/clang ]]; then
        FUZZ_CC=/opt/homebrew/opt/llvm/bin/clang
    else
        FUZZ_CC=clang
    fi
fi
SYSROOT=()
if [[ "$(uname)" == Darwin ]]; then
    SYSROOT=(-isysroot "$(xcrun --show-sdk-path)")
fi

SAN=(-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined
     -fno-sanitize=alignment,function)
CFLAGS=(-g -O1 -std=gnu11 -w -DTINYOS_DEV "${SYSROOT[@]}"
        -I"$HOSTSRC" -I"$FUZZ_DIR/common" -include "$HOSTSRC/fuzz_host.h")
CFLAGS+=(${FUZZ_EXTRA_CFLAGS:-})
# COVERAGE=1: source-based coverage instead of sanitizers, into build/<t>-cov,
# for checking that seeds and corpora reach the code a target claims to cover.
SUFFIX=""
if [[ "${COVERAGE:-0}" == 1 ]]; then
    SAN=(-fsanitize=fuzzer -fprofile-instr-generate -fcoverage-mapping)
    SUFFIX="-cov"
fi

# util.c defines memcpy/strlen/... ; rename those so the sanitizer runtime's
# interceptors keep serving every other object, and so panic() can abort().
UTIL_RENAMES=()
for s in memcmp memcpy memmove memset strcasecmp strchr strcmp strlen strncmp \
         strstr panic kernel_panic system_halt; do
    UTIL_RENAMES+=("-D$s=tinyos_util_$s")
done

# target -> kernel sources (space separated, relative to src/)
target_sources() {
    case "$1" in
        dns)   echo "dns.c" ;;
        dhcp)  echo "dhcp.c" ;;
        elfsig) echo "ecdsa.c sha256.c" ;;  # harness #includes elf.c
        fat32) echo "" ;;  # harness #includes fat32.c
        net)   echo "firewall.c ids.c icmp.c tcp.c dns.c dhcp.c kprintf.c sha256.c" ;;  # harness #includes net.c
        *)     echo "unknown target: $1" >&2; return 1 ;;
    esac
}
ALL_TARGETS="dns dhcp net fat32 elfsig"

prep() {
    python3 "$FUZZ_DIR/prep_hostsrc.py" "$ROOT/src" "$FUZZ_DIR/shim" "$HOSTSRC"
}

build_target() {
    local t=$1 out="$BUILD/$t$SUFFIX" objs=() srcs
    srcs=$(target_sources "$t")
    mkdir -p "$out"
    for s in $srcs; do
        "$FUZZ_CC" "${CFLAGS[@]}" "${SAN[@]}" -c "$HOSTSRC/$s" -o "$out/${s%.c}.o"
        objs+=("$out/${s%.c}.o")
    done
    "$FUZZ_CC" "${CFLAGS[@]}" "${SAN[@]}" "${UTIL_RENAMES[@]}" -c "$HOSTSRC/util.c" -o "$out/util.o"
    "$FUZZ_CC" "${CFLAGS[@]}" "${SAN[@]}" -c "$FUZZ_DIR/common/stubs.c" -o "$out/stubs.o"
    "$FUZZ_CC" "${CFLAGS[@]}" "${SAN[@]}" -c "$FUZZ_DIR/targets/fuzz_$t.c" -o "$out/harness.o"
    objs+=("$out/util.o" "$out/stubs.o" "$out/harness.o")

    # First link only to learn what is undefined; then stub it weakly.
    : > "$out/autostubs.c"
    "$FUZZ_CC" "${CFLAGS[@]}" "${SAN[@]}" -c "$out/autostubs.c" -o "$out/autostubs.o"
    if ! "$FUZZ_CC" "${SAN[@]}" "${SYSROOT[@]}" "${objs[@]}" "$out/autostubs.o" \
            -o "$out/fuzz_$t" 2> "$out/link1.err"; then
        python3 "$FUZZ_DIR/gen_weak_stubs.py" "$HOSTSRC" < "$out/link1.err" > "$out/autostubs.c"
        "$FUZZ_CC" "${CFLAGS[@]}" -c "$out/autostubs.c" -o "$out/autostubs.o"
        "$FUZZ_CC" "${SAN[@]}" "${SYSROOT[@]}" "${objs[@]}" "$out/autostubs.o" -o "$out/fuzz_$t"
    fi
    echo "built $out/fuzz_$t ($(grep -c weak "$out/autostubs.c" || true) weak stubs)"
}

prep
targets=("$@")
[[ ${#targets[@]} -eq 0 ]] && read -r -a targets <<< "$ALL_TARGETS"
for t in "${targets[@]}"; do
    build_target "$t"
done
