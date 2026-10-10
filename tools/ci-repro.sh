#!/usr/bin/env bash
#==============================================================================
# ci-repro.sh -- run .github/workflows/build.yml locally, faithfully.
#
# WHY THIS EXISTS
#
# CI builds with Ubuntu's gcc-i686-linux-gnu; the dev machine builds with
# Homebrew's i686-elf-gcc. The two crosses disagree in ways that pass locally
# and fail CI -- size_t is `unsigned long` on the i686-elf cross but `unsigned
# int` on i686-linux-gnu, so a `%lu` on a size_t is -Werror-clean here and red
# there (see the tree's history of exactly that). Ubuntu's gcc is also newer
# (15.x) and warns about more. So "it built for me" proves nothing about the
# -Werror gate CI actually enforces.
#
# This reproduces that gate without an i686-linux-gnu toolchain on macOS: it
# runs the workflow's own steps inside an ubuntu container, with the SAME
# packages, compiler, flags and harnesses as build.yml. A green run here is a
# green CI run.
#
# WHAT IT MIRRORS (keep in step with .github/workflows/build.yml)
#
#   build job:
#     1. warning-clean -Werror build           (CROSS + -nostdinc -isystem)
#     2. confirm the artifact is a 32-bit ELF
#     3. fault-inject build is warning-clean    (-DTINYOS_FAULT_INJECT)
#     4. every header compiles standalone
#   source-guards job (the non-QEMU harnesses):
#     arch-svg, shell-path-overflow, entropy-pool-stir, ring3-help-complete,
#     edr-rejoin, preserve-serial, elf-enforce-report
#
# NOTES
#
#   - It runs in a throwaway container bind-mounting the repo read/write, and
#     `make clean`s before and after so it never races or pollutes your local
#     i686-elf build tree. (CI gets a fresh checkout; the clean is what makes
#     this equivalent.)
#   - build-essential and python3 are installed on top of the workflow's
#     package list because the real ubuntu-latest runner ships them and two
#     guards rely on them: verify-shell-path-overflow.sh's boundary proof
#     compiles with a host cc against <stdio.h>, and verify-arch-svg.sh runs
#     tools/gen_architecture_svg.py. A bare container lacks both, and the
#     resulting FAILs are environment gaps, not defects.
#
# USAGE
#   tools/ci-repro.sh            # both jobs
#   tools/ci-repro.sh build      # build job only
#   tools/ci-repro.sh guards     # source-guards job only
#   IMAGE=ubuntu:24.04 tools/ci-repro.sh   # pin the base image
#==============================================================================
set -euo pipefail

JOB="${1:-all}"
IMAGE="${IMAGE:-ubuntu:latest}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$JOB" in
    all|build|guards) ;;
    *) echo "usage: $0 [all|build|guards]" >&2; exit 2 ;;
esac

if ! command -v docker >/dev/null 2>&1; then
    echo "ci-repro: docker not found -- this needs a Linux container to run" >&2
    echo "          the i686-linux-gnu toolchain CI uses (unavailable on macOS)." >&2
    exit 2
fi
if ! docker info >/dev/null 2>&1; then
    echo "ci-repro: docker daemon is not running." >&2
    exit 2
fi

echo "== ci-repro: job=$JOB image=$IMAGE =="

docker run --rm -e JOB="$JOB" -v "$REPO_ROOT":/src -w /src "$IMAGE" bash -euo pipefail -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# Workflow package set + build-essential (host cc/libc for the boundary proof,
# present on the real runner).
apt-get install -y -qq --no-install-recommends \
    gcc-i686-linux-gnu binutils-i686-linux-gnu nasm make file \
    build-essential python3 bash gawk coreutils >/dev/null

GCCINC="$(i686-linux-gnu-gcc -print-file-name=include)"
CROSS=i686-linux-gnu-
XCFLAGS="-nostdinc -isystem $GCCINC"

echo "toolchain: $(i686-linux-gnu-gcc --version | head -1)"
echo "nasm:      $(nasm --version)"

run_build() {
    echo "### build job ###"

    echo "--- 1. warning-clean -Werror build ---"
    make clean >/dev/null 2>&1 || true
    make -j"$(nproc)" CROSS="$CROSS" EXTRA_CFLAGS="$XCFLAGS" kernel.elf

    echo "--- 2. confirm 32-bit ELF ---"
    file kernel.elf
    i686-linux-gnu-readelf -h kernel.elf | grep -E "Class:|Machine:"

    echo "--- 3. fault-inject build is warning-clean ---"
    make clean >/dev/null
    make -j"$(nproc)" CROSS="$CROSS" \
         EXTRA_CFLAGS="$XCFLAGS -DTINYOS_FAULT_INJECT" kernel.elf
    make clean >/dev/null

    echo "--- 4. every header compiles standalone ---"
    echo "int ci_translation_unit;" > /tmp/probe.c
    rc=0
    for h in src/*.h userspace/*.h; do
        i686-linux-gnu-gcc -m32 -ffreestanding -Isrc -Iuserspace \
            -nostdinc -isystem "$GCCINC" \
            -c -include "$h" /tmp/probe.c -o /tmp/probe.o 2>/tmp/err.txt \
            || { echo "NOT SELF-SUFFICIENT: $h"; sed -n "1,6p" /tmp/err.txt; rc=1; }
    done
    [ "$rc" -eq 0 ] && echo "all headers self-sufficient"
    return $rc
}

run_guards() {
    echo "### source-guards job ###"
    rc=0
    for g in \
        verify/verify-arch-svg.sh \
        verify/verify-shell-path-overflow.sh \
        verify/verify-entropy-pool-stir.sh \
        verify/verify-ring3-help-complete.sh \
        verify/edr-rejoin-test.sh \
        verify/preserve-serial-test.sh
    do
        echo "--- $g ---"
        bash "$g" || { echo "GUARD FAILED: $g"; rc=1; }
    done

    echo "--- verify-elf-enforce-report.sh (builds twice) ---"
    make clean >/dev/null 2>&1 || true
    CROSS="$CROSS" OBJDUMP=i686-linux-gnu-objdump EXTRA_CFLAGS="$XCFLAGS" \
        bash verify/verify-elf-enforce-report.sh || { echo "GUARD FAILED: elf-enforce-report"; rc=1; }
    make clean >/dev/null 2>&1 || true
    return $rc
}

overall=0
case "$JOB" in
    build)  run_build  || overall=1 ;;
    guards) run_guards || overall=1 ;;
    all)    run_build  || overall=1; run_guards || overall=1 ;;
esac

echo "########## ci-repro ($JOB) overall RC=$overall ##########"
exit $overall
'
