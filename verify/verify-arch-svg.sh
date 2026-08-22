#!/usr/bin/env bash
#
# verify-arch-svg.sh -- the architecture diagram still matches the tree.
#
# WHY THIS EXISTS
# The README's architecture SVG is the first thing a visitor sees, and nothing
# in the build reads it, so it rots silently. It did: the committed pair still
# said "81 kernel modules", drew FAT32 as read-only, showed the kernel shell as
# the login shell (the ring-3 shell has been default since PR #51), and omitted
# knetd/the supervisor entirely. Worse, the light and dark files had drifted to
# DIFFERENT viewBoxes and different markup, so fixing one would not fix the other.
#
# Both are now generated from tools/gen_architecture_svg.py. This script checks
# the claims that have a machine-checkable counterpart in the source, and that
# the generator output is committed (i.e. nobody hand-edited an SVG).
#
# WHAT IT CANNOT CHECK: whether the picture is well laid out. Rendering is a
# human call -- rsvg-convert both files and look.
set -u
cd "$(dirname "$0")/.." || exit 2

pass=0; fail=0
ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $1"; fail=$((fail+1)); }

LIGHT=doc/img/architecture.svg
DARK=doc/img/architecture-dark.svg
GEN=tools/gen_architecture_svg.py

echo "=== 1. both SVGs are the generator's current output ==="
if [ ! -f "$GEN" ]; then
    bad "generator $GEN is missing"
else
    tmp=$(mktemp -d)
    cp "$LIGHT" "$tmp/l.svg"; cp "$DARK" "$tmp/d.svg"
    if python3 "$GEN" >/dev/null 2>&1; then
        if cmp -s "$LIGHT" "$tmp/l.svg" && cmp -s "$DARK" "$tmp/d.svg"; then
            ok "committed SVGs match the generator (no hand edits)"
        else
            bad "committed SVGs differ from the generator -- run: python3 $GEN"
            cp "$tmp/l.svg" "$LIGHT"; cp "$tmp/d.svg" "$DARK"
        fi
    else
        bad "generator failed to run"
    fi
    rm -rf "$tmp"
fi

echo "=== 2. both variants have the same structure ==="
# Same box/text count means a change to one reached the other. This is what
# broke before: two independently hand-drawn files.
for tag in rect text line; do
    l=$(grep -c "<$tag " "$LIGHT"); d=$(grep -c "<$tag " "$DARK")
    if [ "$l" = "$d" ]; then ok "<$tag> count matches ($l)"
    else bad "<$tag> count differs: light $l vs dark $d"; fi
done
lv=$(grep -o 'viewBox="[^"]*"' "$LIGHT" | head -1)
dv=$(grep -o 'viewBox="[^"]*"' "$DARK" | head -1)
[ "$lv" = "$dv" ] && ok "viewBox matches ($lv)" || bad "viewBox differs: $lv vs $dv"

echo "=== 3. claims that must track the source ==="
# The SRC list runs from `SRC :=` to the `OBJ :=` line that consumes it. An
# awk range ending on /^[A-Z]+ *:?=/ matches `SRC :=` ITSELF and yields 0, which
# reads as "the SVG is wrong" against a correct diagram -- that false failure is
# why the range is anchored on OBJ.
MODULES=$(awk '/^SRC :=/{f=1;next} f&&/^OBJ/{exit} f' Makefile \
          | grep -oE 'src/[a-z0-9_]+\.c' | sort -u | wc -l | tr -d ' ')
grep -q "$MODULES kernel modules" "$LIGHT" \
    && ok "module count $MODULES matches the Makefile SRC block" \
    || bad "module count in SVG != $MODULES (Makefile SRC block)"

MAXSYS=$(grep -oE '#define MAX_SYSCALL_NUM +[0-9]+' src/syscall.h | grep -oE '[0-9]+$')
NSYS=$(grep -cE '^#define SYS_[A-Z_]+ +[0-9]+' src/syscall.h)
grep -q "$NSYS syscalls" "$LIGHT" \
    && ok "syscall count $NSYS matches src/syscall.h" \
    || bad "syscall count in SVG != $NSYS"
grep -q "SYS_ENV $MAXSYS" "$LIGHT" \
    && ok "highest syscall SYS_ENV $MAXSYS matches MAX_SYSCALL_NUM" \
    || bad "highest syscall in SVG != MAX_SYSCALL_NUM ($MAXSYS)"

# FAT32 gained a write op; the old diagram said "(read)".
if grep -q '\.write *= *fat32_vfs_write' src/fat32_vfs.c; then
    grep -q 'FAT32   (read / write)' "$LIGHT" \
        && ok "FAT32 drawn read/write, matching its file_operations_t" \
        || bad "fat32_vfs registers .write but the SVG does not say read/write"
fi

# The ring-3 shell is the login shell; the kernel shell is the fallback.
if grep -q 'ring-3 login shell' src/shell.c; then
    grep -q 'DEFAULT LOGIN SHELL' "$LIGHT" \
        && ok "shell.elf drawn as the default login shell" \
        || bad "shell.c launches the ring-3 login shell but the SVG does not show it"
    grep -q 'Kernel shell (fallback)' "$LIGHT" \
        && ok "kernel shell drawn as the fallback" \
        || bad "kernel shell should be drawn as the fallback"
fi

# Daemons that exist must appear.
for d in knetd ktimerd supervisor edr_daemon; do
    if grep -qE "task_(create_kernel|knetd|ktimerd|supervisor)|${d}" src/kernel.c >/dev/null 2>&1; then
        grep -q "$d" "$LIGHT" && ok "daemon '$d' appears in the diagram" \
                              || bad "daemon '$d' runs at boot but is not drawn"
    fi
done

# The RX path parses in task context -- the single most load-bearing net fact.
grep -q 'rx_softirq_ring' src/e1000.c && {
    grep -q 'TASK context' "$LIGHT" \
        && ok "RX drawn as parsing in task context" \
        || bad "rx_softirq_ring exists but the SVG does not show task-context RX"
}

# Default-deny firewall.
grep -q 'Default: DENY ALL' src/firewall.c && {
    grep -q 'default DENY ALL' "$LIGHT" \
        && ok "firewall drawn as default-deny" \
        || bad "firewall.c is default-deny but the SVG does not say so"
}

echo
echo "================ VERDICT ================"
echo "  passed: $pass   failed: $fail"
if [ "$fail" -eq 0 ]; then
    echo "RESULT: PASS -- the architecture diagram matches the tree."
    echo "  NOTE: layout/legibility is NOT checked. Render both files and look:"
    echo "    rsvg-convert -w 1400 $LIGHT -o /tmp/arch-light.png"
    exit 0
else
    echo "RESULT: FAIL -- the diagram no longer matches the source."
    echo "  Edit tools/gen_architecture_svg.py (never the .svg files), then rerun."
    exit 1
fi
