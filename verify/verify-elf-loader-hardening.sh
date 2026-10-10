#!/usr/bin/env bash
#
# verify-elf-loader-hardening.sh -- the three defence-in-depth hardenings added
# to the ELF loader after the 2026-10 CVE-class audit. Source-level, no guest.
#
# WHY SOURCE-LEVEL. The audit found NO exploitable bug; these three are hardening
# of a loader that is already correct, and every crafted-segment attack they
# close is only ring-3-reachable in a -DELF_PERMISSIVE_SIGNATURES build (ENFORCE
# rejects an unsigned/tampered binary before the parse ever runs). There is thus
# no signed, ENFORCE-mode guest input that exercises the new rejection paths, and
# a permissive build proves nothing about the shipped default. The property each
# hardening changed is a structural one about the source, so it is asserted there
# -- against both the hardened and the pre-hardening shape, so no leg can pass
# vacuously against a reverted file. Each leg carries a negative control.
#
# THE THREE HARDENINGS
#
# 1. LOCK CONTRACT. The loader (elf_load_process_argv) fills the static
#    allocated_frames[] array and is correct only under elf_exec_lock(), held by
#    the one true entry point elf_exec_from_path(). It used to be exported in
#    elf.h, leaving the lock contract as prose nothing enforced: a future caller
#    wiring it up directly would silently race the static array. Making it (and
#    the dead no-argv wrapper's removal) file-local turns that misuse into a link
#    error. ==> elf.h exports neither symbol; elf.c defines the loader `static`.
#
# 2. PARSE BOUND == SIGNED BOUND. The signature covers [0, signed_size); the
#    184-byte trailer after it is attacker-controlled. The loader now bounds phdr
#    and segment file offsets against parse_size (= signed_size on a verified
#    binary, else the whole buffer), so a crafted phdr cannot point a segment
#    into the unsigned trailer -- what is parsed equals what was hashed.
#    ==> elf_verify_signature hands back the signed length; the two in-file bounds
#    checks test parse_size, not elf_size.
#
# 3. PAGE-GRANULAR OVERLAP. Mapping is page-granular, so two segments that do not
#    overlap byte-for-byte can still share a 4KB page (last-writer-wins contents
#    under first-mapper flags). The overlap check now rounds each segment out to
#    whole pages before comparing. ==> the overlap loop rounds vaddr down and
#    vaddr+memsz up to a page boundary.
set -u

cd "$(dirname "$0")/.." || exit 2

PASS=0; FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "=== verify-elf-loader-hardening.sh ==="
echo

echo "== hardening 1: the loader is file-local, not an unlocked public symbol =="

# 1a. elf.h must NOT export the loader or the old wrapper (a declaration is all a
#     future caller needs to link against it unlocked).
if grep -qE '^[[:space:]]*int[[:space:]]+elf_load_process(_argv)?[[:space:]]*\(' src/elf.h; then
    bad "elf.h still declares elf_load_process/_argv -- the loader is reachable unlocked"
    grep -nE '^[[:space:]]*int[[:space:]]+elf_load_process(_argv)?[[:space:]]*\(' src/elf.h | sed 's/^/       /'
else
    ok "elf.h exports neither elf_load_process nor elf_load_process_argv"
fi

# 1b. elf.c must DEFINE elf_load_process_argv with internal linkage.
if grep -qE '^static int elf_load_process_argv\(' src/elf.c; then
    ok "elf.c defines elf_load_process_argv with 'static' (internal linkage)"
else
    bad "elf_load_process_argv in elf.c is not static -- still externally linkable"
fi

# 1c. The dead no-argv wrapper must be gone (it was unused and only widened the
#     public surface).
if grep -qE '^int elf_load_process\(' src/elf.c; then
    bad "the dead elf_load_process wrapper is still defined in elf.c"
else
    ok "the dead elf_load_process wrapper has been removed"
fi

# 1d. NEGATIVE CONTROL: the sole live caller is still elf_exec_from_path (which
#     holds the lock). If the loader gained an external caller, 1a/1b would not
#     catch it -- assert no CALL site exists outside this file. A bare name in a
#     doc comment (process.h references it by name) is not a call, so match only
#     `elf_load_process_argv(` on a non-comment line.
callers=$(grep -rnE '\belf_load_process_argv[[:space:]]*\(' src/ userspace/ 2>/dev/null \
              | grep -vE ':[0-9]+:[[:space:]]*(\*|/|//)' \
              | grep -v '^src/elf\.c:' || true)
if [ -z "$callers" ]; then
    ok "elf_load_process_argv is not called from outside elf.c"
else
    bad "elf_load_process_argv is called from outside elf.c:"
    printf '%s\n' "$callers" | sed 's/^/       /'
fi

echo
echo "== hardening 2: parse offsets are bound to the SIGNED length, not elf_size =="

# 2a. elf_verify_signature must expose the signed length via a third parameter.
if grep -qE 'bool elf_verify_signature\(const void\* elf_data, size_t elf_size, size_t\* signed_size\)' src/elf.h \
   && grep -qE 'bool elf_verify_signature\(const void\* elf_data, size_t elf_size, size_t\* signed_size\)' src/elf.c; then
    ok "elf_verify_signature returns the signed length through signed_size"
else
    bad "elf_verify_signature does not expose signed_size (prototype/def mismatch)"
fi

# 2b. It must write the signed length ONLY on a verified binary (never on the
#     attacker-influenced failure path).
vs_body="$(awk '/^bool elf_verify_signature\(/{f=1} f{print} f&&/^}/{exit}' src/elf.c)"
if printf '%s\n' "$vs_body" | grep -qE 'valid && signed_size'; then
    ok "signed_size is written guarded by 'valid' (only a verified length escapes)"
else
    bad "signed_size is not gated on a valid signature"
fi

# 2c. The loader computes parse_size and the two in-file bounds checks use it.
#     Extract the DEFINITION body, not the 3-line forward declaration: arm only
#     on the header whose parameter list does NOT end in ';', then run to the
#     first column-0 '}'.
impl_body="$(awk '
    /^static int elf_load_process_argv_impl\(/ { hdr=1 }
    hdr && /\)[[:space:]]*;[[:space:]]*$/ { hdr=0; next }   # forward decl, skip
    hdr && /\)[[:space:]]*\{?[[:space:]]*$/ { f=1; hdr=0 }
    f { print }
    f && /^}/ { exit }
' src/elf.c)"
if printf '%s\n' "$impl_body" | grep -qE 'parse_size *= *has_valid_signature *\? *signed_size *: *elf_size'; then
    ok "loader sets parse_size = signed length on verify, whole buffer in permissive"
else
    bad "loader does not derive parse_size from the signed length"
fi

# 2d. NEGATIVE CONTROL: the phdr-table and per-segment file-bounds checks must
#     test parse_size. The pre-hardening shape tested elf_size -- which includes
#     the 184-byte unsigned trailer -- so neither may compare against elf_size.
phoff_ok=0; seg_ok=0
printf '%s\n' "$impl_body" | grep -qE 'ehdr->e_phoff > parse_size \|\| phdr_table_size > parse_size - ehdr->e_phoff' && phoff_ok=1
printf '%s\n' "$impl_body" | grep -qE 'offset > parse_size \|\| filesz > \(parse_size - offset\)' && seg_ok=1
if [ "$phoff_ok" -eq 1 ] && [ "$seg_ok" -eq 1 ]; then
    ok "both the phdr-table and per-segment file-bounds checks use parse_size"
else
    bad "a file-bounds check still uses elf_size (phoff=$phoff_ok seg=$seg_ok)"
fi

# 2e. NEGATIVE CONTROL, explicit: neither bounds check still reads elf_size.
if printf '%s\n' "$impl_body" | grep -qE '(e_phoff > elf_size|offset > elf_size|filesz > \(?elf_size)'; then
    bad "a parse bounds check still references elf_size (includes the unsigned trailer)"
    printf '%s\n' "$impl_body" | grep -nE '(e_phoff > elf_size|offset > elf_size|filesz > \(?elf_size)' | sed 's/^/       /'
else
    ok "no parse bounds check references elf_size any more"
fi

echo
echo "== hardening 3: the segment-overlap check is page-granular =="

# The overlap loop rounds each segment to whole pages before comparing, so two
# segments sharing a page collide even when their byte ranges do not.
overlap_body="$(awk '/SECURITY FIX \(AUDIT 7B\)/{f=1} f{print} f&&/Validate Total Process Memory/{exit}' src/elf.c)"

# 3a. Page-rounding macros exist and are applied to both ends of each segment.
if printf '%s\n' "$overlap_body" | grep -qE 'ELF_PAGE_DOWN\(phdr\[i\]\.p_vaddr\)' \
   && printf '%s\n' "$overlap_body" | grep -qE 'ELF_PAGE_UP\(phdr\[i\]\.p_vaddr \+ phdr\[i\]\.p_memsz\)' \
   && printf '%s\n' "$overlap_body" | grep -qE 'ELF_PAGE_DOWN\(phdr\[j\]\.p_vaddr\)' \
   && printf '%s\n' "$overlap_body" | grep -qE 'ELF_PAGE_UP\(phdr\[j\]\.p_vaddr \+ phdr\[j\]\.p_memsz\)'; then
    ok "both segments' start and end are rounded to page boundaries before the test"
else
    bad "the overlap check does not page-round both segments' ranges"
fi

# 3b. NEGATIVE CONTROL: the pre-hardening shape compared raw p_vaddr ranges with
#     no rounding -- assert the loop no longer builds its bounds from a bare
#     p_vaddr/p_memsz (every use is wrapped in a page macro).
if printf '%s\n' "$overlap_body" | grep -qE 'seg_[ij]_(start|end) *= *(phdr\[[ij]\]\.p_vaddr|seg)'; then
    bad "an overlap bound is still a raw (unrounded) p_vaddr expression"
    printf '%s\n' "$overlap_body" | grep -nE 'seg_[ij]_(start|end) *=' | sed 's/^/       /'
else
    ok "no overlap bound is an unrounded byte address"
fi

# 3c. The page macros round correctly: DOWN clears the low 12 bits, UP adds
#     0xFFF before masking. (Guards against a macro that rounds the wrong way.)
if printf '%s\n' "$overlap_body" | grep -qE '#define ELF_PAGE_DOWN\(a\) \(\(a\) & ~\(ELF_PAGE_SIZE - 1\)\)' \
   && printf '%s\n' "$overlap_body" | grep -qE '#define ELF_PAGE_UP\(a\)   \(\(\(a\) \+ \(ELF_PAGE_SIZE - 1\)\) & ~\(ELF_PAGE_SIZE - 1\)\)'; then
    ok "ELF_PAGE_DOWN masks low bits and ELF_PAGE_UP rounds the exclusive end up"
else
    bad "the page-rounding macros are not the expected down/up-to-4KB forms"
fi

echo
echo "================ VERDICT ================"
echo "  passed: $PASS   failed: $FAIL"
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: PASS -- the loader is file-local, parses only signed bytes, and"
    echo "  rejects page-sharing segments."
    exit 0
else
    echo "RESULT: FAIL"
    exit 1
fi
