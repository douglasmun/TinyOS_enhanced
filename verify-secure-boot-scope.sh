#!/usr/bin/env bash
#
# verify-secure-boot-scope.sh -- secure_boot.c holds a pinned key and nothing else.
#
# The bug this guards: secure_boot.c exported a whole DoD/UEFI/TCG-shaped API
# (a second signature verifier, measured-boot PCRs, rollback protection) of
# which NOTHING was ever called, while printing "Measured boot: ENABLED" on a
# machine whose PCRs stayed zero for its entire lifetime. Same class as the
# secstatus "ELF signatures ENFORCED" lie (verify-elf-enforce-report.sh) and
# the IDS loaded-vs-matched count: a status surface that structurally cannot
# report the state it names.
#
# Legs 1-3 are source assertions -- a boot cannot witness the ABSENCE of a
# function. Leg 4 is the runtime half: the honest line prints and the dishonest
# ones do not. Leg 5 is the positive control, and it is the load-bearing one:
# legs 1-4 all pass if you delete the subsystem entirely, so something must
# prove the key that survived is still gating exec.
set -u

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "== leg 1: the dead API is gone from the header =="
DEAD="secure_boot_verify secure_boot_verify_elf secure_boot_extend_pcr
      secure_boot_get_pcr secure_boot_lock secure_boot_is_enforced
      secure_boot_set_min_version secure_boot_attest secure_boot_set_enforcement"
gone=1
for f in $DEAD; do
    if grep -qE "^[a-z].*\b${f}\b *\(" src/secure_boot.h; then
        bad "$f is still declared in secure_boot.h"; gone=0
    fi
done
[ $gone -eq 1 ] && ok "all 9 uncalled functions are gone from secure_boot.h"

echo "== leg 2: no rival enforcement accessor anywhere =="
# secure_boot_is_enforced() was hardwired true. If it comes back, secstatus or
# some future status surface WILL source its answer from it again.
if grep -rn "secure_boot_is_enforced" src --include='*.c' --include='*.h' \
     | grep -vE '^\S+: *\*|^\S+: */\*' | grep -q "secure_boot_is_enforced *("; then
    bad "a callable secure_boot_is_enforced() exists again"
else
    ok "no callable secure_boot_is_enforced(); elf_signatures_enforced() is the only gate"
fi

echo "== leg 3: the only exported API is init + get_config =="
EXPORTED=$(grep -cE "^(void|int|bool) +secure_boot_[a-z_]+ *\(" src/secure_boot.h)
if [ "$EXPORTED" = "2" ]; then
    ok "secure_boot.h exports exactly 2 functions (init, get_config)"
else
    bad "secure_boot.h exports $EXPORTED functions, expected 2"
    grep -nE "^(void|int|bool) +secure_boot_[a-z_]+ *\(" src/secure_boot.h | sed 's/^/       /'
fi

echo "== leg 4: the boot log claims only what is true =="
LOG=$(mktemp /tmp/sbscope.XXXXXX.log)
trap 'rm -f "$LOG"' EXIT
make -j8 kernel.elf >/dev/null 2>&1 || { echo "  build failed"; exit 1; }
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o dist/tinyos.iso iso >/dev/null 2>&1
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso -boot d \
    -m 256M -netdev user,id=net0 -device e1000,netdev=net0 \
    -serial file:"$LOG" -display none >/dev/null 2>&1 &
QP=$!; sleep 25; kill $QP 2>/dev/null; wait $QP 2>/dev/null

SB=$(grep -a "SECURE_BOOT" "$LOG" | tr -d '\r')
if echo "$SB" | grep -q "Signing key pinned"; then
    ok "boot log reports the pinned key"
else
    bad "boot log is missing the 'Signing key pinned' line"
fi
# These are the lies. Each one named a subsystem that did not run.
for lie in "Measured boot" "Enforcement:" "Rollback protection"; do
    if echo "$SB" | grep -q "$lie"; then
        bad "boot log still prints a '$lie' claim"
    else
        ok "boot log no longer claims '$lie'"
    fi
done

echo "== leg 5 (POSITIVE CONTROL): the surviving key still gates exec =="
# Legs 1-4 pass just as well against a deleted subsystem. This is what
# distinguishes "pruned to the load-bearing part" from "gutted".
if ! grep -q "secure_boot_get_config" src/elf.c; then
    bad "elf.c no longer consults the pinned key -- the prune went too far"
elif timeout 400 ./auto-verify-exec.sh 2>&1 | grep -q "RESULT: PASS"; then
    ok "signed hello.elf verifies and runs against the pinned key"
else
    bad "exec of a signed binary no longer works"
fi

echo
echo "================ VERDICT ================"
echo "  passed: $PASS   failed: $FAIL"
if [ $FAIL -eq 0 ]; then
    echo "RESULT: PASS -- secure_boot.c is a pinned key and nothing more"; exit 0
else
    echo "RESULT: FAIL"; exit 1
fi
