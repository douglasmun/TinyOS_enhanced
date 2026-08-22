#!/usr/bin/env bash
# Unit tests for verify/edr-rejoin.sh. No QEMU, no build -- pure text, so this
# runs in CI alongside the other non-QEMU gates.
#
# Every case here is a defect that shipped: cases 3-7 are the four ways the
# five hand-copied versions of this awk each reported a FALSE non-PASS on a
# correct kernel. Case 6 is the negative control -- the lookahead that fixes
# case 4 must NOT glue ordinary adjacent output lines, or the repair becomes
# a corruption.
set -u
cd "$(dirname "$0")"
. ./edr-rejoin.sh

fail=0
chk() {
    local name="$1" input="$2" want="$3" got
    got=$(printf '%s\n' "$input" | rejoin_edr)
    if [ "$got" = "$want" ]; then
        echo "  PASS: $name"
    else
        echo "  FAIL: $name"
        printf '    want: %s\n    got:  %s\n' "$want" "$got"
        fail=1
    fi
}

chk "clean input is passed through untouched" \
"\$ ls
a.txt
b.txt" \
"\$ ls
a.txt
b.txt"

chk "a line starting with a marker is dropped whole" \
"\$ ls
[EDR DAEMON] Scanning 6 active processes
a.txt" \
"\$ ls
a.txt"

chk "single mid-token tear is rejoined" \
"\$ cat /ou[EDR DAEMON] Starting threat scan...
[EDR DAEMON] Scan complete
t.txt" \
"\$ cat /out.txt"

chk "tear spanning the blank-bracketed status report" \
"\$ e[EDR DAEMON] Starting threat scan...
cho 
[EDR DAEMON] ========== STATUS REPORT ==========
[EDR DAEMON] Uptime: 60 seconds

MARK > /root[EDR DAEMON] Starting threat scan...
only/f.txt
shell: cannot create /rootonly/f.txt" \
"\$ echo MARK > /rootonly/f.txt
shell: cannot create /rootonly/f.txt"

chk "ADVANCED marker is repaired too, not just DAEMON" \
"\$ ca[EDR ADVANCED] Suspicious memory
t /out.txt" \
"\$ cat /out.txt"

chk "END flush recovers a tear with nothing after it" \
"\$ hal[EDR DAEMON] Starting threat scan..." \
"\$ hal"

chk "lone prompt line is held for the echo after the report" \
"D:/ \$ touch /t1.txt
D:/ \$ 
[EDR DAEMON] ========== STATUS REPORT ==========
[EDR DAEMON] Uptime: 60 seconds

cat /t1.txt
KEEPME" \
"D:/ \$ touch /t1.txt
D:/ \$ cat /t1.txt
KEEPME"

# KNOWN LIMIT, asserted so it cannot change silently.
#
# When the burst cuts a line the shell wrote as prompt-AND-text ("$ ech"),
# neither hold rule fires: the prompt rule wants the line to be ONLY a prompt,
# the lookahead wants a fragment already pending, and none is. So the leading
# "$ ech" stays on its own line and the rest is spliced correctly beneath it.
#
# This is deliberate. Generalising either rule to cover it -- e.g. holding any
# line whose successor is a burst -- glues untorn output together instead, and
# both negative controls below catch it ("real two" + "real three" becomes
# "real tworeal three"). The log alone cannot tell "cut mid-write" from "burst
# happened to start after a complete line".
#
# The information that resolves it lives in the typist, which knows the exact
# string it typed, so tools/qemu_typist.py matches with newlines stripped. Do
# not "fix" this case here without re-running that harness -- the real failure
# it caused was verify-ramfs-create-perm.sh reporting INCONCLUSIVE against a
# kernel whose every leg was correct.
chk "KNOWN LIMIT: prompt-plus-partial-text is not rejoined (typist handles it)" \
"D:/ \$ ech
[EDR DAEMON] ========== STATUS REPORT ==========
[EDR DAEMON] Uptime: 60 seconds

o MARKREDIR > /r[EDR DAEMON] Starting threat scan...
ootonly/redir.txt" \
"D:/ \$ ech
o MARKREDIR > /rootonly/redir.txt"

chk "NEGATIVE CONTROL: a prompt cut by a burst does not swallow the next command" \
"D:/ \$ write /a.txt KEEP
D:/ \$ [EDR DAEMON] Starting threat scan...
touch /a.txt" \
"D:/ \$ write /a.txt KEEP
D:/ \$ touch /a.txt"

chk "NEGATIVE CONTROL: adjacent real lines are not glued" \
"real one
real two
[EDR DAEMON] Starting threat scan...
real three" \
"real one
real two
real three"

echo
if [ "$fail" -eq 0 ]; then
    echo "RESULT: PASS -- edr-rejoin.sh behaves on all 10 cases"
else
    echo "RESULT: FAIL -- edr-rejoin.sh regressed"
fi
exit "$fail"
