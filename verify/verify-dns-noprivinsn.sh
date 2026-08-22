#!/usr/bin/env bash
#
# verify-dns-noprivinsn.sh — FULLY AUTOMATED check that the parsers PR D1 moves
# to ring 3 contain no privileged instructions, and that DNS still resolves.
#
# WHAT THIS IS TESTING
#
# doc/NETDAEMON_DESIGN.md, D1's first commit. handle_dns_response() is on the
# inbound path that moves to ring 3. It used to snapshot the DNS server address
# under CRITICAL_SECTION_ENTER() -- i.e. `cli`, which executes only at
# CPL <= IOPL. User tasks run with IOPL=0 (process.c, eflags 0x0202), so that
# `cli` would have been a #GP on the first DNS response a ring-3 daemon handled.
#
# The address is now a naturally-aligned 32-bit object accessed with one load or
# store, which is atomic with respect to interrupts at any privilege level and
# needs no lock at all.
#
# WHY THIS ASSERTS ON THE BINARY, NOT THE SOURCE
#
# Grepping dns.c for CRITICAL_SECTION_ENTER proves only that one spelling is
# absent. `cli` reaches the object file through a macro, an inline function, an
# __asm__ block, or any callee that gets inlined -- and the last of those is
# invisible in the source of this file entirely. The question is what the CPU is
# asked to execute, so the check disassembles the linked object.
#
# THE ASSERTION IS THREE-SIDED
#
#   ABSENCE   dns.o/icmp.o/dhcp.o contain no cli/sti opcode
#   PRESENCE  tcp.o DOES contain them -- the negative control. TCP stays in
#             ring 0 precisely because it cannot give up its lock, so a build
#             where tcp.o is also clean means something removed the locking
#             rather than that the moving set was made clean.
#   FUNCTION  DNS still resolves a real name end-to-end, so "no cli" was not
#             achieved by deleting the code that needed it.
#
# The FUNCTION leg matters more than it looks: every other way of satisfying
# ABSENCE (delete the snapshot, drop the source-IP validation, stub the
# handler) also passes ABSENCE. Only an actual resolution proves the parser
# still does its job without the lock.
#
# Exit codes: 0 pass, 1 assertion failed, 2 no output/boot failure,
#             3 build or guard failure.

set -uo pipefail

cd "$(dirname "$0")/.." || exit 3

FAIL=0
note()  { printf '%s\n' "$*"; }
ok()    { printf '  PASS  %s\n' "$*"; }
bad()   { printf '  FAIL  %s\n' "$*"; FAIL=1; }
guard_fail() { printf 'GUARD: %s\n' "$*" >&2; exit 3; }

#==============================================================================
# GUARDS — fail loudly if the thing under test has been renamed or removed,
# rather than passing vacuously.
#==============================================================================

[ -f src/dns.c ] || guard_fail "src/dns.c missing"

grep -q "dns_server_get" src/dns.c \
    || guard_fail "src/dns.c has no dns_server_get(); the aligned-word accessor
this harness exists to verify is gone or renamed. If the design changed, update
this harness deliberately -- do not delete the guard."

grep -q "cmd_dig" src/shell_network.c \
    || guard_fail "cmd_dig not found in src/shell_network.c. Leg 3 drives DNS
through \`dig\`; if that command was renamed this harness would silently grade
a command the shell rejects. (An earlier draft used \`nslookup\`, which does not
exist in this kernel, and leg 3 passed anyway on unrelated boot-log output.)"

grep -q "union" src/dns.c \
    || guard_fail "src/dns.c no longer declares the dns_server union. A bare
uint8_t[4] carries NO alignment guarantee, so the single-load atomicity argument
would not hold even if the accessors were still there."

#==============================================================================
# BUILD
#==============================================================================

note "== Building (default flags) =="
make clean >/dev/null 2>&1
if ! make -j8 kernel.elf >/dev/null 2>&1; then
    guard_fail "build failed"
fi

command -v i686-elf-objdump >/dev/null 2>&1 \
    || guard_fail "i686-elf-objdump not found; cannot inspect the binary"

#==============================================================================
# LEG 1 — ABSENCE: no privileged instructions in the moving set
#==============================================================================

note ""
note "== Leg 1: no cli/sti in the parsers that move to ring 3 =="

count_priv() {
    # Count cli/sti mnemonics in a compiled object. Matches the mnemonic in the
    # disassembly text column only, so a symbol or string containing "cli"
    # (e.g. a "client" label) cannot inflate the count.
    i686-elf-objdump -d "$1" 2>/dev/null \
        | awk '{ for (i=1; i<=NF; i++) if ($i == "cli" || $i == "sti") { n++; break } } END { print n+0 }'
}

for obj in src/dns.o src/icmp.o src/dhcp.o; do
    if [ ! -f "$obj" ]; then
        bad "$obj not built"
        continue
    fi
    n=$(count_priv "$obj")
    if [ "$n" -eq 0 ]; then
        ok "$obj contains no cli/sti"
    else
        bad "$obj contains $n cli/sti instruction(s) — a ring-3 parser would #GP.
      Disassemble with: i686-elf-objdump -d $obj | grep -nE '\\b(cli|sti)\\b'"
    fi
done

#==============================================================================
# LEG 2 — PRESENCE: the negative control
#==============================================================================

note ""
note "== Leg 2: negative control — tcp.o still has them =="

if [ -f src/tcp.o ]; then
    n=$(count_priv src/tcp.o)
    if [ "$n" -gt 0 ]; then
        ok "src/tcp.o contains $n cli/sti (expected: TCP stays ring 0)"
    else
        bad "src/tcp.o contains NO cli/sti. Either TCP_LOCK was removed —
      which would leave tcp_connections[] unserialised against knetd and
      ktimerd — or the counting method above silently stopped working.
      Both make leg 1 meaningless, so this is a failure, not a bonus."
    fi
else
    bad "src/tcp.o not built; cannot run the negative control"
fi

#==============================================================================
# LEG 3 — FUNCTION: DNS still resolves
#==============================================================================

note ""
note "== Leg 3: DNS still resolves end-to-end =="

if [ ! -f dist/tinyos.iso ] || [ kernel.elf -nt dist/tinyos.iso ]; then
    note "  (building ISO)"
    cp kernel.elf iso/boot/kernel.elf 2>/dev/null || guard_fail "cannot stage kernel.elf"
    if ! i686-elf-grub-mkrescue -o dist/tinyos.iso iso >/dev/null 2>&1; then
        guard_fail "grub-mkrescue failed (need xorriso: brew install xorriso)"
    fi
fi

[ -f tools/qemu_typist.py ] \
    || guard_fail "tools/qemu_typist.py missing; cannot drive the functional leg"

WORK=$(mktemp -d -t dnsverify.XXXXXX)
SERIAL="$WORK/serial.log"
MON_SOCK="$WORK/mon.sock"
RUN_DISK="$WORK/disk.img"
PASSWORD="${TINYOS_PASSWORD:-rootpass123}"

# NAT (user-mode) networking, not the mcast socket the injection harnesses use:
# this leg needs a real DNS server to answer, and 10.0.2.3 is QEMU's built-in
# resolver. See memory qemu-networking-wifi-limit for why bridged is not an
# option on this host.
[ -f disk.img ] && cp disk.img "$RUN_DISK"
DISK_ARG=()
[ -f "$RUN_DISK" ] && DISK_ARG=(-drive "file=$RUN_DISK,format=raw,if=ide")

qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso \
    -boot d -m 256M \
    "${DISK_ARG[@]}" \
    -netdev user,id=net0 \
    -device e1000,netdev=net0 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -display none &
QEMU_PID=$!

cleanup_qemu() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; }
trap 'cleanup_qemu; rm -rf "$WORK"' EXIT

TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="dig example.com" \
TINYOS_EXPECT=";; " \
python3 tools/qemu_typist.py >/dev/null 2>&1
TYPIST_RC=$?

sleep 3
cleanup_qemu

if [ ! -s "$SERIAL" ]; then
    note "  no serial output captured (typist rc=$TYPIST_RC)"
    note "  RESULT: FAIL (boot/output failure, not an assertion failure)"
    exit 2
fi

# Assert on dig's FAILURE string being absent, not on an IP address being
# present. The boot log is full of IP addresses (DHCP lease, gateway, DNS
# server), so "an address appeared" passes even when the query never ran -- an
# earlier draft of this harness did exactly that, and passed against a kernel
# with no DNS command at all. `;; connection timed out` is printed only by
# cmd_dig, and only when the resolution loop expired.
if grep -q ";; " "$SERIAL" \
   && ! grep -qi "connection timed out\|Query failed" "$SERIAL" \
   && ! grep -qi "possible DNS spoofing" "$SERIAL"; then
    ok "DNS resolved without tripping the source-IP validation"
else
    bad "DNS did not resolve, or the source-IP check rejected the response.
      That check reads the snapshot this commit changed, so this is the leg
      that catches a broken accessor (e.g. a byte-order slip in the pack or
      unpack, which legs 1 and 2 cannot see)."
    grep -iE "dns|resolv|spoof|nslookup" "$SERIAL" | head -20
fi

#==============================================================================

note ""
if [ "$FAIL" -eq 0 ]; then
    note "RESULT: PASS"
    exit 0
fi
note "RESULT: FAIL"
exit 1
