#!/usr/bin/env bash
#
# verify-curl-sanitize.sh — the kernel-shell `curl` must not hand a remote
# peer's control bytes to the terminal.
#
# cmd_curl printed each received chunk with kprintf("%s", buffer): raw bytes
# chosen by whoever answers on port 80 went straight onto the console. An
# ESC sequence can clear the screen, retitle the window, move the cursor and
# overwrite earlier lines (a forged prompt or a forged "PASS"), and a NUL
# silently truncated the rest of the chunk. The fix prints the body with
# every byte outside 0x20-0x7E, \n, \r and \t replaced by '.'.
#
# Vehicle: QEMU user-net guestfwd maps 10.0.2.100:80 to a local Python server
# that answers one HTTP request with a body full of control bytes. The
# guestfwd target is a chardev: QEMU dials it once at startup, not per guest
# connection, so the peer must not time the idle socket out. The guest
# runs `curl 10.0.2.100/` from the kernel shell. No real network is needed.
#
# Assertions, all on the bytes between "--- Response ---" and "--- End":
#   positive  : CURLHEAD and CURLTAIL both arrived (the body was printed, the
#               text after the NUL was not truncated)
#   ESC       : 0 bytes 0x1b
#   BEL/BS/DEL: 0 bytes 0x07, 0x08, 0x7f
#   high      : 0 bytes >= 0x80 from the payload's 0x9b (8-bit CSI)
#   placeholder: the sanitized sequence "CURLHEAD.[2J" is present, i.e. the
#               bytes were replaced in place, not dropped
#
# Exit 0 = PASS, 1 = FAIL, 2 = no output, 3 = INCONCLUSIVE.
# Logs: curlsan.log (serial), curlsan-trace.log.
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-${TINYOS_PASSWORD:-rootpass1}}"

ISO=dist/tinyos.iso
SERIAL=curlsan.log
TRACE=curlsan-trace.log
RUN_DISK=/tmp/tinyos-curlsan-disk.img
MON_SOCK=/tmp/tinyos-curlsan-mon.sock
PORT_FILE=$(mktemp -t curlsan-port)

echo "==> Building kernel + userspace + ISO..."
(cd userspace && make) >/dev/null || exit 1
python3 tools/sign_elf.py userspace/shell.elf userspace/shell.elf.signed >/dev/null 2>&1 || exit 1
python3 tools/elf_to_c.py userspace/shell.elf.signed \
        src/shell_elf_data.c src/shell_elf_data.h shell_elf_data >/dev/null || exit 1
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

# One-shot HTTP peer. Body: ESC CSI clear-screen, an OSC window-title set
# terminated by BEL, two backspaces, DEL, an 8-bit CSI (0x9b), and a NUL
# followed by a tail marker that only survives if NUL is not a terminator.
python3 - "$PORT_FILE" <<'PY' &
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0)); s.listen(4)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
body = (b"CURLHEAD\x1b[2J\x1b]0;pwned\x07XX\x08\x08\x7f\x9bQ\x00CURLTAIL\n")
s.settimeout(900)
while True:
    try:
        c, _ = s.accept()
    except socket.timeout:
        break
    # guestfwd's chardev connects ONCE, at QEMU startup, long before the
    # guest types curl -- so wait for the request as long as the run lasts.
    c.settimeout(900)
    try:
        c.recv(4096)
        c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
    except OSError:
        pass
    c.close()
PY
PEER_PID=$!
for _ in $(seq 50); do [ -s "$PORT_FILE" ] && break; sleep 0.1; done
PORT=$(cat "$PORT_FILE")
[ -n "$PORT" ] || { echo "RESULT: INCONCLUSIVE — HTTP peer did not start"; kill "$PEER_PID"; exit 3; }

rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
[ -f disk.img ] || { echo "ERROR: disk.img not found"; exit 1; }
cp disk.img "$RUN_DISK"

echo "==> Launching QEMU (guestfwd 10.0.2.100:80 -> 127.0.0.1:$PORT)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev "user,id=net0,guestfwd=tcp:10.0.2.100:80-tcp:127.0.0.1:$PORT" \
    -device e1000,netdev=net0 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() {
    kill "$QEMU_PID" "$PEER_PID" 2>/dev/null
    wait "$QEMU_PID" "$PEER_PID" 2>/dev/null
    rm -f "$MON_SOCK" "$PORT_FILE"
}
trap cleanup EXIT

TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_FOLLOWUP_TIMEOUT=600 \
TINYOS_EXEC_CMD="ifconfig" \
TINYOS_EXPECT="IP Address" \
TINYOS_FOLLOWUP_CMDS="curl 10.0.2.100/=>--- End" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"
[ -s "$SERIAL" ] || { echo "RESULT: FAIL — no serial output (typist rc=$TYPIST_RC)"; exit 2; }

# Byte-exact window: everything after the LAST "--- Response ---" up to
# "--- End". perl, because grep/sed would treat NUL and ESC unevenly.
WINDOW=$(mktemp -t curlsan-win)
perl -0777 -ne 'if (/.*--- Response ---(.*?)--- End/s) { print $1 }' "$SERIAL" > "$WINDOW"
if [ ! -s "$WINDOW" ]; then
    echo "RESULT: INCONCLUSIVE — no curl response window in the log (typist rc=$TYPIST_RC)"
    grep -a "curl\|Fetching\|Failed\|timeout\|DNS" "$SERIAL" | tail -10
    rm -f "$WINDOW"; exit 3
fi

count() { perl -0777 -ne "\$n = () = /$1/g; print \$n+0" "$WINDOW"; }
HEAD=$(count 'CURLHEAD')
TAIL=$(count 'CURLTAIL')
ESC=$(count '\x1b')
CTRL=$(count '[\x07\x08\x7f]')
HIGH=$(count '[\x80-\xff]')
NUL=$(count '\x00')
PLACE=$(count 'CURLHEAD\.\[2J')
rm -f "$WINDOW"

echo "  head=$HEAD tail=$TAIL esc=$ESC bel/bs/del=$CTRL high=$HIGH nul=$NUL placeholder=$PLACE"

if [ "$HEAD" -lt 1 ]; then
    echo "RESULT: INCONCLUSIVE — the body never arrived (no CURLHEAD), so nothing was graded"
    exit 3
fi
FAILS=0
[ "$ESC" -eq 0 ]  || { echo "  FAIL: $ESC ESC byte(s) from the peer reached the console"; FAILS=$((FAILS+1)); }
[ "$CTRL" -eq 0 ] || { echo "  FAIL: $CTRL BEL/BS/DEL byte(s) reached the console"; FAILS=$((FAILS+1)); }
[ "$HIGH" -eq 0 ] || { echo "  FAIL: $HIGH byte(s) >= 0x80 reached the console"; FAILS=$((FAILS+1)); }
[ "$NUL" -eq 0 ]  || { echo "  FAIL: NUL reached the console"; FAILS=$((FAILS+1)); }
[ "$TAIL" -ge 1 ] || { echo "  FAIL: CURLTAIL missing -- the NUL truncated the rest of the chunk"; FAILS=$((FAILS+1)); }
[ "$PLACE" -ge 1 ] || { echo "  FAIL: 'CURLHEAD.[2J' absent -- control bytes were not replaced in place"; FAILS=$((FAILS+1)); }

if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL — $FAILS assertion(s)"
    exit 1
fi
echo "RESULT: PASS — remote control bytes are replaced with '.' before reaching the console"
exit 0
