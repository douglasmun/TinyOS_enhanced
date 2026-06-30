#!/usr/bin/env python3
"""qemu_typist.py — drive TinyOS's first-boot flow over the QEMU monitor socket.

Reads the serial log (TINYOS_SERIAL), waits for each expected prompt, then sends
the scripted keystrokes via QEMU monitor `sendkey` over the Unix socket
(TINYOS_MON_SOCK). Echo-verifies VISIBLE input (username, command) by polling the
serial log; password input is masked so only prompt transitions are checked.

Designed for slow TCG boots: every wait has a generous timeout and the typist
re-reads the whole serial file each poll (it's small).
"""
import os
import socket
import sys
import time

SERIAL = os.environ["TINYOS_SERIAL"]
MON_SOCK = os.environ["TINYOS_MON_SOCK"]
PASSWORD = os.environ.get("TINYOS_PASSWORD", "rootpass1")

# char -> QEMU sendkey key name (US layout). Covers what we actually type.
KEYMAP = {
    "\n": "ret",
    " ": "spc",
    "/": "slash",
    ".": "dot",
    "-": "minus",
    "_": "shift-minus",
}
for c in "abcdefghijklmnopqrstuvwxyz0123456789":
    KEYMAP[c] = c
for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    KEYMAP[c] = "shift-" + c.lower()
# digits shifted -> symbols if ever needed
SHIFT_DIGITS = {"!": "1", "@": "2", "#": "3", "$": "4", "%": "5"}
for sym, d in SHIFT_DIGITS.items():
    KEYMAP[sym] = "shift-" + d


def mon_connect(timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(MON_SOCK)
            s.settimeout(5)
            # drain the QEMU monitor banner
            time.sleep(0.3)
            try:
                s.recv(65536)
            except socket.timeout:
                pass
            return s
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.5)
    raise SystemExit("typist: could not connect to QEMU monitor socket")


def mon_cmd(sock, cmd):
    sock.sendall((cmd + "\n").encode())
    time.sleep(0.05)
    try:
        sock.recv(65536)
    except socket.timeout:
        pass


def read_serial():
    try:
        with open(SERIAL, "r", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def wait_for(text, timeout=120, since=0):
    """Wait until `text` appears in serial AFTER byte offset `since`.
    Returns the new total serial length, or raises on timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = read_serial()
        idx = data.find(text, since)
        if idx >= 0:
            return len(data)
        time.sleep(0.4)
    tail = read_serial()[-600:]
    raise SystemExit(f"typist: TIMEOUT waiting for {text!r}\n--- serial tail ---\n{tail}")


def send_key(sock, ch):
    key = KEYMAP.get(ch)
    if key is None:
        raise SystemExit(f"typist: no keymap for char {ch!r}")
    mon_cmd(sock, "sendkey " + key)
    # TCG needs settle time between keys or it drops them
    time.sleep(0.18)


def type_str(sock, s):
    for ch in s:
        send_key(sock, ch)


def type_verified(sock, s, timeout=40):
    """Type a visible string and echo-verify it landed in the serial log."""
    start = len(read_serial())
    type_str(sock, s)
    # the chars should echo back (login/username/command all echo)
    wait_for(s, timeout=timeout, since=max(0, start - len(s) - 4))


def main():
    sock = mon_connect()
    print("typist: monitor connected")

    # 1) First-boot: set root password (masked, so we verify prompts only)
    end = wait_for("Enter new root password:", timeout=180)
    type_str(sock, PASSWORD + "\n")

    end = wait_for("Confirm new root password:", timeout=60, since=end)
    type_str(sock, PASSWORD + "\n")

    end = wait_for("Root password set successfully!", timeout=120, since=end)
    print("typist: root password set")

    # 2) Login as root (username echoes -> verify)
    end = wait_for("TinyOS login:", timeout=60, since=end)
    type_verified(sock, "root\n")
    end = wait_for("Password:", timeout=30, since=end)
    type_str(sock, PASSWORD + "\n")

    end = wait_for("Login successful", timeout=120, since=end)
    print("typist: logged in as root")

    # 3) Decline regular-user creation -> straight to shell
    end = wait_for("create a regular user now? (y/n):", timeout=60, since=end)
    type_str(sock, "n\n")

    # 4) At the shell, run the signed exec as the FIRST command
    #    (give the shell a beat to draw its prompt)
    time.sleep(2)
    print("typist: sending 'exec /hello.elf'")
    type_verified(sock, "exec /hello.elf\n", timeout=60)

    # 5) Wait for the ENFORCE verify result + the program output
    try:
        wait_for("Hello from ELF", timeout=240, since=end)
        print("typist: 'Hello from ELF!' observed")
    except SystemExit as e:
        # surface whatever we got; the bash verdict will classify
        print(str(e), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
