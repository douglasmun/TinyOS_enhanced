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
    ";": "semicolon",
    ":": "shift-semicolon",
    ",": "comma",
    "=": "equal",
    ">": "shift-dot",
    "<": "shift-comma",
    "|": "shift-backslash",
}
for c in "abcdefghijklmnopqrstuvwxyz0123456789":
    KEYMAP[c] = c
for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    KEYMAP[c] = "shift-" + c.lower()
# digits shifted -> symbols if ever needed
SHIFT_DIGITS = {"!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "&": "7"}
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


def wait_for(text, timeout=240, since=0):
    """Wait until `text` appears in serial at/after byte offset `since`.

    Returns a cursor positioned JUST PAST the matched text (not the full file
    length) so the next wait resumes from there: this neither skips content
    that was already buffered when the previous match resolved, nor re-matches
    an earlier identical banner. Raises on timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = read_serial()
        idx = data.find(text, since)
        if idx >= 0:
            return idx + len(text)
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
    """Type a visible string and echo-verify it landed in the serial log.

    Verifies char-by-char IN ORDER rather than as one contiguous match: a live
    background process writes to the same serial console, so its output
    interleaves into the echo ("jo[SYSCALL]...bs") and a contiguous search for
    "jobs" would spuriously fail on a run that actually worked."""
    start = max(0, len(read_serial()) - len(s) - 4)
    type_str(sock, s)
    cursor = start
    for ch in s:
        if ch == "\n":
            continue
        cursor = wait_for(ch, timeout=timeout, since=cursor)


def main():
    sock = mon_connect()
    print("typist: monitor connected")

    # 1) First-boot: set root password (masked, so we verify prompts only)
    end = wait_for("Enter new root password:", timeout=180)
    type_str(sock, PASSWORD + "\n")

    end = wait_for("Confirm new root password:", timeout=120, since=end)
    type_str(sock, PASSWORD + "\n")

    # PBKDF2 (100k iters) runs here -> slow under TCG; wait generously.
    end = wait_for("Root password set successfully!", timeout=240, since=end)
    print("typist: root password set")

    # 2) Login as root (username echoes -> verify)
    end = wait_for("TinyOS login:", timeout=120, since=end)
    type_verified(sock, "root\n")
    end = wait_for("Password:", timeout=60, since=end)
    type_str(sock, PASSWORD + "\n")

    # Another PBKDF2 verify on login -> slow.
    end = wait_for("Login successful", timeout=240, since=end)
    print("typist: logged in as root")

    # 3) Decline regular-user creation -> straight to shell.
    #    The SECURITY RECOMMENDATION banner + y/n prompt can lag well behind
    #    "Login successful" under TCG host-load spikes, so wait generously.
    end = wait_for("create a regular user now? (y/n):", timeout=180, since=end)
    type_str(sock, "n\n")

    # 4) Login now lands in the RING-3 shell, which has ~13 builtins and knows
    #    nothing of `exec`, pipes or redirection. Every harness except
    #    verify-usershell.sh drives the kernel shell, so by default we type
    #    `kshell` first to get there. Set TINYOS_STAY_IN_RING3=1 to skip it and
    #    drive the ring-3 shell directly.
    #
    #    Doing this here rather than in each harness keeps the eight existing
    #    harnesses working unchanged: the shell they target did not move, only
    #    what login hands you first.
    if os.environ.get("TINYOS_STAY_IN_RING3", "") != "1":
        time.sleep(2)
        print("typist: sending 'kshell' (switch to the kernel shell)")
        mark = len(read_serial())
        type_verified(sock, "kshell\n", timeout=60)
        # Wait for the ring-3 shell to actually exit before typing at the
        # kernel shell; "$" alone is no good as a marker, it is already all
        # over the boot log.
        wait_for("shell: exiting", timeout=120, since=mark)

    # 5) At the shell, run the signed exec as the FIRST command
    #    (give the shell a beat to draw its prompt).
    #    Overridable so harnesses can exercise other binaries/paths
    #    (e.g. TINYOS_EXEC_CMD="exec C:/info.elf").
    exec_cmd = os.environ.get("TINYOS_EXEC_CMD", "exec /hello.elf")
    expect = os.environ.get("TINYOS_EXPECT", "Hello from ELF")
    time.sleep(2)
    print(f"typist: sending '{exec_cmd}'")
    type_verified(sock, exec_cmd + "\n", timeout=60)

    # 5) Wait for the ENFORCE verify result + the program output
    try:
        wait_for(expect, timeout=240, since=end)
        print(f"typist: '{expect}' observed")
    except SystemExit as e:
        # surface whatever we got; the bash verdict will classify
        print(str(e), file=sys.stderr)
        return 2

    # 6) Optional follow-up commands, ';'-separated, sent after the first
    #    command's expect has been observed. Used by the background-jobs
    #    harness to run `jobs`/`ps` while a backgrounded child is still alive.
    #    Each may carry its own expect via "cmd=>expected text".
    followups = os.environ.get("TINYOS_FOLLOWUP_CMDS", "")
    if followups.strip():
        for item in followups.split(";"):
            item = item.strip()
            if not item:
                continue
            if "=>" in item:
                cmd, want = item.split("=>", 1)
                cmd, want = cmd.strip(), want.strip()
            else:
                cmd, want = item, None
            time.sleep(1)
            print(f"typist: sending '{cmd}'")
            mark = len(read_serial())
            type_verified(sock, cmd + "\n", timeout=60)
            if want:
                try:
                    # Same 240s as the first command's expect: a follow-up can
                    # be just as expensive (a ring-3 pipeline spawns TWO
                    # processes, each ECDSA-verified, then streams kilobytes
                    # between them under TCG). Raising a timeout only ever
                    # costs time on a run that was going to fail anyway.
                    wait_for(want, timeout=240, since=mark)
                    print(f"typist: '{want}' observed")
                except SystemExit as e:
                    print(str(e), file=sys.stderr)
                    return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
