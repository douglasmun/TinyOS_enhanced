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
import re
import socket
import subprocess
import sys
import time

# Line-buffer our own progress output.
#
# Every harness redirects this script's stdout to a file, which makes Python
# block-buffer it: the "typist: sending ..." trail then sits unflushed until
# exit, so a run that is alive and progressing looks identical to one that hung
# at boot. That cost real diagnosis time -- a harness was declared stuck when
# its log was merely empty. The 56 call sites do not need `python3 -u` for this.
sys.stdout.reconfigure(line_buffering=True)

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
    "'": "apostrophe",
    '"': "shift-apostrophe",
    "\\": "backslash",
    "[": "bracket_left",
    "]": "bracket_right",
    "{": "shift-bracket_left",
    "}": "shift-bracket_right",
    "+": "shift-equal",
    "?": "shift-slash",
    "~": "shift-grave_accent",
    "`": "grave_accent",
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
    # BrokenPipeError here means QEMU is gone, which on a normal run means the
    # harness already computed its verdict and ran cleanup while this process
    # was mid-sendkey. Raising SystemExit rather than letting the traceback
    # through keeps a PASSING log free of a Python stack trace -- noise that
    # trains a reader to skim past the real ones.
    try:
        sock.sendall((cmd + "\n").encode())
    except (BrokenPipeError, ConnectionResetError):
        raise SystemExit("typist: QEMU monitor closed (VM exited)")
    time.sleep(0.05)
    try:
        sock.recv(65536)
    except (socket.timeout, ConnectionResetError):
        pass


def read_serial():
    try:
        with open(SERIAL, "r", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def _despam(s):
    """Remove EDR status-burst text, rejoining what it tore apart.

    The EDR daemon writes to the same serial console as the shell, and it does
    so mid-line: it cuts the shell's echo at an ARBITRARY character, including
    inside the first word. Measured, at the kernel shell, which echoes per
    keystroke:

        $ w[EDR DAEMON] Starting threat scan...
        rite /secret.txt ROO[EDR DAEMON] Starting threat scan...
        TONLYDATA

    No token of "write /secret.txt ROOTONLYDATA" survives contiguously -- not
    the last ("ROOTONLYDATA" is split), not the first ("write" is split), so
    neither a whole-line match nor any single-token fallback can work. The only
    thing that does is to delete the burst and splice the halves back together,
    which restores the original line exactly.

    Lines that START with the marker are pure noise and are dropped whole;
    lines that merely CONTAIN it carry real output before the burst, so that
    prefix is kept and joined to what follows."""
    out = []
    buf = ""
    for line in s.split("\n"):
        if line.startswith("[EDR DAEMON]") or line.startswith("[EDR ADVANCED]"):
            continue
        m = re.search(r"\[EDR (?:DAEMON|ADVANCED)\]", line)
        if m:
            buf += line[:m.start()]
            continue
        out.append(buf + line)
        buf = ""
    if buf:
        out.append(buf)
    return "\n".join(out)


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
    "jobs" would spuriously fail on a run that actually worked.

    ONLY VALID AT THE LOGIN PROMPT, which echoes each keystroke as it is
    accepted. It is no longer used for shell commands at either shell --
    type_echo_line() is, because this function has two weaknesses that only a
    contiguous match fixes:

      - the scan starts at `len(serial) - len(s) - 4`, a window a few bytes
        wide, so whether it resolves depends on what happens to sit in the tail
        already. Both outcomes were seen on the SAME ring-3 path.
      - an in-order per-character scan is a weak witness: any earlier text
        containing those letters in order satisfies it.

    The login prompt is safe because the string is short, fixed ("root"), and
    typed at a point with no prior shell output to collide with."""
    start = max(0, len(read_serial()) - len(s) - 4)
    type_str(sock, s)
    cursor = start
    for ch in s:
        if ch == "\n":
            continue
        cursor = wait_for(ch, timeout=timeout, since=cursor)


def type_echo_line(sock, s, timeout=60):
    """Type a line and wait for the shell's echo of it, as a unit.

    Correct at BOTH shells, and the only correct choice at ring 3.

    type_verified() scans for each character in order starting from
    `len(serial) - len(s) - 4`. That window is a few bytes wide, so whether it
    resolves depends on which characters happen to sit in the tail already --
    it is a coincidence, not a check. Both outcomes were observed on the SAME
    ring-3 path: `help` "passed" only because the shell's own banner
    ("TinyOS shell (ring 3) - 'help' for builtins, ...") is printed just above
    and contains h,e,l,p in order, so the scan matched the BANNER and never
    looked at the echo; `id` timed out because no 'i' fell inside its 7-byte
    window. A check that passes by matching unrelated earlier text is worse
    than no check.

    The ring-3 shell does echo, just not per keystroke: readline() collects the
    line and prints it once after Enter (src/stdio.c:336,
    userspace/shell.c:2035), as "D:/ $ help". So take a mark BEFORE typing and
    wait for the command text after it.

    The EDR status burst tears that echo at an ARBITRARY character, so no
    token-based fallback can be correct -- see _despam(), which has the
    measured case where neither the first nor the last token survives intact.
    Match on the spliced stream instead, which restores the line exactly.

    The mark is taken on the spliced text before typing, so a match can only be
    text this command produced, never an earlier identical line."""
    mark = len(_despam(read_serial()))
    type_str(sock, s)
    body = s.rstrip("\n")
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _despam(read_serial()).find(body, mark) >= 0:
            return
        time.sleep(0.4)
    tail = _despam(read_serial())[-600:]
    raise SystemExit(
        f"typist: TIMEOUT waiting for echo of {body!r}\n--- serial tail ---\n{tail}")


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

    # 2a) OPTIONAL: failed logins before the real one.
    #
    #     Set TINYOS_PRELOGIN_USERS to a comma-separated list of usernames to
    #     type at the login prompt with a wrong password, each expected to fail.
    #     Defaults to empty, so every existing harness is unaffected.
    #
    #     This is the only way to reach user_authenticate()'s "user not found"
    #     branch: `su` rejects a nonexistent user in the shell before it ever
    #     calls the auth path, so the login prompt is the sole vehicle.
    prelogin = os.environ.get("TINYOS_PRELOGIN_USERS", "")
    if prelogin:
        for name in [u for u in prelogin.split(",") if u]:
            end = wait_for("TinyOS login:", timeout=120, since=end)
            print(f"typist: pre-login failure attempt as '{name}'")
            type_verified(sock, name + "\n", timeout=60)
            end = wait_for("Password:", timeout=60, since=end)
            type_str(sock, "wrongpassword\n")
            # "Login incorrect" covers both auth failure branches (-2 user not
            # found, -5 bad password). NOT "Login failed", which is only the
            # `default` case of that switch and would never appear here.
            end = wait_for("Login incorrect", timeout=240, since=end)

        # TINYOS_PRELOGIN_ONLY: stop here. shell_login_prompt() halts the
        # machine after max_attempts failures, so a harness that spends the
        # whole budget on failures has no session to go on to -- waiting for a
        # login prompt that will never be redrawn would just burn the timeout.
        if os.environ.get("TINYOS_PRELOGIN_ONLY", "") == "1":
            print("typist: pre-login failures done (PRELOGIN_ONLY), stopping")
            return

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
        # Type it WITHOUT per-character echo verification.
        #
        # `kshell` is typed at the RING-3 shell, and that shell does not echo
        # per keystroke: readline() collects the line and the whole thing is
        # echoed only after Enter (src/stdio.c:336, userspace/shell.c:2035).
        # Only the KERNEL shell echoes per character. So type_verified()'s
        # first wait_for("k") could never resolve and always burned its full
        # timeout -- "typist: TIMEOUT waiting for 'k'" -- which failed the run
        # at the very first command, before any harness leg was exercised.
        #
        # It presented as a kernel fault: the boot log ends at "[ELF] Hash
        # verification: PASS" with the shell loaded and simply never speaking,
        # and four different harnesses died identically at 85s (chmod-owner,
        # cred-deprecation, env-pertask, fat32-write), so it read as a
        # regression in the shell rather than as one impossible wait.
        #
        # Nothing is lost by dropping the echo check here: the wait_for below
        # is a STRICTER witness. "shell: exiting" is printed by the ring-3
        # shell as it hands over, so it proves the line was received, parsed
        # and acted on -- which a character echo would only have suggested.
        type_str(sock, "kshell\n")
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

    # WAIT FOR THE RING-3 SHELL TO BE READY, don't sleep at it.
    #
    # On the kshell path the wait_for("shell: exiting") above already proves
    # the kernel shell is up. Under TINYOS_STAY_IN_RING3 there was no such
    # witness -- only a flat time.sleep(2) -- and 2 s is nowhere near enough
    # under TCG, where login has to load and ECDSA-verify a 41 KB shell.elf.
    # So the first command was typed into a shell that had not started
    # reading, the keystrokes went nowhere, and the run died waiting for an
    # echo that could never come. The serial log ends at
    # "[ELF] Hash verification: PASS" with no banner and no prompt, which
    # reads as the shell having failed to start rather than as the typist
    # having jumped the gun.
    #
    # The banner is the right witness: the ring-3 shell prints
    # "TinyOS shell (ring 3) - 'help' for builtins, ..." and then its prompt,
    # so seeing it means readline() is running and will accept input.
    if os.environ.get("TINYOS_STAY_IN_RING3", "") == "1":
        end = wait_for("TinyOS shell (ring 3)", timeout=240, since=end)
        time.sleep(1)
    else:
        time.sleep(2)
    print(f"typist: sending '{exec_cmd}'")
    # Same call at BOTH shells. The ring-3 shell echoes the whole line after
    # Enter; the kernel shell echoes per keystroke. Either way the echoed text
    # ends up contiguous in the SPLICED stream, which is what this matches --
    # so there is no longer a per-shell branch to get wrong.
    type_echo_line(sock, exec_cmd + "\n", timeout=60)

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
    #
    #    A step of the form ">NAME" types nothing and instead runs the host
    #    command in $TINYOS_HOOK_NAME -- see the implementation below for why
    #    the command lives in an env var rather than inline.
    #
    #    A line prefixed with '!' is sent WITHOUT the echo check. That is for
    #    input read by something other than the shell's readline — a password
    #    prompt echoes '*' per keystroke, so verifying the characters back would
    #    always fail. The '!' is stripped before typing; an expect still applies,
    #    which is how such a line stays checked at all (on the prompt or result
    #    that follows it, rather than on its own echo).
    #    A trailing "@NAME=<regex>" captures group 1 of <regex> from the output
    #    this command produced, binding it to NAME. Later commands substitute it
    #    as "{NAME}". This exists because some assertions need a value only the
    #    running system knows -- a PID, above all. A harness that must prove
    #    "the user CAN kill their own process" cannot hardcode the PID, and
    #    without the paired positive, a kill that refuses everything satisfies
    #    every "does not leak" assertion while being entirely broken.
    followups = os.environ.get("TINYOS_FOLLOWUP_CMDS", "")
    followup_timeout = int(os.environ.get("TINYOS_FOLLOWUP_TIMEOUT", "240"))
    captures = {}
    if followups.strip():
        for item in followups.split(";"):
            item = item.strip()
            if not item:
                continue
            # A step of the form ">NAME" runs the HOST command in the
            # environment variable TINYOS_HOOK_NAME instead of typing anything
            # into the guest, then continues with the next step.
            #
            # This exists for harnesses that must perturb the guest from
            # OUTSIDE it -- verify-ids-signature.sh injects UDP datagrams to
            # prove the IDS matches packet payloads, and there is no way to
            # make the guest send itself a packet carrying attack bytes
            # without also testing the sending path.
            #
            # The command lives in an env var rather than inline because ';'
            # is this list's separator, so any shell snippet with a ';' in it
            # would be silently torn into fragments and half-executed.
            if item.startswith(">"):
                hookname = item[1:].strip()
                hookcmd = os.environ.get("TINYOS_HOOK_" + hookname)
                if hookcmd is None:
                    print(f"typist: no TINYOS_HOOK_{hookname} in the "
                          f"environment", file=sys.stderr)
                    return 2
                # Substitute captures into the hook the same way typed
                # commands get them. A hook often needs a value only the
                # guest knows -- the UDP/DHCP counter harnesses inject at
                # the guest's IP, which on a socket/mcast netdev has no
                # DHCP server and so is a per-boot link-local 169.254.x.y,
                # not the 10.0.2.15 NAT lease the injector defaults to.
                # Without this the frames are addressed to nobody, and
                # handle_ip drops all of them BEFORE the counters under
                # test -- every delta reads 0, including the positive
                # control, which looks like a dead parser rather than a
                # misaddressed sender.
                for k, v in captures.items():
                    hookcmd = hookcmd.replace("{" + k + "}", v)
                if "{" in hookcmd and "}" in hookcmd:
                    print(f"typist: unresolved substitution in hook "
                          f"{hookname}: {hookcmd}", file=sys.stderr)
                    return 2
                print(f"typist: host hook {hookname}: {hookcmd}")
                rc = subprocess.call(hookcmd, shell=True)
                if rc != 0:
                    # Not a warning. A hook that failed to fire leaves the
                    # guest unperturbed, and the assertion it was meant to set
                    # up then measures nothing -- which for a negative control
                    # looks exactly like a pass.
                    print(f"typist: host hook {hookname} exited {rc}",
                          file=sys.stderr)
                    return 3
                continue
            capture = None
            if "@" in item:
                item, capspec = item.rsplit("@", 1)
                item = item.strip()
                if "=" not in capspec:
                    print(f"typist: bad capture spec '{capspec}'", file=sys.stderr)
                    return 2
                capname, cappat = capspec.split("=", 1)
                capture = (capname.strip(), cappat.strip())
            if "=>" in item:
                cmd, want = item.split("=>", 1)
                cmd, want = cmd.strip(), want.strip()
            else:
                cmd, want = item, None
            unverified = cmd.startswith("!")
            if unverified:
                cmd = cmd[1:]
            for k, v in captures.items():
                cmd = cmd.replace("{" + k + "}", v)
                if want:
                    want = want.replace("{" + k + "}", v)
            if "{" in cmd and "}" in cmd:
                print(f"typist: unresolved substitution in '{cmd}'", file=sys.stderr)
                return 2
            time.sleep(1)
            print(f"typist: sending '{'*' * len(cmd) if unverified else cmd}'")
            mark = len(read_serial())
            if unverified:
                type_str(sock, cmd + "\n")
            else:
                type_echo_line(sock, cmd + "\n", timeout=60)
            if want:
                try:
                    # Same 240s as the first command's expect: a follow-up can
                    # be just as expensive (a ring-3 pipeline spawns TWO
                    # processes, each ECDSA-verified, then streams kilobytes
                    # between them under TCG). Raising a timeout only ever
                    # costs time on a run that was going to fail anyway.
                    #
                    # TINYOS_FOLLOWUP_TIMEOUT raises it further for the rare
                    # harness that drives something even more expensive -- the
                    # task-slot cap probe spawns TEN ECDSA-verified processes
                    # inside ONE command, which does not fit in 240s under TCG.
                    # Default unchanged, so no other harness is affected.
                    wait_for(want, timeout=followup_timeout, since=mark)
                    print(f"typist: '{want}' observed")
                except SystemExit as e:
                    print(str(e), file=sys.stderr)
                    return 3
            if capture:
                capname, cappat = capture
                m = re.search(cappat, read_serial()[mark:])
                if not m:
                    print(f"typist: capture '{capname}' found no match for "
                          f"{cappat!r}", file=sys.stderr)
                    return 3
                val = m.group(1)
                if not val:
                    # An empty group substitutes as "" and the command silently
                    # becomes something else -- "kill {MYPID}" typed as "kill ",
                    # which the shell reads as PID 0. Refuse rather than run a
                    # different command than the harness asked for.
                    print(f"typist: capture '{capname}' matched an EMPTY group "
                          f"for {cappat!r}", file=sys.stderr)
                    return 3
                captures[capname] = val
                print(f"typist: captured {capname}={val}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
