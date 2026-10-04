# TinyOS Enhanced — User Guide

A short, practical guide to booting and using TinyOS Enhanced. For what the
project *is* and its security scope, see the top-level [`README.md`](../README.md);
for design/security internals, see the other documents in this `doc/` folder.

> **Reminder:** this is an educational/hobby OS — single-core, 32-bit,
> console-only, QEMU-targeted, and **not** for production or untrusted networks.

---

## 1. Booting it

The quickest way is the prebuilt demo ISO from the GitHub **Releases** page, run
under QEMU. The kernel runs DHCP at boot, so attach a virtual NIC so it gets a
lease immediately:

```sh
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom tinyos.iso -m 256M \
  -netdev user,id=net0 -device e1000,netdev=net0
```

(Building from source instead? See **Build & run** in the README. The
`-cpu ...,+rdrand,+rdseed` flags matter — the kernel seeds its CSPRNG from the
hardware RNG at boot.)

You will see boot diagnostics scroll past — entropy/RNG health checks, stack-guard
and ASLR init, the TinyOS banner, then driver and filesystem setup.

---

## 2. First-boot password setup

TinyOS ships with **no default password**. On the very first boot it walks you
through setting the `root` password:

```
 First-Time Setup: Let's Create Your Password
For security, let's set up a root password.
Enter new root password: ********
Confirm new root password: ********
Root password set successfully!
```

The password is hashed with **PBKDF2-HMAC-SHA256 (100,000 iterations)** — there are
no hard-coded credentials anywhere in the system.

> **Where is the password stored?** Only in **kernel memory** — TinyOS has no
> on-disk `/etc/shadow` or credential file by design, so hashes can't be lifted
> from a disk image, backup, or mounted filesystem. The trade-off is that
> accounts don't persist across reboots (you set the root password fresh each
> boot). See *Kernel-Only Credential Store* in
> [`SECURITY_HARDENING.md`](SECURITY_HARDENING.md).

---

## 3. Logging in

After setup you reach the login prompt:

```
*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*
  TinyOS v2.8 Login System
*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*

TinyOS login: root
Password: ********

Login successful. Welcome, root!
```

The first time `root` logs in while it is the only account, TinyOS offers to
create a regular user for daily work (`Would you like to create a regular user
now? (y/n):`). Answer `y` to create one, or `n` and use `useradd` later.

**Failed logins.** Every failure prints the same `Login incorrect`, whatever the
reason, followed by the number of attempts left. The prompt allows **3 attempts**;
after the third it prints `Login failed. System halted.` and you must restart the
VM (and, since accounts live only in memory, set the root password again).
Separately, **3 consecutive wrong passwords for one account lock it for 60
seconds**. Wrong passwords given to `su` and to `passwd` (the current-password
check) count toward the same lockout. A successful authentication resets the count.

Once logged in you land in the **ring-3 shell**, the default login shell. Its
prompt shows the working directory:

```
TinyOS shell (ring 3) - 'help' for builtins, 'kshell' for the kernel shell, 'exit' to log out
D:/ $
```

---

## 4. The shell

TinyOS has two shells:

- the **ring-3 shell** (`/shell.elf`), the login shell. It is an ordinary user
  process and reaches the kernel only through syscalls;
- the **kernel shell**, reached by typing `kshell`. It holds everything the ring-3
  shell does not have yet: networking, security tooling, `exec`, `edit`, `su`,
  `shutdown`/`reboot`. `logout` (or `exit`) there returns to the login prompt.

`kshell` keeps your identity: an unprivileged user is still unprivileged in the
kernel shell. Type `help` in either shell; in the kernel shell `help` lists
categories (`help file`, `help net`, `help security`, ... or `help all`).

### Ring-3 shell (default)

| Command | What it does |
|---------|--------------|
| `help`, `man <cmd>` | List builtins / show help for one |
| `ls [dir]`, `cd [dir]`, `pwd` | List, change, print working directory (`cd` alone: `D:/`) |
| `cat [file]...`, `stat <path>...` | Print files (no argument: copy stdin) / show size, mode, type |
| `write <f> <text>`, `touch`, `cp`, `mv`, `rm`, `mkdir`, `rmdir` | File operations |
| `chmod <mode> <file>` | Change permission bits (octal; RAM disk only) |
| `grep`, `find`, `echo`, `clear`, `history` | Search and text utilities |
| `ps [-l]`, `top`, `kill <pid>`, `jobs`, `getpid` | Processes (`ps` shows your own; root sees all) |
| `id`, `whoami`, `date` | Identity and time |
| `env`, `set`, `unset`, `export`, `alias`, `unalias` | Environment and aliases |
| `passwd [user]`, `useradd <user>`, `userdel <user>` | Accounts (`useradd`/`userdel`: root only) |
| `kshell` | Switch to the kernel shell |
| `exit`, `logout` | Log out |

There is **no `exec`** builtin. Any word containing `/` or ending in `.elf` is run
as a program; the shell waits for it unless the line ends in `&`. Anything else
unknown prints `<cmd>: not found (try 'help')`.

### Kernel shell (`kshell`)

Root-only commands are marked **(root)**; for anyone else they print
`<cmd>: permission denied (must be root)`.

| Command | What it does |
|---------|--------------|
| `ls`, `ls C:`, `ls D:`, `cd`, `pwd`, `cat`, `edit <file>` | List, navigate, view and edit files |
| `cp`, `mv`, `rm`, `mkdir`, `touch`, `write`, `chmod`, `find`, `grep`, `echo` | File operations and search |
| `mount`, `fatls` | Show drives (`C:`=FAT32, `D:`=RAMFS) / list the FAT32 drive |
| `exec <file> [&]` | Load and run a **signed** program (`&` = background) |
| `ps`, `jobs`, `top`, `kill <pid>` | Processes (`top` is live; `q` quits) |
| `whoami`, `id [user]`, `users`, `su [user]`, `passwd`, `useradd`, `userdel` | Accounts |
| `env`, `set`, `unset`, `export`, `alias`, `unalias`, `history`, `date`, `clear` | Session |
| `ifconfig`, `ping <host>`, `dig <name>`, `dhcp [renew]`, `curl <url>` | Networking |
| `secstatus` | Summary of the security subsystems |
| `aslr`, `pae`, `mem`, `wxaudit`, `auditlog`, `loglevel`, `sectest` | Security tooling **(root)** |
| `shutdown`, `reboot` | Power **(root)** |
| `logout`, `exit` | Return to the login prompt |

An unknown command prints `Unknown command: <cmd>`.

### Running a signed program

```
D:/ $ /hello.elf
Hello from ELF!
```

Every user binary is verified against a **pinned ECDSA P-256 key** before it runs,
whether started from the ring-3 shell or with `exec` in the kernel shell. The
bundled programs are signed with that key; unsigned or tampered binaries are
**rejected (fail-closed)** by default. (For local development that accepts
unsigned binaries, the kernel can be built with `-DELF_PERMISSIVE_SIGNATURES` —
see the README. The demo ISO is the enforced build.)

### Background jobs

End the line with `&` to run a program in the background: the shell prints
`[pid] name` and returns to the prompt immediately.

```
D:/ $ /sleeper.elf &
[25160] /sleeper.elf
Sleeper started
D:/ $ jobs
[1]  25160  /sleeper.elf
```

`jobs` lists only this shell's background children that are still running
(`no background jobs` otherwise); `ps` shows every process you can see. A
background job you never wait for is still reaped when it exits. PIDs are not
sequential.

### Pipelines

In the ring-3 shell a pipeline joins **two programs** with one `|`. Both stages
run at the same time over a kernel pipe, so output larger than the pipe buffer
streams through:

```
D:/ $ /producer.elf 800 | /counter.elf
counter: lines=801 bytes=11107
```

A builtin cannot be a stage (it runs inside the shell itself); the shell says so
and points to `kshell`. The kernel shell's pipelines accept builtins and up to 4
stages, but run the stages one after another through a 4 KB buffer: a stage that
produces more is truncated, and the shell reports
`shell: stage N output truncated at 4096 bytes (M dropped)`. In the kernel shell
only `cat` reads its stdin, so the useful form is `cmd | cat` (e.g. `ls | cat -n`).

### Redirection

In the ring-3 shell `>` (truncate), `>>` (append) and `<` work on builtins and
programs alike:

```
D:/ $ echo hello > /scratch/note.txt
D:/ $ echo again >> /scratch/note.txt
D:/ $ cat < /scratch/note.txt
hello
again
```

Paths may be absolute or relative, and `..` is resolved before the file is
opened. In the ring-3 shell the target must be on `D:` (the RAM disk); writing to
anything under `/bin/`, `/sbin/`, `/etc/`, `/boot/` or `/kernel` is refused
(`>: /etc/motd: permission denied`) — those paths need a capability that no
ring-3 process holds, root included. `passwd`, `useradd` and `userdel` cannot be
redirected: they prompt on the console. The kernel shell parses the same three
operators; see [`SHELL_FEATURES.md`](SHELL_FEATURES.md).

### Files and permissions

The RAM disk (`D:`) enforces owner/group/other permission bits. Its root `/` is
mode `0711`: anyone can use it as a working directory, but only root can list it
or create entries in it. `/scratch` is `0777` for everyone's use. New files are
created `0600` and new directories `0700`. A name you neither own nor hold any
permission on, in a directory you cannot list, reads as nonexistent.

---

## 5. Networking — what to expect

With the recommended QEMU command above, DHCP completes at boot and you can reach
the internet. The networking commands live in the kernel shell, so type `kshell`
first:

```
D:/ $ kshell
Switching to the kernel shell; `logout` there returns to login.
$ dhcp
  State:        BOUND
  Offered IP:   10.0.2.15
  Gateway:      10.0.2.2
  DNS Server:   10.0.2.3
$ curl http://google.com
... HTTP/1.0 301 Moved Permanently ...
$ curl 172.66.147.243
... HTTP/1.1 403 Forbidden ...
```

`curl` accepts a literal IPv4 address as well as a name. That path skips DNS
entirely, which makes it the way to test TCP when name resolution is unavailable
or deliberately diverted. Previously a dotted-quad was sent to the resolver as if
it were a hostname and failed with `DNS resolution failed`.

The address is in QEMU's internal **user-mode (NAT) subnet `10.0.2.x`** — this is
normal and gives full *outbound* networking (DNS, TCP, HTTP). The guest is behind
QEMU's NAT, so it is not directly reachable from other machines on your LAN.

> **Getting an address on your real home-router subnet (e.g. `192.168.0.x`)**
> requires *bridged* networking (`vmnet-bridged` on macOS), which only works over a
> **wired Ethernet** interface. macOS/`vmnet` **cannot bridge a Wi-Fi interface** —
> on a Wi-Fi-only Mac, QEMU fails with `cannot create vmnet interface` even with
> `sudo`. Use a wired/USB-Ethernet adapter if you need a real-LAN lease; otherwise
> the NAT setup above is all you need to use and study the OS.

If you boot **without** a NIC, the kernel still tries DHCP and pauses ~30 seconds on
`[NET] DHCP: Waiting for IP address...` before timing out and continuing to the
shell. That wait is expected, not a hang.

---

## 6. Shutting down

As root, type `kshell` and then `shutdown` or `reboot` (both are root-only and
kernel-shell only). Otherwise just close the QEMU window / press **Ctrl-C** in the
terminal running QEMU (or **Ctrl-A** then **X** if you launched with
`-nographic`/`-serial mon:stdio`).

---

See also: [`SHELL_FEATURES.md`](SHELL_FEATURES.md) and
[`STDIN_FEATURES.md`](STDIN_FEATURES.md) for kernel-shell internals,
[`USER_SYSTEM_TEST_GUIDE.md`](USER_SYSTEM_TEST_GUIDE.md) for a walkthrough of the account system,
[`EDR_QUICK_REFERENCE.md`](EDR_QUICK_REFERENCE.md) for the security-monitoring layer, and
[`FIREWALL_AND_IDS_CONFIG.md`](FIREWALL_AND_IDS_CONFIG.md) for configuring the firewall and IDS.
