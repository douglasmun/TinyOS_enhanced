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
  TinyOS v2.0 Login System
TinyOS login: root
Password: ********
Login successful. Welcome, root!
```

Wrong passwords are counted; after several failed attempts the account locks
temporarily. Once logged in you get the shell prompt:

```
$
```

---

## 4. The shell

Type `help` for the full command list. Commonly used commands:

| Command | What it does |
|---------|--------------|
| `help`, `man <cmd>` | List commands / show help for one |
| `ls`, `ls C:`, `ls D:` | List the current dir, the FAT32 `C:` drive, the RAMFS `D:` drive |
| `cd`, `pwd` | Change / print working directory |
| `cat`, `edit <file>` | View / edit a file |
| `cp`, `mv`, `rm`, `mkdir`, `touch` | File operations |
| `find`, `grep`, `echo` | Search and text utilities |
| `mount` | Show mounted drives (`C:`=FAT32, `D:`=RAMFS) |
| `fatls` | List files on the FAT32 `C:` drive |
| `exec /hello.elf` | Load and run a **signed** user program in ring 3 |
| `ps`, `kill <pid>` | List / terminate processes |
| `passwd [user]`, `su [user]`, `logout` | Account management |
| `whoami`, `id`, `env`, `set`, `export`, `alias`, `history` | Session/environment |
| `dhcp [renew]`, `ifconfig`, `ping`, `curl <url>`, `dig`/`net` | Networking |
| `aslr`, `pae`, `mem`, `auditlog`, `date`, `clear`, `reboot` | System / security info |

### Running a signed program

```
$ exec /hello.elf
Hello from ELF!
```

Every user binary is verified against a **pinned ECDSA P-256 key** before it runs.
The bundled `hello.elf`/`shell` are signed with that key, so they execute;
unsigned or tampered binaries are **rejected (fail-closed)** by default. (For local
development that accepts unsigned binaries, the kernel can be built with
`-DELF_PERMISSIVE_SIGNATURES` — see the README. The demo ISO is the enforced build.)

---

## 5. Networking — what to expect

With the recommended QEMU command above, DHCP completes at boot and you can reach
the internet from the shell:

```
$ dhcp
  State:        BOUND
  Offered IP:   10.0.2.15
  Gateway:      10.0.2.2
  DNS Server:   10.0.2.3
$ curl http://google.com
... HTTP/1.0 301 Moved Permanently ...
```

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

Use `reboot` from the shell, or just close the QEMU window / press **Ctrl-C** in the
terminal running QEMU (or **Ctrl-A** then **X** if you launched with
`-nographic`/`-serial mon:stdio`).

---

See also: [`SHELL_FEATURES.md`](SHELL_FEATURES.md) and
[`STDIN_FEATURES.md`](STDIN_FEATURES.md) for shell internals,
[`USER_SYSTEM_TEST_GUIDE.md`](USER_SYSTEM_TEST_GUIDE.md) for the account system,
[`EDR_QUICK_REFERENCE.md`](EDR_QUICK_REFERENCE.md) for the security-monitoring layer, and
[`FIREWALL_AND_IDS_CONFIG.md`](FIREWALL_AND_IDS_CONFIG.md) for configuring the firewall and IDS.
