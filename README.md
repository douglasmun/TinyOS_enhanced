# TinyOS Enhanced

A from-scratch, security-focused **32-bit (i386) operating system kernel**, written in C and x86 assembly. Boots via Multiboot2/GRUB, runs in QEMU, and demonstrates a full vertical slice of OS concepts — protected mode, PAE paging with NX/W^X, preemptive multitasking, ring-3 user processes, a TCP/IP stack on a real NIC driver, from-scratch cryptography, and **ECDSA-signed-ELF secure boot enforced by default**.

> Successor to [douglasmun/TinyOS](https://github.com/douglasmun/TinyOS) — substantially expanded in scope, security, and reliability.

---

## ⚠️ Status: educational / research kernel — NOT production

TinyOS Enhanced is a single-developer **hobby and learning OS**. It is single-core, 32-bit, console-only, and intended to run under QEMU. It is **not** hardened for, or intended for, production or internet-facing use.

- ✅ **Safe for:** OS/kernel learning, security-mechanism study, lab/VM experimentation, coursework.
- ❌ **Not for:** production deployment, untrusted networks, storing sensitive data.

The cryptography is implemented from scratch for educational purposes and has not had external cryptographic review.

---

## What it does (verified working)

- **Boot → shell → login** — Multiboot2 boot, first-boot root password setup, PBKDF2-HMAC-SHA256 (100k iterations) password hashing.
- **Ring-3 user processes** — from-scratch ELF32 loader, `int 0x80` syscall interface; `exec /hello.elf` loads a signed binary, runs it in user mode, services its syscalls, and reaps it on exit.
- **Signed-ELF secure boot** — every user binary is verified against a pinned **ECDSA P-256** key; unsigned/tampered binaries are **rejected (fail-closed) by default**.
- **Memory protection** — PAE paging, **NX / W^X** enforcement, **ASLR**, kernel-stack guard pages.
- **Networking** — TCP/IP stack with **DHCP, DNS, ICMP** over a real **Intel e1000** NIC driver, plus a firewall and intrusion-detection (IDS) layer.
- **Filesystems** — a VFS layer with **FAT32** (`C:`) and **RAMFS** (`D:`) drives; `ls`, file read/write, directories.
- **Security monitoring** — a behavioral **EDR** subsystem (memory/network/crypto/FIM signals).
- **From-scratch crypto** — AES, SHA-256/512, HMAC, PBKDF2, ECDSA P-256, ECDHE, HKDF, ChaCha20 CSPRNG seeded from hardware RNG (RDRAND/RDSEED) + multi-source entropy.

~50K lines of kernel C across ~80 translation units, plus x86 assembly. Builds clean under `-Werror` with an aggressive warning set.

---

## Try it in 30 seconds (prebuilt demo ISO)

A prebuilt, bootable **demo ISO** is published on the [**Releases**](../../releases) page so you can try TinyOS Enhanced without setting up a cross-toolchain. Just QEMU.

**Recommended — with a virtual NIC (DHCP completes immediately):**

```sh
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom tinyos.iso -m 256M \
  -netdev user,id=net0 -device e1000,netdev=net0
```

The kernel runs DHCP at boot. With the e1000 NIC attached (above), it gets a lease right away via QEMU's user-mode network (an address in the `10.0.2.x` NAT range) and drops to the shell promptly — this gives full outbound networking (try `curl http://example.com`). Getting an address on your real home-router subnet (`192.168.0.x`) needs *bridged* networking, which on macOS only works over wired Ethernet, not Wi-Fi — see the [User Guide](doc/USER_GUIDE.md#5-networking--what-to-expect).

**Minimal — no network:**

```sh
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom tinyos.iso -m 256M
```

> Without a NIC, the boot pauses for ~30 seconds on `[NET] DHCP: Waiting for IP address...` before timing out and continuing to the shell — that wait is expected, not a hang. Use the recommended command to skip it.

On first boot it asks you to set a root password, then drops to a shell. Try `ls`, `ls C:`, `ls D:`, and `exec /hello.elf`. For a walkthrough of boot, login, the shell commands, and networking, see the **[User Guide](doc/USER_GUIDE.md)**.

> **About the demo ISO — please read:**
> - It is an **educational demo image**, not a production system (see the status note above). Run it in a VM/QEMU only.
> - It contains the kernel plus signed sample user binaries (`hello.elf`, `shell`) and the **public** ECDSA verification key — **no private keys**. ELF signature enforcement is on by default.
> - It is provided for convenience; for anything beyond trying it out, build from source below so you can read exactly what you're running.

## Build & run

**Toolchain:** an `i686-elf` cross-compiler (`i686-elf-gcc`), `nasm`, `xorriso`, and `qemu-system-i386`.

```sh
# Build the kernel (warning-clean under -Werror)
make -j8 kernel.elf

# Build a bootable ISO
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o dist/tinyos.iso iso     # needs xorriso

# Run headless (serial -> log file)
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed \
  -cdrom dist/tinyos.iso -boot d -m 256M \
  -netdev user,id=net0 -device e1000,netdev=net0 \
  -serial file:serial.log -display none

# Or use the smoke-test harness (GUI, captures serial + verdict)
./verify-exec.sh
```

On first boot you set a root password, then log in. Try `ls`, `ls C:`, `ls D:`, and `exec /hello.elf`.

> **Signature enforcement:** the build enforces ELF signatures by default (fail-closed). The bundled `hello`/`shell` binaries are signed with the pinned key, so a normal build boots and runs them. For fast local dev that accepts running unsigned binaries, build with `-DELF_PERMISSIVE_SIGNATURES` (warn-and-load) — an explicitly named opt-out, never the default.

---

## Project layout

```
src/        kernel C + assembly (memory, scheduler, syscalls, net, fs, crypto, EDR, shell)
userspace/  signed user programs (hello.elf, shell)
tools/      build helpers (ELF signing, embedded-array generation)
doc/        design notes, security audits, and the OS comparison/grade
iso/        GRUB boot config
```

Deeper documentation lives in [`doc/`](doc/) — start with [`doc/USER_GUIDE.md`](doc/USER_GUIDE.md) (boot, login, shell, networking) and [`doc/FIREWALL_AND_IDS_CONFIG.md`](doc/FIREWALL_AND_IDS_CONFIG.md) (configuring the firewall and IDS), then `doc/OS_COMPARISON_AND_GRADE.md` (where this kernel sits vs. xv6 / ToaruOS / SerenityOS and real-world tiny OSes) and `doc/MULTI_AGENT_SECURITY_AUDIT_2026.md` (the security audit history).

---

## Notable engineering

- **Fail-closed signed-ELF secure boot** with key pinning — uncommon even among larger hobby OSes.
- Survived an aggressive whole-kernel security review (memory safety, integer/locking/privilege-boundary, page-table correctness) with the findings fixed and adversarially re-audited.
- Clean `-Werror` build with header-dependency tracking; a reproducible runtime smoke-test harness (`verify-exec.sh`).

## Known limitations

- Single-core, 32-bit, console-only; targets QEMU (256 MB).
- No long-soak / multi-day stability testing yet.
- A formerly-present SSH server was **removed from the build** (it never completed a reliable handshake); its sources are retained on disk but are not compiled or linked.

---

## License

MIT License — see [`LICENSE`](LICENSE). An educational/hobby project; provided
as-is with no warranty (see the status note above).
