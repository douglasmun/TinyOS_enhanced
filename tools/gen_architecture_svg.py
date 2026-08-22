#!/usr/bin/env python3
"""Generate doc/img/architecture{,-dark}.svg from one description.

Both variants come from this file so they cannot drift apart again -- the two
committed SVGs had diverged to different viewBoxes and different markup, which
is how the light one kept saying "81 kernel modules" and "C: FAT32 (read)"
after FAT32 write and the ring-3 shell landed.

Facts asserted here are checked against the tree by verify/verify-arch-svg.sh.
"""

LIGHT = dict(
    bg="#ffffff", fg="#1f2328", muted="#57606a", rule="#d0d7de",
    blue="#0969da", green="#1a7f37", amber="#9a6700", red="#cf222e",
    panel="#f6f8fa",
)
DARK = dict(
    bg="#0d1117", fg="#e6edf3", muted="#8b949e", rule="#30363d",
    blue="#4c8eda", green="#3fb950", amber="#bb8009", red="#e5534b",
    panel="#161b22",
)

SANS = "-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif"
MONO = "ui-monospace,SFMono-Regular,Menlo,monospace"

W, H = 1000, 700

ALT = ("TinyOS Enhanced architecture. Ring-3 user processes -- including the "
       "default login shell -- reach the kernel only through the int 0x80 "
       "privilege boundary, where copy_user validates every buffer and ECDSA "
       "P-256 verification gates every ELF load fail-closed; unsigned binaries "
       "are rejected there. Below it the ring-0 kernel provides process "
       "scheduling and supervised kernel daemons, PAE memory protection, a VFS "
       "over FAT32 and RAMFS (both read/write), and a TCP/IP stack whose receive "
       "path parses in task context behind a default-deny firewall and IDS, all "
       "driving i386 hardware.")


def esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def build(c):
    o = []
    a = o.append
    a(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
      f'width="{W}" height="{H}" role="img" aria-label="{esc(ALT)}">')
    a('  <title>TinyOS Enhanced — architecture</title>')
    a('  <defs>')
    for name, col in (("a", c["muted"]), ("ag", c["green"]), ("ad", c["red"]),
                      ("ab", c["blue"])):
        a(f'    <marker id="{name}" viewBox="0 0 10 10" refX="9" refY="5" '
          f'markerWidth="7" markerHeight="7" orient="auto-start-reverse">')
        a(f'      <path d="M0 0 L10 5 L0 10 z" fill="{col}"/>')
        a('    </marker>')
    a('  </defs>')
    a(f'  <rect width="{W}" height="{H}" fill="{c["bg"]}"/>')

    def text(x, y, s, size=11, fill=None, font=SANS, weight=None, anchor=None):
        at = f' text-anchor="{anchor}"' if anchor else ""
        wt = f' font-weight="{weight}"' if weight else ""
        a(f'  <text x="{x}" y="{y}"{at} font-family="{font}" font-size="{size}"'
          f'{wt} fill="{fill or c["fg"]}">{esc(s)}</text>')

    def box(x, y, w, h, stroke, dash=False, fill="none", rx=6, sw=1.5):
        d = ' stroke-dasharray="4 3"' if dash else ""
        a(f'  <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" '
          f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}/>')

    # ---- header ----
    text(24, 30, "TinyOS Enhanced — architecture", 19, c["fg"], weight="700")
    text(24, 50, "32-bit i386 · Multiboot2 · 92 kernel modules · preemptive, single core",
         12, c["muted"])

    # ---- RING 3 ----
    box(24, 68, 952, 104, c["rule"], dash=True, rx=8, sw=1)
    text(38, 88, "RING 3 · USER MODE", 11.5, c["blue"], weight="700")
    text(190, 88, "linked at 0x08000000 · private PAE address space per process",
         10.5, c["muted"], font=MONO)

    u = [
        (38, "shell.elf", "DEFAULT LOGIN SHELL", "~35 builtins · signed", c["green"]),
        (250, "hello.elf / spawner.elf", "signed", "SYS_SPAWN + argv", c["blue"]),
        (462, "netprobe / msealprobe", "harness drivers", "signed", c["blue"]),
        (674, "tiny libc", "userspace/libc.c", "crt0 · printf · malloc", c["muted"]),
    ]
    for x, t1, t2, t3, col in u:
        dash = col == c["muted"]
        box(x, 98, 200, 60, col, dash=dash, sw=1.2 if dash else 1.5)
        text(x + 100, 118, t1, 12, col, font=MONO, anchor="middle")
        text(x + 100, 133, t2, 9.5, col if col == c["green"] else c["muted"],
             anchor="middle", weight="700" if col == c["green"] else None)
        text(x + 100, 148, t3, 9.5, c["muted"], font=MONO, anchor="middle")

    box(886, 98, 90, 60, c["red"], dash=True, sw=1.2)
    text(931, 121, "unsigned", 10.5, c["red"], font=MONO, anchor="middle")
    text(931, 136, "rejected", 10.5, c["red"], font=MONO, anchor="middle")

    # ---- boundary ----
    y = 186
    box(24, y, 952, 74, c["amber"], rx=8, sw=1.6, fill=c["panel"])
    text(38, y + 20, "PRIVILEGE BOUNDARY", 11.5, c["amber"], weight="700")
    text(196, y + 20, "the only way in — int 0x80 · 42 syscalls (SYS_EXIT 0 … SYS_ENV 41)",
         10.5, c["muted"], font=MONO)
    text(38, y + 41, "copy_user — every buffer bounds-checked and fault-safe",
         10.5, c["fg"], font=MONO)
    text(38, y + 59, "ECDSA P-256 verify — fail-closed, ENFORCE by default",
         10.5, c["green"], font=MONO)
    text(560, y + 41, "per-syscall gating: ungated · ownership · euid",
         10.5, c["fg"], font=MONO)
    text(560, y + 59, "dispatcher counts rejections, never prints them",
         10.5, c["muted"], font=MONO)

    a(f'  <line x1="500" y1="172" x2="500" y2="184" stroke="{c["blue"]}" '
      f'stroke-width="1.5" marker-end="url(#ab)"/>')
    a(f'  <line x1="500" y1="262" x2="500" y2="274" stroke="{c["blue"]}" '
      f'stroke-width="1.5" marker-end="url(#ab)"/>')

    # ---- RING 0 ----
    y0 = 276
    box(24, y0, 952, 300, c["rule"], rx=8, sw=1)
    text(38, y0 + 20, "RING 0 · KERNEL", 11.5, c["green"], weight="700")
    text(160, y0 + 20, "no libc — freestanding C + NASM", 10.5, c["muted"], font=MONO)

    cards = [
        (38, y0 + 32, 224, 96, "Process & scheduling", [
            "round-robin, preemptive (PIT)",
            "kernel threads + ring-3 tasks",
            "wait queues · blocking waitpid",
            "pid + generation tuples",
            "per-uid task cap + root reserve",
        ]),
        (274, y0 + 32, 224, 96, "Memory", [
            "PAE paging · NX / W^X",
            "PMM · double-free detection",
            "ASLR · guard pages (kernel+user)",
            "per-process PDPT (COW tables)",
            "ELF image frames tracked on exit",
        ]),
        (510, y0 + 32, 224, 96, "Storage — VFS", [
            "permission checks in the primitive",
            "C:  FAT32   (read / write)",
            "D:  RAMFS   (read / write)",
            "unlink refuses a busy node",
            "drivers stay stdio-agnostic",
        ]),
        (746, y0 + 32, 230, 96, "Security & crypto", [
            "AES · SHA-2 · HMAC · PBKDF2",
            "ECDSA · ECDHE · HKDF",
            "EDR daemon (supervised)",
            "tamper-evident audit log",
            "credential store",
        ]),
    ]
    for x, yy, w, h, title, lines in cards:
        box(x, yy, w, h, c["rule"], sw=1.2, fill=c["panel"])
        text(x + 12, yy + 19, title, 11.5, c["fg"], weight="700")
        for i, ln in enumerate(lines):
            text(x + 12, yy + 36 + i * 13, ln, 9.5, c["muted"], font=MONO)

    # networking band
    yn = y0 + 140
    box(38, yn, 460, 84, c["blue"], sw=1.4, fill=c["panel"])
    text(50, yn + 19, "Network — RX parses in TASK context", 11.5, c["blue"], weight="700")
    for i, ln in enumerate([
        "ISR copies frame → rx_softirq_ring → knetd drains (IF=1, CPL 0)",
        "firewall: default DENY ALL · IDS signature match → block",
        "TCP · IP · ICMP · ARP · DHCP · DNS",
        "counters, not kprintf: no per-packet print on the RX path",
    ]):
        text(50, yn + 36 + i * 13, ln, 9.5, c["muted"], font=MONO)

    box(510, yn, 466, 84, c["green"], sw=1.4, fill=c["panel"])
    text(522, yn + 19, "Kernel daemons — supervised", 11.5, c["green"], weight="700")
    for i, ln in enumerate([
        "knetd     RX bottom half     (restart-limited, give-up)",
        "ktimerd   timer bottom half",
        "supervisor  CAP_UNKILLABLE · validates pid+generation",
        "edr_daemon  behavioural scan · enqueued at boot",
    ]):
        text(522, yn + 36 + i * 13, ln, 9.5, c["muted"], font=MONO)

    # kernel shell strip
    ys = y0 + 236
    box(38, ys, 938, 50, c["rule"], sw=1.2, dash=True)
    text(50, ys + 20, "Kernel shell (fallback) · stream layer", 11.5, c["fg"], weight="700")
    text(50, ys + 38,
         "reached with `kshell` · ~70 builtins · machine-state + networking tools stay here "
         "(pae, mem, wxaudit, auditlog) — together an ASLR defeat, so euid-0 gated",
         9.5, c["muted"], font=MONO)

    # ---- hardware ----
    yh = 592
    a(f'  <line x1="500" y1="578" x2="500" y2="590" stroke="{c["muted"]}" '
      f'stroke-width="1.5" marker-end="url(#a)"/>')
    box(24, yh, 952, 84, c["rule"], rx=8, sw=1, fill=c["panel"])
    text(38, yh + 20, "HARDWARE · i386", 11.5, c["muted"], weight="700")
    hw = [
        (38, "PIC · PIT · IDT", "interrupts + timer"),
        (232, "IDE disk", "block I/O → FAT32"),
        (426, "Intel e1000 NIC", "DMA ring + IRQ 11, guard-paged"),
        (700, "VBE framebuffer", "fbcon · RDRAND / RDSEED"),
    ]
    for x, t1, t2 in hw:
        text(x, yh + 45, t1, 11, c["fg"], font=MONO)
        text(x, yh + 62, t2, 9.5, c["muted"], font=MONO)

    a('</svg>')
    return "\n".join(o) + "\n"


if __name__ == "__main__":
    open("doc/img/architecture.svg", "w").write(build(LIGHT))
    open("doc/img/architecture-dark.svg", "w").write(build(DARK))
    print("wrote doc/img/architecture.svg and architecture-dark.svg")
