# TinyOS in the browser (v86)

A self-contained web page that boots the TinyOS ISO inside the
[v86](https://github.com/copy/v86) x86-to-WebAssembly emulator — no server, no
build step, nothing leaves the visitor's machine. See
[`../doc/WASM_BROWSER_FEASIBILITY.md`](../doc/WASM_BROWSER_FEASIBILITY.md) for
the feasibility study and empirical results this demo is based on.

**Live demo:** <https://douglasmun.github.io/TinyOS_enhanced/>. This folder is the
source of truth; GitHub Pages serves from a separate **`gh-pages`** branch (repo
*Settings → Pages* only allows `/` or `/docs`, not `/web`). To ship a change here,
copy the updated files to the root of `gh-pages` and push — see "Refreshing the
deployed site" below.

## Run locally

The assets must be served over HTTP (WASM won't load from `file://`). Everything
the page needs — including `tinyos.iso` — lives in this folder, so serve `web/`
directly:

```sh
# from the repo root
python3 -m http.server 8000
# open http://localhost:8000/web/
```

Press **Start**, then click the console and type. First boot sets a root
password; after login try `help`, `ls D:`, and `exec /hello.elf` (verifies an
ECDSA signature, then prints *Hello from ELF!* from ring 3).

Crypto (PBKDF2 100k, bit-serial ECDSA) is slow under the emulator's JIT, so
password setup and the first `exec` take a little while — this is a speed cost,
not a fault.

## Contents

| File | Source | In git? |
|---|---|---|
| `index.html`, `README.md` | the demo page (this repo) | yes |
| `tinyos.iso` | the OS image, loaded at runtime by v86 | yes — force-added past the `*.iso` ignore so Pages can serve it |
| `.nojekyll` | disables GitHub Pages' Jekyll processing | yes |
| `vendor/libv86.js` | v86 emulator (BSD-2-Clause, © the v86 contributors) | yes |
| `vendor/v86.wasm` | v86 WebAssembly core | yes |
| `vendor/seabios.bin`, `vendor/vgabios.bin` | SeaBIOS / VGABIOS ROMs shipped with v86 (LGPLv3) | yes (force-added past `*.bin` ignore) |

## Refreshing the ISO

`web/tinyos.iso` is a committed copy of the built image. After a kernel change,
rebuild and re-copy it (then commit):

```sh
make -j8 kernel.elf
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o dist/tinyos.iso iso     # needs xorriso
cp dist/tinyos.iso web/tinyos.iso
git add -f web/tinyos.iso
```

The committed ISO is built from `main` at **PR #109** (`eaef86d`), and
matches the signed `v2.7` release asset. It is a pinned image, not a rolling
build of `main`: it only moves when someone runs the steps above, so expect it
to fall behind again as work lands.

The previous image had gone badly stale — **v2.6 was 103 commits behind `main`**
by the time this one was cut, so the demo was missing every fix listed below.

**Login drops straight into the ring-3 shell** (PR #51), which is what the demo
shows. That shell now has **40 builtins** against the kernel shell's ~70 (v2.6
had ~25) — type `kshell` to hand over to the kernel shell for the privileged and
introspection commands (`pae`, `mem`, `wxaudit`, `auditlog`, networking), and
`exit` to log out. Note that the nine privileged commands are gated on **euid
0**, so a non-root user reaching the kernel shell still cannot run them.

### What is new since v2.6

The headline is that **the security audit behind this image found 16 issues and
all 16 are fixed here** (PRs #103–#105) — one Critical, two High. Two of them are
reachable from this demo:

- **Critical — `ramfs_open` created files with no permission check on the parent
  directory.** Creating a file is a write to its parent, but the create path
  never asked; every *other* ramfs mutation did. An unprivileged user could
  plant a file in a root-owned `0755` directory. Fixed in the primitive, so the
  next caller inherits the check.
- **High — the firewall had no reachable default-deny.** It now denies by
  default, with an IDS that matches payload signatures and blocks the source.

Also landed since v2.6:

- **A memory leak on every process exit.** Teardown freed only what a `task_t`
  field named, and nothing walked the PTEs — so each `exec` leaked its whole ELF
  image (measured: 8 frames for `/hello.elf`). Since `SYS_SPAWN` is ungated and
  the frames leak on *exit*, a spawn-and-wait loop drained memory without ever
  holding two tasks at once, so the per-uid cap never fired.
- **The EDR daemon never actually ran.** It was created but never enqueued —
  `task_create_kernel()` allocates without scheduling, so it appeared in `ps`
  and in every status surface while executing zero instructions.
- **An editor data-loss bug**: `editor_insert_row` shifted rows before
  allocating, so one OOM insert destroyed a line *and* lost two frames.
- **Remote-driven console floods closed across the RX path** (`tcp.c`, `dns.c`,
  `icmp.c`): any host on the segment could print to the kernel console, twice
  from *before* the connection lookup. These are counters now, surfaced in
  `ifconfig`.
- **A supervised network daemon** (`knetd`) with restart rate-limiting, and RX
  parsing moved into task context rather than the ISR.
- **New ring-3 builtins**: `date`, `chmod`, `whoami`, `clear`, `history`,
  `jobs`, `grep`, `find`, `man`, and the `env`/`alias` group via `SYS_ENV`.

Note the demo has **no NIC attached**, so the networking fixes are not
exercisable here — they matter for the QEMU configuration in the top-level
README.

SHA-256 `372f921c129a0afccbc3db206f924ba0bc27351938e18dde0ee0031f28bd8446` as of
2026-08-22. Note `i686-elf-grub-mkrescue` is non-deterministic, so a fresh
rebuild will hash differently even with identical inputs — this hash identifies
the committed artifact, it is not reproducible from source.

## Refreshing the deployed site

Pages serves the **`gh-pages`** branch (root), not `web/`. After changing a file
here (e.g. `index.html`) and merging it to `main`, mirror it onto `gh-pages`:

```sh
git worktree add /tmp/ghp origin/gh-pages
cp web/index.html /tmp/ghp/index.html          # or the ISO, vendor files, etc.
git -C /tmp/ghp commit -am "gh-pages: sync index.html"
git -C /tmp/ghp push origin HEAD:gh-pages
git worktree remove /tmp/ghp
```

The branch holds only what the site serves: `index.html`, `tinyos.iso`,
`vendor/`, and `.nojekyll` (no `README.md`).

## Known demo limitations

- **No hard disk attached** → drive **C:** (FAT32) is unavailable
  (`[IDE] not initialized` is expected). **D:** (in-memory RAMFS) works.
  To enable C:, attach a FAT32 image as an IDE `hda` in `index.html`.
- **No networking** — `index.html` constructs `V86` with no `net_device`, so
  **no NIC is attached at all** and the PCI scan finds nothing. Expect exactly
  one line:

  ```
  [PCI] No NIC present; networking disabled  [OK]
  ```

  This is a supported configuration, not an error: boot proceeds offline
  (DHCP → APIPA fallback). Adding `net_device` would attach an NE2000 or
  virtio-net, neither of which TinyOS drives — it drives the Intel e1000
  (`8086:100e`) only — so the message would then name the device instead:

  ```
  [PCI] No supported NIC (want 8086:100e); found 1 other NIC(s),
        first 10ec:8029 -- networking disabled  [OK]
  ```
- **NX unavailable** in v86 → W^X enforcement degrades to PARTIAL (by design;
  PAE paging itself works and is active).

## Deploying elsewhere

Any static host works (GitHub Pages, Netlify, etc.). No server code. Copy the
whole `web/` folder — it is self-contained. v86 does **not** require cross-origin
isolation (COOP/COEP) for this single-threaded configuration.
