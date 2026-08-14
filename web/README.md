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

The committed ISO carries the same content as the signed `v2.3` release asset
(SHA-256 `632a5825b6329a6bebc5256b113531ee7dbafab902800499f9beda6c22336077` as of
2026-08-14 — adds background jobs, fd-aware I/O, `SYS_SPAWN` + argv, and shell
pipelines from PRs #30–#33, on top of the v2.2 framebuffer console, userspace
libc + FAT32 exec, and blocking syscalls). Note `i686-elf-grub-mkrescue` is
non-deterministic, so a fresh rebuild will hash differently even with
identical inputs.

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
- **No networking** — v86 emulates NE2000 / virtio-net, not the e1000 TinyOS
  drives. Boot proceeds offline (DHCP → APIPA fallback).
- **NX unavailable** in v86 → W^X enforcement degrades to PARTIAL (by design;
  PAE paging itself works and is active).

## Deploying elsewhere

Any static host works (GitHub Pages, Netlify, etc.). No server code. Copy the
whole `web/` folder — it is self-contained. v86 does **not** require cross-origin
isolation (COOP/COEP) for this single-threaded configuration.
