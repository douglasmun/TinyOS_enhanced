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

The committed ISO is built from `main` at **PR #69** (`ec51d3a`), and matches the
signed `v2.6` release asset. It is a pinned image, not a rolling build of `main`:
it only moves when someone runs the steps above, so expect it to fall behind
again as work lands.

**Login now drops straight into the ring-3 shell** (PR #51), which is what the
demo shows. That shell has ~25 builtins against the kernel shell's ~70 — type
`kshell` to hand over to the kernel shell for the privileged and introspection
commands (`pae`, `mem`, `wxaudit`, `auditlog`, networking), and `exit` to log
out. Note that the nine privileged commands are gated on **euid 0**, so a
non-root user reaching the kernel shell still cannot run them.

Since the previous image (v2.5, PR #67) this adds a **privilege-escalation fix**
(#69): `ramfs_chmod` had no ownership check, so any user could `chmod 666` a
root-owned 0600 file and read it. That is reachable from the demo, because
`kshell` is open to every user by design — so the v2.5 image is exploitable this
way and this one is not. Before it, v2.5 added `cp`/`mv`/`touch` with the
`open(O_TRUNC)` fix underneath them (#67); v2.4 and earlier brought `ps`/`kill`/
`top` from ring 3 via `SYS_PSINFO`/`SYS_KILL` (#62) with the own-only visibility
policy (#61), a per-uid task-slot cap (#60), `require_root` on the machine-state
commands (#58), IDS payload-signature matching and credential-spray detection
(#63, #65), and the `kprintf`→`stream_printf` conversion that makes redirection
work for the system and security-test reports (#64, #66). It keeps FAT32
subdirectories, ring-3 redirection and pipelines, the ring-3 credential
commands, and the credential-syscall hardening from PRs #42–#55.

SHA-256 `0dfdbedaefc925c5f76a7a106abe53ee32fb05893d34140ec91903ecad62e061` as of
2026-08-16. Note `i686-elf-grub-mkrescue` is non-deterministic, so a fresh
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
- **No networking** — v86 emulates NE2000 / virtio-net, not the e1000 TinyOS
  drives. Boot proceeds offline (DHCP → APIPA fallback).
- **NX unavailable** in v86 → W^X enforcement degrades to PARTIAL (by design;
  PAE paging itself works and is active).

## Deploying elsewhere

Any static host works (GitHub Pages, Netlify, etc.). No server code. Copy the
whole `web/` folder — it is self-contained. v86 does **not** require cross-origin
isolation (COOP/COEP) for this single-threaded configuration.
