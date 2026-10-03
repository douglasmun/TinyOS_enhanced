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
password; after login try `help`, `ls D:`, and `/hello.elf` (verifies an
ECDSA signature, then prints *Hello from ELF!* from ring 3).

Crypto (PBKDF2 100k, bit-serial ECDSA) is slow under the emulator's JIT, so
password setup and the first program launch take a little while — this is a speed cost,
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

The committed ISO is built from `main` at **PR #141** (`0297df4`), and
matches the signed `v2.8` release asset. It is a pinned image, not a rolling
build of `main`: it only moves when someone runs the steps above, so expect it
to fall behind again as work lands.

**Login drops straight into the ring-3 shell** (PR #51), which is what the demo
shows. Run a signed program by its path (`/hello.elf`); type `kshell` to hand
over to the kernel shell for the privileged and introspection commands (`pae`,
`mem`, `wxaudit`, `auditlog`, networking), and `exit` to log out. The nine
privileged commands are gated on **euid 0**, so a non-root user reaching the
kernel shell still cannot run them.

### What is new since v2.7

The headline is **PR #141: every input surface fuzzed, 35 defects fixed** — see
[`../doc/FUZZ_REPORT_2026-10.md`](../doc/FUZZ_REPORT_2026-10.md). The ones you
can reach from this demo, as an unprivileged user:

- **A pipe use-after-free**: a spawned child kept writing through frames its
  pipe's owner had already freed.
- **A kernel panic from spawn**: a child's guard page was marked not-present in
  the *caller's* page table, so once the frame was reused a ring-0 page fault
  took the kernel down.
- **Writes landing in another user's file**, two ways: every `exec` closed
  *every* process's close-on-exec fds, and an inherited redirected stdout was a
  bare fd number its creator could close.
- **RAMFS never checked the directory search bit**, so a root-only `0700`
  directory hid nothing.
- **One user could exhaust the RAMFS fd table**, blocking every `exec` including
  root's. Now a per-user cap with a root reserve, released on normal exit.
- **The editor's negative cursor read and wrote kernel memory**, alongside five
  data-loss bugs in `edit`.
- **Every spawn printed ~24 lines**, including the child's ASLR stack address and
  page-table physical addresses. Now one verdict line; load counts are in
  `secstatus`.

Also since v2.7: the DNS/DHCP/ICMP/ARP network audit (7 findings, PRs
#135–#139), FAT32 hardening against hostile volumes, per-user TCP socket caps,
and a double-fault task gate so a kernel stack overflow reports instead of
triple-faulting. The demo has **no NIC and no disk attached**, so the network
and FAT32 fixes matter for the QEMU configuration in the top-level README.

SHA-256 `fd91ef42536947ed4170a250c7a7453e2eeb71f5cf0bfa9c5bb57180982a226b` as of
2026-10-03. Note `i686-elf-grub-mkrescue` is non-deterministic, so a fresh
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
