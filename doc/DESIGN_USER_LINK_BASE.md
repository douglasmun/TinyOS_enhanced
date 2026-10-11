# Design note: the 128 MB user-code / kernel identity-map overlap

Status: **open, latent**. Nothing is fixed yet. This note records the decision
that `doc/SECURITY_AUDIT_2026-10.md` §3 left open.

## The problem in one paragraph

User programs link at `0x08000000` (`userspace/user.ld`). The kernel maps all
RAM 1:1 in PD[0] (`src/pae.c` ~517: `pae_map_page(phys, phys, ...)` for every
frame up to `pmm_total_frames()`), and every user PDPT starts as a by-value copy
of the kernel PDs (`pae_create_user_pdpt`, ~1116). When the loader maps image
page *n* at `0x08000000 + n*4K`, `pae_map_page_into` (~1320) clones the shared
page table and **overwrites the identity PTE** for physical frame
`128 MB + n*4K`. While that process's CR3 is loaded, the kernel's pointer to
that frame no longer reaches the frame; it reaches the process's image page.

## Why it matters

The kernel uses physical frame addresses as pointers. `pmm_alloc()` returns a
frame number and callers dereference it directly (`ramfs.c` `node->data`, pipe
buffers, kernel stacks, e1000 DMA rings). Syscalls run on the caller's CR3
(`syscall.c` never switches CR3; `context_switch.S` loads the task's). Suppose a
kernel object lives in frame F, with `128 MB <= F < 128 MB + image size`:

- **Split view.** The object has one copy under the kernel CR3 and another
  under each process whose image covers F. Writes made in one context are
  invisible in the other.
- **Leak.** A kernel write made during that process's syscall lands in the
  process's own image page. The process can read that page back (its text and
  rodata are user-readable), so it reads kernel data: file contents, a pipe
  buffer, another user's data.
- **Corruption primitive.** The process's data segment is user-writable. If F
  is shadowed by a data page, the process controls what the kernel reads back
  for that object during its own syscalls.

`pae_sync_identity_pte` (~1264) skips user PTEs, so later identity-map updates
cannot restore the kernel view either.

## Why it is latent today

- **RAM.** Harnesses boot with `-m 256M` (118 of them), and `PMM_MAX_BYTES` is
  256 MiB (`pmm.c:71`), so frames above 128 MB exist and are identity-mapped.
  With `-m 128M` there is no overlap.
- **Allocation order.** `pmm_alloc()` (~697) and `pmm_alloc_contiguous()` (~765)
  are both first-fit from the bottom. A kernel object reaches 128 MB only after
  about 32,000 frames (about 127 MB) are in use below it.
- **Caps.** The per-uid caps (task slots, pipes, VFS descriptors, TCP sockets)
  keep any unprivileged user far below that. Root can allocate more, but root
  is not the attacker here.
- **Image size.** The shadowed range is bounded by the image span:
  `ELF_MAX_PROCESS_MEMORY` is 16 MB, so the worst case is frames 128 to 144 MB.
- **Stack.** The user stack does not overlap. ASLR places it within 16 MB below
  `0xC0000000` (`aslr.c:158`, `ASLR_STACK_ENTROPY_PAGES` = 4096).

So the bug becomes live the day either of these happens:
- a cap is raised, or a new uncapped allocation path lands;
- RAM grows, together with a change that allocates from the top or reserves the
  low region.

## A related gap: the loader has no lower bound worth the name

The loader's only lower bound on a PT_LOAD vaddr is `USER_MIN_ADDR = 0x1000`
(`elf.c` ~822). Its upper bound is `ELF_USER_SPACE_END = 0xC0000000` (~749).
That allows a segment at `0x00100000`, over the kernel image's identity view
(the kernel links at 1M, `src/linker.ld:24`). Only the ELF signature stands in
the way. Today the 128 MB overlap is the benign instance of this. The general
rule should be: **no user mapping may fall inside the identity-mapped range**.

## Options

### A. Move the user link base above all identity-mappable RAM (recommended)

Change `user.ld` to `. = 0x20000000;` (512 MB) and give it a single name in
`memory.h`, `USER_IMAGE_BASE`.

- `PMM_MAX_BYTES` (256 MiB) caps the identity map, and `PAE_INITIAL_TABLES` =
  128 caps it at the same point (the pool covers `RAM_MB/2` tables). The kernel
  PD[0] therefore has no PDE at 512 MB. The loader gets a fresh page table
  there, no identity PTE is ever replaced, and the PT copy-on-write path is not
  involved.
- It stays in PD[0], away from the stack window (`0xBF000000` to `0xC0000000`)
  and the framebuffer (PD[3]).
- Enforce it rather than assume it:
  1. `_Static_assert(USER_IMAGE_BASE >= PMM_MAX_BYTES)` next to `PMM_MAX_BYTES`,
     so a future RAM bump fails the build instead of reopening the overlap.
  2. The loader refuses any PT_LOAD whose `[start, start+memsz)` intersects
     `[0, PMM_MAX_BYTES)`. This replaces the `USER_MIN_ADDR` check with the real
     invariant and closes the related gap above. The refusal is a single
     verdict line plus a counter (no per-segment `kprintf`; see
     `doc/RULES_THAT_BITE.md`).
- Cost: every user binary changes, so everything is re-signed (below). No kernel
  logic changes beyond the two checks. `pae_map_page_into`'s PT copy-on-write
  stays, because guard pages and other user mappings still rely on it.

### B. Real kernel direct map (higher-half or a separate window)

Stop using physical addresses as pointers. Map RAM at a fixed kernel window,
for example `0xD0000000 + phys`, and route every `pmm_alloc()` dereference
through `phys_to_virt()`. The comment at `pae.c` ~590 already calls this the
"proper fix".

- It is the right long-term shape, and it removes the identity map's NX
  re-marking and the 1:1 assumptions in DMA code.
- It touches every allocator caller: ramfs, pipes, stacks, e1000 rings, page
  tables, `copy_user`. The kernel image also has to move or be double-mapped.
- Cost is far out of proportion to a latent bug. Revisit only if TinyOS ever
  needs more than about 1 GB of RAM, where identity mapping runs out of PD[0]
  anyway.

### C. Fence the shadowed frames in the PMM (stopgap, no re-sign)

At boot, mark frames `[128 MB, 128 MB + ELF_MAX_PROCESS_MEMORY)` as used, so no
kernel object can ever live in a shadowed frame.

- It is small, and no binary changes.
- It wastes 16 MB (6 % of 256 MB). It encodes the bug as a reservation instead
  of removing it, and it does not close the general loader gap. It also relies
  on `ELF_MAX_PROCESS_MEMORY` and the link base never changing without
  anyone noticing.
- It is acceptable only as a bridge if A has to wait for a release.

### D. Cap RAM at 128 MB

Rejected. It halves usable memory and changes every harness's environment, to
hide a bug that A fixes outright.

## Recommendation

**Do A**, as one PR:

1. Change `userspace/user.ld` to `0x20000000`. Replace the stale
   `USER_CODE_BASE 0x08048000` in `memory.h`, which is wrong today (the real
   base is `0x08000000`), with `USER_IMAGE_BASE 0x20000000`, and update its
   readers: `paging.c:763`, and the `security_tests.c` fault test at 413 to 436.
2. Add the static assert and the loader range refusal.
3. Fix the text that names the old base: `tools/gen_architecture_svg.py:78`
   (then regenerate the SVG; never edit it by hand), the comment in `pae.c`
   ~1116, and `doc/SECURITY_AUDIT_2026-10.md` §3, which moves to "fixed".
4. Leave alone `userspace/msealprobe.c:85`. Its `0x08000000u` is a size (128 MB,
   over the 64 MB cap), not an address.

Do not raise any per-uid cap before this lands.

## Re-signing: what changes

- **Embedded blobs.** All 20 `src/*_elf_data.c` files are regenerated through
  `userspace/Makefile` (`%.elf` to `sign_elf.py` to `%.elf.signed` to
  `elf_to_c.py`) with the dev key. The kernel pins that key (`elf.c:252`), so it
  is unchanged. Build in the main checkout or a bootstrapped worktree;
  otherwise `sign_elf.py` silently falls back to an ephemeral key and every
  harness reports false failures.
- **ELFs on `disk.img` / C:.** Any `.elf` a harness copies onto a disk image
  comes from the same build, so a fresh build covers it. A stale `disk.img`
  holding old-base ELFs would still load: they are signed, and 0x08000000 sits
  inside the identity range, so after the change the new loader check refuses
  them. That refusal is correct, but it is an easy false FAIL. Rebuild
  `disk.img`.
- **Release artefacts.** The signed release ISO (minisign), `web/tinyos.iso`
  and `gh-pages` only change at the next release. They are the four artefacts
  in `web/README.md` and move together. This PR does not touch them.
- **Crypto is not touched.** Same key, same scheme. Only the signed bytes
  change.

## Test plan (fail-first)

1. **Witness, under `-DTINYOS_FAULT_INJECT`.** A kernel self-test claims
   physical frame `0x08000000` from the PMM (or asserts it is free and marks
   it). Under the kernel CR3 it writes a 16-byte sentinel through the identity
   pointer. It builds a user PDPT by loading `hello.elf` without scheduling it,
   switches to that CR3, reads the same identity pointer, switches back, and
   prints one verdict line: `OVERLAP-WITNESS same|differs`. It also releases
   the PDPT and image frames, which the frame-leak harness then checks.
   - On the old base it must print `differs` (it reads image bytes). Run it on
     the unfixed tree first and record that.
   - On the new base it prints `same`.
   - Mutation check: revert only `user.ld` and confirm `differs` comes back.
2. **Loader refusal.** A test-only signed probe linked at `0x00100000`
   (`lowprobe.elf`, its own linker script) must be refused with the single
   verdict line, and the refusal counter must go up by exactly 1. Positive
   control: `hello.elf` at the new base runs to "exited with status 0".
3. **Regressions.** Run the harnesses that cover the loader and address space:
   `verify-exec-frame-leak.sh` (exact frame equality),
   `verify-mseal-counters.sh`, the ASLR, guard-page and W^X harnesses
   (`wxaudit` must still report 0 violations), `verify-argv.sh`, and one
   ring-3 shell login harness. All run at `-m 256M`. Run one boot at `-m 128M`
   as well, to show nothing assumed the old layout.
4. **CI.** The build gate already catches a `-Werror` break and the static
   assert. Add the witness to the non-QEMU set only if it can run without a
   guest. It cannot, so it stays a QEMU harness.

## Open questions for the decision

- Is `0x20000000` the right base, or should it be `0x40000000` (its own PD[1],
  fully separate from the identity PD)? `0x40000000` is cleaner, but it
  collides by name with `USER_STACK_BASE` and `ASLR_STACK_MIN` (both
  `0x40000000`, whose fallback branch at `aslr.c:162` can place a stack just
  above it). `0x20000000` avoids that and leaves room for RAM up to 512 MB.
- Should C ship first as a bridge, or can A go straight in? A is small enough
  that a bridge looks unnecessary.
