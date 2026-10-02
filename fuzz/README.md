# TinyOS fuzz targets

libFuzzer harnesses that run the real kernel sources on the host, under
ASan and UBSan. Each target compiles the `src/` files it names, with a few
shims, so a finding is a bug in the kernel code itself and not in a model of it.

```
fuzz/build.sh [target...]        # all targets if none named
fuzz/run.sh <target> <seconds> [workers]
FUZZ_VERBOSE=1 fuzz/build/<t>/fuzz_<t> <file>   # replay one input
fuzz/coverage.sh <target> <corpus_dir> [function-regex]
```

You need a clang that ships libFuzzer. On macOS that means Homebrew `llvm`,
because Apple clang has none; on Linux, the distro clang. Set `FUZZ_CC` to override.

## Targets

| Target | Code under test | Oracle beyond ASan/UBSan |
|---|---|---|
| `dns` | `dns.c` response parser | — |
| `dhcp` | `dhcp.c` offer/ack parser | — |
| `net` | `net.c` RX path, which in turn runs firewall, IDS, ICMP, TCP, DNS and DHCP | — |
| `fat32` | `fat32.c` with a hostile disk image | writes land only in the FAT and data region |
| `elfsig` | `elf_verify_signature()` + P-256 verify | nothing verifies except a genuine (hash, r) |
| `elfload` | ELF header / program-header validation before task creation | — (permissive build) |
| `ramfs` | `ramfs.c` primitives as uid 1000 | protected files untouched and never opened; the tree stays well formed |
| `shell` | kernel-shell line parsers: `env_expand`, redirections, pipelines, `canonicalize_path`, PATH, the pipe ring | per-mode structural checks, plus a FIFO model for the pipe |
| `editor` | `editor.c` (`edit`) on a RAMFS file, with injected row-allocation failure | a loaded file equals its rows; each key changes the text only as it says; `:w` writes exactly the rows |

The header comment of each harness gives the input format and its oracles.

## How the host build works

- `prep_hostsrc.py` copies `src/` to `build/src`. On the way it applies the
  `shim/` headers, drops the inline asm, and rewrites `(T*)pmm_alloc()` to the
  fuzz page pool.
  - `FUZZ_NO_PREP=1 build.sh <t>` keeps an edited `build/src`, so you can try
    a fix without touching `src/`.
- Most harnesses `#include` the `.c` file under test, so they can reach its
  statics and reset them between inputs.
- Any symbol the link still lacks gets a weak stub from `gen_weak_stubs.py`.
  Behaviour that a harness depends on is defined in `common/stubs.c` or in the
  harness itself.

## Seeds and regressions

`seeds/<t>/` holds the starting corpus. A file named `regress_*` reproduces a
bug that has since been fixed:

- It must pass against the current tree.
- It must trip an oracle or a sanitizer when built against the parent of the
  fix commit. That is the negative control which shows it still guards the fix.

Corpora and crashes are written to `runs/`, which is gitignored.
