# userspace/ — ring-3 shell and libc

- The ring-3 shell is the **default login shell** (PR #51); `kshell` hands over to the kernel
  shell, `exit` logs out. It echoes a whole line after `readline()` returns (`shell.c:2035`).
- `history`/`jobs` are ring-3-local **by design** — sharing the kernel shell's buffers would
  leak one session's command lines to another user.
- **Machine-state commands stay kernel-shell only** (`pae`, `mem`, `wxaudit`, `auditlog`,
  networking and security tooling) — together they are an ASLR defeat (PR #58).
- **Don't migrate `su`, `edit` or `top`.** `su` needs the plaintext password in ring 3 (the
  exposure `SYS_CRED` removes), and a kernel-prompting `CRED_OP_SU` would let ring 3 mutate its
  own uid. `edit`/`top` need a TTY discipline, not write-back. `ls C:/` already *is* `fatls`.
  Reasoning: `doc/ROADMAP_NEXT.md`.
- **`SYS_ENV` (41):** `env_record_t` is mirrored in `libc.h` with `_Static_assert`s on both
  copies — change both. `LIST` enumerates by index. `$VAR`/alias expansion lives in
  `expand_aliases`/`expand_vars` here; the syscall alone ships a dead feature.
- `fork()` was skipped deliberately (PAE, no COW pages).
