# TinyOS Shell Features

## Scope

This document describes the **kernel shell** (`src/shell.c`), reached by typing
`kshell` at the login shell: environment variables, aliases, I/O redirection and
pipelines. The default login shell is the **ring-3 shell** (`userspace/shell.c`);
its differences are summarised in [Ring-3 shell](#ring-3-shell) below, and its
command set is in [`USER_GUIDE.md`](USER_GUIDE.md).

## 1. Environment Variables
**Files**: `src/env.h`, `src/env.c`, `src/shell_system.c`

#### Commands:
- `set VAR=value` - Set a shell variable
- `set` - Display all variables
- `export VAR` - Mark an existing variable for export to child processes
- `export VAR=value` - Set and export in one step
- `export` / `env` - Display exported variables
- `unset VAR...` - Remove one or more variables

#### Variable Expansion:
Both `$VAR` and `${VAR}` are expanded:
```bash
$ set MESSAGE=Hello
$ echo $MESSAGE
Hello
$ echo ${MESSAGE}_World
Hello_World
```

#### Default Environment Variables:
Every login starts from a fresh table with these, all exported:

- `PATH=/bin`
- `HOME=/`
- `USER=root`
- `SHELL=/bin/shell`
- `TERM=vga`
- `PWD=/`
- `OLDPWD=/`
- `HOSTNAME=tinyos`
- `EDITOR=edit`
- `PAGER=cat`

After login, `USER` is set to the logged-in user's name and `HOME` to `/` for
root or `/home` for anyone else.

#### Per-task storage and inheritance:
Variables and aliases live in a per-task 4 KB page, allocated the first time a
task writes one. A program started with `exec` (or `spawn` from ring 3) receives
a **snapshot of the exported variables only**; later changes on either side are
invisible to the other. Aliases are never inherited.

## 2. Command Aliases
**Files**: `src/env.h`, `src/env.c`, `src/shell_system.c`

#### Commands:
- `alias name=command` - Create an alias
- `alias name` - Show one alias
- `alias` - Display all aliases (`alias name='command'` per line)
- `unalias name...` - Remove one or more aliases

The kernel shell splits a line on spaces and has no quoting, so an alias value
must be a single word (`alias cl=clear`). Surrounding quotes are stripped. For a multi-word alias use the ring-3 shell.

Only the first word of a line is checked against the alias table, and expansion
happens once (no recursion).

#### Default Aliases (12 of 16 slots):
```bash
ll    -> ls -l
la    -> ls -a
cls   -> clear
dir   -> ls
copy  -> cp
move  -> mv
del   -> rm
md    -> mkdir
rd    -> rm -r
type  -> cat
..    -> cd ..
h     -> history
```

Four slots are left free for user aliases.

## 3. I/O Redirection
**Files**: `src/shell_redir.h`, `src/shell_redir.c`, `src/shell.c`

#### Operators:
- `>` - Send stdout to a file, replacing its contents
- `>>` - Send stdout to the end of a file, keeping its contents
- `<` - Read stdin from a file

The target of `>`/`>>` is opened for writing, and created if it does not exist;
`>` truncates it first and `>>` writes after its last byte;
the command's stdout stream is bound to it, so output printed through
`stream_printf()` lands in the file. `<` binds stdin to the file. In the kernel
shell `cat` is the command that reads stdin.

```bash
$ echo Hello > /scratch/out.txt
$ cat < /scratch/out.txt
Hello
```

#### Filename validation:
- The path is canonicalized before use, so absolute paths and `..` are accepted
  and resolved.
- Allowed characters: letters, digits, `-`, `_`, `.` and `/`.
- At most 255 characters.
- Output files are opened without following symlinks.
- File permissions are enforced by the RAM disk itself, as for any other open.
- Targets under a protected system path (`/bin`, `/sbin`, `/etc`, `/boot`,
  `/kernel`) are refused unless the shell is running as root. The same rule
  covers `cp`, `mv`, `rm`, `mkdir`, `touch`, `write`, `chmod` and `edit` saves.

A malformed redirection prints `shell: invalid redirection syntax`. A target that
cannot be opened prints `shell: cannot create <file>` or
`shell: <file>: cannot open file for reading`.

## 4. Pipelines

```bash
$ echo hello | cat
hello
$ ls | cat -n
```

- Up to **4 stages** (`MAX_PIPE_STAGES`). More prints
  `shell: invalid pipeline (max 4 stages)`; a `|` with nothing on one side prints
  `shell: syntax error near '|'`.
- Stages run **one after another**. Each stage's output is captured into a
  4 KB buffer (`PIPE_BUFFER_SIZE`) and fed to the next stage's stdin. Output
  beyond 4 KB is dropped and reported:
  `shell: stage N output truncated at 4096 bytes (M dropped)`.
- Each stage is parsed as a full command line, so aliases, variables and
  redirections apply per stage.
- Builtins can be stages. Of the builtins, `cat` reads stdin, so the useful form
  is `cmd | cat`.

The ring-3 shell runs pipelines concurrently over a kernel pipe instead; see
below.

## 5. Background Jobs

`exec <file> &` starts a signed program without waiting for it. `jobs` lists the
background jobs, `ps` all visible processes, and `kill <pid>` ends one.

## 6. Command Processing Order

1. **Copy** - The line is copied before processing.
2. **Pipeline split** - If the line contains `|`, it is split and each stage is
   run through steps 3-6 on its own.
3. **Alias expansion** - First word only, one pass.
4. **Variable expansion** - `$VAR` and `${VAR}`; the result may be at most 512
   bytes (`shell: command too long after variable expansion`).
5. **Redirection parsing** - Operators are extracted and filenames validated.
6. **Execution** - The line is split on spaces into at most 10 arguments
   (`MAX_ARGS`) and dispatched; streams are reset afterwards.

An unknown command prints:

```
Unknown command: <cmd>
Type 'help' for available commands, or 'man <cmd>' for details.
```

## 7. Limits

| Item | Limit |
|------|-------|
| Command line | 256 bytes (`SHELL_BUFFER_SIZE`) |
| Arguments | 10 (`MAX_ARGS`) |
| Expanded line | 512 bytes (`ENV_MAX_EXPAND_LEN`) |
| Variables | 16 (`ENV_MAX_VARS`) |
| Variable name / value | 32 / 64 bytes (`ENV_MAX_NAME_LEN`, `ENV_MAX_VALUE_LEN`) |
| Aliases | 16 (`ALIAS_MAX_COUNT`) |
| Alias name / command | 32 / 64 bytes (`ALIAS_MAX_NAME_LEN`, `ALIAS_MAX_CMD_LEN`) |
| Pipeline stages | 4 (`MAX_PIPE_STAGES`) |
| Pipe buffer | 4096 bytes (`PIPE_BUFFER_SIZE`) |
| Redirection filename | 255 characters |

Variable names must start with a letter or underscore, followed by letters,
digits or underscores.

## Ring-3 shell

The login shell shares the same per-task environment mechanism (through the
`SYS_ENV` syscall) and the same `$VAR` / `${VAR}` syntax, with these differences:

- It starts with the session's exported variables and **no aliases**.
- `alias` handles quotes and multi-word values (`alias ll='ls -l'`).
- `>` truncates, `>>` appends and `<` reads, for builtins and programs alike.
  Targets must be on `D:`, and protected system paths are refused.
- A pipeline joins exactly **two programs**, which run concurrently over a
  kernel pipe; a builtin cannot be a stage.
- `cmd &` runs a program in the background; `jobs` lists them.
- An unknown command prints `<cmd>: not found (try 'help')`.

## Architecture

```
src/
├── env.h, env.c          # Environment and alias tables (per-task page)
├── shell_redir.h/.c      # Redirection parsing, filename validation, pipe buffer
├── stdio.h, stdio.c      # Per-task stdin/stdout/stderr streams
├── shell.c               # Kernel shell: dispatch, pipelines, redirection binding
└── shell_system.c        # env, set, export, unset, alias, unalias
userspace/
└── shell.c               # Ring-3 login shell
```

See [`STDIN_FEATURES.md`](STDIN_FEATURES.md) for the stream layer.

---
**Last Updated**: 2026-10-04
**TinyOS Version**: v2.9
