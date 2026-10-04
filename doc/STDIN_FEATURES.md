# TinyOS Standard Streams Implementation

## Overview
Every task carries Unix-like standard streams (stdin, stdout, stderr). They are
what kernel-shell redirection and pipelines bind, what a ring-3 process's fds 0-2
read and write, and what a spawned child inherits.

## Standard File Descriptors

| FD | Name   | Default | Description |
|----|--------|---------|-------------|
| 0  | stdin  | Keyboard (console) | Standard input |
| 1  | stdout | Console | Standard output |
| 2  | stderr | Console | Standard error |
| 3-18 | - | - | Files opened with `SYS_OPEN` (per-process table) |

## 1. Stream Infrastructure (`src/stdio.h`, `src/stdio.c`)

**Core Components**:
- A `stream_context_t` embedded in each task (`task_t.streams`, `src/process.h`)
- Type-based stream abstraction (console, file, pipe, null)
- Redirection management
- Read/write operations

**Stream Types**:
```c
typedef enum {
    STREAM_TYPE_CONSOLE,    /* VGA console */
    STREAM_TYPE_FILE,       /* RAMFS file */
    STREAM_TYPE_PIPE,       /* Pipe buffer */
    STREAM_TYPE_NULL,       /* /dev/null equivalent */
} stream_type_t;
```

`get_current_streams()` returns the calling task's own context, so a redirection
in one task never affects another.

## 2. File Descriptors and Inheritance

- **fds 0-2** are the three streams. `streams_inherit(child, creator)` copies the
  creator's streams into a new task before it is scheduled; the spawn path calls
  it, so a child writes wherever its parent's stdout pointed. A file stream gets
  its own reference, so parent and child close independently; a pipe stream is
  marked `borrowed`. Without the call a task starts on the console.
- **fds 3-18** come from `SYS_OPEN`. Each task has a 16-slot table
  (`TASK_FDTABLE_SIZE`) mapping its fds to global VFS fds. The table starts empty
  in every new process; it is not inherited.

## 3. stdin

stdin can be a file (`cmd < file`), a pipe, or the console.

The kernel shell's `cat` reads stdin when given no file, and accepts a file or a
pipe there. It refuses the console, since nothing at the keyboard can signal end
of input:

```bash
$ cat
cat: reading from keyboard not supported (use files, pipes or redirection)
$ cat -n < /scratch/notes.txt
$ ls | cat
```

In the ring-3 shell, programs and the `cat` and `grep` builtins read fd 0, which
may be a file, a pipe or the console.

## 4. stdout and stderr

Kernel-shell commands print through `stream_printf(get_current_streams(), ...)`.
When stdout is a file, the formatted text is written to that file; otherwise it
goes to the console through `vkprintf()`. In a kernel-shell pipeline, the stages
before the last have their console output captured into the pipe, so builtins
work as pipeline stages.

For ring-3 processes, `SYS_WRITE` on fd 1 or 2 goes through `stdout_write()` /
`stderr_write()` on the task's streams, which honour file, pipe and null
streams. A pipe write blocks while the pipe is full and fails once the read end
is closed.

## 5. Redirection and Pipes

**Kernel shell**: `cmd > file`, `cmd >> file` and `cmd < file` bind the task's
streams for the duration of one command and reset them afterwards. A pipeline
runs its stages in turn, carrying up to 4 KB between them. See
[`SHELL_FEATURES.md`](SHELL_FEATURES.md).

**Ring 3**: `SYS_REDIRECT` points stdin, stdout or stderr at a RAM-disk file
(`stdin_redirect_from_file()` / `stdout_redirect_to_file()`, which truncates or
appends) or restores it. `SYS_PIPE` creates a pipe and binds its ends to two
processes' streams, so the ring-3 shell's `prog1 | prog2` runs both stages
concurrently.

**Paths**: redirection paths are canonicalized, so absolute paths and `..` are
accepted and resolved. Kernel-shell filenames are limited to letters, digits,
`-`, `_`, `.` and `/`, up to 255 characters. File permissions are enforced by
the RAM disk on open.

## Architecture

```
src/
├── stdio.h, stdio.c      # Streams, inheritance, stream_printf
├── process.h             # task_t.streams and the per-process fd table
├── shell.c               # Kernel-shell redirection binding and pipelines
├── shell_redir.c         # Redirection parsing and filename validation
├── shell_fileops.c       # cat (reads stdin)
└── syscall.c             # SYS_READ/SYS_WRITE on fds, SYS_REDIRECT, SYS_PIPE
```

### Stream Context Flow (kernel shell):
1. **Initialization**: `streams_init()` sets console defaults for a new task.
2. **Redirection Setup**: `<` calls `stdin_redirect_from_file()`; `>`/`>>` bind
   stdout to the opened file.
3. **Command Execution**: commands read with `stdin_read()` and print with
   `stream_printf()`.
4. **Cleanup**: `stdin_reset()` / `stdout_reset()` close the file and restore
   the console.

## Adding stdin Support to a Kernel Command

```c
#include "stdio.h"

void cmd_mycommand(int argc, char* argv[]) {
    stream_context_t* streams = get_current_streams();
    bool use_stdin = (argc < 2);   /* No file argument */
    int fd = -1;

    if (use_stdin) {
        /* Accept a file or a pipe; refuse the console (no EOF there). */
        if (!stdin_is_file(streams) && !stdin_is_pipe(streams)) {
            stream_printf(streams, "mycommand: no input (use files, pipes or redirection)\n");
            return;
        }
    } else {
        fd = ramfs_open(argv[1], RAMFS_FLAG_READ);
        if (fd < 0) {
            stream_printf(streams, "mycommand: cannot open %s\n", argv[1]);
            return;
        }
    }

    char buffer[256];
    int bytes_read;
    while (1) {
        bytes_read = use_stdin ? stdin_read(streams, buffer, sizeof(buffer))
                               : ramfs_read(fd, buffer, sizeof(buffer));
        if (bytes_read <= 0) break;
        /* Process buffer; print results with stream_printf(streams, ...) */
    }

    if (fd >= 0) {
        ramfs_close(fd);
    }
}
```

## API Reference

### Initialization and cleanup
```c
void streams_init(stream_context_t* ctx);
void streams_cleanup(stream_context_t* ctx);
void streams_inherit(stream_context_t* child, const stream_context_t* creator);
```
Set console defaults; close all open stream fds; copy a creator's streams into a
child before it is scheduled.

### stdin
```c
int  stdin_redirect_from_file(stream_context_t* ctx, const char* filename);
void stdin_reset(stream_context_t* ctx);
int  stdin_read(stream_context_t* ctx, char* buffer, size_t size);
int  stdin_getline(stream_context_t* ctx, char* buffer, size_t size);
bool stdin_has_data(stream_context_t* ctx);
bool stdin_is_file(stream_context_t* ctx);
bool stdin_is_pipe(stream_context_t* ctx);
```

### stdout / stderr
```c
int  stdout_redirect_to_file(stream_context_t* ctx, const char* filename, bool append);
void stdout_reset(stream_context_t* ctx);
void stderr_reset(stream_context_t* ctx);
int  stdout_write(stream_context_t* ctx, const char* data, size_t size);
int  stderr_write(stream_context_t* ctx, const char* data, size_t size);
int  stream_printf(stream_context_t* ctx, const char* format, ...);
void printf_stream(const char* str);
```
`stream_printf` is declared with `format(printf, 2, 3)`, so `-Wformat` checks
every call.

### Helper
```c
stream_context_t* get_current_streams(void);
```
Returns the current task's stream context.

## Not Implemented
- Reading the console as stdin from kernel-shell commands (refused, see above)
- `dup` / `dup2`
- `isatty()`

---
**Last Updated**: 2026-10-04
**TinyOS Version**: v2.9
