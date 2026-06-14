# TinyOS Standard Streams Implementation

## Overview
TinyOS now includes Unix-like standard streams (stdin, stdout, stderr) support, enabling proper I/O redirection and command chaining.

## Standard File Descriptors

### Implemented Streams

| FD | Name   | Default | Description |
|----|--------|---------|-------------|
| 0  | stdin  | Keyboard (console) | Standard input |
| 1  | stdout | VGA Console | Standard output |
| 2  | stderr | VGA Console | Standard error |

## Features Implemented

### 1. Stream Infrastructure (`src/stdio.h`, `src/stdio.c`)

**Core Components**:
- Stream context for each shell session
- Type-based stream abstraction (console, file, pipe, null)
- Redirection management
- Read/write operations

**Stream Types**:
```c
typedef enum {
    STREAM_TYPE_CONSOLE,    /* VGA console (default) */
    STREAM_TYPE_FILE,       /* RAMFS file */
    STREAM_TYPE_PIPE,       /* Pipe buffer (infrastructure ready) */
    STREAM_TYPE_NULL,       /* /dev/null equivalent */
} stream_type_t;
```

### 2. stdin Support

**What Works**:
- ✅ Redirection from files (`cat < file.txt`)
- ✅ Commands can read from stdin when no file specified
- ✅ Automatic stream management (open/close)
- ✅ Security validation (same as output redirection)

**Supported Commands**:
- `cat` - Display file or stdin contents
- `cat < file.txt` - Read from file via stdin
- More commands can be easily added

**Example**:
```bash
$ cat readme.txt
Hello TinyOS!

$ cat < readme.txt
Hello TinyOS!
(Functionally identical - both read the file)
```

### 3. Stream Management Functions

**Initialization**:
```c
void streams_init(stream_context_t* ctx);
```
- Sets up stdin/stdout/stderr to console defaults
- Called automatically when shell starts

**stdin Operations**:
```c
int stdin_redirect_from_file(stream_context_t* ctx, const char* filename);
void stdin_reset(stream_context_t* ctx);
int stdin_read(stream_context_t* ctx, char* buffer, size_t size);
bool stdin_is_file(stream_context_t* ctx);
```

**stdout Operations** (ready for future use):
```c
int stdout_redirect_to_file(stream_context_t* ctx, const char* filename, bool append);
void stdout_reset(stream_context_t* ctx);
int stdout_write(stream_context_t* ctx, const char* data, size_t size);
```

**stderr Operations** (ready for future use):
```c
void stderr_reset(stream_context_t* ctx);
int stderr_write(stream_context_t* ctx, const char* data, size_t size);
```

### 4. Integration with Shell

**Automatic Redirection Setup**:
- When `cmd < file` is detected, stdin is automatically redirected
- Stream is reset after command completes
- No manual file descriptor management needed

**Command Integration Example** (cat command):
```c
void cmd_cat(int argc, char* argv[]) {
    stream_context_t* streams = get_current_streams();

    if (argc < 2) {
        /* No file specified - read from stdin */
        if (!stdin_is_file(streams)) {
            kprintf("cat: reading from keyboard not supported\n");
            return;
        }
        /* Read from stdin (which may be redirected from file) */
        bytes_read = stdin_read(streams, buffer, size);
    } else {
        /* File specified - read directly */
        fd = ramfs_open(argv[1], RAMFS_FLAG_READ);
        bytes_read = ramfs_read(fd, buffer, size);
    }
}
```

## Usage Examples

### stdin Redirection

```bash
# Read file via stdin redirection
$ cat < readme.txt
Hello TinyOS!

# Same as
$ cat readme.txt
Hello TinyOS!

# Can use with -n flag
$ cat -n < readme.txt
     1  Hello TinyOS!
```

### stdin from Pipes (Future)

When output capture is implemented:
```bash
# Chain commands
$ ls | cat
# ls output becomes stdin for cat

$ echo "Hello" | cat
Hello
```

## Security Features

All stdin operations include the same security as file redirection:
- ✅ Filename validation (no absolute paths)
- ✅ No directory traversal (`..` rejected)
- ✅ Character whitelist (alphanumeric, dash, underscore, dot, slash)
- ✅ Length limits (255 characters max)
- ✅ Automatic resource cleanup

**Security Example**:
```bash
$ cat < /etc/passwd
shell: /etc/passwd: cannot open file for reading
(Absolute paths rejected)

$ cat < ../../dangerous.txt
shell: invalid redirection syntax
(Directory traversal rejected)
```

## Architecture

### File Organization:
```
src/
├── stdio.h                # Standard streams declarations
├── stdio.c                # Stream implementation
├── shell.c                # Stream initialization and integration
├── shell_fileops.c        # Commands using stdin (cat, etc.)
└── shell_redir.c          # Redirection parsing
```

### Stream Context Flow:
1. **Initialization**: `streams_init()` sets up default console streams
2. **Redirection Setup**: When `<` detected, `stdin_redirect_from_file()` opens file
3. **Command Execution**: Commands read from stdin via `stdin_read()`
4. **Cleanup**: `stdin_reset()` closes file and restores console

### Memory Usage:
- Stream context: ~100 bytes per shell session
- File descriptors managed by RAMFS
- No dynamic allocation - all stack-based

## Current Limitations

### stdout/stderr Redirection Not Active
While the infrastructure exists, stdout and stderr redirection are not actively used because:
- Commands use `kprintf()` directly (writes to console)
- Would require modifying all commands to use `stdout_write()`
- Or implementing kernel-level output capture in `kprintf()`

**What's Ready**:
- ✅ stdout_redirect_to_file() implemented
- ✅ stdout_write() implemented
- ✅ Stream state management ready
- ⚠️ Commands don't use it yet

**Future Enhancement**: Modify commands to use stream context instead of kprintf()

### Keyboard Input Not Supported for stdin
Reading from keyboard (interactive stdin) is not implemented:
- stdin only works with file redirection
- Interactive commands like `cat` (no args) show helpful error
- Keyboard buffer would be needed for this feature

**Current Behavior**:
```bash
$ cat
cat: reading from keyboard not supported (use files or redirection)
```

### Pipe Connection Not Active
Pipe buffer infrastructure exists but stdin/stdout connection through pipes requires:
1. Output capture from first command
2. Feeding captured output to next command's stdin
3. Process management for pipeline execution

**What's Ready**:
- ✅ Pipe buffer implementation (4KB circular buffer)
- ✅ Pipeline parsing (splits commands correctly)
- ✅ Stream infrastructure supports STREAM_TYPE_PIPE
- ⚠️ Output capture not connected yet

## Testing

### Build and Boot Test:
✅ System builds successfully with stdio.c
✅ Boots normally in QEMU
✅ Streams initialize without errors
✅ Shell operates normally

### stdin Redirection Tests:
```bash
# Test basic redirection
$ cat < readme.txt
[File contents displayed]
✅ Works

# Test with flags
$ cat -n < readme.txt
     1  [File contents with line numbers]
✅ Works

# Test security
$ cat < /etc/passwd
shell: /etc/passwd: cannot open file for reading
✅ Blocked correctly

$ cat < ../../../dangerous
shell: invalid redirection syntax
✅ Blocked correctly
```

## How to Add stdin Support to More Commands

To add stdin support to any command:

1. **Include stdio.h**:
```c
#include "stdio.h"
```

2. **Check for stdin**:
```c
void cmd_mycommand(int argc, char* argv[]) {
    bool use_stdin = (argc < 2);  // No file argument
    stream_context_t* streams = NULL;
    int fd = -1;

    if (use_stdin) {
        streams = get_current_streams();
        if (!stdin_is_file(streams)) {
            kprintf("mycommand: stdin not available\n");
            return;
        }
    } else {
        fd = ramfs_open(argv[1], RAMFS_FLAG_READ);
        if (fd < 0) {
            kprintf("mycommand: cannot open %s\n", argv[1]);
            return;
        }
    }
```

3. **Read from appropriate source**:
```c
    char buffer[256];
    int bytes_read;

    while (1) {
        if (use_stdin) {
            bytes_read = stdin_read(streams, buffer, sizeof(buffer));
        } else {
            bytes_read = ramfs_read(fd, buffer, sizeof(buffer));
        }

        if (bytes_read <= 0) break;

        /* Process buffer */
    }
```

4. **Clean up**:
```c
    if (!use_stdin && fd >= 0) {
        ramfs_close(fd);
    }
}
```

## Future Enhancements

1. **stdout Redirection**: Modify commands to use stdout_write() instead of kprintf()
2. **stderr Redirection**: Separate error messages to stderr stream
3. **Keyboard stdin**: Implement keyboard buffer for interactive input
4. **Pipe Output Capture**: Connect command stdout to next command's stdin
5. **File Descriptor Table**: Per-process FD management
6. **dup/dup2**: File descriptor duplication
7. **isatty()**: Check if FD is a terminal

## API Reference

### Stream Initialization
```c
void streams_init(stream_context_t* ctx);
```
Initialize streams to default (console) state.

### stdin Functions
```c
int stdin_redirect_from_file(stream_context_t* ctx, const char* filename);
```
Redirect stdin to read from a file. Returns 0 on success, -1 on error.

```c
void stdin_reset(stream_context_t* ctx);
```
Reset stdin to default (console/keyboard).

```c
int stdin_read(stream_context_t* ctx, char* buffer, size_t size);
```
Read data from stdin. Returns bytes read, -1 on error, 0 on EOF.

```c
bool stdin_is_file(stream_context_t* ctx);
```
Check if stdin is redirected from a file.

### stdout Functions (Ready for Use)
```c
int stdout_redirect_to_file(stream_context_t* ctx, const char* filename, bool append);
```
Redirect stdout to write to a file.

```c
int stdout_write(stream_context_t* ctx, const char* data, size_t size);
```
Write data to stdout (respects redirection).

### Helper Functions
```c
stream_context_t* get_current_streams(void);
```
Get the global stream context for the current shell.

```c
void streams_cleanup(stream_context_t* ctx);
```
Close all open stream file descriptors.

## Summary

### ✅ What's Implemented:
- Standard stream infrastructure (stdin/stdout/stderr)
- stdin file redirection (`cat < file.txt`)
- Stream type abstraction (console, file, pipe, null)
- Security validation for all stream operations
- Integration with shell redirection system
- cat command reads from stdin when no file specified
- Automatic stream cleanup after command execution

### ⚠️ Partially Implemented:
- stdout/stderr infrastructure exists but not actively used
- Pipe streams defined but not connected

### ❌ Not Yet Implemented:
- stdout/stderr redirection (commands still use kprintf())
- Keyboard input to stdin
- Pipe output capture
- Per-process file descriptor tables

### 🎯 Impact:
- **Better Unix compatibility**: Standard FD 0/1/2 model
- **Cleaner command implementation**: Single code path for file/stdin
- **Future-ready**: Infrastructure for full I/O redirection
- **Secure**: All stream operations validated

---
**Last Updated**: 2025-11-14
**TinyOS Version**: v1.0 (Build 20251110)
