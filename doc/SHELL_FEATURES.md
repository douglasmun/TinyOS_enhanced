# TinyOS Shell Features

## Overview
TinyOS now includes a comprehensive bash-like shell with environment variables, command aliases, and I/O redirection infrastructure.

## Features Implemented

### 1. Environment Variables
**Files**: `src/env.h`, `src/env.c`

The shell now supports full environment variable management similar to bash:

#### Commands:
- `set VAR=value` - Set a shell variable
- `set` - Display all variables
- `export VAR` - Mark variable for export to child processes
- `unset VAR` - Remove a variable
- `env` - Display exported variables

#### Variable Expansion:
The shell supports both `$VAR` and `${VAR}` syntax for variable expansion:
```bash
$ set MESSAGE=Hello
$ echo $MESSAGE
Hello
$ echo ${MESSAGE}_World
Hello_World
```

#### Default Environment Variables:
- `PATH=/bin` - Command search path
- `HOME=/` - Home directory
- `USER=root` - Current user
- `SHELL=/bin/shell` - Shell path
- `TERM=vga` - Terminal type
- `PWD=/` - Current working directory
- `OLDPWD=/` - Previous working directory
- `HOSTNAME=tinyos` - System hostname
- `EDITOR=edit` - Default text editor
- `PAGER=cat` - Default pager

### 2. Command Aliases
**Files**: `src/env.h`, `src/env.c`

Create shortcuts for commonly-used commands:

#### Commands:
- `alias name='command'` - Create an alias
- `alias` - Display all aliases
- `unalias name` - Remove an alias

#### Default Aliases (15 total):
```bash
ll    -> ls -l          # Long listing
la    -> ls -a          # Show all files
l     -> ls             # Simple listing
cls   -> clear          # DOS-style clear
dir   -> ls             # DOS-style directory listing
copy  -> cp             # DOS-style copy
move  -> mv             # DOS-style move
del   -> rm             # DOS-style delete
md    -> mkdir          # DOS-style make directory
rd    -> rm -r          # DOS-style remove directory
type  -> cat            # DOS-style type
..    -> cd ..          # Quick parent directory
...   -> cd ../..       # Quick grandparent directory
h     -> history        # Short history
k     -> kill           # Short kill
please -> sudo          # Easter egg (sudo not implemented)
```

### 3. I/O Redirection Infrastructure
**Files**: `src/shell_redir.h`, `src/shell_redir.c`

The shell now parses I/O redirection operators and creates files accordingly:

#### Supported Operators:
- `>` - Output redirection (truncate)
- `>>` - Output redirection (append)
- `<` - Input redirection

#### Security Features:
All redirection filenames are validated to prevent security issues:
- ✅ Only relative paths allowed (no `/etc/passwd`)
- ✅ No parent directory traversal (no `../../../system`)
- ✅ Whitelist of allowed characters (alphanumeric, dash, underscore, dot, slash)
- ✅ Length limits (255 characters max)
- ✅ Buffer overflow protection

#### Example Usage:
```bash
$ echo Hello > output.txt
$ cat output.txt
Hello

$ echo World >> output.txt
$ cat output.txt
Hello
World
```

### 4. Pipe Buffer System
**Files**: `src/shell_redir.h`, `src/shell_redir.c`

A 4KB circular buffer implementation for pipe support:
- `pipe_init()` - Initialize pipe buffer
- `pipe_write()` - Write data to pipe
- `pipe_read()` - Read data from pipe
- `pipe_available()` - Check available data

This infrastructure is ready for implementing shell pipes (`|`).

## Command Processing Order

The shell processes commands in the following order (bash-compliant):

1. **TOCTOU Protection** - Copy command to prevent time-of-check-time-of-use attacks
2. **Alias Expansion** - Expand command aliases (first word only)
3. **Variable Expansion** - Expand `$VAR` and `${VAR}` references
4. **Redirection Parsing** - Extract and validate I/O redirections
5. **Command Execution** - Execute the clean command
6. **Cleanup** - Close redirection file descriptors

This order prevents alias loops, command injection, and buffer overflows.

## Security Features

### 1. TOCTOU Prevention
Commands are copied before processing to prevent race conditions where user input could modify the command during execution.

### 2. Buffer Overflow Protection
All string operations use bounded functions with size limits:
- Command buffer: 256 bytes
- Environment variable names: 32 bytes
- Environment variable values: 256 bytes
- Alias names: 32 bytes
- Alias commands: 128 bytes

### 3. Input Validation
- Environment variable names must be alphanumeric + underscore
- First character must be letter or underscore
- Redirection filenames validated with whitelist

### 4. Filename Security
Redirection filenames are validated to prevent:
- Absolute path access (`/etc/passwd`)
- Directory traversal attacks (`../../../`)
- Special characters that could cause issues
- Excessively long filenames (>255 chars)

## Current Limitations

### Output Capture Not Fully Implemented
The redirection infrastructure is complete and files are created properly, but actual output capture requires deeper kernel integration:

**Why**: All commands use `kprintf()` directly, which writes to VGA console. To capture output, we would need:
1. A kernel-level redirection context
2. Modify `kprintf()` to check for active redirections
3. Buffer management for redirected output
4. Write buffered output to files

**Current Behavior**:
- Redirection syntax is parsed correctly ✅
- Files are created/opened properly ✅
- Command output still goes to console ⚠️
- Files remain empty (no output captured) ⚠️

**Future Enhancement**: Implement a kernel-level output buffer system that `kprintf()` can check for active redirections.

### Input Redirection - ✅ IMPLEMENTED
Input redirection (`<`) is now fully functional for compatible commands:

**How It Works**:
- Syntax: `command < input_file.txt`
- The shell parses the `<` operator and extracts the filename
- For compatible commands (cat, grep, wc), the filename is appended as an argument
- Example: `cat < readme.txt` becomes `cat readme.txt` internally

**Supported Commands**:
- `cat < file.txt` - Display file contents via redirection
- `grep pattern < file.txt` - Search pattern in file via redirection

**Security**: All filenames are validated (no absolute paths, no directory traversal, whitelist characters)

**Unsupported Commands**: Commands that don't accept file input (like `echo`) will show an error

### Pipes - ✅ IMPLEMENTED (Parsing Complete)
Pipe operator (`|`) support is implemented with pipeline parsing and sequential execution:

**How It Works**:
- Syntax: `command1 | command2 | command3`
- The shell detects the pipe operator and splits the command line
- Each command in the pipeline is executed sequentially
- The pipeline structure is parsed and validated

**Current Behavior**:
- Pipeline syntax is parsed correctly ✅
- Commands are split and identified ✅
- Each command executes independently ✅
- Output capture between commands not yet implemented ⚠️

**Example**:
```bash
$ ls | grep txt | wc
shell: executing pipeline with 3 commands
  [1] ls
  [2] grep txt
  [3] wc
shell: note: pipes parse correctly but output capture not yet implemented
```

**Limitation**: Like output redirection, connecting command outputs requires kernel-level output buffering. The pipe buffer infrastructure is ready, but capturing output from one command and feeding it to the next requires deeper `kprintf()` integration.

**Security**: Up to 4 commands per pipeline (MAX_PIPE_STAGES), with buffer overflow protection.

## Testing the Features

### Test Environment Variables:
```bash
$ set NAME=TinyOS
$ echo Hello $NAME
Hello TinyOS

$ set VERSION=1.0
$ echo $NAME version $VERSION
TinyOS version 1.0

$ env
PATH=/bin
HOME=/
USER=root
...
```

### Test Aliases:
```bash
$ alias test='echo Testing'
$ test
Testing

$ alias
ll='ls -l'
la='ls -a'
test='echo Testing'
...

$ unalias test
$ test
Unknown command: test
```

### Test Output Redirection:
```bash
$ echo test > output.txt
(Syntax is parsed, file created, but output not captured yet)

$ ls
output.txt
```

### Test Input Redirection:
```bash
$ cat readme.txt
Hello TinyOS!

$ cat < readme.txt
Hello TinyOS!
(Functionally equivalent - input redirection working)

$ grep Hello < readme.txt
Hello TinyOS!
(Searching with input redirection working)

$ echo test < readme.txt
shell: echo: input redirection not supported for this command
(Unsupported command properly rejected)
```

### Test Pipes:
```bash
$ ls | grep txt
shell: executing pipeline with 2 commands
  [1] ls
  [2] grep txt
shell: note: pipes parse correctly but output capture not yet implemented
(Both commands execute, showing pipeline parsing works)

$ echo Hello | cat | grep llo
shell: executing pipeline with 3 commands
  [1] echo Hello
  [2] cat
  [3] grep llo
shell: note: pipes parse correctly but output capture not yet implemented
(3-stage pipeline correctly parsed and executed)
```

### Test Security:
```bash
$ echo test > /etc/passwd
shell: cannot create /etc/passwd
(Absolute paths rejected)

$ echo test > ../../../dangerous
shell: invalid redirection syntax
(Directory traversal rejected)

$ cat < /etc/passwd
shell: invalid redirection syntax
(Absolute paths in input redirection rejected)

$ cat < ../../system.conf
shell: invalid redirection syntax
(Directory traversal in input redirection rejected)
```

## Architecture

### File Organization:
```
src/
├── env.h                 # Environment & alias declarations
├── env.c                 # Environment & alias implementation
├── shell_redir.h         # Redirection & pipe declarations
├── shell_redir.c         # Redirection & pipe implementation
├── shell.c               # Main shell (integrated with env & redir)
├── shell_system.c        # System commands (env, set, alias, etc.)
└── kernel.c              # Calls env_init() at boot
```

### Integration Points:
1. **kernel.c** - Calls `env_init()` during boot
2. **shell.c** - Uses `env_expand()`, `alias_get()`, `parse_redirections()`, `parse_pipeline()`
3. **shell_system.c** - Implements `cmd_env()`, `cmd_set()`, `cmd_alias()`, etc.
4. **shell_redir.c** - Implements `parse_redirections()` and `parse_pipeline()` for I/O handling

## Memory Usage

### Static Allocations:
- Environment table: 64 variables × 288 bytes = 18,432 bytes
- Alias table: 32 aliases × 168 bytes = 5,376 bytes
- Pipe buffers: 4,096 bytes per pipe
- Total: ~28KB for environment and alias management

### Stack Usage:
- Command processing: ~2KB for expanded command buffers
- Redirection context: ~1KB for redirection structures

## Future Enhancements

1. **Output Capture**: Implement kernel-level output buffer for full redirection and pipe support
2. ~~**Input Redirection**: Read file contents and pass to commands~~ ✅ COMPLETED
3. ~~**Pipe Operator**: Implement command pipelines (`cmd1 | cmd2`)~~ ✅ COMPLETED (parsing)
4. **Full Pipe Output Capture**: Connect command outputs in pipelines
5. **Job Control**: Background processes (`&`), foreground/background switching
6. **Command Substitution**: `$(command)` syntax
7. **Wildcards**: `*.txt` pattern matching
8. **Quoting**: Proper handling of single/double quotes
9. **Escape Sequences**: Backslash escaping

## Testing

The system has been tested with:
- ✅ Boot test in QEMU
- ✅ Environment variable setting and expansion
- ✅ Alias creation and expansion
- ✅ Output redirection parsing and security validation
- ✅ Input redirection parsing and file appending
- ✅ Pipe operator parsing and pipeline splitting
- ✅ File creation for redirections
- ✅ Command processing order
- ✅ Buffer overflow protection
- ✅ TOCTOU protection
- ✅ Input filename validation and security
- ✅ Pipeline command extraction (up to 4 stages)
- ✅ Sequential pipeline execution

## Documentation

For more details on specific components:
- Environment variables: See `src/env.h` header comments
- Redirection: See `src/shell_redir.h` header comments
- Shell integration: See `src/shell.c` parse_and_execute() function

---
**Last Updated**: 2025-11-14
**TinyOS Version**: v1.0 (Build 20251110)
