# ============================================================================
#  User Programs Makefile
# ============================================================================

CROSS         ?= i686-elf-
CC            := $(CROSS)gcc
LD            := $(CROSS)gcc

# Compiler flags for user programs
CFLAGS  := -m32 -ffreestanding -fno-pic -fno-builtin -fno-stack-protector \
           -nostdlib -O0 -Wall -Wextra

# Linker flags
LDFLAGS := -T user.ld -ffreestanding -nostdlib -Wl,--build-id=none

# User programs to build
PROGRAMS := hello.elf shell.elf info.elf sleeper.elf spawner.elf fileio.elf

# Common runtime objects for libc-based programs
LIBC_OBJS := crt0.o libc.o

# ---------------------------------------------------------------------------
# Default target: build all user programs
# ---------------------------------------------------------------------------

all: $(PROGRAMS)

crt0.o: crt0.S
	$(CC) $(CFLAGS) -c crt0.S -o crt0.o

libc.o: libc.c libc.h
	$(CC) $(CFLAGS) -c libc.c -o libc.o

# libc-based programs (crt0 provides _start)
hello.elf: hello.c libc.h $(LIBC_OBJS) user.ld
	$(CC) $(CFLAGS) -c hello.c -o hello.o
	$(LD) $(LDFLAGS) -o hello.elf crt0.o hello.o libc.o -lgcc
	@echo "Built hello.elf"

info.elf: info.c libc.h $(LIBC_OBJS) user.ld
	$(CC) $(CFLAGS) -c info.c -o info.o
	$(LD) $(LDFLAGS) -o info.elf crt0.o info.o libc.o -lgcc
	@echo "Built info.elf"

# sleeper.elf is the background-jobs test fixture (see verify-bgjobs.sh); it
# was previously built by hand, which left no way to rebuild it after an ABI
# change without rediscovering the command.
sleeper.elf: sleeper.c libc.h $(LIBC_OBJS) user.ld
	$(CC) $(CFLAGS) -c sleeper.c -o sleeper.o
	$(LD) $(LDFLAGS) -o sleeper.elf crt0.o sleeper.o libc.o -lgcc
	@echo "Built sleeper.elf"

# spawner.elf is the SYS_SPAWN test fixture (see verify-spawn.sh): a USER
# process that starts another process, which the shell's own `exec` cannot
# demonstrate because that path runs in the kernel.
spawner.elf: spawner.c libc.h $(LIBC_OBJS) user.ld
	$(CC) $(CFLAGS) -c spawner.c -o spawner.o
	$(LD) $(LDFLAGS) -o spawner.elf crt0.o spawner.o libc.o -lgcc
	@echo "Built spawner.elf"

# fileio.elf is the file-syscall test fixture (see verify-fsyscalls.sh): a USER
# process doing open/write/read/readdir. The shell's own cat/ls cannot prove
# these syscalls work, since they run in the kernel and touch ramfs directly.
fileio.elf: fileio.c libc.h $(LIBC_OBJS) user.ld
	$(CC) $(CFLAGS) -c fileio.c -o fileio.o
	$(LD) $(LDFLAGS) -o fileio.elf crt0.o fileio.o libc.o -lgcc
	@echo "Built fileio.elf"

# shell.elf provides its own _start and syscall wrappers
shell.elf: shell.c libc.h $(LIBC_OBJS) user.ld
	$(CC) $(CFLAGS) -c shell.c -o shell.o
	$(LD) $(LDFLAGS) -o shell.elf crt0.o shell.o libc.o -lgcc
	@echo "Built shell.elf"

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

clean:
	rm -f *.o $(PROGRAMS)

# ---------------------------------------------------------------------------
# Info targets
# ---------------------------------------------------------------------------

# Show information about the compiled ELF
info: hello.elf
	@echo "=== ELF Header ==="
	i686-elf-readelf -h hello.elf
	@echo ""
	@echo "=== Program Headers ==="
	i686-elf-readelf -l hello.elf
	@echo ""
	@echo "=== Sections ==="
	i686-elf-readelf -S hello.elf

.PHONY: all clean info
