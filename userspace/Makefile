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
PROGRAMS := hello.elf shell.elf info.elf

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

# shell.elf provides its own _start and syscall wrappers
shell.elf: shell.c user.ld
	$(CC) $(CFLAGS) -c shell.c -o shell.o
	$(LD) $(LDFLAGS) -o shell.elf shell.o -lgcc
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
