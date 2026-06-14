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
PROGRAMS := hello.elf shell.elf

# ---------------------------------------------------------------------------
# Default target: build all user programs
# ---------------------------------------------------------------------------

all: $(PROGRAMS)

# Build hello.elf from hello.c
hello.elf: hello.c user.ld
	$(CC) $(CFLAGS) -c hello.c -o hello.o
	$(LD) $(LDFLAGS) -o hello.elf hello.o -lgcc
	@echo "Built hello.elf"

# Build shell.elf from shell.c
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
