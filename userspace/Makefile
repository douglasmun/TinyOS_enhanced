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
PROGRAMS := hello.elf shell.elf info.elf sleeper.elf spawner.elf fileio.elf \
            producer.elf counter.elf credprobe.elf slotbomb.elf slothold.elf \
            netprobe.elf msealprobe.elf

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

# producer.elf / counter.elf are the two halves of the ring-3 pipeline fixture
# (see verify-ring3-pipes.sh). They must be a PAIR OF PROGRAMS: a pipeline stage
# is a process, so a builtin cannot stand in for either side, and counter.elf is
# the only thing in userspace that reads fd 0 until EOF — which is what proves
# the pipe blocks while data is coming and ends when the write end closes.
producer.elf: producer.c libc.h $(LIBC_OBJS) user.ld
	$(CC) $(CFLAGS) -c producer.c -o producer.o
	$(LD) $(LDFLAGS) -o producer.elf crt0.o producer.o libc.o -lgcc
	@echo "Built producer.elf"

counter.elf: counter.c libc.h $(LIBC_OBJS) user.ld
	$(CC) $(CFLAGS) -c counter.c -o counter.o
	$(LD) $(LDFLAGS) -o counter.elf crt0.o counter.o libc.o -lgcc
	@echo "Built counter.elf"

# credprobe.elf calls the DEPRECATED credential syscalls straight through
# int 0x80. No shell can make those calls, so this is the only way to prove the
# ring-3 gate holds at the syscall boundary itself.
credprobe.elf: credprobe.c libc.h $(LIBC_OBJS) user.ld
	$(CC) $(CFLAGS) -c credprobe.c -o credprobe.o
	$(LD) $(LDFLAGS) -o credprobe.elf crt0.o credprobe.o libc.o -lgcc
	@echo "Built credprobe.elf"

# netprobe.elf drives SYS_NETRX/SYS_NETTX straight through int 0x80. Nothing in
# the kernel calls them yet (the parser has not moved to ring 3), so this is the
# only way to show the boundary carries frames rather than that networking
# happens to still work — see verify-netd-boundary.sh.
netprobe.elf: netprobe.c libc.h $(LIBC_OBJS) user.ld
	$(CC) $(CFLAGS) -c netprobe.c -o netprobe.o
	$(LD) $(LDFLAGS) -o netprobe.elf crt0.o netprobe.o libc.o -lgcc
	@echo "Built netprobe.elf"

# slotbomb.elf spawns /slothold.elf in a tight loop without reaping, to prove the
# per-user concurrent task cap engages (see verify-slotcap.sh). It has to be a
# program rather than a shell loop: the cap lives at the syscall boundary, and
# driving `&` from the shell is slow enough under TCG that the RATE limiter
# would stop it first — which would pass against a kernel with no cap at all.
slotbomb.elf: slotbomb.c libc.h $(LIBC_OBJS) user.ld
	$(CC) $(CFLAGS) -c slotbomb.c -o slotbomb.o
	$(LD) $(LDFLAGS) -o slotbomb.elf crt0.o slotbomb.o libc.o -lgcc
	@echo "Built slotbomb.elf"

# slothold.elf is slotbomb.elf's child: it holds a task slot for minutes. It
# cannot be sleeper.elf, which lives ~6s -- under TCG each ECDSA-verified spawn
# takes tens of seconds, so sleeper children would exit and free their slots
# before the loop finished and the cap would never be reached.
slothold.elf: slothold.c libc.h $(LIBC_OBJS) user.ld
	$(CC) $(CFLAGS) -c slothold.c -o slothold.o
	$(LD) $(LDFLAGS) -o slothold.elf crt0.o slothold.o libc.o -lgcc
	@echo "Built slothold.elf"

# msealprobe.elf drives SYS_MSEAL (16) straight through int 0x80. That syscall
# has NO libc wrapper and NO shell builtin, so no other program in the tree can
# reach it -- which is exactly how sixteen ring-3-driven kprintf sites sat on
# that path unnoticed. See verify-mseal-counters.sh.
msealprobe.elf: msealprobe.c libc.h $(LIBC_OBJS) user.ld
	$(CC) $(CFLAGS) -c msealprobe.c -o msealprobe.o
	$(LD) $(LDFLAGS) -o msealprobe.elf crt0.o msealprobe.o libc.o -lgcc
	@echo "Built msealprobe.elf"

# shell.elf, like the rest, gets _start from crt0 and main(argc, argv)
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
