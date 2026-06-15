# ============================================================================
#  TinyOS Makefile – i386, Multiboot2 with User Mode Support
# ============================================================================

# Cross toolchain (Homebrew cross on macOS)
CROSS         ?= i686-elf-
CC            := $(CROSS)gcc
LD            := $(CROSS)gcc        # use gcc driver to pull in libgcc if needed
AS            := nasm
OBJCOPY       := $(CROSS)objcopy
GRUBMKRESCUE  ?= $(shell command -v i686-elf-grub-mkrescue || command -v grub-mkrescue)
QEMU          ?= qemu-system-i386

CFLAGS  := -m32 -ffreestanding -fno-pic -fno-builtin -fstack-protector-strong \
          -O2 -Wall -Wextra -Werror \
          -Wshadow -Wundef \
          -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
          -Wredundant-decls -Wnested-externs \
          -Wuninitialized -Winit-self \
          -Wformat -Wformat-security \
          -Werror=implicit-function-declaration \
          -Werror=return-type -Werror=uninitialized \
          -Wsign-compare \
          -DTINYOS_DEV \
          $(EXTRA_CFLAGS)
# DEV BUILD: -DTINYOS_DEV is a build-SPEED flag only. PBKDF2 strength is NOT
# tied to it (always OWASP 100k unless you explicitly pass -DTINYOS_FAST_KDF).
#
# ELF signing is ENFORCED (fail-closed) by default: unsigned or tampered
# binaries are rejected. The full P-256 verify runs interrupts-masked (the
# proven fix for the preemption-corruption that used to #UD mid-verify) and
# works end to end; the embedded userspace binaries are signed with the pinned
# trusted key, so a normal build still boots and execs them. The masked verify
# is milliseconds on real hardware but minutes under TCG/QEMU. For fast local
# dev that accepts running UNSIGNED binaries, downgrade to warn-and-load with:
#   make EXTRA_CFLAGS=-DELF_PERMISSIVE_SIGNATURES
LDFLAGS := -T src/linker.ld -ffreestanding -nostdlib -Wl,--build-id=none

SRC := \
  src/kernel.c \
  src/vga.c \
  src/multiboot.c \
  src/util.c \
  src/idt.c \
  src/interrupts.c \
  src/serial.c \
  src/pic.c \
  src/pit.c \
  src/time.c \
  src/kprintf.c \
  src/critical.c \
  src/mutex.c \
  src/pmm.c \
  src/paging.c \
  src/stack_guard.c \
  src/entropy.c \
  src/aslr.c \
  src/pae.c \
  src/net.c \
  src/pci.c \
  src/e1000.c \
  src/ide.c \
  src/fat32.c \
  src/dns.c \
  src/icmp.c \
  src/dhcp.c \
  src/tcp.c \
  src/http_test.c \
  src/tcp_tests.c \
  src/gdt.c \
  src/tss.c \
  src/syscall.c \
  src/copy_user.c \
  src/idt_usermode.c \
  src/usermode_test.c \
  src/process.c \
  src/scheduler.c \
  src/wait_queue.c \
  src/vfs.c \
  src/user.c \
  src/sha512.c \
  src/sha256.c \
  src/crypto.c \
  src/ecdsa.c \
  src/aes_gcm.c \
  src/ecdhe.c \
  src/hkdf.c \
  src/firewall.c \
  src/ids.c \
  src/audit.c \
  src/secure_boot.c \
  src/edr_behavioral.c \
  src/edr_advanced.c \
  src/edr_threat_intel.c \
  src/edr_response.c \
  src/edr_daemon.c \
  src/test_tasks.c \
  src/security_tests.c \
  src/keyboard.c \
  src/elf.c \
  src/hello_elf_data.c \
  src/shell_elf_data.c \
  src/ramfs.c \
  src/ramfs_vfs.c \
  src/fat32_vfs.c \
  src/shell.c \
  src/shell_fileops.c \
  src/shell_search.c \
  src/shell_monitor.c \
  src/shell_history.c \
  src/shell_network.c \
  src/shell_system.c \
  src/shell_user.c \
  src/editor.c \
  src/env.c \
  src/shell_redir.c \
  src/stdio.c

OBJ := $(SRC:.c=.o) src/boot.o src/isr.o src/gdt_asm.o src/syscall_asm.o src/context_switch.o

# ---------------------------------------------------------------------------
# Default target: build ISO safely to dist/ (not inside iso/ tree)
# ---------------------------------------------------------------------------

all: dist/tinyos.iso

# Assembly objects
# Pass KERNEL_BOOT_STACK_SIZE constant to NASM for maintainability
src/boot.o: src/boot.s src/kernel.h
	$(AS) -f elf32 -DKERNEL_BOOT_STACK_SIZE=262144 $< -o $@

src/isr.o: src/isr.S
	$(AS) -f elf32 $< -o $@

src/gdt_asm.o: src/gdt.S
	$(AS) -f elf32 $< -o $@

src/syscall_asm.o: src/syscall.S
	$(AS) -f elf32 $< -o $@

src/context_switch.o: src/context_switch.S
	$(AS) -f elf32 $< -o $@

# C objects
#
# -MMD -MP emits a .d file per object listing every header the TU includes,
# so editing ANY header (e.g. process.h) recompiles exactly the objects that
# depend on it. Without this, only src/kernel.h was tracked, so a struct
# change in another header left stale objects with a mismatched layout linked
# into the kernel — a silent ABI mismatch that caused wild memory writes.
%.o: %.c src/kernel.h
	$(CC) $(CFLAGS) -MMD -MP -Isrc -c $< -o $@

# NOTE: SSH (src/ssh.c, src/ssh_crypto.c) and its RSA dependency (src/rsa.c)
# were removed from the build. The source is retained on disk (gitignored) but
# is no longer compiled or linked. See .gitignore.
#
# Password hashing code (PBKDF2) has deep call stacks that cause stack overflow with stack protection
# Disable stack protection entirely for this file, use -O1 for better codegen
src/user.o: src/user.c src/kernel.h
	$(CC) $(filter-out -O2 -fstack-protector-strong,$(CFLAGS)) -O1 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -MMD -MP -Isrc -c $< -o $@

# Shell user functions call password hashing, disable stack protection
src/shell_user.o: src/shell_user.c src/kernel.h
	$(CC) $(filter-out -O2 -fstack-protector-strong,$(CFLAGS)) -O1 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -MMD -MP -Isrc -c $< -o $@

# Shell task calls shell_user functions, disable stack protection
src/shell.o: src/shell.c src/kernel.h
	$(CC) $(filter-out -O2 -fstack-protector-strong,$(CFLAGS)) -O1 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -MMD -MP -Isrc -c $< -o $@

# Link kernel ELF via gcc driver so libgcc is available if needed
kernel.elf: $(OBJ)
	$(LD) $(LDFLAGS) -o $@ $(OBJ) -lgcc

# Pull in auto-generated header dependencies (-MMD). Safe if absent.
-include $(OBJ:.o=.d)

# Ensure required directories exist
iso/boot/grub:
	mkdir -p iso/boot/grub

dist:
	mkdir -p dist

# Guard that grub.cfg exists (kept in repo). Fail early if missing.
iso/boot/grub/grub.cfg: | iso/boot/grub
	@test -f $@ || (echo "Missing $@. Please create iso/boot/grub/grub.cfg"; exit 1)

# Build ISO OUTSIDE the iso/ tree to avoid xorriso self-inclusion
dist/tinyos.iso: kernel.elf iso/boot/grub/grub.cfg | dist
	@test -n "$(GRUBMKRESCUE)" || (echo "Missing grub-mkrescue; install grub-mkrescue or set GRUBMKRESCUE=/path/to/grub-mkrescue"; exit 1)
	cp kernel.elf iso/boot/kernel.elf
	$(GRUBMKRESCUE) -o $@ iso

# ---------------------------------------------------------------------------
# Run Targets - All use BRIDGED networking (vmnet-bridged)
# ---------------------------------------------------------------------------

# Default run target with bridged networking and FAT32 disk
run: dist/tinyos.iso
	sudo qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso \
		-boot d \
		-m 256M \
		-drive file=disk.img,format=raw,if=ide \
		-netdev vmnet-bridged,id=net0,ifname=en0 \
		-device e1000,netdev=net0,mac=52:54:00:12:34:56 \
		-serial file:serial.log

# Run with serial output (bridged) and FAT32 disk
run-serial: dist/tinyos.iso
	sudo qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso \
		-boot d \
		-m 256M \
		-drive file=disk.img,format=raw,if=ide \
		-netdev vmnet-bridged,id=net0,ifname=en0 \
		-device e1000,netdev=net0,mac=52:54:00:12:34:56 \
		-serial stdio

# Run with debugging (bridged)
run-debug: dist/tinyos.iso
	sudo qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso \
		-boot d \
		-m 256M \
		-drive file=disk.img,format=raw,if=ide \
		-netdev vmnet-bridged,id=net0,ifname=en0 \
		-device e1000,netdev=net0,mac=52:54:00:12:34:56 \
		-d int,cpu_reset -D qemu.log -no-reboot -serial file:serial.log

# Simple GUI run (no sudo, no networking - for keyboard testing, with FAT32 disk)
run-gui: dist/tinyos.iso
	@echo "Starting TinyOS in GUI mode with FAT32 disk..."
	@echo "Press Ctrl+Alt+G to release mouse"
	@echo "Shell commands: help, mount, fatls"
	@echo ""
	qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso \
		-boot d \
		-drive file=disk.img,format=raw,if=ide \
		-no-reboot -serial file:serial.log \
		-m 256M

# GUI run with user-mode networking (no sudo required)
run-gui-net: dist/tinyos.iso
	@echo "Starting TinyOS in GUI mode with networking..."
	@echo "Press Ctrl+Alt+G to release mouse"
	@echo "Network: User-mode (SLIRP) - TinyOS will use DHCP to configure"
	@echo ""
	qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso \
		-boot d \
		-m 256M \
		-drive file=disk.img,format=raw,if=ide \
		-netdev user,id=net0 \
		-device e1000,netdev=net0,mac=52:54:00:12:34:56

# GUI run that ALSO captures serial to panic.log AND freezes on fault
# (-no-reboot) with CPU-reset/interrupt tracing to qemu.log, so a triple fault
# leaves its register dump instead of rebooting. Reproduce a crash in the
# window (e.g. `exec /hello.elf`), then close it and inspect panic.log/qemu.log.
run-gui-panic: dist/tinyos.iso
	@rm -f panic.log qemu.log
	@echo "GUI + serial capture -> panic.log (qemu.log = int/cpu_reset trace)."
	@echo "Reproduce the crash in the window, then close it."
	@echo "Press Ctrl+Alt+G to release mouse."
	qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso \
		-boot d \
		-m 256M \
		-drive file=disk.img,format=raw,if=ide \
		-netdev user,id=net0 \
		-device e1000,netdev=net0,mac=52:54:00:12:34:56 \
		-serial file:panic.log \
		-no-reboot -d int,cpu_reset -D qemu.log

# ---------------------------------------------------------------------------
# Network Debugging Targets - All use BRIDGED networking
# ---------------------------------------------------------------------------

# Run QEMU with bridged networking and pcap capture (for Wireshark)
run-debug-pcap: dist/tinyos.iso
	sudo qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso \
		-boot d \
		-m 256M \
		-drive file=disk.img,format=raw,if=ide \
		-netdev vmnet-bridged,id=net0,ifname=en0 \
		-device e1000,netdev=net0,mac=52:54:00:12:34:56 \
		-object filter-dump,id=f1,netdev=net0,file=network.pcap \
		-serial file:serial.log -d int,cpu_reset -D qemu.log
	@echo "Network capture saved to network.pcap"
	@echo "Open with: wireshark network.pcap"

# Run with verbose network tracing (bridged)
run-debug-trace: dist/tinyos.iso
	sudo qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso \
		-boot d \
		-m 256M \
		-drive file=disk.img,format=raw,if=ide \
		-netdev vmnet-bridged,id=net0,ifname=en0 \
		-device e1000,netdev=net0,mac=52:54:00:12:34:56 \
		-trace enable="e1000*" \
		-serial file:serial.log -d int,cpu_reset -D qemu.log 2>&1 | tee network_trace.txt

# Run with pcap and open Wireshark automatically (bridged)
run-wireshark: dist/tinyos.iso
	@echo "Starting QEMU with packet capture (bridged networking)..."
	@rm -f network.pcap
	sudo qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso \
		-boot d \
		-m 256M \
		-drive file=disk.img,format=raw,if=ide \
		-netdev vmnet-bridged,id=net0,ifname=en0 \
		-device e1000,netdev=net0,mac=52:54:00:12:34:56 \
		-object filter-dump,id=f1,netdev=net0,file=network.pcap \
		-serial file:serial.log &
	@sleep 2
	@echo "Opening Wireshark..."
	@if command -v wireshark > /dev/null; then \
		wireshark network.pcap & \
	else \
		echo "Wireshark not found. Install with: brew install wireshark"; \
	fi

# Run with DNS debugging (bridged)
run-debug-dns: dist/tinyos.iso
	@echo "Running with DNS-focused debugging (bridged)..."
	sudo qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso \
		-boot d \
		-m 256M \
		-drive file=disk.img,format=raw,if=ide \
		-netdev vmnet-bridged,id=net0,ifname=en0 \
		-device e1000,netdev=net0,mac=52:54:00:12:34:56 \
		-object filter-dump,id=f1,netdev=net0,file=dns_debug.pcap \
		-serial file:serial.log
	@echo "DNS packets saved to dns_debug.pcap"

# Quick test with bridged networking
run-test-ping: dist/tinyos.iso
	@echo "Testing with bridged networking (ping should work from host)..."
	sudo qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom dist/tinyos.iso \
		-boot d \
		-m 256M \
		-drive file=disk.img,format=raw,if=ide \
		-netdev vmnet-bridged,id=net0,ifname=en0 \
		-device e1000,netdev=net0,mac=52:54:00:12:34:56 \
		-serial file:serial.log \
		-no-reboot
	@echo "Check serial.log for results"

# ---------------------------------------------------------------------------
# Cleanup Targets
# ---------------------------------------------------------------------------

# Cleanup - remove object files and kernel binary
clean:
	rm -f $(OBJ) $(OBJ:.o=.d) kernel.elf

# Deep cleanup - also remove ISO staging and final ISO
distclean: clean
	rm -f iso/boot/kernel.elf
	rm -f dist/tinyos.iso

# Complete cleanup - remove all generated files and directories
mrproper: distclean
	rm -rf dist

# Clean network debug files
clean-net-debug:
	rm -f network.pcap network_trace.txt serial.log qemu.log

# Clean all non-source generated files
clean-all:
	rm -f $(OBJ) kernel.elf iso/boot/kernel.elf dist/tinyos.iso network.pcap network_trace.txt serial.log qemu.log

# ---------------------------------------------------------------------------
# Status and Info Targets
# ---------------------------------------------------------------------------

# Show what files exist (useful for debugging Makefile)
status:
	@echo "=== Build Artifacts ==="
	@ls -lh kernel.elf 2>/dev/null || echo "  kernel.elf: not built"
	@ls -lh iso/boot/kernel.elf 2>/dev/null || echo "  iso/boot/kernel.elf: not built"
	@ls -lh dist/tinyos.iso 2>/dev/null || echo "  dist/tinyos.iso: not built"
	@echo ""
	@echo "=== Object Files ==="
	@ls -lh $(OBJ) 2>/dev/null || echo "  No object files"

# Show current network configuration
show-net-config:
	@echo "=== BRIDGED Network Configuration ==="
	@echo "Mode:          vmnet-bridged (real LAN access)"
	@echo "Interface:     en0 (configure with ifname=)"
	@echo "Guest MAC:     52:54:00:12:34:56"
	@echo ""
	@echo "IP Configuration:"
	@echo "  - Obtained via DHCP from your router"
	@echo "  - Gateway:     192.168.0.1 (your router)"
	@echo "  - Can ping:    Any device on your LAN"
	@echo "  - Can be pinged: From any device on your LAN"
	@echo ""
	@echo "Requirements:"
	@echo "  - Must run with 'sudo' (needs root for vmnet)"
	@echo "  - Router must have DHCP enabled"
	@echo "  - Real network access (not NAT)"

.PHONY: all run run-serial run-debug run-gui run-gui-net run-gui-panic run-debug-pcap run-debug-trace run-wireshark \
        run-debug-dns run-test-ping clean distclean mrproper clean-net-debug \
        status show-net-config
