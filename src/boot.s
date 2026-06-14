;===============================================================================
; boot.s â€” Multiboot2 header and 32-bit entry
;===============================================================================
; build: nasm -f elf32 boot.s -o boot.o


BITS 32
GLOBAL _start
GLOBAL stack_bottom
GLOBAL stack_top
EXTERN kernel_main


SECTION .multiboot2
align 8
MB2_MAGIC equ 0xE85250D6
MB2_ARCH equ 0 ; 0 = i386
MB2_LEN equ mb2_end - mb2_header
MB2_CSUM equ -(MB2_MAGIC + MB2_ARCH + MB2_LEN)


mb2_header:
dd MB2_MAGIC
dd MB2_ARCH
dd MB2_LEN
dd MB2_CSUM


; required end tag
dw 0 ; type
dw 0 ; flags
dd 8 ; size
mb2_end:


SECTION .text
_start:
; CRITICAL: Disable interrupts IMMEDIATELY to prevent race conditions
; during kernel initialization (IDT, GDT, PIC setup)
cli

; Multiboot2: EAX=magic (0x36D76289), EBX=info ptr

; CRITICAL: Zero BSS manually (GRUB's BSS zeroing may be unreliable)
; Save multiboot parameters in registers not used by rep stosd
mov esi, eax  ; Save magic in ESI (won't be touched)
mov ebp, ebx  ; Save info_ptr in EBP (won't be touched)

; Zero BSS section (from __bss_start to __bss_end, NOT including stack!)
extern __bss_start
extern __bss_end
mov ecx, __bss_end
sub ecx, __bss_start
jbe .skip_bss  ; Skip if BSS is empty or invalid
shr ecx, 2     ; Convert bytes to dwords
xor eax, eax   ; Value to write (0)
mov edi, __bss_start  ; Destination
cld            ; Clear direction flag
rep stosd      ; Zero BSS

.skip_bss:
; Restore multiboot parameters
mov eax, esi   ; Restore magic
mov ebx, ebp   ; Restore info_ptr

; Set up kernel stack
mov esp, stack_top

; Push arguments for kernel_main (cdecl convention: right-to-left)
push ebx  ; info_ptr (2nd argument)
push eax  ; magic (1st argument)
call kernel_main

.hang:
cli
hlt
jmp .hang


SECTION .bss align=16
stack_bottom:
; CRITICAL: Stack size defined in kernel.h via Makefile -D flag
; This ensures synchronization between C code and assembly
%ifndef KERNEL_BOOT_STACK_SIZE
%error "KERNEL_BOOT_STACK_SIZE must be defined via -D flag in Makefile"
%endif
resb KERNEL_BOOT_STACK_SIZE    ; Defined via Makefile (default: 256 KiB)
stack_top:
