;===============================================================================
; isr.S â€” Interrupt Service Routine Stubs for TinyOS
;===============================================================================

[BITS 32]                       ; Generate 32-bit code

;-------------------------------------------------------------------------------
; External References
;-------------------------------------------------------------------------------
extern isr_common_handler       ; C function: void isr_common_handler(interrupt_regs_t* regs)


;===============================================================================
; MACRO DEFINITIONS
;===============================================================================
; We use macros to generate similar code for many interrupt vectors.
; This avoids writing the same code 48 times manually.
;===============================================================================

;-------------------------------------------------------------------------------
; ISR_NOERR: Generate stub for exceptions WITHOUT error code
;-------------------------------------------------------------------------------
%macro ISR_NOERR 1
global isr%1                    ; Export isr%1 symbol for IDT
isr%1:
    cli                         ; Disable interrupts (safety, IF already clear)
    push dword 0                ; Push dummy error code (4 bytes)
    push dword %1               ; Push vector number (4 bytes)
    jmp isr_common              ; Jump to common handler code
%endmacro

;-------------------------------------------------------------------------------
; ISR_ERR: Generate stub for exceptions WITH error code
;-------------------------------------------------------------------------------
%macro ISR_ERR 1
global isr%1                    ; Export isr%1 symbol for IDT
isr%1:
    cli                         ; Disable interrupts
    push dword %1               ; Push vector number (4 bytes)
    jmp isr_common              ; Jump to common handler code
%endmacro

;-------------------------------------------------------------------------------
; IRQ: Generate stub for hardware interrupts
;-------------------------------------------------------------------------------
%macro IRQ 1
global irq%1                    ; Export irq%1 symbol for IDT
irq%1:
    cli                         ; Disable interrupts
    push dword 0                ; Push dummy error code (4 bytes)
    push dword %1               ; Push vector number (4 bytes)
    jmp isr_common              ; Jump to common handler code
%endmacro


;===============================================================================
; COMMON INTERRUPT HANDLER
;===============================================================================
; This code is shared by all interrupt stubs (exceptions and IRQs).
; It saves all registers, calls the C handler, restores registers, and returns.
;===============================================================================

;-------------------------------------------------------------------------------
; isr_common: Common Interrupt Handler Entry Point
;-------------------------------------------------------------------------------
; Stack layout when we enter here:
;   ESP+0:  (will be filled by pusha)
;   After CPU and stub:
;     - EIP, CS, EFLAGS [, ESP, SS if privilege change]
;     - error_code (pushed by stub)
;     - vector (pushed by stub)
;-------------------------------------------------------------------------------
isr_common:
    ;===========================================================================
    ; SECURITY FIX: Sanitize segment registers on kernel entry
    ; When an interrupt occurs from ring 3, CS/SS are switched by the CPU,
    ; but DS/ES/FS/GS are NOT automatically changed. A malicious userland
    ; process can set these to:
    ; - Null selector (0x0) -> triggers #GP on first C code access
    ; - Invalid descriptor -> triggers #GP cascade -> double fault
    ; - User segment with unexpected base/limit -> breaks kernel assumptions
    ;
    ; This is exactly what syscall.S already does. Without this, any interrupt
    ; from ring 3 with corrupted segments will crash the kernel when C code
    ; dereferences pointers assuming flat DS.
    ;
    ; We also clear DF to ensure C code memcpy/string ops work correctly.
    ;===========================================================================

    push ds                     ; Save user DS
    push es                     ; Save user ES
    push fs                     ; Save user FS
    push gs                     ; Save user GS

    mov ax, 0x18                ; 0x18 = kernel data selector (GDT entry 3)
    mov ds, ax                  ; Load kernel DS
    mov es, ax                  ; Load kernel ES
    mov fs, ax                  ; Load kernel FS
    mov gs, ax                  ; Load kernel GS

    cld                         ; Clear direction flag (DF=0)
                                ; GCC assumes DF=0 for string operations
                                ; Userland could have set DF=1 via STD instruction

    pusha                       ; Push all general-purpose registers (32 bytes)
                                ; ESP decremented by 32
                                ; Stack layout after pusha:
                                ; ESP+0:  EDI, ESI, EBP, ESP(old), EBX, EDX, ECX, EAX (32 bytes)
                                ; ESP+32: GS, FS, ES, DS (16 bytes)
                                ; ESP+48: vector number (4 bytes)
                                ; ESP+52: error code (4 bytes)
                                ; ESP+56: EIP, CS, EFLAGS, [ESP, SS if privilege change]

    ;===========================================================================
    ; PREEMPTIVE SCHEDULING WITH IRETD
    ; Pass pointer to entire register structure so scheduler can modify it
    ; When we return with iret, the (possibly modified) state is restored
    ;===========================================================================

    mov eax, esp                ; EAX = pointer to interrupt_regs_t structure
    push eax                    ; Push pointer as parameter

    call isr_common_handler     ; Call void isr_common_handler(interrupt_regs_t* regs)
                                ; Scheduler may modify regs to switch to next task!

    add esp, 4                  ; Remove parameter from stack
                                ; ESP now back to where it was after PUSHA

    popa                        ; Pop all general-purpose registers (32 bytes)
                                ; Registers now restored (possibly from DIFFERENT task!)

    pop gs                      ; Restore user GS
    pop fs                      ; Restore user FS
    pop es                      ; Restore user ES
    pop ds                      ; Restore user DS

    add esp, 8                  ; Remove vector and error code (8 bytes)
                                ; Stack now has only EIP, CS, EFLAGS [, ESP, SS]

    ;===========================================================================
    ; SECURITY FIX: EFLAGS Sanitization (Privilege Escalation Prevention)
    ; CRITICAL: Prevent user mode from manipulating EFLAGS to gain privileges
    ;
    ; When returning to user mode, malicious code could have modified the
    ; saved EFLAGS value on the stack to set:
    ; - IOPL (bits 12-13): I/O privilege level (allows direct hardware access)
    ; - VM (bit 17): Virtual 8086 mode (breaks protected mode isolation)
    ; - NT (bit 14): Nested task flag (breaks task switching)
    ; - RF (bit 16): Resume flag (bypasses debug breakpoints)
    ;
    ; We must sanitize EFLAGS before IRET to prevent privilege escalation.
    ;
    ; Safe EFLAGS mask: 0xFFFC0FFF
    ; - Preserves: CF, PF, AF, ZF, SF, TF, DF, OF (arithmetic/control flags)
    ; - Clears: IOPL (12-13), NT (14), RF (16), VM (17)
    ; - Preserves: IF (9) - interrupt flag (kernel controls this)
    ;
    ; Stack layout before IRET:
    ; [SS][ESP][EFLAGS][CS][EIP] <- ESP points here (if privilege change)
    ; [EFLAGS][CS][EIP]          <- ESP points here (if no privilege change)
    ;
    ; We sanitize EFLAGS at ESP+8 (assuming privilege change to user mode)
    ; If returning to kernel mode, this is harmless (kernel EFLAGS already safe)
    ;===========================================================================
    push eax                    ; Save EAX temporarily
    mov eax, [esp + 12]         ; Load saved EFLAGS (ESP+4 for pushed EAX, +8 for EIP/CS)
    and eax, 0xFFFC0FFF         ; Clear IOPL, NT, RF, VM bits
    mov [esp + 12], eax         ; Write sanitized EFLAGS back to stack
    pop eax                     ; Restore EAX

    iret                        ; Return from interrupt (with sanitized EFLAGS)
                                ; Pops EIP, CS, EFLAGS [, ESP, SS if privilege change]
                                ; Execution resumes in (possibly DIFFERENT) task!


;===============================================================================
; INTERRUPT VECTOR DEFINITIONS
;===============================================================================
; Generate all 48 interrupt stubs using our macros.
; Vectors 0-31: CPU exceptions
; Vectors 32-47: Hardware IRQs (after PIC remap)
;===============================================================================

;-------------------------------------------------------------------------------
; CPU Exception Handlers (Vectors 0-31)
;-------------------------------------------------------------------------------

;--- Exceptions Without Error Codes ---
ISR_NOERR 0                     ; #DE: Divide Error (divide by zero)
ISR_NOERR 1                     ; #DB: Debug Exception
ISR_NOERR 2                     ; NMI: Non-Maskable Interrupt
ISR_NOERR 3                     ; #BP: Breakpoint (INT 3)
ISR_NOERR 4                     ; #OF: Overflow (INTO instruction)
ISR_NOERR 5                     ; #BR: BOUND Range Exceeded
ISR_NOERR 6                     ; #UD: Invalid Opcode
ISR_NOERR 7                     ; #NM: Device Not Available (no FPU)

;--- Exceptions With Error Codes ---
ISR_ERR   8                     ; #DF: Double Fault
                                ; Error code: always 0
                                ; NOTE: Double Fault uses standard handler for now
                                ; Dedicated stack implementation caused boot issues

ISR_NOERR 9                     ; Coprocessor Segment Overrun (legacy)

ISR_ERR   10                    ; #TS: Invalid TSS
                                ; Error code: segment selector

ISR_ERR   11                    ; #NP: Segment Not Present
                                ; Error code: segment selector

ISR_ERR   12                    ; #SS: Stack-Segment Fault
                                ; Error code: segment selector or 0

ISR_ERR   13                    ; #GP: General Protection Fault
                                ; Error code: segment selector or 0

ISR_ERR   14                    ; #PF: Page Fault
                                ; Error code: error flags (P, W/R, U/S, RSVD, I/D)
                                ; CR2 register holds faulting address

ISR_NOERR 15                    ; Intel Reserved

ISR_NOERR 16                    ; #MF: x87 FPU Floating-Point Error

ISR_ERR   17                    ; #AC: Alignment Check
                                ; Error code: always 0

ISR_NOERR 18                    ; #MC: Machine Check
ISR_NOERR 19                    ; #XF/#XM: SIMD Floating-Point Exception
ISR_NOERR 20                    ; #VE: Virtualization Exception
ISR_NOERR 21                    ; #CP: Control Protection Exception

;--- Reserved by Intel ---
ISR_NOERR 22                    ; Intel Reserved
ISR_NOERR 23                    ; Intel Reserved
ISR_NOERR 24                    ; Intel Reserved
ISR_NOERR 25                    ; Intel Reserved
ISR_NOERR 26                    ; Intel Reserved
ISR_NOERR 27                    ; Intel Reserved
ISR_NOERR 28                    ; Intel Reserved
ISR_NOERR 29                    ; Intel Reserved
ISR_NOERR 30                    ; Intel Reserved
ISR_NOERR 31                    ; Intel Reserved

;-------------------------------------------------------------------------------
; Hardware IRQ Handlers (Vectors 32-47)
;-------------------------------------------------------------------------------
IRQ 32                          ; IRQ 0:  PIT Timer (Programmable Interval Timer)
IRQ 33                          ; IRQ 1:  Keyboard
IRQ 34                          ; IRQ 2:  PIC Cascade (internal, never fires)
IRQ 35                          ; IRQ 3:  COM2 Serial Port
IRQ 36                          ; IRQ 4:  COM1 Serial Port
IRQ 37                          ; IRQ 5:  LPT2 Parallel Port
IRQ 38                          ; IRQ 6:  Floppy Disk Controller
IRQ 39                          ; IRQ 7:  LPT1 Parallel Port (can be spurious)
IRQ 40                          ; IRQ 8:  RTC (Real-Time Clock)
IRQ 41                          ; IRQ 9:  ACPI, Available
IRQ 42                          ; IRQ 10: Available
IRQ 43                          ; IRQ 11: Available
IRQ 44                          ; IRQ 12: PS/2 Mouse
IRQ 45                          ; IRQ 13: FPU Exception (Coprocessor)
IRQ 46                          ; IRQ 14: Primary ATA Hard Disk
IRQ 47                          ; IRQ 15: Secondary ATA Hard Disk

