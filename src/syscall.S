;===============================================================================
; syscall.S - System Call Interrupt Handler (INT 0x80)
;===============================================================================

[BITS 32]

;-------------------------------------------------------------------------------
; External C function
;-------------------------------------------------------------------------------
extern syscall_handler_c    ; C handler: void syscall_handler_c(struct cpu_state*)

;-------------------------------------------------------------------------------
; System Call Handler Stub (INT 0x80)
; This is similar to ISR stubs but preserves all registers for system calls
;-------------------------------------------------------------------------------
global syscall_stub
syscall_stub:
    ; Save all segment registers first
    push ds
    push es
    push fs
    push gs

    ; CRITICAL FIX: Explicitly save general-purpose registers (NOT using pusha)
    ; pusha/popa is UNSAFE because:
    ; 1. pusha saves ESP *before* any stack modifications
    ; 2. popa blindly restores that stale ESP value
    ; 3. This corrupts the kernel stack after the C handler modifies it
    ;
    ; Stack layout after these pushes (matching struct cpu_state):
    ; [EDI][ESI][EBP][ESP][EBX][EDX][ECX][EAX] <- ESP points here
    push eax                ; Save EAX
    push ecx                ; Save ECX
    push edx                ; Save EDX
    push ebx                ; Save EBX

    ; Calculate ESP value from BEFORE we started pushing GPRs (for struct compatibility)
    ; Current ESP has been decreased by 4 registers * 4 bytes = 16 bytes
    mov eax, esp            ; Get current ESP
    add eax, 16             ; Add back the 4 registers we've pushed
    push eax                ; Push calculated ESP value

    ; Restore EAX for subsequent pushes (get original value from stack)
    mov eax, [esp + 16]     ; Original EAX is now 16 bytes above current ESP

    push ebp                ; Save EBP
    push esi                ; Save ESI
    push edi                ; Save EDI

    ;===========================================================================
    ; SECURITY FIX: Explicitly reload segment registers to kernel data segment
    ;
    ; CRITICAL: User processes could set DS/ES/FS/GS to malicious values
    ; (e.g., NULL selector 0x00, or invalid selectors). If the kernel C code
    ; accesses memory using these segments, it will trigger #GP and crash.
    ;
    ; We MUST explicitly reload all data segments to the canonical kernel
    ; data segment selector (SEG_KDATA = 0x18) before calling any C code.
    ;
    ; The CPU automatically sets CS and SS during privilege escalation,
    ; but DS/ES/FS/GS are preserved from user mode!
    ;
    ; NOTE: SEG_KCODE=0x10 (code), SEG_KDATA=0x18 (data) from gdt.h
    ;
    ; SECURITY NOTE on segment restore (lines 92-95):
    ; We restore the user's FS/GS values on return. This is safe because:
    ; 1. Segment register validation happens at load time by the CPU
    ; 2. User code can only load valid user-mode selectors (RPL=3)
    ; 3. If user loads invalid selector, #GP occurs in user mode, not kernel
    ; 4. TinyOS doesn't use FS/GS for kernel data, so restoration is harmless
    ;
    ; Alternative approach (if TLS is never used):
    ;   On restore: Zero out FS/GS instead of restoring user values
    ;   This prevents any potential TLS-based attacks
    ;   However, breaks user programs that rely on TLS (e.g., pthread)
    ;===========================================================================
    mov ax, 0x18            ; AX = kernel data segment selector (SEG_KDATA)
    mov ds, ax              ; Load kernel DS
    mov es, ax              ; Load kernel ES
    mov fs, ax              ; Load kernel FS
    mov gs, ax              ; Load kernel GS

    ; Push pointer to register state (for C function)
    push esp                ; ESP points to the saved register state

    ; Call C handler
    call syscall_handler_c

    ; Remove parameter from stack
    add esp, 4

    ; CRITICAL FIX: Explicitly restore registers (NOT using popa)
    ; We restore all registers EXCEPT ESP (which was modified by the C handler)
    pop edi                 ; Restore EDI
    pop esi                 ; Restore ESI
    pop ebp                 ; Restore EBP
    add esp, 4              ; Skip the saved ESP value (don't restore stale ESP!)
    pop ebx                 ; Restore EBX
    pop edx                 ; Restore EDX
    pop ecx                 ; Restore ECX
    pop eax                 ; Restore EAX (includes syscall return value)

    ; Restore segment registers
    pop gs
    pop fs
    pop es
    pop ds

    ;===========================================================================
    ; SECURITY FIX: EFLAGS Sanitization (Privilege Escalation Prevention)
    ; CRITICAL: User mode could manipulate saved EFLAGS to gain privileges
    ;
    ; IRET restores EFLAGS from stack. A malicious user could set:
    ; - IOPL (bits 12-13): I/O privilege level (allows direct hardware access)
    ; - VM (bit 17): Virtual 8086 mode (breaks protected mode isolation)
    ; - NT (bit 14): Nested task flag (breaks task switching)
    ; - RF (bit 16): Resume flag (bypasses debug breakpoints)
    ;
    ; We must mask out these privileged bits before IRET to prevent
    ; privilege escalation attacks.
    ;
    ; Safe EFLAGS mask: 0xFFFC0FFF
    ; - Preserves: CF, PF, AF, ZF, SF, TF, DF, OF (arithmetic/control flags)
    ; - Clears: IOPL (12-13), NT (14), RF (16), VM (17)
    ; - Preserves: IF (9) - interrupt flag (controlled by kernel)
    ; - Preserves: AC (18), VIF (19), VIP (20), ID (21) - safe user flags
    ;
    ; Stack layout before IRET:
    ; [SS][ESP][EFLAGS][CS][EIP] <- ESP points here
    ;
    ; We need to access EFLAGS which is at ESP+8 (skip EIP and CS)
    ;===========================================================================
    push eax                ; Save EAX temporarily
    mov eax, [esp + 12]     ; Load saved EFLAGS (ESP+4 for pushed EAX, +8 for EIP/CS)
    and eax, 0xFFFC0FFF     ; Clear IOPL, NT, RF, VM bits
    mov [esp + 12], eax     ; Write sanitized EFLAGS back to stack
    pop eax                 ; Restore EAX

    ; Return from interrupt (with sanitized EFLAGS)
    iret
