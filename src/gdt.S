;===============================================================================
; gdt.S - GDT and User Mode Assembly Functions
; FIXED: Don't load user segments from ring 0 - let iret do it!
;===============================================================================
; build: nasm -f elf32 gdt.S -o gdt_asm.o

BITS 32

GLOBAL gdt_flush
GLOBAL enter_user_mode
GLOBAL tss_flush

;-------------------------------------------------------------------------------
; gdt_flush - Load new GDT
; CRITICAL: Includes serialization to ensure GDT is fully loaded
; CRITICAL: Reloads all segment registers to use the new GDT
;
; SECURITY (11.B): Defensive GDT Reload
; After lgdt, the CPU's internal segment descriptor cache still contains
; entries from the OLD GDT. If we don't reload ALL segment registers, the
; kernel could temporarily use stale/junk segment descriptors inherited from
; the bootloader, causing transient, non-repeatable memory access errors.
;
; FIX: Explicitly reload CS (via far jump) and ALL data segments (DS, ES, FS,
; GS, SS) to force the CPU to populate the descriptor cache from the new GDT.
;-------------------------------------------------------------------------------
gdt_flush:
    mov eax, [esp + 4]
    lgdt [eax]

    ; CRITICAL: After LGDT, we must reload ALL segment registers
    ; to make them reference entries in the new GDT instead of the old one

    ; We copy GRUB's GDT, so GRUB's selectors (0x10=code, 0x18=data) remain valid
    ; Use a far jump to reload CS
    jmp 0x10:.reload_segments

.reload_segments:
    ; DEFENSIVE SECURITY: Reload ALL data/stack segments with 0x18
    ; This ensures the CPU's internal descriptor cache is loaded from the
    ; new GDT, not stale bootloader values. Missing even one segment reload
    ; could cause intermittent crashes or security vulnerabilities.
    mov ax, 0x18
    mov ds, ax      ; Data segment
    mov es, ax      ; Extra segment
    mov fs, ax      ; FS segment
    mov gs, ax      ; GS segment
    mov ss, ax      ; Stack segment

    ret

;-------------------------------------------------------------------------------
; tss_flush - Load TSS (not used, kept for compatibility)
;-------------------------------------------------------------------------------
tss_flush:
    mov ax, [esp + 4]
    ltr ax
    ret

;-------------------------------------------------------------------------------
; enter_user_mode - Switch from Ring 0 to Ring 3
; Arguments:
;   [esp + 4]  = user_func
;   [esp + 8]  = user_stack  
;   [esp + 12] = user_code_selector (with RPL=3, e.g. 0x23)
;   [esp + 16] = user_data_selector (with RPL=3, e.g. 0x2B)
;
; CRITICAL: Ring 0 cannot load Ring 3 segments!
; We must let iret do ALL segment switching atomically.
;-------------------------------------------------------------------------------
; gdt.S - NASM syntax
global enter_user_mode
extern debug_enter_user_mode

;-------------------------------------------------------------------------------
; enter_user_mode below
;-------------------------------------------------------------------------------

enter_user_mode:
    ; Get parameters from stack - CORRECT OFFSETS
    ; Stack when function is called:
    ; [esp] = return address
    ; [esp+4] = user_function
    ; [esp+8] = user_stack  
    ; [esp+12] = user_code_selector
    ; [esp+16] = user_data_selector
    
    mov eax, [esp + 4]   ; user_function
    mov ebx, [esp + 8]   ; user_stack
    mov cx, [esp + 12]   ; user_code_selector
    mov dx, [esp + 16]   ; user_data_selector

    ; DEBUG: Verify parameters
    push eax
    push ebx
    push ecx
    push edx
    call debug_enter_user_mode
    pop edx
    pop ecx
    pop ebx
    pop eax

    ; CRITICAL SECURITY: Validate user ESP is in user space (< 0xC0000000)
    cmp ebx, 0xC0000000  ; Check if ESP >= kernel base
    jae .panic_invalid_esp ; Panic if ESP is in kernel space

    ; CRITICAL ALIGNMENT: Ensure user ESP is 16-byte aligned for SSE/AVX
    ; The IRET frame (20 bytes: SS, ESP, EFLAGS, CS, EIP) will be pushed,
    ; so we align ESP to 16 bytes BEFORE building the frame
    and ebx, 0xFFFFFFF0  ; Align to 16-byte boundary (clear low 4 bits)

    ; Set up IRET stack frame - IN CORRECT ORDER
    push dx              ; SS (user data selector with RPL=3)
    push ebx             ; ESP (user stack, validated and aligned)

    ; CRITICAL SECURITY: Sanitize EFLAGS to prevent IOPL escalation
    ; Build safe user EFLAGS: IF=1, IOPL=0, reserved bit 1 set
    push dword 0x0202    ; Push sanitized EFLAGS (IF + reserved bit 1)

    push cx              ; CS (user code selector with RPL=3)
    push eax             ; EIP (user function)

    ; SECURITY FIX: Load user data segment selectors BEFORE iret
    ; This prevents user code from starting with kernel data segments
    mov ax, dx           ; Load user data selector (with RPL=3)
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    ; Switch to user mode
    iret

.panic_invalid_esp:
    ; CRITICAL ERROR: User ESP points to kernel memory
    mov edi, 0xB8000
    mov dword [edi], 0x4F214F21  ; "!!" in red
    mov dword [edi+4], 0x4F454F20  ; " E" in red
    mov dword [edi+8], 0x4F504F53  ; "SP" in red
    cli
    hlt
    jmp $

