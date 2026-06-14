;===============================================================================
; context_switch.S - Low-level Context Switching for Multitasking
;===============================================================================

[BITS 32]

global context_switch
global switch_to_first_task

;-------------------------------------------------------------------------------
; FUNCTION: context_switch
; PURPOSE: Switch from current task to next task
;
; C Prototype:
;   void context_switch(task_t* current_task, task_t* next_task);
;
; Parameters:
;   [ESP+4] = current_task pointer (can be NULL if no current task)
;   [ESP+8] = next_task pointer (must not be NULL)
;
; Task Structure Layout (from process.h):
;   Offset 0:  pid (4 bytes)
;   Offset 4:  name[32] (32 bytes)
;   Offset 36: state (4 bytes)
;   Offset 40: PADDING (8 bytes for context alignment!)
;   Offset 48: context (cpu_context_t)
;
; CPU Context Layout (from process.h):
;   Offset 0:  edi
;   Offset 4:  esi
;   Offset 8:  ebp
;   Offset 12: esp
;   Offset 16: ebx
;   Offset 20: edx
;   Offset 24: ecx
;   Offset 28: eax
;   Offset 32: ds
;   Offset 36: es
;   Offset 40: fs
;   Offset 44: gs
;   Offset 48: eip
;   Offset 52: eflags
;   Offset 56: cs
;   Offset 60: ss
;   Offset 64: fpu_state[512] (512 bytes, 16-byte aligned)
;-------------------------------------------------------------------------------

context_switch:
    ; Save current flags
    pushf

    ;===========================================================================
    ; CRITICAL: The entire save/load sequence must run with interrupts
    ; disabled. The caller has already published next_task as
    ; current_running_task; if a timer IRQ fires while we are still saving
    ; into / loading from a task's context struct, the nested
    ; scheduler_schedule_from_interrupt() -> context_switch() OVERWRITES the
    ; very context fields we are mid-way through reading, and the task later
    ; resumes with corrupted registers. This was the residual cause of the
    ; "long computations (ECDSA verify) corrupt under preemption" bug.
    ; The interrupted task's IF state was captured by the pushf above and is
    ; restored by the popf at the end of the load path (or by iret).
    ;===========================================================================
    cli

    ; CRITICAL: Save registers that we'll use as temporaries onto the stack
    push ebx
    push edx
    push ecx
    push eax

    ; Get parameters from stack
    ; Stack is now: [eax][ecx][edx][ebx][eflags][retaddr][current][next]
    mov eax, [esp + 24]   ; EAX = current_task (offset increased by 4 pushes)
    mov ebx, [esp + 28]   ; EBX = next_task

    ; Check if current_task is NULL (first task switch)
    test eax, eax
    jz skip_save

    ;===========================================================================
    ; SAVE CURRENT TASK CONTEXT
    ;===========================================================================

    ; EAX points to current task_t, add 48 to get to context field (accounting for 8-byte padding)
    add eax, 48           ; EAX = &current_task->context

    ; Save general purpose registers
    mov [eax + 0], edi    ; Save EDI
    mov [eax + 4], esi    ; Save ESI
    mov [eax + 8], ebp    ; Save EBP

    ; Save ESP (stack pointer) - need to account for our stack usage
    ; Stack layout: ESP+0=EAX, ESP+4=ECX, ESP+8=EDX, ESP+12=EBX, ESP+16=EFLAGS, ESP+20=retaddr
    mov edx, esp
    add edx, 20           ; BUG FIX: Correct offset to return address (5 pushes * 4 bytes)
    mov [eax + 12], edx   ; Save adjusted ESP (points to return address)

    ; Get registers from our stack and save them
    mov ecx, [esp]        ; ESP+0 = saved EAX
    mov [eax + 28], ecx   ; Save EAX

    mov ecx, [esp + 4]    ; ESP+4 = saved ECX
    mov [eax + 24], ecx   ; Save ECX

    mov ecx, [esp + 8]    ; ESP+8 = saved EDX
    mov [eax + 20], ecx   ; Save EDX

    mov ecx, [esp + 12]   ; ESP+12 = saved EBX
    mov [eax + 16], ecx   ; Save EBX

    ; Save segment registers
    mov edx, ds
    mov [eax + 32], edx   ; Save DS
    mov edx, es
    mov [eax + 36], edx   ; Save ES
    mov edx, fs
    mov [eax + 40], edx   ; Save FS
    mov edx, gs
    mov [eax + 44], edx   ; Save GS

    ; Save return address as EIP
    ; Stack: [eax][ecx][edx][ebx][eflags][retaddr][current][next]
    mov edx, [esp + 20]   ; Get return address from stack
    mov [eax + 48], edx   ; Save as EIP

    ; Save EFLAGS (from saved flags on stack)
    mov edx, [esp + 16]   ; Get saved flags
    mov [eax + 52], edx   ; Save EFLAGS

    ; Save CS
    mov edx, cs
    mov [eax + 56], edx   ; Save CS

    ; Save SS
    mov edx, ss
    mov [eax + 60], edx   ; Save SS

    ;===========================================================================
    ; SECURITY FIX (Issue 5.3): Lazy FPU Switching - Don't save FPU state
    ;
    ; OLD: Eagerly save FPU state on every context switch (expensive!)
    ; NEW: FPU state remains in FPU registers, saved on-demand by #NM handler
    ;
    ; REMOVED: fxsave - will be done by exception handler only if needed
    ;===========================================================================
    ; REMOVED: lea edx, [eax + 64]
    ; REMOVED: fxsave [edx]

skip_save:
    ;===========================================================================
    ; LOAD NEXT TASK CONTEXT
    ;===========================================================================

    ; Clean up our temporary stack frame before switching
    ; Stack: [eax][ecx][edx][ebx][eflags][retaddr][current][next]
    add esp, 20           ; Remove all 5 items (4 registers + eflags) from stack
    ; Stack is now: [retaddr][current][next]

load_next_task:
    ; Get next_task pointer (it's now at ESP+8, not ESP+12)
    mov ebx, [esp + 8]    ; EBX = next_task pointer

    ;===========================================================================
    ; SWITCH PAGE DIRECTORY (CR3) IF NEEDED
    ;===========================================================================
    ; Page directory is at offset 624 in task_t structure:
    ; 0: pid(4), 4: name[32](32), 36: state(4), 40: padding(8), 48: context(576), 624: page_directory
    ; Context is 576 bytes, and there's 8 bytes padding before it for FPU alignment
    mov eax, [ebx + 624]  ; EAX = next_task->page_directory (physical address)

    ; Get current CR3
    mov edx, cr3

    ; Only switch if different
    cmp eax, edx
    je skip_cr3_switch

    ; Load new page directory
    mov cr3, eax

    ; CRITICAL: Serialize to ensure TLB flush is complete before proceeding
    ; This guarantees all subsequent memory accesses use the new page tables
    jmp .cr3_serialized
.cr3_serialized:

skip_cr3_switch:
    add ebx, 48           ; EBX = &next_task->context (48 due to 8-byte padding!)

    ; Check if switching to user mode (CS has RPL=3)
    mov eax, [ebx + 56]   ; Load CS
    and eax, 3            ; Check RPL bits (bits 0-1)
    cmp eax, 3            ; Is RPL=3 (user mode)?
    je switch_to_user_mode_from_context_switch

    ; KERNEL MODE TASK - continue with normal context switch
    ; Load segment registers first
    mov eax, [ebx + 32]   ; Load DS
    mov ds, eax
    mov eax, [ebx + 36]   ; Load ES
    mov es, eax
    mov eax, [ebx + 40]   ; Load FS
    mov fs, eax
    mov eax, [ebx + 44]   ; Load GS
    mov gs, eax

    ; Load SS (stack segment)
    mov eax, [ebx + 60]
    mov ss, eax

    ; Load stack pointer
    mov esp, [ebx + 12]   ; Load ESP

    ; Stage EIP and EFLAGS on the new stack. EFLAGS is restored LAST (popf
    ; below, after every register has been loaded from the context struct):
    ; restoring it here would re-enable interrupts mid-load, and a nested
    ; preemption would overwrite the context fields we are still reading.
    push dword [ebx + 48]  ; EIP (consumed by the final ret)
    push dword [ebx + 52]  ; EFLAGS (consumed by the final popf)

    ;===========================================================================
    ; SECURITY FIX (Issue 5.3): Lazy FPU Switching - Set CR0.TS
    ;
    ; Set CR0.TS to defer FPU restore until task actually uses FPU.
    ; This triggers Device Not Available exception (#NM, vector 7) on first
    ; FPU instruction, where the exception handler will restore FPU state.
    ;===========================================================================
    mov eax, cr0
    or eax, (1 << 3)      ; Set CR0.TS bit (bit 3)
    mov cr0, eax
    ; REMOVED: lea eax, [ebx + 64]
    ; REMOVED: fxrstor [eax]

    ; Restore general purpose registers
    mov edi, [ebx + 0]    ; Restore EDI
    mov esi, [ebx + 4]    ; Restore ESI
    mov ebp, [ebx + 8]    ; Restore EBP
    mov edx, [ebx + 20]   ; Restore EDX
    mov ecx, [ebx + 24]   ; Restore ECX
    mov eax, [ebx + 28]   ; Restore EAX

    ; Restore EBX last since we're using it
    mov ebx, [ebx + 16]   ; Restore EBX

    ; Context fully loaded - now it is safe to restore EFLAGS (may set IF)
    popf                  ; Restore EFLAGS
    ret                   ; Pop EIP and jump to it

;-------------------------------------------------------------------------------
; USER MODE TRANSITION FROM CONTEXT_SWITCH
; This handles switching to a user-mode task from context_switch
;-------------------------------------------------------------------------------
switch_to_user_mode_from_context_switch:
    ; EBX points to &next_task->context
    ; Stack is: [retaddr][current][next]
    ; (Note: eflags was already removed at line 143 with the 4 registers)
    ; We need to clean up the stack and use iret to switch to user mode

    ; Pop/discard the stack frame from context_switch
    add esp, 12           ; Remove [retaddr][current][next] = 3*4 = 12 bytes

    ; Now jump to the common user mode switching code
    ; Note: EBX still points to &next_task->context
    jmp switch_to_user_mode

;-------------------------------------------------------------------------------
; FUNCTION: switch_to_first_task
; PURPOSE: Jump to the first task (no current task to save)
;
; C Prototype:
;   void switch_to_first_task(task_t* task);
;
; Parameters:
;   [ESP+4] = task pointer
;-------------------------------------------------------------------------------

switch_to_first_task:
    ; Interrupts must be off while loading a context (see context_switch)
    cli

    ; Get task pointer
    mov ebx, [esp + 4]    ; EBX = task

    ;===========================================================================
    ; SWITCH PAGE DIRECTORY (CR3)
    ;===========================================================================
    ; Page directory is at offset 624 in task_t structure
    ; 0: pid(4), 4: name[32](32), 36: state(4), 40: padding(8), 48: context(576), 624: page_directory
    mov eax, [ebx + 624]  ; EAX = task->page_directory (physical address)
    mov cr3, eax          ; Load new page directory

    ; CRITICAL: Serialize to ensure TLB flush is complete
    jmp .cr3_first_serialized
.cr3_first_serialized:

    add ebx, 48           ; EBX = &task->context (48 due to 8-byte padding!)

    ; Check if this is a user-mode task (CS has RPL=3)
    mov eax, [ebx + 56]   ; Load CS
    and eax, 3            ; Check RPL bits (bits 0-1)
    cmp eax, 3            ; Is RPL=3 (user mode)?
    je switch_to_user_mode

    ;===========================================================================
    ; KERNEL MODE TASK - Use simple jump
    ;===========================================================================

    ; Load segment registers
    mov eax, [ebx + 32]   ; Load DS
    mov ds, eax
    mov eax, [ebx + 36]   ; Load ES
    mov es, eax
    mov eax, [ebx + 40]   ; Load FS
    mov fs, eax
    mov eax, [ebx + 44]   ; Load GS
    mov gs, eax

    ; Load SS
    mov eax, [ebx + 60]
    mov ss, eax

    ; Load ESP
    mov esp, [ebx + 12]

    ; Stage EIP and EFLAGS on the new stack; EFLAGS restored last (see
    ; context_switch for rationale)
    push dword [ebx + 48]  ; EIP (consumed by the final ret)
    push dword [ebx + 52]  ; EFLAGS (consumed by the final popf)

    ;===========================================================================
    ; SECURITY FIX (Issue 5.3): Lazy FPU Switching - Set CR0.TS
    ;===========================================================================
    mov eax, cr0
    or eax, (1 << 3)      ; Set CR0.TS bit
    mov cr0, eax
    ; REMOVED: lea eax, [ebx + 64]
    ; REMOVED: fxrstor [eax]

    ; Load general purpose registers
    mov edi, [ebx + 0]
    mov esi, [ebx + 4]
    mov ebp, [ebx + 8]
    mov edx, [ebx + 20]
    mov ecx, [ebx + 24]
    mov eax, [ebx + 28]
    mov ebx, [ebx + 16]

    ; Context fully loaded - restore EFLAGS and jump to entry point
    popf
    ret

switch_to_user_mode:
    ;===========================================================================
    ; USER MODE TASK - Use iret to change privilege level
    ;===========================================================================
    ; We're currently in kernel mode (Ring 0) and need to switch to user mode (Ring 3)
    ; This requires using IRET with a proper stack frame

    ; Keep EBX pointing to context
    ; We'll build the iret frame on the KERNEL stack (current ESP)

    ; CRITICAL SECURITY: Validate user ESP is in user space and reasonable
    ; This prevents user code from executing with kernel stack, causing corruption
    mov eax, [ebx + 12]    ; Load user ESP

    ; SECURITY FIX: Additional ESP validation checks
    ; 1. Check ESP is not NULL (0x0)
    test eax, eax
    jz .panic_invalid_esp  ; Panic if ESP is NULL

    ; 2. Check ESP is not in first 4KB (NULL dereference protection)
    cmp eax, 0x1000
    jb .panic_invalid_esp  ; Panic if ESP < 4KB (0x1000)

    ; 3. Check ESP is not in kernel space (< 0xC0000000)
    cmp eax, 0xC0000000    ; Check if ESP >= kernel base (0xC0000000)
    jae .panic_invalid_esp ; Panic if ESP is in kernel space

    ; CRITICAL ALIGNMENT: Ensure user ESP is 16-byte aligned for SSE/AVX
    ; The IRET frame (20 bytes: SS, ESP, EFLAGS, CS, EIP) will be pushed,
    ; so we align ESP to 16 bytes to avoid alignment faults in user code
    and eax, 0xFFFFFFF0    ; Align to 16-byte boundary (clear low 4 bits)

    ; CRITICAL SECURITY: Sanitize EFLAGS to prevent IOPL escalation
    ; Load EFLAGS and mask out dangerous bits (IOPL, NT, etc.)
    ; Safe user EFLAGS: 0x3202 = IF (0x200) + reserved bit 1 (0x2) + IOPL=3 (0x3000)
    ; Actually, we want IOPL=0 for user mode, so: 0x0202
    mov edx, [ebx + 52]    ; Load saved EFLAGS
    and edx, 0x00000CD5    ; Mask: keep CF, PF, AF, ZF, SF, TF, DF, OF
    or  edx, 0x00000202    ; Set IF (interrupts enabled) and reserved bit 1

    ; Build iret stack frame (in reverse order, since stack grows down):
    ; [SS] [ESP] [EFLAGS] [CS] [EIP]

    push dword [ebx + 60]  ; Push SS (user stack segment)
    push eax               ; Push ESP (validated and aligned user stack pointer)
    push edx               ; Push EFLAGS (sanitized)
    push dword [ebx + 56]  ; Push CS (user code segment)
    push dword [ebx + 48]  ; Push EIP (entry point)

    ; SECURITY FIX: Load user data segment selectors BEFORE iret
    ; This prevents user code from starting with kernel data segments
    ; which would allow it to access kernel memory
    mov eax, [ebx + 32]    ; Load user DS selector
    mov ds, eax
    mov eax, [ebx + 36]    ; Load user ES selector
    mov es, eax
    mov eax, [ebx + 40]    ; Load user FS selector
    mov fs, eax
    mov eax, [ebx + 44]    ; Load user GS selector
    mov gs, eax

    ;===========================================================================
    ; SECURITY FIX (Issue 5.3): Lazy FPU Switching - Set CR0.TS
    ;===========================================================================
    mov eax, cr0
    or eax, (1 << 3)       ; Set CR0.TS bit
    mov cr0, eax
    ; REMOVED: lea eax, [ebx + 64]
    ; REMOVED: fxrstor [eax]

    ; Load general purpose registers
    mov edi, [ebx + 0]
    mov esi, [ebx + 4]
    mov ebp, [ebx + 8]
    mov edx, [ebx + 20]
    mov ecx, [ebx + 24]
    mov eax, [ebx + 28]
    mov ebx, [ebx + 16]    ; Restore EBX last

    ; Execute iret - this will:
    ; - Pop EIP, CS, EFLAGS, ESP, SS from stack
    ; - Switch to Ring 3 (user mode)
    ; - Jump to the user code
    ; Note: DS/ES/FS/GS are now set to user segments BEFORE iret
    iret

.panic_invalid_esp:
    ; CRITICAL ERROR: User ESP points to kernel memory
    ; This would cause immediate kernel stack corruption
    ; Print error message to VGA memory (0xB8000) and halt
    mov edi, 0xB8000
    mov dword [edi], 0x4F214F21  ; "!!" in red
    mov dword [edi+4], 0x4F454F20  ; " E" in red
    mov dword [edi+8], 0x4F504F53  ; "SP" in red
    cli
    hlt
    jmp $
