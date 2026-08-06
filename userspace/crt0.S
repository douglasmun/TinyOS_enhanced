/*=============================================================================
 * crt0.S - User program entry point
 *
 * Sets up ring-3 data segments (selector 0x2b = user data, RPL 3), clears
 * EBP for backtrace termination, calls main(), and exits with its return
 * value via SYS_EXIT (int 0x80, eax=0, ebx=status).
 *=============================================================================*/
    .section .text
    .global _start
    .extern main

_start:
    mov $0x2b, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs

    xor %ebp, %ebp
    call main

    mov %eax, %ebx          /* status = return value of main() */
    xor %eax, %eax          /* SYS_EXIT */
    int $0x80
1:  jmp 1b                  /* should never return */
