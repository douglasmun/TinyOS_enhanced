/*=============================================================================
 * crt0.S - User program entry point
 *
 * Sets up ring-3 data segments (selector 0x2b = user data, RPL 3), clears
 * EBP for backtrace termination, calls main(argc, argv), and exits with its
 * return value via SYS_EXIT (int 0x80, eax=0, ebx=status).
 *
 * The kernel (task_create_user_argv) builds an argument block at the bottom
 * of the initial stack and points ESP at it, so on entry:
 *
 *      0(%esp) = argc   (int)
 *      4(%esp) = argv   (char**, NULL-terminated array)
 *
 * A task created without arguments still gets argc == 0 and a valid argv
 * whose first element is NULL, so main() never sees garbage.
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

    /* Load the kernel-supplied argument block before touching ESP. */
    mov 0(%esp), %edi       /* argc */
    mov 4(%esp), %esi       /* argv */

    xor %ebp, %ebp

    /* cdecl: push arguments right-to-left, so argv then argc. */
    push %esi
    push %edi
    call main
    add $8, %esp            /* caller cleans up (cdecl) */

    mov %eax, %ebx          /* status = return value of main() */
    xor %eax, %eax          /* SYS_EXIT */
    int $0x80
1:  jmp 1b                  /* should never return */
