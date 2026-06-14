/*=============================================================================
 * user.ld - Linker Script for User-Mode ELF Programs
 *=============================================================================*/

OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(_start)

SECTIONS
{
    /* Load user programs at virtual address 0x08000000 (128MB mark) */
    . = 0x08000000;

    /* Code section */
    .text ALIGN(4K) : {
        *(.text)
        *(.text.*)
    }

    /* Read-only data */
    .rodata ALIGN(4K) : {
        *(.rodata)
        *(.rodata.*)
    }

    /* Initialized data */
    .data ALIGN(4K) : {
        *(.data)
        *(.data.*)
    }

    /* Uninitialized data (BSS) */
    .bss ALIGN(4K) : {
        *(COMMON)
        *(.bss)
        *(.bss.*)
    }

    /* Discard unnecessary sections */
    /DISCARD/ : {
        *(.comment)
        *(.eh_frame)
        *(.note*)
    }
}
