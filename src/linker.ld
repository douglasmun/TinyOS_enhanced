/*=============================================================================
 * linker.ld - TinyOS Linker Script for i386 ELF Kernel
 *=============================================================================*/

/*-----------------------------------------------------------------------------
 * Entry Point
 *---------------------------------------------------------------------------*/
ENTRY(_start)

/*-----------------------------------------------------------------------------
 * Output Format
 *---------------------------------------------------------------------------*/
OUTPUT_FORMAT(elf32-i386)
OUTPUT_ARCH(i386)

/*=============================================================================
 * SECTIONS - Memory Layout Definition
 *============================================================================*/
SECTIONS {

  /*---------------------------------------------------------------------------
   * Set Location Counter to 1 MiB
   *-------------------------------------------------------------------------*/
  . = 1M;

  /*---------------------------------------------------------------------------
   * Symbol: _kernel_start
   *-------------------------------------------------------------------------*/
  _kernel_start = .;

  /*===========================================================================
   * SECTION: .multiboot2 - Multiboot2 Header
   *=========================================================================*/
  .multiboot2 : {
    KEEP(*(.multiboot2))
  }

  /*===========================================================================
   * SECTION: .text - Executable Code
   *
   * SECURITY FIX (Issue 8.1): Align location counter BEFORE assigning symbol
   * to ensure __text_start is page-aligned for W^X enforcement.
   *=========================================================================*/
  . = ALIGN(4K);
  __text_start = .;
  .text : {
    *(.text .text.*)
  }
  __text_end = .;

  /*===========================================================================
   * SECTION: .user.text - User Mode Code
   *
   * SECURITY FIX (Issue 8.1): Page-align user text section for W^X enforcement
   *=========================================================================*/
  . = ALIGN(4K);
  __user_text_start = .;
  .user.text : {
    *(.user.text)
  }
  __user_text_end = .;

  /*===========================================================================
   * SECTION: .rodata - Read-Only Data
   *
   * SECURITY FIX (Issue 8.1): Page-align rodata section for W^X enforcement
   *=========================================================================*/
  . = ALIGN(4K);
  __rodata_start = .;
  .rodata : {
    *(.rodata*)
  }
  __rodata_end = .;

  /*===========================================================================
   * SECTION: .data - Initialized Data
   *
   * SECURITY FIX (Issue 8.1): Page-align data section for W^X enforcement
   *=========================================================================*/
  . = ALIGN(4K);
  __data_start = .;
  .data : {
    *(.data*)
  }
  __data_end = .;

  /*===========================================================================
   * SECTION: .bss - Uninitialized Data (Block Started by Symbol)
   *
   * SECURITY FIX (Issue 8.1): Page-align bss section for W^X enforcement
   *=========================================================================*/
  . = ALIGN(4K);
  __bss_start = .;
  .bss : {
    *(COMMON)           /* Include COMMON symbols first */
    *(.bss*)            /* Then all .bss sections */
  }
  __bss_end = .;

  /*---------------------------------------------------------------------------
   * Symbol: _kernel_end
   *-------------------------------------------------------------------------*/
  _kernel_end = .;

  /*===========================================================================
   * SECURITY FIX (Issue 8.1): W^X Policy Enforcement via Linker Assertions
   *
   * CRITICAL: Verify that linker does not introduce gaps between sections
   * that could violate Write XOR Execute policy. Gaps can be both writable
   * AND executable, creating a security hole.
   *
   * These assertions catch:
   * - Gaps between sections (misaligned sections)
   * - Section ordering violations
   * - Page alignment issues
   *
   * If any assertion fails, the link will fail with clear error message.
   *=========================================================================*/

  /* ASSERTION 1: .text section must be page-aligned (4KB = 0x1000) */
  ASSERT(__text_start % 0x1000 == 0,
         "ERROR: .text section not page-aligned - W^X enforcement requires 4KB alignment")

  /* ASSERTION 2: .text section must not be empty */
  ASSERT(__text_end > __text_start,
         "ERROR: .text section is empty")

  /* ASSERTION 3: .user.text must immediately follow .text (no gap > 4KB) */
  ASSERT(__user_text_start - __text_end <= 0x1000,
         "ERROR: Gap detected between .text and .user.text - potential W^X violation")

  /* ASSERTION 4: .user.text must be page-aligned */
  ASSERT(__user_text_start % 0x1000 == 0,
         "ERROR: .user.text not page-aligned - W^X enforcement requires 4KB alignment")

  /* ASSERTION 5: .rodata must immediately follow .user.text (no gap > 4KB) */
  ASSERT(__rodata_start - __user_text_end <= 0x1000,
         "ERROR: Gap detected between .user.text and .rodata - potential W^X violation")

  /* ASSERTION 6: .rodata must be page-aligned */
  ASSERT(__rodata_start % 0x1000 == 0,
         "ERROR: .rodata not page-aligned - W^X enforcement requires 4KB alignment")

  /* ASSERTION 7: .data must immediately follow .rodata (no gap > 4KB) */
  ASSERT(__data_start - __rodata_end <= 0x1000,
         "ERROR: Gap detected between .rodata and .data - potential W^X violation")

  /* ASSERTION 8: .data must be page-aligned */
  ASSERT(__data_start % 0x1000 == 0,
         "ERROR: .data not page-aligned - W^X enforcement requires 4KB alignment")

  /* ASSERTION 9: .bss must immediately follow .data (no gap > 4KB) */
  ASSERT(__bss_start - __data_end <= 0x1000,
         "ERROR: Gap detected between .data and .bss - potential W^X violation")

  /* ASSERTION 10: .bss must be page-aligned */
  ASSERT(__bss_start % 0x1000 == 0,
         "ERROR: .bss not page-aligned - W^X enforcement requires 4KB alignment")

  /* ASSERTION 11: Kernel must fit in reasonable memory (sanity check) */
  ASSERT(_kernel_end - _kernel_start < 0x2000000,
         "ERROR: Kernel image exceeds 32 MB - likely linker error")

  /*===========================================================================
   * DISCARD SECTIONS
   *=========================================================================*/
  /DISCARD/ : {
    *(.comment)       /* Compiler comments */
    *(.note*)         /* ELF notes and build IDs */
    *(.eh_frame)      /* Exception handling frames */
    *(.eh_frame_hdr)  /* Exception handling header */
  }
}

