/*=============================================================================
 *  multiboot.c â€” Multiboot2 Boot Information Parser for TinyOS
 *=============================================================================
 * 
 * PURPOSE:
 *   This file implements the parsing and display of boot information provided
 *   by a Multiboot2-compliant bootloader (typically GRUB 2.x). It extracts
 *   critical system information like the bootloader name, command-line
 *   arguments, and most importantly, the physical memory map.
 *
 */
#include "kernel.h"

/*=============================================================================
 * FUNCTION: dump_mmap_mb2 (UNUSED HELPER)
 *=============================================================================*/
__attribute__((unused))
static void dump_mmap_mb2(const struct mb2_tag_mmap* mm) {
    /*
     * Calculate entry array bounds:
     * - p: Start of first entry (right after tag header)
     * - e: End of tag (one byte past last valid entry)
     */
    const uint8_t* p = (const uint8_t*)(mm + 1);  /* First entry */
    const uint8_t* e = ((const uint8_t*)mm) + mm->size;  /* End of tag */

    console_puts("Memory map entries:\n");
    
    /*
     * Loop through all entries:
     * - Check we have space for full entry (p + entry_size <= e)
     * - Cast byte pointer to entry structure
     * - Print entry fields
     * - Advance by entry_size bytes (not sizeof!)
     */
    while (p + mm->entry_size <= e) {
        const struct mb2_mmap_entry* me = (const struct mb2_mmap_entry*)p;
        
        /* Print base address (64-bit, in hex) */
        console_puts("  addr=");
        console_put_hex64(me->addr);
        
        /* Print length (64-bit, in hex) */
        console_puts(" len=");
        console_put_hex64(me->len);
        
        /* Print type (32-bit, in decimal) */
        console_puts(" type=");
        console_put_dec_u32(me->type);
        
        console_putc('\n');
        
        /* Advance to next entry */
        p += mm->entry_size;
    }
}

/*=============================================================================
 * FUNCTION: mb_dump_mb1 (MULTIBOOT1 SUPPORT)
 *=============================================================================*/
void mb_dump_mb1(const struct multiboot_info* mb) {
    console_puts("Bootloader: ");
    
    /*
     * Check if bootloader name field is provided (non-zero).
     * If provided, cast to char* and print.
     * If not provided, print placeholder.
     */
    if (mb->boot_loader_name) {
        /* Cast: uint32_t â†’ uintptr_t â†’ const char* */
        console_puts((const char*)(uintptr_t)mb->boot_loader_name);
    } else {
        console_puts("<unknown>");
    }
    
    console_putc('\n');
}

/*=============================================================================
 * FUNCTION: mb_dump_mb2 (MULTIBOOT2 PARSER AND DISPLAY)
 *=============================================================================
 * 
 * PURPOSE:
 *   Parse and display boot information from Multiboot2 bootloader.
 *   This is the MAIN FUNCTION of this file.
 * 
 * PARAMETERS:
 *   info_ptr - Physical address of Multiboot2 information structure
 *              (provided by GRUB in EBX register)
 * 
 * WHAT IT DISPLAYS:
 *   - Bootloader name and version (e.g., "GRUB 2.06")
 *   - Command line arguments (e.g., "root=/dev/sda1 quiet")
 *   - Memory map (all usable and reserved regions)
 *
 * OUTPUT FORMAT:
 *   Bootloader: GRUB 2.06
 *   Cmdline   : root=/dev/sda1 quiet
 *   Memory map entries:
 *     addr=0x0000000000000000 len=0x000000000009FC00 type=1
 *     addr=0x0000000000100000 len=0x0000000007F00000 type=1
 * 
 */
void mb_dump_mb2(const void* info_ptr) {
    /*-------------------------------------------------------------------------
     * STEP 1: SET UP POINTERS AND BOUNDS
     *-----------------------------------------------------------------------*/

    /* Cast to byte pointer for arithmetic */
    const uint8_t* base = (const uint8_t*)info_ptr;

    /*=========================================================================
     * SECURITY FIX (AUDIT 5A): Validate Multiboot2 total_size
     *=========================================================================
     * VULNERABILITY: Unbounded total_size from Untrusted Bootloader
     *
     * PROBLEM: The bootloader provides total_size, which we trust without
     * validation. A malicious bootloader could provide:
     * - total_size < 8 (less than header size) -> immediate out-of-bounds
     * - total_size = 0xFFFFFFFF -> massive allocation, wraparound
     * - total_size causing base + total_size to overflow
     *
     * FIX: Multi-stage validation of total_size
     *=======================================================================*/

    /*
     * Read total_size from structure header (first 4 bytes).
     * This tells us the size of the entire structure in bytes.
     */
    const uint32_t total_size = *(const uint32_t*)(base + 0);

    /* Minimum size: 8 bytes (total_size + reserved fields) */
    #define MB2_MIN_SIZE 8

    /* Maximum reasonable size: 1MB (prevents DoS via huge structures) */
    #define MB2_MAX_SIZE (1024 * 1024)

    /* Validate minimum size */
    if (total_size < MB2_MIN_SIZE) {
        console_puts("ERROR: Multiboot2 total_size too small: ");
        console_put_dec_u32(total_size);
        console_puts(" (min ");
        console_put_dec_u32(MB2_MIN_SIZE);
        console_puts(")\n");
        return;
    }

    /* Validate maximum size (prevent DoS) */
    if (total_size > MB2_MAX_SIZE) {
        console_puts("ERROR: Multiboot2 total_size too large: ");
        console_put_dec_u32(total_size);
        console_puts(" (max ");
        console_put_dec_u32(MB2_MAX_SIZE);
        console_puts(")\n");
        return;
    }

    /* Validate no pointer overflow (base + total_size >= base) */
    const uint8_t* end_check = base + total_size;
    if (end_check < base) {
        console_puts("ERROR: Multiboot2 total_size causes pointer overflow\n");
        return;
    }

    /* First tag starts at offset 8 (after total_size and reserved) */
    const uint8_t* p = base + 8;

    /* End of structure (one byte past last valid data) */
    const uint8_t* end = base + total_size;

    /*-------------------------------------------------------------------------
     * STEP 2: LOOP THROUGH TAGS
     *-----------------------------------------------------------------------*/
    
    /*
     * Parse tags until we hit end tag or run out of data.
     * 
     * Loop invariant:
     *   p points to start of current tag (or past end if done)
     *   p is 8-byte aligned
     *   We've validated all tags before p
     */
    while (p + sizeof(struct mb2_tag) <= end) {
        /*
         * Read tag header (type and size).
         * We know p + sizeof(struct mb2_tag) <= end, so this is safe.
         */
        const struct mb2_tag* tag = (const struct mb2_tag*)p;

        /*
         * Check for end tag (type 0).
         * This MUST be the last tag in the structure.
         * When we see it, we're done parsing.
         */
        if (tag->type == MB2_TAG_END) {
            break;  /* Normal exit from loop */
        }

        /*=====================================================================
         * SECURITY FIX (AUDIT 5A): Multi-Stage Tag Size Validation
         *=====================================================================
         * VULNERABILITY: Malicious tag->size Can Cause Out-of-Bounds Access
         *
         * PROBLEM: Old code only checked `p + tag->size > end`, missing:
         * 1. Minimum size check (tag->size must be at least header size)
         * 2. Overflow check (p + tag->size must not wrap around)
         * 3. Malicious bootloader could set tag->size < sizeof(struct mb2_tag)
         *
         * ATTACK SCENARIO:
         * - Malicious bootloader sets tag->size = 4 (less than 8-byte header)
         * - Old code: p + 4 < end, validation passes!
         * - Alignment code: next = (p + 4 + 7) & ~7 = p + 8 (or similar)
         * - Next iteration reads garbage as next tag header
         * - Could cause infinite loop, out-of-bounds read, or crash
         *
         * FIX: Three-stage validation (defense in depth)
         *===================================================================*/

        /* Stage 1: Validate minimum tag size (must include full header) */
        if (tag->size < sizeof(struct mb2_tag)) {
            console_puts("WARNING: Multiboot2 tag size too small: ");
            console_put_dec_u32(tag->size);
            console_puts(" (type ");
            console_put_dec_u32(tag->type);
            console_puts("), stopping parse\n");
            break;  /* Stop parsing - structure is corrupted */
        }

        /* Stage 2: Validate no pointer overflow (p + tag->size >= p) */
        const uint8_t* tag_end = p + tag->size;
        if (tag_end < p) {
            console_puts("WARNING: Multiboot2 tag size causes overflow: ");
            console_put_dec_u32(tag->size);
            console_puts(" (type ");
            console_put_dec_u32(tag->type);
            console_puts("), stopping parse\n");
            break;  /* Stop parsing - overflow detected */
        }

        /* Stage 3: Validate tag fits within Multiboot structure bounds */
        if (tag_end > end) {
            console_puts("WARNING: Multiboot2 tag extends past end: ");
            console_put_dec_u32(tag->size);
            console_puts(" (type ");
            console_put_dec_u32(tag->type);
            console_puts("), stopping parse\n");
            break;  /* Stop parsing - tag exceeds structure size */
        }

        /*---------------------------------------------------------------------
         * STEP 3: PROCESS TAG BASED ON TYPE
         *-------------------------------------------------------------------*/

        switch (tag->type) {
            
            /*-----------------------------------------------------------------
             * TAG TYPE 2: BOOTLOADER NAME
             *-----------------------------------------------------------------
             * Contains name and version of bootloader as a null-terminated
             * ASCII string.
             * 
             * Example: "GRUB 2.06" or "GRUB 2.12"
             */
            case MB2_TAG_BOOTLOADER: {
                /* Cast to string tag structure */
                const struct mb2_tag_string* s = (const struct mb2_tag_string*)tag;
                
                /* Print label and string */
                console_puts("Bootloader: ");
                /* We assume s->str is null-terminated. */
                console_puts(s->str);  /* str is char[] at offset 8 */
                console_putc('\n');
                
            } break;

            /*-----------------------------------------------------------------
             * TAG TYPE 1: COMMAND LINE
             *-----------------------------------------------------------------
             * Contains kernel command-line arguments as a null-terminated
             * ASCII string.
             * 
             * Example: "root=/dev/sda1 quiet splash"
             * 
             * This string is typically set in GRUB configuration:
             *   linux /boot/kernel.elf root=/dev/sda1 quiet
             */
            case MB2_TAG_CMDLINE: {
                const struct mb2_tag_string* s = (const struct mb2_tag_string*)tag;
                console_puts("Cmdline   : ");
                console_puts(s->str);
                console_putc('\n');

            } break;

            /*-----------------------------------------------------------------
             * TAG TYPE 6: MEMORY MAP (THE MOST IMPORTANT TAG!)
             *-----------------------------------------------------------------
             * Contains the E820 memory map: a list of physical memory regions
             * with their types (usable, reserved, ACPI, etc.).
             * 
             * This tag is CRITICAL. Without it:
             * - We don't know how much RAM is installed
             * - We don't know where hardware is mapped
             * - We can't set up memory management
             * - Kernel cannot function properly
             */
            case MB2_TAG_MMAP: {
                /* Cast to memory map tag structure */
                const struct mb2_tag_mmap* mm = (const struct mb2_tag_mmap*)tag;
                
                /*
                 * Calculate entry array bounds:
                 * - q: First entry (right after tag header)
                 * - qe: End of tag (one byte past last entry)
                 */
                const uint8_t* q = (const uint8_t*)(mm + 1);
                const uint8_t* qe = p + mm->size;
                
                console_puts("Memory map entries:\n");
                
                /*
                 * Loop through all entries:
                 * - Use entry_size from tag (not sizeof!)
                 * - Check full entry fits before accessing it
                 * - Print address, length, type for each entry
                 */
                while (q + mm->entry_size <= qe) {
                    /* Cast current position to entry structure */
                    const struct mb2_mmap_entry* me = (const struct mb2_mmap_entry*)q;
                    
                    /*
                     * Print entry fields:
                     * - addr: 64-bit physical base address
                     * - len: 64-bit length in bytes
                     * - type: 32-bit region type (1=usable, 2=reserved, etc.)
                     */
                    console_puts("  addr=");
                    console_put_hex64(me->addr);
                    
                    console_puts(" len=");
                    console_put_hex64(me->len);
                    
                    console_puts(" type=");
                    console_put_dec_u32(me->type);
                    
                    console_putc('\n');
                    
                    /*
                     * Advance to next entry.
                     * Use entry_size (not sizeof) for forward compatibility.
                     */
                    q += mm->entry_size;
                }

            } break;

            /*-----------------------------------------------------------------
             * DEFAULT: IGNORE UNKNOWN TAGS
             *-----------------------------------------------------------------*/
            default:
                /* Silently ignore unknown/unimplemented tags */
                break;
        }

        /*=====================================================================
         * STEP 4: ADVANCE TO NEXT TAG (8-BYTE ALIGNED)
         *=====================================================================
         * SECURITY FIX (AUDIT 5B): Integer Overflow Guards for Tag Advancement
         *
         * VULNERABILITY: Integer Overflow in Tag Pointer Arithmetic
         *
         * OLD CODE (VULNERABLE):
         * uintptr_t next = ((uintptr_t)p + tag->size + 7u) & ~((uintptr_t)7u);
         *
         * PROBLEM: Expression can overflow in multiple ways:
         * 1. (uintptr_t)p + tag->size can overflow if tag->size is huge
         * 2. Result + 7u can overflow after first addition
         * 3. If overflow occurs, pointer wraps around to low memory
         * 4. Loop continues parsing kernel/bootloader memory as "tags"
         * 5. Out-of-bounds read, information disclosure, kernel crash
         *
         * ATTACK SCENARIO (Malicious Bootloader):
         * 1. Attacker controls bootloader (GRUB exploit, evil USB stick)
         * 2. Bootloader crafts tag with: tag->size = 0xFFFFFFF0
         * 3. Current pointer p = 0x00100200
         * 4. Addition: 0x00100200 + 0xFFFFFFF0 = 0x100001F0 (OVERFLOW!)
         * 5. Result wraps to 0x000001F0 (low memory, not Multiboot region)
         * 6. Loop parses random kernel data structures as tags
         * 7. Information leak: Console prints kernel memory contents
         * 8. Kernel crash: Dereferencing invalid tag pointers
         *
         * PRODUCTION FAILURE MODES:
         * - Corrupted Multiboot structure (hardware failure, memory bit flip)
         * - Malicious bootloader (compromised GRUB, evil Maid attack)
         * - Fuzzing test case triggers overflow (development/QA testing)
         *
         * FIX: Multi-Stage Overflow Detection Before Arithmetic
         * STAGE 1: Sanity check tag size (reject absurdly large values)
         * STAGE 2: Overflow detection (check if p + tag->size wrapped)
         * STAGE 3: Overflow detection (check if result + 7 wrapped)
         * STAGE 4: Bounds check (ensure next pointer still in valid range)
         *
         * OVERFLOW DETECTION TECHNIQUE:
         * Addition overflow occurs when: (a + b < a) for unsigned integers
         * Why this works:
         * - If no overflow: a + b ≥ a (result is larger or equal)
         * - If overflow: a + b wraps around, result < a
         * Example: 0xFFFFFFFF + 2 = 0x00000001 (wrapped, 1 < 0xFFFFFFFF)
         *===================================================================*/

        /*
         * STAGE 1: Sanity Check - Reject Absurdly Large Tag Sizes
         *
         * Maximum reasonable tag size: 1 MB (Multiboot spec suggests much smaller)
         * - Typical tags: 16-256 bytes (cmdline, module info)
         * - Largest legitimate tag: memory map (~64KB max)
         * - 1 MB gives generous safety margin
         *
         * If tag->size > 1 MB, this is almost certainly corruption or attack.
         */
        #define MAX_TAG_SIZE_SANITY (1024 * 1024)  /* 1 MB */

        if (tag->size > MAX_TAG_SIZE_SANITY) {
            console_puts("WARNING: Multiboot2 tag size exceeds sanity limit (");
            console_put_dec_u32(tag->size);
            console_puts(" > ");
            console_put_dec_u32(MAX_TAG_SIZE_SANITY);
            console_puts("), stopping parse\n");
            break;  /* Stop parsing, don't trust further tags */
        }

        /*
         * STAGE 2: Overflow Detection - Check (p + tag->size)
         *
         * Calculate sum and verify it didn't wrap around.
         */
        const uint8_t* p_plus_size = p + tag->size;
        if (p_plus_size < p) {
            console_puts("WARNING: Multiboot2 tag advancement overflow detected ");
            console_puts("(p=0x");
            console_put_hex64((uintptr_t)p);
            console_puts(" + size=");
            console_put_dec_u32(tag->size);
            console_puts(" < p), stopping parse\n");
            break;
        }

        /*
         * STAGE 3: Overflow Detection - Check (p + tag->size + 7)
         *
         * The +7 is needed for 8-byte alignment rounding.
         * This addition can also overflow.
         */
        const uint8_t* p_plus_size_plus_7 = p_plus_size + 7u;
        if (p_plus_size_plus_7 < p_plus_size) {
            console_puts("WARNING: Multiboot2 alignment overflow detected, ");
            console_puts("stopping parse\n");
            break;
        }

        /*
         * STAGE 4: Bounds Check - Ensure Next Pointer Still in Valid Range
         *
         * After all arithmetic, verify the next pointer hasn't escaped
         * the Multiboot info structure bounds.
         */
        uintptr_t next = ((uintptr_t)p_plus_size_plus_7) & ~((uintptr_t)7u);
        const uint8_t* next_ptr = (const uint8_t*)next;

        if (next_ptr > end) {
            console_puts("WARNING: Multiboot2 tag advancement exceeds bounds ");
            console_puts("(next > end), stopping parse\n");
            break;
        }

        /* All checks passed - safe to advance pointer */
        p = next_ptr;
        
    }    
}

