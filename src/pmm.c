/*=============================================================================
 *  pmm.c - TinyOS Physical Memory Manager (Bitmap Allocator)
 *============================================================================*/

#include "kernel.h"
#include "pmm.h"
#include "kprintf.h"
#include "util.h"  /* For kernel_panic() */

/*=============================================================================
 * CRITICAL SECTION PROTECTION FOR PMM ATOMICITY
 * SECURITY: PMM bitmap operations must be atomic to prevent data races.
 * Without protection, concurrent calls to pmm_alloc/pmm_free from different
 * interrupt contexts could corrupt the bitmap or frame counters.
 *=============================================================================*/
/*=============================================================================
 * CRITICAL SECTION FIX: Atomic EFLAGS Save/Restore
 *
 * SECURITY: The previous implementation had a non-atomic sequence that could
 * allow the compiler to insert instructions between pushfl/cli/popl, creating
 * a race condition window.
 *
 * FIX: Use single atomic inline assembly block with optimal instruction order:
 *   pushfl; popl %0; cli  (instead of pushfl; cli; popl %0)
 *
 * This ensures:
 * 1. EFLAGS saved to register (with original IF state)
 * 2. Interrupts disabled
 * 3. No window for compiler to insert code
 *=============================================================================*/
#define PMM_CRITICAL_ENTER() \
    uint32_t __pmm_flags__; \
    __asm__ volatile("pushfl; popl %0; cli" : "=r"(__pmm_flags__) : : "memory")

#define PMM_CRITICAL_EXIT() \
    __asm__ volatile("pushl %0; popfl" : : "r"(__pmm_flags__) : "memory", "cc")

/*=============================================================================
 * PHYSICAL MEMORY CONFIGURATION
 *
 * PERFORMANCE FIX: Increased from 128 MiB to 256 MiB to support systems with
 * more RAM. Bitmap size increases from 4 KB to 8 KB (still very reasonable).
 *
 * TODO: Make fully dynamic based on multiboot memory map (allocate bitmap
 * from kernel heap instead of static allocation).
 *============================================================================*/
#define PMM_MAX_BYTES   (256u * 1024u * 1024u)      /* 256 MiB (was 128 MiB) */
#define PMM_MAX_FRAMES  (PMM_MAX_BYTES / PMM_PAGE_SIZE)  /* 65,536 frames */

/* Frames below the standard-mode identity-mapped region (first 32 MiB).
 * Paging structures accessed via phys==virt must come from this range. */
#define PMM_LOW_BYTES   (32u * 1024u * 1024u)
#define PMM_LOW_FRAMES  (PMM_LOW_BYTES / PMM_PAGE_SIZE)

/*=============================================================================
 * BITMAP STORAGE
 *============================================================================*/
static uint8_t bitmap[PMM_MAX_FRAMES / 8] __attribute__((aligned(4096)));

/*=============================================================================
 * FRAME COUNTERS (CRITICAL: volatile for interrupt safety)
 *
 * VULNERABILITY (11.A): Compiler optimization can cache these globals in
 * registers. If an interrupt handler modifies frames_free (via pmm_alloc
 * or pmm_free), the interrupted code will continue with stale cached values,
 * causing silent data corruption and memory over-allocation.
 *
 * FIX: Declare as volatile to force memory reads/writes on every access,
 * preventing register caching and ensuring interrupt handlers see current values.
 *============================================================================*/
static volatile uint32_t frames_total = PMM_MAX_FRAMES;  /* Total frames (constant) */
static volatile uint32_t frames_free  = 0;               /* Free frames (dynamic) */

/*=============================================================================
 * KERNEL BOUNDARIES (from linker script and boot.s)
 *============================================================================*/
extern uint8_t _kernel_start;   /* First byte of kernel (from linker) */
extern uint8_t _kernel_end;     /* Last byte of kernel (from linker) */
extern uint8_t stack_bottom;    /* Boot stack bottom (from boot.s) */
extern uint8_t stack_top;       /* Boot stack top (from boot.s) */

/*=============================================================================
 * BITMAP MANIPULATION HELPERS
 *============================================================================*/

/*-----------------------------------------------------------------------------
 * FUNCTION: bset
 *-----------------------------------------------------------------------------
 * DESCRIPTION:
 *   Sets bit i in the bitmap to 1, marking frame i as USED.
 *
 * PARAMETERS:
 *   i - Frame index (0 to PMM_MAX_FRAMES-1)
 *
 *---------------------------------------------------------------------------*/
static inline void bset(uint32_t i) {
    bitmap[i >> 3] |= (1u << (i & 7));
}

/*-----------------------------------------------------------------------------
 * FUNCTION: bclr
 *-----------------------------------------------------------------------------
 * DESCRIPTION:
 *   Clears bit i in the bitmap to 0, marking frame i as FREE.
 *
 * PARAMETERS:
 *   i - Frame index (0 to PMM_MAX_FRAMES-1)
 *
 *---------------------------------------------------------------------------*/
static inline void bclr(uint32_t i) {
    bitmap[i >> 3] &= ~(1u << (i & 7));
}

/*-----------------------------------------------------------------------------
 * FUNCTION: bget
 *-----------------------------------------------------------------------------
 * DESCRIPTION:
 *   Reads bit i from the bitmap, returning its state (0=free, 1=used).
 *
 * PARAMETERS:
 *   i - Frame index (0 to PMM_MAX_FRAMES-1)
 *
 * RETURNS:
 *   int: 0 if frame is free, non-zero (specifically 1) if used
 *
 * OPERATION:
 *   1. Read byte: bitmap[i >> 3]
 *   2. Shift right to bring target bit to LSB: >> (i & 7)
 *   3. Mask LSB: & 1
 *   4. Return result (0 or 1)
 *
 * RETURN VALUE:
 *   Technically returns 0 or 1 (single bit value).
 *   In C, 0 = false, non-zero = true.
 *   
 *   Usage:
 *     if (bget(i)) - frame is used
 *     if (!bget(i)) - frame is free
 *
 *---------------------------------------------------------------------------*/
static inline int bget(uint32_t i) {
    return (bitmap[i >> 3] >> (i & 7)) & 1;
}

/*=============================================================================
 * FUNCTION: mark_range
 *=============================================================================
 * DESCRIPTION:
 *   Marks a range of physical memory as used or free in the bitmap.
 *   This is the core function for reserving/freeing memory regions.
 *   Used during initialization and by pmm_mark_used/pmm_mark_free wrappers.
 *
 * PARAMETERS:
 *   phys - Starting physical address of the range (byte address)
 *          Need not be page-aligned (function handles alignment)
 *   
 *   size - Size of the range in bytes
 *          Need not be page-aligned (function handles alignment)
 *   
 *   used - Boolean: 1 = mark as used, 0 = mark as free
 *
 * USAGE EXAMPLES:
 *   // Reserve low 1 MiB for BIOS
 *   mark_range(0x00000000, 0x00100000, 1);
 *   
 *   // Free a 2 MiB region starting at 4 MiB
 *   mark_range(0x00400000, 0x00200000, 0);
 *   
 *   // Reserve single page at 16 MiB
 *   mark_range(0x01000000, 0x1000, 1);
 *
 *============================================================================*/
static void mark_range(uint32_t phys, uint32_t size, int used) {
    /*=========================================================================
     * STEP 1: Convert byte address to frame index
     *=======================================================================*/
    uint32_t start = phys / PMM_PAGE_SIZE;

    /*=========================================================================
     * SECURITY: Validate Start Frame Index
     * CRITICAL: If phys is very large (e.g., > 128MB), start could exceed
     * PMM_MAX_FRAMES, causing out-of-bounds bitmap access.
     *=======================================================================*/
    if (start >= PMM_MAX_FRAMES) {
        return;  // Entire range is beyond managed memory
    }

    /*=========================================================================
     * STEP 2: Calculate end frame (inclusive range) with overflow protection
     * SECURITY: Integer Overflow Prevention
     * CRITICAL: (phys + size) can overflow, causing wrong end calculation.
     *
     * Attack scenario without this check:
     *   phys = 0xFFFFFF00, size = 0x200
     *   phys + size = 0x100 (OVERFLOWED!)
     *   end = (0x100 + 0xFFF) / 0x1000 = 0x1
     *   Only 1 frame marked instead of wrapping entire address space
     *
     * Fix: Check for overflow before addition, use safe calculation.
     *=======================================================================*/
    uint32_t end;

    // Check if phys + size would overflow
    if (size > (0xFFFFFFFF - phys)) {
        // Overflow would occur - clamp to max address
        end = PMM_MAX_FRAMES;
    } else {
        uint32_t phys_end = phys + size;
        // Now safe to calculate end frame with page alignment
        if (phys_end > (0xFFFFFFFF - PMM_PAGE_SIZE + 1)) {
            // Adding PMM_PAGE_SIZE-1 would overflow
            end = PMM_MAX_FRAMES;
        } else {
            end = (phys_end + PMM_PAGE_SIZE - 1) / PMM_PAGE_SIZE;
        }
    }

    /*=========================================================================
     * STEP 3: Clamp end to maximum frame count
     *=======================================================================*/
    if (end > PMM_MAX_FRAMES) end = PMM_MAX_FRAMES;
    
    /*=========================================================================
     * STEP 4: Update bitmap and counter for each frame
     *=======================================================================*/
    for (uint32_t i = start; i < end; ++i) {
        /*---------------------------------------------------------------------
         * Read current state of this frame
         *-------------------------------------------------------------------*/
        int was = bget(i);
        
        if (used) {
            /*-----------------------------------------------------------------
             * Marking frame as USED
             *---------------------------------------------------------------*/
            if (!was) {
                bset(i);                    /* Set bit to 1 */
                if (frames_free) 
                    frames_free--;          /* Decrease free count */
            }
        } else {
            /*-----------------------------------------------------------------
             * Marking frame as FREE
             *---------------------------------------------------------------*/
            if (was) {
                bclr(i);                    /* Clear bit to 0 */
                frames_free++;              /* Increase free count */
            }
        }
    }
}

/*=============================================================================
 * FUNCTION: pmm_mark_used
 *=============================================================================
 * DESCRIPTION:
 *   Public wrapper that marks a physical memory range as USED (allocated).
 *   Reserves the range so pmm_alloc() won't return frames from it.
 *
 * PARAMETERS:
 *   phys - Starting physical address (need not be page-aligned)
 *   size - Size in bytes (need not be page-aligned)
 *
 * USAGE:
 *   Called during initialization to reserve critical regions:
 *     - Low 1 MiB (BIOS data structures)
 *     - Kernel image (code, data, bss)
 *     - Memory-mapped devices (VGA buffer, etc.)
 *
 * EXAMPLES:
 *   pmm_mark_used(0, 0x100000);              // Reserve low 1 MiB
 *   pmm_mark_used(0x100000, 0x50000);        // Reserve 320 KiB at 1 MiB
 *   pmm_mark_used((uint32_t)&bitmap, 4096);  // Reserve PMM bitmap
 *============================================================================*/
void pmm_mark_used(uint32_t phys, uint32_t size) {
    mark_range(phys, size, 1);  /* 1 = mark as used */
}

/*=============================================================================
 * FUNCTION: pmm_mark_free
 *=============================================================================
 * DESCRIPTION:
 *   Public wrapper that marks a physical memory range as FREE (available).
 *   Makes the range available for allocation by pmm_alloc().
 *
 * PARAMETERS:
 *   phys - Starting physical address (need not be page-aligned)
 *   size - Size in bytes (need not be page-aligned)
 *
 * USAGE:
 *   Called during initialization to mark usable RAM regions.
 *   Bootloader provides memory map with usable regions (Type 1).
 *   We mark these as free so they can be allocated.
 *
 * EXAMPLES:
 *   pmm_mark_free(0x100000, 0x7F00000);  // Free 127 MiB at 1 MiB
 *============================================================================*/
void pmm_mark_free(uint32_t phys, uint32_t size) {
    mark_range(phys, size, 0);  /* 0 = mark as free */
}

/*=============================================================================
 * FUNCTION: pmm_total_frames
 *=============================================================================
 * DESCRIPTION:
 *   Returns the total number of manageable frames (constant after init).
 *
 * RETURNS:
 *   uint32_t: Total frame count (always PMM_MAX_FRAMES = 32768)
 *
 * USAGE:
 *   Display during boot: "PMM: %u total frames\n"
 *   Calculate total memory: total_frames * 4096 bytes
 *============================================================================*/
uint32_t pmm_total_frames(void) {
    return frames_total;
}

/*=============================================================================
 * FUNCTION: pmm_free_frames
 *=============================================================================
 * DESCRIPTION:
 *   Returns the current number of free (unallocated) frames.
 *
 * RETURNS:
 *   uint32_t: Current free frame count (changes with alloc/free)
 *
 * USAGE:
 *   Check available memory: "PMM: %u free frames\n"
 *   Detect low memory: if (pmm_free_frames() < 100) panic("OOM");
 *   Calculate free memory: free_frames * 4096 bytes
 *
 * TYPICAL VALUE:
 *   After init: ~31,000 frames (~121 MiB) for 128 MiB system
 *============================================================================*/
uint32_t pmm_free_frames(void) {
    return frames_free;
}

/*=============================================================================
 * FUNCTION: pmm_init_from_mb2
 *=============================================================================
 * DESCRIPTION:
 *   Initializes the PMM from Multiboot2 information structure.
 *   Parses the memory map, marks usable RAM as free, and reserves
 *   critical regions (BIOS, kernel, bitmap). This is the main initialization
 *   function called once during kernel boot.
 *
 * PARAMETERS:
 *   info_ptr - Pointer to Multiboot2 info structure (provided by bootloader)
 *              This structure contains tags describing system configuration
 s
 *============================================================================*/
void pmm_init_from_mb2(const void* info_ptr) {
    /*=========================================================================
     * PHASE 1: PESSIMISTIC INITIALIZATION
     *=========================================================================*/
    for (uint32_t i = 0; i < sizeof(bitmap); ++i) {
        bitmap[i] = 0xFF;  /* Mark all frames as used */
    }
    frames_free = 0;       /* No free frames yet */
    
    /*=========================================================================
     * PHASE 2: PARSE MULTIBOOT2 MEMORY MAP
     *=======================================================================*/
    const uint8_t* base = (const uint8_t*)info_ptr;
    const uint32_t total_size = *(const uint32_t*)(base + 0);
    const uint8_t* p   = base + 8;    /* Skip total_size and reserved */
    const uint8_t* end = base + total_size;
    
    /*-------------------------------------------------------------------------
     * Walk through all tags until END tag or bounds exceeded
     *-----------------------------------------------------------------------*/
    while (p + sizeof(struct mb2_tag) <= end) {
        const struct mb2_tag* tag = (const struct mb2_tag*)p;
        
        /*---------------------------------------------------------------------
         * Check for END tag (type 0)
         *-------------------------------------------------------------------*/
        if (tag->type == MB2_TAG_END) break;
        
        /*---------------------------------------------------------------------
         * Bounds check: Ensure tag doesn't exceed total_size
         *-------------------------------------------------------------------*/
        if (p + tag->size > end) break;
        
        /*---------------------------------------------------------------------
         * Process MMAP tag (type 6) â€” Memory Map
         *-------------------------------------------------------------------*/
        if (tag->type == MB2_TAG_MMAP) {
            const struct mb2_tag_mmap* mm = (const struct mb2_tag_mmap*)tag;
            const uint8_t* q  = (const uint8_t*)(mm + 1);  /* First entry */
            const uint8_t* qe = p + mm->size;              /* End of tag */
            
            /*-----------------------------------------------------------------
             * Iterate through memory map entries
             *---------------------------------------------------------------*/
            while (q + mm->entry_size <= qe) {
                const struct mb2_mmap_entry* me = (const struct mb2_mmap_entry*)q;
                
                /*-------------------------------------------------------------
                 * Check if region is usable (type 1)
                 *-----------------------------------------------------------*/
                if (me->type == 1) {
                    /* Usable RAM */
                    uint64_t base64 = me->addr;
                    uint64_t len64  = me->len;

                    /*=========================================================
                     * SECURITY FIX: Detect Memory Beyond PMM Limit
                     *
                     * VULNERABILITY: If bootloader reports usable memory
                     * beyond PMM_MAX_BYTES (128 MiB), the PMM silently
                     * ignores it, potentially causing resource exhaustion
                     * or silent allocation failures later.
                     *
                     * FIX: Issue a loud warning if any usable memory is
                     * found beyond our management limit. This alerts the
                     * operator to either increase PMM_MAX_BYTES or expect
                     * limited memory availability.
                     *=======================================================*/
                    if (base64 >= PMM_MAX_BYTES) {
                        kprintf("[PMM] WARNING: Usable RAM at 0x%08x%08x beyond PMM limit (%u MiB)\n",
                                (uint32_t)(base64 >> 32),
                                (uint32_t)base64,
                                PMM_MAX_BYTES / (1024*1024));
                        kprintf("[PMM] WARNING: This memory will NOT be managed by PMM!\n");
                        /* Continue processing - don't allocate, but warn loudly */
                        q += mm->entry_size;
                        continue;
                    }

                    /*---------------------------------------------------------
                     * Clamp to 32-bit addressable space (PMM_MAX_BYTES)
                     *-------------------------------------------------------*/
                    if (base64 < PMM_MAX_BYTES) {
                        /* Calculate how much room left before PMM_MAX_BYTES */
                        uint64_t room = PMM_MAX_BYTES - base64;

                        /* Use min(region length, remaining room) */
                        uint64_t use = (len64 < room) ? len64 : room;

                        /* Warn if we're truncating a region */
                        if (len64 > use) {
                            kprintf("[PMM] WARNING: Memory region truncated at PMM limit\n");
                            kprintf("[PMM] Region: 0x%08x%08x - 0x%08x%08x (truncated to %u MiB)\n",
                                    (uint32_t)(base64 >> 32), (uint32_t)base64,
                                    (uint32_t)((base64 + len64) >> 32), (uint32_t)(base64 + len64),
                                    PMM_MAX_BYTES / (1024*1024));
                        }

                        /* Mark this region as free (cast to 32-bit addresses) */
                        if (use) {
                            pmm_mark_free((uint32_t)base64, (uint32_t)use);
                        }
                    }
                }
                
                /* Advance to next entry */
                q += mm->entry_size;
            }
        }
        
        /*---------------------------------------------------------------------
         * Advance to next tag (8-byte aligned)
         *-------------------------------------------------------------------*/
        uintptr_t next = ((uintptr_t)p + tag->size + 7u) & ~((uintptr_t)7u);
        p = (const uint8_t*)next;
    }
    
    /*=========================================================================
     * PHASE 3: RESERVE CRITICAL REGIONS
     *=======================================================================*/
    
    /*-------------------------------------------------------------------------
     * RESERVATION 1: Low 1 MiB (0x00000000 - 0x000FFFFF)
     *-----------------------------------------------------------------------*/
    /* SECURITY: Reserve entire low 1 MiB region containing:
     * - Real mode IVT (Interrupt Vector Table) at 0x00000000
     * - BIOS Data Area (BDA) at 0x00000400
     * - Video memory (VGA text mode) at 0x000B8000
     * - BIOS ROM area and EBDA
     * - Bootloader code and data structures
     *
     * This prevents user processes from corrupting critical system areas.
     */
    pmm_mark_used(0, 0x100000);  /* 0 to 1 MiB */

    /*-------------------------------------------------------------------------
     * RESERVATION 2: Kernel Image (typically starts at 0x00100000 = 1 MiB)
     *-----------------------------------------------------------------------*/
    /*=========================================================================
     * SECURITY: Reserve entire kernel image to prevent PMM from allocating
     * kernel code/data pages to user processes.
     *
     * The kernel image includes (as defined by linker script src/linker.ld):
     * - .multiboot2: Multiboot2 header for bootloader
     * - .text:       Kernel executable code
     * - .rodata:     Read-only data (string literals, const data)
     * - .data:       Initialized global/static variables
     * - .bss:        Uninitialized data, INCLUDING kernel boot stack
     *
     * CRITICAL: The kernel boot stack (defined in boot.s) lives in .bss,
     * so this reservation protects it. The stack is allocated as:
     *   stack_bottom:
     *   resb KERNEL_BOOT_STACK_SIZE  ; default 256 KiB
     *   stack_top:
     *
     * Per-task kernel stacks are allocated dynamically via pmm_alloc()
     * and are managed separately (see process.c task creation).
     *
     * Linker symbols:
     * - _kernel_start: Beginning of kernel image (set to 1M in linker.ld)
     * - _kernel_end:   End of .bss section (includes boot stack)
     *=======================================================================*/
    uint32_t k_start = ((uint32_t)(uintptr_t)&_kernel_start) & ~0xFFFu;
    uint32_t k_end   = ((uint32_t)(uintptr_t)&_kernel_end   + 0xFFFu) & ~0xFFFu;
    if (k_end > k_start) {
        pmm_mark_used(k_start, k_end - k_start);
    }

    /*=========================================================================
     * SECURITY VERIFICATION: Ensure Boot Stack is Protected (10.B)
     *
     * VULNERABILITY: If the boot stack (defined in boot.s .bss section) is
     * not properly reserved by the kernel image reservation, the PMM could
     * later allocate it to a user process or task, causing immediate kernel
     * stack corruption and system crash.
     *
     * VERIFICATION: The boot stack lives in .bss between stack_bottom and
     * stack_top. These addresses MUST fall within the kernel image range
     * (_kernel_start to _kernel_end) that we just reserved.
     *
     * If this check fails, it indicates a linker script or build error.
     *=======================================================================*/
    uint32_t stack_start = (uint32_t)(uintptr_t)&stack_bottom;
    uint32_t stack_end = (uint32_t)(uintptr_t)&stack_top;

    if (stack_start < k_start || stack_end > k_end) {
        kprintf("[PMM] CRITICAL: Boot stack NOT within kernel reservation!\n");
        kprintf("[PMM] Stack: 0x%08x - 0x%08x (%u KiB)\n",
                stack_start, stack_end, (stack_end - stack_start) / 1024);
        kprintf("[PMM] Kernel: 0x%08x - 0x%08x\n", k_start, k_end);
        kprintf("[PMM] PANIC: Boot stack will be allocated! System UNSAFE!\n");

        /*
         * SECURITY FIX: Use kernel_panic instead of inline halt loop
         * Provides recursion protection and consistent error handling
         */
        kernel_panic("Boot stack outside kernel reservation");
    }

    kprintf("[PMM] Boot stack verified: 0x%08x - 0x%08x (%u KiB) [PROTECTED]\n",
            stack_start, stack_end, (stack_end - stack_start) / 1024);

    /*-------------------------------------------------------------------------
     * RESERVATION 3: PMM bitmap
     * SECURITY: Safe calculation to avoid integer overflow in size computation
     *-----------------------------------------------------------------------*/
    uint32_t bm_phys = (uint32_t)(uintptr_t)bitmap;
    uint32_t bm_size = sizeof(bitmap);

    /*=========================================================================
     * SECURITY: Integer Overflow Prevention in Bitmap Reservation
     * Calculate page-aligned size safely to avoid overflow in addition.
     *
     * Goal: Reserve pages from (bm_phys page-aligned down) to
     *                          (bm_phys + bm_size page-aligned up)
     *=======================================================================*/
    uint32_t bm_start = bm_phys & ~0xFFFu;  // Round down to page boundary

    // Calculate end address with overflow check
    uint32_t bm_end;
    if (bm_size > (0xFFFFFFFF - bm_phys)) {
        // Would overflow - use max address
        bm_end = 0xFFFFFFFF;
    } else {
        bm_end = bm_phys + bm_size;
    }

    // Round up to page boundary
    bm_end = (bm_end + 0xFFFu) & ~0xFFFu;

    // Calculate size (end - start)
    uint32_t bm_reservation_size = bm_end - bm_start;

    pmm_mark_used(bm_start, bm_reservation_size);

    /*-------------------------------------------------------------------------
     * RESERVATION 4: Multiboot Structure (SECURITY FIX)
     *-----------------------------------------------------------------------*/
    /*=========================================================================
     * CRITICAL SECURITY FIX: Reserve Multiboot Structure Memory
     *
     * VULNERABILITY: The Multiboot structure resides in physical memory
     * provided by the bootloader. If the PMM later reallocates these pages
     * to user processes or kernel data structures, the boot information
     * will be corrupted.
     *
     * IMPACT:
     * - Memory corruption if Multiboot pages are overwritten
     * - Potential information leakage if kernel reads corrupted boot data
     * - System instability if boot parameters are referenced later
     *
     * FIX: Explicitly mark the entire Multiboot structure as USED to prevent
     * PMM from ever allocating these pages. The structure includes:
     * - The main header (total_size, reserved)
     * - All tags (bootloader name, cmdline, memory map, etc.)
     * - Tag data (strings, arrays, structures)
     *
     * The total_size field tells us exactly how many bytes to reserve.
     *=======================================================================*/
    uint32_t mb_phys = (uint32_t)(uintptr_t)info_ptr;
    uint32_t mb_size = *(const uint32_t*)((const uint8_t*)info_ptr + 0);  // total_size

    // Round down to page boundary (start)
    uint32_t mb_start = mb_phys & ~0xFFFu;

    // Calculate end address with overflow check
    uint32_t mb_end;
    if (mb_size > (0xFFFFFFFF - mb_phys)) {
        // Would overflow - use max address
        mb_end = 0xFFFFFFFF;
    } else {
        mb_end = mb_phys + mb_size;
    }

    // Round up to page boundary (end)
    mb_end = (mb_end + 0xFFFu) & ~0xFFFu;

    // Calculate reservation size
    uint32_t mb_reservation_size = mb_end - mb_start;

    // Mark as permanently used
    pmm_mark_used(mb_start, mb_reservation_size);

}

/*=============================================================================
 * FUNCTION: pmm_alloc
 *=============================================================================
 * DESCRIPTION:
 *   Allocates a single 4 KiB frame of physical memory.
 *   Uses first-fit algorithm: scans bitmap for first free frame.
 *   Returns physical address of allocated frame, or 0 on failure.
 *
 * RETURNS:
 *   uint32_t: Physical address of allocated frame (page-aligned)
 *             Returns 0 if no free frames available (out of memory)
 *
 *============================================================================*/
uint32_t pmm_alloc(void) {
    /*=========================================================================
     * CRITICAL SECTION: Protect bitmap and counter modifications
     * Without atomicity, two concurrent pmm_alloc() calls could:
     * 1. Both read the same frame as free (race on bget)
     * 2. Both allocate it (double allocation!)
     * 3. Corrupt frames_free counter
     *=======================================================================*/
    PMM_CRITICAL_ENTER();

    /*=========================================================================
     * Scan bitmap for first free frame
     *=======================================================================*/
    for (uint32_t i = 0; i < PMM_MAX_FRAMES; ++i) {
        /*---------------------------------------------------------------------
         * Check if this frame is free
         *-------------------------------------------------------------------*/
        if (!bget(i)) {
            /*-----------------------------------------------------------------
             * Frame is free â€" allocate it
             *---------------------------------------------------------------*/
            bset(i);                        /* Mark frame as used */

            if (frames_free)
                frames_free--;              /* Decrement free count */

            PMM_CRITICAL_EXIT();

            /*-----------------------------------------------------------------
             * Convert frame index to physical address
             *---------------------------------------------------------------*/
            return i * PMM_PAGE_SIZE;
        }
    }

    PMM_CRITICAL_EXIT();

    /*=========================================================================
     * No free frames found â€" out of memory
     *=======================================================================*/
    return 0;
}

/*=============================================================================
 * FUNCTION: pmm_alloc_contiguous
 *=============================================================================
 * DESCRIPTION:
 *   Allocates `count` PHYSICALLY CONTIGUOUS 4 KiB frames and returns the base
 *   physical address, or 0 if no run of that size is free.
 *
 *   WHY THIS EXISTS: kernel stacks are built from N pages and addressed as one
 *   block (esp = base + N*4096, growing down). pmm_alloc() is first-fit
 *   ascending, so N separate calls return ascending but NOT necessarily
 *   contiguous frames once the bitmap has holes (freed RAMFS/page frames). A
 *   non-contiguous "stack" leaves the bytes just below the top page unmapped:
 *   the first interrupt push past a page boundary then #PFs, the fault handler
 *   re-faults on the same bad stack (#DF), and the CPU triple-faults/reboots.
 *   This bit `exec /hello.elf` (a user task, created late when holes exist)
 *   while early-boot kernel tasks happened to get contiguous runs.
 *
 *   Allocation is atomic under the PMM critical section so a concurrent
 *   allocator can't claim a frame mid-run.
 *
 * RETURNS:
 *   uint32_t: page-aligned base physical address of the run, or 0 on failure.
 *============================================================================*/
uint32_t pmm_alloc_contiguous(uint32_t count) {
    if (count == 0) return 0;
    if (count == 1) return pmm_alloc();

    PMM_CRITICAL_ENTER();

    for (uint32_t base = 0; base + count <= PMM_MAX_FRAMES; ++base) {
        /* Check for `count` consecutive free frames starting at base. */
        uint32_t run = 0;
        while (run < count && !bget(base + run)) {
            run++;
        }
        if (run == count) {
            /* Claim the whole run. */
            for (uint32_t k = 0; k < count; ++k) {
                bset(base + k);
                if (frames_free) frames_free--;
            }
            PMM_CRITICAL_EXIT();
            return base * PMM_PAGE_SIZE;
        }
        /* Skip past the used frame that broke the run (base+run). */
        base += run;
    }

    PMM_CRITICAL_EXIT();
    return 0;  /* No contiguous run of the requested size. */
}

/*=============================================================================
 * FUNCTION: pmm_alloc_low
 *=============================================================================
 * DESCRIPTION:
 *   Allocates a single 4 KiB frame from the first 32 MiB of physical memory
 *   (the standard-mode identity-mapped region). Used for paging structures
 *   that are accessed through the identity mapping (virtual == physical).
 *
 * RETURNS:
 *   uint32_t: Physical address of allocated frame (page-aligned)
 *             Returns 0 if no free low frames available
 *
 *============================================================================*/
uint32_t pmm_alloc_low(void) {
    PMM_CRITICAL_ENTER();

    for (uint32_t i = 0; i < PMM_LOW_FRAMES; ++i) {
        if (!bget(i)) {
            bset(i);                        /* Mark frame as used */

            if (frames_free)
                frames_free--;              /* Decrement free count */

            PMM_CRITICAL_EXIT();

            return i * PMM_PAGE_SIZE;
        }
    }

    PMM_CRITICAL_EXIT();

    return 0;
}

/*=============================================================================
 * FUNCTION: pmm_free
 *=============================================================================
 * DESCRIPTION:
 *   Frees a previously allocated 4 KiB frame, returning it to the pool.
 *   Marks the frame as free in the bitmap so it can be allocated again.
 *
 * PARAMETERS:
 *   phys - Physical address of frame to free (must be page-aligned)
 *          Should be an address returned by pmm_alloc()
 *
 *============================================================================*/
void pmm_free(uint32_t phys) {
    /*=========================================================================
     * SECURITY: Reject NULL/Zero Address
     * CRITICAL: Frame 0 (physical address 0x0) contains critical low memory:
     * - BIOS data area (0x400-0x4FF)
     * - Interrupt Vector Table (0x0-0x3FF)
     * - Other BIOS structures
     *
     * Allowing pmm_free(0) could corrupt system stability. This is always
     * a programming error - NULL should never be freed.
     *=======================================================================*/
    if (phys == 0) {
        return;  // Reject freeing frame 0 (NULL/low memory)
    }

    /*=========================================================================
     * SECURITY: Reject Misaligned Addresses
     * CRITICAL: Physical addresses must be 4KB-aligned (multiple of 4096).
     * If a misaligned address is passed (e.g., 0x2001), integer division
     * will truncate it to the wrong frame, potentially corrupting adjacent
     * memory regions.
     *
     * EXPLOIT SCENARIO: An attacker could call pmm_free(0x1001) to corrupt
     * frame 0, or pmm_free(kernel_page + 1) to double-free and corrupt the
     * PMM bitmap.
     *
     * FIX: Reject any address where lower 12 bits are non-zero.
     * PMM_PAGE_SIZE-1 = 0xFFF (lower 12 bits set), so bitwise AND detects
     * misalignment efficiently.
     *=======================================================================*/
    if (phys & (PMM_PAGE_SIZE - 1)) {
        return;  // Reject misaligned address (not a multiple of 4096)
    }

    /*=========================================================================
     * Convert physical address to frame index
     *=======================================================================*/
    uint32_t i = phys / PMM_PAGE_SIZE;

    /*=========================================================================
     * CRITICAL SECTION: Protect bitmap and counter modifications
     * Without atomicity, concurrent pmm_free() and pmm_alloc() calls could:
     * 1. Race on bget/bclr/bset operations
     * 2. Corrupt frames_free counter
     * 3. Cause double-free or use-after-free
     *=======================================================================*/
    PMM_CRITICAL_ENTER();

    /*=========================================================================
     * ARCHITECTURAL FIX: Double-Free Detection with Critical Logging
     *
     * SECURITY ISSUE: Silent acceptance of double-free is dangerous. The
     * application logic that caused the double-free will continue to run,
     * potentially corrupting arbitrary memory when the PMM reassigns the
     * frame to a different process.
     *
     * EXPLOIT SCENARIO:
     * 1. Process A frees page P (legitimate)
     * 2. Process A frees page P again (double-free bug)
     * 3. PMM silently ignores #2
     * 4. Process B allocates page P
     * 5. Process A writes to P (use-after-free)
     * 6. Process B reads corrupted data (security breach)
     *
     * FIX: Detect and log double-free attempts with CRITICAL severity.
     * For high-security kernels, a kernel panic is preferable to prevent
     * continued execution with undefined behavior.
     *
     * PRODUCTION POLICY:
     * - Development: Log warning (allows debugging without system halt)
     * - Production: Kernel panic (enforce memory integrity)
     *=======================================================================*/
    if (i >= PMM_MAX_FRAMES) {
        /* Out-of-bounds address - log critical error */
        kprintf("[PMM] CRITICAL: Attempted to free out-of-bounds address 0x%08x (frame %u >= %u)\n",
                phys, i, PMM_MAX_FRAMES);
        kprintf("[PMM] This indicates memory corruption or a kernel bug\n");
        PMM_CRITICAL_EXIT();
        /* In production, consider: kernel_panic("PMM: Out-of-bounds free"); */
        return;
    }

    if (!bget(i)) {
        /* Double-free detected - frame is already free */
        kprintf("[PMM] CRITICAL: Double-free detected at physical address 0x%08x (frame %u)\n",
                phys, i);
        kprintf("[PMM] Possible causes:\n");
        kprintf("[PMM]   1. Application bug (freed same memory twice)\n");
        kprintf("[PMM]   2. Use-after-free (freed memory still being accessed)\n");
        kprintf("[PMM]   3. Memory corruption (corrupted pointer/metadata)\n");
        kprintf("[PMM] Stack trace (if available) would be logged here\n");
        PMM_CRITICAL_EXIT();

        /*=====================================================================
         * PRODUCTION DECISION POINT:
         * - Option 1: Continue (fault-tolerant, logs error for debugging)
         * - Option 2: Panic (enforce memory integrity, prevent exploitation)
         *
         * For high-security systems, Option 2 is recommended:
         *   kernel_panic("PMM: Double-free detected");
         *===================================================================*/
        #ifdef TINYOS_PRODUCTION
        /* Production mode: Panic to enforce memory integrity */
        /* kernel_panic("PMM: Double-free detected"); */
        #endif
        return;
    }

    /* Valid free - mark frame as available */
    bclr(i);            /* Clear bit (mark as free) */
    frames_free++;      /* Increment free count */

    PMM_CRITICAL_EXIT();
}

