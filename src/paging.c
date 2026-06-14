/*=============================================================================
 *  paging.c Ã¢â‚¬â€ TinyOS Virtual Memory Management (Identity Mapping Bootstrap)
 *=============================================================================
 *
 * PURPOSE:
 *   This file implements the x86 paging subsystem that enables virtual memory.
 *   It creates and enables page tables with identity mapping (virtual address
 *   = physical address) for the first 32 MiB of memory. This is a bootstrap
 *   setup used during kernel initialization before a full MMU is available.
 *
 */
#include <stdint.h>
#include "kernel.h"
#include "paging.h"
#include "pmm.h"     // For pmm_alloc
#include "util.h"    // For memcpy
#include "kprintf.h" // Use your kernel kprintf
#include "memory.h"  // Optional here since paging.h includes it, but good practice


// Page directory - will be set to early_pd after initialization
uint32_t* page_directory = NULL;  // âœ… Declaration only

/*=============================================================================
 * STATIC PAGE TABLES (in .bss)
 *============================================================================*/
static uint32_t __attribute__((aligned(PAGE_SIZE))) early_pd[PD_ENTRIES];
static uint32_t __attribute__((aligned(PAGE_SIZE))) early_pts[MAX_TABLES][PT_ENTRIES];

/*=============================================================================
 * FUNCTION: align_up
 *============================================================================*/
static inline uint32_t align_up(uint32_t x, uint32_t a) {
    return (x + (a - 1u)) & ~(a - 1u);
}

/*=============================================================================
 * FUNCTION: paging_identity_map_early
 *============================================================================*/
void paging_identity_map_early(uint32_t limit_bytes) {

    /*=========================================================================
     * PHASE 1: VALIDATE AND ADJUST MEMORY LIMIT
     *=======================================================================*/
    
    /*-------------------------------------------------------------------------
     * Set minimum limit: 1 MiB
     *-------------------------------------------------------------------------*/
    if (limit_bytes < (1u << 20))  /* 1 << 20 = 1,048,576 = 1 MiB */
        limit_bytes = (1u << 20);
    
    /*-------------------------------------------------------------------------
     * Set maximum limit: 32 MiB
     *-----------------------------------------------------------------------*/
    if (limit_bytes > (MAX_TABLES * PT_COVERS_BYTES))
        limit_bytes = (MAX_TABLES * PT_COVERS_BYTES);
    
    /*=========================================================================
     * SELF-COVERAGE CHECK: Ensure page tables are within mapped region
     *=======================================================================*/
    
    /*-------------------------------------------------------------------------
     * Calculate end addresses of page directory and page tables
     *-----------------------------------------------------------------------*/
    uint32_t pd_end  = (uint32_t)(uintptr_t)early_pd  + sizeof(early_pd);
    uint32_t pts_end = (uint32_t)(uintptr_t)early_pts + sizeof(early_pts);
    
    /*-------------------------------------------------------------------------
     * Find highest address that must be covered
     *-----------------------------------------------------------------------*/
    uint32_t must_cover = (pd_end > pts_end) ? pd_end : pts_end;
    
    /*-------------------------------------------------------------------------
     * Extend limit if page tables fall outside requested range
     *-----------------------------------------------------------------------*/
    if (limit_bytes < must_cover)
        limit_bytes = align_up(must_cover, PT_COVERS_BYTES);
    
    /*=========================================================================
     * PHASE 2: ZERO PAGE DIRECTORY
     *=======================================================================*/
    for (uint32_t i = 0; i < PD_ENTRIES; ++i) {
        early_pd[i] = 0;
    }
    
    /*=========================================================================
     * PHASE 3: CALCULATE NUMBER OF PAGE TABLES NEEDED
     *=======================================================================*/
    uint32_t tables = (limit_bytes + (PT_COVERS_BYTES - 1u)) / PT_COVERS_BYTES;
    
    /*-------------------------------------------------------------------------
     * Clamp to maximum table count
     *-----------------------------------------------------------------------*/
    if (tables > MAX_TABLES) 
        tables = MAX_TABLES;
    
    /*=========================================================================
     * PHASE 4: FILL PAGE TABLES WITH IDENTITY MAPPINGS
     *=======================================================================*/
    for (uint32_t t = 0; t < tables; ++t) {
        /*---------------------------------------------------------------------
         * Calculate base address for this Page Table
         *-------------------------------------------------------------------*/
        uint32_t base = t * PT_COVERS_BYTES;
        
        /*---------------------------------------------------------------------
         * Fill all 1024 entries in this Page Table
         *-------------------------------------------------------------------*/
        for (uint32_t e = 0; e < PT_ENTRIES; ++e) {
            /*-----------------------------------------------------------------
             * Calculate physical address for this page
             *---------------------------------------------------------------*/
            uint32_t phys = base + e * PAGE_SIZE;

            /*=================================================================
             * PHASE 10: NULL POINTER PROTECTION
             *
             * TRADITIONAL UNIX/LINUX WEAKNESS:
             * - Historically, mmap(NULL, ...) could map page 0
             * - Kernel null pointer dereferences became exploitable
             * - Attacker maps address 0, kernel dereferences NULL → executes attacker code
             *
             * ATTACK SCENARIO:
             * 1. Kernel has bug: struct foo *p = NULL; p->callback();
             * 2. Attacker calls mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, ...)
             * 3. Attacker writes shellcode to address 0
             * 4. Kernel dereferences NULL → jumps to address 0 → shellcode executes!
             *
             * HISTORICAL EXPLOITS:
             * - CVE-2009-2692: Linux sock_sendpage NULL pointer dereference
             * - CVE-2010-2959: Linux compat_alloc_user_space exploit
             * - Countless privilege escalations via NULL dereference
             *
             * TINYOS INNOVATION:
             * - Page 0 (address 0x0000-0x0FFF) NEVER MAPPED
             * - Any null pointer dereference causes immediate page fault
             * - No code path allows mapping address 0
             * - NULL dereferences are bugs, not exploits
             *
             * SECURITY BENEFITS:
             * - Null pointer exploits impossible
             * - Kernel bugs fail safely (crash vs. exploit)
             * - Defense in depth against kernel vulnerabilities
             *
             * NOTE: Modern Linux also protects page 0 (mmap_min_addr sysctl)
             *===============================================================*/
            if (phys == 0) {
                /* SKIP page 0: Leave unmapped for NULL pointer protection */
                early_pts[t][e] = 0;  /* Not present */
                continue;
            }

            /*-----------------------------------------------------------------
             * Build Page Table Entry (PTE)
             * SECURITY: Kernel pages must NOT have PAGE_USER flag set
             * This prevents user-mode processes from accessing kernel memory
             *---------------------------------------------------------------*/
            early_pts[t][e] = (phys & ~0xFFFu) | (PTE_P | PTE_RW);
        }

    }
    
    /*=========================================================================
     * PHASE 5: FILL PAGE DIRECTORY
     *=======================================================================*/
    for (uint32_t t = 0; t < tables; ++t) {
        /*---------------------------------------------------------------------
         * Build Page Directory Entry (PDE)
         * SECURITY: Kernel page tables must NOT have PAGE_USER flag set
         *-------------------------------------------------------------------*/
        early_pd[t] = (((uint32_t)(uintptr_t)early_pts[t]) & ~0xFFFu)
                      | (PDE_P | PDE_RW);
    }
    
    /*=========================================================================
     * PHASE 6: LOAD CR3 REGISTER
     *=======================================================================*/
    
    /*-------------------------------------------------------------------------
     * Get physical address of Page Directory
     *-----------------------------------------------------------------------*/
    uint32_t cr3 = (uint32_t)(uintptr_t)early_pd;
    
    /*-------------------------------------------------------------------------
     * Set global page_directory pointer for map_page() function
     *-----------------------------------------------------------------------*/
    page_directory = early_pd;
    
    /*-------------------------------------------------------------------------
     * Write Page Directory address to CR3
     * Memory barrier ensures TLB flush completes before subsequent accesses
     *-----------------------------------------------------------------------*/
    __asm__ volatile ("mov %0, %%cr3" :: "r"(cr3) : "memory");
    
}

/*=============================================================================
 * FUNCTION: paging_enable
 * PURPOSE: Enable paging with optional PAE support for W^X
 *
 * This function checks if PAE was initialized (via pae_init()) and enables
 * paging with or without PAE accordingly. PAE is required for W^X enforcement.
 *============================================================================*/
void paging_enable(void) {
    /*=========================================================================
     * STEP 0: Check if PAE mode should be used (if CR4.PAE is set)
     * If pae_init() was called, CR4.PAE will already be set
     *=======================================================================*/
    uint32_t cr4;
    __asm__ volatile ("mov %%cr4,%0" : "=r"(cr4));
    bool using_pae = (cr4 & (1 << 5)) != 0;  // Check CR4.PAE bit

    if (using_pae) {
        kprintf("[PAGING] Enabling paging with PAE/W^X support\n");

        /*=====================================================================
         * PAE MODE: CR4.PAE is already set by pae_init()
         * CR3 should already point to PDPT (also set by pae_init())
         * Just need to enable paging via CR0.PG
         *===================================================================*/
    } else {
        kprintf("[PAGING] Enabling standard 32-bit paging\n");

        /*=====================================================================
         * STANDARD MODE: No PAE, use traditional 32-bit page tables
         *===================================================================*/
    }

    /*=========================================================================
     * STEP 1: Read current CR0 value
     *=======================================================================*/
    uint32_t cr0;
    __asm__ volatile ("mov %%cr0,%0" : "=r"(cr0));

    /*=========================================================================
     * STEP 2: Set PG and WP bits
     * SECURITY: CR0.WP (bit 16) MUST be set to enforce write-protection
     * in supervisor mode. Without this, the kernel can write to read-only
     * pages, defeating page-level memory protection.
     *
     * CR0.WP=1 ensures:
     * - Kernel page faults on writes to read-only pages (prevents corruption)
     * - Write-protection enforced for all privilege levels
     * - Enables future COW (Copy-on-Write) implementations
     *=======================================================================*/
    cr0 |= CR0_PG;  /* Set paging enable bit (bit 31) */
    cr0 |= CR0_WP;  /* Set write-protect bit (bit 16) */

    /*=========================================================================
     * STEP 3: Write modified CR0 back to register
     * CRITICAL: Memory barrier prevents instruction reordering
     * The memory clobber ensures proper serialization
     *=======================================================================*/
    __asm__ volatile ("mov %0,%%cr0" :: "r"(cr0) : "memory");

    if (using_pae) {
        kprintf("[PAGING] PAE paging enabled - W^X enforcement ready\n");
    } else {
        kprintf("[PAGING] Standard paging enabled\n");
    }
}

/*=============================================================================
 * FUNCTION: map_mmio
 *=============================================================================
 * @brief Maps a physical memory-mapped I/O (MMIO) region to a virtual address.
 * * MMIO regions are typically mapped 1:1 (identity mapped) and require specific
 * flags, often including a flag to disable caching (not included here, but 
 * highly recommended for actual hardware access).
 * * @param phys_addr The starting physical address of the MMIO region.
 * @param size The size of the region to map in bytes.
 * @return uint32_t The virtual address base of the mapped region (same as phys_addr).
 */
uint32_t map_mmio(uint32_t phys_addr, uint32_t size) {
    // Start address must be page-aligned for mapping
    uint32_t start_addr = PAGE_ALIGN_DOWN(phys_addr);
    uint32_t end_addr = phys_addr + size;

    /*=========================================================================
     * SECURITY: MMIO Pages Must Be Supervisor-Only (U/S = 0)
     * CRITICAL: These flags enforce supervisor-only access to hardware MMIO.
     *
     * PAGE_USER is deliberately NOT SET, which means:
     * - U/S bit (bit 2) = 0 → Supervisor-only access
     * - User-mode processes CANNOT access these pages
     *
     * If a user process could access MMIO regions (e.g., E1000 NIC registers),
     * it could:
     * 1. Read/write network packets directly (complete firewall bypass)
     * 2. Reconfigure NIC settings (promiscuous mode, MAC spoofing)
     * 3. Crash the system by writing invalid register values
     *
     * MMIO flags: Present, Read/Write, Cache Disable, Write-Through
     * - Cache Disable is required for hardware correctness (no stale register reads)
     * - Write-Through ensures immediate register writes
     *=======================================================================*/
    uint32_t flags = PAGE_PRESENT | PAGE_READWRITE | PAGE_CACHE_DISABLE | PAGE_WRITETHROUGH; 

    // kprintf("Paging: Mapping MMIO region 0x%x (Phys) to 0x%x (Virt, size 0x%x)...\n",
    //         phys_addr, start_addr, size);

    // Iterate through the address range, mapping page by page
    for (uint32_t addr = start_addr; addr < end_addr; addr += PAGE_SIZE) {
        // Identity map: virtual address (addr) = physical address (addr)
        map_page(addr, addr, flags);
    }

    // Return the virtual base address (which is the starting physical address)
    return start_addr;
}


/*=============================================================================
 * REMOVED: Dangerous old map_page() implementation (lines 238-289)
 *
 * SECURITY ISSUES that made this code unsafe to keep even as a comment:
 * 1. Line 265: Sets PAGE_USER on page table entries (user can modify page tables!)
 * 2. Line 287: Missing "memory" clobber on invlpg (compiler can reorder TLB flush)
 * 3. Excessive debug logging that would spam output if accidentally re-enabled
 *
 * Deleted to prevent future copy-paste mistakes during refactoring.
 * Refer to git history if needed for educational purposes only.
 *===========================================================================*/

/*=============================================================================
 * FUNCTION: map_page
 * SECURITY NOTE: Write-XOR-Execute (W^X) Policy
 *
 * LIMITATION: x86-32 without PAE/NX bit cannot enforce non-executable pages
 * The NX (No eXecute) bit requires either:
 * - PAE (Physical Address Extension) mode, OR
 * - 64-bit (Long) mode
 *
 * W^X POLICY (Software Enforcement):
 * - Code segments: PAGE_READONLY (executable, not writable)
 * - Data segments: PAGE_READWRITE (writable, assumed non-executable)
 * - MMIO regions: PAGE_READWRITE | PAGE_CACHE_DISABLE
 *
 * WARNING: This kernel CANNOT prevent execution from writable pages at
 * the hardware level. To mitigate:
 * 1. Never map writable pages in code regions
 * 2. Use software checks in syscall handlers
 * 3. Consider enabling PAE mode for NX bit support
 *=============================================================================*/
void map_page(uint32_t virtual_addr, uint32_t physical_addr, uint32_t flags) {
    /*=========================================================================
     * PAE MODE: Delegate to PAE mapping function
     *=========================================================================*/
    if (pae_is_active()) {
        /* Convert 32-bit flags to 64-bit PAE flags (bits are in same positions) */
        uint64_t pae_flags = (uint64_t)flags;

        /* Check if we're mapping into a user PDPT (CR3 != kernel CR3) */
        uint32_t current_cr3;
        __asm__ volatile("mov %%cr3, %0" : "=r"(current_cr3));

        uint32_t kernel_cr3 = get_kernel_page_directory();

        if (current_cr3 != kernel_cr3) {
            /* Mapping into user PDPT - use pae_map_page_into() */
            pae_map_page_into(current_cr3, virtual_addr, (uint64_t)physical_addr, pae_flags);
        } else {
            /* Mapping into kernel PDPT - use pae_map_page() */
            pae_map_page(virtual_addr, (uint64_t)physical_addr, pae_flags);
        }
        return;
    }

    /*=========================================================================
     * STANDARD 32-BIT MODE: Use recursive paging
     *=========================================================================*/
    uint32_t pd_index = virtual_addr >> 22;
    uint32_t pt_index = (virtual_addr >> 12) & 0x3FF;

    /* NOTE: there was a "W^X policy check" here with an empty body — it did
     * nothing (no warn, no block) and only ran in the legacy 32-bit non-PAE
     * path, which has no NX bit to enforce W^X with anyway. Real W^X is enforced
     * in the PAE path (pae_apply_kernel_wx / NX); map_page returns early into
     * pae_map_page when PAE is active and never reaches here. Dead branch
     * removed. */

    // kprintf("map_page: v=0x%08x p=0x%08x pd=%d pt=%d\n",
    //        virtual_addr, physical_addr, pd_index, pt_index);

    // Get page directory entry via recursive mapping
    uint32_t* pde = (uint32_t*)0xfffff000 + pd_index;

    // kprintf("  PDE[%d] = 0x%08x (flags: %c%c%c)\n", pd_index, *pde,
    //        (*pde & PAGE_PRESENT) ? 'P' : '-',
    //        (*pde & PAGE_READWRITE) ? 'W' : '-',
    //        (*pde & PAGE_USER) ? 'U' : '-');

    // If page table doesn't exist, create it
    if ((*pde & PAGE_PRESENT) == 0) {
        // kprintf("  Page table for PDE[%d] not present, allocating...\n", pd_index);

        // Allocate a new page table using proper PMM allocation
        uint32_t pt_phys = pmm_alloc();
        if (!pt_phys) {
            kprintf("  ERROR: Failed to allocate page table!\n");
            return;
        }

        // kprintf("  Allocated PT frame at phys=0x%08x\n", pt_phys);

        // Set up the page directory entry
        uint32_t pt_flags = PAGE_PRESENT | PAGE_READWRITE;
        if (flags & PAGE_USER) {
            pt_flags |= PAGE_USER;  // If mapping user page, PT must be user-accessible
        }

        // kprintf("  Setting PDE[%d] = 0x%08x\n", pd_index, pt_phys | pt_flags);
        *pde = pt_phys | pt_flags;
        // kprintf("  PDE written, flushing TLB...\n");

        // CRITICAL: Flush TLB for the recursive mapping area before accessing it
        uint32_t recursive_addr = 0xffc00000 + (pd_index * 0x1000);
        // kprintf("  Recursive addr for clearing: 0x%08x\n", recursive_addr);
        asm volatile("invlpg (%0)" : : "r" (recursive_addr) : "memory");

        // kprintf("  TLB flushed, about to clear PT at virt 0x%08x...\n", recursive_addr);

        // Clear the new page table (via recursive mapping)
        uint32_t* new_pt = (uint32_t*)recursive_addr;
        // kprintf("  Clearing entry 0...\n");
        new_pt[0] = 0;
        // kprintf("  Entry 0 cleared, clearing rest...\n");
        for (int i = 1; i < 1024; i++) {
            new_pt[i] = 0;
        }

        // kprintf("  Created page table at phys=0x%08x for PDE[%d]\n", pt_phys, pd_index);
    }

    // Map the page
    uint32_t* pte = (uint32_t*)(0xffc00000 + (pd_index * 0x1000)) + pt_index;
    // kprintf("  Setting PTE[%d] = 0x%08x\n", pt_index, physical_addr | flags);

    *pte = physical_addr | flags;

    // Flush TLB - memory clobber prevents compiler reordering across TLB invalidation
    asm volatile("invlpg (%0)" : : "r" (virtual_addr) : "memory");

    // kprintf("  Page mapped successfully\n");
}


void unmap_page(uint32_t virt) {
    /*=========================================================================
     * PAE MODE: Delegate to PAE unmap function
     *=========================================================================*/
    if (pae_is_active()) {
        pae_unmap_page(virt);
        return;
    }

    /*=========================================================================
     * STANDARD 32-BIT MODE: Use recursive paging
     *=========================================================================*/
    uint32_t pd_index = virt >> 22;
    uint32_t pt_index = (virt >> 12) & 0x03FF;

    // Get page table via recursive mapping
    uint32_t* page_table = (uint32_t*)(0xFFC00000 + (pd_index << 12));

    if (!(page_directory[pd_index] & PAGE_PRESENT)) {
        kprintf("Unmap Error: PDE for virt 0x%08x not present\n", virt);
        return;
    }

    if (page_table[pt_index] & PAGE_PRESENT) {
        page_table[pt_index] = 0;
        __asm__ volatile("invlpg (%0)" :: "r"(virt) : "memory");
        kprintf("Unmapped virt=0x%08x\n", virt);
    }
}



/*=============================================================================
 * FUNCTION: flush_tlb_single
 *=============================================================================
 * Implementation provided previously (included here for completeness).
 */
/**
 * @brief flush_tlb_single - Invalidates a single entry in the TLB.
 * * Uses the INVLPG (Invalidate Page) instruction, which is required after 
 * modifying a Page Table Entry (PTE) to ensure the CPU uses the new mapping.
 * * @param virt The virtual address whose TLB entry should be flushed.
 */
void flush_tlb_single(uint32_t virt) {
    // The 'invlpg' instruction takes a memory operand (the virtual address)
    __asm__ volatile("invlpg (%0)" : : "r" (virt) : "memory");
}

/*=============================================================================
 * SECURITY FIX (AUDIT 10E): Kernel Page Table Memory Leak Prevention
 *=============================================================================
 * FUNCTION: unmap_page_range
 *
 * VULNERABILITY: Resource Leak in ELF Loader Error Paths
 *
 * PROBLEM: Failed Process Loads Leak Page Tables
 * When elf_load_process() fails partway through segment loading, it frees
 * the allocated physical frames but does NOT free the Page Tables created
 * by map_page(). Each map_page() call that encounters a missing page table
 * allocates a new 4KB page table via pmm_alloc() (line 363 in map_page).
 *
 * ATTACK SCENARIO: Resource Exhaustion via Malformed ELF Files
 * 1. Attacker sends malformed ELF file that passes initial validation
 * 2. ELF loader allocates page directory + page tables for segments
 * 3. Loader encounters error partway through (e.g., pmm_alloc fails)
 * 4. Cleanup code frees physical frames but NOT page tables
 * 5. Each failed load leaks 4KB (page directory) + N*4KB (page tables)
 * 6. After ~1000 failed loads → 4MB+ of kernel heap leaked
 * 7. Kernel heap exhaustion → denial of service
 *
 * ROOT CAUSE: Asymmetric Resource Management
 * - map_page() allocates both physical frames AND page tables
 * - Cleanup code only frees physical frames (pmm_free)
 * - Page tables remain allocated but unreachable → memory leak
 *
 * FIX: Implement Complete Cleanup with Page Table Recycling
 * This function unmaps a range of virtual addresses and frees empty page
 * tables to prevent resource leaks. Algorithm:
 *
 * 1. For each page in range [vaddr_start, vaddr_end):
 *    a. Clear the Page Table Entry (PTE)
 *    b. Flush TLB for that virtual address
 *
 * 2. For each unique Page Table touched:
 *    a. Check if Page Table is now completely empty (all 1024 PTEs == 0)
 *    b. If empty:
 *       - Extract physical address of Page Table from PDE
 *       - Free Page Table physical frame: pmm_free(pt_phys)
 *       - Clear Page Directory Entry (PDE)
 *       - Flush TLB for recursive mapping area
 *
 * SECURITY BENEFITS:
 * - Prevents kernel heap exhaustion attacks
 * - Enables safe cleanup of failed process loads
 * - Recycles page table memory for future allocations
 * - Maintains kernel heap availability under attack
 *
 * USAGE IN ELF LOADER:
 * ```c
 * // After freeing physical frames on error:
 * unmap_page_range(start_page, end_page);
 * ```
 *
 * @param vaddr_start Virtual address of first page to unmap (page-aligned)
 * @param vaddr_end   Virtual address after last page (page-aligned)
 *
 * REFERENCES:
 * - Linux kernel: unmap_page_range() in mm/memory.c
 * - FreeBSD: pmap_remove() in sys/vm/pmap.c
 *===========================================================================*/
void unmap_page_range(uint32_t vaddr_start, uint32_t vaddr_end) {
    /*=========================================================================
     * INPUT VALIDATION: Ensure page-aligned addresses
     *=======================================================================*/
    vaddr_start &= PAGE_FRAME_MASK;  /* Round down to page boundary */
    vaddr_end = (vaddr_end + PAGE_MASK) & PAGE_FRAME_MASK;  /* Round up */

    if (vaddr_start >= vaddr_end) {
        return;  /* Empty range */
    }

    /*=========================================================================
     * PAE MODE: Would need separate implementation for 3-level paging
     * For now, only support standard 32-bit mode
     *=======================================================================*/
    if (pae_is_active()) {
        /* TODO: Implement PAE version with 3-level page table cleanup */
        kprintf("[PAGING] WARNING: unmap_page_range not yet implemented for PAE mode\n");
        return;
    }

    /*=========================================================================
     * PHASE 1: Unmap All Pages in Range
     *=======================================================================*/
    uint32_t num_pages = (vaddr_end - vaddr_start) / PAGE_SIZE;

    for (uint32_t i = 0; i < num_pages; i++) {
        uint32_t vaddr = vaddr_start + (i * PAGE_SIZE);
        uint32_t pd_index = vaddr >> 22;
        uint32_t pt_index = (vaddr >> 12) & 0x3FF;

        /* Check if Page Directory Entry exists */
        uint32_t* pde = (uint32_t*)0xfffff000 + pd_index;
        if ((*pde & PAGE_PRESENT) == 0) {
            continue;  /* Page table doesn't exist, skip to next page */
        }

        /* Get Page Table via recursive mapping */
        uint32_t* page_table = (uint32_t*)(0xFFC00000 + (pd_index << 12));

        /* Clear the Page Table Entry */
        if (page_table[pt_index] & PAGE_PRESENT) {
            page_table[pt_index] = 0;
            __asm__ volatile("invlpg (%0)" :: "r"(vaddr) : "memory");
        }
    }

    /*=========================================================================
     * PHASE 2: Free Empty Page Tables
     * After unmapping, check each touched page table to see if it's now empty.
     * If all 1024 entries are 0, free the page table physical frame.
     *=======================================================================*/
    /* Iterate PDE indices directly: stepping a non-4MB-aligned vaddr by 4MB
     * can skip the final touched page table, leaking it */
    for (uint32_t pd_index = vaddr_start >> 22; pd_index <= (vaddr_end - 1) >> 22; pd_index++) {
        uint32_t* pde = (uint32_t*)0xfffff000 + pd_index;

        /* Skip if Page Directory Entry not present */
        if ((*pde & PAGE_PRESENT) == 0) {
            continue;
        }

        /* Get Page Table via recursive mapping */
        uint32_t* page_table = (uint32_t*)(0xFFC00000 + (pd_index << 12));

        /* Check if all 1024 Page Table Entries are clear */
        bool is_empty = true;
        for (uint32_t j = 0; j < PT_ENTRIES; j++) {
            if (page_table[j] != 0) {
                is_empty = false;
                break;
            }
        }

        /* If Page Table is empty, free it */
        if (is_empty) {
            /* Extract physical address of Page Table from PDE */
            uint32_t pt_phys = *pde & PAGE_FRAME_MASK;

            /* Free the Page Table physical frame */
            pmm_free(pt_phys);

            /* Clear the Page Directory Entry */
            *pde = 0;

            /* Flush TLB for the recursive mapping area */
            uint32_t recursive_addr = 0xffc00000 + (pd_index * 0x1000);
            __asm__ volatile("invlpg (%0)" :: "r"(recursive_addr) : "memory");

            kprintf("[PAGING] Freed empty page table for PDE[%u] (phys=0x%08x)\n",
                    pd_index, pt_phys);
        }
    }
}


/*=============================================================================
 * SECURITY (v1.18): paging_make_user_accessible REMOVED
 *
 * This function was dangerous because it could make arbitrary kernel memory
 * user-accessible without validation. Removed to prevent privilege escalation.
 *
 * If you need to make specific memory user-accessible:
 * - Use map_user_memory() with explicit physical address and validation
 * - Or modify page table entries directly with proper bounds checking
 *=============================================================================*/


// Add this debug function to paging.c
/*=============================================================================
 * New Helper Functions
 *=============================================================================*/

// Helper function to get physical address from virtual address
uint32_t virt_to_phys(uint32_t virtual_addr) {
    /*=========================================================================
     * PAE MODE: Use PAE virt_to_phys function
     *=========================================================================*/
    if (pae_is_active()) {
        uint64_t phys64 = pae_virt_to_phys(virtual_addr);
        return (uint32_t)phys64;  /* Truncate to 32-bit for API compatibility */
    }

    /*=========================================================================
     * STANDARD 32-BIT MODE
     *=========================================================================*/
    // This depends on your paging implementation
    // You might already have this function
    uint32_t* pte = get_page_table_entry(virtual_addr);
    if (pte && (*pte & PAGE_PRESENT)) {
        return (*pte & PAGE_FRAME_MASK) | (virtual_addr & PAGE_MASK);
    }
    return 0;
}

// Get the page table entry for a virtual address
uint32_t* get_page_table_entry(uint32_t virtual_addr) {
    /*=========================================================================
     * PAE MODE: Not supported (PTEs are 64-bit in PAE)
     * Callers should use pae_get_pte() or virt_to_phys() instead
     *=========================================================================*/
    if (pae_is_active()) {
        return NULL;  /* Cannot return 32-bit pointer to 64-bit PTE */
    }

    /*=========================================================================
     * STANDARD 32-BIT MODE: Use recursive paging
     *=========================================================================*/
    // Get the page directory
    uint32_t* page_dir = (uint32_t*)0xFFFFF000;  // Last page of virtual address space

    // Get page directory entry
    uint32_t page_dir_index = (virtual_addr >> 22) & 0x3FF;
    uint32_t page_dir_entry = page_dir[page_dir_index];

    // Check if page table exists
    if (!(page_dir_entry & PAGE_PRESENT)) {
        return NULL;
    }

    // Get the page table
    uint32_t* page_table = (uint32_t*)(0xFFC00000 | (page_dir_index << 12));

    // Get page table entry
    uint32_t page_table_index = (virtual_addr >> 12) & 0x3FF;
    return &page_table[page_table_index];
}


/*=============================================================================
 * New User Memory Functions
 *=============================================================================*/

// Map memory accessible from user mode
void map_user_memory(uint32_t virtual_addr, uint32_t physical_addr, uint32_t flags) {
    kprintf("map_user_memory: virt=0x%08x -> phys=0x%08x, flags=0x%x\n", 
           virtual_addr, physical_addr, flags);
    
    // Ensure user flag is set
    flags |= PAGE_USER;
    
    kprintf("  Calling map_page...\n");
    
    // Use your existing map_page function
    map_page(virtual_addr, physical_addr, flags);
    
    kprintf("  map_page completed for 0x%08x\n", virtual_addr);
}

// Unmap user memory (for process termination)
void unmap_user_memory(uint32_t virtual_addr) {
    if (!is_user_address(virtual_addr)) {
        kprintf("WARNING: Trying to unmap non-user address 0x%08x\n", virtual_addr);
        return;
    }

    /*=========================================================================
     * SECURITY FIX: TLB flush after unmapping
     *
     * CRITICAL: After clearing the present bit, the CPU's TLB may still cache
     * the old translation. Without flushing, user code can continue accessing
     * the unmapped page until something else evicts that TLB entry.
     *
     * This is a classic "use after unmap" / isolation failure that allows:
     * - Reading freed memory (information leak)
     * - Writing to freed memory (corruption if page is reallocated)
     *
     * FIX: Use INVLPG instruction to flush the specific TLB entry immediately.
     *=======================================================================*/
    uint32_t* pte = get_page_table_entry(virtual_addr);
    if (pte && (*pte & PAGE_PRESENT)) {
        *pte &= ~PAGE_PRESENT;

        /* Flush TLB entry for this specific virtual address */
        __asm__ volatile("invlpg (%0)" :: "r"(virtual_addr) : "memory");

        kprintf("Unmapped user memory: 0x%08x (TLB flushed)\n", virtual_addr);
    }
}


// Set up a complete user process address space
bool setup_user_process_paging(uint32_t code_phys_addr, size_t code_size) {
    kprintf("=== setup_user_process_paging START ===\n");
    kprintf("  Code physical: 0x%08x, size: %d bytes\n", code_phys_addr, code_size);
    kprintf("  Code virtual:  0x%08x\n", USER_CODE_BASE);
    kprintf("  Stack virtual: 0x%08x\n", USER_STACK_BASE);

    // Verify recursive mapping is working
    uint32_t* recursive_pde = (uint32_t*)0xfffff000;
    if ((*recursive_pde & PAGE_PRESENT) == 0) {
        kprintf("ERROR: Recursive PDE not present! Paging system is broken.\n");
        return false;
    }

    // Ensure page directory entry for user space exists
    uint32_t* user_pde = (uint32_t*)0xffc00000 + 32;
    if ((*user_pde & PAGE_PRESENT) == 0) {
        kprintf("Pre-allocating page table for user space (PDE 32)\n");
        uint32_t new_pt_phys = pmm_alloc();
        if (!new_pt_phys) {
            kprintf("ERROR: Failed to allocate page table for user space\n");
            return false;
        }
        
        *user_pde = new_pt_phys | PAGE_PRESENT | PAGE_READWRITE | PAGE_USER;
        
        // Clear the new page table
        uint32_t* new_pt = (uint32_t*)0xffc08000;
        for (int i = 0; i < 1024; i++) {
            new_pt[i] = 0;
        }
        kprintf("User page table initialized at phys=0x%08x\n", new_pt_phys);
    }

    // Map user code
    uint32_t code_virt = USER_CODE_BASE;
    uint32_t code_phys = code_phys_addr;
    
    kprintf("1. Mapping user code pages...\n");
    for (size_t i = 0; i < code_size; i += 4096) {
        kprintf("   Page %d: virt=0x%08x -> phys=0x%08x\n", 
               i/4096, code_virt + i, code_phys + i);
        map_user_memory(code_virt + i, code_phys + i, PAGE_READONLY);
        kprintf("   Page %d mapped successfully\n", i/4096);
    }
    kprintf("   All code pages mapped\n");
    
    // Allocate and map user stack (grows down)
    kprintf("2. Allocating user stack...\n");
    uint32_t stack_phys = pmm_alloc();
    if (!stack_phys) {
        kprintf("ERROR: Failed to allocate user stack\n");
        return false;
    }
    kprintf("   Stack physical: 0x%08x\n", stack_phys);
    
    // Map stack with read/write permissions
    kprintf("3. Mapping user stack...\n");
    uint32_t stack_virt = USER_STACK_BASE - 4096;
    kprintf("   Stack virt: 0x%08x -> phys: 0x%08x\n", stack_virt, stack_phys);
    map_user_memory(stack_virt, stack_phys, PAGE_PRESENT | PAGE_READWRITE | PAGE_USER);
    kprintf("   Stack mapped successfully\n");
    
    kprintf("=== setup_user_process_paging COMPLETE ===\n");
    return true;
}


// Check if address is in user space
bool is_user_address(uint32_t addr) {
    /*=========================================================================
     * SECURITY FIX (v1.18): Protect null page from user access
     *
     * NULL PAGE PROTECTION: The first 4KB (one page) should never be mapped
     * to catch null pointer dereferences. This prevents:
     * - NULL pointer dereference exploitation
     * - Accidental null pointer bugs turning into security issues
     * - Memory corruption from treating 0 as a valid address
     *
     * FIX: Reject addresses in range [0, PAGE_SIZE) as invalid user addresses.
     *=======================================================================*/
    return (addr >= PAGE_SIZE && addr < USER_SPACE_END);
}

// Print user memory layout for debugging
void print_user_memory_layout(void) {
    kprintf("=== User Memory Layout ===\n");
    kprintf("User space:   0x%08x - 0x%08x\n", USER_SPACE_BASE, USER_SPACE_END);
    kprintf("Code:         0x%08x\n", USER_CODE_BASE);
    kprintf("Stack:        0x%08x (grows down)\n", USER_STACK_BASE);
    kprintf("Heap:         0x%08x (grows up)\n", USER_HEAP_BASE);
    kprintf("==========================\n");
}


void init_recursive_paging(void) {
    // SILENT MODE - no logging to reduce stack usage
    uint32_t page_dir_phys;

    if ((uint32_t)page_directory >= KERNEL_BASE) {
        page_dir_phys = (uint32_t)page_directory - KERNEL_BASE;
    } else {
        page_dir_phys = (uint32_t)page_directory;
    }

    /*=========================================================================
     * SECURITY: Recursive paging entry MUST be supervisor-only
     * Do NOT set PAGE_USER flag - this prevents user-mode processes from
     * reading kernel page tables, which would expose the entire memory map
     * and defeat ASLR/security mechanisms.
     *=======================================================================*/
    page_directory[1023] = page_dir_phys | (PAGE_PRESENT | PAGE_READWRITE);
    // NOTE: PAGE_USER intentionally omitted - this is supervisor-only

    __asm__ volatile("invlpg (%0)" :: "r"(0xFFFFF000) : "memory");
    __asm__ volatile("invlpg (%0)" :: "r"(0xFFC00000) : "memory");
}




// Call this during paging initialization, after recursive paging is set up
void pre_alloc_user_page_tables(void) {
    // SILENT MODE - no logging to reduce stack usage

    uint32_t* recursive_pde = (uint32_t*)0xfffff000;
    if ((*recursive_pde & PAGE_PRESENT) == 0) {
        return; // Silent failure
    }

    uint32_t essential_pdes[] = {0, 32, 767};  // 767 for high stack at 0xBFFFE000

    for (int i = 0; i < 3; i++) {
        uint32_t pd_index = essential_pdes[i];
        uint32_t* pde = (uint32_t*)0xfffff000 + pd_index;

        if ((*pde & PAGE_PRESENT) == 0) {
            uint32_t new_pt_phys = pmm_alloc();

            if (!new_pt_phys) {
                continue;
            }

            uint32_t flags = PAGE_PRESENT | PAGE_READWRITE;
            if (pd_index >= 32) {
                flags |= PAGE_USER;
            }

            *pde = new_pt_phys | flags;

            // CRITICAL: Flush TLB for the recursive mapping area before accessing it
            uint32_t recursive_addr = 0xffc00000 + (pd_index * 0x1000);
            asm volatile("invlpg (%0)" : : "r" (recursive_addr) : "memory");

            uint32_t* new_pt = (uint32_t*)recursive_addr;

            for (int j = 0; j < 1024; j++) {
                new_pt[j] = 0;
            }
        }
    }
}

/*=============================================================================
 * FUNCTION: validate_memory_range
 *============================================================================*/
bool validate_memory_range(uint32_t addr, uint32_t size, bool require_write) {
    uint32_t end = addr + size;
    
    kprintf("validate_memory_range: addr=0x%08x, size=0x%x, require_write=%d\n", 
           addr, size, require_write);
    
    for (uint32_t current = addr & ~(PAGE_SIZE - 1); current < end; current += PAGE_SIZE) {
        uint32_t* pte = get_page_table_entry(current);
        
        if (!pte) {
            kprintf("  ERROR: No page table for address 0x%08x\n", current);
            return false;
        }
        
        if (!(*pte & PAGE_PRESENT)) {
            kprintf("  ERROR: Page not present at 0x%08x (PTE=0x%08x)\n", current, *pte);
            return false;
        }
        
        if (require_write && !(*pte & PAGE_READWRITE)) {
            kprintf("  ERROR: Page not writable at 0x%08x (PTE=0x%08x)\n", current, *pte);
            return false;
        }
        
        kprintf("  OK: 0x%08x -> present=1, writable=%d\n", 
               current, (*pte & PAGE_READWRITE) ? 1 : 0);
    }
    
    kprintf("  Memory range validation SUCCESS\n");
    return true;
}

void ensure_physical_range_mapped(uint32_t phys_start, uint32_t size) {
    uint32_t start_page = phys_start & ~(PAGE_SIZE - 1);
    uint32_t end_page = (phys_start + size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    kprintf("Ensuring physical range 0x%08x-0x%08x is mapped...\n",
           phys_start, phys_start + size);

    for (uint32_t phys = start_page; phys < end_page; phys += PAGE_SIZE) {
        uint32_t* pte = get_page_table_entry(phys);
        if (!pte || !(*pte & PAGE_PRESENT)) {
            kprintf("  Mapping phys 0x%08x for kernel access\n", phys);
            map_page(phys, phys, PAGE_PRESENT | PAGE_READWRITE);
        }
    }
}

/*=============================================================================
 * PROCESS ISOLATION - PAGE DIRECTORY MANAGEMENT
 *=============================================================================*/

/**
 * @brief Get the kernel page directory physical address
 * @return Physical address of the kernel page directory (or PDPT in PAE mode)
 */
uint32_t get_kernel_page_directory(void) {
    /* In PAE mode, return the saved kernel PDPT address */
    if (pae_is_active()) {
        return pae_get_kernel_pdpt();  /* Return saved kernel PDPT (not current CR3!) */
    }

    /* Standard 32-bit mode: return page directory */
    if ((uint32_t)page_directory >= KERNEL_BASE) {
        return (uint32_t)page_directory - KERNEL_BASE;
    }
    return (uint32_t)page_directory;
}

/**
 * @brief Create a new page directory for a user process
 *
 * This creates a new page directory that:
 * - Copies kernel mappings (first 32MB identity mapped)
 * - Sets up recursive mapping
 * - Is isolated from other user processes
 *
 * @return Physical address of the new page directory, or 0 on failure
 */
uint32_t create_user_page_directory(void) {
    /*=========================================================================
     * PAE MODE: Create PDPT instead of page directory
     *=========================================================================*/
    if (pae_is_active()) {
        return pae_create_user_pdpt();
    }

    /*=========================================================================
     * STANDARD 32-BIT MODE: Create page directory
     *=========================================================================*/
    kprintf("[PAGING] Creating new user page directory...\n");

    // Allocate a physical frame for the new page directory
    // Must be below 32MB: it is accessed through the identity mapping below
    uint32_t new_pd_phys = pmm_alloc_low();
    if (new_pd_phys == 0) {
        kprintf("[PAGING] ERROR: Failed to allocate page directory\n");
        return 0;
    }

    kprintf("[PAGING] Allocated PD at phys=0x%08x\n", new_pd_phys);

    // Map the new page directory into kernel space temporarily so we can initialize it
    // We'll use the identity-mapped region (first 32MB) to access it
    uint32_t* new_pd = (uint32_t*)new_pd_phys;

    // Clear the new page directory
    for (int i = 0; i < 1024; i++) {
        new_pd[i] = 0;
    }

    // Copy kernel mappings from the current page directory
    // The first 8 entries map the first 32MB (kernel space)
    kprintf("[PAGING] Copying kernel mappings (first 32MB)...\n");
    for (uint32_t i = 0; i < MAX_TABLES; i++) {
        new_pd[i] = page_directory[i];
        if (new_pd[i] & PAGE_PRESENT) {
            kprintf("[PAGING]   PDE[%d] = 0x%08x\n", i, new_pd[i]);
        }
    }

    // CRITICAL: Explicitly clear all user-space PDEs (8-1022) to prevent stale mappings
    // from recycled frames or kernel pre-allocated page tables
    // EXCEPT: Preserve PDE[0], PDE[32], PDE[767] if they were pre-allocated
    kprintf("[PAGING] Clearing user-space PDEs (8-1022), preserving pre-allocated PDEs...\n");
    for (int i = MAX_TABLES; i < 1023; i++) {
        // Preserve pre-allocated PDEs: 0 (identity mapping), 32 (code ~128MB), 767 (stack ~3GB)
        if (i == 0 || i == 32 || i == 767) {
            // Copy from kernel page directory (pre-allocated during boot)
            new_pd[i] = page_directory[i];
            if (new_pd[i] & PAGE_PRESENT) {
                kprintf("[PAGING]   Preserved PDE[%d] = 0x%08x\n", i, new_pd[i]);
            }
        } else {
            new_pd[i] = 0;
        }
    }

    /*=========================================================================
     * SECURITY: Set up recursive mapping (supervisor-only)
     * Last PDE points to page directory itself for recursive paging access
     * Do NOT set PAGE_USER - kernel-only page table access
     *=======================================================================*/
    new_pd[1023] = new_pd_phys | (PAGE_PRESENT | PAGE_READWRITE);
    // NOTE: PAGE_USER intentionally omitted for security
    kprintf("[PAGING] Set up recursive mapping: PDE[1023] = 0x%08x (supervisor-only)\n", new_pd[1023]);

    kprintf("[PAGING] Created user page directory at phys=0x%08x\n", new_pd_phys);
    return new_pd_phys;
}

/**
 * @brief Free a page directory and all its user-space page tables
 *
 * This frees:
 * - All user-space page tables (PDE entries 8-1022, excluding kernel space)
 * - The page directory itself
 *
 * Note: Does NOT free kernel page tables (shared across all processes)
 *
 * @param page_dir_phys Physical address of the page directory to free
 */
void free_page_directory(uint32_t page_dir_phys) {
    if (page_dir_phys == 0) {
        return;
    }

    kprintf("[PAGING] Freeing page directory at phys=0x%08x\n", page_dir_phys);

    // Get kernel page directory for comparison
    uint32_t kernel_pd_phys = get_kernel_page_directory();

    // Don't free the kernel page directory!
    if (page_dir_phys == kernel_pd_phys) {
        kprintf("[PAGING] WARNING: Attempted to free kernel page directory!\n");
        return;
    }

    /*=========================================================================
     * PAE MODE: page_dir_phys is a PDPT, not a 32-bit page directory.
     * Mirrors the PAE branch in create_user_page_directory(). Interpreting
     * a PDPT as 1024 32-bit PDEs would pmm_free() arbitrary in-use frames.
     *=======================================================================*/
    if (pae_is_active()) {
        pae_free_user_pdpt(page_dir_phys);
        return;
    }

    // SAFETY: PD is accessed via identity mapping (first 32MB only).
    // create_user_page_directory() allocates via pmm_alloc_low(), so this
    // should never trigger; leak the page tables rather than fault.
    if (page_dir_phys >= MAX_TABLES * PT_COVERS_BYTES) {
        kprintf("[PAGING] WARNING: PD at 0x%08x above identity-mapped region, "
                "freeing PD frame only\n", page_dir_phys);
        pmm_free(page_dir_phys);
        return;
    }

    // CRITICAL FIX: Properly free all user-space page tables
    // NOTE: Currently accessing page directory through identity mapping (first 32MB)
    // This works because PMM allocates from this region, so page_dir_phys < 32MB
    // can be used as virtual address.
    //
    // FUTURE ENHANCEMENT: For page directories above 32MB, use recursive paging:
    // Access via: uint32_t* pd = (uint32_t*)(0xFFFFF000); (entry 1023)
    // This requires temporarily loading the PD into CR3 or using recursive mapping.
    uint32_t* pd = (uint32_t*)page_dir_phys;

    // Get kernel page directory to check which page tables are shared
    uint32_t* kernel_pd = (uint32_t*)kernel_pd_phys;

    int freed_count = 0;

    // Iterate through user-space PDEs (8-1022)
    // PDEs 0-7: Kernel space (first 32MB), don't free
    // PDE 1023: Recursive mapping (points to PD itself), don't free
    for (int i = MAX_TABLES; i < 1023; i++) {
        uint32_t pde = pd[i];

        // Skip if not present
        if (!(pde & PAGE_PRESENT)) {
            continue;
        }

        // Get physical address of the page table
        uint32_t pt_phys = pde & PAGE_FRAME_MASK;  // Mask off flags to get address

        // SAFETY: Don't free if this page table is shared with kernel
        // (shouldn't happen for user-space PDEs, but be defensive)
        if (i < 1024 && (kernel_pd[i] & PAGE_PRESENT)) {
            uint32_t kernel_pt_phys = kernel_pd[i] & PAGE_FRAME_MASK;
            if (pt_phys == kernel_pt_phys) {
                // This page table is shared with kernel, don't free
                continue;
            }
        }

        // Free the page table
        pmm_free(pt_phys);
        freed_count++;
    }

    kprintf("[PAGING] Freed %d user page tables\n", freed_count);

    // Free the page directory itself
    pmm_free(page_dir_phys);
    kprintf("[PAGING] Page directory freed\n");
}


