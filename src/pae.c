/*=============================================================================
 * pae.c - PAE (Physical Address Extension) Implementation for W^X
 *
 * Implements 3-level paging with NX (No eXecute) bit support for
 * Write XOR Execute (W^X) security policy.
 *
 * PAE Structure:
 *   CR3 → PDPT (4 entries, 64-bit each)
 *      → Page Directories (512 entries, 64-bit each)
 *      → Page Tables (512 entries, 64-bit each)
 *      → Physical Pages (4 KB)
 *
 * Version: 1.21
 *===========================================================================*/

#include "paging.h"
#include "pmm.h"
#include "kprintf.h"
#include "critical.h"
#include "util.h"  /* For kernel_panic() */
#include "fbcon.h" /* Framebuffer range for pre-paging identity map */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*=============================================================================
 * SECURITY FIX (Issue 7.1): Atomic 64-bit PAE Write Operations
 *
 * CRITICAL: PAE structures (PTE, PDE, PDPTE) are 64-bit values. In 32-bit
 * mode, the compiler implements 64-bit writes as TWO separate 32-bit stores:
 *   1. Write low 32 bits
 *   2. Write high 32 bits
 *
 * PROBLEM: If an interrupt/NMI fires between these two writes, another thread
 * or interrupt handler could read a CORRUPTED, half-updated entry. This can
 * cause security violations (e.g., wrong page mapped) or crashes.
 *
 * SOLUTION (Single-Core): Use critical sections to disable interrupts during
 * the entire 64-bit write sequence. The CPU then executes both 32-bit stores
 * atomically with respect to interrupt handlers.
 *
 * SOLUTION (SMP/Multi-Core): Would require LOCK CMPXCHG8B instruction or
 * proper memory barriers + spinlocks. This is documented as a limitation.
 *
 * NOTE: These helpers add minimal overhead (~5 cycles for interrupt disable/
 * enable) compared to the catastrophic cost of page table corruption.
 *=============================================================================*/

/**
 * @brief Atomically write a 64-bit PAE PTE entry
 * @param pte_ptr Pointer to the PTE to update
 * @param value New 64-bit value
 *
 * SECURITY: This function ensures the 64-bit write is atomic with respect
 * to interrupts, preventing half-updated page table entries.
 */
static inline void pae_atomic_write_pte(volatile pae_pte_t* pte_ptr, uint64_t value) {
    CRITICAL_SECTION_ENTER();
    *pte_ptr = value;
    CRITICAL_SECTION_EXIT();
}

/**
 * @brief Atomically write a 64-bit PAE PDE entry
 * @param pde_ptr Pointer to the PDE to update
 * @param value New 64-bit value
 */
static inline void pae_atomic_write_pde(volatile pae_pde_t* pde_ptr, uint64_t value) {
    CRITICAL_SECTION_ENTER();
    *pde_ptr = value;
    CRITICAL_SECTION_EXIT();
}

/**
 * @brief Atomically write a 64-bit PAE PDPTE entry
 * @param pdpte_ptr Pointer to the PDPTE to update
 * @param value New 64-bit value
 */
static inline void pae_atomic_write_pdpte(volatile pae_pdpte_t* pdpte_ptr, uint64_t value) {
    CRITICAL_SECTION_ENTER();
    *pdpte_ptr = value;
    CRITICAL_SECTION_EXIT();
}

/*=============================================================================
 * External Symbols from Linker Script (for W^X policy)
 *===========================================================================*/
extern char __text_start[], __text_end[];
extern char __user_text_start[], __user_text_end[];
extern char __rodata_start[], __rodata_end[];
extern char __data_start[], __data_end[];
extern char __bss_start[], __bss_end[];

/*=============================================================================
 * PAE Page Table Structures
 *
 * IMPORTANT ALIGNMENT REQUIREMENTS:
 * - PDPT must be 32-byte aligned and below 4 GB
 * - Page directories must be 4096-byte (page) aligned
 * - Page tables must be 4096-byte (page) aligned
 *===========================================================================*/

/* Page Directory Pointer Table (PDPT) - 4 entries */
static pae_pdpte_t pdpt[PAE_PDPT_ENTRIES] __attribute__((aligned(32)));

/* Page Directories - 4 directories × 512 entries */
static pae_pde_t page_directories[PAE_PDPT_ENTRIES][PAE_PD_ENTRIES]
    __attribute__((aligned(4096)));

/* Initial page tables. Each table maps 2MB, so this pool must cover ALL RAM the
 * boot identity map touches (pmm_total_frames). For the 256MB target that's
 * 256/2 = 128 tables. SIZING THIS TO FULL RAM IS LOAD-BEARING: if the pool is
 * too small, the boot identity-map loop falls back to alloc_initial_pt's
 * pmm_alloc() path, which re-enters pae_map_page to map the new PT frame and can
 * trip the recursion guard, silently leaving not-present PTE holes in the
 * identity map (the loop ignores pae_map_page failures). RAMFS then pmm_alloc's
 * a frame in such a hole and memset's it via its physical address → intermittent
 * early-boot "kernel mode page fault" in memset. 128 tables (512KB BSS) keeps the
 * whole 256MB map in the always-present static pool, so the fallback is never
 * taken. (If RAM grows past 256MB, raise this AND see the failure check added to
 * the identity-map loop.) */
#define PAE_INITIAL_TABLES 128
static pae_pte_t initial_page_tables[PAE_INITIAL_TABLES][PAE_PT_ENTRIES]
    __attribute__((aligned(4096)));

/* Track which initial tables are in use */
static bool initial_tables_used[PAE_INITIAL_TABLES] = {false};

/* PAE enabled flag */
static bool pae_active = false;

/* NX bit enabled flag */
static bool nx_enabled = false;

/* Kernel PDPT physical address (saved at initialization) */
static uint32_t kernel_pdpt_phys = 0;

/*=============================================================================
 * Helper Functions
 *===========================================================================*/

#define PAE_CR3_PDPT_MASK 0xFFFFFFE0u  /* PAE CR3 points to a 32-byte-aligned PDPT */

static inline uint32_t pae_read_cr3_pdpt(void) {
    uint32_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    return cr3 & PAE_CR3_PDPT_MASK;
}

static uint32_t pae_default_pdpt_phys(void) {
    if (kernel_pdpt_phys == 0) {
        return 0;  /* Early PAE init: use the static kernel tables directly */
    }

    uint32_t cr3_pdpt = pae_read_cr3_pdpt();
    return cr3_pdpt ? cr3_pdpt : kernel_pdpt_phys;
}

static bool pae_is_kernel_pdpt(uint32_t pdpt_phys) {
    return pdpt_phys == 0 ||
           (kernel_pdpt_phys != 0 &&
            ((pdpt_phys & PAE_CR3_PDPT_MASK) == kernel_pdpt_phys));
}

static pae_pdpte_t* pae_pdpt_from_phys(uint32_t pdpt_phys) {
    if (pae_is_kernel_pdpt(pdpt_phys)) {
        return pdpt;
    }

    return (pae_pdpte_t*)(uintptr_t)(pdpt_phys & PAE_CR3_PDPT_MASK);
}

static uint64_t pae_pt_phys_from_ptr(pae_pte_t* pt) {
    uint32_t pt_addr = (uint32_t)(uintptr_t)pt;
    if (pt_addr >= KERNEL_BASE) {
        return (uint64_t)(pt_addr - KERNEL_BASE) & PAE_FRAME_MASK;
    }
    return (uint64_t)pt_addr & PAE_FRAME_MASK;
}

/**
 * @brief Read TSC (Time Stamp Counter) for inline assembly operations
 */
static inline uint32_t read_tsc_low(void) {
    uint32_t low;
    __asm__ volatile("rdtsc" : "=a"(low) :: "edx");
    return low;
}

/**
 * @brief Allocate a zeroed page table from initial pool
 * @return Pointer to page table, or NULL if pool exhausted
 */
static pae_pte_t* alloc_initial_pt(void) {
    CRITICAL_SECTION_ENTER();

    /* Try to use pre-allocated pool first */
    for (int i = 0; i < PAE_INITIAL_TABLES; i++) {
        if (!initial_tables_used[i]) {
            initial_tables_used[i] = true;

            /* Zero the table */
            for (int j = 0; j < PAE_PT_ENTRIES; j++) {
                /*=============================================================
                 * SECURITY FIX (Issue 7.1): Use atomic write for PTE zero
                 *===========================================================*/
                pae_atomic_write_pte(&initial_page_tables[i][j], 0);
            }

            CRITICAL_SECTION_EXIT();
            return initial_page_tables[i];
        }
    }

    CRITICAL_SECTION_EXIT();

    /* Pool exhausted - allocate dynamically from PMM */
    uint32_t pt_phys = pmm_alloc();
    if (pt_phys == 0) {
        return NULL;  /* Out of physical memory */
    }
    /*=========================================================================
     * CRITICAL FIX: Ensure PMM-allocated page table is identity-mapped
     *
     * PROBLEM: pmm_alloc() returns a physical address that may not be
     * identity-mapped yet. Trying to write to it causes a page fault.
     *
     * FIX: Identity-map the physical page before accessing it. This is safe
     * because we're in PAE mode and pae_map_page() will either succeed or
     * recursively fail gracefully (returning NULL to caller).
     *
     * NOTE: This creates a potential recursion if pae_map_page() needs to
     * allocate another page table. Today the first-fit allocator returns a low
     * frame whose PD entry is already present, so the present-guard in
     * pae_map_page caps real depth at 1 — but that's an allocator invariant, not
     * a guarantee. Add an EXPLICIT recursion guard so a future allocator change
     * (best-fit / high-watermark) can't turn this into unbounded recursion: past
     * a small depth we bail out cleanly with NULL (which pae_map_page already
     * handles) instead of recursing further.
     *=======================================================================*/
    static int alloc_pt_recursion_depth = 0;
    if (alloc_pt_recursion_depth >= 2) {
        /* Guard tripped: bail out CLEANLY rather than skip the identity-map and
         * then write through a possibly-unmapped pt_phys (that would page-fault
         * inside the allocator with interrupts off → triple fault). The caller
         * (pae_map_page) already handles a NULL return. Free the frame so we
         * don't leak it. (Note: pae_map_page runs under cli, so this recursion
         * can't be interrupted; the static depth counter is balanced.) */
        pmm_free(pt_phys);
        return NULL;
    }
    alloc_pt_recursion_depth++;
    pae_map_page(pt_phys, (uint64_t)pt_phys, PAE_PRESENT | PAE_READWRITE | PAE_NX);
    alloc_pt_recursion_depth--;

    /* Zero the newly allocated page table */
    pae_pte_t* pt = (pae_pte_t*)(uintptr_t)pt_phys;
    for (int j = 0; j < PAE_PT_ENTRIES; j++) {
        /*=====================================================================
         * SECURITY FIX (Issue 7.1): Use atomic write for PTE zero
         *===================================================================*/
        pae_atomic_write_pte(&pt[j], 0);
    }

    return pt;
}

/*=============================================================================
 * CPU Feature Detection
 *===========================================================================*/

bool pae_is_supported(void) {
    uint32_t edx;

    /* CPUID.1:EDX.PAE[bit 6] = 1 indicates PAE support */
    __asm__ volatile(
        "mov $1, %%eax\n"
        "cpuid\n"
        : "=d"(edx)
        :: "eax", "ebx", "ecx"
    );

    return (edx & (1 << 6)) != 0;
}

bool pae_is_active(void) {
    return pae_active;
}

uint32_t pae_get_kernel_pdpt(void) {
    return kernel_pdpt_phys;
}

bool pae_enable_nx(void) {
    uint32_t ext_features;

    /* Check for extended CPUID support */
    uint32_t max_extended;
    __asm__ volatile(
        "mov $0x80000000, %%eax\n"
        "cpuid\n"
        : "=a"(max_extended)
        :: "ebx", "ecx", "edx"
    );

    if (max_extended < 0x80000001) {
        kprintf("[PAE] Extended CPUID not supported\n");
        return false;
    }

    /* CPUID.80000001h:EDX.NX[bit 20] = 1 indicates NX support */
    __asm__ volatile(
        "mov $0x80000001, %%eax\n"
        "cpuid\n"
        : "=d"(ext_features)
        :: "eax", "ebx", "ecx"
    );

    if (!(ext_features & (1 << 20))) {
        kprintf("[PAE] NX bit NOT supported by CPU\n");
        return false;
    }

    /* Enable NX in EFER (MSR 0xC0000080, bit 11) */
    uint32_t eax, edx;
    __asm__ volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(0xC0000080));

    if (eax & (1 << 11)) {
        kprintf("[PAE] NX bit already enabled\n");
        nx_enabled = true;
        return true;
    }

    eax |= (1 << 11);  /* Set EFER.NXE */
    __asm__ volatile("wrmsr" :: "a"(eax), "d"(edx), "c"(0xC0000080));

    kprintf("[PAE] NX bit enabled in EFER\n");
    nx_enabled = true;
    return true;
}

/*=============================================================================
 * FUNCTION: pae_apply_kernel_wx
 * PURPOSE: Apply W^X policy to kernel memory sections
 *
 * Remaps kernel pages with appropriate NX flags based on section type:
 * - .text/.user.text: R+X (executable, not writable)
 * - .rodata: R+NX (read-only, not executable)
 * - .data/.bss: R+W+NX (writable, not executable)
 *===========================================================================*/
static void pae_apply_kernel_wx(void) {
    if (!nx_enabled) {
        kprintf("[PAE_WX] NX not supported - skipping W^X enforcement\n");
        return;
    }

    kprintf("[PAE_WX] Applying W^X policy to kernel sections...\n");

    /* Convert linker symbols to addresses */
    uint32_t text_start = (uint32_t)__text_start;
    uint32_t text_end = (uint32_t)__text_end;
    uint32_t user_text_start = (uint32_t)__user_text_start;
    uint32_t user_text_end = (uint32_t)__user_text_end;
    uint32_t rodata_start = (uint32_t)__rodata_start;
    uint32_t rodata_end = (uint32_t)__rodata_end;
    uint32_t data_start = (uint32_t)__data_start;
    uint32_t data_end = (uint32_t)__data_end;
    uint32_t bss_start = (uint32_t)__bss_start;
    uint32_t bss_end = (uint32_t)__bss_end;

    kprintf("[PAE_WX] .text:      0x%08x - 0x%08x (%u KB) [R+X]\n",
            text_start, text_end, (text_end - text_start) / 1024);
    kprintf("[PAE_WX] .user.text: 0x%08x - 0x%08x (%u KB) [R+X]\n",
            user_text_start, user_text_end, (user_text_end - user_text_start) / 1024);
    kprintf("[PAE_WX] .rodata:    0x%08x - 0x%08x (%u KB) [R+NX]\n",
            rodata_start, rodata_end, (rodata_end - rodata_start) / 1024);
    kprintf("[PAE_WX] .data:      0x%08x - 0x%08x (%u KB) [R+W+NX]\n",
            data_start, data_end, (data_end - data_start) / 1024);
    kprintf("[PAE_WX] .bss:       0x%08x - 0x%08x (%u KB) [R+W+NX]\n",
            bss_start, bss_end, (bss_end - bss_start) / 1024);

    /*=========================================================================
     * SECURITY FIX (Issue 12.1): FULL W^X ENFORCEMENT
     *
     * Apply Write XOR Execute policy to ALL kernel sections.
     * Each memory page can be EITHER writable OR executable, NEVER both.
     *
     * ATTACK PREVENTION:
     * - .text R+X (no write): Prevents code injection attacks
     * - .rodata R+NX: Prevents JOP/ROP gadgets in constant data
     * - .data/.bss R+W+NX: Prevents stack/heap code execution
     *=========================================================================*/

    /*=========================================================================
     * STEP 1: Remap .text section as R+X (executable, NOT writable)
     *=========================================================================*/
    kprintf("[PAE_WX] Remapping .text section as R+X...\n");
    for (uint32_t addr = text_start; addr < text_end; addr += 0x1000) {
        pae_map_page(addr, addr, PAE_PRESENT);  /* R+X (no NX, no write) */
    }

    /*=========================================================================
     * STEP 2: Remap .user.text section as R+X (if non-empty)
     *=========================================================================*/
    if (user_text_end > user_text_start) {
        kprintf("[PAE_WX] Remapping .user.text section as R+X...\n");
        for (uint32_t addr = user_text_start; addr < user_text_end; addr += 0x1000) {
            pae_map_page(addr, addr, PAE_PRESENT);  /* R+X (no NX, no write) */
        }
    }

    /*=========================================================================
     * STEP 3: Remap .rodata section as R+NX (read-only, not executable)
     *=========================================================================*/
    kprintf("[PAE_WX] Remapping .rodata section as R+NX...\n");
    for (uint32_t addr = rodata_start; addr < rodata_end; addr += 0x1000) {
        pae_map_page(addr, addr, PAE_PRESENT | PAE_NX);  /* R+NX (read-only, not executable) */
    }

    /*=========================================================================
     * STEP 4: Remap .data section as R+W+NX (writable, not executable)
     *=========================================================================*/
    kprintf("[PAE_WX] Remapping .data section as R+W+NX...\n");
    for (uint32_t addr = data_start; addr < data_end; addr += 0x1000) {
        pae_map_page(addr, addr, PAE_PRESENT | PAE_READWRITE | PAE_NX);  /* R+W+NX */
    }

    /*=========================================================================
     * STEP 5: Remap .bss section as R+W+NX (writable, not executable)
     * This provides DEP for stack and uninitialized data
     *=========================================================================*/
    kprintf("[PAE_WX] Remapping .bss section as R+W+NX...\n");
    for (uint32_t addr = bss_start; addr < bss_end; addr += 0x1000) {
        pae_map_page(addr, addr, PAE_PRESENT | PAE_READWRITE | PAE_NX);  /* R+W+NX */
    }

    kprintf("[PAE_WX] W^X policy FULLY ENFORCED on all kernel sections\n");
}

/*=============================================================================
 * PAE Initialization
 *===========================================================================*/

void pae_init(void) {
    kprintf("[PAE] Initializing PAE paging with W^X support...\n");

    /* Step 1: Check CPU support */
    if (!pae_is_supported()) {
        kprintf("[PAE] ERROR: CPU does not support PAE\n");
        kprintf("[PAE] W^X protection DISABLED\n");
        return;
    }
    kprintf("[PAE] CPU supports PAE............. [OK]\n");

    /* Step 2: Initialize PDPT (Page Directory Pointer Table) */
    kprintf("[PAE] Initializing PDPT at 0x%08x\n", (uint32_t)(uintptr_t)pdpt);

    /* Ensure PDPT is below 4 GB (required by CPU) */
    if ((uintptr_t)pdpt >= 0x100000000ULL) {
        kprintf("[PAE] ERROR: PDPT above 4 GB boundary\n");
        return;
    }

    /* Zero PDPT */
    for (int i = 0; i < PAE_PDPT_ENTRIES; i++) {
        /*=====================================================================
         * SECURITY FIX (Issue 7.1): Use atomic write for 64-bit PDPT entry
         * Prevents corruption if interrupt fires during 64-bit write sequence
         *===================================================================*/
        pae_atomic_write_pdpte(&pdpt[i], 0);
    }

    /* Step 3: Initialize Page Directories */
    kprintf("[PAE] Initializing %d page directories\n", PAE_PDPT_ENTRIES);

    for (int pd_idx = 0; pd_idx < PAE_PDPT_ENTRIES; pd_idx++) {
        /* Zero page directory */
        for (int i = 0; i < PAE_PD_ENTRIES; i++) {
            /*=================================================================
             * SECURITY FIX (Issue 7.1): Use atomic write for 64-bit PDE
             *===============================================================*/
            pae_atomic_write_pde(&page_directories[pd_idx][i], 0);
        }

        /* Point PDPT entry to this page directory */
        uint64_t pd_phys = (uint64_t)(uintptr_t)&page_directories[pd_idx][0];
        /*=====================================================================
         * SECURITY FIX (Issue 7.1): Use atomic write for PDPT entry
         *===================================================================*/
        pae_atomic_write_pdpte(&pdpt[pd_idx], pd_phys | PAE_PRESENT);
    }

    kprintf("[PAE] Page directories initialized\n");

    /* Mark PAE as active before using pae_map_page() */
    pae_active = true;

    /*=========================================================================
     * BUG FIX: Dynamic Identity Mapping Based on Detected RAM
     *
     * CRITICAL: RAMFS allocates physical pages via pmm_alloc() and uses them
     * as virtual pointers. Identity mapping must cover ALL physical RAM that
     * PMM can allocate from, otherwise pmm_alloc() can return addresses beyond
     * the mapped range, causing #UD Invalid Opcode exceptions when accessed.
     *
     * Root Cause: src/ramfs.c:694
     *   node->data = (uint8_t*)pmm_alloc();  // Physical addr used as virtual!
     *   memset(node->data, 0, 4096);         // Access unmapped memory → crash
     *
     * Fix: Query PMM for total memory size and identity map the entire range.
     * This works regardless of system RAM size (256 MB, 512 MB, 1 GB, etc.)
     *
     * Future: Proper fix would be to map physical pages into kernel virtual
     * address space instead of relying on identity mapping.
     *=======================================================================*/
    uint32_t total_frames = pmm_total_frames();  /* Get detected RAM size */
    uint32_t total_bytes = total_frames * 4096;   /* Convert to bytes */
    uint32_t total_mb = total_bytes / (1024 * 1024);

    kprintf("[PAE] Identity mapping %u MB (%u pages)...\n", total_mb, total_frames);

    uint32_t pages_mapped = 0;
    for (uint32_t phys = 0; phys < total_bytes; phys += 4096) {
        /* Map as read-write initially (need write access for kernel .data/.bss/stack)
         * W^X will be enforced later when we know which sections are code vs data */
        pae_map_page(phys, phys, PAE_PRESENT | PAE_READWRITE);
        pages_mapped++;
    }

    kprintf("[PAE] Mapped %u pages (identity)\n", pages_mapped);

    /* VERIFY the identity map has NO not-present holes. pae_map_page returns
     * void (can't signal failure), and a silent hole here is catastrophic but
     * invisible: a later pmm_alloc'd frame in the hole, written via its physical
     * address (e.g. RAMFS alloc_node memset), faults at runtime — intermittently,
     * depending on which frames boot allocations consumed. With the static PT
     * pool now sized to full RAM this should never trip; if it does (e.g. RAM >
     * pool, exhausting alloc_initial_pt), PANIC loudly here at boot rather than
     * crash unpredictably later in memset. */
    for (uint32_t phys = 0; phys < total_bytes; phys += 4096) {
        pae_pte_t* pte = pae_get_pte(phys);
        if (!pte || !(*pte & PAE_PRESENT)) {
            kprintf("[PAE] FATAL: identity-map hole at phys=0x%08x (PT not present)\n", phys);
            kprintf("[PAE] The static page-table pool (PAE_INITIAL_TABLES=%d) is too small\n",
                    PAE_INITIAL_TABLES);
            kprintf("[PAE] for %u MB of RAM. Raise PAE_INITIAL_TABLES to >= RAM_MB/2.\n", total_mb);
            kernel_panic("PAE identity map incomplete - would fault in memset later");
        }
    }
    kprintf("[PAE] Identity map verified complete (no holes)\n");

    /* Step 5: Enable NX bit */
    if (pae_enable_nx()) {
        kprintf("[PAE] NX bit support............... [OK]\n");

        /*=====================================================================
         * SECURITY FIX: NX the general RAM identity map
         *
         * The loop above (step 4) mapped ALL of RAM as PAE_PRESENT |
         * PAE_READWRITE with no NX, because NX isn't enabled yet at that
         * point and the loop must remain correct regardless of NX support.
         * Left as-is, every non-kernel-section page in physical RAM (heap,
         * PMM pool, RAMFS-allocated frames) stays permanently R+W+X, which
         * is what pae_wx_audit()/`secstatus`/`wxaudit` correctly flag.
         *
         * Now that NX is available, re-mark the whole identity map NX
         * (R+W+NX, i.e. PAE_PAGE_KERNEL_DATA) so ordinary RAM can still be
         * allocated and written by PMM/RAMFS but can no longer be executed.
         * pae_apply_kernel_wx() (next step) then re-opens exactly the
         * kernel .text/.user.text ranges as R+X on top of this.
         *=====================================================================*/
        kprintf("[PAE] Applying NX to general RAM identity map...\n");
        for (uint32_t phys = 0; phys < total_bytes; phys += 4096) {
            pae_map_page(phys, phys, PAE_PAGE_KERNEL_DATA);
        }
    } else {
        kprintf("[PAE] NX bit support............... [UNAVAILABLE]\n");
        kprintf("[PAE] W^X enforcement limited\n");
    }

    /* Map the VBE linear framebuffer (fbcon), if active. It lives above RAM
     * (e.g. 0xFD000000 on QEMU) so the identity-map loop above never covers
     * it, and the very next kprintf after paging goes live would page-fault.
     * Must happen before CR3 load / CR0.PG. Write-through, supervisor-only,
     * and NX where available (bit 63 is reserved without EFER.NXE — e.g. v86). */
    {
        uint32_t fb_phys, fb_size;
        if (fbcon_get_range(&fb_phys, &fb_size)) {
            uint64_t fb_flags = PAE_PRESENT | PAE_READWRITE | PAE_WRITETHROUGH |
                                (nx_enabled ? PAE_NX : 0);
            for (uint32_t off = 0; off < fb_size; off += 4096u) {
                pae_map_page(fb_phys + off, (uint64_t)fb_phys + off, fb_flags);
            }
            kprintf("[PAE] Mapped framebuffer 0x%08x (%u KB)\n",
                    fb_phys, fb_size / 1024u);
        }
    }

    /* Step 6: Enable PAE in CR4 */
    kprintf("[PAE] Enabling CR4.PAE bit\n");

    uint32_t cr4;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));

    if (cr4 & (1 << 5)) {
        kprintf("[PAE] PAE already enabled in CR4\n");
    } else {
        cr4 |= (1 << 5);  /* Set CR4.PAE (bit 5) */
        __asm__ volatile("mov %0, %%cr4" :: "r"(cr4));
        kprintf("[PAE] PAE enabled in CR4........... [OK]\n");
    }

    /* Step 7: Load CR3 with PDPT address */
    kprintf("[PAE] Loading CR3 with PDPT address\n");

    uint32_t pdpt_phys = (uint32_t)(uintptr_t)pdpt;
    __asm__ volatile("mov %0, %%cr3" :: "r"(pdpt_phys) : "memory");

    /* Save kernel PDPT address for later use */
    kernel_pdpt_phys = pdpt_phys;

    kprintf("[PAE] CR3 loaded with PDPT......... [OK]\n");

    /* Step 8: Apply W^X policy to kernel sections */
    pae_apply_kernel_wx();

    kprintf("[PAE] Initialization complete\n");
    kprintf("[PAE] PDPT physical address: 0x%08x\n", (uint32_t)(uintptr_t)pdpt);
    kprintf("[PAE] W^X enforcement: %s\n", nx_enabled ? "ACTIVE" : "PARTIAL");
}

/*=============================================================================
 * PAE Page Mapping Functions
 *===========================================================================*/

static pae_pde_t* pae_get_pde_by_index_in(uint32_t pdpt_phys,
                                           uint32_t pdpt_idx,
                                           uint32_t pd_idx) {
    if (!pae_active) {
        return NULL;
    }

    if (pdpt_idx >= PAE_PDPT_ENTRIES || pd_idx >= PAE_PD_ENTRIES) {
        return NULL;
    }

    pae_pdpte_t* target_pdpt = pae_pdpt_from_phys(pdpt_phys);

    /* Check PDPT entry */
    if (!(target_pdpt[pdpt_idx] & PAE_PRESENT)) {
        return NULL;  /* PDPT entry not present */
    }

    /* Get page directory */
    uint64_t pd_phys = target_pdpt[pdpt_idx] & PAE_FRAME_MASK;
    pae_pde_t* pd = (pae_pde_t*)(uintptr_t)pd_phys;

    return &pd[pd_idx];
}

pae_pde_t* pae_get_pde_in(uint32_t pdpt_phys, uint32_t virt) {
    return pae_get_pde_by_index_in(pdpt_phys,
                                   PAE_PDPT_INDEX(virt),
                                   PAE_PD_INDEX(virt));
}

pae_pde_t* pae_get_pde(uint32_t virt, uint32_t pdpt_index) {
    return pae_get_pde_by_index_in(pae_default_pdpt_phys(),
                                   pdpt_index,
                                   PAE_PD_INDEX(virt));
}

pae_pte_t* pae_get_pte_in(uint32_t pdpt_phys, uint32_t virt) {
    if (!pae_active) {
        return NULL;
    }

    uint32_t pt_idx = PAE_PT_INDEX(virt);
    pae_pde_t* pde = pae_get_pde_in(pdpt_phys, virt);

    /* Check PD entry */
    if (!pde || !(*pde & PAE_PRESENT)) {
        return NULL;  /* Page directory entry not present */
    }

    /* Get page table from PD entry */
    uint64_t pt_phys = *pde & PAE_FRAME_MASK;
    pae_pte_t* pt = (pae_pte_t*)(uintptr_t)pt_phys;  /* Identity mapped */

    /* Return pointer to PTE */
    return &pt[pt_idx];
}

pae_pte_t* pae_get_pte(uint32_t virt) {
    return pae_get_pte_in(pae_default_pdpt_phys(), virt);
}

static bool pae_user_range_bounds(uint32_t start, size_t len,
                                  uint32_t* last_out) {
    if (len == 0) {
        return true;
    }

    /* Keep the null page unavailable and USER_SPACE_END as an exclusive bound. */
    if (start < PAGE_SIZE || start >= USER_SPACE_END) {
        return false;
    }

    uint64_t last_wide = (uint64_t)start + (uint64_t)len - 1u;
    if (last_wide >= USER_SPACE_END) {
        return false;
    }

    *last_out = (uint32_t)last_wide;
    return true;
}

/* Caller holds the paging critical section for the complete walk. */
static bool pae_user_range_accessible_locked(uint32_t pdpt_phys,
                                             uint32_t start, uint32_t last,
                                             bool require_write) {
    pae_pdpte_t* target_pdpt = pae_pdpt_from_phys(pdpt_phys);
    uint64_t required = PAE_PRESENT | PAE_USER;
    if (require_write) {
        required |= PAE_READWRITE;
    }

    uint32_t page = start & ~(PAGE_SIZE - 1u);
    uint32_t final_page = last & ~(PAGE_SIZE - 1u);

    for (;;) {
        uint32_t pdpt_idx = PAE_PDPT_INDEX(page);
        uint32_t pd_idx = PAE_PD_INDEX(page);
        uint32_t pt_idx = PAE_PT_INDEX(page);

        pae_pdpte_t pdpte = target_pdpt[pdpt_idx];
        if (!(pdpte & PAE_PRESENT)) {
            return false;
        }

        pae_pde_t* pd = (pae_pde_t*)(uintptr_t)(pdpte & PAE_FRAME_MASK);
        pae_pde_t pde = pd[pd_idx];
        if ((pde & required) != required) {
            return false;
        }

        if (!(pde & PAE_LARGE_PAGE)) {
            pae_pte_t* pt = (pae_pte_t*)(uintptr_t)(pde & PAE_FRAME_MASK);
            pae_pte_t pte = pt[pt_idx];
            if ((pte & required) != required) {
                return false;
            }
        }

        if (page == final_page) {
            return true;
        }
        page += PAGE_SIZE;
    }
}

bool pae_user_range_accessible_in(uint32_t pdpt_phys, uint32_t start,
                                  size_t len, bool require_write) {
    uint32_t last = 0;
    if (!pae_active || !pae_user_range_bounds(start, len, &last)) {
        return len == 0 && pae_active;
    }

    CRITICAL_SECTION_ENTER();
    bool allowed = pae_user_range_accessible_locked(pdpt_phys, start, last,
                                                    require_write);
    CRITICAL_SECTION_EXIT();
    return allowed;
}

bool pae_user_range_accessible(uint32_t start, size_t len,
                               bool require_write) {
    uint32_t last = 0;
    if (!pae_active || !pae_user_range_bounds(start, len, &last)) {
        return len == 0 && pae_active;
    }

    /* Read CR3 with interrupts disabled so the selected address space cannot
     * change before the walk completes on this single-core kernel. */
    CRITICAL_SECTION_ENTER();
    uint32_t pdpt_phys = pae_read_cr3_pdpt();
    bool allowed = pae_user_range_accessible_locked(pdpt_phys, start, last,
                                                    require_write);
    CRITICAL_SECTION_EXIT();
    return allowed;
}

void pae_map_page(uint32_t virt, uint64_t phys, uint64_t flags) {
    pae_map_page_into(kernel_pdpt_phys, virt, phys, flags);
}

void pae_unmap_page_in(uint32_t pdpt_phys, uint32_t virt) {
    if (!pae_active) {
        return;
    }

    CRITICAL_SECTION_ENTER();

    pae_pte_t* pte = pae_get_pte_in(pdpt_phys, virt);
    if (!pte) {
        CRITICAL_SECTION_EXIT();
        return;  /* Not mapped */
    }

    if (*pte & PAE_SEALED) {
        kprintf("[MSEAL] DENIED: refusing to unmap sealed page 0x%08x\n", virt);
        CRITICAL_SECTION_EXIT();
        return;
    }

    /* Clear PTE */
    /*=========================================================================
     * SECURITY FIX (Issue 7.1): Use atomic write for clearing PTE
     * Must be atomic to prevent reading half-cleared entry
     *=======================================================================*/
    pae_atomic_write_pte(pte, 0);

    /* Flush TLB */
    __asm__ volatile("invlpg (%0)" :: "r"(virt) : "memory");

    CRITICAL_SECTION_EXIT();
}

void pae_unmap_page(uint32_t virt) {
    pae_unmap_page_in(pae_default_pdpt_phys(), virt);
}

uint64_t pae_virt_to_phys_in(uint32_t pdpt_phys, uint32_t virt) {
    pae_pte_t* pte = pae_get_pte_in(pdpt_phys, virt);
    if (!pte || !(*pte & PAE_PRESENT)) {
        return 0;  /* Not mapped */
    }

    /* Extract physical frame and add page offset */
    uint64_t phys_frame = *pte & PAE_FRAME_MASK;
    uint32_t offset = PAE_PAGE_OFFSET(virt);

    return phys_frame | offset;
}

uint64_t pae_virt_to_phys(uint32_t virt) {
    return pae_virt_to_phys_in(pae_default_pdpt_phys(), virt);
}

/*=============================================================================
 * W^X Auditing
 *===========================================================================*/

uint32_t pae_wx_audit(void) {
    if (!pae_active) {
        kprintf("[W^X] PAE not active, cannot audit\n");
        return 0;
    }

    kprintf("\n=== W^X Memory Audit (PAE) ===\n\n");

    uint32_t total_pages = 0;
    uint32_t executable_pages = 0;
    uint32_t writable_pages = 0;
    uint32_t wx_violations = 0;

    /* Cap verbose per-violation lines: without NX support (e.g. v86, which has
     * no NX bit at all) nearly every writable page qualifies, and printing one
     * line each floods/hangs a slow console. Detailed lines still help pinpoint
     * the handful of real violations on NX-capable hardware/QEMU. */
    #define PAE_WX_AUDIT_PRINT_LIMIT 20

    /* Scan all page tables */
    for (int pdpt_idx = 0; pdpt_idx < PAE_PDPT_ENTRIES; pdpt_idx++) {
        if (!(pdpt[pdpt_idx] & PAE_PRESENT)) continue;

        pae_pde_t* pd = page_directories[pdpt_idx];

        for (int pd_idx = 0; pd_idx < PAE_PD_ENTRIES; pd_idx++) {
            if (!(pd[pd_idx] & PAE_PRESENT)) continue;

            uint64_t pt_phys = pd[pd_idx] & PAE_FRAME_MASK;
            pae_pte_t* pt = (pae_pte_t*)(uintptr_t)pt_phys;

            for (int pt_idx = 0; pt_idx < PAE_PT_ENTRIES; pt_idx++) {
                pae_pte_t pte = pt[pt_idx];

                if (!(pte & PAE_PRESENT)) continue;

                total_pages++;

                bool writable = (pte & PAE_READWRITE) != 0;
                bool executable = (pte & PAE_NX) == 0;  /* NX=0 means executable */

                if (writable) writable_pages++;
                if (executable) executable_pages++;

                /* W^X violation: both writable AND executable */
                if (writable && executable) {
                    wx_violations++;

                    if (wx_violations <= PAE_WX_AUDIT_PRINT_LIMIT) {
                        /* Calculate virtual address */
                        uint32_t virt = (pdpt_idx << 30) | (pd_idx << 21) | (pt_idx << 12);
                        uint64_t phys = pte & PAE_FRAME_MASK;

                        kprintf("[W^X] VIOLATION: virt=0x%08x phys=0x%012llx (R+W+X)\n",
                                virt, phys);
                    } else if (wx_violations == PAE_WX_AUDIT_PRINT_LIMIT + 1) {
                        kprintf("[W^X] ... further violations suppressed (NX likely "
                                "unsupported by this CPU/emulator) - see summary below\n");
                    }
                }
            }
        }
    }

    kprintf("\nSummary:\n");
    kprintf("  Total pages:      %u\n", total_pages);
    kprintf("  Executable (X):   %u\n", executable_pages);
    kprintf("  Writable (W):     %u\n", writable_pages);
    kprintf("  W+X violations:   %u\n", wx_violations);

    if (wx_violations == 0) {
        kprintf("\nW^X Policy: ENFORCED ✅\n\n");
    } else {
        kprintf("\nW^X Policy: VIOLATIONS DETECTED ❌\n\n");
    }

    return wx_violations;
}

/*=============================================================================
 * Debugging Functions
 *===========================================================================*/

void pae_dump_tables_in(uint32_t pdpt_phys, uint32_t virt) {
    if (!pae_active) {
        kprintf("[PAE] PAE not active\n");
        return;
    }

    uint32_t pdpt_idx = PAE_PDPT_INDEX(virt);
    uint32_t pd_idx = PAE_PD_INDEX(virt);
    uint32_t pt_idx = PAE_PT_INDEX(virt);

    kprintf("\n=== PAE Page Table Walk for 0x%08x ===\n", virt);
    kprintf("PDPT index: %u\n", pdpt_idx);
    kprintf("PD index:   %u\n", pd_idx);
    kprintf("PT index:   %u\n", pt_idx);
    kprintf("Offset:     0x%03x\n", PAE_PAGE_OFFSET(virt));
    kprintf("\n");

    pae_pdpte_t* target_pdpt = pae_pdpt_from_phys(pdpt_phys);

    /* PDPT Entry */
    pae_pdpte_t pdpte = target_pdpt[pdpt_idx];
    kprintf("PDPT[%u]: 0x%016llx\n", pdpt_idx, pdpte);
    kprintf("  Present: %s\n", (pdpte & PAE_PRESENT) ? "Yes" : "No");

    if (!(pdpte & PAE_PRESENT)) {
        kprintf("  (Not present - walk ends here)\n\n");
        return;
    }

    /* PD Entry */
    uint64_t pd_phys = pdpte & PAE_FRAME_MASK;
    pae_pde_t* pd = (pae_pde_t*)(uintptr_t)pd_phys;
    pae_pde_t pde = pd[pd_idx];
    kprintf("PD[%u]:   0x%016llx\n", pd_idx, pde);
    kprintf("  Present: %s\n", (pde & PAE_PRESENT) ? "Yes" : "No");

    if (!(pde & PAE_PRESENT)) {
        kprintf("  (Not present - walk ends here)\n\n");
        return;
    }

    /* PT Entry */
    uint64_t pt_phys = pde & PAE_FRAME_MASK;
    pae_pte_t* pt = (pae_pte_t*)(uintptr_t)pt_phys;
    pae_pte_t pte = pt[pt_idx];
    kprintf("PT[%u]:   0x%016llx\n", pt_idx, pte);
    kprintf("  Present:    %s\n", (pte & PAE_PRESENT) ? "Yes" : "No");

    if (!(pte & PAE_PRESENT)) {
        kprintf("  (Not present - walk ends here)\n\n");
        return;
    }

    kprintf("  Writable:   %s\n", (pte & PAE_READWRITE) ? "Yes" : "No");
    kprintf("  User:       %s\n", (pte & PAE_USER) ? "Yes" : "No");
    kprintf("  Executable: %s\n", (pte & PAE_NX) ? "No (NX set)" : "Yes");
    kprintf("  Sealed:     %s\n", (pte & PAE_SEALED) ? "Yes" : "No");
    kprintf("  Phys Frame: 0x%012llx\n", pte & PAE_FRAME_MASK);

    uint64_t final_phys = pae_virt_to_phys_in(pdpt_phys, virt);
    kprintf("\nFinal physical address: 0x%012llx\n\n", final_phys);
}

void pae_dump_tables(uint32_t virt) {
    pae_dump_tables_in(pae_default_pdpt_phys(), virt);
}

/*=============================================================================
 * FUNCTION: pae_create_user_pdpt
 * PURPOSE: Create a new PAE PDPT for a user process
 *
 * Creates a new Page Directory Pointer Table (PDPT) and 4 page directories
 * for a user process, with kernel mappings copied from the current PDPT.
 *
 * @return Physical address of the new PDPT, or 0 on failure
 *===========================================================================*/
uint32_t pae_create_user_pdpt(void) {
    kprintf("[PAE] Creating new user PDPT...\n");

    /*=========================================================================
     * STEP 1: Allocate physical frames
     *=========================================================================*/

    /* Allocate one page for PDPT (only 32 bytes used, but must be page-aligned) */
    uint32_t pdpt_phys = pmm_alloc();
    if (pdpt_phys == 0) {
        /*=====================================================================
         * SECURITY FIX (Issue 4.2): Boot-Path Allocation Failure → Panic
         *
         * CRITICAL: PAE initialization is boot-critical. If we can't allocate
         * the PDPT, the system CANNOT function. Returning 0 and continuing
         * leads to:
         * - Silent fallback to 32-bit paging (loses W^X enforcement)
         * - NULL dereference later → triple fault → silent reboot
         *
         * FIX: Panic immediately with clear message about OOM condition.
         * This is much better than mysterious reboot loops.
         *===================================================================*/
        kprintf("[PAE] CRITICAL: Failed to allocate PDPT - out of memory!\n");
        kprintf("[PAE] Available frames: %u KB\n", (pmm_free_frames() * 4096) / 1024);
        kernel_panic("PAE initialization failed - insufficient memory");
    }
    kprintf("[PAE] Allocated PDPT at phys=0x%08x\n", pdpt_phys);

    /* Allocate 4 pages for the 4 page directories */
    uint32_t pd_phys[PAE_PDPT_ENTRIES];
    for (int i = 0; i < PAE_PDPT_ENTRIES; i++) {
        pd_phys[i] = pmm_alloc();
        if (pd_phys[i] == 0) {
            /*=================================================================
             * SECURITY FIX (Issue 4.2): Boot-Path Allocation Failure → Panic
             * Page directory allocation is boot-critical - panic on failure.
             *===============================================================*/
            kprintf("[PAE] CRITICAL: Failed to allocate page directory %d\n", i);
            kprintf("[PAE] Available frames: %u KB\n", (pmm_free_frames() * 4096) / 1024);
            /* No cleanup needed - kernel_panic() halts system */
            kernel_panic("PAE initialization failed - insufficient memory for page directories");
        }
        kprintf("[PAE] Allocated PD[%d] at phys=0x%08x\n", i, pd_phys[i]);
    }

    /*=========================================================================
     * STEP 2: Initialize PDPT entries
     *=========================================================================*/

    pae_pdpte_t* new_pdpt = (pae_pdpte_t*)(uintptr_t)pdpt_phys;

    for (int i = 0; i < PAE_PDPT_ENTRIES; i++) {
        /* PDPT entries: bits 12-51 = physical address of PD, bit 0 = Present */
        /*=====================================================================
         * SECURITY FIX (Issue 7.1): Use atomic write for 64-bit PDPT entry
         * Prevents corruption during process creation if interrupt fires
         *===================================================================*/
        uint64_t pdpt_value = (uint64_t)pd_phys[i] | PAE_PRESENT;
        pae_atomic_write_pdpte(&new_pdpt[i], pdpt_value);
        kprintf("[PAE] PDPT[%d] = 0x%016llx (PD at 0x%08x)\n",
                i, pdpt_value, pd_phys[i]);
    }

    /*=========================================================================
     * STEP 3: Initialize each page directory
     *=========================================================================*/

    for (int i = 0; i < PAE_PDPT_ENTRIES; i++) {
        pae_pde_t* new_pd = (pae_pde_t*)(uintptr_t)pd_phys[i];

        /* Clear all 512 entries */
        for (int j = 0; j < PAE_PD_ENTRIES; j++) {
            /*=================================================================
             * SECURITY FIX (Issue 7.1): Use atomic write for PDE zero
             *===============================================================*/
            pae_atomic_write_pde(&new_pd[j], 0);
        }

        /* Copy kernel mappings from the current page directories.
         * PD[0] holds the RAM identity map (kernel + user link range; user
         * PTEs are copy-on-write'd into private PTs by pae_map_page_into).
         * PD[3] holds supervisor-only MMIO such as the VBE framebuffer
         * (0xFD000000) — it MUST be present in user PDPTs or any fbcon
         * output while a user CR3 is active page-faults and triple-faults.
         * PD[1]/PD[2] are currently empty; copying them is a no-op. */
        for (int j = 0; j < PAE_PD_ENTRIES; j++) {
            /*=============================================================
             * SECURITY FIX (Issue 7.1): Use atomic write for PDE copy
             *===========================================================*/
            pae_atomic_write_pde(&new_pd[j], page_directories[i][j]);
        }
    }

    kprintf("[PAE] Created user PDPT at phys=0x%08x\n", pdpt_phys);
    return pdpt_phys;
}

/*=============================================================================
 * FUNCTION: pae_free_user_pt (helper)
 * PURPOSE: Return a user page table to its allocator
 *
 * Page tables come from alloc_initial_pt(): either the static initial pool
 * (returned by marking the slot unused) or pmm_alloc() (returned via
 * pmm_free()).
 *===========================================================================*/
static void pae_free_user_pt(uint32_t pt_phys) {
    uint32_t pool_addr = (uint32_t)(uintptr_t)initial_page_tables;
    uint32_t pool_phys = (pool_addr >= KERNEL_BASE) ? (pool_addr - KERNEL_BASE)
                                                    : pool_addr;

    if (pt_phys >= pool_phys &&
        pt_phys < pool_phys + sizeof(initial_page_tables)) {
        uint32_t idx = (pt_phys - pool_phys) / sizeof(initial_page_tables[0]);
        CRITICAL_SECTION_ENTER();
        initial_tables_used[idx] = false;
        CRITICAL_SECTION_EXIT();
        return;
    }

    pmm_free(pt_phys);
}

/*=============================================================================
 * FUNCTION: pae_free_user_pdpt
 * PURPOSE: Free a user PDPT created by pae_create_user_pdpt()
 *
 * Frees all user-allocated page tables, the 4 page directories, and the
 * PDPT frame itself. Page tables shared with the kernel (PD[0] entries
 * copied from the kernel page directory at creation) are NOT freed.
 *
 * @param pdpt_phys Physical address of the PDPT to free
 *===========================================================================*/
void pae_free_user_pdpt(uint32_t pdpt_phys) {
    if (pdpt_phys == 0 || pdpt_phys == kernel_pdpt_phys) {
        return;
    }

    kprintf("[PAE] Freeing user PDPT at phys=0x%08x\n", pdpt_phys);

    /* All RAM is identity-mapped in PAE mode */
    pae_pdpte_t* user_pdpt = (pae_pdpte_t*)(uintptr_t)pdpt_phys;

    int freed_count = 0;

    for (int i = 0; i < PAE_PDPT_ENTRIES; i++) {
        if (!(user_pdpt[i] & PAE_PRESENT)) {
            continue;
        }

        uint32_t pd_phys = (uint32_t)(user_pdpt[i] & PAE_FRAME_MASK);
        pae_pde_t* pd = (pae_pde_t*)(uintptr_t)pd_phys;

        for (int j = 0; j < PAE_PD_ENTRIES; j++) {
            if (!(pd[j] & PAE_PRESENT)) {
                continue;
            }

            uint64_t pt_phys = pd[j] & PAE_FRAME_MASK;

            /* Creation copies kernel PDEs from ALL four PDs by value (PD[0]
             * RAM identity map, PD[3] framebuffer/MMIO), so the shared-PT
             * skip must cover every slot — gating on i == 0 alone would free
             * the kernel's live PD[3] page tables on the first process exit,
             * corrupting fbcon translations once the frame is reused. */
            if ((page_directories[i][j] & PAE_PRESENT) &&
                (page_directories[i][j] & PAE_FRAME_MASK) == pt_phys) {
                continue;
            }

            pae_free_user_pt((uint32_t)pt_phys);
            freed_count++;
        }

        pmm_free(pd_phys);
    }

    kprintf("[PAE] Freed %d user page tables\n", freed_count);

    pmm_free(pdpt_phys);
}

/*=============================================================================
 * FUNCTION: pae_map_page_into
 * PURPOSE: Map a page into a specific PDPT (for user process address spaces)
 *
 * This function maps a page into a given PDPT structure (not necessarily
 * the current kernel PDPT). Used by ELF loader to map pages into user
 * process address spaces.
 *
 * @param pdpt_phys Physical address of the PDPT to map into
 * @param virt Virtual address to map
 * @param phys Physical address to map to
 * @param flags Page flags (including potential NX bit)
 *===========================================================================*/
void pae_map_page_into(uint32_t pdpt_phys, uint32_t virt, uint64_t phys, uint64_t flags) {
    if (!pae_active) {
        kprintf("[PAE] WARNING: PAE not active, cannot map\n");
        return;
    }

    uint32_t pdpt_idx = PAE_PDPT_INDEX(virt);
    uint32_t pd_idx = PAE_PD_INDEX(virt);
    uint32_t pt_idx = PAE_PT_INDEX(virt);

    /* PAE requires bits 12-51 only for physical address; bits 62:52 are reserved. */
    phys &= PAE_FRAME_MASK;
    flags &= PAE_FLAGS_MASK;

    bool target_is_kernel = pae_is_kernel_pdpt(pdpt_phys);
    pae_pdpte_t* target_pdpt = pae_pdpt_from_phys(pdpt_phys);

    CRITICAL_SECTION_ENTER();

    if (!(target_pdpt[pdpt_idx] & PAE_PRESENT)) {
        kprintf("[PAE] ERROR: PDPT[%u] not present in target PDPT\n", pdpt_idx);
        CRITICAL_SECTION_EXIT();
        return;
    }

    uint64_t pd_phys = target_pdpt[pdpt_idx] & PAE_FRAME_MASK;
    pae_pde_t* target_pd = (pae_pde_t*)(uintptr_t)pd_phys;
    pae_pte_t* pt = NULL;

    if (target_pd[pd_idx] & PAE_PRESENT) {
        uint64_t pt_phys_addr = target_pd[pd_idx] & PAE_FRAME_MASK;

        /* If a user PDPT still points at a kernel-shared PT, clone it before
         * writing the user mapping so kernel identity mappings are not changed. */
        uint64_t kernel_pde = page_directories[pdpt_idx][pd_idx];
        bool shared_with_kernel =
            !target_is_kernel &&
            (kernel_pde & PAE_PRESENT) &&
            ((kernel_pde & PAE_FRAME_MASK) == (target_pd[pd_idx] & PAE_FRAME_MASK));

        if (shared_with_kernel) {
            pae_pte_t* priv = alloc_initial_pt();
            if (priv == NULL) {
                kprintf("[PAE] ERROR: COW page-table alloc failed for PD[%u]\n", pd_idx);
                CRITICAL_SECTION_EXIT();
                return;
            }

            pae_pte_t* shared_pt = (pae_pte_t*)(uintptr_t)pt_phys_addr;
            for (int e = 0; e < PAE_PT_ENTRIES; e++) {
                priv[e] = shared_pt[e];
            }

            pae_atomic_write_pde(&target_pd[pd_idx],
                                 pae_pt_phys_from_ptr(priv) |
                                 PAE_PRESENT | PAE_READWRITE | PAE_USER);
            pt = priv;
        } else {
            pt = (pae_pte_t*)(uintptr_t)pt_phys_addr;
        }
    } else {
        pae_pte_t* pt_alloc = alloc_initial_pt();
        if (pt_alloc == NULL) {
            kprintf("[PAE] ERROR: Failed to allocate page table for PD[%u]\n", pd_idx);
            CRITICAL_SECTION_EXIT();
            return;
        }

        pt = pt_alloc;
        pae_atomic_write_pde(&target_pd[pd_idx],
                             pae_pt_phys_from_ptr(pt_alloc) |
                             PAE_PRESENT | PAE_READWRITE | PAE_USER);
    }

    if (pt[pt_idx] & PAE_SEALED) {
        kprintf("[MSEAL] DENIED: refusing to remap sealed page 0x%08x\n", virt);
        CRITICAL_SECTION_EXIT();
        return;
    }

    pae_atomic_write_pte(&pt[pt_idx], phys | flags);

    uint32_t cr0;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    if (cr0 & (1 << 31)) {
        __asm__ volatile("invlpg (%0)" :: "r"(virt) : "memory");
    }

    CRITICAL_SECTION_EXIT();
}

/*=============================================================================
 * SECURITY FIX (Issue 12.1): Kernel Memory Layout Verification
 *
 * CRITICAL: Verify that kernel memory sections are properly segregated and
 * W^X policy is enforced. This prevents:
 * 1. User data accidentally mapped as executable (ROP attack vector)
 * 2. Kernel code accidentally writable (code injection)
 * 3. Linker script errors creating overlapping sections
 *
 * ATTACK SCENARIO (without verification):
 * - Linker places shell_elf_data in .text section
 * - Section mapped as R+W+X (writable AND executable)
 * - Attacker writes shellcode to buffer → executes in kernel mode
 *
 * FIX: Runtime verification during boot before executing any user code.
 *=============================================================================*/

/**
 * @brief Verify kernel memory layout for W^X policy enforcement
 *
 * Checks that:
 * 1. .text section is executable but NOT writable
 * 2. .rodata section is readable but NOT writable or executable
 * 3. .data/.bss sections are writable but NOT executable
 * 4. No section overlaps
 * 5. All sections are page-aligned
 *
 * @return true if layout is secure, false otherwise (calls kernel_panic)
 */
bool pae_verify_kernel_layout(void) {
    if (!pae_active || !nx_enabled) {
        kprintf("[SECURITY] PAE/NX not active - skipping W^X verification\n");
        return true;  /* Verification skipped/passed when NX not available */
    }

    kprintf("[SECURITY] Verifying kernel memory layout (W^X enforcement)...\n");

    uint32_t text_start = (uint32_t)__text_start;
    uint32_t text_end = (uint32_t)__text_end;
    uint32_t rodata_start = (uint32_t)__rodata_start;
    uint32_t rodata_end = (uint32_t)__rodata_end;
    uint32_t data_start = (uint32_t)__data_start;
    uint32_t data_end = (uint32_t)__data_end;
    uint32_t bss_start = (uint32_t)__bss_start;
    uint32_t bss_end = (uint32_t)__bss_end;

    /*=========================================================================
     * CHECK 1: Verify section page alignment (4KB boundaries)
     *=======================================================================*/
    kprintf("[SECURITY] Checking section alignment...\n");

    if (text_start % 0x1000 != 0) {
        kernel_panic(".text section start not page-aligned!");
    }
    if (rodata_start % 0x1000 != 0) {
        kernel_panic(".rodata section start not page-aligned!");
    }
    if (data_start % 0x1000 != 0) {
        kernel_panic(".data section start not page-aligned!");
    }
    if (bss_start % 0x1000 != 0) {
        kernel_panic(".bss section start not page-aligned!");
    }

    kprintf("[SECURITY]   All sections page-aligned... [OK]\n");

    /*=========================================================================
     * CHECK 2: Verify no section overlap
     *=======================================================================*/
    kprintf("[SECURITY] Checking for section overlap...\n");

    if (text_end > rodata_start) {
        kernel_panic(".text and .rodata sections overlap!");
    }
    if (rodata_end > data_start) {
        kernel_panic(".rodata and .data sections overlap!");
    }
    if (data_end > bss_start) {
        kernel_panic(".data and .bss sections overlap!");
    }

    kprintf("[SECURITY]   No section overlap detected... [OK]\n");

    /*=========================================================================
     * CHECK 3: Verify .text section is R+X (not writable)
     *=======================================================================*/
    kprintf("[SECURITY] Verifying .text section (R+X, not W)...\n");

    uint32_t violations = 0;
    for (uint32_t addr = text_start; addr < text_end; addr += 0x1000) {
        pae_pte_t* pte = pae_get_pte(addr);

        if (!pte || !(*pte & PAE_PRESENT)) {
            kprintf("[SECURITY] WARNING: .text page 0x%08x not mapped!\n", addr);
            violations++;
            continue;
        }

        if (*pte & PAE_READWRITE) {
            kprintf("[SECURITY] VIOLATION: .text page 0x%08x is WRITABLE!\n", addr);
            kernel_panic(".text section has writable pages - W^X violation!");
        }

        if (*pte & PAE_NX) {
            kprintf("[SECURITY] VIOLATION: .text page 0x%08x is NOT EXECUTABLE!\n", addr);
            kernel_panic(".text section has non-executable pages!");
        }
    }

    kprintf("[SECURITY]   .text section: R+X enforcement... [OK]\n");

    /*=========================================================================
     * CHECK 4: Verify .data/.bss sections are R+W+NX (not executable)
     *=======================================================================*/
    kprintf("[SECURITY] Verifying .data/.bss sections (R+W+NX)...\n");

    for (uint32_t addr = data_start; addr < bss_end; addr += 0x1000) {
        pae_pte_t* pte = pae_get_pte(addr);

        if (!pte || !(*pte & PAE_PRESENT)) {
            continue;  /* Unmapped pages OK */
        }

        if (!(*pte & PAE_NX)) {
            kprintf("[SECURITY] VIOLATION: data page 0x%08x is EXECUTABLE!\n", addr);
            kernel_panic(".data/.bss section has executable pages - DEP violation!");
        }
    }

    kprintf("[SECURITY]   .data/.bss: R+W+NX enforcement... [OK]\n");

    /*=========================================================================
     * FINAL STATUS
     *=======================================================================*/
    kprintf("[SECURITY] Kernel memory layout verification: ");
    if (violations == 0) {
        kprintf("PASS \n");
        kprintf("[SECURITY] W^X policy enforced successfully\n");
        return true;
    } else {
        kprintf("FAIL ✗ (%u violations)\n\n", violations);
        kernel_panic("Kernel memory layout verification failed!");
        return false;
    }
}

/*=============================================================================
 * PHASE 14: Memory Sealing (mseal) Implementation
 *
 * Modern Linux kernel feature (introduced 2024) that makes memory regions
 * permanently immutable. Once sealed, pages cannot be:
 * - Unmapped (munmap)
 * - Remapped (mremap)
 * - Protection changed (mprotect)
 * - Modified in any way
 *
 * Primary use case: Seal .text section after program load to prevent
 * code modification attacks (ROP/JOP chains, shellcode injection).
 *===========================================================================*/

/**
 * @brief Seal a memory region in a target PDPT, making it permanently immutable
 */
int pae_seal_memory_in(uint32_t pdpt_phys, uint32_t vaddr_start, uint32_t size) {
    if (!pae_active) {
        kprintf("[MSEAL] ERROR: PAE not active\n");
        return -1;
    }

    if ((vaddr_start & (PAGE_SIZE - 1)) != 0) {
        kprintf("[MSEAL] ERROR: Address 0x%08x not page-aligned\n", vaddr_start);
        return -1;
    }

    if (size == 0) {
        kprintf("[MSEAL] ERROR: Size must be non-zero\n");
        return -1;
    }

    uint32_t end = vaddr_start + size;
    if (end < vaddr_start) {
        kprintf("[MSEAL] ERROR: Address range wraps around\n");
        return -1;
    }

    uint32_t end_rounded = end;
    if ((end_rounded & (PAGE_SIZE - 1)) != 0) {
        if (end_rounded > 0xFFFFFFFFu - (PAGE_SIZE - 1)) {
            kprintf("[MSEAL] ERROR: Rounded address range wraps around\n");
            return -1;
        }
        end_rounded = (end_rounded + PAGE_SIZE - 1) & PAGE_FRAME_MASK;
    }

    uint32_t num_pages = (end_rounded - vaddr_start) / PAGE_SIZE;
    kprintf("[MSEAL] Sealing %u pages starting at 0x%08x (size: %u bytes)\n",
            num_pages, vaddr_start, size);

    CRITICAL_SECTION_ENTER();

    for (uint32_t vaddr = vaddr_start; vaddr < end_rounded; vaddr += PAGE_SIZE) {
        pae_pde_t* pde = pae_get_pde_in(pdpt_phys, vaddr);
        pae_pte_t* pte = pae_get_pte_in(pdpt_phys, vaddr);
        if (!pde || !(*pde & PAE_PRESENT) ||
            !pte || !(*pte & PAE_PRESENT)) {
            CRITICAL_SECTION_EXIT();
            kprintf("[MSEAL] ERROR: Page 0x%08x not mapped\n", vaddr);
            return -1;
        }

        if (!(*pde & PAE_USER) || !(*pte & PAE_USER)) {
            CRITICAL_SECTION_EXIT();
            kprintf("[MSEAL] ERROR: Page 0x%08x is not user-accessible\n", vaddr);
            return -1;
        }
    }

    uint32_t cr0;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));

    for (uint32_t vaddr = vaddr_start; vaddr < end_rounded; vaddr += PAGE_SIZE) {
        pae_pte_t* pte = pae_get_pte_in(pdpt_phys, vaddr);
        uint64_t sealed_pte = (*pte | PAE_SEALED) & ~PAE_READWRITE;
        pae_atomic_write_pte(pte, sealed_pte);
        if (cr0 & (1 << 31)) {
            __asm__ volatile("invlpg (%0)" :: "r"(vaddr) : "memory");
        }
    }

    CRITICAL_SECTION_EXIT();

    kprintf("[MSEAL] Successfully sealed %u pages\n", num_pages);
    return 0;
}

/**
 * @brief Seal a memory region in the current CR3
 */
int pae_seal_memory(uint32_t vaddr_start, uint32_t size) {
    return pae_seal_memory_in(pae_default_pdpt_phys(), vaddr_start, size);
}

/**
 * @brief Check if a memory region is sealed in a target PDPT
 */
bool pae_is_sealed_in(uint32_t pdpt_phys, uint32_t vaddr) {
    if (!pae_active) {
        return false;
    }

    pae_pte_t* pte = pae_get_pte_in(pdpt_phys, vaddr);
    if (!pte || !(*pte & PAE_PRESENT)) {
        return false;
    }

    return (*pte & PAE_SEALED) != 0;
}

/**
 * @brief Check if a memory region is sealed in the current CR3
 */
bool pae_is_sealed(uint32_t vaddr) {
    return pae_is_sealed_in(pae_default_pdpt_phys(), vaddr);
}
