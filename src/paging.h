/*=============================================================================
 *  paging.h — TinyOS Paging (identity map first 16–32 MiB)
 *============================================================================*/
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "memory.h"

/*=============================================================================
 * PAGE TABLE FLAGS (x86)
 *============================================================================*/
#define PDE_P   0x001u   /* Page Directory Entry: Present */
#define PDE_RW  0x002u   /* Page Directory Entry: Read/Write */
#define PTE_P   0x001u   /* Page Table Entry: Present */
#define PTE_RW  0x002u   /* Page Table Entry: Read/Write */

/*=============================================================================
 * PAGE GEOMETRY CONSTANTS
 *============================================================================*/
#define PAGE_SIZE        4096u                         /* 4 KiB per page */
#define PT_ENTRIES       1024u                         /* Entries per Page Table */
#define PD_ENTRIES       1024u                         /* Entries in Page Directory */
#define PT_COVERS_BYTES  (PT_ENTRIES * PAGE_SIZE)     /* 4 MiB per table */
#define MAX_TABLES       8u                            /* 8 tables = 32 MiB */

/*=============================================================================
 * PAGE TABLE ENTRY FLAGS
 *============================================================================*/
#define PAGE_PRESENT        (1 << 0)
#define PAGE_READWRITE      (1 << 1)
#define PAGE_USER           (1 << 2)
#define PAGE_WRITETHROUGH   (1 << 3)  // Write-through caching
#define PAGE_CACHE_DISABLE  (1 << 4)  // Disable caching (required for MMIO)
#define PAGE_READONLY       (PAGE_PRESENT | PAGE_USER)  // Present + User, read-only

/*=============================================================================
 * CR0 CONTROL REGISTER BITS
 *============================================================================*/
#define CR0_PG              (1U << 31)   // Paging enable bit
#define CR0_WP              (1U << 16)   // Write protect (ring 0 honors R/O pages)
#define CR0_PE              (1U << 0)    // Protection enable

/*=============================================================================
 * PAGE ADDRESS MASKS
 *============================================================================*/
#define PAGE_MASK           0xFFFu       // Lower 12 bits (offset within page)
#define PAGE_FRAME_MASK     0xFFFFF000u  // Upper 20 bits (page frame address)
#define PAGE_ALIGN_DOWN(addr) ((addr) & PAGE_FRAME_MASK)
#define PAGE_ALIGN_UP(addr)   (((addr) + PAGE_MASK) & PAGE_FRAME_MASK)

/*=============================================================================
 * Functions declarations
 *============================================================================*/

/* Map [0, limit_bytes) identity and enable paging */
void paging_identity_map_early(uint32_t limit_bytes);
void paging_enable(void);

uint32_t map_mmio(uint32_t phys_addr, uint32_t size);
void map_page(uint32_t virt, uint32_t phys, uint32_t flags);
void unmap_page(uint32_t virt);
void unmap_page_range(uint32_t vaddr_start, uint32_t vaddr_end);
void flush_tlb_single(uint32_t virt);

// New functions
/* SECURITY (v1.18): paging_make_user_accessible REMOVED - too dangerous */

void init_recursive_paging(void);
void pre_alloc_user_page_tables(void);
void ensure_physical_range_mapped(uint32_t phys_start, uint32_t size);
bool validate_memory_range(uint32_t addr, uint32_t size, bool require_write);

// Add this declaration:
uint32_t* get_page_table_entry(uint32_t virtual_addr);

// Only need these core functions to get user mode working
void map_user_memory(uint32_t virtual_addr, uint32_t physical_addr, uint32_t flags);
bool setup_user_process_paging(uint32_t code_phys_addr, size_t code_size);
void unmap_user_memory(uint32_t virtual_addr);
// Utility functions
bool is_user_address(uint32_t addr);
void print_user_memory_layout(void);
uint32_t virt_to_phys(uint32_t virtual_addr);


// These two functions (allocate_user_stack, free_user_memory) are
// for more advanced memory management that you can add later when
// you implement process isolation and dynamic memory allocation.
// uint32_t allocate_user_stack(void);
// void free_user_memory(uint32_t virtual_addr, size_t size);

// Process isolation - page directory management
uint32_t create_user_page_directory(void);
void free_page_directory(uint32_t page_dir_phys);
uint32_t get_kernel_page_directory(void);

/*=============================================================================
 * PAE (Physical Address Extension) Support for W^X (v1.21)
 *
 * PAE enables:
 * - 64-bit page table entries (instead of 32-bit)
 * - NX (No eXecute) bit (bit 63) for W^X enforcement
 * - 36-bit physical addressing (up to 64 GB RAM)
 * - 3-level page tables (PDPT → PD → PT)
 *
 * Required for W^X: Pages can be Writable OR Executable, never both
 *===========================================================================*/

/*=============================================================================
 * PAE Page Table Entry Types (64-bit)
 *===========================================================================*/
typedef uint64_t pae_pte_t;    /* Page Table Entry (64 bits) */
typedef uint64_t pae_pde_t;    /* Page Directory Entry (64 bits) */
typedef uint64_t pae_pdpte_t;  /* Page Directory Pointer Table Entry (64 bits) */

/*=============================================================================
 * PAE Page Table Flags (64-bit)
 *===========================================================================*/
#define PAE_PRESENT         (1ULL << 0)   /* Page is present in memory */
#define PAE_READWRITE       (1ULL << 1)   /* Page is writable (vs read-only) */
#define PAE_USER            (1ULL << 2)   /* User-accessible (vs supervisor) */
#define PAE_WRITETHROUGH    (1ULL << 3)   /* Write-through caching */
#define PAE_CACHE_DISABLE   (1ULL << 4)   /* Disable caching */
#define PAE_ACCESSED        (1ULL << 5)   /* Page has been accessed */
#define PAE_DIRTY           (1ULL << 6)   /* Page has been written to */
#define PAE_PAT             (1ULL << 7)   /* Page Attribute Table */
#define PAE_GLOBAL          (1ULL << 8)   /* Global page (TLB not flushed on CR3 change) */

/*=============================================================================
 * PHASE 14: Memory Sealing (mseal) - Modern Linux Kernel Feature
 *
 * TRADITIONAL ATTACK VECTOR:
 * - Attacker exploits buffer overflow to call mprotect(code_addr, PROT_WRITE)
 * - Makes .text section writable, overwrites code with shellcode
 * - Enables ROP/JOP attacks by modifying return addresses
 * - Can disable security mitigations (ASLR, stack canaries) by patching code
 *
 * MODERN LINUX INNOVATION (2024):
 * - mseal() syscall prevents ANY future modifications to memory region
 * - Once sealed, cannot be unmapped, remapped, or have permissions changed
 * - Even root cannot modify sealed pages
 * - Protects against: mprotect(), munmap(), mremap(), madvise()
 *
 * TINYOS IMPLEMENTATION:
 * - PAE_SEALED flag (bit 9) marks pages as permanently immutable
 * - sys_mseal() sets this flag on specified memory range
 * - Page fault handler enforces: sealed pages reject all modifications
 * - Ideal for code sections after program load
 *
 * SECURITY BENEFITS:
 * - ROP/JOP defense: Code cannot be modified at runtime
 * - Control-flow integrity: Return addresses stay intact
 * - Mitigation bypass prevention: Security code cannot be patched
 * - Exploit mitigation: Attacker cannot change memory protections
 *===========================================================================*/
#define PAE_SEALED          (1ULL << 9)   /* PHASE 14: Page is sealed (immutable) */

#define PAE_NX              (1ULL << 63)  /* No eXecute bit (AMD64/Intel 64) */

/*=============================================================================
 * W^X Policy - Combined Flags for Memory Regions
 *
 * These flags enforce the Write XOR Execute policy:
 * - Code pages: Readable + Executable (NOT writable, NO NX bit)
 * - Data pages: Readable + Writable + NX (NOT executable)
 * - Stack pages: Readable + Writable + NX (NOT executable)
 *===========================================================================*/
#define PAE_PAGE_CODE       (PAE_PRESENT | PAE_USER)
    /* Code: R+X, no write, no NX */

#define PAE_PAGE_DATA       (PAE_PRESENT | PAE_READWRITE | PAE_USER | PAE_NX)
    /* Data: R+W+NX, not executable */

#define PAE_PAGE_STACK      (PAE_PRESENT | PAE_READWRITE | PAE_USER | PAE_NX)
    /* Stack: R+W+NX, not executable */

#define PAE_PAGE_RODATA     (PAE_PRESENT | PAE_USER | PAE_NX)
    /* Read-only data: R+NX, not writable, not executable */

#define PAE_PAGE_KERNEL_CODE (PAE_PRESENT)
    /* Kernel code: R+X (supervisor only) */

#define PAE_PAGE_KERNEL_DATA (PAE_PRESENT | PAE_READWRITE | PAE_NX)
    /* Kernel data: R+W+NX (supervisor only) */

/*=============================================================================
 * PAE Geometry Constants
 *===========================================================================*/
#define PAE_PDPT_ENTRIES    4      /* 4 entries in PDPT (covers 4 GB) */
#define PAE_PD_ENTRIES      512    /* 512 entries per Page Directory */
#define PAE_PT_ENTRIES      512    /* 512 entries per Page Table */

#define PAE_PDPT_INDEX(virt)  (((virt) >> 30) & 0x3)     /* Bits 30-31 */
#define PAE_PD_INDEX(virt)    (((virt) >> 21) & 0x1FF)   /* Bits 21-29 */
#define PAE_PT_INDEX(virt)    (((virt) >> 12) & 0x1FF)   /* Bits 12-20 */
#define PAE_PAGE_OFFSET(virt) ((virt) & 0xFFF)           /* Bits 0-11 */

/*=============================================================================
 * PAE Address Masks
 *===========================================================================*/
#define PAE_FRAME_MASK      0x000FFFFFFFFFF000ULL  /* Bits 12-51: Page Frame Number */
#define PAE_FLAGS_MASK      0x8000000000000FFFULL  /* Bits 0-11, 63: Flags */
#define PAE_PHYS_MASK       0x000FFFFFFFFFFFFFULL  /* Bits 0-51: Physical address */

/*=============================================================================
 * PAE Function Declarations
 *===========================================================================*/

/**
 * @brief Initialize PAE paging mode
 * Enables CR4.PAE, sets up PDPT, and converts to 3-level paging
 */
void pae_init(void);

/**
 * @brief Check if CPU supports PAE
 * @return true if PAE is supported, false otherwise
 */
bool pae_is_supported(void);

/**
 * @brief Check if PAE is currently active
 * @return true if PAE was successfully initialized, false otherwise
 */
bool pae_is_active(void);

/**
 * @brief Get the kernel PDPT physical address
 * @return Physical address of the kernel PDPT (saved at PAE initialization)
 */
uint32_t pae_get_kernel_pdpt(void);

/**
 * @brief Create a new PAE PDPT for a user process
 *
 * Creates a new Page Directory Pointer Table (PDPT) and 4 page directories
 * for a user process, with kernel mappings copied from the current PDPT.
 *
 * @return Physical address of the new PDPT, or 0 on failure
 */
uint32_t pae_create_user_pdpt(void);

/**
 * @brief Free a user PDPT created by pae_create_user_pdpt()
 *
 * Frees all user-allocated page tables, the 4 page directories, and the
 * PDPT itself. Kernel-shared page tables (copied into PD[0]) are not freed.
 *
 * @param pdpt_phys Physical address of the PDPT to free
 */
void pae_free_user_pdpt(uint32_t pdpt_phys);

/**
 * @brief Enable NX (No eXecute) bit in EFER MSR
 * Required for W^X enforcement
 * @return true if NX was enabled, false if not supported
 */
bool pae_enable_nx(void);

/**
 * @brief Map a physical page to virtual address with PAE
 * @param virt Virtual address
 * @param phys Physical address
 * @param flags PAE flags (including potential NX bit)
 */
void pae_map_page(uint32_t virt, uint64_t phys, uint64_t flags);

/**
 * @brief Map a page into a specific PDPT (for user process address spaces)
 * @param pdpt_phys Physical address of the PDPT to map into
 * @param virt Virtual address to map
 * @param phys Physical address to map to
 * @param flags Page flags (including potential NX bit)
 */
void pae_map_page_into(uint32_t pdpt_phys, uint32_t virt, uint64_t phys, uint64_t flags);

/**
 * @brief Unmap a virtual page in PAE mode
 * @param virt Virtual address to unmap
 */
void pae_unmap_page(uint32_t virt);

/**
 * @brief Get PAE page table entry for virtual address
 * @param virt Virtual address
 * @return Pointer to PTE, or NULL if not mapped
 */
pae_pte_t* pae_get_pte(uint32_t virt);

/**
 * @brief Get PAE page directory entry
 * @param virt Virtual address
 * @param pdpt_index PDPT index (0-3)
 * @return Pointer to PDE, or NULL if not present
 */
pae_pde_t* pae_get_pde(uint32_t virt, uint32_t pdpt_index);

/**
 * @brief Translate virtual to physical address (PAE mode)
 * @param virt Virtual address
 * @return Physical address, or 0 if not mapped
 */
uint64_t pae_virt_to_phys(uint32_t virt);

/**
 * @brief Audit memory for W^X violations
 * Scans all mapped pages and reports any with W+X permissions
 * @return Number of violations found (should be 0)
 */
uint32_t pae_wx_audit(void);

/**
 * @brief Print PAE page table structures for debugging
 * @param virt Virtual address to dump tables for
 */
void pae_dump_tables(uint32_t virt);

/**
 * @brief Verify kernel memory layout for W^X compliance (Issue 12.1)
 *
 * SECURITY: Performs runtime verification of kernel memory layout to ensure
 * Write XOR Execute policy is properly enforced:
 * - Verifies section page alignment (4KB boundaries)
 * - Detects section overlap (W^X gap violations)
 * - Checks .text is R+X (not writable)
 * - Checks .data/.bss are R+W+NX (not executable)
 *
 * Should be called AFTER pae_init() and pae_apply_kernel_wx() during boot.
 * Triggers kernel panic if violations are detected.
 *
 * @return true if verification passed, false otherwise
 */
bool pae_verify_kernel_layout(void);

/*=============================================================================
 * PHASE 14: Memory Sealing Functions (mseal)
 *===========================================================================*/

/**
 * @brief Seal a memory region, making it permanently immutable
 *
 * Marks the specified virtual address range as sealed, preventing any future:
 * - Permission changes (mprotect)
 * - Unmapping (munmap)
 * - Remapping (mremap)
 * - Any modifications to page table entries
 *
 * Once sealed, the region remains immutable until process termination.
 *
 * @param vaddr_start Starting virtual address (must be page-aligned)
 * @param size Size in bytes (will be rounded up to page boundary)
 * @return 0 on success, -1 on error (invalid address, not mapped, already sealed)
 */
int pae_seal_memory(uint32_t vaddr_start, uint32_t size);

/**
 * @brief Check if a memory region is sealed
 *
 * @param vaddr Virtual address to check
 * @return true if page is sealed, false otherwise
 */
bool pae_is_sealed(uint32_t vaddr);
