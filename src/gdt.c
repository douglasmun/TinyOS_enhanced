/*=============================================================================
 * gdt.c - Global Descriptor Table Implementation
 * FIXED: Tracks selectors and passes them as parameters
 *============================================================================*/
#include <stdint.h>
#include <stddef.h>
#include "gdt.h"
#include "paging.h"    // For is_user_address
#include "memory.h"    // For USER_CODE_BASE, USER_STACK_BASE, etc.
#include "kprintf.h"   // For kprintf

/*-----------------------------------------------------------------------------
 * GDT Table - Large enough for GRUB's entries + our additions
 *-----------------------------------------------------------------------------*/
static struct gdt_entry gdt[16];
static struct gdt_ptr gdtr;

/*=============================================================================
 * SECURITY FIX (Issue 12.2): Removed Duplicate TSS Structure
 *
 * DELETED: static struct tss_entry tss;
 *
 * This was a duplicate TSS structure that was NOT being used by the CPU.
 * The actual TSS loaded into the CPU is in tss.c (tss_t tss).
 *
 * Having two separate TSS structures caused a critical bug where
 * tss_set_kernel_stack() updated this unused structure instead of the
 * real TSS, causing esp0 updates from the scheduler to be silently ignored.
 *===========================================================================*/

/* Track the selectors we created - NOT static so they can be accessed via extern */
uint16_t user_code_selector = 0;
uint16_t user_data_selector = 0;
uint16_t tss_selector = 0;

/*-----------------------------------------------------------------------------
 * External Assembly Functions
 *-----------------------------------------------------------------------------*/
extern void gdt_flush(uint32_t gdt_ptr);
extern void tss_flush_with_selector(uint16_t selector);

/*-----------------------------------------------------------------------------
 * Read current GDT
 *-----------------------------------------------------------------------------*/
static void read_current_gdt(struct gdt_ptr* current_gdtr) {
    __asm__ volatile("sgdt %0" : "=m"(*current_gdtr));
}

/*-----------------------------------------------------------------------------
 * Set a GDT Entry
 *-----------------------------------------------------------------------------*/
static void gdt_set_entry(int index, uint32_t base, uint32_t limit,
                          uint8_t access, uint8_t gran) {
    gdt[index].base_low    = (base & 0xFFFF);
    gdt[index].base_mid    = (base >> 16) & 0xFF;
    gdt[index].base_high   = (base >> 24) & 0xFF;
    
    gdt[index].limit_low   = (limit & 0xFFFF);
    gdt[index].granularity = gran;  // Just assign directly!
    gdt[index].granularity |= (limit >> 16) & 0x0F;
    
    gdt[index].access      = access;
}

/*=============================================================================
 * SECURITY FIX (Issue 12.2): Removed Duplicate gdt_set_tss_entry()
 *
 * DELETED: static void gdt_set_tss_entry(...)
 *
 * This was a duplicate of gdt_set_tss_descriptor() (which is used by tss.c).
 * Now we have a single function for setting TSS GDT entries.
 *===========================================================================*/

/*=============================================================================
 * SECURITY FIX (Issue 12.2): Removed Duplicate tss_init() Function
 *
 * DELETED: static void tss_init(uint16_t kernel_data_selector) { ... }
 *
 * This function initialized the WRONG TSS structure (the one in gdt.c that
 * wasn't loaded into the CPU). The real TSS initialization happens in
 * tss.c:tss_init(), which is called from kernel_main().
 *
 * Keeping this function would be confusing and error-prone.
 *===========================================================================*/


// Add this debug function to gdt.c (outside gdt_init)
static void dump_gdt_entry(int index) __attribute__((unused));
static void dump_gdt_entry(int index) {
    struct gdt_entry* entry = &gdt[index];
    uint32_t base = (entry->base_high << 24) | (entry->base_mid << 16) | entry->base_low;
    uint32_t limit = (entry->granularity & 0x0F) << 16 | entry->limit_low;
    uint8_t granularity = entry->granularity;
    uint8_t access = entry->access;

    kprintf("GDT[%d]: base=0x%08x limit=0x%05x gran=0x%02x access=0x%02x\n",
            index, base, limit, granularity, access);
}

/**
 * @brief Set a TSS descriptor in the GDT
 * @param num GDT entry number
 * @param base Physical address of TSS
 * @param limit Size of TSS - 1
 */
void gdt_set_tss_descriptor(int num, uint32_t base, uint32_t limit) {
    /*=========================================================================
     * SECURITY FIX (Issue 12.2): TSS Descriptor Flags
     *
     * CRITICAL: TSS descriptor must be properly configured for protected mode
     *
     * Access byte (0x89):
     * - Bit 7: Present = 1
     * - Bits 6-5: DPL = 0 (ring 0)
     * - Bit 4: 0 = system descriptor (not code/data)
     * - Bits 3-0: 1001 = Available 32-bit TSS (will become 1011 after LTR)
     *
     * Granularity byte:
     * - Bit 7: G = 0 (byte granularity, not 4K page granularity)
     * - Bits 6-4: Available for system software / Reserved = 0
     *   NOTE: Bit 6 (D/B) is NOT used for TSS descriptors!
     *   It only applies to code/data segments.
     * - Bits 3-0: Limit[19:16]
     *=======================================================================*/

    /* Set base address */
    gdt[num].base_low = (base & 0xFFFF);
    gdt[num].base_mid = ((base >> 16) & 0xFF);
    gdt[num].base_high = ((base >> 24) & 0xFF);

    /* Set limit */
    gdt[num].limit_low = (limit & 0xFFFF);
    gdt[num].granularity = ((limit >> 16) & 0x0F);

    /* Set access byte: Present, Ring 0, Available 32-bit TSS */
    gdt[num].access = 0x89;  /* 10001001 - Present=1, DPL=0, Type=1001 (32-bit TSS) */

    /* Granularity: byte granularity (G=0), upper limit bits only */
    /* NOTE: Do NOT set bit 6 - it has no meaning for TSS descriptors! */
    gdt[num].granularity |= 0x00;  /* Just use limit bits, G=0 for byte granularity */
}

/*-----------------------------------------------------------------------------
 * MODIFIED Initialize GDT - Copy GRUB's GDT and extend it
 *-----------------------------------------------------------------------------*/
void gdt_init(void) {
    // Read GRUB's current GDT (silent)
    struct gdt_ptr grub_gdtr;
    read_current_gdt(&grub_gdtr);

    // Calculate how many entries GRUB has
    int grub_entries = (grub_gdtr.limit + 1) / sizeof(struct gdt_entry);

    // Copy GRUB's GDT entries to our GDT
    struct gdt_entry* grub_gdt = (struct gdt_entry*)grub_gdtr.base;
    for (int i = 0; i < grub_entries && i < 8; i++) {
        gdt[i] = grub_gdt[i];
    }

    // Detect GRUB's kernel data selector (usually 0x10 or 0x18)
    uint16_t kernel_data_sel;
    __asm__ volatile("mov %%ds, %0" : "=r"(kernel_data_sel));

    // Add our user mode segments starting after GRUB's entries
    int next_free = grub_entries;
    if (next_free < 3) next_free = 3;  // Safety

    // Track which indices we use for user segments
    int user_code_index = next_free;
    int user_data_index = next_free + 1;
    int tss_index = next_free + 2;

    // Add user code segment - BASE MUST BE 0!
    gdt_set_entry(user_code_index, 0, 0xFFFFF, GDT_UCODE_ACCESS,
                  GDT_GRAN_4K | GDT_GRAN_32BIT | 0x0F);

    user_code_selector = user_code_index * 8;
    next_free++;

    // Add user data segment - BASE MUST BE 0!
    gdt_set_entry(user_data_index, 0, 0xFFFFF, GDT_UDATA_ACCESS,
                  GDT_GRAN_4K | GDT_GRAN_32BIT | 0x0F);

    user_data_selector = user_data_index * 8;
    next_free++;

    /*=========================================================================
     * SECURITY FIX (Issue 12.2): TSS Initialization Moved to tss.c
     *
     * REMOVED: tss_init() and gdt_set_tss_entry() calls from here
     *
     * The TSS is now initialized separately by calling tss.c:tss_init() from
     * kernel_main() AFTER gdt_init(). This provides:
     * - Single source of truth for TSS management
     * - Proper page alignment validation
     * - Centralized esp0 management with validation
     *
     * TSS GDT entry (at index 5) will be added by tss.c:tss_init() which
     * calls gdt_set_tss_descriptor().
     *=======================================================================*/

    // Track TSS index for later (will be populated by tss_init)
    tss_selector = tss_index * 8;

    // SET UP GDT POINTER (reserve space for TSS entry to be added later)
    gdtr.limit = (sizeof(struct gdt_entry) * (tss_index + 1)) - 1;
    gdtr.base = (uint32_t)&gdt[0];

    // Memory synchronization
    __asm__ volatile("" : : : "memory");  // Compiler memory barrier

    // Load the GDT
    gdt_flush((uint32_t)&gdtr);
}


/*-----------------------------------------------------------------------------
 * Load TSS (must be called after gdt_init)
 *-----------------------------------------------------------------------------*/
void tss_load(void) {
    if (tss_selector == 0) {
        return;
    }

    // Call assembly function with correct selector
    __asm__ volatile(
        "mov %0, %%ax\n"
        "ltr %%ax"
        : : "r"((uint16_t)tss_selector) : "ax"
    );
}

/*=============================================================================
 * SECURITY FIX (Issue 12.2): Removed Buggy tss_set_kernel_stack() Function
 *
 * DELETED: void tss_set_kernel_stack(uint32_t stack) { tss.esp0 = stack; }
 *
 * CRITICAL BUG: This function updated the WRONG TSS structure!
 *
 * The scheduler called this function 3 times per context switch:
 * - scheduler.c:466, 709, 1068
 *
 * But it updated `gdt.c:tss.esp0`, NOT `tss.c:tss.esp0` (the real TSS).
 * Result: All esp0 updates from the scheduler were SILENTLY IGNORED!
 *
 * The CPU continued using the initial esp0 value set during boot, which
 * could cause kernel stack corruption if multiple user processes tried to
 * enter the kernel simultaneously.
 *
 * FIX: Use tss.c:tss_set_kernel_stack() which updates the correct TSS and
 * includes validation to prevent corruption.
 *===========================================================================*/

    
/*-----------------------------------------------------------------------------
 * Switch to User Mode, this version has incorporated user memory management
 *-----------------------------------------------------------------------------*/
void switch_to_user_mode(uint32_t user_code_addr, uint32_t user_stack_addr) {
    kprintf("=== switch_to_user_mode START ===\n");
    kprintf("User code: 0x%08x, User stack: 0x%08x\n", user_code_addr, user_stack_addr);

    // Calculate selectors with RPL=3 from the dynamically created segments
    uint16_t user_code_sel_rpl3 = user_code_selector | 0x3;
    uint16_t user_data_sel_rpl3 = user_data_selector | 0x3;

    kprintf("Using selectors: CS=0x%04x, DS=0x%04x\n", user_code_sel_rpl3, user_data_sel_rpl3);

    // Debug: check page mappings
    kprintf("Checking user code page mapping...\n");
    uint32_t code_phys = virt_to_phys(user_code_addr);
    kprintf("  virt=0x%08x -> phys=0x%08x\n", user_code_addr, code_phys);

    kprintf("Checking user stack page mapping...\n");
    uint32_t stack_phys = virt_to_phys(user_stack_addr - 4096); // Stack grows down
    kprintf("  stack virt=0x%08x -> phys=0x%08x\n", user_stack_addr - 4096, stack_phys);

    kprintf("About to switch to user mode...\n");

    // Build IRET frame and switch to user mode
    asm volatile(
        "cli              \n"  // Disable interrupts during switch

        // Build IRET frame on KERNEL stack (using kernel segments)
        "pushl %2         \n"  // SS (user data selector with RPL=3)
        "pushl %0         \n"  // ESP (user stack pointer)
        "pushl $0x3002    \n"  // EFLAGS (IOPL=3 for I/O access, interrupts disabled, reserved bit 1)
        "pushl %3         \n"  // CS (user code selector with RPL=3)
        "pushl %1         \n"  // EIP (user code entry point)

        // NOW set data segments to user mode (after IRET frame is built!)
        // Don't use stack or memory after this point!
        "movw %w2, %%ax   \n"  // Load user data selector
        "mov %%ax, %%ds   \n"
        "mov %%ax, %%es   \n"
        "mov %%ax, %%fs   \n"
        "mov %%ax, %%gs   \n"

        "iret             \n"  // Switch to user mode!
        :
        : "r" (user_stack_addr), "r" (user_code_addr),
          "r" ((uint32_t)user_data_sel_rpl3), "r" ((uint32_t)user_code_sel_rpl3)
        : "memory", "eax"
    );

    // This should never be reached
    kprintf("ERROR: Returned from IRET!\n");
}


// Add this function to verify GDT is loaded correctly
void verify_gdt_loaded(void) {
    struct gdt_ptr current_gdtr;
    __asm__ volatile("sgdt %0" : "=m"(current_gdtr));
 
    kprintf("Inside verify_gdt_loaded...\n");
    kprintf("Current GDT: base=0x%08x, limit=0x%04x\n", 
            current_gdtr.base, current_gdtr.limit);
    
    // Check if it matches our expected GDT
    if (current_gdtr.base == (uint32_t)&gdt[0]) {
        kprintf("GDT load: SUCCESS (matches our GDT)\n");
    } else {
        kprintf("GDT load: FAILED (expected 0x%08x, got 0x%08x)\n",
                (uint32_t)&gdt[0], current_gdtr.base);
    }
}

void verify_gdt_entries(void) {
    kprintf("=== GDT VERIFICATION AFTER SETUP ===\n");
    
    // Check user code segment
    struct gdt_entry* entry = &gdt[4];
    uint32_t base = (entry->base_high << 24) | (entry->base_mid << 16) | entry->base_low;
    kprintf("User Code (index 4): base=0x%08x, access=0x%02x, gran=0x%02x\n",
            base, entry->access, entry->granularity);
    
    // Check user data segment  
    entry = &gdt[5];
    base = (entry->base_high << 24) | (entry->base_mid << 16) | entry->base_low;
    kprintf("User Data (index 5): base=0x%08x, access=0x%02x, gran=0x%02x\n",
            base, entry->access, entry->granularity);
    
    kprintf("=== END GDT VERIFICATION ===\n\n");
}


// Use in gdt.S, enter_user_mode added this debug
void debug_user_switch(uint32_t eip, uint32_t cs, uint32_t ss) {
    kprintf("DEBUG USER SWITCH: EIP=0x%08x, CS=0x%04x, SS=0x%04x\n", eip, cs, ss);
}

// Add this to gdt.c
void debug_enter_user_mode(uint32_t func, uint32_t stack, uint16_t code_sel, uint16_t data_sel) {
    kprintf("DEBUG enter_user_mode assembly:\n");
    kprintf("  Function: 0x%08x\n", func);
    kprintf("  Stack:    0x%08x\n", stack);
    kprintf("  CS:       0x%04x\n", code_sel);
    kprintf("  SS:       0x%04x\n", data_sel);
    
    // Verify RPL bits
    if ((code_sel & 3) != 3) {
        kprintf("  ERROR: CS selector 0x%04x missing RPL=3! (has RPL=%d)\n", 
                code_sel, code_sel & 3);
    } else {
        kprintf("  CS RPL check: GOOD (RPL=3)\n");
    }
    
    if ((data_sel & 3) != 3) {
        kprintf("  ERROR: SS selector 0x%04x missing RPL=3! (has RPL=%d)\n",
                data_sel, data_sel & 3);
    } else {
        kprintf("  SS RPL check: GOOD (RPL=3)\n");
    }
    
    // Check stack alignment
    if ((stack & 0xF) != 0) {
        kprintf("  WARNING: Stack not 16-byte aligned! (alignment: %d bytes)\n", stack & 0xF);
    } else {
        kprintf("  Stack alignment: GOOD (16-byte aligned)\n");
    }
}


// Add this function to gdt.c
void debug_user_segments(void) {
    kprintf("=== USER SEGMENTS DEBUG ===\n");
    
    // Check user code segment at index 4
    struct gdt_entry* entry = &gdt[4];
    uint8_t access = entry->access;
    kprintf("User Code (index 4): access=0x%02x\n", access);
    kprintf("  Present: %d, DPL: %d, Type: %s, Conforming: %d, Readable: %d\n",
            (access >> 7) & 1, (access >> 5) & 3,
            (access & 0x08) ? "Code" : "Data",
            (access >> 2) & 1, (access >> 1) & 1);
    
    // Check user data segment at index 5
    entry = &gdt[5];
    access = entry->access;
    kprintf("User Data (index 5): access=0x%02x\n", access);
    kprintf("  Present: %d, DPL: %d, Type: %s, Expand-down: %d, Writable: %d\n",
            (access >> 7) & 1, (access >> 5) & 3,
            (access & 0x08) ? "Code" : "Data",
            (access >> 2) & 1, (access >> 1) & 1);
    
    kprintf("=== END USER SEGMENTS DEBUG ===\n\n");
}


