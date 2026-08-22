/*=============================================================================
 *  kernel.c Ã¢â‚¬â€œ TinyOS Main Kernel Entry Point and Initialization
 *=============================================================================*/
#include "kernel.h"
#include "fbcon.h"
#include "idt.h"
#include "pmm.h"
#include "paging.h"
#include "serial.h"
#include "kprintf.h"
#include "pic.h"
#include "pit.h"
#include "time.h"
#include "net.h"
#include "dns.h"
#include "dhcp.h"
#include "icmp.h"
#include "tcp.h"
#include "http_test.h"
#include "tcp_tests.h"
#include "gdt.h"
#include "tss.h"
#include "syscall.h"
#include "memory.h"
#include "util.h"
#include "process.h"
#include "scheduler.h"
#include "test_tasks.h"
#include "supervisor.h"
#include "elf.h"
#include "hello_elf_data.h"
#include "sleeper_elf_data.h"
#include "spawner_elf_data.h"
#include "fileio_elf_data.h"
#include "producer_elf_data.h"
#include "counter_elf_data.h"
#include "credprobe_elf_data.h"
#include "netprobe_elf_data.h"
#include "msealprobe_elf_data.h"
#include "callprobe_elf_data.h"
#include "busyprobe_elf_data.h"
#include "slotbomb_elf_data.h"
#include "slothold_elf_data.h"
#include "shell_elf_data.h"
#include "shell.h"
#include "keyboard.h"
#include "ramfs.h"
#include "ramfs_vfs.h"  /* RAMFS VFS driver */
#include "vfs.h"
#include "ide.h"        /* IDE/ATA disk driver */
#include "fat32.h"      /* FAT32 filesystem */
#include "fat32_vfs.h"  /* FAT32 VFS driver */
#include "user.h"  /* User/Group management (v1.10) */
#include "crypto.h" /* Cryptographic infrastructure (v1.14) */
#include "ecdsa.h"  /* ECDSA P-256 digital signatures (v1.14) */
#include "audit.h"  /* Security audit logging (v1.14) */
/* #include "secure_delete.h" */ /* DISABLED: Secure file deletion (v1.14) - causing crashes */
#include "secure_boot.h" /* Secure boot chain (v1.15) */
#include "trusted_signing_key.h" /* Pinned ELF signing public key */
#include "firewall.h" /* Packet filtering firewall (v1.16) */
#include "ids.h" /* Intrusion Detection System (v1.17) */
#include "env.h"
#include "entropy.h" /* Hardware RNG (RDRAND) + Entropy Pool (v2.0) */
#include "stack_guard.h" /* Stack Smashing Protection (v1.19) */
#include "aslr.h" /* Address Space Layout Randomization (v1.20) */
#include "edr_advanced.h" /* EDR Phase 3: Advanced Detection */
#include "edr_ml.h" /* EDR Phase 4a: Threat Intelligence + Automated Response */


/*-----------------------------------------------------------------------------
 * User Stack Alignment variable to verify in the stack setup
 *-----------------------------------------------------------------------------*/
// #define USER_STACK_SIZE 4096
// static uint8_t user_stack[USER_STACK_SIZE] __attribute__((aligned(16)));

/*-----------------------------------------------------------------------------
 * Double Fault Handler Dedicated Stack (8 KiB)
 * CRITICAL: This stack is used exclusively by the Double Fault handler
 * to ensure we can safely diagnose exceptions that corrupt the main stack
 *-----------------------------------------------------------------------------*/
static uint8_t double_fault_stack[8192] __attribute__((aligned(16))) __attribute__((unused));
#define DOUBLE_FAULT_STACK_TOP ((uint32_t)double_fault_stack + sizeof(double_fault_stack))

/*-----------------------------------------------------------------------------
 * Local Function Prototypes
 *-----------------------------------------------------------------------------*/
static void ip_to_string(const uint8_t* ip, char* buffer, size_t buffer_size);


/*-----------------------------------------------------------------------------
 * HELPER: ip_to_string
 * Convert IP byte array to string "xxx.xxx.xxx.xxx"
 *-----------------------------------------------------------------------------*/
static void ip_to_string(const uint8_t* ip, char* buffer, size_t buf_size) {
    if (buf_size < 16u) return;  // Need at least 16 bytes for "255.255.255.255\0"

    size_t pos = 0;
    for (size_t i = 0; i < 4u; i++) {
        uint8_t octet = ip[i];

        // Convert octet to string (without sprintf)
        if (octet >= 100u) {
            buffer[pos++] = (char)('0' + (octet / 100u));
            octet = (uint8_t)(octet % 100u);
        }
        if (octet >= 10u || ip[i] >= 100u) {
            buffer[pos++] = (char)('0' + (octet / 10u));
            octet = (uint8_t)(octet % 10u);
        }
        buffer[pos++] = (char)('0' + octet);

        // Add dot separator (except after last octet)
        if (i < 3u) {
            buffer[pos++] = '.';
        }
    }
    buffer[pos] = '\0';
}

/*=============================================================================
 * FUNCTION: kernel_main
 *============================================================================*/
void kernel_main(uint32_t magic, uint32_t info_ptr) {
    /* Initialize serial port (COM1) for debug output */
    serial_init();

    /* Activate the framebuffer console if GRUB honored the Multiboot2
     * framebuffer tag (boot.s). Must run before the first console output;
     * falls back silently to VGA text mode when no usable mode was set. */
    fbcon_early_init(magic, (const void*)(uintptr_t)info_ptr);

    /* Clear screen (framebuffer or VGA text) and reset cursor */
    console_clear();

    if (fbcon_active()) {
        uint32_t fb_w, fb_h, fb_cols, fb_rows;
        fbcon_get_mode(&fb_w, &fb_h, &fb_cols, &fb_rows);
        kprintf("[FBCON] Framebuffer console %ux%ux32 (%ux%u text)\n",
                fb_w, fb_h, fb_cols, fb_rows);
    }

    /* Disable interrupts during initialization */
    __asm__ volatile("cli");

    /*=========================================================================
     * CRITICAL: Enable FPU and SSE Support
     *
     * FXSAVE/FXRSTOR instructions (used by scheduler for context switching)
     * will cause #UD (Invalid Opcode) exception if CR4.OSFXSR is not set
     * OR if the CPU doesn't support FXSR feature.
     *
     * CR0 Configuration:
     *   - Bit 2 (EM): Must be 0 (Emulation disabled)
     *   - Bit 5 (NE): Must be 1 (Numeric Error reporting enabled)
     *   - Bit 1 (MP): Should be 1 (Monitor Coprocessor)
     *
     * CR4 Configuration:
     *   - Bit 9 (OSFXSR): Must be 1 (OS support for FXSAVE/FXRSTOR)
     *   - Bit 10 (OSXMMEXCPT): Must be 1 (OS support for SIMD exceptions)
     *=======================================================================*/
    uint32_t cr0, cr4;

    /* Check CPUID for FXSR support (CPUID.1:EDX bit 24) */
    uint32_t cpuid_edx;
    __asm__ volatile(
        "mov $1, %%eax\n"        /* CPUID function 1 */
        "cpuid\n"
        : "=d"(cpuid_edx)        /* Output: EDX register */
        :
        : "eax", "ebx", "ecx"    /* Clobbered registers */
    );

    bool fxsr_supported = (cpuid_edx & (1 << 24)) != 0;  /* FXSR bit */
    bool sse_supported = (cpuid_edx & (1 << 25)) != 0;   /* SSE bit */

    /* Configure CR0 for FPU support */
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 &= ~(1 << 2);  /* Clear EM (Emulation) bit */
    cr0 |= (1 << 1);   /* Set MP (Monitor Coprocessor) bit */
    cr0 |= (1 << 5);   /* Set NE (Numeric Error) bit */
    __asm__ volatile("mov %0, %%cr0" :: "r"(cr0));

    /*=========================================================================
     * SECURITY FIX (v2.0): Enforce FXSR Capability Requirement
     *
     * VULNERABILITY (Issue 2.3): Context switch code (context_switch.S) uses
     * FXSAVE/FXRSTOR instructions unconditionally. If CPU lacks FXSR support,
     * this causes #UD (Invalid Opcode) exception during first context switch.
     *
     * ROOT CAUSE: Previous code detected lack of FXSR but allowed boot to
     * continue. There was no fallback to legacy FSAVE/FRSTOR, causing crash.
     *
     * FIX: Enforce FXSR as a minimum CPU requirement. TinyOS requires:
     * - FXSR (FXSAVE/FXRSTOR) for 512-byte FPU state save/restore
     * - Pentium II / Athlon or newer (1997+)
     *
     * RATIONALE: Adding legacy FSAVE/FRSTOR fallback is complex:
     * 1. FSAVE only saves 108 bytes (no SSE registers)
     * 2. Would need runtime branching in context_switch.S
     * 3. Modern crypto/networking code expects SSE anyway
     *
     * Modern OSes (Linux, Windows, BSD) all require FXSR.
     *=======================================================================*/
    if (!fxsr_supported) {
        kprintf("\n");
        kprintf("*****************************************************************\n");
        kprintf("*  BOOT FAILED: CPU DOES NOT SUPPORT REQUIRED FEATURES         *\n");
        kprintf("*****************************************************************\n");
        kprintf("\n");
        kprintf("TinyOS requires FXSAVE/FXRSTOR instructions (CPUID.1:EDX[24]).\n");
        kprintf("\n");
        kprintf("Minimum CPU requirements:\n");
        kprintf("  - Intel: Pentium II (1997) or newer\n");
        kprintf("  - AMD:   Athlon (1999) or newer\n");
        kprintf("\n");
        kprintf("Your CPU:\n");
        kprintf("  FXSR support: NO (required)\n");
        kprintf("  SSE support:  %s\n", sse_supported ? "YES" : "NO");
        kprintf("\n");
        kprintf("QEMU users: Use -cpu core2duo or similar modern CPU model.\n");
        kprintf("\n");
        kprintf("System halting to prevent #UD exception during context switch.\n");
        kprintf("*****************************************************************\n");
        kernel_panic("CPU lacks FXSR support (required for FXSAVE/FXRSTOR)");
    }

    /* Configure CR4 for SSE/FXSAVE support (CPU supports it, enforced above) */
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= (1 << 9);   /* Set OSFXSR (FXSAVE/FXRSTOR support) bit */
    if (sse_supported) {
        cr4 |= (1 << 10);  /* Set OSXMMEXCPT (SIMD exception support) bit */
    }
    __asm__ volatile("mov %0, %%cr4" :: "r"(cr4));

    /* Initialize FPU to clean state */
    __asm__ volatile("fninit");

    /*=========================================================================
     * CRITICAL: Initialize Hardware RNG / Entropy Pool FIRST
     *
     * Provides cryptographically strong randomness for:
     * - Stack canary generation (SSP)
     * - Address space randomization (ASLR)
     * - Cryptographic operations
     *
     * Uses Intel RDRAND/RDSEED if available, falls back to entropy pool
     * with TSC jitter and other unpredictable sources.
     *
     * Timing: FIRST security initialization (others depend on this)
     *=========================================================================*/
    entropy_init();

    /*=========================================================================
     * CRITICAL: Initialize Stack Protection EARLY
     *
     * SECURITY: Must be called BEFORE any stack-protected functions run.
     * This initializes the global canary (__stack_chk_guard) that GCC's
     * -fstack-protector-strong instrumentation will use.
     *
     * Timing: After entropy_init(), before everything else
     *=========================================================================*/
    stack_guard_init();

    /*=========================================================================
     * SECURITY: Initialize ASLR (Address Space Layout Randomization)
     *
     * ASLR randomizes memory addresses to make exploitation harder.
     * Even if attacker finds a buffer overflow, they don't know where to jump.
     *
     * Timing: After entropy_init(), before any processes are created
     *=========================================================================*/
    aslr_init();

    /* DEBUG: Print current segment selectors from GRUB - DISABLED for cleaner boot */
#ifdef VERBOSE_DEBUG
    uint16_t cs_val, ds_val, ss_val;
    __asm__ volatile("mov %%cs, %0" : "=r"(cs_val));
    __asm__ volatile("mov %%ds, %0" : "=r"(ds_val));
    __asm__ volatile("mov %%ss, %0" : "=r"(ss_val));
    // kprintf("[DEBUG] GRUB selectors: CS=0x%04x DS=0x%04x SS=0x%04x\n", cs_val, ds_val, ss_val);
    // kprintf("[DEBUG] CPUID: FXSR=%d SSE=%d\n", fxsr_supported ? 1 : 0, sse_supported ? 1 : 0);
    // kprintf("[DEBUG] FPU/SSE enabled: CR0=0x%08x CR4=0x%08x\n", cr0, cr4);
#endif

    /*=========================================================================
     * PHASE 1: BOOT INFORMATION DISPLAY (MINIMAL)
     *=========================================================================*/
    kprintf("\n~*~ Starting TinyOS ~*~\n\n");
    kprintf("   (\\_/)  Small .\n");
    kprintf("   (o.o)  Footprint _\n");
    kprintf("   (> <)  Big   ##\n");
    kprintf("   /^|^\\  Heart <3\n");
    kprintf("\n");
    kprintf("~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~\n");
    kprintf("   %s\n", TINYOS_VERSION_NAME);
    kprintf("~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~\n");
    kprintf("\n");

    if (magic != 0x36D76289) {
        kprintf("ERROR: Not Multiboot2!\n");

        /*
         * SECURITY FIX: Use kernel_panic instead of inline halt loop
         * Provides recursion protection and consistent error handling
         */
        kernel_panic("Invalid Multiboot2 magic number");
    }

    /*=========================================================================
     * PHASE 2: IDT SETUP (SILENT)
     *=========================================================================*/
    idt_init();

    /* DEBUG: Verify IDT entry 24 and IDT location - DISABLED for cleaner boot */
#ifdef VERBOSE_DEBUG
    {
        struct idt_entry* e = &idt[24];
        uint32_t offset = ((uint32_t)e->offset_high << 16) | e->offset_low;
        // kprintf("[DEBUG] IDT entry size: %u bytes (should be 8)\n", (unsigned)sizeof(struct idt_entry));
        // kprintf("[DEBUG] IDT array at: 0x%08x\n", (uint32_t)&idt[0]);
        // kprintf("[DEBUG] IDT[24] at: 0x%08x (offset from base: %u bytes)\n",
        //         (uint32_t)e, (unsigned)((uint32_t)e - (uint32_t)&idt[0]));
        // kprintf("[DEBUG] IDT[24]: offset=0x%08x selector=0x%04x flags=0x%02x zero=0x%02x\n",
        //         offset, e->selector, e->type_attr, e->zero);
        (void)offset; (void)e;  // Suppress unused variable warnings
    }
#endif

    /*=========================================================================
     * PHASE 2.5: GDT AND USER MODE SETUP (SILENT)
     *=========================================================================*/
    gdt_init();
    tss_init();  /* Initialize TSS with page alignment and validation (Issue 12.2) */

    idt_setup_syscall();

    /*=========================================================================
     * SECURITY FIX (Issue 12.2): Removed Redundant tss_load()
     *
     * CRITICAL: Do NOT call tss_load() after tss_init()!
     *
     * Reason: The LTR (Load Task Register) instruction can only be executed
     * on an "Available" TSS (type 0x9). After the first LTR in tss_init(),
     * the CPU automatically changes the TSS type to "Busy" (type 0xB).
     * Executing LTR again on a Busy TSS causes #GP (General Protection Fault).
     *
     * Previous bug: kernel.c called both tss_init() and tss_load(), causing:
     * 1. tss_init() loads TSS (type 0x9 -> 0xB) [SUCCESS]
     * 2. tss_load() tries to load again (type 0xB) [#GP EXCEPTION!]
     *
     * Fix: tss_init() now handles both descriptor creation AND loading.
     * No need for separate tss_load() call.
     *=======================================================================*/

    /*=========================================================================
     * PHASE 3: PMM INITIALIZATION (SILENT)
     *=========================================================================*/
    pmm_init_from_mb2((const void*)(uintptr_t)info_ptr);

    /* DEBUG: Check if PMM corrupted IDT[24] - DISABLED for cleaner boot */
#ifdef VERBOSE_DEBUG
    {
        struct idt_entry* e = &idt[24];
        uint32_t offset = ((uint32_t)e->offset_high << 16) | e->offset_low;
        // kprintf("[DEBUG] After PMM: IDT[24] offset=0x%08x selector=0x%04x\n",
        //         offset, e->selector);
        (void)offset; (void)e;  // Suppress unused variable warnings
    }
#endif

    /*=========================================================================
     * PHASE 4: PAGING WITH W^X SUPPORT
     *=========================================================================*/

    /* Try to initialize PAE for W^X enforcement */
    pae_init();

    /* If PAE is not active, fall back to 32-bit paging */
    if (!pae_is_active()) {
        paging_identity_map_early(32u * 1024u * 1024u);
    }

    /* Enable paging (CR0.PG) - works for both PAE and 32-bit modes */
    paging_enable();

    /* Only use recursive paging in 32-bit mode (not compatible with PAE) */
    if (!pae_is_active()) {
        init_recursive_paging();
    }

    /*=========================================================================
     * SECURITY FIX (Issue 12.1): Kernel Memory Layout Verification
     *
     * CRITICAL: Verify kernel W^X enforcement BEFORE running any user code.
     * This runtime check ensures linker assertions were respected and detects:
     * - Section misalignment (breaks page-granular protection)
     * - Section overlap (creates W^X gaps)
     * - .text pages that are writable (code injection risk)
     * - .data/.bss pages that are executable (ROP gadget risk)
     *
     * ATTACK PREVENTION:
     * - Prevents exploitation if linker script is misconfigured
     * - Catches compiler optimization bugs that violate W^X
     * - Verifies ASLR doesn't break memory layout assumptions
     *
     * Triggers kernel panic if violations detected.
     *=======================================================================*/
    if (pae_is_active()) {
        if (!pae_verify_kernel_layout()) {
            kernel_panic("Kernel layout verification failed - W^X policy violated!");
        }
        kprintf("[SECURITY] Kernel layout verification passed\n");
    }
    // Skip debug output
    // debug_memory_state();

    /* Only preallocate page tables in 32-bit mode (uses recursive paging) */
    if (!pae_is_active()) {
        pre_alloc_user_page_tables();
    }

    // Skip debug output
    // debug_page_directory();

    /*=========================================================================
     * PHASE 5: PMM TEST (Silent)
     *
     * SECURITY: PMM Allocation Failure Check
     * CRITICAL: Even test code must check for allocation failures. If memory
     * is exhausted during boot, attempting to free NULL (0x0) could corrupt
     * the PMM bitmap or cause undefined behavior.
     *=========================================================================*/
    uint32_t a = pmm_alloc();
    uint32_t b = pmm_alloc();

    if (!a || !b) {
        kprintf("[MEM] CRITICAL: PMM allocation failed during boot test!\n");
        kprintf("[MEM] Available frames: %u (Free memory: %u KB)\n",
                pmm_free_frames(), (pmm_free_frames() * PMM_PAGE_SIZE) / 1024);
        panic("Insufficient memory for kernel operation");
    }

    pmm_free(a);
    pmm_free(b);

    kprintf("[MEM] Allocating Cozy Memory Pages.. [OK]\n");
    kprintf("[MEM] System RAM: 256 MB............ [OK]\n");

    /*=========================================================================
     * PHASE 6: PIC AND TIMER SETUP (BEFORE NETWORK!) - Silent
     *=========================================================================*/
    /* Remap PIC to vectors 32-47 */
    pic_remap();

    /* Start with all IRQs masked */
    pic_mask_all();

    /* Initialize PIT timer (100 Hz) */
    pit_init(100);

    /* Initialize RTC and system time */
    rtc_init();
    time_init();

    /* Environment variables are initialized PER SHELL SESSION, in shell_task()
     * after login -- not here. Storage is per-task (task->env), so a boot-time
     * call would have no task to populate: scheduler_get_current_task() returns
     * NULL this early and env_init() would allocate nothing.
     *
     * This call sat commented out as "TEMPORARILY DISABLED FOR TESTING" from
     * the initial public release onward, which left the whole subsystem inert:
     * `env`, `set` and `alias` all reported empty and $VAR expanded to nothing,
     * while every command that consumed them was wired and working. */

    /* Initialize PS/2 keyboard driver */
#ifdef VERBOSE_DEBUG
    uint32_t esp_before;
    __asm__ volatile("mov %%esp, %0" : "=r"(esp_before));
    // kprintf("[DEBUG] ESP before keyboard_init: 0x%08x\n", esp_before);
#endif

    keyboard_init();

#ifdef VERBOSE_DEBUG
    uint32_t esp_after;
    __asm__ volatile("mov %%esp, %0" : "=r"(esp_after));
    // kprintf("[DEBUG] ESP after keyboard_init: 0x%08x (delta: %d bytes)\n",
    //         esp_after, (int)(esp_after - esp_before));
#endif

    /* CRITICAL FIX: Keep ALL IRQs masked until AFTER sti completes
     * This prevents spurious/pending interrupts from firing during the
     * critical transition when interrupts are enabled */

    /* Enable CPU interrupts with all PIC IRQs still masked */
    __asm__ volatile("sti");

    /* NOW unmask specific IRQs we want (timer, keyboard, E1000) */
    pic_unmask(0);   /* Timer */
    pic_unmask(1);   /* Keyboard */
    keyboard_enable_irq();  /* Notify keyboard driver that IRQ is now enabled */
    pic_unmask(11);  /* E1000 */

    /* Force unmask cascade/E1000 if needed (silent fix) */
    uint8_t master = inb(0x21);
    uint8_t slave = inb(0xA1);
    if (master & 0x04u) {
        outb(0x21, (uint8_t)(master & ~0x04u));
    }
    if (slave & 0x08u) {
        outb(0xA1, (uint8_t)(slave & ~0x08u));
    }

    /* Wait for timer to confirm interrupts work */
    uint32_t start = get_timer_ticks();
    uint32_t timeout = 0;
    while (get_timer_ticks() == start && timeout++ < 10000000);

    if (timeout >= 10000000) {
        kprintf("ERROR: Timer interrupt not working!\n");
        for (;;) __asm__ volatile("hlt");
    }

    /*=========================================================================
     * PHASE 7: IDE/ATA DISK INITIALIZATION
     *=========================================================================*/
    ide_init();

    /*=========================================================================
     * PHASE 8: NETWORK INITIALIZATION (AFTER INTERRUPTS READY!)
     *=========================================================================*/
    kprintf("[NET] Waking up the Network......... [OK]\n");
    net_init();
    tcp_init();

    /*=========================================================================
     * PHASE 9: DHCP CLIENT INITIALIZATION
     *=========================================================================*/
    /*
     * CRITICAL: Clear my_ip to 0.0.0.0 before DHCP discovery
     *
     * Problem: my_ip is initialized to a default IP (192.168.0.80) at compile time.
     * During DHCP discovery, the DHCP server sends an ARP probe (WHO-HAS 192.168.0.80?)
     * to check if the IP is already in use. If we respond to this ARP request,
     * the DHCP server thinks the IP is taken and won't offer it.
     *
     * Solution: Set my_ip to 0.0.0.0 before DHCP starts. This prevents us from
     * responding to ARP probes during DHCP discovery. After DHCP completes,
     * my_ip will be set to the assigned IP by set_network_config().
     */
    my_ip[0] = 0;
    my_ip[1] = 0;
    my_ip[2] = 0;
    my_ip[3] = 0;
    kprintf("[NET] IP cleared (0.0.0.0) for DHCP.. [OK]\n");

    dhcp_init();
    dhcp_start();

    /* Wait for DHCP to complete (with timeout) */
    kprintf("[NET] DHCP: Waiting for IP address...\n");
    uint32_t dhcp_start_ticks = get_timer_ticks();
    uint32_t dhcp_max_ticks = 3000;  // 30 seconds at 100 Hz (increased from 10s for slower networks)
    uint32_t last_dot_ticks = dhcp_start_ticks;

    while (!dhcp_is_configured()) {
        /* Poll network for DHCP responses */
        e1000_poll_rx();

        /* Drain the RX softirq ring by hand: e1000_poll_rx() only queues
         * frames now (doc/NETWORK_ISOLATION.md item 1), and knetd — which
         * normally drains it — does not exist yet. Without this the DHCP
         * offer sits in the ring until the scheduler starts and the lease
         * always times out. Safe here because this loop is thread context,
         * so handle_packet() runs with interrupts enabled exactly as it does
         * under knetd. */
        e1000_rx_softirq_run();

        uint32_t now_ticks = get_timer_ticks();
        uint32_t elapsed = now_ticks - dhcp_start_ticks;

        /* Check timeout */
        if (elapsed >= dhcp_max_ticks) {
            break;  // Timeout
        }

        /* Print progress dots every ~1 second */
        if ((now_ticks - last_dot_ticks) >= 100) {
            kprintf(".");
            last_dot_ticks = now_ticks;
        }

        /*
         * CRITICAL: Yield CPU to allow timer interrupts to fire
         *
         * Problem: e1000_poll_rx() uses E1000_LOCK() which disables interrupts (cli).
         * If we poll continuously without pausing, the cumulative time with interrupts
         * disabled prevents timer interrupts from firing, causing get_timer_ticks()
         * to stop incrementing, which breaks our timeout calculation.
         *
         * Solution: Use hlt to pause until next interrupt (usually timer at 100Hz).
         * This guarantees at least 10ms between polls, giving timers time to update.
         *
         * Performance: Polling every 10ms is sufficient for DHCP (server responds
         * in ~100ms minimum). We don't need to poll at full CPU speed.
         */
        __asm__ volatile("hlt");  // Wait for next interrupt (timer tick)
    }

    if (dhcp_is_configured()) {
        /* DHCP module already printed success message */
        char ip_str[16];
        ip_to_string(my_ip, ip_str, sizeof(ip_str));
        kprintf("[NET] Assigned IP: %s..... [OK]\n", ip_str);
    } else {
        kprintf(" [TIMEOUT]\n");
        kprintf("[NET] DHCP: Failed to get IP address\n");

        /*=========================================================================
         * APIPA (Automatic Private IP Addressing) - RFC 3927
         *=========================================================================
         *
         * When DHCP fails, use link-local auto-configuration (like Windows/macOS).
         * This assigns an IP in the 169.254.0.0/16 range, allowing:
         * - Local network communication without DHCP
         * - Zero-configuration networking
         * - No IP conflicts across different networks
         *
         * RFC 3927 specifies:
         * - Range: 169.254.1.0 to 169.254.254.255
         * - Netmask: 255.255.0.0 (16-bit prefix)
         * - No default gateway (link-local only)
         *
         * IMPLEMENTATION:
         * We generate a pseudo-random IP using entropy and MAC address
         * to minimize collisions when multiple machines auto-configure.
         *=========================================================================*/
        kprintf("[NET] Using APIPA (link-local IP)...\n");

        /* Generate pseudo-random APIPA address: 169.254.x.y
         * Use entropy and MAC address for randomization to avoid collisions */
        uint32_t entropy_val = 0;
        entropy_get_bytes((uint8_t*)&entropy_val, sizeof(entropy_val));

        /* Combine MAC address and entropy for randomization
         * This makes it unlikely two machines get the same APIPA address */
        uint32_t seed = (my_mac[4] << 8) | my_mac[5];
        seed ^= (entropy_val & 0xFFFF);

        /* Generate x in range [1, 254] (avoid 0 and 255)
         * Use modulo 254 + 1 to get range [1, 254] */
        uint8_t x = ((seed >> 8) % 254) + 1;
        uint8_t y = (seed % 254) + 1;

        /* APIPA address: 169.254.x.y */
        uint8_t apipa_ip[4] = {169, 254, x, y};
        uint8_t apipa_mask[4] = {255, 255, 0, 0};  /* /16 netmask */
        uint8_t apipa_gateway[4] = {0, 0, 0, 0};   /* No gateway for link-local */

        set_network_config(apipa_ip, apipa_mask, apipa_gateway);

        char ip_str[16];
        ip_to_string(my_ip, ip_str, sizeof(ip_str));
        kprintf("[NET] APIPA address: %s (link-local)\n", ip_str);
        kprintf("[NET] Netmask: 255.255.0.0\n");
        kprintf("[NET] Gateway: none (link-local only)\n");
    }

    /*=========================================================================
     * PHASE 10: CRYPTOGRAPHIC SUBSYSTEM INITIALIZATION
     *=========================================================================*/
    kprintf("[CRYPTO] Initializing crypto subsystem.. [OK]\n");
    crypto_init();
    kprintf("[CRYPTO] Initializing ECDSA P-256.......");
    if (!ecdsa_init()) {
        /* The generator point failed its on-curve check, which means the curve
         * arithmetic is broken -- the same routine guards ecdsa_verify()'s
         * check on the supplied public key, so ELF signature enforcement
         * cannot be trusted. Refuse to continue rather than verify with it. */
        kprintf(" [FAIL]\n");
        kernel_panic("ECDSA P-256 self-test failed (generator point off curve)");
    }
    kprintf(" [OK]\n");
    kprintf("[AUDIT] Initializing audit logging......");
    audit_init();
    kprintf(" [OK]\n");
    firewall_init();

    /*=========================================================================
     * FIREWALL RULES CONFIGURATION
     *
     * SECURITY: Configure firewall rules BEFORE network traffic starts
     * to prevent the "DENY ALL" policy from blocking legitimate traffic.
     *
     * REQUIRED RULES:
     * 1. Allow DHCP (UDP 67/68) - for IP address acquisition
     * 2. Allow DNS (UDP 53) - for name resolution
     * 3. Allow established connections - for response packets
     * 4. Allow ICMP - for ping/diagnostics
     *=======================================================================*/
    kprintf("[FIREWALL] Configuring allow rules........\n");

    /* Allow outgoing traffic (required for DHCP client requests) */
    firewall_allow_outgoing();
    kprintf("[FIREWALL]   - Outgoing connections: ALLOW\n");

    /* Allow established/related connections (stateful inspection) */
    firewall_allow_established();
    kprintf("[FIREWALL]   - Established connections: ALLOW\n");

    /* Allow ICMP (ping, traceroute, etc.) */
    firewall_allow_icmp();
    kprintf("[FIREWALL]   - ICMP (ping): ALLOW\n");

    /* Note: DHCP ports 67/68 UDP are already handled by outgoing rule */
    /* Note: DNS port 53 UDP is handled by established connections */

#ifdef TINYOS_FAULT_INJECT
    /* verify-tcp-rx-counters.sh only.
     *
     * The harness injects crafted TCP segments to prove that malformed inbound
     * headers are COUNTED rather than printed. Since c5fa987 made the firewall
     * default-deny, those segments never reach the L4 dispatch at all: they die
     * at firewall.c's `Default: DENY ALL`, one layer ABOVE tcp_handle_packet(),
     * and every counter the harness reads stays 0 -- including its positive
     * control. The harness FAILed with `malformed 0 (expected 20)` against a
     * completely correct kernel, and contains no firewall reference to explain
     * it. (`ifconfig`'s FW verdict line now makes that diagnosis immediate.)
     *
     * None of the four standing accept paths can carry it: firewall-disabled is
     * not an option, the DHCP 68->67 exception returns true ABOVE match_rule()
     * so it cannot exercise a rule, an ESTABLISHED flow does not exist for an
     * injected segment, and no ACCEPT rule covers inbound TCP.
     *
     * So this is the vehicle, and it is deliberately the narrowest one: a
     * single destination port, TCP only, at the same priority 50 as the
     * standing ICMP rule -- NOT a loosening of the default deny, which stays
     * exactly as it is for every other port and protocol. It is compiled out of
     * every default build, like every other fault-injection hook.
     *
     * Port 80 matches tools/inject_frames.py's --tcp-dst-port default. If that
     * default changes, this must change with it or the harness silently returns
     * to reading zeroes. */
    firewall_allow_port(80, IPPROTO_TCP, "FAULT_INJECT: TCP RX counter harness");
    kprintf("[FIREWALL]   - TCP/80 inbound: ALLOW (TINYOS_FAULT_INJECT)\n");
#endif

    kprintf("[FIREWALL] Configuration complete........ [OK]\n");

    ids_init();

    /* DISABLED: secure_delete causing intermittent crashes */
    /* kprintf("[SECURE_DELETE] Initializing............ [OK]\n"); */
    /* secure_delete_init(); */

    /* Pin the ELF signing key. Whether unsigned binaries are rejected is a
     * separate question, decided at build time in elf.c -- see
     * elf_signatures_enforced(). */
    secure_boot_init(tinyos_trusted_signing_key);

    /* Initialize EDR Advanced Detection (Phase 3) */
    edr_advanced_init();

    /* Initialize EDR Phase 4a MVP: Threat Intelligence + Automated Response */
    edr_ti_init();
    edr_response_init();

    /*=========================================================================
     * PHASE 11: USER SYSTEM, VFS AND FAT32/RAM FILESYSTEM INITIALIZATION
     *=========================================================================*/
    user_init();  /* Initialize user/group database (v1.10) */
    vfs_init();

    /* Initialize and mount FAT32 filesystem from disk */
    fat32_init();
    if (fat32_mount() == 0) {
        fat32_vfs_init();  /* Register FAT32 as VFS driver */
        vfs_mount('C', "fat32");  /* Mount C: as FAT32 */
        kprintf("[VFS] C: drive mounted as FAT32\n");
    } else {
        kprintf("[VFS] WARNING: FAT32 mount failed, C: drive not available\n");
    }

    /* Initialize RAMFS and mount as D: drive */
    ramfs_init();
    ramfs_vfs_init();  /* Register RAMFS as VFS driver */
    vfs_mount('D', "ramfs");  /* Mount D: as RAMFS (for temp/system workloads) */
    kprintf("[VFS] D: drive mounted as RAMFS\n");

    /* Test VFS directory operations on D: drive (RAMFS) */
    kprintf("[TEST] Creating D:/hello directory via VFS...\n");
    int mkdir_result = vfs_mkdir("D:/hello");
    if (mkdir_result < 0) {
        kprintf("[TEST] WARNING: vfs_mkdir(\"D:/hello\") failed with code %d\n", mkdir_result);
    } else {
        kprintf("[TEST] Directory D:/hello created successfully via VFS\n");
    }

    kprintf("[TEST] Creating D:/hello/test.txt file via VFS...\n");
    int test_fd = vfs_open("D:/hello/test.txt", VFS_O_WRONLY | VFS_O_CREAT);
    if (test_fd >= 0) {
        const char* test_data = "Hello from VFS on D: drive (RAMFS)!\nVFS integration is working.\n";
        ssize_t bytes_written = vfs_write(test_fd, test_data, strlen(test_data));
        kprintf("[TEST] VFS file created: fd=%d, wrote %d bytes\n", test_fd, bytes_written);
        vfs_close(test_fd);
        kprintf("[TEST] Test file D:/hello/test.txt created successfully via VFS [OK]\n");
    } else {
        kprintf("[TEST] ERROR: vfs_open(\"D:/hello/test.txt\") failed with code %d\n", test_fd);
    }

    /* Stage the embedded signed demo binary on the RAMFS (D:/system) drive so
     * 'exec /hello.elf' has something to run. */
    {
        int elf_fd = ramfs_open("/hello.elf", RAMFS_FLAG_WRITE);
        if (elf_fd >= 0) {
            ramfs_write(elf_fd, hello_elf_data, hello_elf_data_len);
            ramfs_close(elf_fd);
            /* RAMFS creates files 0600 (RAMFS_DEFAULT_FILE_MODE), which is
             * root-only. These are programs meant to be run BY user processes:
             * task_create_user gives a ring-3 task uid 1000, so without an
             * other-readable mode SYS_SPAWN's open fails with -EACCES. The
             * shell's own `exec` is unaffected (it runs as root), which is why
             * only the spawn path exposed this. */
            ramfs_chmod("/hello.elf", 0755);
        }
    }

    /* sleeper.elf runs for ~6 seconds, unlike hello.elf which exits in
     * milliseconds. It exists so 'exec /sleeper.elf &' leaves a child that is
     * still ALIVE when the next shell command runs — without it, `jobs` and
     * `ps` can never observe a background job. */
    {
        int sleeper_fd = ramfs_open("/sleeper.elf", RAMFS_FLAG_WRITE);
        if (sleeper_fd >= 0) {
            ramfs_write(sleeper_fd, sleeper_elf_data, sleeper_elf_data_len);
            ramfs_close(sleeper_fd);
            /* RAMFS creates files 0600 (RAMFS_DEFAULT_FILE_MODE), which is
             * root-only. These are programs meant to be run BY user processes:
             * task_create_user gives a ring-3 task uid 1000, so without an
             * other-readable mode SYS_SPAWN's open fails with -EACCES. The
             * shell's own `exec` is unaffected (it runs as root), which is why
             * only the spawn path exposed this. */
            ramfs_chmod("/sleeper.elf", 0755);
        }
    }

    /* shell.elf is the ring-3 shell (roadmap item 4) and is the DEFAULT LOGIN
     * SHELL since PR #51 -- login runs it directly (see shell.c's
     * "Run /shell.elf as the ring-3 login shell"), and the kernel shell is now
     * the fallback, reached with `kshell`. It spawns other programs itself, so
     * it must be readable by uid 1000 for the same reason as the binaries
     * above. */
    {
        int shell_fd = ramfs_open("/shell.elf", RAMFS_FLAG_WRITE);
        if (shell_fd >= 0) {
            ramfs_write(shell_fd, shell_elf_data, shell_elf_data_len);
            ramfs_close(shell_fd);
            ramfs_chmod("/shell.elf", 0755);
        }
    }

    /* spawner.elf exercises SYS_SPAWN from ring 3: it spawns /hello.elf with
     * arguments and waits for it. `exec` alone cannot prove that path, since
     * the shell loads processes from inside the kernel. */
    {
        int spawner_fd = ramfs_open("/spawner.elf", RAMFS_FLAG_WRITE);
        if (spawner_fd >= 0) {
            ramfs_write(spawner_fd, spawner_elf_data, spawner_elf_data_len);
            ramfs_close(spawner_fd);
            /* RAMFS creates files 0600 (RAMFS_DEFAULT_FILE_MODE), which is
             * root-only. These are programs meant to be run BY user processes:
             * task_create_user gives a ring-3 task uid 1000, so without an
             * other-readable mode SYS_SPAWN's open fails with -EACCES. The
             * shell's own `exec` is unaffected (it runs as root), which is why
             * only the spawn path exposed this. */
            ramfs_chmod("/spawner.elf", 0755);
        }
    }

    /* producer.elf | counter.elf is the ring-3 pipeline fixture (SYS_PIPE).
     * Both stages have to be PROGRAMS: a pipeline stage is a process, and the
     * shell cannot be both the producer and the consumer at once. 0755 for the
     * same uid-1000 reason as spawner.elf above — the ring-3 shell spawns
     * these, so they must be readable by a non-root process. */
    {
        int producer_fd = ramfs_open("/producer.elf", RAMFS_FLAG_WRITE);
        if (producer_fd >= 0) {
            ramfs_write(producer_fd, producer_elf_data, producer_elf_data_len);
            ramfs_close(producer_fd);
            ramfs_chmod("/producer.elf", 0755);
        }

        int counter_fd = ramfs_open("/counter.elf", RAMFS_FLAG_WRITE);
        if (counter_fd >= 0) {
            ramfs_write(counter_fd, counter_elf_data, counter_elf_data_len);
            ramfs_close(counter_fd);
            ramfs_chmod("/counter.elf", 0755);
        }
    }

    /* credprobe.elf calls the DEPRECATED credential syscalls (SYS_SWITCH_USER,
     * SYS_CHANGE_PASSWORD) directly through int 0x80. No shell offers those
     * calls, so a probe that bypasses the shell entirely is the only way to
     * assert the ring-3 gate holds at the SYSCALL BOUNDARY rather than merely
     * that nothing happens to invoke them. 0755 for the same uid-1000 reason as
     * spawner.elf above. */
    {
        int credprobe_fd = ramfs_open("/credprobe.elf", RAMFS_FLAG_WRITE);
        if (credprobe_fd >= 0) {
            ramfs_write(credprobe_fd, credprobe_elf_data, credprobe_elf_data_len);
            ramfs_close(credprobe_fd);
            ramfs_chmod("/credprobe.elf", 0755);
        }
    }

    /* netprobe.elf drives SYS_NETRX/SYS_NETTX straight through int 0x80
     * (doc/NETDAEMON_DESIGN.md item 4, PR B). Nothing in the kernel calls those
     * syscalls yet — the parser has not moved to ring 3 — so the boundary is
     * unreachable from any shell command, and "networking still works" is what
     * a build with the boundary bypassed shows too. Only a ring-3 caller can
     * demonstrate frames traversing the pair. 0755 for the same uid-1000 reason
     * as spawner.elf above; the syscalls themselves are root-only, which is
     * half of what this probe exists to assert. */
    {
        int netprobe_fd = ramfs_open("/netprobe.elf", RAMFS_FLAG_WRITE);
        if (netprobe_fd >= 0) {
            ramfs_write(netprobe_fd, netprobe_elf_data, netprobe_elf_data_len);
            ramfs_close(netprobe_fd);
            ramfs_chmod("/netprobe.elf", 0755);
        }
    }

    /* msealprobe.elf drives SYS_MSEAL (16) straight through int 0x80. That
     * syscall has no libc wrapper and no shell builtin, so no other program in
     * the tree reaches it -- which is how sixteen ring-3-driven kprintf sites
     * sat on that path unnoticed until the mseal audit. Every rejection it
     * provokes uses its OWN arguments and needs no privilege, so 0755 is
     * correct and deliberate: the point is that an unprivileged caller drives
     * these counters. See verify-mseal-counters.sh. */
    {
        int msealprobe_fd = ramfs_open("/msealprobe.elf", RAMFS_FLAG_WRITE);
        if (msealprobe_fd >= 0) {
            ramfs_write(msealprobe_fd, msealprobe_elf_data, msealprobe_elf_data_len);
            ramfs_close(msealprobe_fd);
            ramfs_chmod("/msealprobe.elf", 0755);
        }
    }

    /* callprobe.elf drives the syscall dispatcher's reject counters. An
     * out-of-range syscall number reaches the range check with no libc
     * wrapper, no builtin and no privilege behind it -- the number is the
     * caller's own byte -- so nothing in the tree produced one and the three
     * kprintf sites there went unnoticed, the same way SYS_MSEAL's sixteen
     * did. 0755 is deliberate: the point is that an UNPRIVILEGED caller
     * drives these counters. See verify-syscall-reject-counters.sh. */
    {
        int callprobe_fd = ramfs_open("/callprobe.elf", RAMFS_FLAG_WRITE);
        if (callprobe_fd >= 0) {
            ramfs_write(callprobe_fd, callprobe_elf_data, callprobe_elf_data_len);
            ramfs_close(callprobe_fd);
            ramfs_chmod("/callprobe.elf", 0755);
        }
    }

    /* busyprobe.elf holds a descriptor open across an unlink, which no shell
     * builtin does -- cmd_path_op opens nothing, and every builtin that opens
     * a file closes it before returning. Without a driver the busy refusal has
     * nothing to conflict with and a harness would pass against the unfixed
     * kernel. 0755: an unprivileged caller must be able to drive it, since the
     * use-after-free it prevents needed no privilege either.
     * See verify-ramfs-unlink-busy.sh. */
    {
        int busyprobe_fd = ramfs_open("/busyprobe.elf", RAMFS_FLAG_WRITE);
        if (busyprobe_fd >= 0) {
            ramfs_write(busyprobe_fd, busyprobe_elf_data, busyprobe_elf_data_len);
            ramfs_close(busyprobe_fd);
            ramfs_chmod("/busyprobe.elf", 0755);
        }
    }

    /* slotbomb.elf spawns /slothold.elf in a tight loop WITHOUT reaping, to
     * prove the per-user concurrent task cap engages (see verify-slotcap.sh).
     * Like credprobe.elf it has to bypass the shell: the cap lives in
     * task_create_user, and a shell-driven `&` loop is slow enough under TCG
     * that the RATE limiter would stop it first, which would pass against a
     * kernel with no cap at all.
     *
     * slothold.elf is the child, NOT sleeper.elf: each spawn costs a full ECDSA
     * verification under TCG, so ~6s sleeper children would exit and free their
     * slots before the loop finished and the cap would never be reached.
     *
     * Both 0755 for the same uid-1000 reason as spawner.elf above. */
    {
        int slotbomb_fd = ramfs_open("/slotbomb.elf", RAMFS_FLAG_WRITE);
        if (slotbomb_fd >= 0) {
            ramfs_write(slotbomb_fd, slotbomb_elf_data, slotbomb_elf_data_len);
            ramfs_close(slotbomb_fd);
            ramfs_chmod("/slotbomb.elf", 0755);
        }

        int slothold_fd = ramfs_open("/slothold.elf", RAMFS_FLAG_WRITE);
        if (slothold_fd >= 0) {
            ramfs_write(slothold_fd, slothold_elf_data, slothold_elf_data_len);
            ramfs_close(slothold_fd);
            ramfs_chmod("/slothold.elf", 0755);
        }
    }

    /* fileio.elf exercises SYS_OPEN/SYS_CLOSE/SYS_READDIR from ring 3. It needs
     * a file it is allowed to write, but RAMFS's root directory is 0755 and
     * root-owned, so a uid-1000 process cannot create one. Seed it empty here
     * and make it 0666 — the demo opens it O_WRONLY|O_TRUNC. */
    {
        int fileio_fd = ramfs_open("/fileio.elf", RAMFS_FLAG_WRITE);
        if (fileio_fd >= 0) {
            ramfs_write(fileio_fd, fileio_elf_data, fileio_elf_data_len);
            ramfs_close(fileio_fd);
            ramfs_chmod("/fileio.elf", 0755);
        }

        /* The demo works inside /fio rather than the RAMFS root, because the
         * root is 0700 (RAMFS_DEFAULT_DIR_MODE) and a uid-1000 process cannot
         * list or write it. Deliberate hardening — give the test its own
         * world-readable directory instead of loosening the root. */
        if (ramfs_mkdir("/fio") >= 0) {
            ramfs_chmod("/fio", 0755);
        }

        int data_fd = ramfs_open("/fio/fileio-test.txt", RAMFS_FLAG_WRITE);
        if (data_fd >= 0) {
            ramfs_close(data_fd);
            ramfs_chmod("/fio/fileio-test.txt", 0666);
        }

        /* A second entry, so readdir has to return more than one name and the
         * demo's search cannot pass by finding whatever happens to be first. */
        int marker_fd = ramfs_open("/fio/marker.txt", RAMFS_FLAG_WRITE);
        if (marker_fd >= 0) {
            ramfs_write(marker_fd, "marker", 6);
            ramfs_close(marker_fd);
            ramfs_chmod("/fio/marker.txt", 0644);
        }

        /* A separate 0777 scratch directory for the mkdir/rmdir/unlink demo.
         * It cannot share /fio: that one is 0755 root-owned, so a uid-1000
         * process cannot create entries in it, and loosening it would break
         * the readdir test's "exactly two entries" expectation. */
        if (ramfs_mkdir("/scratch") >= 0) {
            ramfs_chmod("/scratch", 0777);
        }
    }

    // Temporary removed the PHASE 8 to 10 Networking Tests to fasten testing of 11.


    /*=========================================================================
     * PHASE 12: MULTITASKING INITIALIZATION (Silent)
     *=========================================================================*/
    kprintf("[SHELL] Dusting off the Tinyshell... [OK]\n");

    // Initialize process management
    process_init();

    // Initialize scheduler
    scheduler_init();

    // Create shell task
    int pid_shell_kernel = task_create_kernel(shell_task, "Shell");
    if (pid_shell_kernel < 0) {
        kprintf("ERROR: Failed to create Shell task\n");
        for(;;) __asm__ volatile("hlt");
    }

    // Create test task that will exit after 3 seconds (only in test builds)
#ifdef TINYOS_ENABLE_TESTS
    int pid_exit_test = task_create_kernel(task_exit_test, "ExitTest");
    if (pid_exit_test < 0) {
        kprintf("ERROR: Failed to create ExitTest task\n");
        for(;;) __asm__ volatile("hlt");
    }
#endif

    /* Create Idle task - PID 2 */
    int pid_idle = task_create_kernel(task_idle, "Idle");
    if (pid_idle < 0) {
        kprintf("ERROR: Failed to create Idle task\n");
        for(;;) __asm__ volatile("hlt");
    }

    /* Create ktimerd - runs the deferred timer bottom-half (tcp/dhcp/EDR/
     * reseed) in task context so it can't corrupt interrupted computations. */
    int pid_ktimerd = task_create_kernel(task_ktimerd, "ktimerd");
    if (pid_ktimerd < 0) {
        kprintf("ERROR: Failed to create ktimerd task\n");
        for(;;) __asm__ volatile("hlt");
    }

    /* RX bottom half. Without it the e1000 ISR still queues frames but nothing
     * parses them, so the box goes silently deaf — fatal, same as ktimerd. */
    int pid_knetd = task_create_kernel(task_knetd, "knetd");
    if (pid_knetd < 0) {
        kprintf("ERROR: Failed to create knetd task\n");
        for(;;) __asm__ volatile("hlt");
    }

    /*
     * Supervise knetd (doc/NETDAEMON_DESIGN.md item 4, PR D2).
     *
     * knetd cannot currently be killed: task_create_kernel() assigns CAP_ALL
     * (process.c), which is 0xFFFFFFFF and therefore INCLUDES CAP_UNKILLABLE,
     * so sys_kill refuses every kernel task. The explicit `|= CAP_UNKILLABLE`
     * grants further down are redundant for that reason -- they are kept only
     * because they document intent for the three tasks that would still want it
     * if the default ever narrowed.
     *
     * So supervision is not closing a live `kill <pid>` hole today; it is the
     * prerequisite for PR D1, which moves the parser to ring 3 where the whole
     * premise is that it CAN die -- crash, fault, or be killed -- and must come
     * back. Protection is the wrong answer there: a ring-3 parser that faults
     * cannot be protected into staying alive, only restarted.
     *
     * Registered here, watched by task_supervisor below.
     */
    supervisor_init();
    supervisor_watch("knetd", task_knetd, (uint32_t)pid_knetd);

    int pid_supervisor = task_create_kernel(task_supervisor, "supervisor");
    if (pid_supervisor < 0) {
        kprintf("ERROR: Failed to create supervisor task\n");
        for(;;) __asm__ volatile("hlt");
    }

    /* Start EDR daemon (Phase 4a MVP) - protected background monitoring.
     * Take the pid it returns. This used to be hardcoded `pid_edr = 3` with the
     * comment "created third" -- but PIDs are crypto-random in 100..65535
     * (process.c), so 3 can never be allocated: task_get(3) returned NULL on
     * every boot and the EDR grant below never executed once. The missing
     * "[KERNEL] EDR daemon protected" line was the only evidence, and it reads
     * as a line that simply is not there rather than as a failure. */
    int pid_edr = edr_daemon_start();

    /* Protect critical system processes with CAP_UNKILLABLE.
     *
     * These ORs are REDUNDANT today: task_create_kernel() grants CAP_ALL
     * (0xFFFFFFFF), which already includes CAP_UNKILLABLE. They are kept
     * because they document which tasks would still need it if that default
     * ever narrowed -- but the log lines below deliberately say "already
     * protected" rather than "protected", because announcing a no-op as a
     * security step is how the EDR bug stayed invisible: the operation the
     * line described was not the reason the task was safe. */
    task_t* shell_task_ptr = task_get((uint32_t)pid_shell_kernel);
    task_t* idle_task_ptr = task_get((uint32_t)pid_idle);
    task_t* edr_task_ptr = task_get((uint32_t)pid_edr);

    if (shell_task_ptr) {
        shell_task_ptr->capabilities |= CAP_UNKILLABLE;
        kprintf("[KERNEL] Shell already protected (CAP_UNKILLABLE via CAP_ALL)\n");
    }
    if (idle_task_ptr) {
        idle_task_ptr->capabilities |= CAP_UNKILLABLE;
        kprintf("[KERNEL] Idle already protected (CAP_UNKILLABLE via CAP_ALL)\n");
    }
    if (edr_task_ptr) {
        edr_task_ptr->capabilities |= CAP_UNKILLABLE;
        kprintf("[KERNEL] EDR daemon already protected (CAP_UNKILLABLE via CAP_ALL)\n");
    } else {
        /* Loud, because the silent version of this hid a dead grant for the
         * lifetime of the feature. */
        kprintf("[KERNEL] WARNING: EDR daemon task not found (pid %d) - not protected\n",
                pid_edr);
    }

    /*
     * The supervisor itself IS protected, and knetd deliberately is not.
     * That asymmetry is the design: the supervised task must stay killable or
     * the restart path can never be exercised (and after PR D1 it must be able
     * to die anyway), while a killable supervisor would let one `kill` disable
     * restarts for everything it watches -- turning a recoverable failure back
     * into a permanent one, silently.
     */
    task_t* supervisor_task_ptr = task_get((uint32_t)pid_supervisor);
    if (supervisor_task_ptr) {
        supervisor_task_ptr->capabilities |= CAP_UNKILLABLE;
        kprintf("[KERNEL] Supervisor already protected (CAP_UNKILLABLE via CAP_ALL)\n");
    }

    // Set task priorities
    task_set_priority(task_get((uint32_t)pid_shell_kernel), PRIORITY_HIGH);     // Shell is interactive
#ifdef TINYOS_ENABLE_TESTS
    task_set_priority(task_get((uint32_t)pid_exit_test), PRIORITY_NORMAL);      // Test task
#endif
    task_set_priority(task_get((uint32_t)pid_idle), PRIORITY_IDLE);             // Idle task (lowest)
    task_set_priority(task_get((uint32_t)pid_ktimerd), PRIORITY_HIGH);          // Timer bottom-half (responsive)
    /* EDR priority is set inside edr_daemon_start() to PRIORITY_HIGH */

    int pid_user = -1;
    int pid_elf = -1;
    int pid_shell = -1;

    // Add tasks to scheduler ready queue
    scheduler_add_task(task_get((uint32_t)pid_shell_kernel));
#ifdef TINYOS_ENABLE_TESTS
    scheduler_add_task(task_get((uint32_t)pid_exit_test));
#endif
    if (pid_user >= 0) {
        scheduler_add_task(task_get((uint32_t)pid_user));
    }
    if (pid_elf >= 0) {
        scheduler_add_task(task_get((uint32_t)pid_elf));
    }
    if (pid_shell >= 0) {
        scheduler_add_task(task_get((uint32_t)pid_shell));
    }
    scheduler_add_task(task_get((uint32_t)pid_idle));
    scheduler_add_task(task_get((uint32_t)pid_ktimerd));
    scheduler_add_task(task_get((uint32_t)pid_knetd));
    /* task_create_kernel() does NOT enqueue -- every kernel task is added here
     * explicitly. Omitting this line leaves the supervisor created, registered
     * and CAP_UNKILLABLE, but never once scheduled: `ps` still lists it and
     * `ifconfig` still reports "1 watched", so the omission reads as healthy
     * from both status surfaces while nothing is actually being supervised. */
    scheduler_add_task(task_get((uint32_t)pid_supervisor));

    /* Same omission as the supervisor line above, and it hid the same way:
     * edr_daemon_start() creates the task, sets PRIORITY_HIGH and prints
     * "EDR daemon started successfully", so the boot log, `ps` and the
     * CAP_UNKILLABLE grant all show a healthy daemon -- while edr_daemon_main()
     * had never executed a single instruction. Every EDR counter therefore
     * read 0, which is indistinguishable from "scanned everything, found
     * nothing". The daemon whose serial spam CLAUDE.md tells us to grep away
     * was the syscall-path hook, not this task.
     *
     * Guarded because edr_daemon_start() returns -1 on failure, and
     * task_get(-1) would not find a task to enqueue. */
    if (pid_edr >= 0) {
        scheduler_add_task(task_get((uint32_t)pid_edr));
    }

    kprintf("[SHELL] Tinyshell is ready to play!  [OK]\n");

    // Start the scheduler (does not return)
    scheduler_start();

    /*=========================================================================
     * UNREACHABLE - Scheduler never returns
     *=========================================================================*/
    kprintf("ERROR: Scheduler returned!\n");
    for(;;) __asm__ volatile("hlt");
}
