/*=============================================================================
 * shell_system.c - Shell System Commands Implementation
 *=============================================================================*/
#include "shell_system.h"
#include "kprintf.h"
#include "pmm.h"
#include "process.h"
#include "kernel.h"
#include "util.h"
#include "pic.h"
#include "scheduler.h"
#include "time.h"
#include "env.h"
#include "audit.h"
#include "secure_delete.h"
#include "vfs.h"  /* For CAP_UNKILLABLE */
#include "syscall.h"  /* sys_kill: the kill policy lives there, not here */
#include "errno.h"
#include "critical.h"
#include "aslr.h"  /* For ASLR statistics */
#include "paging.h"  /* For PAE/W^X functions */
#include "security_tests.h"  /* For security test suite */
#include "firewall.h"  /* secstatus: firewall stats */
#include "ids.h"  /* secstatus: IDS stats */
#include "edr_ml.h"  /* secstatus: EDR daemon stats */
#include "secure_boot.h"  /* secstatus: secure-boot key pinning state */
#include "elf.h"          /* elf_signatures_enforced: the real ELF gate */
#include "stdio.h"  /* stream_printf / get_current_streams */
#include <stdint.h>
/* INT_MAX/INT_MIN from the compiler's own predefined macros rather than
 * <limits.h>. limits.h is a freestanding header, but a Linux-targeting
 * cross (gcc-i686-linux-gnu, which CI uses) reaches glibc's copy by
 * #include_next, and under -nostdinc that chain has nowhere to go. The
 * predefines are guaranteed by the compiler with no headers at all. */
#define INT_MAX  __INT_MAX__
#define INT_MIN  (-__INT_MAX__ - 1)
#include <stdbool.h>

/*=============================================================================
 * HELPER: Require root privilege for command execution
 * SECURITY: Prevents non-root users from executing destructive commands
 *=============================================================================*/
static bool require_root(const char *cmd) {
    /* Fetched here rather than passed in by each of the nine callers: the
     * refusal is the user's own error message and belongs on their stream, and
     * a helper that quietly wrote to the kernel console instead would make
     * `mem 2>/dev/null` print anyway. */
    stream_context_t* ctx = get_current_streams();

    task_t *t = scheduler_get_current_task();
    if (!t) {
        stream_printf(ctx, "%s: ERROR: Cannot determine current task\n", cmd);
        return false;
    }

    /* Check effective user ID (euid) for privilege */
    if (t->euid != 0) {
        stream_printf(ctx, "%s: permission denied (must be root)\n", cmd);
        stream_printf(ctx, "Current user: UID=%d EUID=%d (root is UID=0)\n",
                      t->uid, t->euid);
        return false;
    }

    return true;
}

/*=============================================================================
 * HELPER: Safe integer parsing with overflow protection
 *=============================================================================*/
static bool safe_parse_int(const char* str, int* result) {
    if (!str || !*str) {
        return false;
    }

    int value = 0;
    const char* p = str;

    /* Parse digits with overflow checking */
    while (*p >= '0' && *p <= '9') {
        int digit = *p - '0';

        /* Check for overflow before multiplication */
        if (value > (INT_MAX / 10)) {
            return false;  /* Would overflow */
        }

        value *= 10;

        /* Check for overflow before addition */
        if (value > (INT_MAX - digit)) {
            return false;  /* Would overflow */
        }

        value += digit;
        p++;
    }

    /* Ensure we consumed the entire string */
    if (*p != '\0') {
        return false;  /* Invalid characters */
    }

    /* Ensure we parsed at least one digit */
    if (p == str) {
        return false;  /* Empty string */
    }

    *result = value;
    return true;
}

/*=============================================================================
 * COMMAND: mem - Display memory usage
 *=============================================================================*/
void cmd_mem(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    /* Root only: the layout it prints (heap/stack bases, region addresses) is
     * exactly what an attacker needs to defeat the ASLR this kernel implements. */
    if (!require_root("mem")) {
        return;
    }

    /*=========================================================================
     * SECURITY FIX (v1.18): Enforce strict argument count
     *
     * Reject extra arguments to prevent command injection or unexpected
     * behavior. Dangerous commands should have well-defined, fixed argument
     * counts to reduce attack surface.
     *=======================================================================*/
    if (argc != 1) {
        stream_printf(ctx, "mem: command takes no arguments\n");
        stream_printf(ctx, "Usage: mem\n");
        return;
    }

    (void)argv;  /* Unused except for validation */

    uint32_t total = pmm_total_frames();
    uint32_t free = pmm_free_frames();
    uint32_t used = total - free;

    /*
     * Use uint64_t for KB calculation to prevent overflow on systems with >16GB RAM.
     * With 4KB pages, uint32_t overflows at 2^32 bytes = 4GB * 4 = 16GB.
     */
    uint64_t total_kb = (uint64_t)total * 4;
    uint64_t used_kb = (uint64_t)used * 4;
    uint64_t free_kb = (uint64_t)free * 4;

    stream_printf(ctx, "\nMemory Usage:\n");
    stream_printf(ctx, "  Total: %u frames (%llu KB)\n", total, total_kb);
    stream_printf(ctx, "  Used:  %u frames (%llu KB)\n", used, used_kb);
    stream_printf(ctx, "  Free:  %u frames (%llu KB)\n", free, free_kb);
    stream_printf(ctx, "\n");
}

/*=============================================================================
 * COMMAND: aslr - Display ASLR statistics
 *=============================================================================*/
void cmd_aslr(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    /* Root only: reporting the entropy and the randomized bases of the running
     * system tells a local attacker how much guessing ASLR actually costs them. */
    if (!require_root("aslr")) {
        return;
    }

    if (argc != 1) {
        stream_printf(ctx, "aslr: command takes no arguments\n");
        stream_printf(ctx, "Usage: aslr\n");
        return;
    }

    (void)argv;  /* Unused except for validation */

    aslr_stats_t stats;
    aslr_get_stats(&stats);

    stream_printf(ctx, "\n");
    stream_printf(ctx, "=== ASLR (Address Space Layout Randomization) ===\n");
    stream_printf(ctx, "\n");
    stream_printf(ctx, "Status: %s\n", stats.enabled ? "ENABLED" : "DISABLED");

    if (!stats.enabled) {
        stream_printf(ctx, "\nWARNING: ASLR is disabled - system is vulnerable!\n");
        stream_printf(ctx, "Stack addresses are predictable, making exploitation easier.\n");
        stream_printf(ctx, "\n");
        return;
    }

    stream_printf(ctx, "\nEntropy:\n");
    stream_printf(ctx, "  Bits:           %u bits\n", stats.entropy_bits);
    stream_printf(ctx, "  Page range:     4096 pages (16 MB)\n");
    stream_printf(ctx, "  Possible addrs: %u (2^%u)\n",
                  1U << stats.entropy_bits, stats.entropy_bits);
    /* No %f here on purpose. kprintf/vsnprintf_impl implement no float
     * conversion at all -- an unknown specifier is echoed literally AND its
     * argument is never consumed, so "%.4f" printed the four characters "%.4f"
     * and left every following vararg in that call misaligned. Both quantities
     * are exact integers anyway; the probability is expressed as the 1/N it
     * actually is rather than as a decimal the kernel cannot format. */
    stream_printf(ctx, "  Exploit chance: 1 in %u\n", 1U << stats.entropy_bits);

    stream_printf(ctx, "\nStatistics:\n");
    stream_printf(ctx, "  Stacks randomized: %u\n", stats.stacks_randomized);
    stream_printf(ctx, "  RNG reseeds:       %u\n", stats.rng_reseeds);

    if (stats.stacks_randomized > 0) {
        stream_printf(ctx, "\nAddress Range:\n");
        stream_printf(ctx, "  Minimum: 0x%08x\n", stats.min_stack_addr);
        stream_printf(ctx, "  Maximum: 0x%08x\n", stats.max_stack_addr);
        stream_printf(ctx, "  Spread:  %u KB\n",
                      (stats.max_stack_addr - stats.min_stack_addr) / 1024);
    }

    stream_printf(ctx, "\nSecurity Impact:\n");
    stream_printf(ctx, "  Without ASLR: Exploits work every time\n");
    stream_printf(ctx, "  With ASLR:    Exploits work 1 attempt in %u\n",
                  1U << stats.entropy_bits);
    stream_printf(ctx, "  Protection:   ~%ux harder to exploit\n",
                  1U << stats.entropy_bits);

    stream_printf(ctx, "\nNote: Combined with stack protection, TinyOS has\n");
    stream_printf(ctx, "      industry-grade exploit mitigation!\n");
    stream_printf(ctx, "\n");
}

/*=============================================================================
 * COMMAND: pae - Display PAE (Physical Address Extension) status
 *=============================================================================*/
void cmd_pae(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    (void)argc;
    (void)argv;

    /* Root only: this dumps page-directory and page-table PHYSICAL addresses,
     * which hands a local attacker the kernel's memory map directly. */
    if (!require_root("pae")) {
        return;
    }

    stream_printf(ctx, "\n=== PAE (Physical Address Extension) Status ===\n");
    stream_printf(ctx, "\nCPU Support:\n");

    if (pae_is_supported()) {
        stream_printf(ctx, "  PAE: SUPPORTED ✅\n");
    } else {
        stream_printf(ctx, "  PAE: NOT SUPPORTED ❌\n");
        stream_printf(ctx, "\nPAE is required for W^X (Write XOR Execute) enforcement.\n");
        stream_printf(ctx, "This CPU does not support PAE paging mode.\n\n");
        return;
    }

    /* Check NX bit support */
    uint32_t ext_features;
    uint32_t max_extended;

    __asm__ volatile(
        "mov $0x80000000, %%eax\n"
        "cpuid\n"
        : "=a"(max_extended)
        :: "ebx", "ecx", "edx"
    );

    bool nx_supported = false;
    if (max_extended >= 0x80000001) {
        __asm__ volatile(
            "mov $0x80000001, %%eax\n"
            "cpuid\n"
            : "=d"(ext_features)
            :: "eax", "ebx", "ecx"
        );
        nx_supported = (ext_features & (1 << 20)) != 0;
    }

    if (nx_supported) {
        stream_printf(ctx, "  NX bit: SUPPORTED ✅\n");
    } else {
        stream_printf(ctx, "  NX bit: NOT SUPPORTED ❌\n");
    }

    /* Check if PAE is currently enabled */
    uint32_t cr4;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    bool pae_enabled = (cr4 & (1 << 5)) != 0;

    stream_printf(ctx, "\nCurrent Status:\n");
    stream_printf(ctx, "  CR4.PAE: %s\n", pae_enabled ? "ENABLED" : "DISABLED");

    if (nx_supported && max_extended >= 0x80000001) {
        /* Check EFER.NXE */
        uint32_t eax, edx;
        __asm__ volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(0xC0000080));
        bool nx_enabled = (eax & (1 << 11)) != 0;
        stream_printf(ctx, "  EFER.NXE: %s\n", nx_enabled ? "ENABLED" : "DISABLED");

        if (!nx_enabled) {
            stream_printf(ctx, "\nNote: NX bit is supported but not enabled.\n");
            stream_printf(ctx, "      Call pae_enable_nx() to enable W^X protection.\n");
        }
    }

    stream_printf(ctx, "\nW^X Enforcement:\n");
    if (pae_enabled && nx_supported) {
        stream_printf(ctx, "  Status: READY ✅\n");
        stream_printf(ctx, "  Memory pages can be:\n");
        stream_printf(ctx, "    - Writable (data/stack) with NX bit set\n");
        stream_printf(ctx, "    - Executable (code) without NX bit\n");
        stream_printf(ctx, "    - Never BOTH writable AND executable\n");
    } else {
        stream_printf(ctx, "  Status: UNAVAILABLE ❌\n");
        if (!pae_enabled) {
            stream_printf(ctx, "  Reason: PAE mode not enabled\n");
        }
        if (!nx_supported) {
            stream_printf(ctx, "  Reason: CPU lacks NX bit support\n");
        }
    }

    stream_printf(ctx, "\nTo enable W^X:\n");
    stream_printf(ctx, "  1. Ensure PAE-capable CPU (done ✅)\n");
    stream_printf(ctx, "  2. Enable PAE in boot code (boot.s)\n");
    stream_printf(ctx, "  3. Call pae_init() during kernel init\n");
    stream_printf(ctx, "  4. Use pae_map_page() with NX flags\n");
    stream_printf(ctx, "  5. Run 'wxaudit' to verify enforcement\n");
    stream_printf(ctx, "\n");
}

/*=============================================================================
 * COMMAND: wxaudit - Audit memory for W^X violations
 *=============================================================================*/
void cmd_wxaudit(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    (void)argc;
    (void)argv;

    /* Root only: a W^X violation report is a list of pages that are both
     * writable and executable — i.e. where to put shellcode, ranked. */
    if (!require_root("wxaudit")) {
        return;
    }

    /* Run PAE W^X audit */
    uint32_t violations = pae_wx_audit();

    if (violations > 0) {
        stream_printf(ctx, "\nWARNING:️  WARNING: %u W^X violations detected!\n", violations);
        stream_printf(ctx, "Memory pages should NEVER be writable AND executable.\n");
        stream_printf(ctx, "This is a serious security vulnerability.\n\n");
    }
}

/*=============================================================================
 * COMMAND: kill - Terminate a task
 *=============================================================================*/
void cmd_kill(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    /*=========================================================================
     * SECURITY FIX (v1.18): Enforce strict argument count
     *
     * Reject extra arguments to prevent command injection or unexpected
     * behavior. The kill command takes exactly one argument (the PID).
     *=======================================================================*/
    if (argc != 2) {
        stream_printf(ctx, "Usage: kill <pid>\n");
        stream_printf(ctx, "kill: expected exactly 1 argument (pid), got %d\n", argc - 1);
        return;
    }

    /* Parse PID with overflow protection */
    int pid = 0;
    if (!safe_parse_int(argv[1], &pid)) {
        stream_printf(ctx, "kill: invalid PID: '%s'\n", argv[1]);
        return;
    }

    if (pid <= 0) {
        stream_printf(ctx, "kill: invalid PID: %d (must be positive)\n", pid);
        return;
    }

    /* The name is COPIED OUT before the kill, for the messages below: after
     * task_terminate the slot may already have been reused, so a task_t*
     * retained across it would print the wrong process's name.
     *
     * Copied under CRITICAL_SECTION and the pointer dropped immediately -- the
     * same slot reuse applies between task_get() and the read. The name is only
     * ever displayed on paths sys_kill has already permitted, so this is a
     * correctness guard on the message, not the policy check; the policy is
     * sys_kill's alone. */
    char name[TASK_NAME_LEN];
    name[0] = '\0';
    CRITICAL_SECTION_ENTER();
    {
        task_t* task = task_get(pid);
        if (task) {
            safe_strcpy(name, task->name, sizeof(name));
        }
    }
    CRITICAL_SECTION_EXIT();

    /*=========================================================================
     * The policy (own-only unless euid 0, CAP_UNKILLABLE protected, and an
     * invisible PID reported as nonexistent) lives in sys_kill, so the kernel
     * shell and ring 3 cannot drift apart. This function is now presentation:
     * it turns the errno into the messages this shell has always printed.
     *
     * -ESRCH covers both "no such process" and "not yours" deliberately --
     * distinguishing them would let a user enumerate every live PID, which is
     * exactly what filtering `ps` was meant to prevent.
     *=======================================================================*/
    int rc = sys_kill(pid);

    if (rc == -ESRCH) {
        stream_printf(ctx, "kill: no such process: %d\n", pid);
        return;
    }
    if (rc == -EPERM) {
        stream_printf(ctx, "kill: cannot kill protected system process '%s' (PID %d, CAP_UNKILLABLE)\n",
                      name, pid);
        stream_printf(ctx, "Processes 'Shell' and 'Idle' are essential and cannot be terminated.\n");
        return;
    }
    if (rc < 0) {
        stream_printf(ctx, "kill: invalid PID: %d\n", pid);
        return;
    }

    stream_printf(ctx, "Terminating task %d (%s)...\n", pid, name);
    stream_printf(ctx, "Task terminated.\n");
}

/*=============================================================================
 * COMMAND: shutdown - Shutdown the system
 *=============================================================================*/
void cmd_shutdown(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    /*=========================================================================
     * SECURITY FIX (v1.18): Enforce strict argument count
     *
     * Reject extra arguments to prevent command injection or unexpected
     * behavior. The shutdown command takes no arguments.
     *=======================================================================*/
    if (argc != 1) {
        stream_printf(ctx, "Usage: shutdown\n");
        stream_printf(ctx, "shutdown: command takes no arguments\n");
        return;
    }

    (void)argv;  /* Unused except for validation */

    /* SECURITY: Only root can shutdown the system */
    if (!require_root("shutdown")) {
        return;
    }

    /* kprintf, NOT stream_printf, and the same in cmd_reboot below. This is the
     * one class of output in this file that must not follow a redirect: the
     * machine halts a few lines later, so `shutdown > log` would put the notice
     * in a ramfs file that dies with the RAM and leave the user watching a
     * console that says nothing before it stops. The argument errors and the
     * permission refusal above DO belong on the user's stream -- the command
     * has not committed to halting at that point. */
    kprintf("\n        Sweet Dreams!\n");
    kprintf("        \n");
    kprintf("     (\\_/)   Tiny footprints,\n");
    kprintf("     (-.-)~  Big memories.\n");
    kprintf("     (> <)   Until next time!\n");
    kprintf("     \n");
    kprintf("   [ Shutting down... ]\n\n");

    /*
     * Brief delay for output to flush (assuming 100Hz timer, ~200ms delay).
     * Use scheduler yield instead of busy wait to allow other tasks to run.
     */
    uint32_t start = get_timer_ticks();
    while (get_timer_ticks() < start + 20) {
        scheduler_yield();
    }

    /*=========================================================================
     * CLEAN SHUTDOWN: Use system_halt() for graceful termination
     *
     * Previously used kernel_panic() which displays "KERNEL PANIC" - scary
     * and inappropriate for normal shutdowns. system_halt() provides clean
     * shutdown without panic messages.
     *=======================================================================*/
    system_halt();
}

/*=============================================================================
 * COMMAND: reboot - Reboot the system
 *=============================================================================*/
void cmd_reboot(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    /*=========================================================================
     * SECURITY FIX (v1.18): Enforce strict argument count
     *
     * Reject extra arguments to prevent command injection or unexpected
     * behavior. The reboot command takes no arguments.
     *=======================================================================*/
    if (argc != 1) {
        stream_printf(ctx, "Usage: reboot\n");
        stream_printf(ctx, "reboot: command takes no arguments\n");
        return;
    }

    (void)argv;  /* Unused except for validation */

    /* SECURITY: Only root can reboot the system */
    if (!require_root("reboot")) {
        return;
    }

    kprintf("Rebooting...\n");  /* console, not the stream -- see cmd_shutdown */

    /*
     * Brief delay for output to flush (assuming 100Hz timer, ~200ms delay).
     * Use scheduler yield instead of busy wait to allow other tasks to run.
     */
    uint32_t start = get_timer_ticks();
    while (get_timer_ticks() < start + 20) {
        scheduler_yield();
    }

    /* Use keyboard controller to reboot */
    uint8_t temp;
    __asm__ volatile("cli");  /* Disable interrupts */

    /*
     * CRITICAL: Clear keyboard controller with memory barriers.
     * Memory barriers prevent CPU reordering of I/O operations,
     * ensuring reliable communication with the keyboard controller.
     */
    do {
        /* Memory barrier before I/O read */
        __asm__ volatile("" ::: "memory");
        temp = inb(0x64);
        /* Memory barrier after I/O read */
        __asm__ volatile("" ::: "memory");

        if (temp & 0x01) {
            __asm__ volatile("" ::: "memory");
            inb(0x60);
            __asm__ volatile("" ::: "memory");
        }
    } while (temp & 0x02);

    /* Memory barrier before sending reboot command */
    __asm__ volatile("" ::: "memory");
    /* Send reboot command */
    outb(0x64, 0xFE);
    /* Memory barrier after reboot command */
    __asm__ volatile("" ::: "memory");

    /* If that didn't work, halt */
    for(;;) __asm__ volatile("hlt");
}

/*=============================================================================
 * COMMAND: date - Display or set system date/time
 *=============================================================================*/
void cmd_date(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    const char* day_names[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    const char* month_names[] = {"", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

    if (argc == 1) {
        /* Display current date/time */
        datetime_t dt;
        if (!time_get_datetime(&dt)) {
            stream_printf(ctx, "date: failed to read system time\n");
            return;
        }

        /* Unix-style output: Dow Mon DD HH:MM:SS YYYY */
        stream_printf(ctx, "%s %s %2d %02d:%02d:%02d %04d\n",
                      day_names[dt.weekday],
                      month_names[dt.month],
                      dt.day,
                      dt.hour, dt.minute, dt.second,
                      dt.year);

        /* Also show uptime */
        uint32_t uptime = time_get_uptime_seconds();
        uint32_t days = uptime / 86400;
        uint32_t hours = (uptime % 86400) / 3600;
        uint32_t minutes = (uptime % 3600) / 60;
        uint32_t seconds = uptime % 60;

        stream_printf(ctx, "Uptime: ");
        if (days > 0) {
            stream_printf(ctx, "%u day%s, ", days, days == 1 ? "" : "s");
        }
        stream_printf(ctx, "%02u:%02u:%02u\n", hours, minutes, seconds);
    }
    else if (strcmp(argv[1], "-u") == 0 || strcmp(argv[1], "--utc") == 0) {
        /* Display Unix timestamp */
        datetime_t dt;
        if (!time_get_datetime(&dt)) {
            stream_printf(ctx, "date: failed to read system time\n");
            return;
        }

        uint32_t timestamp = datetime_to_timestamp(&dt);
        stream_printf(ctx, "%u\n", timestamp);
    }
    else if (strcmp(argv[1], "-R") == 0 || strcmp(argv[1], "--rfc-2822") == 0) {
        /* RFC 2822 format */
        datetime_t dt;
        if (!time_get_datetime(&dt)) {
            stream_printf(ctx, "date: failed to read system time\n");
            return;
        }

        stream_printf(ctx, "%s, %02d %s %04d %02d:%02d:%02d +0000\n",
                      day_names[dt.weekday],
                      dt.day,
                      month_names[dt.month],
                      dt.year,
                      dt.hour, dt.minute, dt.second);
    }
    else if (strcmp(argv[1], "-I") == 0 || strcmp(argv[1], "--iso-8601") == 0) {
        /* ISO 8601 format */
        datetime_t dt;
        if (!time_get_datetime(&dt)) {
            stream_printf(ctx, "date: failed to read system time\n");
            return;
        }

        stream_printf(ctx, "%04d-%02d-%02d\n", dt.year, dt.month, dt.day);
    }
    else if (strcmp(argv[1], "--help") == 0) {
        /* Help message */
        stream_printf(ctx, "Usage: date [OPTION]\n");
        stream_printf(ctx, "Display or set the system date and time.\n\n");
        stream_printf(ctx, "Options:\n");
        stream_printf(ctx, "  -u, --utc        Display Unix timestamp\n");
        stream_printf(ctx, "  -R, --rfc-2822   Display RFC 2822 format\n");
        stream_printf(ctx, "  -I, --iso-8601   Display ISO 8601 date format\n");
        stream_printf(ctx, "  -s TIME          Set time (format: \"YYYY-MM-DD HH:MM:SS\")\n");
        stream_printf(ctx, "  --help           Display this help message\n\n");
        stream_printf(ctx, "Examples:\n");
        stream_printf(ctx, "  date             Show current date and time\n");
        stream_printf(ctx, "  date -u          Show Unix timestamp\n");
        stream_printf(ctx, "  date -s \"2025-01-14 10:30:00\"\n");
    }
    else if (strcmp(argv[1], "-s") == 0 && argc >= 3) {
        /* Set date/time */
        /* Expected format: "YYYY-MM-DD HH:MM:SS" */
        const char* timestr = argv[2];
        datetime_t dt = {0};

        /* Parse YYYY-MM-DD HH:MM:SS */
        int year, month, day, hour, minute, second;
        int parsed = 0;

        /* Simple parser */
        const char* p = timestr;

        /* Parse year */
        year = 0;
        while (*p >= '0' && *p <= '9' && parsed < 4) {
            year = year * 10 + (*p - '0');
            p++;
            parsed++;
        }
        if (*p != '-' || parsed != 4) goto parse_error;
        p++;
        parsed = 0;

        /* Parse month */
        month = 0;
        while (*p >= '0' && *p <= '9' && parsed < 2) {
            month = month * 10 + (*p - '0');
            p++;
            parsed++;
        }
        if (*p != '-' || parsed != 2) goto parse_error;
        p++;
        parsed = 0;

        /* Parse day */
        day = 0;
        while (*p >= '0' && *p <= '9' && parsed < 2) {
            day = day * 10 + (*p - '0');
            p++;
            parsed++;
        }
        if (*p != ' ' || parsed != 2) goto parse_error;
        p++;
        parsed = 0;

        /* Parse hour */
        hour = 0;
        while (*p >= '0' && *p <= '9' && parsed < 2) {
            hour = hour * 10 + (*p - '0');
            p++;
            parsed++;
        }
        if (*p != ':' || parsed != 2) goto parse_error;
        p++;
        parsed = 0;

        /* Parse minute */
        minute = 0;
        while (*p >= '0' && *p <= '9' && parsed < 2) {
            minute = minute * 10 + (*p - '0');
            p++;
            parsed++;
        }
        if (*p != ':' || parsed != 2) goto parse_error;
        p++;
        parsed = 0;

        /* Parse second */
        second = 0;
        while (*p >= '0' && *p <= '9' && parsed < 2) {
            second = second * 10 + (*p - '0');
            p++;
            parsed++;
        }
        if (*p != '\0' || parsed != 2) goto parse_error;

        /* Validate ranges */
        if (year < 2000 || year > 2099 ||
            month < 1 || month > 12 ||
            day < 1 || day > 31 ||
            hour > 23 || minute > 59 || second > 59) {
            stream_printf(ctx, "date: invalid date/time values\n");
            return;
        }

        /* Fill datetime structure */
        dt.year = (uint16_t)year;
        dt.month = (uint8_t)month;
        dt.day = (uint8_t)day;
        dt.hour = (uint8_t)hour;
        dt.minute = (uint8_t)minute;
        dt.second = (uint8_t)second;
        dt.weekday = get_day_of_week(dt.year, dt.month, dt.day);

        /* Set the time */
        if (time_set_datetime(&dt)) {
            stream_printf(ctx, "System time set to: %s %s %2d %02d:%02d:%02d %04d\n",
                          day_names[dt.weekday],
                          month_names[dt.month],
                          dt.day,
                          dt.hour, dt.minute, dt.second,
                          dt.year);
        } else {
            stream_printf(ctx, "date: failed to set system time\n");
        }
        return;

parse_error:
        stream_printf(ctx, "date: invalid time format\n");
        stream_printf(ctx, "Use: date -s \"YYYY-MM-DD HH:MM:SS\"\n");
        stream_printf(ctx, "Example: date -s \"2025-01-14 10:30:00\"\n");
    }
    else {
        stream_printf(ctx, "date: invalid option: '%s'\n", argv[1]);
        stream_printf(ctx, "Try 'date --help' for more information.\n");
    }
}

/*=============================================================================
 * COMMAND: env
 * Display environment variables
 *=============================================================================*/
void cmd_env(int argc, char* argv[]) {
    (void)argc;  /* Unused */
    (void)argv;  /* Unused */

    /* Display only exported variables (like bash 'env') */
    env_list(true);
}

/*=============================================================================
 * COMMAND: set
 * Set or display shell variables
 *=============================================================================*/
void cmd_set(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    if (argc == 1) {
        /* No arguments: display all variables (like bash 'set') */
        env_list(false);
    }
    else if (argc == 2) {
        /* Parse VAR=VALUE format */
        char* eq = strchr(argv[1], '=');
        if (!eq) {
            stream_printf(ctx, "set: invalid format\n");
            stream_printf(ctx, "Usage: set VAR=VALUE\n");
            stream_printf(ctx, "   or: set (to display all variables)\n");
            return;
        }

        /* Split into name and value */
        *eq = '\0';
        char* name = argv[1];
        char* value = eq + 1;

        /* Set the variable */
        if (env_set(name, value) < 0) {
            stream_printf(ctx, "set: failed to set variable '%s'\n", name);
            stream_printf(ctx, "(invalid name or environment table full)\n");
        }
    }
    else {
        stream_printf(ctx, "set: too many arguments\n");
        stream_printf(ctx, "Usage: set VAR=VALUE\n");
    }
}

/*=============================================================================
 * COMMAND: unset
 * Remove environment variable
 *=============================================================================*/
void cmd_unset(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    if (argc < 2) {
        stream_printf(ctx, "unset: missing variable name\n");
        stream_printf(ctx, "Usage: unset VARIABLE\n");
        return;
    }

    for (int i = 1; i < argc; i++) {
        if (env_unset(argv[i]) < 0) {
            stream_printf(ctx, "unset: variable '%s' not found\n", argv[i]);
        }
    }
}

/*=============================================================================
 * COMMAND: export
 * Mark variable for export to child processes
 *=============================================================================*/
void cmd_export(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    if (argc == 1) {
        /* No arguments: display exported variables */
        env_list(true);
        return;
    }

    for (int i = 1; i < argc; i++) {
        char* arg = argv[i];

        /* Check for VAR=VALUE format */
        char* eq = strchr(arg, '=');
        if (eq) {
            /* export VAR=VALUE: set and export in one step */
            *eq = '\0';
            char* name = arg;
            char* value = eq + 1;

            if (env_set(name, value) < 0) {
                stream_printf(ctx, "export: failed to set variable '%s'\n", name);
                continue;
            }

            if (env_export(name) < 0) {
                stream_printf(ctx, "export: failed to export '%s'\n", name);
            }
        } else {
            /* export VAR: just mark existing variable as exported */
            if (env_export(arg) < 0) {
                stream_printf(ctx, "export: variable '%s' not found\n", arg);
            }
        }
    }
}

/*=============================================================================
 * COMMAND: alias
 * Set or display command aliases
 *=============================================================================*/
void cmd_alias(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    if (argc == 1) {
        /* No arguments: display all aliases */
        alias_list();
        return;
    }

    /* Parse alias definition: alias name='command' */
    char* arg = argv[1];
    char* eq = strchr(arg, '=');

    if (!eq) {
        /* Just show one alias: alias name */
        char cmd[ALIAS_MAX_CMD_LEN];
        if (alias_get(arg, cmd, sizeof(cmd))) {
            stream_printf(ctx, "alias %s='%s'\n", arg, cmd);
        } else {
            stream_printf(ctx, "alias: %s: not found\n", arg);
        }
        return;
    }

    /* Set alias: name=value
     * SECURITY FIX: Never modify input argv buffers (input tainting)
     * Copy the name portion to a local buffer instead of using *eq = '\0'
     * to split the string in place. If argv is shared or re-used by history
     * or other components, the original command would be corrupted.
     */
    char name[ALIAS_MAX_NAME_LEN];
    size_t name_len = eq - arg;

    /* Validate name length before copying */
    if (name_len >= ALIAS_MAX_NAME_LEN) {
        stream_printf(ctx, "alias: name too long (max %d chars)\n", ALIAS_MAX_NAME_LEN - 1);
        return;
    }

    /* Safe copy of name portion without modifying argv */
    for (size_t i = 0; i < name_len; i++) {
        name[i] = arg[i];
    }
    name[name_len] = '\0';

    char* value = eq + 1;

    /* Remove quotes if present */
    if (*value == '\'' || *value == '"') {
        value++;
        size_t len = strlen(value);
        if (len > 0 && (value[len-1] == '\'' || value[len-1] == '"')) {
            /* SECURITY: This still modifies argv for the value part.
             * However, this is acceptable because:
             * 1. The value is at the end of the string
             * 2. We're only removing the trailing quote, not splitting
             * 3. Shell typically doesn't re-use command strings after execution
             * For absolute safety, this could also be copied to a local buffer.
             */
            value[len-1] = '\0';
        }
    }

    if (alias_set(name, value) < 0) {
        stream_printf(ctx, "alias: failed to set alias '%s'\n", name);
    }
}

/*=============================================================================
 * COMMAND: unalias
 * Remove command alias
 *=============================================================================*/
void cmd_unalias(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    if (argc < 2) {
        stream_printf(ctx, "unalias: missing alias name\n");
        stream_printf(ctx, "Usage: unalias NAME\n");
        return;
    }

    for (int i = 1; i < argc; i++) {
        if (alias_unset(argv[i]) < 0) {
            stream_printf(ctx, "unalias: %s: not found\n", argv[i]);
        }
    }
}

/*=============================================================================
 * COMMAND: auditlog
 * View security audit logs
 *=============================================================================*/
void cmd_auditlog(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    /* Parse options */
    audit_severity_t min_severity = AUDIT_DEBUG;
    bool show_stats = false;
    bool verify = false;
    int max_results = 50;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--stats") == 0) {
            show_stats = true;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verify") == 0) {
            verify = true;
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            if (!safe_parse_int(argv[++i], &max_results) || max_results <= 0) {
                max_results = 50;
            }
        } else if (strcmp(argv[i], "--warn") == 0) {
            min_severity = AUDIT_WARN;
        } else if (strcmp(argv[i], "--error") == 0) {
            min_severity = AUDIT_ERROR;
        } else if (strcmp(argv[i], "--critical") == 0) {
            min_severity = AUDIT_CRITICAL;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            stream_printf(ctx, "Usage: auditlog [OPTIONS]\n");
            stream_printf(ctx, "\nOptions:\n");
            stream_printf(ctx, "  -s, --stats      Show audit log statistics\n");
            stream_printf(ctx, "  -v, --verify     Verify audit log integrity (HMAC chain)\n");
            stream_printf(ctx, "  -n NUM           Show last NUM events (default: 50)\n");
            stream_printf(ctx, "  --warn           Show only warnings and above\n");
            stream_printf(ctx, "  --error          Show only errors and above\n");
            stream_printf(ctx, "  --critical       Show only critical events\n");
            stream_printf(ctx, "  -h, --help       Show this help\n");
            stream_printf(ctx, "\nExamples:\n");
            stream_printf(ctx, "  auditlog              # Show last 50 audit events\n");
            stream_printf(ctx, "  auditlog -n 100       # Show last 100 events\n");
            stream_printf(ctx, "  auditlog --error      # Show only errors/critical\n");
            stream_printf(ctx, "  auditlog -s           # Show statistics\n");
            stream_printf(ctx, "  auditlog -v           # Verify integrity\n");
            stream_printf(ctx, "\nNote: the audit log is held in RAM and is cleared\n");
            stream_printf(ctx, "on reboot. It is not written to disk.\n");
            return;
        }
    }

    /* Root only, and checked HERE rather than at function entry so that
     * `auditlog --help` still works for anyone: usage text discloses nothing.
     *
     * Everything below this point does. The audit log records who logged in and
     * when, which accounts exist, and which are locked -- and PR #55 exists
     * precisely so an `su` cannot forge a clean root login in it. A log an
     * unprivileged user can READ still leaks the account inventory and the
     * administrator's activity pattern; -v additionally reports whether the
     * HMAC chain is intact, which tells a tamperer whether they were caught. */
    if (!require_root("auditlog")) {
        return;
    }

    /* Show statistics if requested */
    if (show_stats) {
        audit_stats_t stats;
        audit_get_stats(&stats);

        stream_printf(ctx, "\n=== Audit Log Statistics ===\n");
        /* "since boot", not "total". The ring is in RAM and audit_init()
         * memsets it on every boot, so a bare "Total events logged" reads as an
         * all-time figure that this counter structurally cannot report. See
         * doc/AUDIT_LOG_PERSISTENCE.md for why the log is not persisted. */
        stream_printf(ctx, "Events logged (this boot): %u\n", stats.total_events);
        stream_printf(ctx, "Events in buffer:          %u\n", stats.events_in_buffer);
        stream_printf(ctx, "Events dropped:            %u\n", stats.events_dropped);
        stream_printf(ctx, "Tamper detections:         %u\n", stats.tamper_detections);
        stream_printf(ctx, "Oldest sequence:           %u\n", stats.oldest_sequence);
        stream_printf(ctx, "Newest sequence:           %u\n", stats.newest_sequence);
        stream_printf(ctx, "\nLog is VOLATILE: held in RAM, cleared on reboot.\n");
        stream_printf(ctx, "\n");
        return;
    }

    /* Verify integrity if requested */
    if (verify) {
        stream_printf(ctx, "\nVerifying audit log integrity (HMAC chain)...\n");
        if (audit_verify_integrity()) {
            stream_printf(ctx, "[OK] Audit log integrity verified - no tampering detected\n");
        } else {
            stream_printf(ctx, "[FAIL] Audit log tampering detected!\n");
        }
        stream_printf(ctx, "\n");
        return;
    }

    /* Query audit logs with filter */
    audit_filter_t filter = {
        .type = 0,              /* All types */
        .min_severity = min_severity,
        .uid = 0xFFFF,          /* All users */
        .start_time = 0,
        .end_time = 0
    };

    /* ~17.6 KB on the kernel task stack (sizeof audit_event_t is ~176: a
     * 96-byte description plus a 64-byte HMAC). That is a big local of exactly
     * the kind the stack budget warns about. It is left alone deliberately:
     *
     *   - `static` is the usual fix in this tree (exec_buffer,
     *     allocated_frames) and is WRONG here. Printing now goes through
     *     stream_printf, which on a redirected stream reaches ramfs_write and
     *     can block and reschedule inside the print loop below; two shell
     *     sessions running `auditlog` would interleave into one shared array
     *     and print each other's records. A stack buffer is per-task.
     *   - Batching into a small buffer needs a cursor, and audit_query() has
     *     none -- it always returns from the same end of the ring, so a loop
     *     either repeats the first N records forever or silently truncates the
     *     listing. Giving audit_query a cursor is the real fix and is a change
     *     to audit.c, not to this call site.
     *
     * 17.6 KB fits the 128 KB stack with room to spare and this is not on the
     * exec chain. Revisit when `auditlog` moves to ring 3, where it will not be
     * running on this stack at all. */
    audit_event_t results[100];
    int count = audit_query(&filter, results, max_results > 100 ? 100 : max_results);

    if (count == 0) {
        stream_printf(ctx, "No audit events found.\n");
        return;
    }

    /* Display audit events */
    stream_printf(ctx, "\n=== Security Audit Log (showing %d events) ===\n", count);
    stream_printf(ctx, "%-6s %-8s %-24s %-8s %s\n",
                  "SEQ", "SEVERITY", "EVENT", "UID/PID", "DESCRIPTION");
    stream_printf(ctx, "----------------------------------------------------------------------\n");

    for (int i = 0; i < count; i++) {
        audit_event_t* event = &results[i];
        stream_printf(ctx, "%-6u %-8s %-24s %u/%-5u %s\n",
                      event->sequence,
                      audit_severity_str(event->severity),
                      audit_event_type_str(event->type),
                      event->uid,
                      event->pid,
                      event->description);
    }
    stream_printf(ctx, "\n");
}

/*=============================================================================
 * Secure File Deletion Command
 * DISABLED: secure_delete module removed due to crashes
 *=============================================================================*/
#if 0
void cmd_shred(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    /* SECURITY: Only root can securely delete files */
    if (!require_root("shred")) {
        return;
    }

    if (argc < 2) {
        stream_printf(ctx, "Usage: shred [OPTIONS] <file> [file2] ...\n");
        stream_printf(ctx, "\nSecurely delete files using DoD 5220.22-M 3-pass overwrite:\n");
        stream_printf(ctx, "  Pass 1: Random data\n");
        stream_printf(ctx, "  Pass 2: Complement of Pass 1\n");
        stream_printf(ctx, "  Pass 3: Random data\n");
        stream_printf(ctx, "\nOptions:\n");
        stream_printf(ctx, "  -z, --zero       Fast zero-fill (1 pass, less secure)\n");
        stream_printf(ctx, "  -v, --verbose    Show detailed statistics\n");
        stream_printf(ctx, "  -h, --help       Show this help\n");
        stream_printf(ctx, "\nExamples:\n");
        stream_printf(ctx, "  shred secret.txt             # Securely delete with 3-pass overwrite\n");
        stream_printf(ctx, "  shred -v passwords.txt       # With verbose output\n");
        stream_printf(ctx, "  shred -z temp.log            # Fast zero-fill deletion\n");
        stream_printf(ctx, "  shred file1.txt file2.txt    # Delete multiple files\n");
        return;
    }

    /* Parse options */
    bool verbose = false;
    bool use_zero = false;
    int file_start = 1;

    /* Process flags */
    for (int i = 1; i < argc && argv[i][0] == '-'; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
            file_start = i + 1;
        } else if (strcmp(argv[i], "-z") == 0 || strcmp(argv[i], "--zero") == 0) {
            use_zero = true;
            file_start = i + 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            stream_printf(ctx, "Usage: shred [OPTIONS] <file> [file2] ...\n");
            stream_printf(ctx, "\nSecurely delete files using DoD 5220.22-M 3-pass overwrite\n");
            return;
        } else {
            stream_printf(ctx, "shred: unknown option: %s\n", argv[i]);
            stream_printf(ctx, "Try 'shred --help' for more information.\n");
            return;
        }
    }

    /* Check if we have files to shred */
    if (file_start >= argc) {
        stream_printf(ctx, "shred: no files specified\n");
        return;
    }

    /* Setup deletion options */
    secure_delete_opts_t opts = secure_delete_get_default_opts();
    if (use_zero) {
        opts.method = SECURE_DELETE_ZERO;
        opts.verify_overwrite = false;
    }

    /* Process each file */
    int success_count = 0;
    int fail_count = 0;

    for (int i = file_start; i < argc; i++) {
        const char* path = argv[i];
        secure_delete_stats_t stats;

        if (verbose) {
            stream_printf(ctx, "shred: %s: ", path);
        }

        /* Perform secure deletion */
        int ret = secure_delete_file_ex(path, &opts, &stats);

        if (ret == 0) {
            success_count++;
            if (verbose) {
                stream_printf(ctx, "OK (%u bytes, %u passes)\n",
                              stats.total_bytes, stats.passes_completed);
            } else {
                stream_printf(ctx, "shred: %s: removed\n", path);
            }
        } else {
            fail_count++;
            if (ret == -1) {
                stream_printf(ctx, "shred: %s: file not found\n", path);
            } else if (ret == -4) {
                stream_printf(ctx, "shred: %s: verification failed\n", path);
            } else if (ret == -7) {
                stream_printf(ctx, "shred: %s: unlink failed after overwrite\n", path);
            } else {
                stream_printf(ctx, "shred: %s: error %d\n", path, ret);
            }
        }
    }

    /* Summary */
    if (verbose && (success_count + fail_count > 1)) {
        stream_printf(ctx, "\nSummary: %d succeeded, %d failed\n", success_count, fail_count);
    }
}
#endif /* DISABLED: secure_delete module removed */

/*=============================================================================
 * COMMAND: sectest
 * PURPOSE: Run security hardening test suite
 * USAGE: sectest
 *=============================================================================*/
void cmd_sectest(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    /* Root only: the suite exercises kernel internals and reports what it
     * found, so its output doubles as a probe of the running system. */
    if (!require_root("sectest")) {
        return;
    }

    /* Now on the stream, following its output. This line was held on kprintf on
     * purpose while security_tests.c was console-only -- a banner routed to the
     * stream while the results went to the console would have made
     * `sectest > report.txt` produce a file containing the banner and nothing
     * else. The suite (and scheduler_stats()/arp_security_self_test(), its two
     * out-of-file reporters) now writes to the stream too, so the banner
     * follows its output instead of abandoning it. */
    stream_printf(get_current_streams(), "Starting security test suite...\n");
    run_security_tests();
}

/*=============================================================================
 * COMMAND: secstatus - One-screen summary of every security subsystem.
 *
 * TinyOS's differentiator is its security stack, but it was scattered across
 * five separate diagnostic verbs (aslr/pae/wxaudit/auditlog/sectest) with no
 * at-a-glance view. This aggregates the live state of each subsystem so a user
 * (or a reviewer) can see "is this box actually hardened?" in one command.
 * Every value is read from the real subsystem getters — nothing is hardcoded.
 *=============================================================================*/
void cmd_secstatus(int argc, char* argv[]) {
    stream_context_t* ctx = get_current_streams();
    (void)argc;
    (void)argv;

    aslr_stats_t aslr;
    aslr_get_stats(&aslr);

    firewall_stats_t fw;
    firewall_get_stats(&fw);

    ids_stats_t ids;
    ids_get_stats(&ids);

    uint32_t edr_scans = 0, edr_threats = 0, edr_procs = 0, edr_responses = 0;
    edr_daemon_get_stats(&edr_scans, &edr_threats, &edr_procs, &edr_responses);

    uint32_t wx_violations = pae_wx_audit();

    /* SYS_MSEAL (16) is ungated, so its rejection sites are driven by a ring-3
     * caller's own arguments -- they count instead of printing (PR: mseal
     * kprintf sweep). Successes are reported alongside, because a mechanism
     * nobody ever uses successfully looks identical to one that works. */
    uint32_t ms_bounds = 0, ms_size = 0, ms_nospace = 0, ms_failed = 0, ms_sealed = 0;
    syscall_get_mseal_stats(&ms_bounds, &ms_size, &ms_nospace, &ms_failed, &ms_sealed);
    uint32_t ms_pae_args = 0, ms_pae_unmapped = 0, ms_pae_pages = 0;
    pae_get_mseal_stats(&ms_pae_args, &ms_pae_unmapped, &ms_pae_pages);
    /* The ACTUAL gate, from elf.c -- a build-mode question, not a policy flag.
     * This line used to come from secure_boot_is_enforced(), which was hardwired
     * true and so reported "ENFORCED" even in a permissive build. */
    bool elf_enforced = elf_signatures_enforced();

    stream_printf(ctx, "\n");
    stream_printf(ctx, "=== TinyOS Security Status ===\n");
    stream_printf(ctx, "\n");

    stream_printf(ctx, "  Memory protection\n");
    stream_printf(ctx, "    ASLR ................ %s (%u-bit entropy, %u stacks)\n",
                  aslr.enabled ? "ENABLED" : "DISABLED",
                  aslr.entropy_bits, aslr.stacks_randomized);
    stream_printf(ctx, "    W^X enforcement ..... %s (%u current violations)\n",
                  wx_violations == 0 ? "CLEAN" : "VIOLATIONS",
                  wx_violations);

    stream_printf(ctx, "    Memory sealing ...... %u regions / %u pages sealed, %u rejected (%u bounds, %u size, %u nospace, %u failed)\n",
                  ms_sealed, ms_pae_pages, ms_bounds + ms_size + ms_nospace + ms_failed,
                  ms_bounds, ms_size, ms_nospace, ms_failed);
    stream_printf(ctx, "    Seal arg rejects .... %u bad-args, %u unmapped-page\n",
                  ms_pae_args, ms_pae_unmapped);

    /* Dispatcher accept/reject. These replaced kprintf sites that sat ABOVE
     * the EDR hook and echoed the caller's own syscall number, so any ring-3
     * process could write chosen text into the kernel log at syscall rate.
     * `accepted` is the positive control -- the reject counts alone read the
     * same whether the dispatcher works or refuses everything. */
    uint32_t sc_ok = 0, sc_range = 0, sc_unimpl = 0;
    syscall_get_reject_stats(&sc_ok, &sc_range, &sc_unimpl);
    stream_printf(ctx, "    Syscall dispatch .... %u accepted, %u out-of-range, %u unimplemented\n",
                  sc_ok, sc_range, sc_unimpl);

    stream_printf(ctx, "\n  Boot integrity\n");
    stream_printf(ctx, "    ELF signatures ...... %s\n",
                  elf_enforced ? "ENFORCED (fail-closed)" : "PERMISSIVE (warn-and-load)");

    stream_printf(ctx, "\n  Network defense\n");
    stream_printf(ctx, "    Firewall ............ %llu pkts (%llu dropped, %llu rejected)\n",
                  (unsigned long long)fw.packets_total,
                  (unsigned long long)fw.packets_dropped,
                  (unsigned long long)fw.packets_rejected);
    stream_printf(ctx, "    Attacks detected .... %llu SYN-flood, %llu port-scan\n",
                  (unsigned long long)fw.syn_floods_detected,
                  (unsigned long long)fw.port_scans_detected);
    /* The match count belongs next to the signature count: a loaded count on
     * its own was what made AUDIT-8E read as protection for as long as it did. */
    stream_printf(ctx, "    IDS ................. %u signatures, %llu matches, %llu alerts, %llu IPs blocked\n",
                  ids.signatures_loaded,
                  (unsigned long long)ids.signature_matches,
                  (unsigned long long)ids.alerts_generated,
                  (unsigned long long)ids.ips_blocked);

    stream_printf(ctx, "\n  Endpoint detection (EDR)\n");
    stream_printf(ctx, "    Scans / threats ..... %u scans, %u threats, %u responses\n",
                  edr_scans, edr_threats, edr_responses);

    stream_printf(ctx, "\n");
    stream_printf(ctx, "  Details (root): aslr | pae | wxaudit | auditlog | sectest\n");
    stream_printf(ctx, "\n");
}
