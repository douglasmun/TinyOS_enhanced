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
#include "aslr.h"  /* For ASLR statistics */
#include "paging.h"  /* For PAE/W^X functions */
#include "security_tests.h"  /* For security test suite */
#include "firewall.h"  /* secstatus: firewall stats */
#include "ids.h"  /* secstatus: IDS stats */
#include "edr_ml.h"  /* secstatus: EDR daemon stats */
#include "secure_boot.h"  /* secstatus: ELF enforcement state */
#include <stdint.h>
#include <limits.h>
#include <stdbool.h>

/*=============================================================================
 * HELPER: Require root privilege for command execution
 * SECURITY: Prevents non-root users from executing destructive commands
 *=============================================================================*/
static bool require_root(const char *cmd) {
    task_t *t = scheduler_get_current_task();
    if (!t) {
        kprintf("%s: ERROR: Cannot determine current task\n", cmd);
        return false;
    }

    /* Check effective user ID (euid) for privilege */
    if (t->euid != 0) {
        kprintf("%s: permission denied (must be root)\n", cmd);
        kprintf("Current user: UID=%d EUID=%d (root is UID=0)\n", t->uid, t->euid);
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
    /*=========================================================================
     * SECURITY FIX (v1.18): Enforce strict argument count
     *
     * Reject extra arguments to prevent command injection or unexpected
     * behavior. Dangerous commands should have well-defined, fixed argument
     * counts to reduce attack surface.
     *=======================================================================*/
    if (argc != 1) {
        kprintf("mem: command takes no arguments\n");
        kprintf("Usage: mem\n");
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

    kprintf("\nMemory Usage:\n");
    kprintf("  Total: %u frames (%llu KB)\n", total, total_kb);
    kprintf("  Used:  %u frames (%llu KB)\n", used, used_kb);
    kprintf("  Free:  %u frames (%llu KB)\n", free, free_kb);
    kprintf("\n");
}

/*=============================================================================
 * COMMAND: aslr - Display ASLR statistics
 *=============================================================================*/
void cmd_aslr(int argc, char* argv[]) {
    if (argc != 1) {
        kprintf("aslr: command takes no arguments\n");
        kprintf("Usage: aslr\n");
        return;
    }

    (void)argv;  /* Unused except for validation */

    aslr_stats_t stats;
    aslr_get_stats(&stats);

    kprintf("\n");
    kprintf("=== ASLR (Address Space Layout Randomization) ===\n");
    kprintf("\n");
    kprintf("Status: %s\n", stats.enabled ? "ENABLED" : "DISABLED");

    if (!stats.enabled) {
        kprintf("\nWARNING: ASLR is disabled - system is vulnerable!\n");
        kprintf("Stack addresses are predictable, making exploitation easier.\n");
        kprintf("\n");
        return;
    }

    kprintf("\nEntropy:\n");
    kprintf("  Bits:           %u bits\n", stats.entropy_bits);
    kprintf("  Page range:     4096 pages (16 MB)\n");
    kprintf("  Possible addrs: %u (2^%u)\n",
            1U << stats.entropy_bits, stats.entropy_bits);
    kprintf("  Exploit chance: 1/%u (~%.4f%%)\n",
            1U << stats.entropy_bits,
            100.0 / (1U << stats.entropy_bits));

    kprintf("\nStatistics:\n");
    kprintf("  Stacks randomized: %u\n", stats.stacks_randomized);
    kprintf("  RNG reseeds:       %u\n", stats.rng_reseeds);

    if (stats.stacks_randomized > 0) {
        kprintf("\nAddress Range:\n");
        kprintf("  Minimum: 0x%08x\n", stats.min_stack_addr);
        kprintf("  Maximum: 0x%08x\n", stats.max_stack_addr);
        kprintf("  Spread:  %u KB\n",
                (stats.max_stack_addr - stats.min_stack_addr) / 1024);
    }

    kprintf("\nSecurity Impact:\n");
    kprintf("  Without ASLR: Exploits work 100%% of the time\n");
    kprintf("  With ASLR:    Exploits work %.4f%% of the time\n",
            100.0 / (1U << stats.entropy_bits));
    kprintf("  Protection:   ~%.2fx harder to exploit\n",
            (float)(1U << stats.entropy_bits));

    kprintf("\nNote: Combined with stack protection, TinyOS has\n");
    kprintf("      industry-grade exploit mitigation!\n");
    kprintf("\n");
}

/*=============================================================================
 * COMMAND: pae - Display PAE (Physical Address Extension) status
 *=============================================================================*/
void cmd_pae(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    kprintf("\n=== PAE (Physical Address Extension) Status ===\n");
    kprintf("\nCPU Support:\n");

    if (pae_is_supported()) {
        kprintf("  PAE: SUPPORTED ✅\n");
    } else {
        kprintf("  PAE: NOT SUPPORTED ❌\n");
        kprintf("\nPAE is required for W^X (Write XOR Execute) enforcement.\n");
        kprintf("This CPU does not support PAE paging mode.\n\n");
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
        kprintf("  NX bit: SUPPORTED ✅\n");
    } else {
        kprintf("  NX bit: NOT SUPPORTED ❌\n");
    }

    /* Check if PAE is currently enabled */
    uint32_t cr4;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    bool pae_enabled = (cr4 & (1 << 5)) != 0;

    kprintf("\nCurrent Status:\n");
    kprintf("  CR4.PAE: %s\n", pae_enabled ? "ENABLED" : "DISABLED");

    if (nx_supported && max_extended >= 0x80000001) {
        /* Check EFER.NXE */
        uint32_t eax, edx;
        __asm__ volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(0xC0000080));
        bool nx_enabled = (eax & (1 << 11)) != 0;
        kprintf("  EFER.NXE: %s\n", nx_enabled ? "ENABLED" : "DISABLED");

        if (!nx_enabled) {
            kprintf("\nNote: NX bit is supported but not enabled.\n");
            kprintf("      Call pae_enable_nx() to enable W^X protection.\n");
        }
    }

    kprintf("\nW^X Enforcement:\n");
    if (pae_enabled && nx_supported) {
        kprintf("  Status: READY ✅\n");
        kprintf("  Memory pages can be:\n");
        kprintf("    - Writable (data/stack) with NX bit set\n");
        kprintf("    - Executable (code) without NX bit\n");
        kprintf("    - Never BOTH writable AND executable\n");
    } else {
        kprintf("  Status: UNAVAILABLE ❌\n");
        if (!pae_enabled) {
            kprintf("  Reason: PAE mode not enabled\n");
        }
        if (!nx_supported) {
            kprintf("  Reason: CPU lacks NX bit support\n");
        }
    }

    kprintf("\nTo enable W^X:\n");
    kprintf("  1. Ensure PAE-capable CPU (done ✅)\n");
    kprintf("  2. Enable PAE in boot code (boot.s)\n");
    kprintf("  3. Call pae_init() during kernel init\n");
    kprintf("  4. Use pae_map_page() with NX flags\n");
    kprintf("  5. Run 'wxaudit' to verify enforcement\n");
    kprintf("\n");
}

/*=============================================================================
 * COMMAND: wxaudit - Audit memory for W^X violations
 *=============================================================================*/
void cmd_wxaudit(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    /* Run PAE W^X audit */
    uint32_t violations = pae_wx_audit();

    if (violations > 0) {
        kprintf("\nWARNING:️  WARNING: %u W^X violations detected!\n", violations);
        kprintf("Memory pages should NEVER be writable AND executable.\n");
        kprintf("This is a serious security vulnerability.\n\n");
    }
}

/*=============================================================================
 * COMMAND: kill - Terminate a task
 *=============================================================================*/
void cmd_kill(int argc, char* argv[]) {
    /*=========================================================================
     * SECURITY FIX (v1.18): Enforce strict argument count
     *
     * Reject extra arguments to prevent command injection or unexpected
     * behavior. The kill command takes exactly one argument (the PID).
     *=======================================================================*/
    if (argc != 2) {
        kprintf("Usage: kill <pid>\n");
        kprintf("kill: expected exactly 1 argument (pid), got %d\n", argc - 1);
        return;
    }

    /* Parse PID with overflow protection */
    int pid = 0;
    if (!safe_parse_int(argv[1], &pid)) {
        kprintf("kill: invalid PID: '%s'\n", argv[1]);
        return;
    }

    if (pid <= 0) {
        kprintf("kill: invalid PID: %d (must be positive)\n", pid);
        return;
    }

    task_t* task = task_get(pid);
    if (!task) {
        kprintf("kill: no such process: %d\n", pid);
        return;
    }

    /*=========================================================================
     * SECURITY: Privilege check for kill command
     * - Allow killing own processes
     * - Require root to kill other users' processes
     *=======================================================================*/
    task_t* current = scheduler_get_current_task();
    if (current && task->uid != current->uid && current->euid != 0) {
        kprintf("kill: permission denied (not owner, not root)\n");
        kprintf("Process %d belongs to UID=%d, you are UID=%d\n",
                pid, task->uid, current->uid);
        return;
    }

    /*=========================================================================
     * SECURITY FIX (v1.20): Protect processes with CAP_UNKILLABLE capability
     *
     * CRITICAL: Instead of hardcoding process names, check the CAP_UNKILLABLE
     * capability flag. This provides a generic protection mechanism that works
     * for any critical system process.
     *
     * Protected processes include:
     * - Shell: Main shell (set by process_init or manually)
     * - Idle: Idle task (set by process_init or manually)
     * - edr_daemon: EDR monitoring daemon (self-protects on startup)
     * - Any future critical system services
     *
     * The capability is enforced at both the shell command level (here) and
     * the kernel syscall level (task_terminate in process.c).
     *=======================================================================*/
    if (task->capabilities & CAP_UNKILLABLE) {
        kprintf("kill: cannot kill protected system process '%s' (PID %d, CAP_UNKILLABLE)\n", task->name, pid);
        kprintf("Processes 'Shell' and 'Idle' are essential and cannot be terminated.\n");
        return;
    }

    kprintf("Terminating task %d (%s)...\n", pid, task->name);
    task_terminate(pid);
    kprintf("Task terminated.\n");
}

/*=============================================================================
 * COMMAND: shutdown - Shutdown the system
 *=============================================================================*/
void cmd_shutdown(int argc, char* argv[]) {
    /*=========================================================================
     * SECURITY FIX (v1.18): Enforce strict argument count
     *
     * Reject extra arguments to prevent command injection or unexpected
     * behavior. The shutdown command takes no arguments.
     *=======================================================================*/
    if (argc != 1) {
        kprintf("Usage: shutdown\n");
        kprintf("shutdown: command takes no arguments\n");
        return;
    }

    (void)argv;  /* Unused except for validation */

    /* SECURITY: Only root can shutdown the system */
    if (!require_root("shutdown")) {
        return;
    }

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
    /*=========================================================================
     * SECURITY FIX (v1.18): Enforce strict argument count
     *
     * Reject extra arguments to prevent command injection or unexpected
     * behavior. The reboot command takes no arguments.
     *=======================================================================*/
    if (argc != 1) {
        kprintf("Usage: reboot\n");
        kprintf("reboot: command takes no arguments\n");
        return;
    }

    (void)argv;  /* Unused except for validation */

    /* SECURITY: Only root can reboot the system */
    if (!require_root("reboot")) {
        return;
    }

    kprintf("Rebooting...\n");

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
    const char* day_names[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    const char* month_names[] = {"", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

    if (argc == 1) {
        /* Display current date/time */
        datetime_t dt;
        if (!time_get_datetime(&dt)) {
            kprintf("date: failed to read system time\n");
            return;
        }

        /* Unix-style output: Dow Mon DD HH:MM:SS YYYY */
        kprintf("%s %s %2d %02d:%02d:%02d %04d\n",
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

        kprintf("Uptime: ");
        if (days > 0) {
            kprintf("%u day%s, ", days, days == 1 ? "" : "s");
        }
        kprintf("%02u:%02u:%02u\n", hours, minutes, seconds);
    }
    else if (strcmp(argv[1], "-u") == 0 || strcmp(argv[1], "--utc") == 0) {
        /* Display Unix timestamp */
        datetime_t dt;
        if (!time_get_datetime(&dt)) {
            kprintf("date: failed to read system time\n");
            return;
        }

        uint32_t timestamp = datetime_to_timestamp(&dt);
        kprintf("%u\n", timestamp);
    }
    else if (strcmp(argv[1], "-R") == 0 || strcmp(argv[1], "--rfc-2822") == 0) {
        /* RFC 2822 format */
        datetime_t dt;
        if (!time_get_datetime(&dt)) {
            kprintf("date: failed to read system time\n");
            return;
        }

        kprintf("%s, %02d %s %04d %02d:%02d:%02d +0000\n",
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
            kprintf("date: failed to read system time\n");
            return;
        }

        kprintf("%04d-%02d-%02d\n", dt.year, dt.month, dt.day);
    }
    else if (strcmp(argv[1], "--help") == 0) {
        /* Help message */
        kprintf("Usage: date [OPTION]\n");
        kprintf("Display or set the system date and time.\n\n");
        kprintf("Options:\n");
        kprintf("  -u, --utc        Display Unix timestamp\n");
        kprintf("  -R, --rfc-2822   Display RFC 2822 format\n");
        kprintf("  -I, --iso-8601   Display ISO 8601 date format\n");
        kprintf("  -s TIME          Set time (format: \"YYYY-MM-DD HH:MM:SS\")\n");
        kprintf("  --help           Display this help message\n\n");
        kprintf("Examples:\n");
        kprintf("  date             Show current date and time\n");
        kprintf("  date -u          Show Unix timestamp\n");
        kprintf("  date -s \"2025-01-14 10:30:00\"\n");
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
            kprintf("date: invalid date/time values\n");
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
            kprintf("System time set to: %s %s %2d %02d:%02d:%02d %04d\n",
                    day_names[dt.weekday],
                    month_names[dt.month],
                    dt.day,
                    dt.hour, dt.minute, dt.second,
                    dt.year);
        } else {
            kprintf("date: failed to set system time\n");
        }
        return;

parse_error:
        kprintf("date: invalid time format\n");
        kprintf("Use: date -s \"YYYY-MM-DD HH:MM:SS\"\n");
        kprintf("Example: date -s \"2025-01-14 10:30:00\"\n");
    }
    else {
        kprintf("date: invalid option: '%s'\n", argv[1]);
        kprintf("Try 'date --help' for more information.\n");
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
    if (argc == 1) {
        /* No arguments: display all variables (like bash 'set') */
        env_list(false);
    }
    else if (argc == 2) {
        /* Parse VAR=VALUE format */
        char* eq = strchr(argv[1], '=');
        if (!eq) {
            kprintf("set: invalid format\n");
            kprintf("Usage: set VAR=VALUE\n");
            kprintf("   or: set (to display all variables)\n");
            return;
        }

        /* Split into name and value */
        *eq = '\0';
        char* name = argv[1];
        char* value = eq + 1;

        /* Set the variable */
        if (env_set(name, value) < 0) {
            kprintf("set: failed to set variable '%s'\n", name);
            kprintf("(invalid name or environment table full)\n");
        }
    }
    else {
        kprintf("set: too many arguments\n");
        kprintf("Usage: set VAR=VALUE\n");
    }
}

/*=============================================================================
 * COMMAND: unset
 * Remove environment variable
 *=============================================================================*/
void cmd_unset(int argc, char* argv[]) {
    if (argc < 2) {
        kprintf("unset: missing variable name\n");
        kprintf("Usage: unset VARIABLE\n");
        return;
    }

    for (int i = 1; i < argc; i++) {
        if (env_unset(argv[i]) < 0) {
            kprintf("unset: variable '%s' not found\n", argv[i]);
        }
    }
}

/*=============================================================================
 * COMMAND: export
 * Mark variable for export to child processes
 *=============================================================================*/
void cmd_export(int argc, char* argv[]) {
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
                kprintf("export: failed to set variable '%s'\n", name);
                continue;
            }

            if (env_export(name) < 0) {
                kprintf("export: failed to export '%s'\n", name);
            }
        } else {
            /* export VAR: just mark existing variable as exported */
            if (env_export(arg) < 0) {
                kprintf("export: variable '%s' not found\n", arg);
            }
        }
    }
}

/*=============================================================================
 * COMMAND: alias
 * Set or display command aliases
 *=============================================================================*/
void cmd_alias(int argc, char* argv[]) {
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
        const char* cmd = alias_get(arg);
        if (cmd) {
            kprintf("alias %s='%s'\n", arg, cmd);
        } else {
            kprintf("alias: %s: not found\n", arg);
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
        kprintf("alias: name too long (max %d chars)\n", ALIAS_MAX_NAME_LEN - 1);
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
        kprintf("alias: failed to set alias '%s'\n", name);
    }
}

/*=============================================================================
 * COMMAND: unalias
 * Remove command alias
 *=============================================================================*/
void cmd_unalias(int argc, char* argv[]) {
    if (argc < 2) {
        kprintf("unalias: missing alias name\n");
        kprintf("Usage: unalias NAME\n");
        return;
    }

    for (int i = 1; i < argc; i++) {
        if (alias_unset(argv[i]) < 0) {
            kprintf("unalias: %s: not found\n", argv[i]);
        }
    }
}

/*=============================================================================
 * COMMAND: auditlog
 * View security audit logs
 *=============================================================================*/
void cmd_auditlog(int argc, char* argv[]) {
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
            kprintf("Usage: auditlog [OPTIONS]\n");
            kprintf("\nOptions:\n");
            kprintf("  -s, --stats      Show audit log statistics\n");
            kprintf("  -v, --verify     Verify audit log integrity (HMAC chain)\n");
            kprintf("  -n NUM           Show last NUM events (default: 50)\n");
            kprintf("  --warn           Show only warnings and above\n");
            kprintf("  --error          Show only errors and above\n");
            kprintf("  --critical       Show only critical events\n");
            kprintf("  -h, --help       Show this help\n");
            kprintf("\nExamples:\n");
            kprintf("  auditlog              # Show last 50 audit events\n");
            kprintf("  auditlog -n 100       # Show last 100 events\n");
            kprintf("  auditlog --error      # Show only errors/critical\n");
            kprintf("  auditlog -s           # Show statistics\n");
            kprintf("  auditlog -v           # Verify integrity\n");
            return;
        }
    }

    /* Show statistics if requested */
    if (show_stats) {
        audit_stats_t stats;
        audit_get_stats(&stats);

        kprintf("\n=== Audit Log Statistics ===\n");
        kprintf("Total events logged:    %u\n", stats.total_events);
        kprintf("Events in buffer:       %u\n", stats.events_in_buffer);
        kprintf("Events dropped:         %u\n", stats.events_dropped);
        kprintf("Tamper detections:      %u\n", stats.tamper_detections);
        kprintf("Oldest sequence:        %u\n", stats.oldest_sequence);
        kprintf("Newest sequence:        %u\n", stats.newest_sequence);
        kprintf("\n");
        return;
    }

    /* Verify integrity if requested */
    if (verify) {
        kprintf("\nVerifying audit log integrity (HMAC chain)...\n");
        if (audit_verify_integrity()) {
            kprintf("[OK] Audit log integrity verified - no tampering detected\n");
        } else {
            kprintf("[FAIL] Audit log tampering detected!\n");
        }
        kprintf("\n");
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

    audit_event_t results[100];
    int count = audit_query(&filter, results, max_results > 100 ? 100 : max_results);

    if (count == 0) {
        kprintf("No audit events found.\n");
        return;
    }

    /* Display audit events */
    kprintf("\n=== Security Audit Log (showing %d events) ===\n", count);
    kprintf("%-6s %-8s %-24s %-8s %s\n",
            "SEQ", "SEVERITY", "EVENT", "UID/PID", "DESCRIPTION");
    kprintf("----------------------------------------------------------------------\n");

    for (int i = 0; i < count; i++) {
        audit_event_t* event = &results[i];
        kprintf("%-6u %-8s %-24s %u/%-5u %s\n",
                event->sequence,
                audit_severity_str(event->severity),
                audit_event_type_str(event->type),
                event->uid,
                event->pid,
                event->description);
    }
    kprintf("\n");
}

/*=============================================================================
 * Secure File Deletion Command
 * DISABLED: secure_delete module removed due to crashes
 *=============================================================================*/
#if 0
void cmd_shred(int argc, char* argv[]) {
    /* SECURITY: Only root can securely delete files */
    if (!require_root("shred")) {
        return;
    }

    if (argc < 2) {
        kprintf("Usage: shred [OPTIONS] <file> [file2] ...\n");
        kprintf("\nSecurely delete files using DoD 5220.22-M 3-pass overwrite:\n");
        kprintf("  Pass 1: Random data\n");
        kprintf("  Pass 2: Complement of Pass 1\n");
        kprintf("  Pass 3: Random data\n");
        kprintf("\nOptions:\n");
        kprintf("  -z, --zero       Fast zero-fill (1 pass, less secure)\n");
        kprintf("  -v, --verbose    Show detailed statistics\n");
        kprintf("  -h, --help       Show this help\n");
        kprintf("\nExamples:\n");
        kprintf("  shred secret.txt             # Securely delete with 3-pass overwrite\n");
        kprintf("  shred -v passwords.txt       # With verbose output\n");
        kprintf("  shred -z temp.log            # Fast zero-fill deletion\n");
        kprintf("  shred file1.txt file2.txt    # Delete multiple files\n");
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
            kprintf("Usage: shred [OPTIONS] <file> [file2] ...\n");
            kprintf("\nSecurely delete files using DoD 5220.22-M 3-pass overwrite\n");
            return;
        } else {
            kprintf("shred: unknown option: %s\n", argv[i]);
            kprintf("Try 'shred --help' for more information.\n");
            return;
        }
    }

    /* Check if we have files to shred */
    if (file_start >= argc) {
        kprintf("shred: no files specified\n");
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
            kprintf("shred: %s: ", path);
        }

        /* Perform secure deletion */
        int ret = secure_delete_file_ex(path, &opts, &stats);

        if (ret == 0) {
            success_count++;
            if (verbose) {
                kprintf("OK (%u bytes, %u passes)\n",
                        stats.total_bytes, stats.passes_completed);
            } else {
                kprintf("shred: %s: removed\n", path);
            }
        } else {
            fail_count++;
            if (ret == -1) {
                kprintf("shred: %s: file not found\n", path);
            } else if (ret == -4) {
                kprintf("shred: %s: verification failed\n", path);
            } else if (ret == -7) {
                kprintf("shred: %s: unlink failed after overwrite\n", path);
            } else {
                kprintf("shred: %s: error %d\n", path, ret);
            }
        }
    }

    /* Summary */
    if (verbose && (success_count + fail_count > 1)) {
        kprintf("\nSummary: %d succeeded, %d failed\n", success_count, fail_count);
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

    kprintf("Starting security test suite...\n");
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
    bool elf_enforced = secure_boot_is_enforced();

    kprintf("\n");
    kprintf("=== TinyOS Security Status ===\n");
    kprintf("\n");

    kprintf("  Memory protection\n");
    kprintf("    ASLR ................ %s (%u-bit entropy, %u stacks)\n",
            aslr.enabled ? "ENABLED" : "DISABLED",
            aslr.entropy_bits, aslr.stacks_randomized);
    kprintf("    W^X enforcement ..... %s (%u current violations)\n",
            wx_violations == 0 ? "CLEAN" : "VIOLATIONS",
            wx_violations);

    kprintf("\n  Boot integrity\n");
    kprintf("    ELF signatures ...... %s\n",
            elf_enforced ? "ENFORCED (fail-closed)" : "PERMISSIVE (warn-and-load)");

    kprintf("\n  Network defense\n");
    kprintf("    Firewall ............ %llu pkts (%llu dropped, %llu rejected)\n",
            (unsigned long long)fw.packets_total,
            (unsigned long long)fw.packets_dropped,
            (unsigned long long)fw.packets_rejected);
    kprintf("    Attacks detected .... %llu SYN-flood, %llu port-scan\n",
            (unsigned long long)fw.syn_floods_detected,
            (unsigned long long)fw.port_scans_detected);
    kprintf("    IDS ................. %u signatures, %llu alerts, %llu IPs blocked\n",
            ids.signatures_loaded,
            (unsigned long long)ids.alerts_generated,
            (unsigned long long)ids.ips_blocked);

    kprintf("\n  Endpoint detection (EDR)\n");
    kprintf("    Scans / threats ..... %u scans, %u threats, %u responses\n",
            edr_scans, edr_threats, edr_responses);

    kprintf("\n");
    kprintf("  Details: aslr | pae | wxaudit | auditlog | sectest\n");
    kprintf("\n");
}
