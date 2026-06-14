/*=============================================================================
 * shell_monitor.c - Shell System Monitoring Implementation
 *=============================================================================*/
#include "shell_monitor.h"
#include "scheduler.h"
#include "process.h"
#include "pmm.h"
#include "kernel.h"
#include "kprintf.h"
#include "keyboard.h"
#include "util.h"
#include "critical.h"
#include "stdio.h"
#include "vfs.h"  /* For CAP_UNKILLABLE */
#include <stddef.h>
#include <stdint.h>

/*=============================================================================
 * HELPER: Get task state string
 *=============================================================================*/
static const char* get_state_string(task_state_t state) {
    switch (state) {
        case TASK_STATE_READY:      return "READY";
        case TASK_STATE_RUNNING:    return "RUN";
        case TASK_STATE_BLOCKED:    return "BLOCK";
        case TASK_STATE_SLEEPING:   return "SLEEP";
        case TASK_STATE_ZOMBIE:     return "ZOMBI";
        case TASK_STATE_TERMINATED: return "TERM";
        default:                    return "UNK";
    }
}

/*=============================================================================
 * HELPER: Quicksort partition for task sorting by total_ticks (descending)
 *=============================================================================*/
static int partition_tasks(task_t** tasks, int low, int high) {
    // Use last element as pivot, validate it first
    if (!tasks[high] || tasks[high]->pid == 0) {
        return low;
    }

    uint32_t pivot_ticks = tasks[high]->total_ticks;
    int i = low - 1;

    for (int j = low; j < high; j++) {
        // Validate task before comparing (descending order)
        if (tasks[j] && tasks[j]->pid != 0 &&
            tasks[j]->total_ticks > pivot_ticks) {
            i++;
            task_t* temp = tasks[i];
            tasks[i] = tasks[j];
            tasks[j] = temp;
        }
    }

    task_t* temp = tasks[i + 1];
    tasks[i + 1] = tasks[high];
    tasks[high] = temp;
    return i + 1;
}

/*=============================================================================
 * HELPER: Quicksort tasks by total_ticks (descending order)
 *=============================================================================*/
static void quicksort_tasks(task_t** tasks, int low, int high) {
    if (low < high) {
        int pi = partition_tasks(tasks, low, high);
        quicksort_tasks(tasks, low, pi - 1);
        quicksort_tasks(tasks, pi + 1, high);
    }
}

/*=============================================================================
 * COMMAND: ps - Extended process listing
 *=============================================================================*/
void cmd_ps_extended(int argc, char** argv) {
    stream_context_t* ctx = get_current_streams();
    bool show_all = false;
    bool long_format = false;

    // Parse options
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0) {
            show_all = true;
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--long") == 0) {
            long_format = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            stream_printf(ctx, "Usage: ps [-a] [-l]\n");
            stream_printf(ctx, "  -a, --all   Show all processes including terminated\n");
            stream_printf(ctx, "  -l, --long  Long format with detailed information\n");
            return;
        }
    }

    // Get task list from scheduler with critical section protection
    task_t** tasks;
    int count;

    CRITICAL_SECTION_ENTER();
    count = scheduler_get_all_tasks(&tasks);
    CRITICAL_SECTION_EXIT();

    if (count == 0) {
        stream_printf(ctx, "No processes found\n");
        return;
    }

    // Print header
    if (long_format) {
        stream_printf(ctx, "PID  STATE  PRI  TYPE    TICKS   SLICE  PROTECTED  NAME\n");
        stream_printf(ctx, "---  -----  ---  ------  ------  -----  ---------  ----\n");
    } else {
        stream_printf(ctx, "PID  STATE  PROTECTED  NAME\n");
        stream_printf(ctx, "---  -----  ---------  ----\n");
    }

    // Print each task (validate before accessing)
    for (int i = 0; i < count; i++) {
        task_t* task = tasks[i];

        // Validate task pointer and ensure it's not a freed slot (pid != 0)
        if (!task || task->pid == 0) continue;

        // Skip terminated unless -a
        if (!show_all && task->state == TASK_STATE_TERMINATED) {
            continue;
        }

        if (long_format) {
            const char* type = task->is_kernel_task ? "KERNEL" : "USER";
            const char* protected = (task->capabilities & CAP_UNKILLABLE) ? "[PROTECT]" : "";
            stream_printf(ctx, "%-3d  %-5s  %-3d  %-6s  %-6u  %-5u  %-9s  %s\n",
                    task->pid,
                    get_state_string(task->state),
                    task->priority,
                    type,
                    task->total_ticks,
                    task->time_slice,
                    protected,
                    task->name);
        } else {
            const char* protected = (task->capabilities & CAP_UNKILLABLE) ? "[PROTECT]" : "";
            stream_printf(ctx, "%-3d  %-5s  %-9s  %s\n",
                    task->pid,
                    get_state_string(task->state),
                    protected,
                    task->name);
        }
    }

    stream_printf(ctx, "\nTotal: %d process(es)\n", count);
}

/*=============================================================================
 * COMMAND: top - Real-time system monitor
 *=============================================================================*/
void cmd_top(int argc, char** argv) {
    (void)argc;
    (void)argv;

    kprintf("TinyOS System Monitor (press 'q' to quit)\n");
    kprintf("==========================================\n\n");

    bool running = true;
    uint32_t last_update = get_timer_ticks();
    const uint32_t update_interval = 50; // Update every 0.5 seconds (50 ticks at 100Hz)

    while (running) {
        // Check for quit key
        if (keyboard_has_data()) {
            char c = keyboard_getchar_nonblock();
            if (c == 'q' || c == 'Q') {
                kprintf("\nExiting top...\n");
                break;
            }
        }

        // Only update display at specified interval
        uint32_t current_ticks = get_timer_ticks();
        if (current_ticks - last_update < update_interval) {
            scheduler_yield();
            continue;
        }
        last_update = current_ticks;

        // Clear previous display (simple approach - just add some newlines)
        kprintf("\n--- System Status (tick %u) ---\n", current_ticks);

        /*=====================================================================
         * ROBUSTNESS (v1.14): 64-bit Math for Memory Stats to Prevent Overflow
         *
         * ISSUE: With PAE enabled, x86-32 can address up to 64GB of RAM.
         * At 80% utilization of 64GB:
         *   used_kb = 53,687,091 KB
         *   used_kb * 100 = 5,368,709,100 → OVERFLOW (exceeds uint32_t max)
         *
         * DEFENSE: Use 64-bit arithmetic for percentage calculation to support
         * large memory configurations without integer overflow.
         *===================================================================*/
        // Memory information
        uint32_t total_frames = pmm_total_frames();
        uint32_t free_frames = pmm_free_frames();
        uint32_t used_frames = total_frames - free_frames;

        /* Use 64-bit for KB calculations to prevent overflow on large memory */
        uint64_t total_kb = (uint64_t)total_frames * 4;
        uint64_t used_kb = (uint64_t)used_frames * 4;
        uint64_t free_kb = (uint64_t)free_frames * 4;

        /* Safe percentage calculation with 64-bit intermediate result */
        uint32_t usage_percent = 0;
        if (total_kb > 0) {
            usage_percent = (uint32_t)((used_kb * 100) / total_kb);
        }

        kprintf("Memory: %llu KB total, %llu KB used (%u%%), %llu KB free\n",
                total_kb,
                used_kb,
                usage_percent,
                free_kb);

        // Process information
        task_t** tasks;
        int task_count;

        // CRITICAL SECTION: Get task list snapshot
        CRITICAL_SECTION_ENTER();
        task_count = scheduler_get_all_tasks(&tasks);
        CRITICAL_SECTION_EXIT();

        int running_count = 0;
        int ready_count = 0;
        int blocked_count = 0;
        int sleeping_count = 0;
        int zombie_count = 0;

        for (int i = 0; i < task_count; i++) {
            // Validate task pointer and ensure it's not a freed slot
            if (!tasks[i] || tasks[i]->pid == 0) continue;

            switch (tasks[i]->state) {
                case TASK_STATE_RUNNING:    running_count++; break;
                case TASK_STATE_READY:      ready_count++; break;
                case TASK_STATE_BLOCKED:    blocked_count++; break;
                case TASK_STATE_SLEEPING:   sleeping_count++; break;
                case TASK_STATE_ZOMBIE:     zombie_count++; break;
                case TASK_STATE_TERMINATED: break;
            }
        }

        kprintf("Tasks: %d total (%d run, %d ready, %d block, %d sleep, %d zombie)\n\n",
                task_count, running_count, ready_count, blocked_count, sleeping_count, zombie_count);

        // Top processes by CPU time
        kprintf("PID  STATE  %%CPU  TICKS   NAME\n");
        kprintf("---  -----  ----  ------  ----\n");

        /*
         * Calculate total ticks for CPU percentage.
         * NOTE: This sums task ticks which approximates relative CPU usage.
         * LIMITATION: New tasks with total_ticks=0 are handled correctly.
         * For more accurate CPU usage, a production system should measure
         * delta ticks over the update interval against system uptime.
         */
        uint32_t total_ticks = 0;
        for (int i = 0; i < task_count; i++) {
            // Validate task pointer and ensure it's not a freed slot
            if (tasks[i] && tasks[i]->pid != 0 && tasks[i]->state != TASK_STATE_TERMINATED) {
                total_ticks += tasks[i]->total_ticks;
            }
        }

        /* Prevent division by zero for new systems or all-idle states */
        if (total_ticks == 0) {
            total_ticks = 1;  /* Ensure we don't divide by zero */
        }

        // Sort by CPU time (quicksort - O(n log n) average time complexity)
        if (task_count > 1) {
            quicksort_tasks(tasks, 0, task_count - 1);
        }

        // Display top processes (up to 10)
        int display_count = task_count < 10 ? task_count : 10;
        for (int i = 0; i < display_count; i++) {
            task_t* task = tasks[i];

            // Validate task pointer and ensure it's not a freed slot
            if (!task || task->pid == 0) continue;
            if (task->state == TASK_STATE_TERMINATED) continue;

            uint32_t cpu_percent = 0;
            if (total_ticks > 0) {
                cpu_percent = (task->total_ticks * 100) / total_ticks;
            }

            kprintf("%-3d  %-5s  %3u%%  %-6u  %s\n",
                    task->pid,
                    get_state_string(task->state),
                    cpu_percent,
                    task->total_ticks,
                    task->name);
        }

        kprintf("\n[Press 'q' to quit]\n");

        // Yield to other tasks
        scheduler_yield();
    }
}
