/*=============================================================================
 * shell_history.c - Shell History & Help Implementation
 *=============================================================================*/
#include "shell_history.h"
#include "kprintf.h"
#include "util.h"
#include "critical.h"
#include <stddef.h>

/*=============================================================================
 * HISTORY DATA STRUCTURES
 *=============================================================================*/
static char history_buffer[HISTORY_SIZE][HISTORY_LINE_SIZE];
static int history_count = 0;
static int history_index = 0;

/*=============================================================================
 * FUNCTION: history_init
 *=============================================================================*/
void history_init(void) {
    history_count = 0;
    history_index = 0;
    for (int i = 0; i < HISTORY_SIZE; i++) {
        history_buffer[i][0] = '\0';
    }
}

/*=============================================================================
 * FUNCTION: history_add
 *=============================================================================*/
void history_add(const char* command) {
    if (!command || command[0] == '\0') {
        return;
    }

    // CRITICAL SECTION: Protect history buffer access
    CRITICAL_SECTION_ENTER();

    // Don't add if it's the same as the last command
    if (history_count > 0) {
        int last = (history_index - 1 + HISTORY_SIZE) % HISTORY_SIZE;
        if (strcmp(history_buffer[last], command) == 0) {
            CRITICAL_SECTION_EXIT();
            return;
        }
    }

    // Copy command to history buffer
    size_t len = strlen(command);
    if (len >= HISTORY_LINE_SIZE) {
        len = HISTORY_LINE_SIZE - 1;
    }

    memcpy(history_buffer[history_index], command, len);
    history_buffer[history_index][len] = '\0';

    history_index = (history_index + 1) % HISTORY_SIZE;
    if (history_count < HISTORY_SIZE) {
        history_count++;
    }

    CRITICAL_SECTION_EXIT();
}

/*=============================================================================
 * FUNCTION: history_get
 * NOTE: Returns pointer to internal buffer - caller must not hold pointer
 *       across context switches or use it after calling history_add()
 *=============================================================================*/
const char* history_get(int index) {
    // CRITICAL SECTION: Protect history buffer access
    CRITICAL_SECTION_ENTER();

    if (history_count == 0) {
        CRITICAL_SECTION_EXIT();
        return NULL;
    }

    // Handle negative indices (recent history)
    if (index < 0) {
        index = history_count + index;
    }

    if (index < 0 || index >= history_count) {
        CRITICAL_SECTION_EXIT();
        return NULL;
    }

    // Calculate actual position in circular buffer
    int pos = (history_index - history_count + index + HISTORY_SIZE) % HISTORY_SIZE;
    const char* result = history_buffer[pos];

    CRITICAL_SECTION_EXIT();
    return result;
}

/*=============================================================================
 * COMMAND: history - Display command history
 *=============================================================================*/
void cmd_history(int argc, char** argv) {
    // CRITICAL SECTION: Protect history buffer access for consistent snapshot
    CRITICAL_SECTION_ENTER();

    int display_count = history_count;

    // Parse optional count argument
    if (argc >= 2) {
        display_count = 0;
        for (const char* p = argv[1]; *p; p++) {
            if (*p >= '0' && *p <= '9') {
                display_count = display_count * 10 + (*p - '0');
            } else {
                kprintf("history: invalid number '%s'\n", argv[1]);
                CRITICAL_SECTION_EXIT();
                return;
            }
        }

        if (display_count > history_count) {
            display_count = history_count;
        }
    }

    if (history_count == 0) {
        kprintf("No commands in history\n");
        CRITICAL_SECTION_EXIT();
        return;
    }

    // Display history (most recent first or oldest first?)
    // Let's show oldest first (chronological order)
    int start_index = history_count - display_count;

    for (int i = start_index; i < history_count; i++) {
        // Calculate position directly instead of calling history_get()
        // to avoid nested critical sections
        int pos = (history_index - history_count + i + HISTORY_SIZE) % HISTORY_SIZE;
        kprintf("%4d  %s\n", i + 1, history_buffer[pos]);
    }

    kprintf("\nShowing %d of %d command(s)\n", display_count, history_count);

    CRITICAL_SECTION_EXIT();
}

/*=============================================================================
 * COMMAND: man - Display command manual/help
 *=============================================================================*/
void cmd_man(int argc, char** argv) {
    if (argc < 2) {
        kprintf("Usage: man <command>\n");
        kprintf("Available commands:\n");
        kprintf("  help, ls, cat, echo, clear, ps, top, mkdir, touch, rm\n");
        kprintf("  cp, mv, chmod, grep, find, history, man\n");
        kprintf("  mem, arp, ping, dhcp, dig, tcp, http, exec\n");
        return;
    }

    const char* cmd = argv[1];

    // File Management Commands
    if (strcmp(cmd, "ls") == 0) {
        kprintf("NAME\n");
        kprintf("    ls - list directory contents\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    ls [directory]\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    List information about files in the current or specified directory.\n");
    }
    else if (strcmp(cmd, "cat") == 0) {
        kprintf("NAME\n");
        kprintf("    cat - concatenate and print files\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    cat <file>\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Read file and print contents to console.\n");
    }
    else if (strcmp(cmd, "cp") == 0) {
        kprintf("NAME\n");
        kprintf("    cp - copy files\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    cp <source> <destination>\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Copy SOURCE file to DESTINATION.\n");
    }
    else if (strcmp(cmd, "mv") == 0) {
        kprintf("NAME\n");
        kprintf("    mv - move (rename) files\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    mv <source> <destination>\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Move (rename) SOURCE to DESTINATION.\n");
    }
    else if (strcmp(cmd, "rm") == 0) {
        kprintf("NAME\n");
        kprintf("    rm - remove files\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    rm <file>\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Remove (delete) specified file.\n");
    }
    else if (strcmp(cmd, "mkdir") == 0) {
        kprintf("NAME\n");
        kprintf("    mkdir - make directories\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    mkdir <directory>\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Create a new directory.\n");
    }
    else if (strcmp(cmd, "touch") == 0) {
        kprintf("NAME\n");
        kprintf("    touch - create empty file\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    touch <file>\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Create an empty file or update timestamp.\n");
    }
    else if (strcmp(cmd, "chmod") == 0) {
        kprintf("NAME\n");
        kprintf("    chmod - change file permissions\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    chmod <mode> <file>\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Change file permissions (not yet fully implemented).\n");
    }
    // Search Commands
    else if (strcmp(cmd, "grep") == 0) {
        kprintf("NAME\n");
        kprintf("    grep - search for patterns in files\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    grep <pattern> [file...]\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Search for PATTERN in each FILE. If no files specified,\n");
        kprintf("    searches all files in root directory.\n");
    }
    else if (strcmp(cmd, "find") == 0) {
        kprintf("NAME\n");
        kprintf("    find - search for files by name\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    find [directory] [pattern]\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Search for files matching PATTERN. Supports * wildcard.\n");
        kprintf("    Examples:\n");
        kprintf("      find *.txt    - Find all .txt files\n");
        kprintf("      find test*    - Find files starting with 'test'\n");
    }
    // Process Management
    else if (strcmp(cmd, "ps") == 0) {
        kprintf("NAME\n");
        kprintf("    ps - report process status\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    ps [-a] [-l]\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Display information about running processes.\n");
        kprintf("    -a, --all   Show all processes including terminated\n");
        kprintf("    -l, --long  Long format with detailed information\n");
    }
    else if (strcmp(cmd, "top") == 0) {
        kprintf("NAME\n");
        kprintf("    top - display system resource usage\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    top\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Display real-time system information including memory usage\n");
        kprintf("    and process CPU time. Press 'q' to quit.\n");
    }
    // Shell Features
    else if (strcmp(cmd, "history") == 0) {
        kprintf("NAME\n");
        kprintf("    history - display command history\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    history [n]\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Display command history. Optional argument N limits display\n");
        kprintf("    to last N commands.\n");
    }
    else if (strcmp(cmd, "man") == 0) {
        kprintf("NAME\n");
        kprintf("    man - display command manual\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    man <command>\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Display manual page for the specified command.\n");
    }
    else if (strcmp(cmd, "help") == 0) {
        kprintf("NAME\n");
        kprintf("    help - display available commands\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    help\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Display a list of available commands with brief descriptions.\n");
        kprintf("    Use 'man <command>' for detailed help.\n");
    }
    // Other common commands
    else if (strcmp(cmd, "clear") == 0) {
        kprintf("NAME\n");
        kprintf("    clear - clear the screen\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    clear\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Clear the terminal screen.\n");
    }
    else if (strcmp(cmd, "echo") == 0) {
        kprintf("NAME\n");
        kprintf("    echo - display a line of text\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    echo [text...]\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Display TEXT on standard output.\n");
    }
    else if (strcmp(cmd, "exec") == 0) {
        kprintf("NAME\n");
        kprintf("    exec - execute a program\n\n");
        kprintf("SYNOPSIS\n");
        kprintf("    exec <program>\n\n");
        kprintf("DESCRIPTION\n");
        kprintf("    Load and execute an ELF program from filesystem.\n");
    }
    else {
        kprintf("No manual entry for '%s'\n", cmd);
        kprintf("Try 'man man' for a list of available commands.\n");
    }
}
