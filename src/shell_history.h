/*=============================================================================
 * shell_history.h - Shell History & Help Module
 *
 * Commands: history, man
 *=============================================================================*/
#pragma once

/*=============================================================================
 * SECURITY FIX (Issue 4.3): Shell History Limits (DoS Prevention)
 *
 * CRITICAL: Without limits, malicious user can exhaust memory by adding
 * thousands of history entries, causing DoS. Limit to reasonable values:
 * - 50 history entries (down from 100)
 * - 256 bytes per entry (unchanged)
 * - Total: 50 * 256 = 12.8 KB max (acceptable memory overhead)
 *===========================================================================*/
#define HISTORY_SIZE 50
#define HISTORY_LINE_SIZE 256

/**
 * @brief Initialize history system
 */
void history_init(void);

/**
 * @brief Add command to history
 * @param command Command string to add
 */
void history_add(const char* command);

/**
 * @brief Display command history
 * @param argc Number of arguments
 * @param argv Argument array
 */
void cmd_history(int argc, char** argv);

/**
 * @brief Display manual/help for a command
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = command name)
 */
void cmd_man(int argc, char** argv);

/**
 * @brief Get command from history by index
 * @param index History index (negative for recent)
 * @return Command string or NULL
 */
const char* history_get(int index);
