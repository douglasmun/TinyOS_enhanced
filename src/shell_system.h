/*=============================================================================
 * shell_system.h - Shell System Commands Module
 *
 * Commands: mem, kill, shutdown, reboot, date, env, set, unset, export
 *=============================================================================*/
#pragma once

/**
 * @brief Display memory usage
 * @param argc Number of arguments (must be 1)
 * @param argv Argument array
 */
void cmd_mem(int argc, char* argv[]);

/**
 * @brief Terminate a task
 * @param argc Number of arguments (must be 2: command + pid)
 * @param argv Argument array (argv[1] = pid)
 */
void cmd_kill(int argc, char* argv[]);

/**
 * @brief Shutdown the system
 * @param argc Number of arguments (must be 1)
 * @param argv Argument array
 */
void cmd_shutdown(int argc, char* argv[]);

/**
 * @brief Reboot the system
 * @param argc Number of arguments (must be 1)
 * @param argv Argument array
 */
void cmd_reboot(int argc, char* argv[]);

/**
 * @brief Display or set system date/time
 * @param argc Number of arguments
 * @param argv Argument array
 */
void cmd_date(int argc, char* argv[]);

/**
 * @brief Display environment variables
 * @param argc Number of arguments
 * @param argv Argument array
 */
void cmd_env(int argc, char* argv[]);

/**
 * @brief Set or display shell variables
 * @param argc Number of arguments
 * @param argv Argument array
 */
void cmd_set(int argc, char* argv[]);

/**
 * @brief Remove environment variable
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = variable name)
 */
void cmd_unset(int argc, char* argv[]);

/**
 * @brief Mark variable for export to child processes
 * @param argc Number of arguments
 * @param argv Argument array
 */
void cmd_export(int argc, char* argv[]);

/**
 * @brief Set or display command aliases
 * @param argc Number of arguments
 * @param argv Argument array
 */
void cmd_alias(int argc, char* argv[]);

/**
 * @brief Remove command alias
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = alias name)
 */
void cmd_unalias(int argc, char* argv[]);

/**
 * @brief View security audit logs
 * @param argc Number of arguments
 * @param argv Argument array (supports: -s, -v, -n, --warn, --error, --critical)
 */
void cmd_auditlog(int argc, char* argv[]);

/**
 * @brief Securely delete files (DoD 5220.22-M 3-pass overwrite)
 * @param argc Number of arguments
 * @param argv Argument array (argv[1..n] = file paths, supports: -z, -v, --zero, --verbose)
 */
void cmd_shred(int argc, char* argv[]);

/**
 * @brief Display ASLR (Address Space Layout Randomization) statistics
 * @param argc Number of arguments
 * @param argv Argument array
 */
void cmd_aslr(int argc, char* argv[]);

/**
 * @brief Display PAE (Physical Address Extension) status
 * @param argc Number of arguments
 * @param argv Argument array
 */
void cmd_pae(int argc, char* argv[]);

/**
 * @brief Audit memory for W^X (Write XOR Execute) violations
 * @param argc Number of arguments
 * @param argv Argument array
 */
void cmd_wxaudit(int argc, char* argv[]);

/**
 * @brief Run security hardening test suite
 * @param argc Number of arguments
 * @param argv Argument array
 */
void cmd_sectest(int argc, char* argv[]);

/**
 * @brief One-screen summary of all security subsystems (ASLR, W^X, ELF
 *        signing, firewall, IDS, EDR). Aggregates live subsystem getters.
 * @param argc Number of arguments
 * @param argv Argument array
 */
void cmd_secstatus(int argc, char* argv[]);
