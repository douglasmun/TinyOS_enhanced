/*=============================================================================
 * shell_monitor.h - Shell System Monitoring Module
 *
 * Commands: top, ps (extended)
 *=============================================================================*/
#pragma once

/**
 * @brief Display real-time system resource usage
 * @param argc Number of arguments
 * @param argv Argument array
 */
void cmd_top(int argc, char** argv);

/**
 * @brief Display detailed process information
 * @param argc Number of arguments
 * @param argv Argument array (supports -a for all, -l for long format)
 */
void cmd_ps_extended(int argc, char** argv);

/**
 * @brief List background processes started by the calling shell
 * @param argc Number of arguments (unused)
 * @param argv Argument array (unused)
 */
void cmd_jobs(int argc, char** argv);
