/*=============================================================================
 * shell_search.h - Shell Search & Filter Module
 *
 * Commands: grep, find
 *=============================================================================*/
#pragma once

/**
 * @brief Search for pattern in file(s)
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = pattern, argv[2+] = files)
 */
void cmd_grep(int argc, char** argv);

/**
 * @brief Find files by name pattern
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = starting directory, argv[2] = pattern)
 */
void cmd_find(int argc, char** argv);
