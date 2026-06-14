/*=============================================================================
 * shell_fileops.h - Shell File Operations Module
 *
 * Commands: cp, mv, chmod, pwd, cd, ls, cat, mkdir, touch, write, rm, exec
 *=============================================================================*/
#pragma once

#include <stddef.h>

/**
 * @brief Copy file
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = source, argv[2] = destination)
 */
void cmd_cp(int argc, char** argv);

/**
 * @brief Move/rename file
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = source, argv[2] = destination)
 */
void cmd_mv(int argc, char** argv);

/**
 * @brief Change file permissions (placeholder)
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = mode, argv[2] = file)
 */
void cmd_chmod(int argc, char** argv);

/**
 * @brief Print working directory
 */
void cmd_pwd(void);

/**
 * @brief Change directory
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = path)
 */
void cmd_cd(int argc, char** argv);

/**
 * @brief List directory contents
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = path, optional)
 */
void cmd_ls(int argc, char** argv);

/**
 * @brief Display file contents
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = file)
 */
void cmd_cat(int argc, char** argv);

/**
 * @brief Create directory
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = path)
 */
void cmd_mkdir(int argc, char** argv);

/**
 * @brief Create empty file
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = file)
 */
void cmd_touch(int argc, char** argv);

/**
 * @brief Write text to file
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = file, argv[2...] = text)
 */
void cmd_write(int argc, char** argv);

/**
 * @brief Remove file
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = file)
 */
void cmd_rm(int argc, char** argv);

/**
 * @brief Execute ELF binary
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = file)
 */
void cmd_exec(int argc, char** argv);

/**
 * @brief Text editor
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = file)
 */
void cmd_edit(int argc, char** argv);

/**
 * @brief Show mounted drives (Phase 1: FAT32 Support)
 * @param argc Number of arguments
 * @param argv Argument array (unused)
 */
void cmd_mount(int argc, char** argv);

/**
 * @brief List FAT32 root directory (Phase 1: Basic C: access)
 * @param argc Number of arguments
 * @param argv Argument array (unused)
 */
void cmd_fatls(int argc, char** argv);

/**
 * @brief Canonicalize a path (resolve .., ., //, etc.)
 * @param path Input path (relative or absolute)
 * @param canonical_out Output buffer for canonical path
 * @param size Size of output buffer
 * @return 0 on success, -1 on error (buffer too small, invalid path)
 *
 * SECURITY: This function normalizes paths to prevent traversal attacks:
 * - Converts relative paths to absolute paths
 * - Resolves ".." and "." components
 * - Removes duplicate slashes
 * - Validates result stays within root filesystem "/"
 */
int canonicalize_path(const char* path, char* canonical_out, size_t size);
