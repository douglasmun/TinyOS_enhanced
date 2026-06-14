/*=============================================================================
 * fat32_vfs.h - FAT32 VFS Driver Interface
 *=============================================================================*/
#pragma once

#include "vfs.h"

/**
 * @brief Register FAT32 as a VFS driver
 * @return 0 on success, negative error code on failure
 */
int fat32_vfs_init(void);

/**
 * @brief Get FAT32 file operations for VFS
 * @return Pointer to file operations structure
 */
const file_operations_t* fat32_get_vfs_ops(void);
