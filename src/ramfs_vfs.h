/*=============================================================================
 * ramfs_vfs.h - RAMFS VFS Driver Interface
 *=============================================================================*/
#pragma once

#include "vfs.h"

/**
 * @brief Register RAMFS as a VFS driver
 * @return 0 on success, negative error code on failure
 */
int ramfs_vfs_init(void);

/**
 * @brief Get RAMFS file operations for VFS
 * @return Pointer to file operations structure
 */
const file_operations_t* ramfs_get_vfs_ops(void);
