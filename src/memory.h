/*=============================================================================
 *  memory.h — TinyOS Memory Layout
 *============================================================================*/
#pragma once

#ifndef MEMORYLAYOUT_H
#define MEMORYLAYOUT_H

// Kernel space (higher half)
#define KERNEL_BASE      0xC0000000
#define KERNEL_CODE_BASE 0xC0100000

// User space (lower half)  
#define USER_SPACE_BASE  0x00000000
#define USER_SPACE_END   0xBFFFFFFF

// Standard user memory layout
#define USER_CODE_BASE   0x08048000  // Where user programs start
#define USER_STACK_BASE  0x40000000  // User stack grows down from here
#define USER_STACK_SIZE  0x00100000  // 1MB stack
#define USER_HEAP_BASE   0x50000000  // User heap starts here
#define USER_MMAP_BASE   0x60000000  // Memory mappings start here

#endif
