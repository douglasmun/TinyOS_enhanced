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
//
// User images link here (userspace/user.ld). It must sit above every physical
// address the kernel identity-maps (PMM_MAX_BYTES, static-asserted in elf.c):
// a user PTE at a virtual address the kernel also maps 1:1 replaces the
// kernel's view of that physical frame while the process's CR3 is loaded.
// The old base, 0x08000000, shadowed frames 128 MB and up.
// See doc/DESIGN_USER_LINK_BASE.md.
#define USER_IMAGE_BASE  0x20000000
#define USER_STACK_BASE  0x40000000  // User stack grows down from here
#define USER_STACK_SIZE  0x00100000  // 1MB stack
#define USER_HEAP_BASE   0x50000000  // User heap starts here
#define USER_MMAP_BASE   0x60000000  // Memory mappings start here

#endif
