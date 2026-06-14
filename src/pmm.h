/*=============================================================================
 *  pmm.h â€” TinyOS Physical Memory Manager (bitmap)
 *============================================================================*/
#pragma once
#include <stdint.h>
#include <stddef.h>

/* 4 KiB frames */
#define PMM_PAGE_SIZE 4096

/* Initialize from Multiboot2 info pointer */
void pmm_init_from_mb2(const void* mb2_info);

/* Mark a physical range as used / free (helpers) */
void pmm_mark_used(uint32_t phys, uint32_t size);
void pmm_mark_free(uint32_t phys, uint32_t size);

/* Allocate/free one 4 KiB frame. Returns physical address or 0 on failure. */
uint32_t pmm_alloc(void);
void     pmm_free(uint32_t phys);

/* Allocate `count` physically CONTIGUOUS 4 KiB frames; returns base physical
 * address or 0 if no run that large is free. Required for multi-page kernel
 * stacks, which are addressed as a single block (esp = base + count*4096). */
uint32_t pmm_alloc_contiguous(uint32_t count);

/* Allocate one 4 KiB frame below 32 MiB (identity-mapped region).
 * For paging structures accessed via virtual == physical. */
uint32_t pmm_alloc_low(void);

/* Stats */
uint32_t pmm_total_frames(void);
uint32_t pmm_free_frames(void);

