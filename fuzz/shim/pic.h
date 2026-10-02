/* Host-build replacement for src/pic.h (fuzzing only): port I/O is a no-op. */
#pragma once
#include <stdint.h>
#include <stdbool.h>

static inline void outb(uint16_t p, uint8_t v) { (void)p; (void)v; }
static inline uint8_t inb(uint16_t p) { (void)p; return 0xFF; }
void pic_remap(void);
void pic_eoi(uint8_t irq);
bool pic_read_isr(uint8_t irq);
static inline void pic_mask_all(void) {}
static inline void pic_mask(uint8_t irq) { (void)irq; }
static inline void pic_unmask(uint8_t irq) { (void)irq; }
