#pragma once
#include <stdint.h>
#include <stdbool.h>

/* Low-level I/O port access */
static inline void outb(uint16_t p, uint8_t v) { 
    __asm__ volatile("outb %0,%1"::"a"(v),"Nd"(p)); 
}

static inline uint8_t inb(uint16_t p) { 
    uint8_t r; 
    __asm__ volatile("inb %1,%0":"=a"(r):"Nd"(p)); 
    return r; 
}

/* PIC functions - implemented in pic.c */
void pic_remap(void);           /* Remap PIC to IRQ 32-47 */
void pic_eoi(uint8_t irq);      /* Send End-Of-Interrupt */
bool pic_read_isr(uint8_t irq); /* Read ISR to detect spurious interrupts */

/* Inline helper functions */
static inline void pic_mask_all(void) {
    outb(0x21, 0xFF);  /* Mask all IRQs on master PIC */
    __asm__ volatile("outb %%al, $0x80" : : "a"(0) : "memory");  /* I/O barrier */
    outb(0xA1, 0xFF);  /* Mask all IRQs on slave PIC */
    __asm__ volatile("outb %%al, $0x80" : : "a"(0) : "memory");  /* I/O barrier */
}

static inline void pic_mask(uint8_t irq) {
    uint16_t port = (irq < 8u) ? 0x21 : 0xA1;
    uint8_t bit = (irq < 8u) ? irq : (uint8_t)(irq - 8u);
    // Read current mask from hardware
    uint8_t mask = inb(port);
    mask = (uint8_t)(mask | (uint8_t)(1u << bit));
    outb(port, mask);
    __asm__ volatile("outb %%al, $0x80" : : "a"(0) : "memory");  /* I/O barrier */
}

static inline void pic_unmask(uint8_t irq) {
    uint16_t port = (irq < 8u) ? 0x21 : 0xA1;
    uint8_t bit = (irq < 8u) ? irq : (uint8_t)(irq - 8u);
    // CRITICAL: Read current mask from hardware (no caching) to ensure coherency
    uint8_t mask = inb(port);
    mask = (uint8_t)(mask & (uint8_t)~(1u << bit));
    outb(port, mask);
    __asm__ volatile("outb %%al, $0x80" : : "a"(0) : "memory");  /* I/O barrier */
}
