/*=============================================================================
 *  TinyOS â€” Public Kernel Interface (kernel.h)
 *============================================================================*/
#ifndef TINYOS_KERNEL_H
#define TINYOS_KERNEL_H

#include <stdint.h>
#include <stddef.h>

#if defined(__GNUC__) || defined(__clang__)
#  define PACKED     __attribute__((packed))
#  define NORETURN   __attribute__((noreturn))
#else
#  define PACKED
#  define NORETURN
#endif

/*=============================================================================
 * Secure Memory Zeroing - Inline version for password clearing
 * Uses volatile to prevent compiler optimization from removing the writes
 * Simpler than crypto_secure_zero() to avoid memory corruption issues
 *===========================================================================*/
static inline void secure_zero_inline(void* ptr, size_t len) {
    volatile uint8_t* vptr = (volatile uint8_t*)ptr;
    for (size_t i = 0; i < len; i++) {
        vptr[i] = 0;
    }
}

/* Convenience macro for zeroing password buffers */
#define SECURE_ZERO_PASSWORD(var) secure_zero_inline(&(var), sizeof(var))

/* VGA text-mode */
enum { VGA_WIDTH = 80, VGA_HEIGHT = 25, VGA_BUFFER_ADDR = 0xB8000 };
#define VGA_DEFAULT_ATTR 0x0F

/* Boot stack configuration */
/* CRITICAL: This constant MUST match the stack size in boot.s */
/* Stack size for kernel boot (before multitasking starts) */
#define KERNEL_BOOT_STACK_SIZE  262144   /* 256 KiB */

/* Multiboot magic values (EAX on entry) */
#define MB1_MAGIC_BOOT  0x2BADB002u
#define MB2_MAGIC_BOOT  0x36D76289u

/* ------------------------- Multiboot v1 ------------------------- */
struct PACKED multiboot_info {
    uint32_t flags;
    uint32_t mem_lower, mem_upper;
    uint32_t boot_device;            /* optional */
    uint32_t cmdline;                /* char* */
    uint32_t mods_count, mods_addr;  /* optional */
    uint32_t num, size, addr, shndx; /* ELF */
    uint32_t mmap_length, mmap_addr; /* memory map */
    uint32_t drives_length, drives_addr;
    uint32_t config_table;
    uint32_t boot_loader_name;       /* char* */
    uint32_t apm_table;
    uint32_t vbe_ctrl_info, vbe_mode_info, vbe_mode;
    uint32_t vbe_interface_seg, vbe_interface_off, vbe_interface_len;
};

struct PACKED mb1_mmap_entry {
    uint32_t size;       /* size of the remaining fields (20) */
    uint32_t base_lo, base_hi;
    uint32_t len_lo,  len_hi;
    uint32_t type;       /* 1 = usable RAM */
};

/* ------------------------- Multiboot v2 ------------------------- */
struct PACKED mb2_tag { uint32_t type, size; };

enum { MB2_TAG_END = 0, MB2_TAG_CMDLINE = 1, MB2_TAG_BOOTLOADER = 2, MB2_TAG_MMAP = 6 };

struct PACKED mb2_tag_string { uint32_t type, size; char str[]; };

struct PACKED mb2_tag_mmap {
    uint32_t type, size;
    uint32_t entry_size;
    uint32_t entry_version;
    /* entries follow */
};

struct PACKED mb2_mmap_entry {
    uint64_t addr;
    uint64_t len;
    uint32_t type;
    uint32_t zero;
};

/* Entry point from boot.s */
void kernel_main(uint32_t magic, uint32_t info_ptr);

/* Console (vga.c) */
void  console_clear(void);
void  console_putc(char c);
void  console_puts(const char* s);
void  console_backspace(void);
void  console_put_hex32(uint32_t v);
void  console_put_hex64(uint64_t v);
void  console_put_dec_u32(uint32_t v);
void  console_put_dec_i32(int32_t v);
void  console_putchar_at(char c, uint8_t x, uint8_t y);
void  console_set_cursor_pos(uint8_t x, uint8_t y);

/* Timer (interrupts.c) */
uint32_t get_timer_ticks(void);

/* Deferred timer bottom-half: run from task context (ktimerd), NOT from the
 * ISR. The timer interrupt only flags pending work; this drains it. */
void timer_softirq_run(void);

/* Multiboot dumpers (multiboot.c) */
void  mb_dump_mb1(const struct multiboot_info* mb);
void  mb_dump_mb2(const void* info_ptr);

#endif 
