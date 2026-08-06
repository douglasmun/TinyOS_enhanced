/*=============================================================================
 *  fbcon.h — Linear-framebuffer console (VBE via Multiboot2)
 *=============================================================================
 * Backend for the console_* API in vga.c. When GRUB honors the Multiboot2
 * framebuffer tag (boot.s) and hands us a 32bpp direct-RGB linear framebuffer,
 * vga.c dispatches every console operation here; otherwise the classic VGA
 * text-mode path runs unchanged.
 *===========================================================================*/
#ifndef FBCON_H
#define FBCON_H

#include <stdint.h>
#include <stdbool.h>

/* Parse the Multiboot2 framebuffer tag (type 8) and activate the framebuffer
 * console if a usable 32bpp RGB mode was set up. Must run before the first
 * console output (kernel_main calls it before console_clear). Safe to call
 * with a bad magic/pointer: it simply leaves the VGA text path active. */
void fbcon_early_init(uint32_t magic, const void* mb2_info);

bool fbcon_active(void);

/* Physical range of the framebuffer (page-aligned), for PAE mapping.
 * Returns false when the framebuffer console is not active. */
bool fbcon_get_range(uint32_t* phys, uint32_t* size);

/* Mode info for banners/diagnostics. Valid only when fbcon_active(). */
void fbcon_get_mode(uint32_t* width, uint32_t* height, uint32_t* text_cols,
                    uint32_t* text_rows);

/* Console operations mirroring the vga.c semantics. */
void fbcon_clear(void);
void fbcon_putc(char c);
void fbcon_backspace(void);
void fbcon_putchar_at(char c, uint8_t x, uint8_t y);
void fbcon_set_cursor_pos(uint8_t x, uint8_t y);

#endif /* FBCON_H */
