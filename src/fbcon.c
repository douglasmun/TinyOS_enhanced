/*=============================================================================
 *  fbcon.c — Linear-framebuffer console (VBE via Multiboot2)
 *=============================================================================
 * Renders the text console into a 32bpp direct-RGB linear framebuffer that
 * GRUB sets up in response to the Multiboot2 framebuffer tag in boot.s.
 *
 * Glyphs come from the public-domain 8x8 IBM VGA font (font8x8_basic.h,
 * Marcel Sondaar / Daniel Hepper); each font row is doubled to fill a classic
 * 8x16 text cell, so a 640x480 mode yields an 80x30 console.
 *
 * A text shadow buffer (char + VGA attribute per cell) mirrors the screen so
 * cells can be re-rendered without ever reading the framebuffer (framebuffer
 * reads are slow on real hardware and under emulation).
 *
 * The framebuffer physical range sits above RAM (e.g. 0xFD000000 on QEMU), so
 * pae_init() maps it explicitly before paging is enabled — see fbcon_get_range.
 *===========================================================================*/
#include "kernel.h"
#include "critical.h"
#include "util.h"      /* memmove */
#include "fbcon.h"
#include "font8x8_basic.h"

#define FBCON_CELL_W   8u
#define FBCON_CELL_H   16u
#define FBCON_MAX_COLS 128u   /* supports modes up to 1024 px wide  */
#define FBCON_MAX_ROWS 64u    /* supports modes up to 1024 px tall  */

/* Sanity bounds for the mode reported by the bootloader */
#define FBCON_MIN_WIDTH   320u
#define FBCON_MIN_HEIGHT  200u
#define FBCON_MAX_WIDTH   4096u
#define FBCON_MAX_HEIGHT  4096u

#define MB2_FB_TYPE_RGB 1u

static bool fb_active = false;

static uint32_t fb_phys;      /* physical base address (below 4 GB)     */
static uint32_t fb_pitch;     /* bytes per scanline                     */
static uint32_t fb_width;     /* pixels per scanline                    */
static uint32_t fb_height;    /* scanlines                              */

static uint32_t text_cols;    /* usable console columns (<= MAX_COLS)   */
static uint32_t text_rows;    /* usable console rows (<= MAX_ROWS)      */

static uint32_t cur_col;
static uint32_t cur_row;

/* 32bpp pixel values for the 16 VGA colors, packed per the mode's RGB field
 * positions at init time. */
static uint32_t palette[16];

/* Shadow of the visible text: low byte = character, high byte = attribute. */
static uint16_t shadow[FBCON_MAX_ROWS][FBCON_MAX_COLS];

/* Standard VGA 16-color palette, {r, g, b} */
static const uint8_t vga_rgb[16][3] = {
    {0x00,0x00,0x00}, {0x00,0x00,0xAA}, {0x00,0xAA,0x00}, {0x00,0xAA,0xAA},
    {0xAA,0x00,0x00}, {0xAA,0x00,0xAA}, {0xAA,0x55,0x00}, {0xAA,0xAA,0xAA},
    {0x55,0x55,0x55}, {0x55,0x55,0xFF}, {0x55,0xFF,0x55}, {0x55,0xFF,0xFF},
    {0xFF,0x55,0x55}, {0xFF,0x55,0xFF}, {0xFF,0xFF,0x55}, {0xFF,0xFF,0xFF},
};

/*=============================================================================
 * Pixel-level helpers
 *===========================================================================*/

static inline volatile uint32_t* fb_line(uint32_t y) {
    return (volatile uint32_t*)(uintptr_t)(fb_phys + y * fb_pitch);
}

/* Re-render one text cell from the shadow buffer. Overwrites every pixel of
 * the cell (including background), so it also erases any cursor overlay. */
static void render_cell(uint32_t x, uint32_t y) {
    const uint16_t cell = shadow[y][x];
    uint8_t ch = (uint8_t)(cell & 0xFFu);
    const uint8_t at = (uint8_t)(cell >> 8);
    const uint32_t fg = palette[at & 0x0Fu];
    const uint32_t bg = palette[(at >> 4) & 0x0Fu];

    if (ch >= 128u) ch = '?';   /* font covers ASCII 0-127 only */
    const unsigned char* glyph = font8x8_basic[ch];

    const uint32_t px = x * FBCON_CELL_W;
    const uint32_t py = y * FBCON_CELL_H;

    for (uint32_t fy = 0; fy < FBCON_CELL_H; ++fy) {
        /* Row-double the 8x8 glyph into the 8x16 cell */
        const unsigned char bits = glyph[fy >> 1];
        volatile uint32_t* line = fb_line(py + fy) + px;
        for (uint32_t fx = 0; fx < FBCON_CELL_W; ++fx) {
            /* font8x8 convention: bit 0 is the LEFTMOST pixel */
            line[fx] = (bits & (1u << fx)) ? fg : bg;
        }
    }
}

/* Cursor overlay: two bright scanlines at the bottom of the current cell.
 * Erased by re-rendering the cell from the shadow (render_cell). */
static void cursor_draw(void) {
    const uint32_t fg = palette[VGA_DEFAULT_ATTR & 0x0Fu];
    const uint32_t px = cur_col * FBCON_CELL_W;
    const uint32_t py = cur_row * FBCON_CELL_H;

    for (uint32_t fy = FBCON_CELL_H - 2u; fy < FBCON_CELL_H; ++fy) {
        volatile uint32_t* line = fb_line(py + fy) + px;
        for (uint32_t fx = 0; fx < FBCON_CELL_W; ++fx) {
            line[fx] = fg;
        }
    }
}

static void cursor_erase(void) {
    render_cell(cur_col, cur_row);
}

/* Fill a horizontal band of scanlines [y0, y0+n) with the background color. */
static void fill_band(uint32_t y0, uint32_t n, uint32_t color) {
    for (uint32_t y = y0; y < y0 + n; ++y) {
        volatile uint32_t* line = fb_line(y);
        for (uint32_t x = 0; x < fb_width; ++x) {
            line[x] = color;
        }
    }
}

static void put_at(char c, uint8_t a, uint32_t x, uint32_t y) {
    if (x >= text_cols || y >= text_rows) return;
    shadow[y][x] = (uint16_t)((uint8_t)c | ((uint16_t)a << 8));
    render_cell(x, y);
}

static void scroll(void) {
    /* Shift the shadow up one row and re-render only the cells whose value
     * changed. This is write-only with respect to the framebuffer — the whole
     * point of the shadow buffer — where a framebuffer memmove would read
     * ~1 MB of slow (write-through-mapped) framebuffer per scrolled line, all
     * inside the caller's interrupts-off window. Unchanged cells (blank over
     * blank is the common case) cost one shadow compare and no pixel I/O.
     * Callers erase the cursor overlay before scrolling, so skipping an
     * unchanged cell never leaves a stale overlay behind. */
    const uint16_t blank = (uint16_t)(' ' | ((uint16_t)VGA_DEFAULT_ATTR << 8));

    for (uint32_t y = 0; y + 1u < text_rows; ++y) {
        for (uint32_t x = 0; x < text_cols; ++x) {
            const uint16_t nv = shadow[y + 1u][x];
            if (shadow[y][x] != nv) {
                shadow[y][x] = nv;
                render_cell(x, y);
            }
        }
    }
    for (uint32_t x = 0; x < text_cols; ++x) {
        if (shadow[text_rows - 1u][x] != blank) {
            shadow[text_rows - 1u][x] = blank;
            render_cell(x, text_rows - 1u);
        }
    }
}

static void advance(void) {
    if (++cur_col >= text_cols) { cur_col = 0; ++cur_row; }
    if (cur_row >= text_rows) { scroll(); cur_row = text_rows - 1u; }
}

/*=============================================================================
 * Public console operations (semantics mirror vga.c)
 *===========================================================================*/

bool fbcon_active(void) {
    return fb_active;
}

bool fbcon_get_range(uint32_t* phys, uint32_t* size) {
    if (!fb_active) return false;
    const uint32_t base = fb_phys & ~0xFFFu;
    const uint32_t end = fb_phys + fb_height * fb_pitch;
    *phys = base;
    *size = ((end - base) + 0xFFFu) & ~0xFFFu;
    return true;
}

void fbcon_get_mode(uint32_t* width, uint32_t* height, uint32_t* out_cols,
                    uint32_t* out_rows) {
    if (width) *width = fb_width;
    if (height) *height = fb_height;
    if (out_cols) *out_cols = text_cols;
    if (out_rows) *out_rows = text_rows;
}

void fbcon_clear(void) {
    uint32_t flags = disable_interrupts();

    const uint16_t blank = (uint16_t)(' ' | ((uint16_t)VGA_DEFAULT_ATTR << 8));
    for (uint32_t y = 0; y < FBCON_MAX_ROWS; ++y)
        for (uint32_t x = 0; x < FBCON_MAX_COLS; ++x)
            shadow[y][x] = blank;

    fill_band(0, fb_height, palette[(VGA_DEFAULT_ATTR >> 4) & 0x0Fu]);
    cur_col = cur_row = 0;
    cursor_draw();

    restore_interrupts(flags);
}

void fbcon_putc(char c) {
    uint32_t flags = disable_interrupts();

    if (c == '\n') {
        cursor_erase();
        cur_col = 0; ++cur_row;
        if (cur_row >= text_rows) { scroll(); cur_row = text_rows - 1u; }
    } else if (c == '\r') {
        cursor_erase();
        cur_col = 0;
    } else if (c == '\b') {
        cursor_erase();
        if (cur_col > 0) {
            cur_col--;
        } else if (cur_row > 0) {
            cur_row--;
            cur_col = text_cols - 1u;
        }
    } else {
        /* No separate cursor_erase: put_at fully re-renders the cursor cell
         * (every pixel), which erases the overlay as a side effect. */
        put_at(c, VGA_DEFAULT_ATTR, cur_col, cur_row);
        advance();
    }

    cursor_draw();
    restore_interrupts(flags);
}

void fbcon_backspace(void) {
    uint32_t flags = disable_interrupts();

    cursor_erase();

    if (cur_col > 0) {
        cur_col--;
    } else if (cur_row > 0) {
        cur_row--;
        cur_col = text_cols - 1u;
    } else {
        cursor_draw();
        restore_interrupts(flags);
        return;
    }

    put_at(' ', VGA_DEFAULT_ATTR, cur_col, cur_row);
    cursor_draw();
    restore_interrupts(flags);
}

void fbcon_putchar_at(char c, uint8_t x, uint8_t y) {
    uint32_t flags = disable_interrupts();
    put_at(c, VGA_DEFAULT_ATTR, x, y);
    /* Re-assert the cursor in case the write landed on its cell */
    if (x == cur_col && y == cur_row) cursor_draw();
    restore_interrupts(flags);
}

void fbcon_set_cursor_pos(uint8_t x, uint8_t y) {
    uint32_t flags = disable_interrupts();

    cursor_erase();
    cur_col = (x >= text_cols) ? text_cols - 1u : x;
    cur_row = (y >= text_rows) ? text_rows - 1u : y;
    cursor_draw();

    restore_interrupts(flags);
}

/*=============================================================================
 * Multiboot2 framebuffer tag parsing
 *===========================================================================*/

void fbcon_early_init(uint32_t magic, const void* mb2_info) {
    if (magic != MB2_MAGIC_BOOT || mb2_info == NULL) return;

    /* Bounds-checked tag walk, same discipline as mb_dump_mb2() */
    const uint8_t* base = (const uint8_t*)mb2_info;
    const uint32_t total_size = *(const uint32_t*)base;
    if (total_size < 8u || total_size > (1024u * 1024u)) return;

    const uint8_t* end = base + total_size;
    if (end < base) return;

    const uint8_t* p = base + 8;
    const struct mb2_tag_framebuffer* fbtag = NULL;

    while (p + sizeof(struct mb2_tag) <= end) {
        const struct mb2_tag* tag = (const struct mb2_tag*)p;
        if (tag->type == MB2_TAG_END) break;
        if (tag->size < sizeof(struct mb2_tag)) return;
        if (tag->size > (uintptr_t)(end - p)) return;

        if (tag->type == MB2_TAG_FRAMEBUFFER &&
            tag->size >= sizeof(struct mb2_tag_framebuffer)) {
            fbtag = (const struct mb2_tag_framebuffer*)tag;
            break;
        }

        const uintptr_t adv = ((uintptr_t)tag->size + 7u) & ~(uintptr_t)7u;
        if (adv == 0 || adv > (uintptr_t)(end - p)) return;
        p += adv;
    }

    if (!fbtag) return;                         /* no framebuffer tag: VGA text */
    if (fbtag->fb_type != MB2_FB_TYPE_RGB) return;  /* EGA text / indexed: VGA */
    if (fbtag->bpp != 32u) return;              /* only 32bpp supported */
    if (fbtag->addr >= 0x100000000ULL) return;  /* must be addressable in PAE32 */

    const uint32_t w = fbtag->width, h = fbtag->height;
    if (w < FBCON_MIN_WIDTH || w > FBCON_MAX_WIDTH) return;
    if (h < FBCON_MIN_HEIGHT || h > FBCON_MAX_HEIGHT) return;
    /* Bound pitch both ways: below by the row's pixel data, above by the
     * widest supported mode. An unbounded bootloader-supplied pitch would
     * overflow the 32-bit fb_height * fb_pitch products in fb_line() and
     * fbcon_get_range(), mapping the wrong range and writing outside it. */
    if (fbtag->pitch < w * 4u || fbtag->pitch > FBCON_MAX_WIDTH * 4u) return;
    /* The whole framebuffer must fit below 4 GB (PAE32-addressable). */
    if (fbtag->addr + (uint64_t)h * fbtag->pitch > 0x100000000ULL) return;
    /* RGB field positions must fit a 32-bit pixel */
    if (fbtag->red_pos > 24u || fbtag->green_pos > 24u || fbtag->blue_pos > 24u)
        return;

    fb_phys = (uint32_t)fbtag->addr;
    fb_pitch = fbtag->pitch;
    fb_width = w;
    fb_height = h;

    text_cols = w / FBCON_CELL_W;
    if (text_cols > FBCON_MAX_COLS) text_cols = FBCON_MAX_COLS;
    text_rows = h / FBCON_CELL_H;
    if (text_rows > FBCON_MAX_ROWS) text_rows = FBCON_MAX_ROWS;

    for (uint32_t i = 0; i < 16u; ++i) {
        palette[i] = ((uint32_t)vga_rgb[i][0] << fbtag->red_pos) |
                     ((uint32_t)vga_rgb[i][1] << fbtag->green_pos) |
                     ((uint32_t)vga_rgb[i][2] << fbtag->blue_pos);
    }

    cur_col = cur_row = 0;
    fb_active = true;
    /* kernel_main calls console_clear() right after this, which now paints
     * the framebuffer via fbcon_clear(). */
}
