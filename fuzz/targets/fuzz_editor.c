/* Fuzz target: the kernel-shell text editor, src/editor.c (`edit <file>`).
 *
 * Any user reaches it: `kshell` is ungated and `edit` opens any file the
 * user can read. It runs on the shell task's kernel stack, and its rows are
 * pmm pages, so a slip here is a kernel memory bug.
 *
 * Input:
 *   byte 0      bit 0: the file exists before the editor opens it
 *   byte 1      which row allocation fails (0 = none), as an OOM would
 *   bytes 2..3  file length, little-endian, capped at the bytes that follow
 *   ...         file contents, then keystrokes
 * A keystroke byte < 8 is a special key (: Enter Backspace Esc and the four
 * arrows); anything else is typed as is.
 *
 * Oracles:
 *   - Open: if the editor reports "Loaded file", its rows are the file,
 *     line for line. Anything it could not hold must be refused, not dropped:
 *     a later :w would write the truncated text over the original.
 *   - Keys: the characters in the buffer change only as the key says.
 *     Typing adds at most one, Enter and the arrows add none and remove none,
 *     Backspace removes at most one. A key that cannot be honoured may do
 *     nothing; it may not lose text.
 *   - Save: after "File saved", the file holds exactly the rows, each
 *     followed by a newline.
 *   - Rows: size and render stay inside their pages and are terminated.
 * ASan covers the row pages (each its own 4 KB heap block). */
#include <stdint.h>
void* fuzz_page_alloc(void);
static char* editor_fuzz_alloc(void);
#include "editor.c"
#include "ramfs.c"

#include <stdlib.h>
#include "fuzz_common.h"

static void die(int line) {
    char msg[32] = "editor: oracle line ";
    int n = 20;
    char d[8];
    int k = 0;
    do { d[k++] = (char)('0' + line % 10); line /= 10; } while (line);
    while (k) msg[n++] = d[--k];
    msg[n] = 0;
    fuzz_note(msg);
    abort();
}
#define abort() die(__LINE__)

static task_t task_root;
task_t* scheduler_get_current_task(void) { return &task_root; }

/* build.sh rewrites the row allocation to this: pmm_alloc() returns a
 * uint32_t the host cannot hold a pointer in. */
static int alloc_seq, alloc_fail_at;
static char* editor_fuzz_alloc(void) {
    if (++alloc_seq == alloc_fail_at) return NULL;
    return fuzz_page_alloc();
}

/* ---- keyboard ---- */
static const uint8_t* keys;
static size_t keys_left;
bool keyboard_has_data(void) { return keys_left > 0; }
static const uint8_t SPECIAL[8] = { ':', '\n', '\b', 27,
                                    KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT };
char keyboard_getchar_nonblock(void) {
    uint8_t c = *keys++;
    keys_left--;
    return (char)(c < 8 ? SPECIAL[c] : c);
}
void console_putchar_at(char c, uint8_t x, uint8_t y) {
    (void)c;
    if (x >= 80 || y >= 25) abort();
}
void console_set_cursor_pos(uint8_t x, uint8_t y) { (void)x; (void)y; }

/* ---- helpers ---- */
static void free_tree(ramfs_node_t* n) {
    while (n) {
        ramfs_node_t* next = n->next;
        free_tree(n->children);
        for (int i = 0; i < RAMFS_MAX_PAGES; i++)
            if (n->data_pages[i]) fuzz_page_free(n->data_pages[i]);
        fuzz_page_free(n);
        n = next;
    }
}

static long chars_in_buffer(void) {
    long c = 0;
    for (int i = 0; i < E.numrows; i++) {
        erow* r = &E.rows[i];
        if (r->size < 0 || r->size > 4095 || r->chars[r->size]) abort();
        if (r->rsize < 0 || r->rsize > 4095 || r->render[r->rsize]) abort();
        c += r->size;
    }
    return c;
}

static int read_file(char* buf, size_t cap) {
    int fd = ramfs_open("/f", RAMFS_FLAG_READ);
    if (fd < 0) return -1;
    int n = ramfs_read(fd, buf, cap);
    ramfs_close(fd);
    return n;
}

/* The rows joined the way editor_save() writes them. */
static size_t rows_text(char* out) {
    size_t n = 0;
    for (int i = 0; i < E.numrows; i++) {
        memcpy(out + n, E.rows[i].chars, (size_t)E.rows[i].size);
        n += (size_t)E.rows[i].size;
        out[n++] = '\n';
    }
    return n;
}

/* Rows editor_open() should produce: one per '\n'-separated segment
 * (including the one after the last newline), a trailing '\r' dropped. */
static void check_loaded(const uint8_t* f, size_t len) {
    int row = 0;
    size_t start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i < len && f[i] != '\n') continue;
        size_t l = i - start;
        if (l && f[i - 1] == '\r') l--;
        if (row >= E.numrows) abort();
        if ((size_t)E.rows[row].size != l) abort();
        if (memcmp(E.rows[row].chars, f + start, l)) abort();
        row++;
        start = i + 1;
    }
    if (row != E.numrows) abort();
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len) {
    static char text[FILE_BUFFER_SIZE + 4096], back[FILE_BUFFER_SIZE + 4096];
    if (len < 4) return 0;
    uint8_t flags = data[0];
    alloc_fail_at = data[1];
    size_t flen = (size_t)data[2] | (size_t)data[3] << 8;
    data += 4;
    len -= 4;
    if (flen > len) flen = len;

    fuzz_reset();
    alloc_seq = 0;
    for (int i = 0; i < RAMFS_MAX_FDS; i++) file_descriptors[i].in_use = false;
    if (root) free_tree(root);
    root = NULL;
    total_nodes = 0;
    memset(&task_root, 0, sizeof(task_root));
    ramfs_init();

    if (flags & 1) {
        int fd = ramfs_open("/f", RAMFS_FLAG_READ | RAMFS_FLAG_WRITE);
        if (fd < 0) abort();
        ramfs_write(fd, data, flen);
        ramfs_close(fd);
    }

    memset(&E, 0, sizeof(E));
    editor_init();
    if (!E.rows) abort();
    editor_open("/f");
    if (!strcmp(E.statusmsg, "Loaded file")) check_loaded(data, flen);

    keys = data + flen;
    keys_left = len - flen;
    while (keys_left) {
        bool cmd = E.command_mode;
        uint8_t k = *keys;
        long before = chars_in_buffer();
        E.statusmsg[0] = 0;
        bool go = editor_process_keypress();
        long d = chars_in_buffer() - before;
        unsigned char c = (unsigned char)(k < 8 ? SPECIAL[k] : k);
        if (cmd || c == ':') {
            if (d != 0) abort();
        } else if (c == '\b' || c == 127) {
            if (d != 0 && d != -1) abort();
        } else if (c >= 32 && c < 127) {
            if (d != 0 && d != 1) abort();
        } else if (d != 0) {
            abort();  /* Enter, arrows, Esc and the rest move or split text */
        }
        if (E.cx < 0 || E.cy < 0 || E.rowoff < 0) abort();
        if (!strcmp(E.statusmsg, "File saved")) {
            size_t n = rows_text(text);
            int got = read_file(back, sizeof(back));
            if (got < 0 || (size_t)got != n || memcmp(back, text, n)) abort();
        }
        editor_draw_rows();
        editor_draw_status_bar();
        if (!go) break;
    }
    editor_cleanup();
    return 0;
}
