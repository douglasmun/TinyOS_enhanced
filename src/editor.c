/*=============================================================================
 * editor.c - Simple Text Editor for TinyOS
 *=============================================================================*/
#include "editor.h"
#include "kernel.h"
#include "kprintf.h"
#include "keyboard.h"
#include "ramfs.h"
#include "util.h"
#include "pit.h"
#include "pmm.h"
#include "stdio.h"
#include <stddef.h>

/*=============================================================================
 * GLOBAL EDITOR STATE - THREADING AND SYNCHRONIZATION ANALYSIS
 *=============================================================================
 * SECURITY FIX (AUDIT 5C): Editor State Synchronization Assessment
 *
 * AUDIT CONCERN: "The global EditorState structure is accessed by multiple
 * functions but lacks synchronization. If the editor is used in a multi-
 * threaded or interrupt-driven context, race conditions could occur."
 *
 * CURRENT IMPLEMENTATION ANALYSIS:
 *
 * 1. THREADING MODEL:
 *    - TinyOS is a single-CPU, cooperative multitasking kernel
 *    - The editor runs as a userspace process (Ring 3)
 *    - No preemptive multithreading exists in current implementation
 *    - Only interrupts (timer, keyboard) can interrupt editor execution
 *
 * 2. INTERRUPT SAFETY:
 *    - Timer ISR: Does NOT access EditorState 
 *    - Keyboard ISR: Does NOT access EditorState 
 *    - Editor accesses timer via get_timer_ticks() which is already
 *      protected with critical sections (Fix #16) 
 *
 * 3. RACE CONDITION ASSESSMENT:
 *    Since no ISRs modify EditorState and TinyOS has no threading,
 *    the current implementation is safe. No additional synchronization
 *    is required at this time.
 *
 * 4. FUTURE CONSIDERATIONS:
 *    If TinyOS adds preemptive multithreading or allows multiple processes
 *    to run the editor concurrently, synchronization will be required:
 *    - Option 1: Add mutex around all EditorState access
 *    - Option 2: Make editor single-instance (lock file)
 *    - Option 3: Per-process editor state (no global variable)
 *
 * CONCLUSION: No changes required. Current design is safe given TinyOS
 * architecture. This comment documents the threading model for future
 * developers and addresses the audit's theoretical concern.
 *===========================================================================*/
static EditorState E;

/* Memory buffer for file content */
#define FILE_BUFFER_SIZE (64 * 1024)
static char file_buffer[FILE_BUFFER_SIZE];

/*=============================================================================
 * UTILITY FUNCTIONS
 *=============================================================================*/

static void editor_set_status_message(const char *msg) {
    size_t len = strlen(msg);
    if (len >= sizeof(E.statusmsg)) len = sizeof(E.statusmsg) - 1;

    for (size_t i = 0; i < len; i++) {
        E.statusmsg[i] = msg[i];
    }
    E.statusmsg[len] = '\0';
    E.statusmsg_time = get_timer_ticks();
}

/*=============================================================================
 * ROW OPERATIONS
 *=============================================================================*/

static void editor_update_row(erow *row) {
    int tabs = 0;
    for (int i = 0; i < row->size; i++) {
        if (row->chars[i] == '\t') tabs++;
    }

    /* SECURITY FIX: Prevent render buffer overflow from tab expansion
     * Calculate expected render size. With EDITOR_TAB_STOP=8, worst case
     * is all tabs: 4095 chars * 8 spaces = 32760 bytes, which exceeds the
     * 4096-byte render buffer from pmm_alloc(). We must validate that
     * expansion won't overflow before writing to render buffer.
     *
     * Example attack: 512 tabs @ position 7 each = 512 * 8 = 4096 spaces,
     * overflowing into next page. */
    row->rsize = row->size + tabs * (EDITOR_TAB_STOP - 1);
    if (row->rsize >= 4096) {
        /* Render would overflow - truncate to prevent buffer overflow */
        row->rsize = 4095;
    }

    /* Expand tabs to spaces with bounds checking */
    int idx = 0;
    for (int i = 0; i < row->size && idx < 4095; i++) {
        if (row->chars[i] == '\t') {
            row->render[idx++] = ' ';
            while (idx % EDITOR_TAB_STOP != 0 && idx < 4095) {
                row->render[idx++] = ' ';
            }
        } else {
            row->render[idx++] = row->chars[i];
        }
    }
    row->render[idx] = '\0';
    row->rsize = idx;
}

#ifdef TINYOS_FAULT_INJECT
/* 0 = no injection; 1 = fail the `chars` alloc; 2 = fail the `render` alloc.
 * Cleared by the alloc it fires on, so one arm = one failure. */
static int editor_inject_fail = 0;
static int editor_alloc_seq = 0;

void editor_fail_next_alloc(int which) {
    editor_inject_fail = which;
    editor_alloc_seq = 0;
}

/* pmm_alloc() wrapper used ONLY by editor_insert_row, so injection cannot
 * disturb E.rows/E.filename or anything outside the path under test. */
static uint32_t editor_row_alloc(void) {
    editor_alloc_seq++;
    if (editor_inject_fail == editor_alloc_seq) {
        editor_inject_fail = 0;
        return 0;
    }
    return pmm_alloc();
}
#else
#define editor_row_alloc() pmm_alloc()
#endif

static void editor_insert_row(int at, const char *s, size_t len) {
    if (at > E.numrows || E.numrows >= EDITOR_MAX_ROWS) return;
    /* E.rows is a single 4096-byte page; never exceed the slots it holds */
    if (E.numrows >= (int)(4096 / sizeof(erow))) return;

    /* SECURITY FIX: Prevent buffer overflow when len is at maximum
     * The pmm_alloc() returns a 4096-byte page. Writing chars[4096] when
     * len==4096 would overflow into the next page. Limit len to 4095 to
     * ensure room for null terminator. */
    if (len >= 4096) {
        len = 4095;  /* Reserve one byte for null terminator */
    }

    /* Allocate BEFORE shifting.
     *
     * This ordering is load-bearing, not style. The shift makes E.rows[at] a
     * bitwise copy of E.rows[at + 1] -- same `chars`, same `render`. If a
     * pmm_alloc() then fails and we return, that aliasing survives: two slots
     * below E.numrows name the same two frames, and editor_cleanup()'s
     * per-row editor_free_row() hands each of them to pmm_free() TWICE.
     *
     * pmm_free() has a double-free guard (pmm.c:963) that detects the second
     * free and returns WITHOUT freeing, so this does not become frame
     * aliasing -- credit where due. What it does instead, measured on the
     * unfixed kernel: the refused frees permanently lose 2 frames per failed
     * insert, and the surviving rows are corrupted -- the row that was at
     * `at` reads back as NULL, because the failed slot's pointers were
     * written over it. Editing a file after a single OOM hiccup silently
     * destroys a line of the user's text.
     *
     * The failing insert is the one that matters: Enter pressed mid-file
     * (editor_process_keypress, at = E.cy + E.rowoff + 1 < E.numrows) is the
     * only caller with a non-empty shift loop -- the other three append at
     * E.numrows, where the loop body never runs and no alias exists. So the
     * append callers hid this for as long as they were the ones being tested.
     *
     * Allocating first means a failure returns with E.rows completely
     * untouched: no shift to unwind, no partial row, nothing for cleanup to
     * see. Do not "tidy" this back into shift-then-allocate. */
    char *new_chars = (char*)editor_row_alloc();
    if (!new_chars) {
        editor_set_status_message("Out of memory");
        return;
    }

    char *new_render = (char*)editor_row_alloc();
    if (!new_render) {
        pmm_free((uint32_t)new_chars);
        editor_set_status_message("Out of memory");
        return;
    }

    for (size_t i = 0; i < len; i++) {
        new_chars[i] = s[i];
    }
    new_chars[len] = '\0';

    /* Past this point nothing can fail, so the array is safe to disturb. */
    for (int i = E.numrows; i > at; i--) {
        E.rows[i] = E.rows[i - 1];
    }

    E.rows[at].size = len;
    E.rows[at].chars = new_chars;
    E.rows[at].render = new_render;

    editor_update_row(&E.rows[at]);
    E.numrows++;
    E.dirty = true;
}

static void editor_free_row(erow *row) {
    if (row->chars) pmm_free((uint32_t)row->chars);
    if (row->render) pmm_free((uint32_t)row->render);
}

static void editor_del_row(int at) {
    if (at < 0 || at >= E.numrows) return;

    editor_free_row(&E.rows[at]);

    /* Shift rows up */
    for (int i = at; i < E.numrows - 1; i++) {
        E.rows[i] = E.rows[i + 1];
    }

    E.numrows--;

    /* Clear the vacated slot. The shift leaves E.rows[E.numrows] holding a
     * duplicate of the row now at E.numrows - 1 -- same chars/render
     * pointers. It is out of range today, so nothing frees it twice, but that
     * safety rests entirely on every future loop bound staying strictly below
     * E.numrows. Zeroing costs nothing and makes a hypothetical <= bound a
     * no-op free instead of a double free. */
    E.rows[E.numrows].chars = NULL;
    E.rows[E.numrows].render = NULL;
    E.rows[E.numrows].size = 0;
    E.rows[E.numrows].rsize = 0;

    E.dirty = true;
}

static void editor_row_insert_char(erow *row, int at, char c) {
    if (at < 0 || at > row->size) at = row->size;
    if (row->size >= 4095) return; /* Limit line length */

    /* Shift characters right */
    for (int i = row->size; i > at; i--) {
        row->chars[i] = row->chars[i - 1];
    }

    row->chars[at] = c;
    row->size++;
    row->chars[row->size] = '\0';

    editor_update_row(row);
    E.dirty = true;
}

static void editor_row_del_char(erow *row, int at) {
    if (at < 0 || at >= row->size) return;

    /* Shift characters left */
    for (int i = at; i < row->size - 1; i++) {
        row->chars[i] = row->chars[i + 1];
    }

    row->size--;
    row->chars[row->size] = '\0';

    editor_update_row(row);
    E.dirty = true;
}

static void editor_row_append_string(erow *row, const char *s, size_t len) {
    if (row->size + len >= 4096) return;

    for (size_t i = 0; i < len; i++) {
        row->chars[row->size + i] = s[i];
    }

    row->size += len;
    row->chars[row->size] = '\0';

    editor_update_row(row);
    E.dirty = true;
}

/*=============================================================================
 * EDITOR OPERATIONS
 *=============================================================================*/

static void editor_insert_char(char c) {
    int filerow = E.cy + E.rowoff;

    /* Add empty rows until we reach cursor */
    while (E.numrows <= filerow) {
        int before = E.numrows;
        editor_insert_row(E.numrows, "", 0);
        if (E.numrows == before) return; /* Row limit or out of memory */
    }

    editor_row_insert_char(&E.rows[filerow], E.cx + E.coloff, c);
    E.cx++;
}

static void editor_insert_newline(void) {
    if (E.cy + E.rowoff >= E.numrows) {
        editor_insert_row(E.numrows, "", 0);
    } else {
        erow *row = &E.rows[E.cy + E.rowoff];
        int split = E.cx + E.coloff;
        if (split > row->size) split = row->size;
        if (split < 0) split = 0;
        editor_insert_row(E.cy + E.rowoff + 1,
                         row->chars + split,
                         row->size - split);

        row = &E.rows[E.cy + E.rowoff];
        row->size = split;
        row->chars[row->size] = '\0';
        editor_update_row(row);
    }

    E.cy++;
    E.cx = 0;
    E.coloff = 0;
    if (E.cy >= E.screenrows) {
        E.rowoff += E.cy - (E.screenrows - 1);
        E.cy = E.screenrows - 1;
    }
}

static void editor_del_char(void) {
    int filerow = E.cy + E.rowoff;
    int filecol = E.cx + E.coloff;

    if (filerow >= E.numrows) return;
    if (filecol == 0 && filerow == 0) return;

    erow *row = &E.rows[filerow];

    if (filecol > 0) {
        editor_row_del_char(row, filecol - 1);
        E.cx--;
    } else {
        /* Join with previous line */
        E.cx = E.rows[filerow - 1].size;
        editor_row_append_string(&E.rows[filerow - 1], row->chars, row->size);
        editor_del_row(filerow);
        E.cy--;
    }
}

/*=============================================================================
 * FILE I/O
 *=============================================================================*/

void editor_open(const char *filename) {
    /* Store filename */
    size_t len = strlen(filename);
    E.filename = (char*)pmm_alloc();
    if (!E.filename) return;

    /* Clamp ONCE, then use the clamped length for both the copy and the
     * terminator. Previously the loop clamped at 4095 but the terminator wrote
     * E.filename[len] with the UNCLAMPED len -- a 5000-byte name would have
     * written a zero 904 bytes past this page. Not reachable today (cmd_edit
     * is the only caller and resolve_path bounds it by MAX_PATH == 256), which
     * is precisely why it is worth fixing now rather than when a second caller
     * makes it reachable. */
    if (len > 4095) {
        len = 4095;
    }
    for (size_t i = 0; i < len; i++) {
        E.filename[i] = filename[i];
    }
    E.filename[len] = '\0';

    /*=========================================================================
     * SECURITY FIX (AUDIT 5B): File Size Validation Before Buffer Read
     *=========================================================================
     * VULNERABILITY: Missing Buffer Overflow Protection
     *
     * OLD CODE (VULNERABLE):
     * - Opens file without checking size
     * - Calls ramfs_read() with buffer size limit
     * - Relies on ramfs_read() to truncate (implicit trust)
     *
     * PROBLEM: Defense-in-depth violation
     * - No explicit size validation before buffer operation
     * - If ramfs_read() has a bug, buffer overflow occurs
     * - Attacker can craft large file to overflow stack/heap
     * - Memory corruption, potential code execution
     *
     * ATTACK SCENARIO:
     * 1. Attacker gains write access to filesystem (elevated privileges)
     * 2. Creates malicious file: /tmp/exploit.txt (size = 100KB)
     * 3. User runs: edit /tmp/exploit.txt
     * 4. Editor tries to read 100KB into 64KB buffer
     * 5. If ramfs_read() fails to enforce limit: buffer overflow
     * 6. Stack smashing, return address overwrite, code execution
     *
     * PRODUCTION FAILURE MODES:
     * - Corrupted filesystem (bit flip increases file size metadata)
     * - Bug in ramfs_read() size limiting logic
     * - Future code changes remove ramfs_read() bounds check
     *
     * FIX: Explicit Size Validation (Defense-in-Depth)
     * STEP 1: Get file metadata using ramfs_find() BEFORE opening
     * STEP 2: Check if file->size exceeds FILE_BUFFER_SIZE
     * STEP 3: Reject files that are too large (fail-safe)
     * STEP 4: Only proceed with open/read if size is safe
     *
     * WHY THIS IS NECESSARY:
     * - Defense-in-depth: Don't trust single layer (ramfs_read())
     * - Fail-fast: Detect problem before memory access
     * - User feedback: Show meaningful error message
     * - Security: Explicit validation prevents silent truncation bugs
     *
     * RATIONALE FOR FILE_BUFFER_SIZE:
     * - 64KB is reasonable for text editor (line 18)
     * - Larger files should use streaming editor or pagination
     * - This limit prevents memory exhaustion and buffer overflows
     *=======================================================================*/

    /* STEP 1: Get file metadata to check size */
    ramfs_node_t* file_node = ramfs_find(filename);
    if (file_node == NULL) {
        /* File doesn't exist - treat as new file */
        editor_set_status_message("New file");
        return;
    }

    /* STEP 2: Validate file size BEFORE attempting to read */
    if (file_node->size >= FILE_BUFFER_SIZE) {
        /* File too large for editor buffer - reject */
        editor_set_status_message("Error: File too large (max 64KB)");
        return;
    }

    /* STEP 3: Size check passed - safe to proceed with open/read */
    int fd = ramfs_open(filename, RAMFS_FLAG_READ);
    if (fd < 0) {
        /* Open failed (permissions, etc.) */
        editor_set_status_message("Error: Cannot open file");
        return;
    }

    /* STEP 4: Read file into buffer (now guaranteed to fit) */
    int bytes_read = ramfs_read(fd, file_buffer, FILE_BUFFER_SIZE - 1);
    ramfs_close(fd);

    if (bytes_read < 0) {
        editor_set_status_message("Error reading file");
        return;
    }

    file_buffer[bytes_read] = '\0';

    /* Parse into lines */
    int line_start = 0;
    for (int i = 0; i <= bytes_read; i++) {
        if (i == bytes_read || file_buffer[i] == '\n') {
            int line_len = i - line_start;
            if (line_len > 0 && file_buffer[i - 1] == '\r') line_len--;

            editor_insert_row(E.numrows, file_buffer + line_start, line_len);
            line_start = i + 1;
        }
    }

    E.dirty = false;
    editor_set_status_message("Loaded file");
}

int editor_save(void) {
    if (!E.filename) {
        editor_set_status_message("No filename");
        return -1;
    }

    /* Build file content */
    int total_len = 0;
    for (int i = 0; i < E.numrows; i++) {
        total_len += E.rows[i].size + 1; /* +1 for newline */
    }

    if (total_len >= FILE_BUFFER_SIZE) {
        editor_set_status_message("File too large");
        return -1;
    }

    int pos = 0;
    for (int i = 0; i < E.numrows; i++) {
        for (int j = 0; j < E.rows[i].size; j++) {
            file_buffer[pos++] = E.rows[i].chars[j];
        }
        file_buffer[pos++] = '\n';
    }

    /* Write to file */
    int fd = ramfs_open(E.filename, RAMFS_FLAG_WRITE);
    if (fd < 0) {
        editor_set_status_message("Error opening file for write");
        return -1;
    }

    int written = ramfs_write(fd, file_buffer, pos);
    ramfs_close(fd);

    if (written != pos) {
        editor_set_status_message("Error writing file");
        return -1;
    }

    E.dirty = false;
    editor_set_status_message("File saved");
    return 0;
}

/*=============================================================================
 * SCREEN RENDERING
 *=============================================================================*/

static void editor_scroll(void) {
    /* Adjust scroll offsets based on cursor position */
    if (E.cy < 0) E.cy = 0;
    if (E.cx < 0) E.cx = 0;

    /* Vertical scrolling */
    if (E.cy < E.rowoff) {
        E.rowoff = E.cy;
    }
    if (E.cy >= E.rowoff + E.screenrows) {
        E.rowoff = E.cy - E.screenrows + 1;
    }

    /* Horizontal scrolling */
    if (E.cx < E.coloff) {
        E.coloff = E.cx;
    }
    if (E.cx >= E.coloff + E.screencols) {
        E.coloff = E.cx - E.screencols + 1;
    }
}

static void editor_draw_rows(void) {
    for (int y = 0; y < E.screenrows; y++) {
        int filerow = y + E.rowoff;

        if (filerow >= E.numrows) {
            /* Empty line */
            console_putchar_at('~', 0, y);
            for (int x = 1; x < E.screencols; x++) {
                console_putchar_at(' ', x, y);
            }
        } else {
            /* Draw line */
            erow *row = &E.rows[filerow];
            int len = row->rsize - E.coloff;
            if (len < 0) len = 0;
            if (len > E.screencols) len = E.screencols;

            for (int x = 0; x < len; x++) {
                console_putchar_at(row->render[E.coloff + x], x, y);
            }
            for (int x = len; x < E.screencols; x++) {
                console_putchar_at(' ', x, y);
            }
        }
    }
}

static void editor_draw_status_bar(void) {
    /* Reverse video for status bar */
    char status[81];
    int len = 0;

    /* Filename */
    const char *name = E.filename ? E.filename : "[No Name]";
    for (int i = 0; name[i] && len < 20; i++) {
        status[len++] = name[i];
    }

    /* Modified indicator */
    if (E.dirty) {
        status[len++] = ' ';
        status[len++] = '*';
    }

    /* Pad to screen width */
    while (len < E.screencols) {
        status[len++] = ' ';
    }
    status[E.screencols] = '\0';

    for (int i = 0; i < E.screencols; i++) {
        console_putchar_at(status[i], i, E.screenrows);
    }

    /* Message bar - show command prompt if in command mode */
    if (E.command_mode) {
        /* Show command prompt */
        console_putchar_at(':', 0, E.screenrows + 1);
        int cmdlen = E.command_len;
        if (cmdlen > E.screencols - 1) cmdlen = E.screencols - 1;

        for (int i = 0; i < cmdlen; i++) {
            console_putchar_at(E.command_buf[i], i + 1, E.screenrows + 1);
        }
        for (int i = cmdlen + 1; i < E.screencols; i++) {
            console_putchar_at(' ', i, E.screenrows + 1);
        }
    } else if (E.statusmsg[0] && (get_timer_ticks() - E.statusmsg_time) < 500) {
        /* Show status message */
        int msglen = strlen(E.statusmsg);
        if (msglen > E.screencols) msglen = E.screencols;

        for (int i = 0; i < msglen; i++) {
            console_putchar_at(E.statusmsg[i], i, E.screenrows + 1);
        }
        for (int i = msglen; i < E.screencols; i++) {
            console_putchar_at(' ', i, E.screenrows + 1);
        }
    } else {
        /* Clear message bar */
        for (int i = 0; i < E.screencols; i++) {
            console_putchar_at(' ', i, E.screenrows + 1);
        }
    }
}

static void editor_refresh_screen(void) {
    editor_scroll();
    editor_draw_rows();
    editor_draw_status_bar();

    /* Position cursor */
    console_set_cursor_pos(E.cx, E.cy);
}

/*=============================================================================
 * COMMAND MODE (VI-STYLE)
 *=============================================================================*/

static bool editor_execute_command(void) {
    /* Execute vi-style command and return true to continue, false to quit */
    const char *cmd = E.command_buf;

    /* :w - save file */
    if (strcmp(cmd, "w") == 0) {
        if (editor_save() == 0) {
            editor_set_status_message("File saved");
        }
        return true;
    }

    /* :q - quit (with unsaved warning) */
    if (strcmp(cmd, "q") == 0) {
        if (E.dirty) {
            editor_set_status_message("Unsaved changes! Use :q! to force quit or :wq to save");
            return true;
        }
        return false; /* Exit */
    }

    /* :q! - force quit without saving */
    if (strcmp(cmd, "q!") == 0) {
        return false; /* Exit */
    }

    /* :wq or :x - save and quit */
    if (strcmp(cmd, "wq") == 0 || strcmp(cmd, "x") == 0) {
        if (editor_save() == 0) {
            return false; /* Exit after saving */
        }
        return true; /* Stay if save failed */
    }

    /* Unknown command */
    editor_set_status_message("Unknown command");
    return true;
}

/*=============================================================================
 * INPUT HANDLING
 *=============================================================================*/

static void editor_move_cursor(unsigned char key) {
    erow *row = (E.cy + E.rowoff < E.numrows) ? &E.rows[E.cy + E.rowoff] : NULL;

    switch (key) {
        case KEY_UP:
            if (E.cy > 0) E.cy--;
            else if (E.rowoff > 0) E.rowoff--;
            break;

        case KEY_DOWN:
            if (E.cy + E.rowoff < E.numrows - 1) {
                if (E.cy < E.screenrows - 1) E.cy++;
                else E.rowoff++;
            }
            break;

        case KEY_LEFT:
            if (E.cx > 0) {
                E.cx--;
            } else if (E.cy + E.rowoff > 0) {
                /* Move to end of previous line */
                if (E.cy > 0) E.cy--;
                else E.rowoff--;

                row = &E.rows[E.cy + E.rowoff];
                E.cx = row->size;
            }
            break;

        case KEY_RIGHT:
            if (row && E.cx + E.coloff < row->size) {
                E.cx++;
            } else if (row && E.cx + E.coloff == row->size) {
                /* Move to start of next line */
                if (E.cy + E.rowoff < E.numrows - 1) {
                    if (E.cy < E.screenrows - 1) E.cy++;
                    else E.rowoff++;
                    E.cx = 0;
                    E.coloff = 0;
                }
            }
            break;
    }

    /* Clamp cursor to line length */
    row = (E.cy + E.rowoff < E.numrows) ? &E.rows[E.cy + E.rowoff] : NULL;
    int rowlen = row ? row->size : 0;
    if (E.cx + E.coloff > rowlen) {
        E.cx = rowlen - E.coloff;
        if (E.cx < 0) E.cx = 0;
    }
}

static bool editor_process_keypress(void) {
    if (!keyboard_has_data()) return true;

    unsigned char c = keyboard_getchar_nonblock();

    /* Handle command mode input */
    if (E.command_mode) {
        /* Enter - execute command */
        if (c == '\n' || c == '\r') {
            E.command_buf[E.command_len] = '\0';
            E.command_mode = false;
            bool result = editor_execute_command();
            E.command_len = 0;
            E.command_buf[0] = '\0';
            return result;
        }

        /* Escape - cancel command */
        if (c == 27) {
            E.command_mode = false;
            E.command_len = 0;
            E.command_buf[0] = '\0';
            editor_set_status_message("Command cancelled");
            return true;
        }

        /* Backspace */
        if (c == '\b' || c == 127) {
            if (E.command_len > 0) {
                E.command_len--;
                E.command_buf[E.command_len] = '\0';
            }
            return true;
        }

        /* Add character to command buffer */
        if (c >= 32 && c < 127 && E.command_len < 78) {
            E.command_buf[E.command_len++] = c;
            E.command_buf[E.command_len] = '\0';
        }

        return true;
    }

    /* Normal mode - check for colon to enter command mode */
    if (c == ':') {
        E.command_mode = true;
        E.command_len = 0;
        E.command_buf[0] = '\0';
        return true;
    }

    /* Movement keys (arrow keys) */
    if (c == KEY_UP || c == KEY_DOWN || c == KEY_LEFT || c == KEY_RIGHT) {
        editor_move_cursor(c);
        return true;
    }

    /* Backspace */
    if (c == '\b' || c == 127) {
        editor_del_char();
        return true;
    }

    /* Enter */
    if (c == '\n' || c == '\r') {
        editor_insert_newline();
        return true;
    }

    /* Regular characters */
    if (c >= 32 && c < 127) {
        editor_insert_char(c);
    }

    return true;
}

/*=============================================================================
 * INITIALIZATION
 *=============================================================================*/

void editor_init(void) {
    E.cx = 0;
    E.cy = 0;
    E.rx = 0;
    E.rowoff = 0;
    E.coloff = 0;
    E.screenrows = 22; /* Leave room for status */
    E.screencols = 80;
    E.numrows = 0;

    /*=========================================================================
     * SECURITY: PMM Allocation Failure Check
     * CRITICAL: If pmm_alloc() fails (returns NULL), accessing E.rows later
     * will cause a page fault at address 0x0, potentially crashing the editor
     * or corrupting kernel memory.
     *=========================================================================*/
    E.rows = (erow*)pmm_alloc();
    if (!E.rows) {
        // Cannot initialize editor without memory for row storage
        // Set a safe state and return (editor won't function, but won't crash)
        E.rows = NULL;
        E.numrows = 0;
        /* Clear filename HERE too. This early return skips the
         * E.filename = NULL below, so a failed init would leave the previous
         * session's pointer in place; the following editor_open() overwrites
         * it with a fresh page and that frame is lost. Cheap to get right, and
         * it keeps every exit from this function leaving E in one known
         * state. */
        E.filename = NULL;
        kprintf("EDITOR: CRITICAL - Failed to allocate memory for rows\n");
        return;  // Safe degradation - editor won't work, but kernel continues
    }

    E.dirty = false;
    E.filename = NULL;
    E.statusmsg[0] = '\0';
    E.statusmsg_time = 0;
    E.command_mode = false;
    E.command_buf[0] = '\0';
    E.command_len = 0;
}

void editor_run(void) {
    editor_set_status_message(":w = save | :q = quit | :wq = save & quit | :q! = force quit");

    while (1) {
        editor_refresh_screen();

        if (!editor_process_keypress()) {
            break; /* User quit */
        }
    }
}


void editor_cleanup(void) {
    /* Free all rows */
    for (int i = 0; i < E.numrows; i++) {
        editor_free_row(&E.rows[i]);
    }

    if (E.rows) pmm_free((uint32_t)E.rows);
    if (E.filename) pmm_free((uint32_t)E.filename);

    /* Leave E in a state where a second cleanup is a no-op rather than a
     * double free. cmd_edit pairs one init with one cleanup today, so this is
     * belt-and-braces -- but every other defect fixed in this file came from a
     * pointer outliving the frame it named. */
    E.rows = NULL;
    E.filename = NULL;
    E.numrows = 0;
}

#ifdef TINYOS_FAULT_INJECT
/* verify-editor-rowfail.sh only.
 *
 * WHAT IS BEING ASSERTED, and why it is the free-frame count.
 *
 * The bug was: editor_insert_row() shifted E.rows[at] <- E.rows[at-1] BEFORE
 * allocating, so a failed pmm_alloc() returned with slots `at` and `at + 1`
 * holding identical chars/render pointers. Both sit below E.numrows, so
 * editor_cleanup()'s per-row editor_free_row() handed the SAME frames to
 * pmm_free() twice.
 *
 * pmm_free() catches that (pmm.c:963) and REFUSES the second free, so the
 * outcome is not frame aliasing. Measured on the unfixed kernel it is: 2
 * frames permanently lost per failed insert (the refused frees never return
 * them), plus corruption of a surviving row. Do not expect free_frames to
 * RISE -- the guard is why it falls instead. That prediction was wrong once
 * already; the counter direction below is what the hardware actually did.
 *
 * The test brackets each arm with pmm_free_frames() and requires the count to
 * return EXACTLY to baseline:
 *
 *   too LOW  after  -> frames allocated and never freed (this bug, or a leak)
 *   too HIGH after  -> freed more often than allocated, on a kernel whose
 *                      double-free guard was removed or bypassed
 *   equal           -> the freed set is precisely the allocated set
 *
 * Exact equality BOTH ways is the point; a one-sided check passes against
 * whichever direction it does not test.
 *
 * The mid-file insert is the load-bearing case. Appending at E.numrows leaves
 * the shift loop empty, so it never aliased and would pass against the
 * unfixed kernel -- that is precisely how this survived: the other three
 * callers of editor_insert_row all append. Every arm below inserts at index 1
 * of a 3-row buffer, where the shift loop actually runs. */
void editor_rowtest(void) {
    uint32_t base, after;
    int failures = 0;

    stream_printf(get_current_streams(), "[ROWTEST] editor_insert_row failure-path check\n");

    /* --- Arm 1: POSITIVE CONTROL -------------------------------------
     * No injection. Proves the sequence really allocates and frees -- an
     * assertion that only ever runs against a no-op path is not evidence.
     * If this arm does not move the counter during the run, the later arms
     * are measuring nothing. */
    base = pmm_free_frames();
    editor_init();
    editor_insert_row(0, "alpha", 5);
    editor_insert_row(1, "beta", 4);
    editor_insert_row(2, "gamma", 5);
    {
        uint32_t peak = pmm_free_frames();
        if (peak >= base) {
            stream_printf(get_current_streams(),
                "[ROWTEST] arm1 CONTROL-DEAD: 3 rows allocated nothing (%u -> %u)\n",
                base, peak);
            failures++;
        } else {
            stream_printf(get_current_streams(),
                "[ROWTEST] arm1 control: 3 rows consumed %u frames\n", base - peak);
        }
    }
    editor_insert_row(1, "delta", 5);   /* mid-file insert, succeeds */
    editor_cleanup();
    after = pmm_free_frames();
    if (after != base) {
        stream_printf(get_current_streams(),
            "[ROWTEST] arm1 FAIL: %u -> %u (%s)\n", base, after,
            after > base ? "double free" : "leak");
        failures++;
    } else {
        stream_printf(get_current_streams(), "[ROWTEST] arm1 PASS: balanced at %u\n", after);
    }

    /* --- Arm 2: `chars` alloc fails on a mid-file insert --------------
     * Unfixed kernel: the shift has already happened, E.rows[1].render
     * aliases E.rows[2].render, and cleanup frees that frame twice ->
     * after > base. */
    base = pmm_free_frames();
    editor_init();
    editor_insert_row(0, "alpha", 5);
    editor_insert_row(1, "beta", 4);
    editor_insert_row(2, "gamma", 5);
    editor_fail_next_alloc(1);
    editor_insert_row(1, "should-fail", 11);
    editor_cleanup();
    after = pmm_free_frames();
    if (after != base) {
        stream_printf(get_current_streams(),
            "[ROWTEST] arm2 FAIL: chars-alloc failure %u -> %u (%s)\n", base, after,
            after > base ? "DOUBLE FREE" : "leak");
        failures++;
    } else {
        stream_printf(get_current_streams(), "[ROWTEST] arm2 PASS: balanced at %u\n", after);
    }

    /* --- Arm 3: `render` alloc fails on a mid-file insert -------------
     * A separate bug on the unfixed kernel, not a repeat of arm 2: there the
     * old code freed `chars` explicitly but left the stale pointer in the
     * slot, so cleanup double-freed BOTH chars and the aliased render. */
    base = pmm_free_frames();
    editor_init();
    editor_insert_row(0, "alpha", 5);
    editor_insert_row(1, "beta", 4);
    editor_insert_row(2, "gamma", 5);
    editor_fail_next_alloc(2);
    editor_insert_row(1, "should-fail", 11);
    editor_cleanup();
    after = pmm_free_frames();
    if (after != base) {
        stream_printf(get_current_streams(),
            "[ROWTEST] arm3 FAIL: render-alloc failure %u -> %u (%s)\n", base, after,
            after > base ? "DOUBLE FREE" : "leak");
        failures++;
    } else {
        stream_printf(get_current_streams(), "[ROWTEST] arm3 PASS: balanced at %u\n", after);
    }

    /* --- Arm 4: the failed insert must not corrupt the surviving rows --
     * Balanced frame accounting alone would also be satisfied by a failure
     * path that dropped or mangled existing rows. Allocating before shifting
     * means the array is untouched, so row 1 must still read "beta". */
    editor_init();
    editor_insert_row(0, "alpha", 5);
    editor_insert_row(1, "beta", 4);
    editor_insert_row(2, "gamma", 5);
    editor_fail_next_alloc(1);
    editor_insert_row(1, "should-fail", 11);
    if (E.numrows != 3 ||
        !E.rows[1].chars || strcmp(E.rows[1].chars, "beta") != 0) {
        stream_printf(get_current_streams(),
            "[ROWTEST] arm4 FAIL: rows disturbed by failed insert (numrows=%d row1=%s)\n",
            E.numrows, E.rows[1].chars ? E.rows[1].chars : "(null)");
        failures++;
    } else {
        stream_printf(get_current_streams(),
            "[ROWTEST] arm4 PASS: 3 rows intact, row1 unchanged\n");
    }
    editor_cleanup();

    stream_printf(get_current_streams(), "[ROWTEST] VERDICT: %s (%d failure(s))\n",
                  failures == 0 ? "PASS" : "FAIL", failures);
}
#endif
