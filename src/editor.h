/*=============================================================================
 * editor.h - Simple Text Editor for TinyOS
 *=============================================================================*/
#pragma once

#include <stdint.h>
#include <stdbool.h>

/* Editor configuration */
#define EDITOR_MAX_ROWS 256  /* E.rows is one 4096-byte page: 4096/sizeof(erow) slots */
#define EDITOR_TAB_STOP 4
#define EDITOR_QUIT_TIMES 2

/* Key definitions */
#define CTRL_KEY(k) ((k) & 0x1f)

/* Editor row structure */
typedef struct erow {
    int size;
    int rsize;
    char *chars;
    char *render;
} erow;

/* Editor state */
typedef struct {
    int cx, cy;           /* Cursor position */
    int rx;               /* Rendered x position */
    int rowoff;           /* Row offset for scrolling */
    int coloff;           /* Column offset for scrolling */
    int screenrows;       /* Number of rows visible */
    int screencols;       /* Number of columns visible */
    int numrows;          /* Number of rows in file */
    erow *rows;           /* Array of rows */
    bool dirty;           /* File modified flag */
    char *filename;       /* Current filename */
    char statusmsg[80];   /* Status message */
    uint32_t statusmsg_time; /* When status was set */
    bool command_mode;    /* Vi-style command mode (:) */
    char command_buf[80]; /* Command buffer */
    int command_len;      /* Command buffer length */
} EditorState;

/* Editor functions */
void editor_init(void);
void editor_open(const char *filename);
int editor_save(void);
void editor_run(void);
void editor_cleanup(void);
