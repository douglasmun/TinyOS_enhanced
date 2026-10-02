/* Fuzz target: the kernel shell's command-line parsers -- everything a typed
 * line passes through in shell.c before a command runs.
 *
 *   env_expand()          $VAR / ${VAR} / $$ into the 512-byte expanded_cmd
 *   parse_redirections()  > >> < split out of the expanded line
 *   parse_pipeline()      | split into at most MAX_PIPE_STAGES stages
 *   canonicalize_path()   what validate_redir_filename() trusts
 *   env_find_in_path()    PATH lookup for a bare command name
 *   pipe_write/pipe_read  the 4 KB ring a pipeline's stages share
 *
 * Any user reaches these: `kshell` is ungated, and the variables and aliases
 * the expansion reads are the user's own (`set`, `alias`).
 *
 * Byte 0 picks the mode; the rest is the line (NUL-terminated copy, capped at
 * what the caller can hand over). Oracles per mode are in the comments below.
 * ASan covers the fixed-size buffers each parser writes into. */
#include "shell_redir.c"
#include "env.c"

#include <stdlib.h>
#include "fuzz_common.h"

static void die(int line) {
    char msg[32] = "shell: oracle line ";
    int n = 19;
    char d[8];
    int k = 0;
    do { d[k++] = (char)('0' + line % 10); line /= 10; } while (line);
    while (k) msg[n++] = d[--k];
    msg[n] = 0;
    fuzz_note(msg);
    abort();
}
#define abort() die(__LINE__)

/* util.h has no strnlen and shadows <string.h>. */
static size_t strnlen(const char* s, size_t max) {
    size_t n = 0;
    while (n < max && s[n]) n++;
    return n;
}

static task_t task_self;
static env_state_t env_page;

task_t* scheduler_get_current_task(void) { return &task_self; }

/* The pipe's wait-queue frame: 0 puts pipe_init() in its non-blocking
 * fallback, the only mode a single-threaded harness can drive. env.c's
 * (env_state_t*)pmm_alloc() is rewritten to the fuzz page pool, not this. */
uint32_t pmm_alloc(void) { return 0; }

/* canonicalize_path() is in shell_fileops.c, which drags the whole file-command
 * layer with it. It reads only current_dir, so build.sh cuts the function out
 * of the real source into canonicalize_path.inc rather than linking the file. */
static char current_dir[MAX_PATH] = "/";
#include "canonicalize_path.inc"

/* ---- oracles ---- */

/* A canonical path: absolute, no empty / "." / ".." component, no trailing
 * slash except "/" itself, and a fixed point of canonicalisation. */
static void check_canonical(const char* c, size_t cap) {
    size_t n = strnlen(c, cap);
    if (n == cap || c[0] != '/') abort();
    if (n > 1 && c[n - 1] == '/') abort();
    const char* p = c + 1;
    while (n > 1 && *p) {
        const char* e = strchr(p, '/');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l == 0) abort();
        if (l == 1 && p[0] == '.') abort();
        if (l == 2 && p[0] == '.' && p[1] == '.') abort();
        p += l + (e ? 1 : 0);
    }
    char again[256];
    if (canonicalize_path(c, again, sizeof(again)) != 0) abort();
    if (strcmp(again, c)) abort();
}

static void mode_redirect(const char* line) {
    cmd_context_t ctx;
    memset(&ctx, 0xA5, sizeof(ctx));
    if (parse_redirections(line, &ctx) != 0) return;
    size_t cl = strnlen(ctx.command, sizeof(ctx.command));
    if (cl == sizeof(ctx.command)) abort();
    if (strchr(ctx.command, '>') || strchr(ctx.command, '<')) abort();
    if (cl && ctx.command[cl - 1] == ' ') abort();
    if (ctx.redir_count < 0 || ctx.redir_count > MAX_REDIRECTS) abort();
    for (int i = 0; i < ctx.redir_count; i++) {
        redir_t* r = &ctx.redirects[i];
        if (!r->active || (r->type != REDIR_OUTPUT && r->type != REDIR_APPEND)) abort();
        if (!validate_redir_filename(r->filename)) abort();
    }
    if (ctx.has_input_redir && !validate_redir_filename(ctx.input_file)) abort();
}

static void mode_pipeline(const char* line) {
    pipeline_t pl;
    memset(&pl, 0xA5, sizeof(pl));
    if (parse_pipeline(line, &pl) != 0) return;
    if (pl.cmd_count < 1 || pl.cmd_count > MAX_PIPE_STAGES) abort();
    for (int i = 0; i < pl.cmd_count; i++) {
        const char* c = pl.commands[i];
        size_t l = strnlen(c, sizeof(pl.commands[i]));
        if (l == 0 || l == sizeof(pl.commands[i])) abort();
        if (strchr(c, '|') || c[0] == ' ' || c[l - 1] == ' ') abort();
    }
}

/* env_expand into an exact-size heap buffer, so ASan sees the first byte past
 * it. Then: success means the whole input was consumed and the output is
 * terminated inside the buffer. */
static void mode_expand(const char* line, size_t cap) {
    char* out = malloc(cap);
    int r = env_expand(line, out, cap);
    if (r == 0 && strnlen(out, cap) == cap) abort();
    free(out);
}

static void mode_canon(const char* line, size_t cwd_len) {
    /* First bytes become the cwd, as `cd` would leave it. */
    size_t l = strlen(line);
    if (cwd_len > l) cwd_len = l;
    if (cwd_len >= MAX_PATH) cwd_len = MAX_PATH - 1;
    current_dir[0] = '/';
    if (cwd_len) {
        char cwd[MAX_PATH];
        if (canonicalize_path(line, cwd, sizeof(cwd)) == 0 && strlen(cwd) <= cwd_len)
            memcpy(current_dir, cwd, strlen(cwd) + 1);
        line += cwd_len;
    } else {
        current_dir[1] = 0;
    }
    char out[256];
    if (canonicalize_path(line, out, sizeof(out)) == 0) check_canonical(out, sizeof(out));
    for (size_t cap = 2; cap < 16; cap++) {
        char* small = malloc(cap);
        if (canonicalize_path(line, small, cap) == 0) check_canonical(small, cap);
        free(small);
    }
    validate_redir_filename(line);
}

/* PATH and aliases come from the user's own `set` / `alias`. */
static void mode_path(const char* line) {
    const char* sep = strchr(line, ' ');
    char path[ENV_MAX_VALUE_LEN];
    size_t pl = sep ? (size_t)(sep - line) : strlen(line);
    if (pl >= sizeof(path)) pl = sizeof(path) - 1;
    memcpy(path, line, pl);
    path[pl] = 0;
    env_set("PATH", path);
    const char* cmd = sep ? sep + 1 : "";
    for (size_t cap = 1; cap < 300; cap += 37) {
        char* out = malloc(cap);
        if (env_find_in_path(cmd, out, cap) == 0 && strnlen(out, cap) == cap) abort();
        free(out);
    }
    alias_set(path, cmd);
    char a[ALIAS_MAX_CMD_LEN];
    if (alias_get(path, a, sizeof(a)) && strnlen(a, sizeof(a)) == sizeof(a)) abort();
    env_unset("PATH");
    alias_unset(path);
}

/* Pipe ring against a FIFO model: every byte comes out once, in order. */
static void mode_pipe(const uint8_t* d, size_t len) {
    static pipe_buffer_t p;
    static char model[1 << 16], buf[PIPE_BUFFER_SIZE * 2];
    size_t head = 0, tail = 0;
    pipe_init(&p);
    for (size_t i = 0; i + 1 < len; i += 2) {
        size_t n = (size_t)d[i + 1] * 37;
        if (n > sizeof(buf)) n = sizeof(buf);
        if (d[i] & 1) {
            memset(buf, (char)i, n);
            int w = pipe_write(&p, buf, n);
            if (w < 0 || (size_t)w > n) abort();
            if (tail + (size_t)w > sizeof(model)) break;
            memcpy(model + tail, buf, (size_t)w);
            tail += (size_t)w;
        } else {
            int r = pipe_read(&p, buf, n);
            if (r < 0 || (size_t)r > n || (size_t)r > tail - head) abort();
            if (memcmp(buf, model + head, (size_t)r)) abort();
            head += (size_t)r;
        }
        if (pipe_available(&p) != tail - head) abort();
        if (tail - head > PIPE_BUFFER_SIZE) abort();
    }
    pipe_destroy(&p);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len) {
    if (len < 2) return 0;
    fuzz_reset();
    memset(&task_self, 0, sizeof(task_self));
    memset(&env_page, 0, sizeof(env_page));
    task_self.env = &env_page;
    env_set("HOME", "/home");
    env_set("LONG", "0123456789012345678901234567890123456789012345678901234567890");
    alias_set("ll", "ls -l");

    uint8_t mode = data[0], arg = data[1];
    data += 2;
    len -= 2;
    if (mode % 6 == 5) {
        mode_pipe(data, len);
        return 0;
    }
    /* The shell copies the typed line into SHELL_BUFFER_SIZE and env_expand
     * writes ENV_MAX_EXPAND_LEN; nothing longer reaches the parsers. */
    size_t cap = mode % 6 == 0 ? 256 : ENV_MAX_EXPAND_LEN;
    size_t n = len < cap - 1 ? len : cap - 1;
    char* line = malloc(n + 1);
    memcpy(line, data, n);
    line[n] = 0;
    switch (mode % 6) {
    case 0: mode_expand(line, (size_t)arg * 3 + 1); break;
    case 1: mode_redirect(line); break;
    case 2: mode_pipeline(line); break;
    case 3: mode_canon(line, arg); break;
    case 4: mode_path(line); break;
    }
    free(line);
    return 0;
}
