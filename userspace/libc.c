/*=============================================================================
 * libc.c - Minimal freestanding C library for TinyOS user programs
 *=============================================================================*/
#include "libc.h"

/*-----------------------------------------------------------------------------
 * Raw syscalls (int 0x80, number in eax, args in ebx/ecx/edx)
 *---------------------------------------------------------------------------*/
int syscall0(int num) {
    int ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(num));
    return ret;
}

int syscall1(int num, uint32_t arg1) {
    int ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(num), "b"(arg1));
    return ret;
}

int syscall3(int num, uint32_t arg1, uint32_t arg2, uint32_t arg3) {
    int ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(num), "b"(arg1), "c"(arg2), "d"(arg3));
    return ret;
}

/*-----------------------------------------------------------------------------
 * Process
 *---------------------------------------------------------------------------*/
void exit(int status) {
    syscall1(SYS_EXIT, (uint32_t)status);
    for (;;) { }
}

int getpid(void) { return syscall0(SYS_GETPID); }
int getuid(void) { return syscall0(SYS_GETUID); }
int getgid(void) { return syscall0(SYS_GETGID); }
void yield(void)  { syscall0(SYS_YIELD); }
int sleep_ms(uint32_t ms) { return syscall1(SYS_SLEEP, ms); }
int waitpid(int pid) { return syscall1(SYS_WAITPID, (uint32_t)pid); }

int spawn(const char* path, char* const* argv) {
    /* syscall3 with an unused third argument: the kernel only extracts the
     * three arg registers and SYS_SPAWN reads two of them. */
    return syscall3(SYS_SPAWN, (uint32_t)(uintptr_t)path,
                    (uint32_t)(uintptr_t)argv, 0);
}

/*-----------------------------------------------------------------------------
 * I/O
 *---------------------------------------------------------------------------*/
int write(int fd, const void* buf, size_t len) {
    return syscall3(SYS_WRITE, (uint32_t)fd, (uint32_t)(uintptr_t)buf,
                    (uint32_t)len);
}

int read(int fd, void* buf, size_t len) {
    return syscall3(SYS_READ, (uint32_t)fd, (uint32_t)(uintptr_t)buf,
                    (uint32_t)len);
}

int open(const char* path, int flags) {
    return syscall3(SYS_OPEN, (uint32_t)(uintptr_t)path, (uint32_t)flags, 0);
}

int close(int fd) {
    return syscall1(SYS_CLOSE, (uint32_t)fd);
}

int readdir(int fd, void* buf, size_t size) {
    return syscall3(SYS_READDIR, (uint32_t)fd, (uint32_t)(uintptr_t)buf,
                    (uint32_t)size);
}

int stat(const char* path, void* buf, size_t size) {
    return syscall3(SYS_STAT, (uint32_t)(uintptr_t)path,
                    (uint32_t)(uintptr_t)buf, (uint32_t)size);
}

int lseek(int fd, int offset, int whence) {
    return syscall3(SYS_LSEEK, (uint32_t)fd, (uint32_t)offset,
                    (uint32_t)whence);
}

int mkdir(const char* path) {
    return syscall1(SYS_MKDIR, (uint32_t)(uintptr_t)path);
}

int rmdir(const char* path) {
    return syscall1(SYS_RMDIR, (uint32_t)(uintptr_t)path);
}

int unlink(const char* path) {
    return syscall1(SYS_UNLINK, (uint32_t)(uintptr_t)path);
}

int getcwd(char* buf, unsigned int size) {
    /* syscall3 with an unused third argument, like spawn: there is no
     * two-argument entry stub. */
    return syscall3(SYS_GETCWD, (uint32_t)(uintptr_t)buf, (uint32_t)size, 0);
}

int chdir(const char* path) {
    return syscall1(SYS_CHDIR, (uint32_t)(uintptr_t)path);
}

int systime(void* buf, size_t size) {
    return syscall3(SYS_TIME, (uint32_t)(uintptr_t)buf, (uint32_t)size, 0);
}

int psinfo(void* buf, size_t size) {
    return syscall3(SYS_PSINFO, (uint32_t)(uintptr_t)buf, (uint32_t)size, 0);
}

int kill(int pid) {
    return syscall1(SYS_KILL, (uint32_t)pid);
}

int chmod(const char* path, unsigned int mode) {
    return syscall3(SYS_CHMOD, (uint32_t)(uintptr_t)path, (uint32_t)mode, 0);
}

/*=============================================================================
 * SYS_ENV wrappers
 *
 * Every op shares one env_record_t. Each wrapper zeroes it before filling the
 * fields that op reads -- the kernel forces NUL termination on the way in, but
 * a record left partly uninitialised here would send this process's own stack
 * bytes across as a variable name.
 *===========================================================================*/
static int env_call(unsigned int op, env_record_t* rec) {
    return syscall3(SYS_ENV, (uint32_t)op, (uint32_t)(uintptr_t)rec,
                    (uint32_t)sizeof(env_record_t));
}

int env_get_var(const char* name, char* value_out, size_t value_size) {
    if (!name || !value_out || value_size == 0) {
        return -ELIBC_EINVAL;
    }

    env_record_t rec;
    memset(&rec, 0, sizeof(rec));
    strncpy(rec.name, name, sizeof(rec.name) - 1);

    int rc = env_call(ENV_OP_GET, &rec);
    if (rc < 0) {
        return rc;
    }

    /* rec.value is NUL-terminated by the kernel, but terminate again after the
     * copy: value_size may be shorter than the field. */
    strncpy(value_out, rec.value, value_size - 1);
    value_out[value_size - 1] = '\0';
    return 0;
}

int env_set_var(const char* name, const char* value) {
    if (!name || !value) {
        return -ELIBC_EINVAL;
    }

    env_record_t rec;
    memset(&rec, 0, sizeof(rec));
    strncpy(rec.name, name, sizeof(rec.name) - 1);
    strncpy(rec.value, value, sizeof(rec.value) - 1);

    return env_call(ENV_OP_SET, &rec);
}

int env_unset_var(const char* name) {
    if (!name) {
        return -ELIBC_EINVAL;
    }

    env_record_t rec;
    memset(&rec, 0, sizeof(rec));
    strncpy(rec.name, name, sizeof(rec.name) - 1);

    return env_call(ENV_OP_UNSET, &rec);
}

int env_export_var(const char* name) {
    if (!name) {
        return -ELIBC_EINVAL;
    }

    env_record_t rec;
    memset(&rec, 0, sizeof(rec));
    strncpy(rec.name, name, sizeof(rec.name) - 1);

    return env_call(ENV_OP_EXPORT, &rec);
}

int env_list(unsigned int index, env_record_t* rec_out) {
    if (!rec_out) {
        return -ELIBC_EINVAL;
    }

    memset(rec_out, 0, sizeof(*rec_out));
    rec_out->index = index;

    return env_call(ENV_OP_LIST, rec_out);
}

int alias_get_cmd(const char* name, char* cmd_out, size_t cmd_size) {
    if (!name || !cmd_out || cmd_size == 0) {
        return -ELIBC_EINVAL;
    }

    env_record_t rec;
    memset(&rec, 0, sizeof(rec));
    strncpy(rec.name, name, sizeof(rec.name) - 1);

    int rc = env_call(ENV_OP_ALIAS_GET, &rec);
    if (rc < 0) {
        return rc;
    }

    strncpy(cmd_out, rec.value, cmd_size - 1);
    cmd_out[cmd_size - 1] = '\0';
    return 0;
}

int alias_set_cmd(const char* name, const char* cmd) {
    if (!name || !cmd) {
        return -ELIBC_EINVAL;
    }

    env_record_t rec;
    memset(&rec, 0, sizeof(rec));
    strncpy(rec.name, name, sizeof(rec.name) - 1);
    strncpy(rec.value, cmd, sizeof(rec.value) - 1);

    return env_call(ENV_OP_ALIAS_SET, &rec);
}

int alias_list_get(unsigned int index, env_record_t* rec_out) {
    if (!rec_out) {
        return -ELIBC_EINVAL;
    }

    memset(rec_out, 0, sizeof(*rec_out));
    rec_out->index = index;

    return env_call(ENV_OP_ALIAS_LIST, rec_out);
}

int redirect(int fd, const char* path, int mode) {
    return syscall3(SYS_REDIRECT, (uint32_t)fd, (uint32_t)(uintptr_t)path,
                    (uint32_t)mode);
}

int pipe_op(int op, int id) {
    return syscall3(SYS_PIPE, (uint32_t)op, (uint32_t)id, 0);
}

int cred(int op, const char* user) {
    return syscall3(SYS_CRED, (uint32_t)op, (uint32_t)user, 0);
}

int putchar(int c) {
    char ch = (char)c;
    write(1, &ch, 1);
    return (unsigned char)c;
}

void print(const char* s) {
    write(1, s, strlen(s));
}

int puts(const char* s) {
    print(s);
    putchar('\n');
    return 0;
}

int getchar(void) {
    char c;
    int n = read(0, &c, 1);
    return (n == 1) ? (unsigned char)c : -1;
}

int readline(char* buf, size_t size) {
    if (size == 0) return -1;
    int n = read(0, buf, size - 1);
    if (n < 0) return n;
    if (n > 0 && buf[n - 1] == '\n') n--;
    buf[n] = '\0';
    return n;
}

/*-----------------------------------------------------------------------------
 * printf — supports %c %s %d %i %u %x %p %%, an optional minimum field width
 * and a leading '-' to left-align within it. No precision, no '0' padding.
 *
 * Width is not a nicety: without it an unknown conversion like "%-3u" fell into
 * the default case, printed "%-" literally, consumed NO argument, and every
 * later conversion in that call took the WRONG one -- a %s then dereferenced an
 * integer and the process took a page fault. Any column-aligned output (ps,
 * top) needs this, so it is implemented rather than worked around.
 *
 * Output is batched into a buffer to keep syscall count low.
 *---------------------------------------------------------------------------*/
typedef struct {
    char buf[128];
    size_t len;
    int total;
} out_t;

static void out_flush(out_t* o) {
    if (o->len > 0) {
        write(1, o->buf, o->len);
        o->len = 0;
    }
}

static void out_ch(out_t* o, char c) {
    if (o->len == sizeof(o->buf)) out_flush(o);
    o->buf[o->len++] = c;
    o->total++;
}

static void out_str(out_t* o, const char* s) {
    while (*s) out_ch(o, *s++);
}

/* Render one conversion into `tmp` (NUL-terminated) so the caller can pad it to
 * a field width. 32 bytes covers the longest: 10 digits for a uint32, 11 for a
 * negative int, 10 for "0x" + 8 hex. */
#define CONV_MAX 32

static void conv_udec(char* dst, uint32_t v) {
    char rev[12];
    int i = 0, j = 0;
    do { rev[i++] = (char)('0' + v % 10u); v /= 10u; } while (v);
    while (i > 0) dst[j++] = rev[--i];
    dst[j] = '\0';
}

static void conv_hex(char* dst, uint32_t v, int prefix) {
    static const char digits[] = "0123456789abcdef";
    char rev[8];
    int i = 0, j = 0;
    if (prefix) { dst[j++] = '0'; dst[j++] = 'x'; }
    do { rev[i++] = digits[v & 0xF]; v >>= 4; } while (v);
    while (i > 0) dst[j++] = rev[--i];
    dst[j] = '\0';
}

int vprintf(const char* fmt, va_list ap) {
    out_t o = { .len = 0, .total = 0 };

    for (; *fmt; fmt++) {
        if (*fmt != '%') {
            out_ch(&o, *fmt);
            continue;
        }
        fmt++;

        int left = 0;
        while (*fmt == '-') { left = 1; fmt++; }

        /* '0' flag. Must be consumed BEFORE the width digits below, or the
         * leading zero of "%02d" is read as part of the width and the flag
         * silently disappears -- which is what made `date` print "7:30: 3"
         * where it meant "07:30:03". Ignored when left-justifying, as in C:
         * "%-05d" pads on the right, where zeros would change the value. */
        int zero = 0;
        while (*fmt == '0') { zero = 1; fmt++; }

        int width = 0;
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (*fmt - '0');
            fmt++;
        }

        /* `body` points at the rendered conversion; `tmp` backs it when the
         * conversion is numeric. Padding is applied uniformly afterwards, so
         * every conversion honours the width the same way. */
        char tmp[CONV_MAX];
        const char* body = tmp;

        switch (*fmt) {
        case 'c':
            tmp[0] = (char)va_arg(ap, int);
            tmp[1] = '\0';
            break;
        case 's': {
            const char* s = va_arg(ap, const char*);
            body = s ? s : "(null)";
            break;
        }
        case 'd':
        case 'i': {
            int v = va_arg(ap, int);
            if (v < 0) {
                tmp[0] = '-';
                conv_udec(tmp + 1, (uint32_t)(-(int64_t)v));
            } else {
                conv_udec(tmp, (uint32_t)v);
            }
            break;
        }
        case 'u': conv_udec(tmp, va_arg(ap, uint32_t)); break;
        case 'x': conv_hex(tmp, va_arg(ap, uint32_t), 0); break;
        case 'p': conv_hex(tmp, (uint32_t)(uintptr_t)va_arg(ap, void*), 1); break;
        case '%':
            tmp[0] = '%';
            tmp[1] = '\0';
            break;
        case '\0':
            /* Trailing '%' with nothing after it. Step back so the loop's
             * fmt++ lands on the NUL and terminates. */
            fmt--;
            continue;
        default:
            /* Unknown conversion: echo it back verbatim rather than consuming
             * an argument, which would desynchronise everything after it. */
            out_ch(&o, '%');
            out_ch(&o, *fmt);
            continue;
        }

        int len = 0;
        while (body[len]) len++;
        int pad = (width > len) ? width - len : 0;

        if (left) {
            out_str(&o, body);
            while (pad-- > 0) out_ch(&o, ' ');
        } else if (zero) {
            /* Zeros go AFTER any sign, not before it: "%05d" of -42 is
             * "-0042", never "00-42". Emit the '-' first, then the zeros,
             * then the digits. */
            int off = 0;
            if (body[0] == '-') { out_ch(&o, '-'); off = 1; }
            while (pad-- > 0) out_ch(&o, '0');
            out_str(&o, body + off);
        } else {
            while (pad-- > 0) out_ch(&o, ' ');
            out_str(&o, body);
        }
    }

    out_flush(&o);
    return o.total;
}

int printf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vprintf(fmt, ap);
    va_end(ap);
    return n;
}

/*-----------------------------------------------------------------------------
 * Strings
 *---------------------------------------------------------------------------*/
size_t strlen(const char* s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

int strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char* a, const char* b, size_t n) {
    for (; n > 0; n--, a++, b++) {
        if (*a != *b) return (unsigned char)*a - (unsigned char)*b;
        if (*a == '\0') return 0;
    }
    return 0;
}

char* strcpy(char* dst, const char* src) {
    char* d = dst;
    while ((*d++ = *src++)) { }
    return dst;
}

char* strncpy(char* dst, const char* src, size_t n) {
    size_t i = 0;
    for (; i < n && src[i]; i++) dst[i] = src[i];
    for (; i < n; i++) dst[i] = '\0';
    return dst;
}

char* strchr(const char* s, int c) {
    for (;; s++) {
        if (*s == (char)c) return (char*)s;
        if (*s == '\0') return NULL;
    }
}

void* memcpy(void* dst, const void* src, size_t n) {
    unsigned char* d = dst;
    const unsigned char* s = src;
    while (n--) *d++ = *s++;
    return dst;
}

void* memmove(void* dst, const void* src, size_t n) {
    unsigned char* d = dst;
    const unsigned char* s = src;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else if (d > s) {
        d += n; s += n;
        while (n--) *--d = *--s;
    }
    return dst;
}

void* memset(void* dst, int c, size_t n) {
    unsigned char* d = dst;
    while (n--) *d++ = (unsigned char)c;
    return dst;
}

int memcmp(const void* a, const void* b, size_t n) {
    const unsigned char* pa = a;
    const unsigned char* pb = b;
    for (; n > 0; n--, pa++, pb++) {
        if (*pa != *pb) return *pa - *pb;
    }
    return 0;
}

/*-----------------------------------------------------------------------------
 * Conversion
 *---------------------------------------------------------------------------*/
int atoi(const char* s) {
    int neg = 0;
    int v = 0;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '-') { neg = 1; s++; }
    else if (*s == '+') s++;
    while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
    return neg ? -v : v;
}

/*-----------------------------------------------------------------------------
 * Heap — 16 KB static arena, bump allocation, free() is a no-op
 *---------------------------------------------------------------------------*/
#define HEAP_SIZE 16384

static unsigned char heap[HEAP_SIZE] __attribute__((aligned(8)));
static size_t heap_used;

void* malloc(size_t size) {
    size = (size + 7u) & ~(size_t)7u;
    if (size == 0 || size > HEAP_SIZE - heap_used) return NULL;
    void* p = &heap[heap_used];
    heap_used += size;
    return p;
}

void free(void* ptr) {
    (void)ptr;
}
