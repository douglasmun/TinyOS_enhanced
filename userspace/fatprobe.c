/*=============================================================================
 * fatprobe.c — ring-3 driver for FAT32 (C:) file-content integrity.
 *
 * C:'s read and write paths are reached only through SYS_READ/SYS_WRITE, and
 * those feed the VFS in fixed chunks (sys_write 512 bytes, sys_read 1024). The
 * shipped volume has 1024-byte clusters, so an ordinary multi-kilobyte write
 * or read crosses cluster boundaries at call boundaries. A shell `cat` of a
 * short file never does, which is why nothing caught it.
 *
 * Mode "big": every leg writes a pattern whose bytes differ per cluster, reads
 * it back, and compares byte for byte. Each line carries the stat size (the
 * positive control: the write path claimed success) and the first mismatch.
 *
 *   PROBE big one   size=3000 read=3000 bad=-1   one write() of 3000 bytes
 *   PROBE big three size=3000 read=3000 bad=-1   three write()s of 1000
 *   PROBE big append size=2148 read=2148 bad=-1  2048, then lseek END + 100
 *   PROBE done
 *
 * bad= is the first differing offset, -1 when the content matches. Runs
 * unprivileged: C: has no ownership model, so uid does not change the path.
 *===========================================================================*/
#include "libc.h"

#define BIG 3000
#define APPEND_BASE 2048
#define APPEND_MORE 100

static unsigned char wbuf[4096];
static unsigned char rbuf[4096];

/* Distinct per offset AND per 1024-byte cluster, so a cluster read twice or
 * written over another never compares equal by accident. */
static unsigned char pat(int i) {
    return (unsigned char)(i * 7 + i / 1024 * 31 + 1);
}

static int stat_size(const char* path) {
    dirent_t de;
    memset(&de, 0, sizeof(de));
    int rc = stat(path, &de, sizeof(de));
    return rc < 0 ? rc : (int)de.size;
}

/* Read the whole file with plain read() calls, as any program would. */
static int read_all(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return fd;
    int total = 0, n;
    while (total < (int)sizeof(rbuf) &&
           (n = read(fd, rbuf + total, sizeof(rbuf) - (size_t)total)) > 0) {
        total += n;
    }
    close(fd);
    return total;
}

static int first_bad(int len) {
    for (int i = 0; i < len; i++) {
        if (rbuf[i] != pat(i)) return i;
    }
    return -1;
}

static void report(const char* leg, const char* path, int expect) {
    memset(rbuf, 0, sizeof(rbuf));
    int size = stat_size(path);
    int got = read_all(path);
    int bad = got == expect ? first_bad(expect) : 0;
    printf("PROBE big %s size=%d read=%d bad=%d\n", leg, size, got, bad);
}

static int create(const char* path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) printf("PROBE open %s failed %d\n", path, fd);
    return fd;
}

static void big(void) {
    for (int i = 0; i < (int)sizeof(wbuf); i++) wbuf[i] = pat(i);

    int fd = create("C:/BIGONE.BIN");
    if (fd >= 0) {
        write(fd, wbuf, BIG);
        close(fd);
    }
    report("one", "C:/BIGONE.BIN", BIG);

    fd = create("C:/BIGTHR.BIN");
    if (fd >= 0) {
        for (int off = 0; off < BIG; off += 1000) write(fd, wbuf + off, 1000);
        close(fd);
    }
    report("three", "C:/BIGTHR.BIN", BIG);

    /* EOF exactly on a cluster boundary: the append must extend the chain,
     * not land on the last existing cluster. */
    fd = create("C:/BIGAPP.BIN");
    if (fd >= 0) {
        write(fd, wbuf, APPEND_BASE);
        close(fd);
    }
    fd = open("C:/BIGAPP.BIN", O_WRONLY);
    if (fd >= 0) {
        lseek(fd, 0, SEEK_END);
        write(fd, wbuf + APPEND_BASE, APPEND_MORE);
        close(fd);
    }
    report("append", "C:/BIGAPP.BIN", APPEND_BASE + APPEND_MORE);
}

int main(int argc, char** argv) {
    if (argc > 1 && !strcmp(argv[1], "big")) {
        big();
    } else {
        print("usage: fatprobe big\n");
    }
    print("PROBE done\n");
    return 0;
}
