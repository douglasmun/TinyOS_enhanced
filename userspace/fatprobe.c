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
 * Mode "stale" (see stale() below): unlink and O_TRUNC must not strand
 * another open fd on storage that was released. See verify-fat32-stale-fd.sh.
 *
 * Mode "mode" (see mode() below): access mode, O_APPEND and the protected-path
 * gate on C:. See verify-fat32-access-mode.sh.
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

/* Mode "stale": another fd must never act on a file whose storage was
 * released under it. Both legs run in a fresh directory, so the slot and
 * cluster that get reused are the ones the leg just freed.
 *
 *   PROBE stale unlink busy=<rc> victim_size=12 victim_bad=-1 after=0
 *     unlink of an open EMPTY file is refused (busy < 0). The victim created
 *     next lands in the slot a successful unlink would have freed; the open
 *     fd then writes and closes, and must not rewrite the victim's entry.
 *     after=0 is the positive control: once closed, the unlink succeeds.
 *   PROBE stale trunc size=100 bad=-1 other_size=3000 other_bad=-1
 *     fd1 is open on a 3000-byte file when fd2 truncates it; OTHER is then
 *     written into the freed clusters. fd1 writes 100 bytes at its cursor:
 *     the file must hold exactly those, and OTHER must be untouched. */
#define VICTIM_LEN 12

static int compare_file(const char* path, int expect, int (*want)(int)) {
    memset(rbuf, 0, sizeof(rbuf));
    int got = read_all(path);
    if (got != expect) return got < 0 ? -2 : (got < expect ? got : expect);
    for (int i = 0; i < expect; i++) {
        if (rbuf[i] != (unsigned char)want(i)) return i;
    }
    return -1;
}

static int want_victim(int i) { return 'V' + (i % 3); }
static int want_z(int i) { (void)i; return 'Z'; }
static int want_pat(int i) { return pat(i); }

static void stale(void) {
    for (int i = 0; i < (int)sizeof(wbuf); i++) wbuf[i] = pat(i);
    unsigned char vbuf[VICTIM_LEN];
    for (int i = 0; i < VICTIM_LEN; i++) vbuf[i] = (unsigned char)want_victim(i);
    unsigned char zbuf[100];
    memset(zbuf, 'Z', sizeof(zbuf));

    /* --- leg unlink -------------------------------------------------- */
    int rc = mkdir("C:/STALEU");
    if (rc < 0) printf("PROBE mkdir C:/STALEU failed %d\n", rc);
    int fd = create("C:/STALEU/EMPTY.TXT");
    if (fd >= 0) close(fd);
    int held = open("C:/STALEU/EMPTY.TXT", O_WRONLY);
    int busy = unlink("C:/STALEU/EMPTY.TXT");
    fd = create("C:/STALEU/VICTIM.TXT");
    if (fd >= 0) {
        write(fd, vbuf, VICTIM_LEN);
        close(fd);
    }
    if (held >= 0) {
        write(held, zbuf, 5);   /* flushes the held fd's dirent */
        close(held);
    } else {
        printf("PROBE open held failed %d\n", held);
    }
    int vsize = stat_size("C:/STALEU/VICTIM.TXT");
    int vbad = compare_file("C:/STALEU/VICTIM.TXT", VICTIM_LEN, want_victim);
    int after = unlink("C:/STALEU/EMPTY.TXT");
    if (busy == 0) after = 0;   /* already gone; the control is moot */
    printf("PROBE stale unlink busy=%d victim_size=%d victim_bad=%d after=%d\n",
           busy, vsize, vbad, after);

    /* --- leg trunc --------------------------------------------------- */
    rc = mkdir("C:/STALET");
    if (rc < 0) printf("PROBE mkdir C:/STALET failed %d\n", rc);
    fd = create("C:/STALET/TRUNC.BIN");
    if (fd >= 0) {
        write(fd, wbuf, BIG);
        close(fd);
    }
    int fd1 = open("C:/STALET/TRUNC.BIN", O_RDWR);
    int fd2 = open("C:/STALET/TRUNC.BIN", O_WRONLY | O_TRUNC);
    if (fd2 >= 0) close(fd2);
    fd = create("C:/STALET/OTHER.BIN");
    if (fd >= 0) {
        write(fd, wbuf, BIG);
        close(fd);
    }
    if (fd1 >= 0) {
        write(fd1, zbuf, sizeof(zbuf));
        close(fd1);
    } else {
        printf("PROBE open fd1 failed %d\n", fd1);
    }
    int tsize = stat_size("C:/STALET/TRUNC.BIN");
    int tbad = compare_file("C:/STALET/TRUNC.BIN", (int)sizeof(zbuf), want_z);
    int osize = stat_size("C:/STALET/OTHER.BIN");
    int obad = compare_file("C:/STALET/OTHER.BIN", BIG, want_pat);
    printf("PROBE stale trunc size=%d bad=%d other_size=%d other_bad=%d\n",
           tsize, tbad, osize, obad);
}

/* Mode "mode": run as a NON-ROOT user. disk.img has no /etc, so every
 * refusal of a protected name below is the gate's -13, never "exists".
 *
 *   PROBE mode bs dir=<rc> file=<rc> file_size=<rc>
 *     A backslash is not a separator to the VFS, so C:/<bs>etc is one
 *     unprotected component to the gate. Both must fail; file_size is stat
 *     of the /MODE/BS.TXT a backslash-splitting driver would have created
 *     (want < 0).
 *     Runs first, so a bypass cannot hide behind the case leg's EEXIST.
 *   PROBE mode case lower=-13 upper=-13 file=-13 ctl=0
 *     mkdir C:/etc (positive control: the gate is live for this uid),
 *     mkdir C:/ETC, open C:/Etc/X.TXT for create; ctl = mkdir C:/MODE/SUB.
 *   PROBE mode access trunc_size=100 rdwrite=-9 wrread=-9 bad=-1 wctl=5 rctl=100
 *     O_RDONLY|O_TRUNC must not empty the file; write on an O_RDONLY fd and
 *     read on an O_WRONLY fd are refused; the file keeps its content. wctl
 *     and rctl are the same calls on correctly opened fds.
 *   PROBE mode append c_size=15 c_bad=-1 d_size=15 d_bad=-1
 *     10 'A's, then O_WRONLY|O_APPEND writes 5 'B's: on C: and on D:. */
#define APP_BASE 10
#define APP_MORE 5

static int want_app(int i) { return i < APP_BASE ? 'A' : 'B'; }

static void append_leg(const char* path, int* size, int* bad) {
    unsigned char a[APP_BASE], b[APP_MORE];
    memset(a, 'A', sizeof(a));
    memset(b, 'B', sizeof(b));
    int fd = create(path);
    if (fd >= 0) {
        write(fd, a, sizeof(a));
        close(fd);
    }
    fd = open(path, O_WRONLY | O_APPEND);
    if (fd >= 0) {
        write(fd, b, sizeof(b));
        close(fd);
    } else {
        printf("PROBE open %s failed %d\n", path, fd);
    }
    *size = stat_size(path);
    *bad = compare_file(path, APP_BASE + APP_MORE, want_app);
}

static void mode(void) {
    for (int i = 0; i < (int)sizeof(wbuf); i++) wbuf[i] = pat(i);
    unsigned char zbuf[5];
    memset(zbuf, 'Z', sizeof(zbuf));

    int rc = mkdir("C:/MODE");
    if (rc < 0) printf("PROBE mkdir C:/MODE failed %d\n", rc);

    /* --- leg bs ------------------------------------------------------ */
    int bsdir = mkdir("C:/\\etc");
    int bsfile = open("C:/MODE\\BS.TXT", O_WRONLY | O_CREAT);
    if (bsfile >= 0) close(bsfile);
    printf("PROBE mode bs dir=%d file=%d file_size=%d\n",
           bsdir, bsfile, stat_size("C:/MODE/BS.TXT"));

    /* --- leg case ---------------------------------------------------- */
    int lower = mkdir("C:/etc");
    int upper = mkdir("C:/ETC");
    int cfile = open("C:/Etc/X.TXT", O_WRONLY | O_CREAT);
    if (cfile >= 0) close(cfile);
    int ctl = mkdir("C:/MODE/SUB");
    printf("PROBE mode case lower=%d upper=%d file=%d ctl=%d\n",
           lower, upper, cfile, ctl);

    /* --- leg access -------------------------------------------------- */
    int fd = create("C:/MODE/T.BIN");
    if (fd >= 0) {
        write(fd, wbuf, 100);
        close(fd);
    }
    fd = open("C:/MODE/T.BIN", O_RDONLY | O_TRUNC);
    if (fd >= 0) close(fd);
    int tsize = stat_size("C:/MODE/T.BIN");

    int rdwrite = -999;
    fd = open("C:/MODE/T.BIN", O_RDONLY);
    if (fd >= 0) {
        rdwrite = write(fd, zbuf, sizeof(zbuf));
        close(fd);
    }
    int wrread = -999;
    fd = open("C:/MODE/T.BIN", O_WRONLY);
    if (fd >= 0) {
        wrread = read(fd, rbuf, 10);
        close(fd);
    }
    int bad = compare_file("C:/MODE/T.BIN", 100, want_pat);

    int wctl = -999;
    fd = create("C:/MODE/W.BIN");
    if (fd >= 0) {
        wctl = write(fd, zbuf, sizeof(zbuf));
        close(fd);
    }
    /* rctl reads its own file: T.BIN is the one the bugs damage. */
    fd = create("C:/MODE/R.BIN");
    if (fd >= 0) {
        write(fd, wbuf, 100);
        close(fd);
    }
    int rctl = read_all("C:/MODE/R.BIN");
    printf("PROBE mode access trunc_size=%d rdwrite=%d wrread=%d bad=%d wctl=%d rctl=%d\n",
           tsize, rdwrite, wrread, bad, wctl, rctl);

    /* --- leg append -------------------------------------------------- */
    int csize, cbad, dsize, dbad;
    append_leg("C:/MODE/A.BIN", &csize, &cbad);
    append_leg("D:/scratch/fpapp.txt", &dsize, &dbad);
    printf("PROBE mode append c_size=%d c_bad=%d d_size=%d d_bad=%d\n",
           csize, cbad, dsize, dbad);
}

int main(int argc, char** argv) {
    if (argc > 1 && !strcmp(argv[1], "big")) {
        big();
    } else if (argc > 1 && !strcmp(argv[1], "stale")) {
        stale();
    } else if (argc > 1 && !strcmp(argv[1], "mode")) {
        mode();
    } else {
        print("usage: fatprobe big|stale|mode\n");
    }
    print("PROBE done\n");
    return 0;
}
