/*=============================================================================
 * fileio.c - SYS_OPEN / SYS_CLOSE / SYS_READDIR test program
 *
 * Proves a RING 3 process can do file I/O on its own: create a file, write to
 * it, read it back, and list a directory — all through per-process fds handed
 * out by SYS_OPEN. The shell's own `cat`/`ls` cannot prove any of this: they
 * run in the kernel and touch ramfs_node_t directly, never crossing the
 * syscall boundary.
 *
 * NOTE: the output strings are load-bearing — verify-fsyscalls.sh greps for
 * "fileio: read back:", "fileio: found both entries", "fileio: fat32
 * entries=", "fileio: stat ok", "fileio: seek ok" and "fileio: done".
 * Keep them byte-identical.
 *===========================================================================*/
#include "libc.h"

#define TEST_DIR   "D:/fio"
#define TEST_PATH   TEST_DIR "/fileio-test.txt"
#define TEST_DATA  "ring3-file-io-ok"

/* The file itself is pre-created by the kernel at boot, mode 0666: RAMFS's
 * root directory is 0700 root-owned, so a ring-3 process (uid 1000) cannot
 * create entries in it. Opening an existing world-writable file is the part
 * that belongs to userspace, and is what this exercises. */
static int do_write(void) {
    int fd = open(TEST_PATH, O_WRONLY | O_TRUNC);
    if (fd < 0) {
        printf("fileio: open for write failed %d\n", fd);
        return -1;
    }
    printf("fileio: write fd=%d\n", fd);

    int len = (int)strlen(TEST_DATA);
    int n = write(fd, TEST_DATA, (size_t)len);
    close(fd);

    if (n != len) {
        printf("fileio: short write %d of %d\n", n, len);
        return -1;
    }
    return 0;
}

static int do_read(void) {
    int fd = open(TEST_PATH, O_RDONLY);
    if (fd < 0) {
        printf("fileio: open for read failed %d\n", fd);
        return -1;
    }

    char buf[64];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n < 0) {
        printf("fileio: read failed %d\n", n);
        return -1;
    }
    buf[n] = '\0';
    printf("fileio: read back: %s\n", buf);

    if (strcmp(buf, TEST_DATA) != 0) {
        print("fileio: content MISMATCH\n");
        return -1;
    }
    return 0;
}

static int do_readdir(void) {
    int fd = open(TEST_DIR, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        printf("fileio: opendir failed %d\n", fd);
        return -1;
    }

    /* Room for several entries per call, so the multi-entry path is exercised
     * rather than always taking the one-at-a-time branch. */
    char buf[sizeof(dirent_t) * 4];
    int found_marker = 0;
    int found_test = 0;
    int n = 0;

    while ((n = readdir(fd, buf, sizeof(buf))) > 0) {
        int count = n / (int)sizeof(dirent_t);
        for (int i = 0; i < count; i++) {
            dirent_t* de = (dirent_t*)(buf + i * (int)sizeof(dirent_t));
            printf("fileio: entry %s type=%d size=%d\n",
                   de->name, de->type, de->size);
            if (strcmp(de->name, "marker.txt") == 0) found_marker = 1;
            if (strcmp(de->name, "fileio-test.txt") == 0) found_test = 1;
        }
    }
    close(fd);

    if (n < 0) {
        printf("fileio: readdir failed %d\n", n);
        return -1;
    }
    if (!found_marker) {
        print("fileio: marker.txt NOT in listing\n");
        return -1;
    }
    if (!found_test) {
        print("fileio: fileio-test.txt NOT in listing\n");
        return -1;
    }
    print("fileio: found both entries\n");
    return 0;
}

/* Same syscall against the OTHER filesystem. Until now C: had no .readdir at
 * all, so this call returned -EINVAL while the identical call on D: worked —
 * exactly the kind of per-drive asymmetry that makes a syscall unusable from a
 * portable program. Contents depend on the disk image, so assert only that the
 * enumeration runs, returns whole records, and terminates. */
static int do_readdir_fat32(void) {
    int fd = open("C:/", O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        printf("fileio: fat32 opendir failed %d\n", fd);
        return -1;
    }

    char buf[sizeof(dirent_t) * 4];
    int entries = 0;
    int n = 0;

    /* Bounded: a cursor that never advances would otherwise spin forever. */
    while (entries < 256 && (n = readdir(fd, buf, sizeof(buf))) > 0) {
        if (n % (int)sizeof(dirent_t) != 0) {
            printf("fileio: fat32 partial record %d\n", n);
            close(fd);
            return -1;
        }
        entries += n / (int)sizeof(dirent_t);
    }
    close(fd);

    if (n < 0) {
        printf("fileio: fat32 readdir failed %d\n", n);
        return -1;
    }
    printf("fileio: fat32 entries=%d\n", entries);

    /* A non-root FAT32 directory must be refused, not silently answered with
     * the root's contents. */
    int bad = open("C:/nosuchdir", O_RDONLY | O_DIRECTORY);
    if (bad >= 0) {
        print("fileio: fat32 subdir wrongly accepted\n");
        close(bad);
        return -1;
    }
    return 0;
}

/* stat() answers the question readdir cannot: how big is THIS path, without
 * burning one of the system-wide VFS descriptors to find out. The size must
 * agree with what the write above actually put there. */
static int do_stat(void) {
    dirent_t st;

    int rc = stat(TEST_PATH, &st, sizeof(st));
    if (rc < 0) {
        printf("fileio: stat failed %d\n", rc);
        return -1;
    }
    printf("fileio: stat size=%d type=%d\n", st.size, st.type);

    if (st.size != (uint32_t)strlen(TEST_DATA)) {
        print("fileio: stat size MISMATCH\n");
        return -1;
    }
    if (st.type != DT_REG) {
        print("fileio: stat type not regular\n");
        return -1;
    }

    /* Directories must come back as directories, not as zero-size files. */
    rc = stat(TEST_DIR, &st, sizeof(st));
    if (rc < 0 || st.type != DT_DIR) {
        printf("fileio: stat dir failed rc=%d type=%d\n", rc, st.type);
        return -1;
    }

    /* Same call on the other filesystem — a stat that only works on D: is as
     * useless to a portable program as a readdir that only works on D:. */
    rc = stat("C:/", &st, sizeof(st));
    if (rc < 0 || st.type != DT_DIR) {
        printf("fileio: stat fat32 root failed rc=%d type=%d\n", rc, st.type);
        return -1;
    }

    if (stat("D:/fio/nosuchfile", &st, sizeof(st)) >= 0) {
        print("fileio: stat of missing file succeeded\n");
        return -1;
    }

    /* A buffer too small for one record must be refused rather than partly
     * filled — the caller would read fields that were never written. */
    if (stat(TEST_PATH, &st, sizeof(st) - 1) >= 0) {
        print("fileio: stat short buffer accepted\n");
        return -1;
    }

    print("fileio: stat ok\n");
    return 0;
}

/* lseek is what makes a fd more than a one-shot stream: re-reading a region,
 * or checking a size by seeking to the end, both need it. Exercised on D:
 * here; RAMFS had no seek at all until this change, so this is the half that
 * could not have worked before. */
static int do_seek(void) {
    int fd = open(TEST_PATH, O_RDONLY);
    if (fd < 0) {
        printf("fileio: seek open failed %d\n", fd);
        return -1;
    }

    char buf[8];
    int n = read(fd, buf, 4);
    if (n != 4) {
        printf("fileio: seek pre-read %d\n", n);
        close(fd);
        return -1;
    }

    /* SEEK_CUR must be relative to where the read left the cursor (4), not
     * to the start — the bug a VFS-layer offset copy would have introduced. */
    int pos = lseek(fd, 2, SEEK_CUR);
    if (pos != 6) {
        printf("fileio: SEEK_CUR gave %d, expected 6\n", pos);
        close(fd);
        return -1;
    }

    /* Back to the start, then re-read what the first read already consumed:
     * proves the cursor really moved rather than the call just reporting a
     * number. */
    pos = lseek(fd, 0, SEEK_SET);
    if (pos != 0) {
        printf("fileio: SEEK_SET gave %d, expected 0\n", pos);
        close(fd);
        return -1;
    }
    n = read(fd, buf, 4);
    buf[(n > 0) ? n : 0] = '\0';
    if (n != 4 || strcmp(buf, "ring") != 0) {
        printf("fileio: re-read after seek gave '%s' (%d)\n", buf, n);
        close(fd);
        return -1;
    }

    /* SEEK_END with a zero offset is the idiomatic "how big is this?". */
    pos = lseek(fd, 0, SEEK_END);
    if (pos != (int)strlen(TEST_DATA)) {
        printf("fileio: SEEK_END gave %d, expected %d\n",
               pos, (int)strlen(TEST_DATA));
        close(fd);
        return -1;
    }

    /* Negative displacement from the end. */
    pos = lseek(fd, -3, SEEK_END);
    if (pos != (int)strlen(TEST_DATA) - 3) {
        printf("fileio: negative SEEK_END gave %d\n", pos);
        close(fd);
        return -1;
    }

    /* Past EOF clamps to the size rather than creating a hole. */
    pos = lseek(fd, 4096, SEEK_SET);
    if (pos != (int)strlen(TEST_DATA)) {
        printf("fileio: past-EOF seek gave %d, expected clamp to %d\n",
               pos, (int)strlen(TEST_DATA));
        close(fd);
        return -1;
    }

    /* Seeking before the start is an error, not a clamp to 0. */
    if (lseek(fd, -1, SEEK_SET) >= 0) {
        print("fileio: negative seek accepted\n");
        close(fd);
        return -1;
    }

    /* An unknown origin must be rejected rather than defaulting to SEEK_SET
     * and silently moving the cursor. */
    if (lseek(fd, 0, 99) >= 0) {
        print("fileio: bad whence accepted\n");
        close(fd);
        return -1;
    }
    close(fd);

    /* Same syscall against the OTHER filesystem, on a file whose size the
     * test does not control: seek to EOF, then back, and confirm the byte
     * stream agrees with what a fresh read from the start returns. */
    int cfd = open("C:/HELLO.ELF", O_RDONLY);
    if (cfd < 0) {
        printf("fileio: fat32 seek open failed %d\n", cfd);
        return -1;
    }

    int end = lseek(cfd, 0, SEEK_END);
    if (end <= 0) {
        printf("fileio: fat32 SEEK_END gave %d\n", end);
        close(cfd);
        return -1;
    }
    printf("fileio: fat32 seek end=%d\n", end);

    /* An ELF always starts with \x7fELF; reading it after seeking back to 0
     * proves the cursor moved rather than the call merely reporting a size. */
    if (lseek(cfd, 0, SEEK_SET) != 0) {
        print("fileio: fat32 rewind failed\n");
        close(cfd);
        return -1;
    }
    char magic[4];
    n = read(cfd, magic, 4);
    if (n != 4 || magic[0] != 0x7f || magic[1] != 'E' ||
        magic[2] != 'L' || magic[3] != 'F') {
        printf("fileio: fat32 magic wrong after rewind (%d)\n", n);
        close(cfd);
        return -1;
    }

    /* Past EOF clamps on C: exactly as it does on D: — the whole reason
     * whence is resolved in the driver rather than per-filesystem. */
    if (lseek(cfd, end + 4096, SEEK_SET) != end) {
        print("fileio: fat32 past-EOF did not clamp\n");
        close(cfd);
        return -1;
    }
    close(cfd);

    int dfd = open(TEST_DIR, O_RDONLY | O_DIRECTORY);
    if (dfd >= 0) {
        /* A directory has no read/write cursor — seeking one would
         * desynchronise the readdir walk. */
        if (lseek(dfd, 0, SEEK_SET) >= 0) {
            print("fileio: seek on directory accepted\n");
            close(dfd);
            return -1;
        }
        close(dfd);
    }

    print("fileio: seek ok\n");
    return 0;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;

    print("fileio: starting\n");

    if (do_write() < 0) return 1;
    if (do_read() < 0) return 1;
    if (do_readdir() < 0) return 1;
    if (do_readdir_fat32() < 0) return 1;
    if (do_stat() < 0) return 1;
    if (do_seek() < 0) return 1;

    /* A never-opened fd must not resolve to anything. The VFS fd pool is
     * system-wide, so if the table leaked raw VFS numbers this could name
     * another process's open file. Must be a non-zero length: read() returns
     * 0 for len==0 before it ever looks at the fd. */
    char scratch[8];
    if (read(9, scratch, sizeof(scratch)) >= 0) {
        print("fileio: stale fd accepted\n");
        return 1;
    }

    print("fileio: done\n");
    return 0;
}
