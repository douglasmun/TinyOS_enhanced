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
 * entries=", "fileio: stat ok", "fileio: seek ok", "fileio: fat32 namespace
 * ok", "fileio: namespace ok" and "fileio: done".
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

/*=============================================================================
 * mkdir / rmdir / unlink
 *
 * Works in /scratch (0777) rather than /fio (0755 root-owned): a ring-3
 * process is uid 1000 and cannot create entries in a directory it does not
 * have write permission on. That restriction is itself worth asserting, so
 * the negative half of this test tries /fio on purpose.
 *===========================================================================*/
#define SCRATCH_DIR  "D:/scratch"
#define NEW_DIR      SCRATCH_DIR "/newdir"
/* Deliberately INSIDE the new directory: the non-empty-rmdir check is only
 * meaningful if the file is actually a child of NEW_DIR. */
#define NEW_FILE     NEW_DIR "/newfile.txt"

static int do_namespace(void) {
    /* Clean up anything a previous run left behind, so the test is
     * repeatable across reboots of a persistent image. Failures are ignored:
     * on a first run there is nothing to remove. */
    unlink(NEW_FILE);
    rmdir(NEW_DIR);

    int rc = mkdir(NEW_DIR);
    if (rc < 0) {
        printf("fileio: mkdir failed %d\n", rc);
        return -1;
    }

    /* Creating the same name twice must fail rather than silently succeed or
     * produce a duplicate entry. */
    if (mkdir(NEW_DIR) >= 0) {
        print("fileio: duplicate mkdir accepted\n");
        return -1;
    }

    /* The directory must really exist: open it and confirm it is a
     * directory, not just trust mkdir's return value. */
    int dfd = open(NEW_DIR, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) {
        printf("fileio: new dir not openable %d\n", dfd);
        return -1;
    }
    close(dfd);

    /* A file inside the new directory: proves mkdir produced a usable
     * directory rather than a stray entry. */
    int fd = open(NEW_FILE, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) {
        printf("fileio: create in new dir failed %d\n", fd);
        return -1;
    }
    write(fd, "gone soon", 9);
    close(fd);

    /* A non-empty directory must not be removable — otherwise its children
     * become unreachable garbage. */
    if (rmdir(NEW_DIR) >= 0) {
        print("fileio: rmdir of non-empty dir accepted\n");
        return -1;
    }

    /* unlink must refuse a directory, and rmdir must refuse a file: each
     * would corrupt bookkeeping that assumes the other type. */
    if (unlink(NEW_DIR) >= 0) {
        print("fileio: unlink of directory accepted\n");
        return -1;
    }
    if (rmdir(NEW_FILE) >= 0) {
        print("fileio: rmdir of file accepted\n");
        return -1;
    }

    rc = unlink(NEW_FILE);
    if (rc < 0) {
        printf("fileio: unlink failed %d\n", rc);
        return -1;
    }

    /* Gone means gone: the name must no longer open. */
    fd = open(NEW_FILE, O_RDONLY);
    if (fd >= 0) {
        print("fileio: unlinked file still opens\n");
        close(fd);
        return -1;
    }

    /* Now that it is empty, the directory goes too. */
    rc = rmdir(NEW_DIR);
    if (rc < 0) {
        printf("fileio: rmdir failed %d\n", rc);
        return -1;
    }
    if (open(NEW_DIR, O_RDONLY | O_DIRECTORY) >= 0) {
        print("fileio: removed dir still opens\n");
        return -1;
    }

    /* Permission is enforced on the PARENT directory: /fio is 0755 and owned
     * by root, so uid 1000 must not be able to create inside it. Without this
     * check the syscalls would be a filesystem-wide write primitive. */
    if (mkdir("D:/fio/nope") >= 0) {
        print("fileio: mkdir in root-owned dir accepted\n");
        return -1;
    }
    if (unlink("D:/fio/marker.txt") >= 0) {
        print("fileio: unlink in root-owned dir accepted\n");
        return -1;
    }

    /* Removing a non-existent name is an error, not a silent success. */
    if (unlink(SCRATCH_DIR "/never-existed") >= 0) {
        print("fileio: unlink of missing file accepted\n");
        return -1;
    }

    /*=====================================================================
     * The SAME syscalls against FAT32. This half matters more than the D:
     * half: the FAT32 mkdir/rmdir/unlink were dead code before this change
     * (nothing outside the driver called them) and carried the bugs that
     * would have become ring-3 corruption primitives — rmdir was literally
     * unlink, which freed a directory's cluster chain without checking that
     * it was empty.
     *===================================================================*/
    unlink("C:/NSFILE.TXT");
    rmdir("C:/NSDIR");

    rc = mkdir("C:/NSDIR");
    if (rc < 0) {
        printf("fileio: fat32 mkdir failed %d\n", rc);
        return -1;
    }

    /* Duplicate mkdir previously appended a SECOND dirent with the same 8.3
     * name, stranding the original's clusters. */
    if (mkdir("C:/NSDIR") >= 0) {
        print("fileio: fat32 duplicate mkdir accepted\n");
        return -1;
    }

    /* unlink() must refuse a directory: doing it the old way freed the
     * cluster chain while the entries inside still referenced it. */
    if (unlink("C:/NSDIR") >= 0) {
        print("fileio: fat32 unlink of directory accepted\n");
        return -1;
    }

    /* A file to delete, and to prove rmdir refuses a non-directory. */
    fd = open("C:/NSFILE.TXT", O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) {
        printf("fileio: fat32 create failed %d\n", fd);
        return -1;
    }
    write(fd, "fat32-ns", 8);

    /* Unlinking a file that is still OPEN would free clusters out from under
     * the descriptor, so the next writer aliases them. */
    if (unlink("C:/NSFILE.TXT") >= 0) {
        print("fileio: fat32 unlink of open file accepted\n");
        close(fd);
        return -1;
    }
    close(fd);

    if (rmdir("C:/NSFILE.TXT") >= 0) {
        print("fileio: fat32 rmdir of file accepted\n");
        return -1;
    }

    rc = unlink("C:/NSFILE.TXT");
    if (rc < 0) {
        printf("fileio: fat32 unlink failed %d\n", rc);
        return -1;
    }
    if (open("C:/NSFILE.TXT", O_RDONLY) >= 0) {
        print("fileio: fat32 unlinked file still opens\n");
        return -1;
    }

    rc = rmdir("C:/NSDIR");
    if (rc < 0) {
        printf("fileio: fat32 rmdir failed %d\n", rc);
        return -1;
    }

    print("fileio: fat32 namespace ok\n");

    print("fileio: namespace ok\n");
    return 0;
}

/*=============================================================================
 * Working directory: SYS_GETCWD / SYS_CHDIR
 *
 * The point of the cwd is not the two syscalls but what they do to every OTHER
 * path syscall, so most of this exercises relative paths through open/stat/
 * mkdir/unlink rather than testing chdir in isolation.
 *===========================================================================*/
static int do_cwd(void) {
    char buf[256];

    /* A process starts at the default drive root, drive-qualified. */
    int rc = getcwd(buf, sizeof(buf));
    if (rc < 0) {
        printf("fileio: getcwd failed %d\n", rc);
        return -1;
    }
    if (strcmp(buf, "D:/") != 0) {
        printf("fileio: initial cwd is '%s', expected D:/\n", buf);
        return -1;
    }
    /* The return value is the length written, excluding the NUL. */
    if (rc != 3) {
        printf("fileio: getcwd returned %d, expected 3\n", rc);
        return -1;
    }

    /* A buffer too small must fail rather than hand back a truncated path: a
     * truncated path names a different directory. */
    if (getcwd(buf, 2) >= 0) {
        print("fileio: getcwd accepted a short buffer\n");
        return -1;
    }

    rc = chdir(SCRATCH_DIR);
    if (rc < 0) {
        printf("fileio: chdir failed %d\n", rc);
        return -1;
    }
    if (getcwd(buf, sizeof(buf)) < 0 || strcmp(buf, SCRATCH_DIR) != 0) {
        printf("fileio: cwd after chdir is '%s'\n", buf);
        return -1;
    }

    /* THE POINT: a bare relative name now resolves inside the cwd. Created
     * relative, then verified through its absolute path. */
    int fd = open("cwdfile.txt", O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) {
        printf("fileio: relative create failed %d\n", fd);
        return -1;
    }
    write(fd, "cwd-relative", 12);
    close(fd);

    dirent_t st;
    if (stat(SCRATCH_DIR "/cwdfile.txt", &st, sizeof(st)) < 0) {
        print("fileio: relative create did not land in the cwd\n");
        return -1;
    }
    if (st.size != 12) {
        printf("fileio: relative file size %d, expected 12\n", (int)st.size);
        return -1;
    }

    /* An absolute path must IGNORE the cwd, not get prefixed with it. */
    if (stat("D:/scratch/cwdfile.txt", &st, sizeof(st)) < 0) {
        print("fileio: absolute path broken by cwd\n");
        return -1;
    }

    /* ".." resolves against the cwd and is clamped at the drive root. */
    if (chdir("..") < 0 || getcwd(buf, sizeof(buf)) < 0) {
        print("fileio: chdir .. failed\n");
        return -1;
    }
    if (strcmp(buf, "D:/") != 0) {
        printf("fileio: cwd after .. is '%s', expected D:/\n", buf);
        return -1;
    }

    /* Relative chdir from the root, to prove the join is not root-only. */
    if (chdir("scratch") < 0 || getcwd(buf, sizeof(buf)) < 0) {
        print("fileio: relative chdir failed\n");
        return -1;
    }
    if (strcmp(buf, SCRATCH_DIR) != 0) {
        printf("fileio: relative chdir landed at '%s'\n", buf);
        return -1;
    }

    if (unlink("cwdfile.txt") < 0) {
        print("fileio: relative unlink failed\n");
        return -1;
    }

    /* A failed chdir must leave the cwd untouched — otherwise a process ends
     * up stranded somewhere that does not resolve. */
    if (chdir("D:/no-such-dir") >= 0) {
        print("fileio: chdir to missing dir accepted\n");
        return -1;
    }
    if (getcwd(buf, sizeof(buf)) < 0 || strcmp(buf, SCRATCH_DIR) != 0) {
        printf("fileio: failed chdir moved cwd to '%s'\n", buf);
        return -1;
    }

    /* chdir to a FILE is ENOTDIR, not success. */
    if (chdir(TEST_PATH) >= 0) {
        print("fileio: chdir to a file accepted\n");
        return -1;
    }

    /* C: root is reachable. A nonexistent FAT32 directory must still be
     * refused — subdirectories work now, so this checks existence rather than
     * the old blanket "no subdirectories" rule. */
    if (chdir("C:/") < 0) {
        print("fileio: chdir to C:/ failed\n");
        return -1;
    }
    if (getcwd(buf, sizeof(buf)) < 0 || strcmp(buf, "C:/") != 0) {
        printf("fileio: cwd after C: chdir is '%s'\n", buf);
        return -1;
    }
    if (chdir("C:/NOPE") >= 0) {
        print("fileio: chdir to a missing FAT32 directory accepted\n");
        return -1;
    }

    /* Back to a known place so later tests are not affected by the cwd. */
    if (chdir("D:/") < 0) {
        print("fileio: chdir back to D:/ failed\n");
        return -1;
    }

    print("fileio: cwd ok\n");
    return 0;
}

/*=============================================================================
 * FAT32 subdirectories.
 *
 * Everything above operates on C:'s root, which is all the driver could reach:
 * create/mkdir/rmdir/unlink each took the whole path as one filename and acted
 * on the root cluster unconditionally, so "C:/A/B" meant a root entry named
 * "A/B" truncated to 8 characters. This stage exercises the nesting itself —
 * creation at depth, I/O through a nested path, listing, and the refusals that
 * must survive.
 *===========================================================================*/
static int do_fat32_subdirs(void) {
    int rc;
    char buf[64];

    /* Clean up anything a previous run left behind. Deepest first: a
     * non-empty directory cannot be removed. */
    unlink("C:/SUBA/SUBB/DEEP.TXT");
    rmdir("C:/SUBA/SUBB");
    rmdir("C:/SUBA");

    rc = mkdir("C:/SUBA");
    if (rc < 0) {
        printf("fileio: fat32 mkdir SUBA failed %d\n", rc);
        return -1;
    }

    /* The nested mkdir: previously impossible. */
    rc = mkdir("C:/SUBA/SUBB");
    if (rc < 0) {
        printf("fileio: fat32 nested mkdir failed %d\n", rc);
        return -1;
    }

    /* mkdir under a MISSING parent must fail rather than silently landing in
     * the root, which is what the old path-as-one-name behaviour did. */
    if (mkdir("C:/NOSUCH/CHILD") >= 0) {
        print("fileio: fat32 mkdir under missing parent accepted\n");
        return -1;
    }

    /* A parent that is a FILE, not a directory, must also be refused. */
    int probe = open("C:/SUBFILE.TXT", O_WRONLY | O_CREAT | O_TRUNC);
    if (probe < 0) {
        printf("fileio: fat32 create SUBFILE failed %d\n", probe);
        return -1;
    }
    close(probe);
    if (mkdir("C:/SUBFILE.TXT/CHILD") >= 0) {
        print("fileio: fat32 mkdir under a file accepted\n");
        return -1;
    }

    /* Write through a nested path, then read it back after a close — this is
     * what proves the dirent was written into the SUBdirectory's cluster and
     * not the root's. */
    int fd = open("C:/SUBA/SUBB/DEEP.TXT", O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) {
        printf("fileio: fat32 nested create failed %d\n", fd);
        return -1;
    }
    if (write(fd, "deep-ok", 7) != 7) {
        print("fileio: fat32 nested write short\n");
        close(fd);
        return -1;
    }
    close(fd);

    fd = open("C:/SUBA/SUBB/DEEP.TXT", O_RDONLY);
    if (fd < 0) {
        printf("fileio: fat32 nested reopen failed %d\n", fd);
        return -1;
    }
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n != 7) {
        printf("fileio: fat32 nested read got %d\n", n);
        return -1;
    }
    buf[n] = '\0';
    if (strcmp(buf, "deep-ok") != 0) {
        printf("fileio: fat32 nested content '%s'\n", buf);
        return -1;
    }

    /* stat must resolve the nested path and report the real size. A stat that
     * silently searched the root would report ENOENT here. */
    dirent_t st;
    rc = stat("C:/SUBA/SUBB/DEEP.TXT", &st, sizeof(st));
    if (rc < 0) {
        printf("fileio: fat32 nested stat failed %d\n", rc);
        return -1;
    }
    if (st.size != 7) {
        printf("fileio: fat32 nested stat size=%u\n", st.size);
        return -1;
    }

    /* The nested file must NOT appear in the root — the whole failure mode
     * this stage exists to catch. */
    if (stat("C:/DEEP.TXT", &st, sizeof(st)) >= 0) {
        print("fileio: fat32 nested file also visible in root\n");
        return -1;
    }

    /* Enumerate the subdirectory: DEEP.TXT plus "." and "..". */
    int dfd = open("C:/SUBA/SUBB", O_RDONLY | O_DIRECTORY);
    if (dfd < 0) {
        printf("fileio: fat32 subdir open failed %d\n", dfd);
        return -1;
    }
    dirent_t ents[8];
    int found_deep = 0;
    for (;;) {
        int got = readdir(dfd, ents, sizeof(ents));
        if (got <= 0) {
            break;
        }
        int count = got / (int)sizeof(dirent_t);
        for (int i = 0; i < count; i++) {
            if (strcmp(ents[i].name, "DEEP.TXT") == 0) {
                found_deep = 1;
            }
        }
    }
    close(dfd);
    if (!found_deep) {
        print("fileio: fat32 subdir listing missing DEEP.TXT\n");
        return -1;
    }

    /* Opening a FILE with O_DIRECTORY must fail rather than enumerate. */
    if (open("C:/SUBA/SUBB/DEEP.TXT", O_RDONLY | O_DIRECTORY) >= 0) {
        print("fileio: fat32 O_DIRECTORY on a file accepted\n");
        return -1;
    }

    /* chdir into a FAT32 subdirectory now works, and relative paths resolve
     * against it. This is what the old -ENOSYS gate refused outright. */
    if (chdir("C:/SUBA/SUBB") < 0) {
        print("fileio: fat32 chdir into subdir failed\n");
        return -1;
    }
    if (getcwd(buf, sizeof(buf)) < 0 || strcmp(buf, "C:/SUBA/SUBB") != 0) {
        printf("fileio: fat32 cwd is '%s'\n", buf);
        return -1;
    }
    fd = open("DEEP.TXT", O_RDONLY);
    if (fd < 0) {
        printf("fileio: fat32 relative open in subdir failed %d\n", fd);
        return -1;
    }
    close(fd);

    if (chdir("D:/") < 0) {
        print("fileio: fat32 chdir back to D:/ failed\n");
        return -1;
    }

    /* A non-empty directory must still be refused — the check that rmdir
     * exists for, now that there is real nesting to get it wrong. */
    if (rmdir("C:/SUBA") >= 0) {
        print("fileio: fat32 rmdir of non-empty parent accepted\n");
        return -1;
    }
    if (rmdir("C:/SUBA/SUBB") >= 0) {
        print("fileio: fat32 rmdir of non-empty subdir accepted\n");
        return -1;
    }

    /* Tear down deepest-first; each step must succeed. */
    rc = unlink("C:/SUBA/SUBB/DEEP.TXT");
    if (rc < 0) {
        printf("fileio: fat32 nested unlink failed %d\n", rc);
        return -1;
    }
    rc = rmdir("C:/SUBA/SUBB");
    if (rc < 0) {
        printf("fileio: fat32 nested rmdir failed %d\n", rc);
        return -1;
    }
    rc = rmdir("C:/SUBA");
    if (rc < 0) {
        printf("fileio: fat32 parent rmdir failed %d\n", rc);
        return -1;
    }
    unlink("C:/SUBFILE.TXT");

    print("fileio: fat32 subdirs ok\n");
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
    if (do_namespace() < 0) return 1;
    if (do_cwd() < 0) return 1;
    if (do_fat32_subdirs() < 0) return 1;

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
