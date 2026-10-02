/* Fuzz target: the FAT32 driver, src/fat32.c, against a hostile disk image.
 *
 * The input IS the disk: sector N is bytes [N*512, N*512+512). Reads past the
 * end fail the way an IDE read past the last LBA does. Writes go to a private
 * copy, so a driver that writes metadata and reads it back sees its own
 * writes.
 *
 * fat32.c is #included so the harness can unmount between inputs (its state
 * is all file-static). Each input runs one fixed script: mount, walk the tree
 * two levels deep, read and seek every file found, then create / write /
 * truncate / mkdir / unlink / rmdir -- every entry point a shell user reaches
 * through the VFS.
 *
 * Oracles beyond ASan/UBSan: a mounted driver writes only the FAT and the
 * data region, and a path that names NEW.TXT only by losing characters
 * never opens it. */
#include "fat32.c"

#include <stdlib.h>
#include "fuzz_common.h"

#define MAX_NAMES 24

static uint8_t* disk;
static size_t disk_len;

int ide_read_sectors(uint32_t lba, uint8_t count, void* buffer) {
    uint64_t off = (uint64_t)lba * 512, n = (uint64_t)count * 512;
    if (off + n > disk_len) return -1;
    memcpy(buffer, disk + off, (size_t)n);
    return 0;
}

/* FUZZ_FAT32_NO_DISKSIZE=1 reports an unknown size (0), switching off the
 * mount's volume-vs-disk check so a reproducer is judged on the cluster-range
 * checks alone. */
uint32_t ide_get_sector_count(void) {
    static int off = -1;
    if (off < 0) off = getenv("FUZZ_FAT32_NO_DISKSIZE") != NULL;
    return off ? 0 : (uint32_t)(disk_len / 512);
}

/* Oracle: a mounted driver writes only FAT sectors and the data region.
 * A write to the boot sector or the rest of the reserved area means a
 * cluster number escaped its range. */
int ide_write_sectors(uint32_t lba, uint8_t count, const void* buffer) {
    uint64_t off = (uint64_t)lba * 512, n = (uint64_t)count * 512;
    if (fat32_mounted) {
        uint64_t fat_end = (uint64_t)fat_start_sector +
                           (uint64_t)boot_sector.num_fats * boot_sector.fat_size_32;
        bool in_fat = lba >= fat_start_sector && (uint64_t)lba + count <= fat_end;
        bool in_data = lba >= data_start_sector &&
                       (uint64_t)lba + count <= boot_sector.total_sectors_32;
        if (!in_fat && !in_data) abort();
    }
    if (off + n > disk_len) return -1;
    memcpy(disk + off, buffer, (size_t)n);
    return 0;
}

struct names {
    char path[MAX_NAMES][FAT32_MAX_PATH];
    bool is_dir[MAX_NAMES];
    int count;
    const char* parent;
};

static void collect(void* ctx, const char* name, uint32_t size, bool is_dir) {
    struct names* n = ctx;
    (void)size;
    if (n->count >= MAX_NAMES || !name || name[0] == '.') return;
    size_t pl = strlen(n->parent), nl = strlen(name);
    if (pl + 1 + nl + 1 > FAT32_MAX_PATH) return;
    char* p = n->path[n->count];
    memcpy(p, n->parent, pl);
    if (!pl || n->parent[pl - 1] != '/') p[pl++] = '/';
    memcpy(p + pl, name, nl + 1);
    n->is_dir[n->count] = is_dir;
    n->count++;
}

static void read_file(const char* path) {
    static uint8_t buf[8192];
    uint32_t size;
    uint8_t attr;
    fat32_stat(path, &size, &attr);
    int fd = fat32_open(path);
    if (fd < 0) return;
    int total = 0, r;
    while (total < 65536 && (r = fat32_read(fd, buf, sizeof(buf))) > 0) total += r;
    int sz = fat32_fd_size(fd);
    if (sz > 0) {
        fat32_seek(fd, (uint32_t)sz / 2);
        fat32_read(fd, buf, 700);
        fat32_seek(fd, (uint32_t)sz + 4096);
        fat32_read(fd, buf, 16);
    }
    fat32_tell(fd);
    fat32_close(fd);
}

static void walk_dir(const char* path, int depth, struct names* all) {
    struct names here = { .parent = path };
    fat32_list_dir_cb(path, collect, &here);
    int dfd = fat32_opendir(path);
    if (dfd >= 0) {
        char name[256];
        uint32_t size;
        uint8_t attr;
        for (int i = 0; i < 64 && fat32_readdir(dfd, name, &size, &attr) > 0; i++) {
        }
        fat32_close(dfd);
    }
    for (int i = 0; i < here.count; i++) {
        if (all->count < MAX_NAMES) {
            memcpy(all->path[all->count], here.path[i], FAT32_MAX_PATH);
            all->is_dir[all->count] = here.is_dir[i];
            all->count++;
        }
        if (here.is_dir[i]) {
            if (depth < 2) walk_dir(here.path[i], depth + 1, all);
        } else {
            read_file(here.path[i]);
        }
    }
}

static void unmount(void) {
    for (int i = 0; i < FAT32_MAX_OPEN_FILES; i++) open_files[i].in_use = false;
    if (cluster_buffer) {
        fuzz_page_free(cluster_buffer);
        cluster_buffer = NULL;
    }
    fat32_mounted = false;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len) {
    static bool inited;
    if (!inited) {
        fat32_init();
        inited = true;
    }
    fuzz_reset();
    disk = fuzz_dup(data, len);
    disk_len = len;

    if (fat32_mount() == 0) {
        fuzz_note("fat32: mounted");
        struct names all = { .parent = "/" };
        all.count = 0;
        walk_dir("/", 0, &all);

        static uint8_t wbuf[5000];
        memset(wbuf, 'A', sizeof(wbuf));
        if (fat32_create("/NEW.TXT") == 0) {
            int fd = fat32_open("/NEW.TXT");
            if (fd >= 0) {
                fat32_write(fd, wbuf, sizeof(wbuf));
                fat32_truncate(fd);
                fat32_write(fd, wbuf, 1000);
                fat32_seek(fd, 10);
                fat32_write(fd, wbuf, 600);
                fat32_close(fd);
            }
            read_file("/NEW.TXT");
            /* Names that only reach NEW.TXT by dropping or clipping part of
             * the path. parse_path() skipped a long component and
             * filename_to_83() clipped a long extension, so each of these
             * opened -- and an unlink would have deleted -- /NEW.TXT. */
            static const char* const alias[] = {
                "/LONGDIRNAME1/NEW.TXT", "/NEW.TXTX", "/NEW.TXT.TXT", "NEW.T.TXT",
            };
            for (size_t i = 0; i < sizeof(alias) / sizeof(alias[0]); i++) {
                int fd = fat32_open(alias[i]);
                if (fd >= 0) {
                    fuzz_note(alias[i]);
                    abort();
                }
            }
        }
        if (fat32_mkdir("/D2") == 0) {
            fat32_create("/D2/X.TXT");
            fat32_unlink("/D2/X.TXT");
            fat32_rmdir("/D2");
        }
        for (int i = 0; i < all.count && i < 4; i++) {
            if (all.is_dir[i]) {
                fat32_rmdir(all.path[i]);
            } else {
                int fd = fat32_open(all.path[i]);
                if (fd >= 0) {
                    fat32_seek(fd, 100);
                    fat32_write(fd, wbuf, 1500);
                    fat32_close(fd);
                }
                fat32_unlink(all.path[i]);
            }
        }
        fat32_unlink("/NEW.TXT");
    }

    unmount();
    free(disk);
    disk = NULL;
    return 0;
}
