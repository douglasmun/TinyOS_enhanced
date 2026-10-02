/* Fuzz target: the RAMFS primitives in src/ramfs.c, driven by an
 * unprivileged caller.
 *
 * ramfs_open/mkdir/rmdir/unlink/rename/chmod are what SYS_OPEN, SYS_MKDIR,
 * SYS_UNLINK, SYS_RENAME and SYS_CHMOD reach from ring 3 (through vfs.c and
 * ramfs_vfs.c, which canonicalise the path but enforce nothing ramfs does not).
 * Permissions are enforced here, in the primitive, so this is the boundary
 * to fuzz.
 *
 * Every input starts from the same tree, built as root:
 *   /secret          root 0600 "TOPSECRET"
 *   /rootdir/        root 0700
 *   /rootdir/pub     root 0644 "TOPSECRET"  -- readable only by traversing 0700
 *   /vdir/           uid 1001 0755
 *   /vdir/victim     uid 1001 0600 "VICTIMDATA"
 *   /scratch/        root 0777  (as kernel.c makes it)
 * then runs a sequence of operations as uid 1000.
 *
 * Oracles, checked after every operation:
 *   - the protected files keep their owner, mode and contents;
 *   - no descriptor uid 1000 opened points at a protected file;
 *   - the tree is well formed: parent links, child_count, total_nodes equal
 *     to the nodes reachable from the root, no children under a file, and
 *     sibling names that are unique, non-empty, not "." / ".." and slash-free
 *     (a name lookups cannot reach is a node nobody can delete).
 * ASan covers the memory side (data pages, node frames, use after free). */
#include "ramfs.c"

#include <stdlib.h>
#include "fuzz_common.h"

/* abort() that names its line under FUZZ_VERBOSE=1, so a reproducer says
 * which oracle it tripped without a debugger. */
static void die(int line) {
    char msg[32] = "ramfs: oracle line ";
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

#define ATTACKER 1000
#define VICTIM   1001
#define NSLOTS   8

static task_t task_root, task_attacker, task_victim;
static task_t* current_task_ptr;

task_t* scheduler_get_current_task(void) { return current_task_ptr; }

static const char* const PATHS[16] = {
    "/", "/scratch", "/scratch/a", "/scratch/a/b",
    "/secret", "/rootdir", "/rootdir/pub", "/vdir",
    "/vdir/victim", "/scratch/b", "//scratch//a", "/scratch/../secret",
    "/scratch/a/x", "/scratch/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "/scratch/d", "/scratch/d/e",
};

struct prot {
    const char* path;
    ramfs_node_t* node;
    uint16_t uid, mode;
    const char* data;
};
static struct prot prot[3] = {
    { "/secret", NULL, 0, 0600, "TOPSECRET" },
    { "/rootdir/pub", NULL, 0, 0644, "TOPSECRET" },
    { "/vdir/victim", NULL, VICTIM, 0600, "VICTIMDATA" },
};

/* ---- input cursor ---- */
static const uint8_t* in;
static size_t in_left;

static uint8_t take(void) {
    if (!in_left) return 0;
    in_left--;
    return *in++;
}

/* Byte < 16 picks a canned path; otherwise a raw NUL-terminated string. */
static const char* take_path(char* buf, size_t cap) {
    if (!in_left) return PATHS[0];
    if (*in < 16) return PATHS[take()];
    size_t n = 0;
    while (in_left && n + 1 < cap) {
        uint8_t c = take();
        if (!c) break;
        buf[n++] = (char)c;
    }
    buf[n] = '\0';
    return buf;
}

/* ---- tree teardown and invariants ---- */
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

static uint32_t check_dir(ramfs_node_t* d, int depth) {
    if (depth > 20) abort();
    uint32_t count = 1, kids = 0;
    if (d->type == RAMFS_TYPE_FILE && d->children) abort();
    for (ramfs_node_t* c = d->children; c; c = c->next) {
        if (++kids > RAMFS_MAX_FILES) abort();
        if (c->parent != d) abort();
        if (!c->name[0] || strchr(c->name, '/')) abort();
        if (!strcmp(c->name, ".") || !strcmp(c->name, "..")) abort();
        for (ramfs_node_t* o = c->next; o; o = o->next)
            if (!strcmp(o->name, c->name)) abort();
        count += check_dir(c, depth + 1);
    }
    if (kids != d->child_count) abort();
    return count;
}

static void check_invariants(void) {
    if (check_dir(root, 0) != total_nodes) abort();
    for (int i = 0; i < 3; i++) {
        struct prot* p = &prot[i];
        ramfs_node_t* n = p->node;
        size_t len = strlen(p->data);
        if (n->uid != p->uid || n->mode != p->mode || n->size != len) abort();
        if (memcmp(n->data_pages[0], p->data, len)) abort();
    }
}

/* ---- per-input setup ---- */
static void as(task_t* t) { current_task_ptr = t; }

static void make_file(const char* path, const char* data, uint16_t mode) {
    int fd = ramfs_open(path, RAMFS_FLAG_READ | RAMFS_FLAG_WRITE);
    if (fd < 0) abort();
    ramfs_write(fd, data, strlen(data));
    ramfs_close(fd);
    if (ramfs_chmod(path, mode) != 0) abort();
}

static void setup(void) {
    for (int i = 0; i < RAMFS_MAX_FDS; i++) file_descriptors[i].in_use = false;
    if (root) free_tree(root);
    root = NULL;
    total_nodes = 0;

    memset(&task_root, 0, sizeof(task_root));
    memset(&task_attacker, 0, sizeof(task_attacker));
    memset(&task_victim, 0, sizeof(task_victim));
    task_attacker.uid = task_attacker.euid = ATTACKER;
    task_attacker.gid = task_attacker.egid = ATTACKER;
    task_victim.uid = task_victim.euid = VICTIM;
    task_victim.gid = task_victim.egid = VICTIM;
    memcpy(task_attacker.private_tmp_dir, "/scratch/", 10);

    as(&task_root);
    ramfs_init();
    if (ramfs_mkdir("/scratch") || ramfs_chmod("/scratch", 0777)) abort();
    make_file("/secret", "TOPSECRET", 0600);
    if (ramfs_mkdir("/rootdir")) abort();
    make_file("/rootdir/pub", "TOPSECRET", 0644);
    if (ramfs_mkdir("/vdir")) abort();
    ramfs_find("/vdir")->uid = VICTIM;
    ramfs_find("/vdir")->gid = VICTIM;
    if (ramfs_chmod("/vdir", 0755)) abort();
    as(&task_victim);
    make_file("/vdir/victim", "VICTIMDATA", 0600);
    as(&task_root);
    for (int i = 0; i < 3; i++)
        if (!(prot[i].node = ramfs_find(prot[i].path))) abort();
    as(&task_attacker);
    check_invariants();
}

static bool is_protected(const ramfs_node_t* n) {
    for (int i = 0; i < 3; i++)
        if (prot[i].node == n) return true;
    return false;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len) {
    static uint8_t buf[256 * 300];
    char p1[128], p2[128];
    int slot[NSLOTS];
    for (int i = 0; i < NSLOTS; i++) slot[i] = -1;

    fuzz_reset();
    setup();
    in = data;
    in_left = len;

    for (int step = 0; in_left && step < 64; step++) {
        uint8_t op = take() % 13, s = take() % NSLOTS;
        const char* a;
        int fd = slot[s], r;
        switch (op) {
        case 0:
            a = take_path(p1, sizeof(p1));
            r = ramfs_open(a, take() & (RAMFS_FLAG_READ | RAMFS_FLAG_WRITE | RAMFS_FLAG_NOFOLLOW));
            if (r >= 0) {
                if (is_protected(file_descriptors[r].node)) abort();
                if (fd >= 0) ramfs_close(fd);
                slot[s] = r;
            }
            break;
        case 1:
            r = ramfs_read(fd, buf, (size_t)take() * 300);
            break;
        case 2: {
            size_t n = (size_t)take() * 300;
            memset(buf, 'W', n);
            ramfs_write(fd, buf, n);
            break;
        }
        case 3:
            ramfs_seek(fd, (uint32_t)take() << 9);
            break;
        case 4:
            ramfs_truncate(fd);
            break;
        case 5:
            ramfs_close(fd);
            slot[s] = -1;
            break;
        case 6:
            ramfs_mkdir(take_path(p1, sizeof(p1)));
            break;
        case 7:
            ramfs_rmdir(take_path(p1, sizeof(p1)));
            break;
        case 8:
            ramfs_unlink(take_path(p1, sizeof(p1)));
            break;
        case 9:
            a = take_path(p1, sizeof(p1));
            ramfs_rename(a, take_path(p2, sizeof(p2)));
            break;
        case 10: {
            a = take_path(p1, sizeof(p1));
            uint16_t mode = (uint16_t)(take() << 8);
            ramfs_chmod(a, mode | take());
            break;
        }
        case 11:
            ramfs_find(take_path(p1, sizeof(p1)));
            ramfs_tell(fd);
            ramfs_fd_size(fd);
            break;
        case 12: {
            char name[64];
            r = ramfs_mkstemps(name, sizeof(name));
            if (r >= 0) {
                if (fd >= 0) ramfs_close(fd);
                slot[s] = r;
            }
            break;
        }
        }
        check_invariants();
    }
    for (int i = 0; i < NSLOTS; i++)
        if (slot[i] >= 0) ramfs_close(slot[i]);
    return 0;
}
