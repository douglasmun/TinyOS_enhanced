/*=============================================================================
 * busyprobe.c — ring-3 driver for ramfs's unlink/rmdir busy refusal.
 *
 * THE BUG THIS DRIVES
 *
 * free_node() releases the ramfs_node_t frame and all of its data pages back
 * to the PMM immediately. There is no refcount, and neither ramfs_read nor
 * ramfs_write revalidates its cached node pointer -- both check only in_use
 * and the flag bits, and the stale pointer is non-NULL. So unlinking a node
 * out from under an open descriptor turned every later write through that fd
 * into a write of caller-chosen bytes into recycled kernel memory, reachable
 * from ring 3 with no privilege at all.
 *
 * WHY A PROBE IS NEEDED AT ALL
 *
 * No shell command holds a file open across an `rm` -- cmd_path_op opens
 * nothing, and every builtin that opens a file closes it before returning. So
 * nothing in the tree drives this path, and a harness built on shell builtins
 * would grade an unlink that never had a descriptor to conflict with: it
 * would pass identically against the unfixed kernel. Same "no driver, so the
 * sites rot" condition that hid the SYS_MSEAL and syscall-dispatch kprintfs.
 *
 * The refusal is invisible to `cat` and to `ls` -- the witness is the ERRNO,
 * which is why each leg prints its raw return value rather than a verdict.
 *
 * Leg 3 is the POSITIVE CONTROL and is not optional: a vfs_unlink() that
 * refused EVERY unlink would satisfy leg 1 perfectly while breaking `rm`
 * entirely. Only "refused while open, succeeded after close" separates the
 * fix from a blanket refusal.
 *===========================================================================*/
#include "libc.h"

#define BUSY_PATH "/busyprobe.tmp"

int main(void) {
    int fd, rc;

    /* --- Leg 1: unlink while the descriptor is OPEN -> must be refused --- */
    fd = open(BUSY_PATH, O_WRONLY | O_CREAT);
    if (fd < 0) {
        printf("PROBE create rc=%d\n", fd);
        printf("PROBE done\n");
        return 1;
    }
    write(fd, "busy", 4);

    rc = unlink(BUSY_PATH);
    printf("PROBE open-unlink rc=%d\n", rc);

    /* A write through the still-open fd AFTER the refused unlink. On the
     * unfixed kernel the node is already freed here and these bytes land in
     * whatever the PMM handed the frame to next. On the fixed kernel the
     * unlink was refused, so the node is still ours and this succeeds. Its
     * return value is reported, not asserted on, because the interesting
     * outcome on a broken kernel is corruption elsewhere rather than an
     * error here. */
    rc = write(fd, "afterfree", 9);
    printf("PROBE post-write rc=%d\n", rc);

    close(fd);

    /* --- Leg 2 (POSITIVE CONTROL): unlink after close -> must succeed ---- */
    rc = unlink(BUSY_PATH);
    printf("PROBE closed-unlink rc=%d\n", rc);

    /* --- Leg 3: the file is really gone -------------------------------- */
    fd = open(BUSY_PATH, O_WRONLY);
    printf("PROBE reopen rc=%d\n", fd);
    if (fd >= 0) close(fd);

    printf("PROBE done\n");
    return 0;
}
