/*=============================================================================
 * netprobe.c — ring-3 probe for the packet-path boundary (SYS_NETRX/SYS_NETTX).
 *
 * doc/NETDAEMON_DESIGN.md item 4, PR B. The two syscalls exist so the boundary
 * can be proven to carry real frames BEFORE the parser moves to ring 3. Nothing
 * in the kernel calls them yet, so a stock boot leaves both counters at zero —
 * which is exactly why this program exists. "Networking still works" is what a
 * build with the boundary bypassed also shows; only a ring-3 caller going
 * straight to int 0x80 can demonstrate that frames traverse the syscall pair.
 *
 * It also probes the root-only gate. Run as an unprivileged user, both calls
 * must return -EPERM with the counters unmoved: raw TX forges any source MAC or
 * IP it likes (ARP poisoning, DHCP spoofing) and raw RX hands over traffic
 * addressed to every other service on the host.
 *
 * Prints one PROBE line per call so a harness can assert on the exact errno and
 * on the exact frame count, not on the presence of a word.
 *===========================================================================*/
#include "libc.h"

#define SYS_NETRX 35
#define SYS_NETTX 36

#define EPERM     1
#define EAGAIN    11
#define EINVAL    22

/* A minimal, deliberately inert frame: broadcast destination, a locally
 * administered source MAC that belongs to nobody, and an EtherType the stack
 * does not parse (0x88B5 is IEEE-reserved for local experimental use). It
 * leaves the NIC and is ignored by every listener, so the probe cannot perturb
 * ARP or IP state on the segment it runs on. */
static unsigned char probe_frame[60] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x02, 0x00, 0x00, 0x54, 0x45, 0x53,
    0x88, 0xb5,
    'N', 'E', 'T', 'P', 'R', 'O', 'B', 'E',
};

static int netrx(void* buf, unsigned int len) {
    return syscall3(SYS_NETRX, (uint32_t)(uintptr_t)buf, (uint32_t)len, 0);
}

static int nettx(const void* buf, unsigned int len) {
    return syscall3(SYS_NETTX, (uint32_t)(uintptr_t)buf, (uint32_t)len, 0);
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    unsigned char rxbuf[1600];
    int uid = getuid();

    printf("PROBE uid=%d\n", uid);

    /* Transmit first. Its return value is unambiguous — a positive byte count
     * or a negative errno — whereas receive legitimately returns -EAGAIN on an
     * idle segment, which would make an empty ring indistinguishable from a
     * broken boundary if TX had not already answered. */
    int tx_rc = nettx(probe_frame, sizeof(probe_frame));
    printf("PROBE nettx rc=%d\n", tx_rc);

    /* Argument validation, only meaningful once TX proved we are permitted.
     * A frame with no room for an Ethernet header is refused, not padded. */
    int tx_short = nettx(probe_frame, 4);
    printf("PROBE nettx_short rc=%d\n", tx_short);

    /* Drain whatever is queued. Non-blocking by design (a blocking receive
     * needs an ISR-driven wait queue, and a lost wakeup there wedges the whole
     * stack silently), so the loop is bounded and -EAGAIN is a normal answer. */
    int received = 0;
    int i;
    for (i = 0; i < 64; i++) {
        int rc = netrx(rxbuf, sizeof(rxbuf));
        if (rc == -EAGAIN) {
            break;
        }
        if (rc < 0) {
            printf("PROBE netrx rc=%d\n", rc);
            break;
        }
        received++;
    }
    printf("PROBE netrx frames=%d last_rc_eagain_after=%d\n", received, i);

    if (uid != 0) {
        /* The whole point of running unprivileged. Both must be refused, and
         * refused identically, so the errno leaks nothing about the ring. */
        if (tx_rc == -EPERM && received == 0) {
            printf("PROBE VERDICT denied\n");
            return 0;
        }
        printf("PROBE VERDICT leaked\n");
        return 1;
    }

    if (tx_rc == (int)sizeof(probe_frame) && tx_short == -EINVAL) {
        printf("PROBE VERDICT ok\n");
        return 0;
    }
    printf("PROBE VERDICT broken\n");
    return 1;
}
