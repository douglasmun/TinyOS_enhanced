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
#define SYS_NETSTAT 37

#define EPERM     1
#define EAGAIN    11
#define EINVAL    22
#define EBADF     9

/* SYS_NETSTAT subcommands and its packed first argument -- see syscall.h. */
#define NETSTAT_IFACE    0
#define NETSTAT_DHCP     1
#define NETSTAT_DNS      2
#define NETSTAT_SOCKET   3
#define NETSTAT_SOCKLIST 4
#define NETSTAT_ARG(subcmd, sockfd) \
    (((uint32_t)(subcmd) & 0xFFFFu) | (((uint32_t)(sockfd) & 0xFFFFu) << 16))

typedef struct {
    uint8_t ip[4];
    uint8_t netmask[4];
    uint8_t gateway[4];
    uint8_t mac[6];
    uint8_t _pad[2];
} netstat_iface_t;

typedef struct {
    uint32_t visible_mask;
} netstat_socklist_t;

typedef struct {
    uint32_t state;
    uint32_t connected;
    uint32_t available;
    uint8_t  remote_ip[4];
    uint16_t local_port;
    uint16_t remote_port;
} netstat_socket_t;

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

static int netstat(unsigned int subcmd, int sockfd, void* buf, unsigned int len) {
    return syscall3(SYS_NETSTAT, NETSTAT_ARG(subcmd, sockfd),
                    (uint32_t)(uintptr_t)buf, (uint32_t)len);
}

/*=============================================================================
 * SYS_NETSTAT probe (PR C1).
 *
 * Unlike the RX/TX pair above, this one must succeed for an UNPRIVILEGED
 * caller -- these are read-only queries gated on socket ownership, not on
 * euid, so a -EPERM here would be the bug rather than the proof.
 *
 * The socket bitmap reads 0 for BOTH root and the unprivileged caller on a
 * stock boot, and that is not evidence of filtering: the TCP table is simply
 * empty, because DHCP and DNS use raw UDP and never call tcp_socket(). Opening
 * a socket from ring 3 needs the write half (PR C2), which this PR
 * deliberately does not add. See the long note in verify-netd-boundary.sh
 * before reading the zero as proof of anything.
 *===========================================================================*/
static int netstat_probe(int uid) {
    netstat_iface_t iface;
    netstat_socklist_t list;
    netstat_socket_t sock;
    int rc;

    rc = netstat(NETSTAT_IFACE, 0, &iface, sizeof(iface));
    printf("PROBE netstat_iface rc=%d ip=%d.%d.%d.%d gw=%d.%d.%d.%d\n",
           rc, iface.ip[0], iface.ip[1], iface.ip[2], iface.ip[3],
           iface.gateway[0], iface.gateway[1], iface.gateway[2], iface.gateway[3]);

    /* A size the kernel did not expect must be refused outright. Truncating
     * would hand back a struct whose tail is whatever the caller had there. */
    rc = netstat(NETSTAT_IFACE, 0, &iface, sizeof(iface) - 1);
    printf("PROBE netstat_badlen rc=%d\n", rc);

    rc = netstat(99, 0, &iface, sizeof(iface));
    printf("PROBE netstat_badcmd rc=%d\n", rc);

    rc = netstat(NETSTAT_SOCKLIST, 0, &list, sizeof(list));
    printf("PROBE netstat_socklist rc=%d mask=%d\n", rc, (int)list.visible_mask);

    /* An out-of-range descriptor and a live-but-foreign one must be reported
     * identically (-EBADF), or the errno enumerates other users' sockets. */
    rc = netstat(NETSTAT_SOCKET, 31, &sock, sizeof(sock));
    printf("PROBE netstat_sock_oob rc=%d\n", rc);

    rc = netstat(NETSTAT_SOCKET, 0, &sock, sizeof(sock));
    printf("PROBE netstat_sock0 rc=%d\n", rc);

    if (uid != 0) {
        /* An empty set, and a per-socket query that refuses identically
         * whether the descriptor is foreign or absent. The empty set is weak
         * evidence on its own (see the note above); the identical errno is
         * not, since it is what stops the error code enumerating the table. */
        if (list.visible_mask != 0) {
            printf("PROBE NETSTAT VERDICT leaked_mask\n");
            return 1;
        }
        /* Distinct verdict: an errno that separates "not yours" from "not
         * there" is the enumeration leak, and it needs its own name so the
         * harness reports the actual finding rather than a generic refusal. */
        if (rc != -EBADF) {
            printf("PROBE NETSTAT VERDICT leaked_errno rc=%d\n", rc);
            return 1;
        }
        printf("PROBE NETSTAT VERDICT scoped\n");
        return 0;
    }

    printf("PROBE NETSTAT VERDICT ok\n");
    return 0;
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

    /* Reported on its own line, and deliberately NOT folded into the verdict
     * below. The two cover unrelated gates -- the RX/TX euid check and the
     * SYS_NETSTAT ownership filter -- and combining them made a NETSTAT errno
     * leak print "PROBE VERDICT leaked", which reads as a raw-frame
     * escalation and sends the reader to the wrong subsystem. Each gate
     * reports its own finding; the exit status carries both. */
    int netstat_bad = netstat_probe(uid);
    int rxtx_bad;

    if (uid != 0) {
        /* The whole point of running unprivileged. Both must be refused, and
         * refused identically, so the errno leaks nothing about the ring. */
        rxtx_bad = !(tx_rc == -EPERM && received == 0);
        printf("PROBE VERDICT %s\n", rxtx_bad ? "leaked" : "denied");
    } else {
        rxtx_bad = !(tx_rc == (int)sizeof(probe_frame) && tx_short == -EINVAL);
        printf("PROBE VERDICT %s\n", rxtx_bad ? "broken" : "ok");
    }

    return (rxtx_bad || netstat_bad) ? 1 : 0;
}
