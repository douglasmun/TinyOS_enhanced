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
#define SYS_TCPSOCK 38

#define EPERM     1
#define EAGAIN    11
#define EINVAL    22
#define EBADF     9
#define EMFILE    24
#define EMSGSIZE  56
#define ENOTCONN  73

/* SYS_TCPSOCK subcommands and packed argument -- see syscall.h. */
#define TCPSOCK_SOCKET  0
#define TCPSOCK_CONNECT 1
#define TCPSOCK_SEND    2
#define TCPSOCK_RECV    3
#define TCPSOCK_CLOSE   4
#define TCPSOCK_ARG(subcmd, sockfd) \
    (((uint32_t)(subcmd) & 0xFFFFu) | (((uint32_t)(sockfd) & 0xFFFFu) << 16))
#define TCPSOCK_MAX_IO  1024

typedef struct {
    uint8_t  remote_ip[4];
    uint16_t remote_port;
    uint16_t _pad;
} tcpsock_connect_t;

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

static int tcpsock(unsigned int subcmd, int sockfd, void* buf, unsigned int len) {
    return syscall3(SYS_TCPSOCK, TCPSOCK_ARG(subcmd, sockfd),
                    (uint32_t)(uintptr_t)buf, (uint32_t)len);
}

/*=============================================================================
 * SYS_TCPSOCK probe (PR C2) -- the data path.
 *
 * This is the probe that can finally prove what C1's could not. C1 asserted
 * that an unprivileged caller sees an empty socket bitmap, which was TRUE of a
 * working ownership filter AND of a completely inert one, because the TCP table
 * is empty on a stock boot (DHCP and DNS use raw UDP and never call
 * tcp_socket()). A negative control that hollowed tcp_owner_visible() to
 * `return true` PASSED that harness.
 *
 * Here the caller OPENS a socket first. So the bitmap is non-zero for its owner
 * by construction, and an inert filter is no longer indistinguishable from a
 * working one -- it shows up as the wrong descriptor being visible, or as a
 * foreign descriptor answering instead of returning -EBADF.
 *
 * Every assertion below is reachable without a peer. The connect/send/recv
 * round trip is probed separately (see tcp_roundtrip_probe) because it needs
 * the network, and a probe that cannot distinguish "the gate is broken" from
 * "the internet is down" is not a security assertion.
 *===========================================================================*/
static int tcpsock_probe(int uid) {
    netstat_socklist_t list;
    netstat_socket_t sock;
    int bad = 0;
    int rc;

    int fd = tcpsock(TCPSOCK_SOCKET, 0, 0, 0);
    printf("PROBE tcpsock_socket fd=%d\n", fd);
    if (fd < 0) {
        printf("PROBE TCPSOCK VERDICT no_socket fd=%d\n", fd);
        return 1;
    }

    /* The socket we just opened must now appear in OUR bitmap. This is the
     * assertion C1 could not make: a zero here is a real failure, not an empty
     * table. An inert ownership filter cannot fake this one either -- it would
     * show every socket, including any the kernel owns. */
    rc = netstat(NETSTAT_SOCKLIST, 0, &list, sizeof(list));
    printf("PROBE tcpsock_ownmask rc=%d mask=%d fd=%d\n",
           rc, (int)list.visible_mask, fd);
    if (rc < 0 || !(list.visible_mask & (1u << fd))) {
        printf("PROBE TCPSOCK VERDICT own_socket_invisible\n");
        bad = 1;
    }

    /* A socket we own answers. */
    rc = netstat(NETSTAT_SOCKET, fd, &sock, sizeof(sock));
    printf("PROBE tcpsock_ownquery rc=%d state=%d\n", rc, (int)sock.state);
    if (rc < 0) {
        printf("PROBE TCPSOCK VERDICT own_socket_query_failed\n");
        bad = 1;
    }

    /* Argument validation on the write surface, all reachable with no peer.
     * Each must be REFUSED; a kernel that accepts any of these is one that
     * would act on an out-of-range descriptor or an unbounded length. */
    rc = tcpsock(TCPSOCK_SEND, 31, (void*)"x", 1);
    printf("PROBE tcpsock_send_oob rc=%d\n", rc);
    if (rc != -EBADF) bad = 1;

    rc = tcpsock(TCPSOCK_RECV, 31, &sock, sizeof(sock));
    printf("PROBE tcpsock_recv_oob rc=%d\n", rc);
    if (rc != -EBADF) bad = 1;

    rc = tcpsock(TCPSOCK_CLOSE, 31, 0, 0);
    printf("PROBE tcpsock_close_oob rc=%d\n", rc);
    if (rc != -EBADF) bad = 1;

    /* Oversized send is refused outright, never truncated: a short write the
     * caller believes was complete corrupts its own framing. */
    static unsigned char big[TCPSOCK_MAX_IO + 64];
    rc = tcpsock(TCPSOCK_SEND, fd, big, sizeof(big));
    printf("PROBE tcpsock_send_toobig rc=%d\n", rc);
    if (rc != -EMSGSIZE) bad = 1;

    /* Sending on a socket that was never connected must fail, not emit. */
    rc = tcpsock(TCPSOCK_SEND, fd, (void*)"x", 1);
    printf("PROBE tcpsock_send_unconnected rc=%d\n", rc);
    if (rc != -ENOTCONN) bad = 1;

    rc = tcpsock(99, fd, 0, 0);
    printf("PROBE tcpsock_badcmd rc=%d\n", rc);
    if (rc != -EINVAL) bad = 1;

    /*=====================================================================
     * The exclusion assertion -- the one that actually tests the filter.
     *
     * Everything above proves the caller can see its OWN socket. That is
     * necessary but proves nothing about exclusion, and exclusion is the
     * whole security property. A negative control confirmed it: an inert
     * tcp_owner_visible() that returns true for everything ALSO yields
     * mask=1 here, because only one socket exists at that moment.
     *
     * So the root pass deliberately LEAKS a socket -- opens one and does not
     * close it -- and the unprivileged pass that follows must not see it.
     * Now the two builds differ: a working filter reports only the caller's
     * own bit, an inert one reports the root-owned socket too.
     *
     * uid 0 leaks; everyone else audits. The leaked descriptor is a CLOSED
     * socket that never connects, so it holds no port and no buffer -- it
     * exists purely as a foreign table entry for the next run to not see.
     *===================================================================*/
    if (uid == 0) {
        int leak = tcpsock(TCPSOCK_SOCKET, 0, 0, 0);
        printf("PROBE tcpsock_leak fd=%d\n", leak);
        /* Deliberately NOT closed. */
    } else {
        /* A root-owned socket is live right now (leaked by the root pass).
         * It must be absent from our bitmap and must refuse our queries. */
        rc = netstat(NETSTAT_SOCKLIST, 0, &list, sizeof(list));
        unsigned int foreign = list.visible_mask & ~(1u << fd);
        printf("PROBE tcpsock_foreign rc=%d mask=%d foreign=%d\n",
               rc, (int)list.visible_mask, (int)foreign);
        if (foreign != 0) {
            printf("PROBE TCPSOCK VERDICT foreign_visible\n");
            return 1;
        }
    }

    rc = tcpsock(TCPSOCK_CLOSE, fd, 0, 0);
    printf("PROBE tcpsock_close rc=%d\n", rc);
    if (rc != 0) bad = 1;

    printf("PROBE TCPSOCK VERDICT %s\n", bad ? "broken" : "ok");
    return bad;
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
    int tcpsock_bad = tcpsock_probe(uid);
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

    return (rxtx_bad || netstat_bad || tcpsock_bad) ? 1 : 0;
}
