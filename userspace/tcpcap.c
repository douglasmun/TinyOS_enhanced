/*=============================================================================
 * tcpcap.c — ring-3 driver for TCP socket-table exhaustion by any user.
 *
 * SYS_TCPSOCK's TCPSOCK_SOCKET is ungated: any user may open a socket. The
 * table holds TCP_MAX_CONNECTIONS (8), there was no per-user limit, and a
 * socket left open when its task exited was never released -- nothing
 * reclaims a CLOSED socket. So one unprivileged user could take every slot,
 * exit, and leave the kernel (and root) without TCP until reboot.
 *
 * Leg "cap": open sockets until refused, then close them all.
 *
 *   PROBE cap opened=N refused=RC   fixed: opened=2, refused=-11 (EAGAIN)
 *
 * Leg "exit": spawn a child that opens until refused and exits WITHOUT
 * closing, then open until refused here. The child's sockets must have been
 * released by its exit, or this task's own cap -- same uid -- is already
 * spent and it opens none.
 *
 *   PROBE exit child=N opened=N   fixed: child=2, opened=2
 *
 * Both run unprivileged: root is exempt from the cap by design.
 *===========================================================================*/
#include "libc.h"

#define SELF "/tcpcap.elf"

#define SYS_TCPSOCK     38
#define TCPSOCK_SOCKET  0
#define TCPSOCK_CLOSE   4
#define TCPSOCK_ARG(subcmd, sockfd) \
    (((uint32_t)(subcmd) & 0xFFFFu) | (((uint32_t)(sockfd) & 0xFFFFu) << 16))

#define TRIES 10

static int tcpsock(unsigned int subcmd, int sockfd) {
    return syscall3(SYS_TCPSOCK, TCPSOCK_ARG(subcmd, sockfd), 0, 0);
}

/* Open until refused; return how many opened and store the refusal. */
static int open_all(int* fds, int* refused) {
    int n = 0;
    *refused = 0;
    while (n < TRIES) {
        int fd = tcpsock(TCPSOCK_SOCKET, 0);
        if (fd < 0) {
            *refused = fd;
            break;
        }
        fds[n++] = fd;
    }
    return n;
}

static void close_all(const int* fds, int n) {
    for (int i = 0; i < n; i++) {
        tcpsock(TCPSOCK_CLOSE, fds[i]);
    }
}

int main(int argc, char** argv) {
    int fds[TRIES], refused;

    if (argc > 1 && !strcmp(argv[1], "hold")) {
        /* Exit holding them; the count travels back as the exit status. */
        return open_all(fds, &refused);
    }

    int n = open_all(fds, &refused);
    close_all(fds, n);
    printf("PROBE cap opened=%d refused=%d\n", n, refused);

    char* const args[] = { SELF, "hold", 0 };
    int pid = spawn(SELF, args);
    int child = pid >= 0 ? waitpid(pid) : pid;
    n = open_all(fds, &refused);
    close_all(fds, n);
    printf("PROBE exit child=%d opened=%d refused=%d\n", child, n, refused);
    printf("PROBE done\n");
    return 0;
}
