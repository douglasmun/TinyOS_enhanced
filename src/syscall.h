/*=============================================================================
 * syscall.h - System Call Interface for User Mode Programs
 *============================================================================*/
#ifndef SYSCALL_H
#define SYSCALL_H

#include <stdint.h>
#include <stddef.h>

/*-----------------------------------------------------------------------------
 * System Call Numbers
 *-----------------------------------------------------------------------------*/
#define SYS_EXIT        0   // Exit process
#define SYS_WRITE       1   // Write to console
#define SYS_READ        2   // Read from console
#define SYS_GETPID      3   // Get process ID
#define SYS_YIELD       4   // Yield CPU

/* User/Group Management (v1.10) */
#define SYS_GETUID      5   // Get real user ID
#define SYS_GETGID      6   // Get real group ID
#define SYS_GETEUID     7   // Get effective user ID
#define SYS_GETEGID     8   // Get effective group ID
#define SYS_SETUID      9   // Set user ID (root only)
#define SYS_SETGID     10   // Set group ID (root only)
#define SYS_SETEUID    11   // Set effective user ID
#define SYS_SETEGID    12   // Set effective group ID

/* Cryptographic Operations (v1.13) */
#define SYS_CRYPTO     13   // Cryptographic operations (DH, RSA, etc.)

/* Blocking primitives (v2.2) */
#define SYS_SLEEP      17   // Sleep for N milliseconds (blocks, timer wake)
#define SYS_WAITPID    18   // Wait for a child process to exit

/* Process creation (v2.3) */
#define SYS_SPAWN      19   // Load an ELF and start it as a child process

/* File I/O (v2.4) — the foundation for a ring-3 shell. Until these existed a
 * user process could not open a file at all: sys_read/sys_write only accepted
 * fds 0/1/2. Descriptors returned here are PER-PROCESS indices (3+) into
 * task->fdtable, not global VFS fds. */
#define SYS_OPEN       20   // Open a file, returns a per-process fd (3+)
#define SYS_CLOSE      21   // Close a per-process fd
#define SYS_READDIR    22   // Read directory entries from a fd opened on a dir
#define SYS_STAT       23   // Metadata for a path, without opening it

/* SYS_LSEEK needed a VFS .seek op and a RAMFS implementation first, so that
 * it could not work on C: and fail on D:. Both now exist (ramfs_seek/tell/
 * fd_size, fat32_tell/fd_size), and whence is resolved in the driver because
 * only the driver holds the live position — see the .seek op in vfs.h. */
#define SYS_LSEEK      24   // Reposition an open fd's cursor

/* Namespace mutation. The drivers already had mkdir/rmdir/unlink, but the VFS
 * ops tables exposed none of them on FAT32 and no .unlink op existed at all,
 * so they were dead code reachable from nowhere. Exposing them to ring 3 also
 * required hardening fat32_unlink (it happily deleted directories and open
 * files) and rewriting fat32_rmdir (it was `return fat32_unlink(path)`, which
 * removed a directory's entry while leaking its whole cluster chain). */
#define SYS_MKDIR      25   // Create a directory
#define SYS_RMDIR      26   // Remove an empty directory
#define SYS_UNLINK     27   // Remove a file

/* Per-process working directory. Every path syscall above resolves a relative
 * path against the caller's cwd (task_resolve_path), so these two are what
 * make "open("foo.txt")" mean something other than the default drive root. */
#define SYS_GETCWD     28   // Read the caller's working directory
#define SYS_CHDIR      29   // Change the caller's working directory

/* Shell redirection: point one of the caller's standard streams at a file.
 *
 * NOT dup2(). POSIX dup2 copies one fd-table slot onto another, but fds 0/1/2
 * are deliberately NOT in this kernel's fdtable — they live in task->streams,
 * which is what already models console/file/pipe backing and what sys_spawn
 * inherits into a child (see the fdtable comment in process.h). A dup2 that
 * took an fd from SYS_OPEN would have to convert a VFS fd into a stream and
 * would still not compose with inheritance, so the honest primitive is the one
 * the stream layer actually has: rebind a standard stream to a path.
 *
 * Redirection therefore reaches a spawned child for free: the shell rebinds
 * its own stream, spawns, and restores. The child inherited the redirected
 * stream at spawn time. */
#define SYS_REDIRECT   30   // Point stdin/stdout/stderr at a file (or restore)

/* SYS_PIPE — create a pipe and bind one end to one of MY standard streams.
 *
 * Not POSIX pipe(int fd[2]), for the same reason SYS_REDIRECT is not dup2: the
 * ends a shell needs to connect are stdin and stdout, and those are not fds at
 * all. Handing userspace two fd numbers would mean inventing a way to turn an
 * fd back into a stream, which is exactly the conversion that does not exist.
 *
 * So the pipe is named by an opaque kernel-assigned ID instead, and the
 * operations are: create one bound to my stdout (the producer end), then bind
 * that same ID to another process's stdin by having the SHELL bind it to its
 * own stdin before spawning the consumer — inheritance carries it, the way it
 * already carries redirection.
 *
 * The pipe_buffer_t itself lives in KERNEL memory and is never mapped into any
 * user address space. Ring 3 only ever holds the ID, so a malicious ID is a
 * lookup failure (-EBADF), not a pointer. */
#define SYS_PIPE       31   // Create/bind/close a pipe between two processes

/* SYS_CRED — credential administration (passwd / useradd / userdel).
 *
 * The password NEVER crosses the ring boundary. Ring 3 names an operation and a
 * username; the KERNEL prints the prompts, reads the keystrokes into its own
 * buffer, applies the euid checks, and zeroes the buffer before returning. A
 * plaintext password is therefore never present in any user address space, in
 * argv, or in a syscall argument register.
 *
 * That is the whole reason this is not "let ring 3 read a password and pass it
 * down". A ring-3 buffer holding a plaintext password would be readable by
 * anything that later reuses those pages, would appear in a core-style dump of
 * the shell, and would have to survive an unbounded number of preemptions
 * between being typed and being hashed. Keeping it kernel-side means the only
 * copy lives for the length of one syscall and is wiped on every exit path.
 *
 * Authorization is NOT reimplemented here: the checks (own password vs another
 * user's, root-only creation/deletion, refusing to delete root, requiring the
 * current password from a non-root caller) already exist in shell_user.c and
 * are the same code the kernel shell uses. This syscall is a ring-3 entry point
 * to them, not a second copy of the policy. */
#define SYS_CRED       32   // passwd / useradd / userdel, prompts kernel-side

/* SYS_PSINFO — read the process table, filtered by the visibility policy.
 *
 * Returns an ARRAY OF RECORDS, not formatted text. The kernel decides WHAT the
 * caller may see; ring 3 decides how to print it. Returning preformatted lines
 * would put ps/top's column layout in the kernel and force every future format
 * change through a syscall change.
 *
 * THE FILTER IS THE POINT. The same rule ps and top apply in the kernel shell
 * (task_visible_to_current, in process.c so both callers share one copy) is
 * applied HERE, before anything is copied out: an unprivileged caller sees only their own tasks, root sees
 * all. Filtering in the kernel rather than in the ring-3 shell is what makes it
 * a policy instead of a convention -- a userspace filter is advice that any
 * program linking its own syscall stub can decline to follow.
 *
 * WHAT IS DELIBERATELY NOT IN THE RECORD: kernel/user stack addresses, page
 * directory physicals, the EDR anomaly score, the syscall-filter bitmap. Those
 * are in task_t and none of them belong in ring 3 -- the stack and page-table
 * addresses defeat ASLR outright (the same reason pae/mem/aslr/wxaudit became
 * root-only), and the EDR fields tell a probing process how close it is to
 * tripping detection. This struct is an allow-list, not task_t minus secrets.
 *
 * The count is bounded by what fits in the caller's buffer; a caller wanting
 * the whole table sizes it at MAX_TASKS. Returns BYTES written, like
 * SYS_READDIR, so a short buffer truncates rather than failing. */
#define SYS_PSINFO     33   // Process listing, filtered by visibility policy

/* SYS_KILL — terminate a process.
 *
 * Ring 3 previously had NO way to kill anything: `kill` existed only as a
 * kernel-shell command. Adding it alongside SYS_PSINFO is not optional --
 * a `ps` you can read but cannot act on would push users back to `kshell`,
 * and the two commands have to agree about which processes exist.
 *
 * SAME VISIBILITY RULE, SAME ANSWER. A PID the caller may not see is
 * reported as -ESRCH, exactly as a PID that does not exist. If this returned
 * -EPERM instead, `kill` would become the existence oracle that filtering
 * `ps` was meant to close: a user could sweep the PID space and learn every
 * live process from the errno alone.
 *
 * CAP_UNKILLABLE is enforced here as it is in the kernel shell, and
 * separately again in task_terminate -- the shell command is a convenience,
 * the syscall is the boundary, and neither is trusted to be the only check.
 *
 * No signal number: this kernel has no signals. The argument is a PID and the
 * action is unconditional termination. */
#define SYS_KILL       34   // Terminate a process, subject to the same policy

/* SYS_NETRX / SYS_NETTX — the packet-path boundary for the ring-3 network
 * daemon (doc/NETDAEMON_DESIGN.md, item 4 PR B).
 *
 * WHAT THESE ARE FOR. The end state is a ring-3 daemon running the ~8,350-line
 * L4 parser, with the kernel keeping only MMIO, DMA and the descriptor rings,
 * which need physical addresses and port access. These two calls are that
 * boundary and nothing more: dequeue one received frame, hand one frame to the
 * NIC. The parser's ENTIRE dependency on kernel services is e1000_send(), which
 * is why the packet path needs two syscalls rather than a subsystem.
 *
 * IN PR B THE PARSER HAS NOT MOVED. knetd still calls handle_packet() in the
 * kernel. These calls exist so the boundary can be proven to carry real traffic
 * BEFORE anything changes trust domain -- the exposure PR is separate and comes
 * after the audit. Nothing is exposed by adding them that is not already
 * reachable: a frame is bytes off the wire that the kernel parser already
 * accepts from any host on the segment.
 *
 * ROOT ONLY, DELIBERATELY. Both refuse for euid != 0. SYS_NETRX hands over raw
 * frames addressed to other services on the host, and SYS_NETTX forges the
 * source MAC and IP of anything it likes -- ARP poisoning, DHCP spoofing and
 * off-host traffic with no local account are all one call away. The daemon runs
 * as root; that is the whole population that should reach these. A capability
 * would be the better long-term answer and is noted in the design doc, but a
 * euid check is the honest version of "root only" today rather than a bespoke
 * mechanism invented at the same moment as its first user.
 *
 * NON-BLOCKING, DELIBERATELY. SYS_NETRX returns -EAGAIN on an empty ring rather
 * than sleeping. A blocking receive needs a wait queue whose wakeup is driven
 * from the ISR, and a lost wakeup there is a silently wedged network stack --
 * real complexity that belongs in the PR that needs it, not in the one whose
 * job is to prove the boundary works. The caller polls and yields, which is
 * exactly what knetd already does. The design doc records this as an open
 * question for the PR that moves the parser.
 *
 * arg1 = user buffer, arg2 = buffer length.
 * SYS_NETRX returns bytes copied, -EAGAIN if empty, -EMSGSIZE if the frame does
 * not fit (the frame is CONSUMED in that case -- see sys_netrx). */
#define SYS_NETRX      35   // Dequeue one received Ethernet frame (non-blocking)
#define SYS_NETTX      36   // Transmit one Ethernet frame

/*=============================================================================
 * SYS_NETSTAT -- read-only network state (doc/NETDAEMON_DESIGN.md PR C1)
 *
 * The query half of the socket API: seven kernel-only accessors (tcp_available,
 * tcp_is_connected, tcp_get_state, dns_is_resolved, dns_get_resolved_ip,
 * dhcp_is_configured, dhcp_get_client_info) plus the interface addresses, made
 * readable from ring 3. There is no write surface here -- nothing this syscall
 * reaches can open, send on, or close a connection.
 *
 * ONE syscall with a subcommand rather than seven, deliberately. Each separate
 * entry point would need its own credential check and its own bounds check;
 * seven of those is seven chances to omit one. This gates once, in one place.
 *
 * NOT euid-gated, unlike SYS_NETRX/SYS_NETTX. Those two hand over raw frames --
 * the whole segment's traffic -- so they are root-only. These report the
 * caller's OWN sockets, and the access control is ownership rather than
 * privilege: tcp_owner_visible() filters per socket, root sees all. Gating on
 * euid instead would make the ring-3 shell unable to see its own connections,
 * which is the point of the syscall.
 *
 * The syscall ABI carries three registers (ebx/ecx/edx) and this call wants
 * four values, so the subcommand and the sockfd share arg1: subcmd in the low
 * 16 bits, sockfd in the high 16. Build it with NETSTAT_ARG().
 *
 * arg1 = NETSTAT_ARG(subcmd, sockfd), arg2 = user buffer receiving a
 * fixed-size struct, arg3 = buffer length.
 * Structs are copied out by value; no kernel pointer crosses the boundary --
 * dhcp_get_client_info returns a pointer INTO kernel state and must never be
 * handed over as one.
 *
 * A socket the caller cannot see is reported as nonexistent (-EBADF), never
 * -EPERM -- the ps/kill policy, for the same reason: -EPERM on a live socket
 * and -EBADF on a dead one lets a caller enumerate other users' sockets
 * through the error code alone. */
#define SYS_NETSTAT    37   // Read-only network state; ownership-filtered

/*=============================================================================
 * SYS_TCPSOCK -- the socket data path (doc/NETDAEMON_DESIGN.md PR C2)
 *
 * The WRITE half of the socket API, and the counterpart to SYS_NETSTAT's
 * read-only queries: socket/connect/send/recv/close. This is the first time
 * ring 3 can make the kernel emit an attacker-chosen TCP payload, so every
 * primitive it reaches was audited in this same PR (the #45/#47/#54/#55 rule).
 * That audit found two live bugs, both fixed here rather than in a follow-up:
 * tcp_socket()'s TIME_WAIT eviction retry never stamped owner_uid (sockets came
 * back root-owned), and tcp_recv() read in_use/state/rx_head/rx_tail OUTSIDE
 * TCP_LOCK, so a torn head/tail pair could hand the copy loop a bogus length.
 *
 * ONE syscall with a subcommand, for the reason SYS_NETSTAT gives: five entry
 * points is five chances to omit a credential or bounds check.
 *
 * Ownership-gated, not euid-gated -- same polarity as SYS_NETSTAT and the
 * OPPOSITE of SYS_NETRX/SYS_NETTX. An unprivileged caller MUST be able to open
 * and drive its own sockets; that is the point. tcp_owner_visible() is checked
 * on every subcommand that names an existing sockfd, and a socket the caller
 * cannot see is -EBADF, never -EPERM, so the errno cannot enumerate the table.
 *
 * The ownership check lives HERE rather than inside tcp_send/tcp_recv/tcp_close
 * deliberately: the kernel's own callers (curl, tcp_tick, the IRQ-path
 * receiver) run with no current task or as root and must not be filtered. The
 * primitive stays uid-blind; the boundary is where the credential exists.
 *
 * arg1 = TCPSOCK_ARG(subcmd, sockfd), arg2 = user buffer, arg3 = length.
 * CONNECT takes a tcpsock_connect_t in the buffer; SEND/RECV take raw bytes;
 * SOCKET and CLOSE take no buffer.
 *
 * RECV is NON-BLOCKING, matching SYS_NETRX. It returns the byte count, 0 when
 * nothing is queued or the peer closed and the buffer is drained, and a
 * negative errno on a dead socket. A blocking variant needs an ISR-driven wait
 * queue, where one lost wakeup wedges the stack with no diagnostic; that is a
 * separate PR, not a flag on this one. */
#define SYS_TCPSOCK    38   // Socket data path; ownership-filtered

/* SYS_TCPSOCK subcommands. */
#define TCPSOCK_SOCKET     0   // Allocate a socket; returns the descriptor
#define TCPSOCK_CONNECT    1   // Connect to remote (tcpsock_connect_t in buf)
#define TCPSOCK_SEND       2   // Send bytes on an ESTABLISHED socket
#define TCPSOCK_RECV       3   // Non-blocking receive; 0 = nothing queued/EOF
#define TCPSOCK_CLOSE      4   // Close a socket the caller owns

/* Same packing as NETSTAT_ARG: subcmd low 16, sockfd high 16. */
#define TCPSOCK_ARG(subcmd, sockfd) \
    (((uint32_t)(subcmd) & 0xFFFFu) | (((uint32_t)(sockfd) & 0xFFFFu) << 16))
#define TCPSOCK_SUBCMD(a)  ((uint32_t)(a) & 0xFFFFu)
#define TCPSOCK_SOCKFD(a)  ((int)(((uint32_t)(a) >> 16) & 0xFFFFu))

/* Largest payload one SEND/RECV may carry. Bounds the kernel staging buffer;
 * a caller asking for more is refused, not silently truncated. */
#define TCPSOCK_MAX_IO     1024

/*-----------------------------------------------------------------------------
 * SYS_TIME — read the wall clock and the uptime counter.
 *
 * Read-only on purpose. time_set_datetime() exists and is deliberately NOT
 * reachable from here: the RTC is global machine state, so a setter needs a
 * privilege check, and `date` has never had a set path to justify one. Adding
 * the write direction is a separate decision with its own audit -- don't fold
 * it in because the underlying function happens to be available.
 *
 * arg1 = user buffer receiving a systime_t, arg2 = sizeof that buffer.
 * Ungated: the clock is not a secret, and every user can already observe time
 * passing. Returns 0, or -EFAULT / -EINVAL.
 *---------------------------------------------------------------------------*/
#define SYS_TIME       39   // Wall clock + uptime; read-only, unprivileged

typedef struct {
    uint8_t  remote_ip[4];
    uint16_t remote_port;
    uint16_t _pad;
} tcpsock_connect_t;

/* SYS_NETSTAT subcommands. */
#define NETSTAT_IFACE      0   // Interface addresses (ip/mask/gateway/mac)
#define NETSTAT_DHCP       1   // DHCP lease state, by value
#define NETSTAT_DNS        2   // Last DNS resolution result
#define NETSTAT_SOCKET     3   // One socket's state, if visible to the caller
#define NETSTAT_SOCKLIST   4   // Visible socket descriptors as a bitmap

/* subcmd in the low 16 bits, sockfd in the high 16. The sockfd is masked back
 * to a signed int by NETSTAT_SOCKFD; a value above TCP_MAX_CONNECTIONS is
 * rejected downstream by tcp_snapshot(), so a caller cannot smuggle a negative
 * index through the high half. */
#define NETSTAT_ARG(subcmd, sockfd) \
    (((uint32_t)(subcmd) & 0xFFFFu) | (((uint32_t)(sockfd) & 0xFFFFu) << 16))
#define NETSTAT_SUBCMD(a)  ((uint32_t)(a) & 0xFFFFu)
#define NETSTAT_SOCKFD(a)  ((int)(((uint32_t)(a) >> 16) & 0xFFFFu))

/*=============================================================================
 * SYS_NETSTAT payload structs.
 *
 * Fixed layout, no pointers, no padding-dependent fields. Each is copied out
 * whole; the caller passes sizeof() as arg4 and a mismatch is -EINVAL, so
 * adding a field is a visible break rather than a silent short read.
 *===========================================================================*/
typedef struct {
    uint8_t ip[4];
    uint8_t netmask[4];
    uint8_t gateway[4];
    uint8_t mac[6];
    uint8_t _pad[2];
} netstat_iface_t;

/* Deliberately NOT the whole dhcp_client_t. That struct carries the DHCP
 * transaction id, which is exactly the value needed to forge a reply into an
 * in-flight exchange, and there is no reason an unprivileged caller learns it.
 * The server IP and lease timings below are facts a client legitimately
 * reports; xid is not among them. */
typedef struct {
    uint32_t configured;       // bool widened, for a stable layout
    uint32_t state;            // dhcp_state_t widened
    uint8_t  server_ip[4];
    uint8_t  dns_server[4];
    uint32_t lease_time;
    uint32_t lease_start;
    uint32_t renewal_time;
} netstat_dhcp_t;

typedef struct {
    uint32_t resolved;         // bool widened
    uint8_t  ip[4];
} netstat_dns_t;

typedef struct {
    uint32_t state;            // tcp_state_t widened
    uint32_t connected;        // bool widened
    uint32_t available;        // bytes pending in the RX buffer
    uint8_t  remote_ip[4];
    uint16_t local_port;
    uint16_t remote_port;
} netstat_socket_t;

/* Bitmap of socket descriptors visible to the caller: bit N set means sockfd N
 * is in use AND passes tcp_owner_visible(). A bitmap rather than a count,
 * because a bare count of foreign sockets would state how many are being
 * withheld -- the same leak the ps totals had. */
typedef struct {
    uint32_t visible_mask;
} netstat_socklist_t;

/*=============================================================================
 * PHASE 2: Capability-Based Privilege Operations (v1.14)
 *
 * REVOLUTIONARY SECURITY: Eliminate setuid binaries entirely
 *
 * TRADITIONAL UNIX/LINUX WEAKNESS:
 * - Privileged operations require setuid binaries (/bin/passwd, /bin/su, /bin/mount)
 * - Setuid bit makes binary run with root privileges regardless of caller
 * - Accounts for 90% of privilege escalation exploits:
 *   * Buffer overflows in setuid binaries = instant root
 *   * Path injection attacks (PATH=/tmp sudo)
 *   * LD_PRELOAD attacks to hijack library functions
 *   * Race conditions in temp file handling
 * - Examples: Dirty COW, Polkit, sudo vulnerabilities
 *
 * TINYOS INNOVATION: Capability-Based Syscalls
 * - NO setuid binaries anywhere in the system
 * - Privileged operations implemented as kernel syscalls with explicit authentication
 * - Each operation validates credentials at the kernel level
 * - Eliminates entire class of vulnerabilities:
 *   * No buffer overflow escalation (kernel validates, not userspace binary)
 *   * No path injection (kernel has no PATH environment variable)
 *   * No LD_PRELOAD attacks (kernel doesn't load libraries)
 *   * No temp file races (kernel operates on kernel data structures)
 *
 * SECURITY BENEFITS:
 * - Attack surface reduced by ~90% (no more vulnerable setuid binaries)
 * - Explicit authentication for each privileged operation
 * - Kernel-level validation (harder to exploit than userspace)
 * - Audit trail for all privilege operations
 * - Principle of least privilege (only grant capability for specific operation)
 *===========================================================================*/
#define SYS_CHANGE_PASSWORD  14  // Change user password (replaces /bin/passwd)
#define SYS_SWITCH_USER      15  // Switch to another user (replaces /bin/su)

/*=============================================================================
 * DEPRECATED FROM RING 3: SYS_CHANGE_PASSWORD (14) and SYS_SWITCH_USER (15)
 *
 * Both take a PLAINTEXT PASSWORD through a syscall argument register, which is
 * exactly the exposure SYS_CRED (32) was built to remove: there the kernel
 * prompts and reads the keystrokes itself, so a password never enters a user
 * address space, an argv, or a register at all. A ring-3 caller of these two
 * must hold the plaintext to make the call, so the class cannot be fixed
 * without changing the interface.
 *
 * The DISPATCHER CASES are therefore refused with -ENOSYS by default. The
 * C functions remain and stay fully supported for KERNEL callers — the kernel
 * shell's `su` (shell_user.c) calls sys_switch_user() directly, not through
 * int 0x80, so it is unaffected.
 *
 * Build -DTINYOS_LEGACY_CRED_SYSCALLS to re-enable ring-3 dispatch. Like every
 * other build flag in this tree it is an explicitly named opt-out, never a
 * default. Even then the calls are now policy-enforcing (see below), so the
 * opt-in restores reachability, NOT the vulnerabilities.
 *===========================================================================*/

/*=============================================================================
 * PHASE 14: Memory Sealing Syscall (Modern Linux 2024 Feature)
 *
 * TRADITIONAL ATTACK VECTOR:
 * - Attacker exploits vulnerability to call mprotect(code_page, PROT_WRITE)
 * - Modifies .text section to inject shellcode or disable mitigations
 * - ROP/JOP attacks by modifying return addresses in code
 *
 * MODERN DEFENSE:
 * - mseal() permanently locks memory region against modifications
 * - Once sealed, NO operation can modify page table entries
 * - Protects against: mprotect, munmap, mremap, madvise
 * - Even root cannot unseal pages
 *
 * USAGE:
 *   mseal(code_start, code_size);  // Seal .text section after program load
 *
 * SECURITY GUARANTEE:
 * - Sealed pages remain immutable until process termination
 * - Prevents code modification attacks
 * - Enables control-flow integrity (CFI)
 *===========================================================================*/
#define SYS_MSEAL            16  // Seal memory region (make immutable)

/* Crypto operation types */
#define CRYPTO_OP_MODEXP  1  // Modular exponentiation for DH

/*-----------------------------------------------------------------------------
 * SECURITY (v1.11): Maximum syscall number for range validation
 * Update this whenever adding new syscalls
 *-----------------------------------------------------------------------------*/
/* Must cover the HIGHEST number defined above, not the highest in this block:
 * SYS_SLEEP (17) and SYS_WAITPID (18) are declared further up and have working
 * dispatcher cases, but this bound stayed at 16 when they were added, so the
 * range check rejected both before dispatch and userspace could never block. */
#define MAX_SYSCALL_NUM  39  // Highest valid syscall number (SYS_TIME)

/*-----------------------------------------------------------------------------
 * SYS_PSINFO record. One per visible task; see the SYS_PSINFO comment above for
 * why this is an allow-list rather than a redacted task_t.
 *
 * Fixed-width fields and a fixed name length so the layout is identical on both
 * sides of the ring boundary without a packing attribute: 4-byte members first,
 * then the 2-byte pair, then the char array. uid is included because `ps -l`
 * shows an owner column and root needs it to be useful; an unprivileged caller
 * only ever receives records whose uid is already their own.
 *---------------------------------------------------------------------------*/
#define PSINFO_NAME_LEN 32

typedef struct {
    uint32_t pid;
    uint32_t ppid;
    uint32_t state;          /* task_state_t, widened for a stable ABI */
    uint32_t total_ticks;
    uint32_t time_slice;
    uint32_t capabilities;   /* CAP_* -- ps prints the [PROTECT] marker */
    uint16_t uid;
    uint16_t priority;
    uint8_t  is_kernel_task;
    uint8_t  reserved[3];    /* Explicit: keeps the struct 4-byte aligned and
                              * zeroed rather than leaking padding to ring 3. */
    char     name[PSINFO_NAME_LEN];
} psinfo_t;

/* The layout is an ABI: userspace/libc.h declares a byte-identical copy and the
 * kernel memcpys records straight into a ring-3 buffer. Nothing at runtime
 * checks the two agree, so a field added on one side only would silently shift
 * every subsequent field in the listing. These assertions turn that into a
 * build failure; update libc.h and these numbers together, never separately. */
_Static_assert(sizeof(psinfo_t) == 64, "psinfo_t layout changed: update userspace/libc.h to match");
_Static_assert(offsetof(psinfo_t, uid) == 24, "psinfo_t.uid moved: update userspace/libc.h to match");
_Static_assert(offsetof(psinfo_t, name) == 32, "psinfo_t.name moved: update userspace/libc.h to match");

/*-----------------------------------------------------------------------------
 * SYS_TIME record.
 *
 * NOT datetime_t. That struct is 9 bytes of mixed uint16/uint8 whose tail
 * padding the compiler is free to choose, and copying it straight out would
 * hand ring 3 those uninitialised bytes. This is a widened, explicitly padded
 * copy built field by field, on the same "allow-list, not a redacted kernel
 * struct" principle as psinfo_t above.
 *
 * uptime_seconds rides along because `date` prints it and a second syscall to
 * fetch one uint32 would be gratuitous.
 *---------------------------------------------------------------------------*/
typedef struct {
    uint32_t uptime_seconds;
    uint16_t year;
    uint8_t  month;          /* 1-12 */
    uint8_t  day;            /* 1-31 */
    uint8_t  hour;           /* 0-23 */
    uint8_t  minute;         /* 0-59 */
    uint8_t  second;         /* 0-59 */
    uint8_t  weekday;        /* 0 = Sunday */
} systime_t;

/* Same ABI contract as psinfo_t: userspace/libc.h carries a byte-identical
 * copy and nothing at runtime checks they agree. */
_Static_assert(sizeof(systime_t) == 12, "systime_t layout changed: update userspace/libc.h to match");
_Static_assert(offsetof(systime_t, year) == 4, "systime_t.year moved: update userspace/libc.h to match");

/*=============================================================================
 * PHASE 11: NO chroot() Syscall (Security-by-Omission)
 *
 * TRADITIONAL UNIX/LINUX WEAKNESS:
 * chroot() changes apparent root directory but is fundamentally broken:
 *
 * SECURITY ISSUES:
 * 1. **Double chroot() escape**:
 *    chroot("/jail"); chroot("../../.."); → escapes jail
 *
 * 2. **Doesn't change working directory**:
 *    chdir("/"); chroot("/jail"); fchdir(saved_fd); → still outside jail
 *
 * 3. **Requires root to call**:
 *    If you're root, you can escape anyway (mknod, ptrace, /proc, etc.)
 *
 * 4. **File descriptor leaks**:
 *    Open FDs outside jail remain accessible after chroot
 *
 * 5. **Mount namespace not isolated**:
 *    Can mount new filesystems to escape
 *
 * HISTORICAL EXPLOITS:
 * - BSD chroot escape (1991): Double chroot to parent directory
 * - Linux chroot + pivot_root escape
 * - Schroot privilege escalation (CVE-2017-2616)
 * - Dozens of container escapes via chroot weaknesses
 *
 * TINYOS INNOVATION:
 * - NO chroot() syscall implemented
 * - No false sense of security from weak jails
 * - Future: Implement proper namespaces/containers instead
 *   (separate PID, mount, network, IPC namespaces)
 *
 * SECURITY BENEFITS:
 * - No chroot escape vulnerabilities
 * - Developers can't rely on broken security model
 * - Forces use of proper containerization (when implemented)
 * - Clear distinction: No isolation = no false assumptions
 *
 * ALTERNATIVE APPROACHES (not yet implemented):
 * - Linux-style namespaces (proper isolation)
 * - FreeBSD jails (more secure than chroot)
 * - Capability-based confinement
 *
 * This is a PERMANENT decision. chroot() will NEVER be implemented.
 * Proper containerization will be added via namespaces in the future.
 *===========================================================================*/
/* #define SYS_CHROOT  <NEVER>  -- EXPLICITLY NOT IMPLEMENTED */

/*-----------------------------------------------------------------------------
 * System Call Handler (called from interrupt)
 *-----------------------------------------------------------------------------*/
void syscall_handler(void);

/*-----------------------------------------------------------------------------
 * IDT Setup for System Calls
 *-----------------------------------------------------------------------------*/
void idt_setup_syscall(void);

/*-----------------------------------------------------------------------------
 * Kernel-side System Call Implementations
 *-----------------------------------------------------------------------------*/
void sys_exit(int status);
int sys_write(int fd, const char* buf, size_t len);
/* fd is honoured and must be STDIN_FILENO; both route through the calling
 * task's stream_context_t rather than the console/keyboard directly. */
int sys_read(int fd, char* buf, size_t len);
int sys_getpid(void);
void sys_yield(void);
int sys_sleep(uint32_t ms);
int sys_waitpid(int pid);

/**
 * @brief Load an ELF from the filesystem and start it as a child process
 *
 * @param user_path User pointer to a NUL-terminated path
 * @param user_argv User pointer to a NULL-terminated char* array, or NULL
 * @return Child PID (> 0) on success, negative errno on failure
 *
 * Does not block. The child inherits the caller's streams and is recorded as
 * its child, so waitpid() on the returned PID works. All user memory is copied
 * in before use.
 */
int sys_spawn(const char* user_path, char* const* user_argv);

/**
 * @brief Open a file or directory, returning a per-process fd
 *
 * @param user_path User pointer to a NUL-terminated path ("/f.txt", "C:/F.TXT")
 * @param flags VFS_O_* flags; VFS_O_DIRECTORY opens a directory for readdir
 * @return Per-process fd (>= TASK_FD_BASE) on success, negative errno on failure
 *
 * The returned descriptor indexes task->fdtable, NOT the global VFS fd pool —
 * ring 3 never learns a global fd number. The path is copied in before use.
 */
int sys_open(const char* user_path, int flags);

/**
 * @brief Close a per-process fd
 * @param fd Per-process fd from sys_open
 * @return 0 on success, negative errno on failure
 */
int sys_close(int fd);

/**
 * @brief Read directory entries into a user buffer
 *
 * @param fd Per-process fd opened with VFS_O_DIRECTORY
 * @param user_buf User pointer receiving an array of vfs_dirent_t
 * @param size Size of user_buf in bytes
 * @return Bytes written (a multiple of sizeof(vfs_dirent_t)), 0 at end of
 *         directory, or negative errno
 */
int sys_readdir(int fd, void* user_buf, uint32_t size);

/**
 * @brief Metadata for a path, without opening it
 * @param user_path User-space path pointer (drive-qualified or not)
 * @param user_buf User-space buffer receiving one vfs_dirent_t
 * @param size Buffer size; must be at least sizeof(vfs_dirent_t)
 * @return 0 on success, negative errno on failure
 */
int sys_stat(const char* user_path, void* user_buf, uint32_t size);

/**
 * @brief Reposition an open fd's read/write cursor
 * @param fd Per-process fd (3+) from SYS_OPEN
 * @param offset Signed displacement, interpreted per `whence`
 * @param whence SEEK_SET / SEEK_CUR / SEEK_END (VFS_SEEK_* values)
 * @return Resulting absolute position, or negative errno
 *
 * Seeking past EOF clamps to the file size on both drives rather than
 * creating a sparse region — neither driver can represent a hole.
 */
int sys_lseek(int fd, int32_t offset, int whence);

/* Path-based namespace mutation. Each copies the path into kernel memory
 * first (copy_string_from_user) and then delegates to the VFS, which applies
 * the protected-path capability check before reaching a driver. */
int sys_mkdir(const char* user_path);
int sys_rmdir(const char* user_path);
int sys_unlink(const char* user_path);

/**
 * @brief Copy the caller's cwd out to userspace.
 *
 * Writes the absolute, drive-qualified cwd ("D:/scratch") including its NUL.
 *
 * @param user_buf Destination in the caller's address space
 * @param size     Size of user_buf
 * @return Bytes written excluding the NUL, -ERANGE if the cwd does not fit
 */
int sys_getcwd(char* user_buf, uint32_t size);

/**
 * @brief Read the process table, filtered by the visibility policy.
 *
 * Fills user_buf with psinfo_t records for the tasks the CALLER may see:
 * their own if unprivileged, all of them if euid 0. Terminated slots are
 * always skipped.
 *
 * @param user_buf Destination array of psinfo_t in the caller's address space
 * @param size     Size of user_buf in BYTES (not records)
 * @return Bytes written (a whole multiple of sizeof(psinfo_t)), or -EINVAL /
 *         -EFAULT / -ESRCH. A buffer too small to hold every visible task
 *         truncates rather than failing.
 */
int sys_psinfo(void* user_buf, uint32_t size);

/**
 * @brief Terminate a process, subject to the visibility policy.
 *
 * A PID the caller may not see is reported as -ESRCH, identically to a PID
 * that does not exist, so kill cannot be used to enumerate live PIDs that
 * SYS_PSINFO hides.
 *
 * @param pid Target process ID
 * @return 0 on success, -ESRCH if absent or not visible, -EPERM if the target
 *         holds CAP_UNKILLABLE, -EINVAL for a non-positive pid
 */
int sys_kill(int pid);
int sys_time(void* user_buf, uint32_t size);

/**
 * SYS_NETRX / SYS_NETTX — raw Ethernet frames across the ring boundary.
 * Root only; non-blocking. See the SYS_NETRX comment block above and
 * doc/NETDAEMON_DESIGN.md.
 *
 * @return netrx: bytes copied, -EAGAIN if the ring is empty, -EMSGSIZE if the
 *         frame did not fit (it is dropped, not left to wedge the ring).
 *         nettx: bytes sent, -EMSGSIZE if too long, -EINVAL if shorter than an
 *         Ethernet header. Both: -EPERM if euid != 0, -EFAULT on a bad buffer.
 */
int sys_netrx(void* user_buf, size_t len);
int sys_nettx(const void* user_buf, size_t len);
int sys_netstat(uint32_t subcmd, int sockfd, void* user_buf, size_t len);
int sys_tcpsock(uint32_t subcmd, int sockfd, void* user_buf, size_t len);

/**
 * @brief Change the caller's cwd.
 *
 * @param user_path Absolute or relative path, optionally drive-qualified
 * @return 0 on success, -ENOENT/-ENOTDIR/-EACCES on failure
 */
int sys_chdir(const char* user_path);

/*-----------------------------------------------------------------------------
 * SYS_REDIRECT modes. Passed in arg3; the target stream is arg1 and the path
 * is arg2 (ignored, and may be NULL, for REDIR_MODE_RESTORE).
 *---------------------------------------------------------------------------*/
#define REDIR_MODE_TRUNC    0   /* stdout/stderr: create or truncate  ('>')  */
#define REDIR_MODE_APPEND   1   /* stdout/stderr: create or append    ('>>') */
#define REDIR_MODE_READ     2   /* stdin: open an existing file       ('<')  */
#define REDIR_MODE_RESTORE  3   /* put the stream back on the console        */

/**
 * @brief Point one of the caller's standard streams at a file, or restore it.
 *
 * This is the ring-3 half of shell redirection. See the SYS_REDIRECT comment
 * above for why this is not dup2().
 *
 * A restore is always available to the caller and never fails on a missing
 * path, so a shell can unconditionally restore in its cleanup path after a
 * failed redirect without having to track what it managed to change.
 *
 * stderr may be RESTORED but not redirected to a file (-ENOSYS): the stream
 * layer has no stderr_redirect_to_file and no shell parses `2>` yet.
 *
 * Only the RAMFS drive (D:) can be a redirect target. STREAM_TYPE_FILE is
 * hard-wired to RAMFS, so a path on another drive is refused with -EXDEV
 * rather than silently opened on D:.
 *
 * @param fd    STDIN_FILENO or STDOUT_FILENO (STDERR_FILENO: restore only)
 * @param user_path Path to open; unused when mode is REDIR_MODE_RESTORE
 * @param mode  One of the REDIR_MODE_* values above
 * @return 0 on success, -EBADF for a non-standard fd, -EINVAL for a bad mode
 *         or a direction that does not match the stream, -EXDEV for a non-D:
 *         path, -ENOSYS for redirecting stderr, -ENOENT if the open failed
 */
int sys_redirect(int fd, const char* user_path, int mode);

/*-----------------------------------------------------------------------------
 * SYS_PIPE operations. Passed in arg1; arg2 is the pipe ID (ignored by CREATE,
 * which returns a fresh one).
 *
 * The lifecycle a shell drives for `producer | consumer`:
 *
 *   id = pipe(PIPE_OP_CREATE)     bind MY stdout to a new pipe's write end
 *   spawn(producer)               inherits the bound stdout
 *   pipe(PIPE_OP_UNBIND_STDOUT,id) MY stdout back to the console
 *   pipe(PIPE_OP_BIND_STDIN, id)  bind MY stdin to the same pipe's read end
 *   spawn(consumer)               inherits the bound stdin, console stdout
 *   pipe(PIPE_OP_RESTORE, id)     put MY OWN stdin/stdout back on the console
 *   waitpid(producer)
 *   pipe(PIPE_OP_CLOSE_WRITE, id) the consumer's read() can now see EOF
 *   waitpid(consumer)
 *   pipe(PIPE_OP_DESTROY, id)     free the buffer and the wait-queue page
 *
 * UNBIND_STDOUT is not a convenience. Because a child inherits the shell's
 * streams AS THEY ARE AT SPAWN TIME, a stdout still bound to the write end when
 * the consumer is spawned makes the consumer write its output into the very
 * pipe it is reading — the data never reaches the console and, worse, the
 * consumer feeds itself. RESTORE cannot do this job: it resets BOTH streams,
 * and stdin must stay on the read end across the consumer's spawn.
 *
 * CLOSE_WRITE is the step with no safe default: until it runs, a consumer that
 * has drained the buffer BLOCKS rather than seeing end-of-input, because more
 * data could still arrive. Nothing in task teardown closes it — a dying task's
 * inherited streams are marked borrowed precisely so they do not touch the
 * creator's resources — so the shell must call it after reaping the producer.
 *---------------------------------------------------------------------------*/
#define PIPE_OP_CREATE         0  /* new pipe, bind write end to my stdout   */
#define PIPE_OP_BIND_STDIN     1  /* bind the read end to my stdin           */
#define PIPE_OP_CLOSE_WRITE    2  /* producer is done: readers now see EOF   */
#define PIPE_OP_RESTORE        3  /* my own stdin+stdout back to the console */
#define PIPE_OP_DESTROY        4  /* release the pipe                        */
#define PIPE_OP_UNBIND_STDOUT  5  /* my stdout only, back to the console     */

/**
 * @brief Create a pipe, bind it to one of the caller's streams, or release it.
 *
 * Not POSIX pipe(): see the SYS_PIPE comment above for why two fds cannot
 * express this. The pipe is named by an opaque ID and the buffer stays in
 * kernel memory, so ring 3 never holds a pointer to it.
 *
 * A pipe is owned by the process that created it, and only that process may
 * operate on it. That is what makes an ID safe to hand out: another process
 * guessing an ID gets -EPERM, not somebody else's data stream.
 *
 * @param op One of the PIPE_OP_* values above
 * @param id Pipe ID from a previous CREATE; ignored by CREATE itself
 * @return CREATE returns a positive pipe ID; the others return 0 on success.
 *         -EMFILE if no pipe slot is free, -ENOMEM if the buffer could not be
 *         allocated, -EBADF for an unknown ID, -EPERM for another process's
 *         pipe, -EINVAL for an unknown op.
 */
int sys_pipe(int op, int id);

/*-----------------------------------------------------------------------------
 * SYS_CRED operations. arg1 is the op; arg2 is a user pointer to a NUL-
 * terminated username (may be NULL for CRED_OP_PASSWD, meaning "my own").
 *
 * The password is read by the KERNEL, from the keyboard, into a kernel buffer.
 * Ring 3 never sees it and never supplies it — see the SYS_CRED comment above
 * for why that is the point rather than an inconvenience.
 *---------------------------------------------------------------------------*/
#define CRED_OP_PASSWD   0  /* change a password (own, or another's as root) */
#define CRED_OP_USERADD  1  /* create a user (root only)                     */
#define CRED_OP_USERDEL  2  /* delete a user (root only, never root itself)  */

/**
 * @brief Administer credentials from ring 3, with prompts handled kernel-side.
 *
 * Delegates to the same shell_user.c implementations the kernel shell uses, so
 * the authorization policy has exactly one definition. The only thing added
 * here is the ring-3 entry point: argument validation, a bounded copy of the
 * username out of user memory, and routing the command's output to the caller's
 * stream rather than the kernel console.
 *
 * @param op        One of the CRED_OP_* values
 * @param user_name User pointer to a NUL-terminated username, or NULL for
 *                  CRED_OP_PASSWD to mean the calling user
 * @return 0 on success, -EPERM if the caller's euid is not permitted the
 *         operation, -EINVAL for an unknown op or a missing required name,
 *         -ENAMETOOLONG if the username exceeds USER_MAX_USERNAME, -EFAULT if
 *         the username pointer is not readable, -ESRCH if no such user.
 */
int sys_cred(int op, const char* user_name);

/*-----------------------------------------------------------------------------
 * Record a process death and wake every sys_waitpid() waiter.
 *
 * sys_exit calls this on the clean-exit path. task_terminate MUST call it too:
 * a process killed externally (kill, #PF, guard-page hit) never runs sys_exit,
 * and since waiters now BLOCK on a wait queue instead of polling every tick,
 * an unwoken waiter would hang forever rather than merely noticing late.
 *
 * Takes its own critical section (they nest), so callers already inside one —
 * such as sys_exit's cleanup window — can call it directly.
 *---------------------------------------------------------------------------*/
void waitpid_notify_death(uint32_t pid, uint32_t generation, int status);

/* User/Group Management Syscalls (v1.10) */
uint16_t sys_getuid(void);
uint16_t sys_getgid(void);
uint16_t sys_geteuid(void);
uint16_t sys_getegid(void);
int sys_setuid(uint16_t uid);
int sys_setgid(uint16_t gid);
int sys_seteuid(uint16_t euid);
int sys_setegid(uint16_t egid);

/* Cryptographic Syscalls (v1.13) */
int sys_crypto(int op, void* arg1, void* arg2, void* arg3, void* arg4);

/* Capability-Based Privilege Syscalls (v1.14).
 *
 * Ring-3 dispatch is DEPRECATED (see the SYS_CHANGE_PASSWORD block above); both
 * remain first-class entry points for kernel callers such as the kernel shell's
 * `su`. Both enforce the account-lockout and locked/inactive policy themselves
 * rather than assuming a caller checked first. */
int sys_change_password(const char* old_password, const char* new_password);
int sys_switch_user(const char* username, const char* password);

/* Variant of sys_switch_user for a caller that has ALREADY authenticated the
 * target through the user_authenticate() family this instant — it performs the same
 * lock/active re-checks and the switch, but skips the second password
 * verification. Exists so the kernel shell's `su` does not pay PBKDF2 twice
 * (100k iterations, and slow under TCG) for one interactive login. The password
 * is still required and still verified by the caller; this is a cost
 * optimisation, not an authentication bypass, and nothing reachable from ring 3
 * calls it. */
int sys_switch_user_preauth(const char* username);

/* Memory Sealing Syscall (Phase 14) */
int sys_mseal(uint32_t addr, uint32_t size);

/*-----------------------------------------------------------------------------
 * User-space System Call Wrappers (inline for user programs)
 * These should be compiled with user programs, not the kernel
 *-----------------------------------------------------------------------------*/

#ifdef USER_MODE

// Exit the program
static inline void exit(int status) {
    __asm__ volatile (
        "int $0x80"
        :
        : "a"(SYS_EXIT), "b"(status)
    );
    __builtin_unreachable();
}

// Write to console
static inline int write(int fd, const char* buf, size_t len) {
    int ret;
    __asm__ volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(SYS_WRITE), "b"(fd), "c"(buf), "d"(len)
    );
    return ret;
}

// Read from the stream bound to fd (0 = stdin)
static inline int read(int fd, char* buf, size_t len) {
    int ret;
    __asm__ volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(SYS_READ), "b"(fd), "c"(buf), "d"(len)
    );
    return ret;
}

// Get process ID (placeholder)
static inline int getpid(void) {
    int ret;
    __asm__ volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(SYS_GETPID)
    );
    return ret;
}

// Yield CPU (placeholder)
static inline void yield(void) {
    __asm__ volatile (
        "int $0x80"
        :
        : "a"(SYS_YIELD)
    );
}

// Helper function to write a string
static inline void puts(const char* str) {
    size_t len = 0;
    while (str[len]) len++;
    write(1, str, len);  // fd=1 for stdout
}

#endif // USER_MODE

#endif // SYSCALL_H
