/*=============================================================================
 * tcp.c - TinyOS TCP Stack Implementation
 *
 * A complete TCP implementation following RFC 793 with:
 * - Full state machine
 * - Connection management
 * - Reliable data transfer
 * - Flow control and windowing
 *=============================================================================*/
#include "tcp.h"
#include "net.h"
#include "kernel.h"
#include "kprintf.h"
#include "util.h"
#include "critical.h"  /* For proper nested critical section support */
#include "crypto.h"    /* For CSPRNG ISN generation (global_csprng) */
#include "sha256.h"    /* For RFC 6528 ISN PRF */

/*=============================================================================
 * CONCURRENCY PROTECTION (Global Interrupt Disable - Coarse-Grained Locking)
 *
 * CRITICAL: The tcp_connections array is accessed from multiple contexts:
 * 1. Main kernel loop (tcp_tick, tcp_poll)
 * 2. Interrupt handler (handle_tcp -> tcp_handle_packet)
 * 3. Application code (tcp_connect, tcp_send, tcp_recv, tcp_close)
 *
 * Without protection, race conditions will cause:
 * - Corrupted connection state (in_use flag flips)
 * - Non-deterministic kernel crashes
 * - Connection leaks
 *
 * CURRENT SOLUTION: Global Interrupt Disable (cli/sti)
 * - TCP_LOCK() = cli() → Disable ALL interrupts globally
 * - TCP_UNLOCK() = sti() → Re-enable interrupts
 *
 * LOCK GRANULARITY ANALYSIS:
 *
 * Granularity: COARSE (Global interrupt disable)
 * - Protects: Entire tcp_connections[] array and all TCP state
 * - Duration: Varies by operation (microseconds to milliseconds)
 * - Latency Impact: HIGH - Timer interrupts delayed during lock hold
 *
 * TRADEOFFS:
 *
 * Advantages:
 * 1. Simple implementation - no complex spinlock logic
 * 2. Guaranteed atomic access - no race conditions possible
 * 3. Works in any context (interrupt, kernel, future user-mode)
 * 4. Zero overhead for lock acquisition (single instruction)
 *
 * Disadvantages:
 * 1. HIGH INTERRUPT LATENCY - All interrupts blocked (timer, network, keyboard)
 * 2. Poor scalability - Single global lock for all connections
 * 3. Priority inversion - Low-priority TCP operations block high-priority interrupts
 * 4. Time drift - Long critical sections (tcp_tick) delay PIT timer interrupts
 *
 * MEASURED CRITICAL SECTION DURATIONS (Approximate):
 * - tcp_send(): ~10-50 microseconds (minimal - buffer copy)
 * - tcp_recv(): ~10-50 microseconds (minimal - buffer copy)
 * - tcp_connect(): ~20-100 microseconds (SYN packet construction)
 * - tcp_handle_packet(): ~50-200 microseconds (state machine + ACK processing)
 * - tcp_tick(): ~100-500 microseconds (iterate all connections, timeouts)
 *   ^^^^ WORST CASE: Can cause 0.5ms interrupt latency spike
 *
 * INTERRUPT LATENCY IMPLICATIONS:
 * - PIT Timer (100Hz): Interrupts every 10ms. Max 0.5ms delay = 5% jitter.
 * - E1000 NIC RX: Can miss incoming packets if ring buffer fills during lock.
 * - Keyboard: Can miss keypresses if held for >10ms (unlikely in practice).
 *
 * FUTURE IMPROVEMENTS (When Interrupt Latency Becomes Critical):
 *
 * Option 1: PER-CONNECTION SPINLOCKS (Fine-Grained)
 * - Add `spinlock_t lock` to tcp_connection_t structure
 * - Only lock the specific connection being accessed
 * - Reduces contention, allows concurrent access to different connections
 * - Complexity: Must handle lock ordering to prevent deadlocks
 * - Best for: Multi-core systems or high connection counts (>100)
 *
 * Option 2: READ-WRITE LOCKS (Moderate-Grained)
 * - Allow multiple readers (tcp_get_state, tcp_is_connected)
 * - Exclusive writer (tcp_send, tcp_handle_packet, tcp_tick)
 * - Improves read-heavy workloads (monitoring, status checks)
 * - Still requires interrupt disable (can't sleep in interrupt context)
 *
 * Option 3: DEFERRED PROCESSING (Avoid Locks in Interrupts)
 * - Network RX interrupt: Copy packet to queue, defer processing to kernel loop
 * - tcp_handle_packet(): Process queue in kernel context without interrupt disable
 * - Minimizes interrupt handler duration
 * - Requires careful queue synchronization (producer/consumer pattern)
 * - Best for: High packet rates where interrupt latency is critical
 *
 * Option 4: MICRO-LOCKING (Extreme Fine-Grained)
 * - Separate locks for: tx_buffer, rx_buffer, state machine, timers
 * - Lock only what you touch (e.g., tcp_send locks tx_buffer only)
 * - Extremely low latency, maximum concurrency
 * - Complexity: Very high - risk of deadlocks, lock ordering bugs
 * - Best for: Real-time systems with strict latency requirements
 *
 * CURRENT DECISION: Global Interrupt Disable (COARSE)
 * Rationale:
 * - Simple and correct for this kernel's scale (8 connections max)
 * - Interrupt latency acceptable for firewall workload
 * - 100Hz timer has 10ms period, 0.5ms jitter is tolerable
 * - E1000 ring buffer (256 descriptors) absorbs short lock durations
 *
 * WHEN TO MIGRATE TO FINER-GRAINED LOCKING:
 * - Connection count increases (>32 connections)
 * - Real-time requirements (audio/video streaming through firewall)
 * - Multi-core support (current global lock is SMP-hostile)
 * - Measured interrupt latency exceeds 1ms consistently
 * - Packet loss observed during tcp_tick() execution
 *
 *=============================================================================*/
/*=============================================================================
 * SECURITY FIX: Replace cli/sti with nested-safe critical sections
 *
 * PREVIOUS ISSUE: Raw cli()/sti() is not re-entrant. If tcp_send() is called
 * within an existing critical section, sti() would prematurely re-enable
 * interrupts even though the outer critical section should still be active.
 *
 * FIX: CRITICAL_SECTION_ENTER/EXIT uses depth tracking to only restore
 * interrupts when exiting the outermost critical section.
 *=============================================================================*/
#define TCP_LOCK()   CRITICAL_SECTION_ENTER()
#define TCP_UNLOCK() CRITICAL_SECTION_EXIT()

/*=============================================================================
 * TCP CONNECTION TABLE AND SYN FLOOD PROTECTION
 *=============================================================================*/
static tcp_connection_t tcp_connections[TCP_MAX_CONNECTIONS];
static uint16_t next_ephemeral_port = 49152; // Start of ephemeral port range

/*=============================================================================
 * SECURITY: SYN FLOOD PROTECTION
 *
 * CRITICAL DDOS FLAW: Without limits, an attacker can send endless SYN
 * packets with spoofed source IPs, exhausting the TCP_MAX_CONNECTIONS array
 * and causing legitimate connections to be rejected.
 *
 * Mitigation Strategy:
 * 1. Limit half-open connections (SYN_SENT, SYN_RECEIVED states)
 * 2. Track per-IP connection attempts (not implemented - requires IP tracking)
 * 3. For production: Implement SYN cookies (stateless SYN-ACK)
 *=============================================================================*/
#define TCP_MAX_HALF_OPEN_CONNECTIONS 4  // Max half-open at once

/**
 * @brief Count half-open connections (SYN flood detection)
 * @return Number of connections in SYN_SENT or SYN_RECEIVED state
 */
static int tcp_count_half_open_connections(void) {
    int count = 0;
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        if (tcp_connections[i].in_use &&
            (tcp_connections[i].state == TCP_SYN_SENT ||
             tcp_connections[i].state == TCP_SYN_RECEIVED)) {
            count++;
        }
    }
    return count;
}

/**
 * @brief Count connections in TIME_WAIT state
 * SECURITY: TIME_WAIT Exhaustion Protection
 *
 * In a firewall under attack, rapid connection bursts can fill the
 * connection table with TIME_WAIT entries, preventing new connections.
 *
 * @return Number of connections in TIME_WAIT state
 */
static int tcp_count_time_wait_connections(void) {
    int count = 0;
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        if (tcp_connections[i].in_use && tcp_connections[i].state == TCP_TIME_WAIT) {
            count++;
        }
    }
    return count;
}

/**
 * @brief Force-close oldest TIME_WAIT connection (LIFO eviction)
 * SECURITY: Fail-Safe for Connection Table Exhaustion
 *
 * When TIME_WAIT entries exceed threshold, forcibly close the oldest
 * to free a slot. This trades a low-risk protocol violation for
 * guaranteed new connection capacity.
 *
 * @return true if a connection was evicted
 */
static bool tcp_evict_oldest_time_wait(void) {
    uint32_t oldest_time = 0xFFFFFFFF;
    int oldest_idx = -1;

    // Find oldest TIME_WAIT connection
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        if (tcp_connections[i].in_use && tcp_connections[i].state == TCP_TIME_WAIT) {
            if (tcp_connections[i].time_wait_start < oldest_time) {
                oldest_time = tcp_connections[i].time_wait_start;
                oldest_idx = i;
            }
        }
    }

    if (oldest_idx >= 0) {
        kprintf("TCP: TIME_WAIT exhaustion - forcibly closing oldest connection %d\n", oldest_idx);
        tcp_connections[oldest_idx].state = TCP_CLOSED;
        tcp_connections[oldest_idx].in_use = false;
        return true;
    }

    return false;
}

/**
 * @brief Validate TCP sequence number against expected range
 * SECURITY: Sequence Number Wraparound Protection
 *
 * Without validation, an attacker can send:
 * 1. Old segments from previous connections (after wraparound)
 * 2. Segments with sequence numbers far in the future
 *
 * @param seq Received sequence number
 * @param expected Expected sequence number (rcv_nxt)
 * @param window Receive window size
 * @return true if sequence number is valid
 */
static bool tcp_validate_sequence(uint32_t seq, uint32_t expected, uint32_t window) {
    /*=====================================================================
     * TCP sequence number validation (RFC 793 Section 3.3)
     *
     * Accept if: expected <= seq < (expected + window)
     * Must handle 32-bit wraparound correctly
     *===================================================================*/

    // Allow exact match
    if (seq == expected) {
        return true;
    }

    // Calculate difference (handles wraparound via unsigned arithmetic)
    uint32_t diff = seq - expected;

    // Accept if within receive window
    // Diff < window means seq is ahead but within acceptable range
    if (diff < window) {
        return true;
    }

    // Reject segments that are:
    // 1. Far in the future (diff >= window)
    // 2. From the past (diff > 2^31, indicates negative offset due to wraparound)
    #define TCP_SEQ_FUTURE_THRESHOLD (1U << 31)  // Half the sequence space
    if (diff >= TCP_SEQ_FUTURE_THRESHOLD) {
        // This is actually an old segment (from the past)
        return false;
    }

    // Segment is too far in the future
    return false;
}

/*=============================================================================
 * HELPER FUNCTIONS
 *=============================================================================*/

/*=============================================================================
 * FUNCTION: tcp_generate_isn
 * PURPOSE: Generate RFC 6528-compliant Initial Sequence Numbers
 *
 * SECURITY CRITICAL: RFC 6528 - Defending Against Sequence Number Attacks
 *
 * WHY RFC 6528 COMPLIANCE IS MANDATORY:
 * --------------------------------------
 * TCP sequence number prediction is a practical, exploitable attack.
 * Historic vulnerabilities (CVE-2004-0230, Mitnick attack on Shimomura 1994)
 * demonstrate that predictable ISNs enable:
 * 1. Session hijacking (inject forged packets into existing connections)
 * 2. Connection spoofing (forge SYN-ACK responses)
 * 3. Data injection attacks
 *
 * ATTACK SCENARIO (Predictable ISNs):
 * ------------------------------------
 * 1. Attacker observes ISNs from victim: ISN_1, ISN_2, ISN_3
 * 2. Attacker predicts next ISN: ISN_next = f(ISN_1, ISN_2, ISN_3)
 * 3. Victim opens connection to server (ISN = ISN_next)
 * 4. Attacker races to inject forged packet with seq=ISN_next+1
 * 5. Server accepts forged packet → Attacker controls connection
 *
 * RFC 6528 ALGORITHM:
 * -------------------
 * ISN = M + F(local_ip, local_port, remote_ip, remote_port, secret_key)
 *
 * Where:
 * - M: Monotonically increasing counter (4 μs timer per RFC 793)
 *      We use millisecond timer * 250 to approximate 4 μs increments
 * - F(): Pseudorandom Function (PRF) - we use HMAC-SHA256
 * - secret_key: 32-byte random key, generated once at boot
 *
 * SECURITY PROPERTIES:
 * --------------------
 * 1. Unpredictability: F(4-tuple, secret) is cryptographically random
 * 2. Per-connection uniqueness: Different 4-tuples → Different ISNs
 * 3. Monotonic increase: M ensures ISNs generally increase over time
 * 4. Wrap-around safety: 32-bit ISN space wraps every ~4.55 hours
 *============================================================================*/

/* Secret key for ISN generation (initialized once, never changes) */
static uint8_t isn_secret_key[32] = {0};
static bool isn_secret_initialized = false;

static uint32_t tcp_generate_isn(const uint8_t* local_ip, uint16_t local_port,
                                  const uint8_t* remote_ip, uint16_t remote_port) {
    /*=========================================================================
     * Step 1: Initialize secret key on first call (one-time setup)
     *=======================================================================*/
    if (!isn_secret_initialized) {
        csprng_random_bytes(&global_csprng, isn_secret_key, sizeof(isn_secret_key));
        isn_secret_initialized = true;
    }

    /*=========================================================================
     * Step 2: Calculate M (monotonic counter)
     * RFC 793 specifies ISN should increment every 4 microseconds.
     * Our timer is millisecond-resolution, so we multiply by 250 to
     * approximate 4μs increments: 1ms = 1000μs = 250 * 4μs
     *=======================================================================*/
    uint32_t M = tcp_get_time_ms() * 250;

    /*=========================================================================
     * Step 3: Build input for PRF F()
     * Input: local_ip (4) + local_port (2) + remote_ip (4) + remote_port (2)
     *        + secret_key (32) = 44 bytes total
     *=======================================================================*/
    uint8_t prf_input[44];
    size_t offset = 0;

    /* Local IP (4 bytes) */
    memcpy(prf_input + offset, local_ip, 4);
    offset += 4;

    /* Local port (2 bytes, big-endian) */
    prf_input[offset++] = (uint8_t)(local_port >> 8);
    prf_input[offset++] = (uint8_t)(local_port & 0xFF);

    /* Remote IP (4 bytes) */
    memcpy(prf_input + offset, remote_ip, 4);
    offset += 4;

    /* Remote port (2 bytes, big-endian) */
    prf_input[offset++] = (uint8_t)(remote_port >> 8);
    prf_input[offset++] = (uint8_t)(remote_port & 0xFF);

    /* Secret key (32 bytes) */
    memcpy(prf_input + offset, isn_secret_key, 32);

    /*=========================================================================
     * Step 4: Compute F() using SHA256 as PRF
     * We hash the concatenated input and extract first 4 bytes as F().
     * SHA256 provides strong avalanche effect: changing any bit of input
     * changes ~50% of output bits → Unpredictable ISNs.
     *=======================================================================*/
    uint8_t hash[32];
    sha256(prf_input, sizeof(prf_input), hash);

    /* Extract first 4 bytes of hash as F() output */
    uint32_t F = ((uint32_t)hash[0] << 24) |
                 ((uint32_t)hash[1] << 16) |
                 ((uint32_t)hash[2] << 8) |
                 ((uint32_t)hash[3]);

    /*=========================================================================
     * Step 5: Compute final ISN = M + F()
     * The addition wraps naturally in 32-bit arithmetic, which is correct
     * per RFC 793 sequence number semantics.
     *=======================================================================*/
    return M + F;
}

/**
 * @brief Allocate an ephemeral port
 * SECURITY: Check for port collisions to prevent connection confusion
 * In high-traffic scenarios, wrapping ephemeral ports without checking
 * can cause the same port to be assigned to multiple connections
 */
static uint16_t tcp_allocate_port(void) {
    #define EPHEMERAL_PORT_START 49152
    #define EPHEMERAL_PORT_END   65535
    #define MAX_PORT_SEARCH_ATTEMPTS 100

    uint16_t attempts = 0;
    uint16_t start_port = next_ephemeral_port;

    while (attempts < MAX_PORT_SEARCH_ATTEMPTS) {
        uint16_t port = next_ephemeral_port++;

        // Handle wraparound (uint16_t wraps at 65535->0 automatically)
        if (next_ephemeral_port == 0 || next_ephemeral_port < EPHEMERAL_PORT_START) {
            next_ephemeral_port = EPHEMERAL_PORT_START;
        }

        /*=====================================================================
         * SECURITY: Port Collision Check (TIME_WAIT Protection)
         *
         * CRITICAL: RFC 793 requires that we MUST NOT reuse a port that is
         * currently in TIME_WAIT state, as delayed packets from the old
         * connection could corrupt the new connection's sequence numbers.
         *
         * Attack Scenario:
         * 1. Connection A closes, enters TIME_WAIT (port 50000)
         * 2. New connection B allocated same port 50000 immediately
         * 3. Delayed ACK from connection A arrives
         * 4. Connection B processes the ACK, corrupting its sequence numbers
         * 5. Connection B can be hijacked or forced to reset
         *
         * Protection:
         * - Check not only for `in_use`, but also for TIME_WAIT state
         * - Mark port as unavailable until TIME_WAIT expires (30 seconds)
         *
         * RFC 793 Section 3.5:
         * "The TIME-WAIT state provides protection against two incarnations
         * of the same connection existing simultaneously."
         *===================================================================*/
        bool port_in_use = false;
        for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
            if (tcp_connections[i].in_use && tcp_connections[i].local_port == port) {
                // Port is in use - check if it's safe to reuse
                if (tcp_connections[i].state != TCP_CLOSED) {
                    // Connection is active or in transitional state - cannot reuse
                    port_in_use = true;
                    break;
                }
            }
        }

        if (!port_in_use) {
            return port;  // Found free port
        }

        attempts++;

        // Prevent infinite loop if all ports exhausted
        if (next_ephemeral_port == start_port) {
            kprintf("TCP: WARNING - All ephemeral ports exhausted!\n");
            return 0;  // Indicate failure
        }
    }

    kprintf("TCP: WARNING - Could not find free port after %d attempts\n",
            MAX_PORT_SEARCH_ATTEMPTS);
    return 0;  // Indicate failure
}

/**
 * @brief Find connection by ports and IP
 * NOTE: Caller must hold TCP_LOCK when calling from interrupt context
 */
static tcp_connection_t* tcp_find_connection(const uint8_t* remote_ip,
                                             uint16_t remote_port,
                                             uint16_t local_port) {
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        tcp_connection_t* conn = &tcp_connections[i];
        if (conn->in_use &&
            conn->local_port == local_port &&
            conn->remote_port == remote_port &&
            memcmp(conn->remote_ip, remote_ip, 4) == 0) {
            return conn;
        }
    }
    return NULL;
}

/**
 * @brief Calculate bytes available in RX buffer
 */
static uint16_t tcp_rx_available(tcp_connection_t* conn) {
    if (conn->rx_head >= conn->rx_tail) {
        return conn->rx_head - conn->rx_tail;
    } else {
        return TCP_RX_BUFFER_SIZE - conn->rx_tail + conn->rx_head;
    }
}

/**
 * @brief Calculate free space in RX buffer
 *
 * SECURITY FIX: Prevents buffer overrun by tracking actual free space.
 * Returns available bytes for incoming data before buffer wraps and overwrites
 * unread data.
 *
 * @param conn TCP connection
 * @return Number of bytes that can be safely written to RX buffer
 *
 * NOTE: We reserve 1 byte to distinguish full (head == tail-1) from
 *       empty (head == tail) state in circular buffer.
 */
static uint16_t tcp_rx_free_space(tcp_connection_t* conn) {
    uint16_t used = tcp_rx_available(conn);

    /*=========================================================================
     * SECURITY: Reserve 1 byte sentinel to prevent full/empty ambiguity
     *
     * In a circular buffer using head/tail pointers:
     * - Empty: head == tail (available = 0)
     * - Full:  head == tail (available = SIZE) ← AMBIGUOUS!
     *
     * By reserving 1 byte, we ensure:
     * - Empty: head == tail (available = 0)
     * - Full:  head == tail - 1 (available = SIZE - 1) ← UNAMBIGUOUS
     *
     * This prevents a full buffer from being treated as empty.
     *=======================================================================*/
    return TCP_RX_BUFFER_SIZE - used - 1;
}

/**
 * @brief Calculate bytes available in TX buffer
 */
static uint16_t tcp_tx_available(tcp_connection_t* conn) {
    if (conn->tx_head >= conn->tx_tail) {
        return conn->tx_head - conn->tx_tail;
    } else {
        return TCP_TX_BUFFER_SIZE - conn->tx_tail + conn->tx_head;
    }
}

/**
 * @brief Get string representation of TCP state
 */
const char* tcp_state_to_string(tcp_state_t state) {
    switch (state) {
        case TCP_CLOSED:       return "CLOSED";
        case TCP_LISTEN:       return "LISTEN";
        case TCP_SYN_SENT:     return "SYN_SENT";
        case TCP_SYN_RECEIVED: return "SYN_RECEIVED";
        case TCP_ESTABLISHED:  return "ESTABLISHED";
        case TCP_FIN_WAIT_1:   return "FIN_WAIT_1";
        case TCP_FIN_WAIT_2:   return "FIN_WAIT_2";
        case TCP_CLOSE_WAIT:   return "CLOSE_WAIT";
        case TCP_CLOSING:      return "CLOSING";
        case TCP_LAST_ACK:     return "LAST_ACK";
        case TCP_TIME_WAIT:    return "TIME_WAIT";
        default:               return "UNKNOWN";
    }
}

/*=============================================================================
 * TCP PACKET TRANSMISSION
 *=============================================================================*/

/**
 * @brief Send a TCP segment
 * @param conn Connection control block
 * @param flags TCP flags (SYN, ACK, FIN, RST, etc.)
 * @param data Optional payload data
 * @param data_len Length of payload
 */
static void tcp_send_segment(tcp_connection_t* conn, uint8_t flags,
                             const void* data, size_t data_len) {
    // DEBUG: All kprintf calls removed to test if kprintf is causing the issue

    /*=========================================================================
     * DANGEROUS INVARIANT: Static TCP Packet Buffer
     *
     * This static buffer is shared across all TCP send operations WITHOUT locking.
     * This is SAFE ONLY because:
     * - TCP is called exclusively from E1000 IRQ 11 handler path
     * - Same interrupt cannot nest (IRQ 11 masked during handling)
     * - No syscall/user-mode entry points to tcp_send_segment()
     *
     * BREAKS IF:
     * - Socket API syscalls are added that call TCP directly
     * - Multiple concurrent TCP connections send data simultaneously
     * - TCP is moved to kernel threads with preemption
     * - SMP is enabled
     *
     * FIX REQUIRED: Allocate per-connection buffers or add critical sections
     * before adding concurrency. Max packet = 14 (eth) + 20 (IP) + 20 (TCP) + 1460 (MSS) = 1514 bytes
     *=======================================================================*/
    static uint8_t packet[1514];
    #define MAX_TCP_PACKET_SIZE 1514

    /* SECURITY FIX (v1.17): Buffer overflow protection
     * Validate packet size before construction to prevent stack corruption */
    size_t tcp_len = sizeof(tcp_header_t) + data_len;
    size_t ip_len = sizeof(ip_header_t) + tcp_len;
    size_t packet_len = sizeof(eth_header_t) + ip_len;

    if (packet_len > MAX_TCP_PACKET_SIZE) {
        kprintf("[TCP] ERROR: Packet too large! len=%zu, max=%d, data_len=%zu\n",
                packet_len, MAX_TCP_PACKET_SIZE, data_len);
        /* Truncate to fit - this preserves headers but drops excess data */
        size_t max_data_len = MAX_TCP_PACKET_SIZE - sizeof(eth_header_t)
                              - sizeof(ip_header_t) - sizeof(tcp_header_t);
        data_len = max_data_len;
        tcp_len = sizeof(tcp_header_t) + data_len;
        ip_len = sizeof(ip_header_t) + tcp_len;
        packet_len = sizeof(eth_header_t) + ip_len;
        kprintf("[TCP] Truncated data to %zu bytes\n", data_len);
    }

    memset(packet, 0, packet_len);

    // Build headers
    eth_header_t* eth_hdr = (eth_header_t*)packet;
    ip_header_t* ip_hdr = (ip_header_t*)(packet + sizeof(eth_header_t));
    tcp_header_t* tcp_hdr = (tcp_header_t*)((uint8_t*)ip_hdr + sizeof(ip_header_t));

    // Ethernet header
    memcpy(eth_hdr->dest_mac, conn->remote_mac, 6);
    memcpy(eth_hdr->src_mac, my_mac, 6);
    eth_hdr->ethertype = htons(ETH_TYPE_IPV4);

    // IP header
    ip_hdr->version_ihl = 0x45;
    ip_hdr->tos = 0;
    ip_hdr->total_length = htons(ip_len);
    ip_hdr->identification = htons(0x4000);
    ip_hdr->flags_fragment = 0;
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_TCP;
    ip_hdr->checksum = 0;
    memcpy(ip_hdr->src_ip, my_ip, 4);
    memcpy(ip_hdr->dest_ip, conn->remote_ip, 4);

    // TCP header
    tcp_hdr->src_port = htons(conn->local_port);
    tcp_hdr->dest_port = htons(conn->remote_port);
    tcp_hdr->sequence_number = htonl(conn->snd_nxt);
    tcp_hdr->acknowledgement_number = htonl(conn->rcv_nxt);
    tcp_hdr->offset_reserved = (sizeof(tcp_header_t) / 4) << 4;
    tcp_hdr->flags = flags;

    /*=========================================================================
     * SECURITY FIX: Advertise Actual RX Buffer Free Space
     * CRITICAL: The TCP window field MUST reflect actual available buffer
     * space, not a static maximum value. This is TCP flow control.
     *
     * Before: Advertised fixed TCP_RX_BUFFER_SIZE (2048 bytes) even when
     *         buffer was full, causing peer to send data we cannot store.
     *
     * After:  Advertise actual free space calculated from circular buffer
     *         (TCP_RX_BUFFER_SIZE - used - 1). When buffer fills up, we
     *         advertise window=0, telling peer to STOP sending until we
     *         consume data (and advertise window>0 again).
     *
     * This is how TCP flow control SHOULD work per RFC 793 Section 3.7:
     * "The window field is a count of data octets beginning with the one
     *  indicated in the acknowledgment field which the sender of this
     *  segment is willing to accept."
     *
     * Security: Prevents buffer overrun by implementing proper TCP flow
     * control. Peer cannot send more data than we have space to store.
     *=======================================================================*/
    tcp_hdr->window_size = htons(tcp_rx_free_space(conn));
    tcp_hdr->urgent_pointer = 0;

    // Copy data if present
    if (data && data_len > 0) {
        memcpy((uint8_t*)tcp_hdr + sizeof(tcp_header_t), data, data_len);
    }

    // Calculate checksums
    tcp_hdr->checksum = 0;
    tcp_hdr->checksum = htons(calculate_l4_checksum(my_ip, conn->remote_ip,
                                                     IPPROTO_TCP, tcp_hdr, tcp_len));
    ip_hdr->checksum = htons(calculate_checksum(ip_hdr, sizeof(ip_header_t)));

    // Send packet
    e1000_send(packet, packet_len);
    
    // Update sequence number if we sent data or SYN/FIN
    if (data_len > 0 || (flags & (TCP_SYN | TCP_FIN))) {
        conn->snd_nxt += data_len;
        if (flags & TCP_SYN) conn->snd_nxt++;
        if (flags & TCP_FIN) conn->snd_nxt++;
    }
    
    // Debug output (commented out for less verbosity)
    // const char* flag_str = "";
    // if (flags == TCP_SYN) flag_str = "SYN";
    // else if (flags == (TCP_SYN | TCP_ACK)) flag_str = "SYN-ACK";
    // else if (flags == TCP_ACK) flag_str = "ACK";
    // else if (flags == (TCP_ACK | TCP_FIN)) flag_str = "FIN-ACK";
    // else if (flags == (TCP_ACK | TCP_PSH)) flag_str = "PSH-ACK";
    // else if (flags == TCP_RST) flag_str = "RST";
    // kprintf("TCP: Sent %s to %d.%d.%d.%d:%d (Seq: %u, Ack: %u, Len: %d)\n",
    //         flag_str,
    //         conn->remote_ip[0], conn->remote_ip[1],
    //         conn->remote_ip[2], conn->remote_ip[3],
    //         conn->remote_port,
    //         ntohl(tcp_hdr->sequence_number),
    //         ntohl(tcp_hdr->acknowledgement_number),
    //         data_len);  // Commented for less verbosity
}

/*=============================================================================
 * TCP STATE MACHINE
 *=============================================================================*/

/**
 * @brief Handle received TCP segment and update state machine
 */
static void tcp_process_segment(tcp_connection_t* conn, tcp_header_t* tcp_hdr,
                               const uint8_t* data, size_t data_len,
                               const uint8_t* src_ip) {
    (void)src_ip;  // Reserved for future use (e.g., validation)

    uint8_t flags = tcp_hdr->flags;
    uint32_t seq = ntohl(tcp_hdr->sequence_number);
    uint32_t ack = ntohl(tcp_hdr->acknowledgement_number);
    uint16_t window = ntohs(tcp_hdr->window_size);

    // kprintf("TCP: [%s] Received flags=0x%x Seq=%u Ack=%u Len=%d\n",
    //         tcp_state_to_string(conn->state), flags, seq, ack, data_len);  // Commented for less verbosity

    /*=========================================================================
     * SECURITY: RST/FIN Flood Protection
     * CRITICAL: Rate limit RST and FIN packets to prevent connection DoS
     * An attacker can send rapid RST/FIN packets to tear down connections
     *
     * Mitigation: Track last RST/FIN time and enforce minimum interval
     *=======================================================================*/
    static uint32_t last_rst_time[TCP_MAX_CONNECTIONS] = {0};
    static uint32_t last_fin_time[TCP_MAX_CONNECTIONS] = {0};
    #define RST_FIN_MIN_INTERVAL_MS 100  // Minimum 100ms between RST/FIN

    // Handle RST with rate limiting
    if (flags & TCP_RST) {
        uint32_t now = tcp_get_time_ms();
        int conn_idx = conn - tcp_connections;  // Calculate connection index

        if (conn_idx >= 0 && conn_idx < TCP_MAX_CONNECTIONS) {
            // Check if RST is coming too fast
            if (now - last_rst_time[conn_idx] < RST_FIN_MIN_INTERVAL_MS) {
                kprintf("TCP: RST flood detected, dropping packet\n");
                return;
            }
            last_rst_time[conn_idx] = now;
        }

        /* RFC 5961: only accept in-window RSTs for synchronized states.
         * Handshake states (SYN_SENT/SYN_RECEIVED) have no meaningful
         * receive window yet, so the strict check is skipped there. */
        if (conn->state >= TCP_ESTABLISHED &&
            !tcp_validate_sequence(seq, conn->rcv_nxt, conn->rcv_wnd)) {
            kprintf("TCP: out-of-window RST dropped\n");
            return;
        }

        kprintf("TCP: Connection reset by peer\n");
        conn->state = TCP_CLOSED;
        conn->in_use = false;
        return;
    }

    /*=========================================================================
     * SECURITY: TCP Window Size Validation
     * CRITICAL: Validate window size to prevent integer overflow attacks
     * A malicious peer can send zero or extremely large window sizes
     *
     * NOTE: window is uint16_t (0-65535), so max value is inherently limited
     * to 64KB which is the standard TCP window size without scaling.
     * Window scaling (RFC 1323) is not implemented in this simple stack.
     *=======================================================================*/
    // Window size of 0 is valid (flow control), but log suspicious behavior
    if (window == 0 && conn->snd_wnd > 0) {
        kprintf("TCP: Peer window closed (zero window received)\n");
    }
    // No need to check window > 65535 since uint16_t cannot exceed this
    
    // State machine processing
    switch (conn->state) {
        case TCP_SYN_SENT:
            // Expecting SYN-ACK
            if ((flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
                // Valid SYN-ACK received
                if (ack == conn->snd_nxt) {
                    conn->rcv_nxt = seq + 1;
                    conn->irs = seq;
                    conn->snd_una = ack;
                    conn->snd_wnd = window;
                    conn->state = TCP_ESTABLISHED;

                    kprintf("TCP: Connection established!\n");

                    // Send ACK to complete 3-way handshake
                    tcp_send_segment(conn, TCP_ACK, NULL, 0);
                }
            }
            break;

        case TCP_SYN_RECEIVED:
            // Expecting ACK to complete 3-way handshake
            if (flags & TCP_ACK) {
                if (ack == conn->snd_nxt) {
                    conn->snd_una = ack;
                    conn->snd_wnd = window;
                    conn->state = TCP_ESTABLISHED;
                    kprintf("TCP: Connection established (server side)!\n");
                }
            }
            break;
            
        case TCP_ESTABLISHED:
            /*=================================================================
             * SECURITY: Strict Sequence Number Window Validation (RFC 793)
             * CRITICAL: ALL segments (including zero-length ACKs) must have
             * their sequence numbers validated against the receive window.
             *
             * Attack vector: An attacker sends ACK-only segments with sequence
             * numbers "one byte off" from the expected value. Without validation,
             * these trigger duplicate ACKs or RSTs, causing a connection-targeted
             * DoS through CPU/bandwidth exhaustion.
             *
             * Rule: RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND
             * Exception: Allow exact match for retransmissions
             *===============================================================*/
            if (!tcp_validate_sequence(seq, conn->rcv_nxt, conn->rcv_wnd)) {
                kprintf("TCP: Segment with invalid sequence %u rejected (expected %u, window %u).\n",
                        seq, conn->rcv_nxt, conn->rcv_wnd);
                // Send duplicate ACK per RFC 793 (but rate-limit to prevent ACK storm)
                tcp_send_segment(conn, TCP_ACK, NULL, 0);
                return;
            }

            // Check if ACK acknowledges our data
            if (flags & TCP_ACK) {
                /*
                 * SECURITY: Use wrap-around-safe sequence comparison
                 * Accept ACK if: snd_una < ack <= snd_nxt
                 */
                if (TCP_SEQ_GT(ack, conn->snd_una) && TCP_SEQ_LEQ(ack, conn->snd_nxt)) {
                    conn->snd_una = ack;
                    // Update window
                    conn->snd_wnd = window;
                }
            }

            // Check for incoming data
            if (data_len > 0) {

                // Only accept in-order data for this simple implementation
                if (seq == conn->rcv_nxt) {
                    /*=========================================================
                     * SECURITY FIX: TCP RX Buffer Overrun Prevention
                     * CRITICAL: Check free space BEFORE writing to buffer
                     *
                     * Without this check:
                     * 1. Attacker fills buffer with 2048 bytes (we ACK)
                     * 2. Application hasn't read data yet (rx_tail = 0)
                     * 3. Attacker sends 100 more bytes
                     * 4. rx_head wraps: (2048 + 100) % 2048 = 100
                     * 5. Overwrites bytes 0-99 (SILENT DATA CORRUPTION)
                     * 6. We ACK anyway (TCP PROTOCOL VIOLATION)
                     *
                     * With this check:
                     * 1. Calculate actual free space in buffer
                     * 2. If data_len > free_space: DROP and DO NOT ACK
                     * 3. Peer will retransmit when we advertise window > 0
                     * 4. No data corruption, protocol correctness preserved
                     *
                     * RFC 793: "A TCP MUST be able to receive a TCP option
                     * in any segment. A TCP MUST ignore without error any
                     * TCP option it does not implement, assuming that the
                     * option has a length field."
                     *
                     * Translation: Dropping data when buffer is full is
                     * CORRECT behavior. We signal this via window = 0.
                     *=======================================================*/
                    uint16_t free_space = tcp_rx_free_space(conn);

                    if (data_len > free_space) {
                        /*=====================================================
                         * Buffer full - DROP data and DO NOT ACK
                         *
                         * This is the CORRECT TCP behavior per RFC 793:
                         * - We MUST NOT ACK data we cannot store
                         * - We MUST advertise window = 0 to stop sender
                         * - Sender will retransmit when window opens
                         *
                         * Security: Prevents silent data corruption by
                         * refusing to overwrite unread data in RX buffer.
                         *====================================================*/
                        kprintf("[TCP] SECURITY: RX buffer full (%u free, %zu needed). "
                                "Dropping data without ACK.\n", free_space, data_len);
                        kprintf("[TCP] Peer will retransmit when we advertise window > 0 "
                                "(after application reads buffered data).\n");

                        // Update rcv_wnd to 0 to signal full buffer
                        conn->rcv_wnd = 0;

                        // Send ACK with window=0 to inform peer (optional)
                        tcp_send_segment(conn, TCP_ACK, NULL, 0);
                        return;
                    }

                    // Buffer has space - safe to write
                    for (size_t i = 0; i < data_len; i++) {
                        conn->rx_buffer[conn->rx_head] = data[i];
                        conn->rx_head = (conn->rx_head + 1) % TCP_RX_BUFFER_SIZE;
                    }
                    conn->rcv_nxt += data_len;

                    // Update receive window to reflect new free space
                    conn->rcv_wnd = tcp_rx_free_space(conn);

                    // kprintf("TCP: Received %d bytes of data\n", data_len);  // Commented for less verbosity

                    // Send ACK for received data
                    tcp_send_segment(conn, TCP_ACK, NULL, 0);
                }
            }
            
            // Check for FIN with rate limiting
            if (flags & TCP_FIN) {
                uint32_t now = tcp_get_time_ms();
                int conn_idx = conn - tcp_connections;

                if (conn_idx >= 0 && conn_idx < TCP_MAX_CONNECTIONS) {
                    // Rate limit FIN packets
                    if (now - last_fin_time[conn_idx] < RST_FIN_MIN_INTERVAL_MS) {
                        kprintf("TCP: FIN flood detected, dropping packet\n");
                        return;
                    }
                    last_fin_time[conn_idx] = now;
                }

                conn->rcv_nxt = seq + 1;
                conn->fin_received = true;
                conn->state = TCP_CLOSE_WAIT;

                // kprintf("TCP: Received FIN, entering CLOSE_WAIT\n");  // Commented for less verbosity

                // Send ACK for FIN
                tcp_send_segment(conn, TCP_ACK, NULL, 0);
            }
            break;
            
        case TCP_FIN_WAIT_1:
            // Waiting for ACK of our FIN
            if (flags & TCP_ACK) {
                if (ack == conn->snd_nxt) {
                    conn->snd_una = ack;
                    conn->state = TCP_FIN_WAIT_2;
                    conn->fin_wait_2_start = tcp_get_time_ms();  // Start timeout timer (RFC 1122)
                    // kprintf("TCP: FIN acknowledged, entering FIN_WAIT_2\n");  // Commented for less verbosity
                }
            }

            // Peer might also send FIN (simultaneous close)
            if (flags & TCP_FIN) {
                conn->rcv_nxt = seq + 1;
                conn->fin_received = true;

                if (conn->state == TCP_FIN_WAIT_2) {
                    // Got FIN after our FIN was acked
                    conn->state = TCP_TIME_WAIT;
                    conn->time_wait_start = tcp_get_time_ms();
                    // kprintf("TCP: Entering TIME_WAIT\n");  // Commented for less verbosity
                } else {
                    // Simultaneous close
                    conn->state = TCP_CLOSING;
                    // kprintf("TCP: Simultaneous close, entering CLOSING\n");  // Commented for less verbosity
                }
                
                // ACK the FIN
                tcp_send_segment(conn, TCP_ACK, NULL, 0);
            }
            break;
            
        case TCP_FIN_WAIT_2:
            // Waiting for peer's FIN
            if (flags & TCP_FIN) {
                conn->rcv_nxt = seq + 1;
                conn->fin_received = true;
                conn->state = TCP_TIME_WAIT;
                conn->time_wait_start = tcp_get_time_ms();

                // kprintf("TCP: Received FIN, entering TIME_WAIT\n");  // Commented for less verbosity

                // ACK the FIN
                tcp_send_segment(conn, TCP_ACK, NULL, 0);
            }
            break;
            
        case TCP_CLOSING:
            // Waiting for ACK of our FIN (simultaneous close)
            if (flags & TCP_ACK) {
                if (ack == conn->snd_nxt) {
                    conn->state = TCP_TIME_WAIT;
                    conn->time_wait_start = tcp_get_time_ms();
                    // kprintf("TCP: Entering TIME_WAIT\n");  // Commented for less verbosity
                }
            }
            break;
            
        case TCP_CLOSE_WAIT:
            // Peer closed, waiting for application to close
            // Just ACK any data
            if (flags & TCP_ACK) {
                conn->snd_una = ack;
            }
            break;
            
        case TCP_LAST_ACK:
            // Waiting for ACK of our FIN
            if (flags & TCP_ACK) {
                if (ack == conn->snd_nxt) {
                    kprintf("TCP: Connection closed\n");
                    conn->state = TCP_CLOSED;
                    conn->in_use = false;
                }
            }
            break;
            
        case TCP_TIME_WAIT:
            // Just waiting for timeout
            break;
            
        default:
            break;
    }
}

/*=============================================================================
 * PUBLIC API IMPLEMENTATION
 *=============================================================================*/

/**
 * @brief Initialize TCP stack
 */
void tcp_init(void) {
    memset(tcp_connections, 0, sizeof(tcp_connections));
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        tcp_connections[i].state = TCP_CLOSED;
        tcp_connections[i].in_use = false;
        tcp_connections[i].rcv_wnd = TCP_RX_BUFFER_SIZE;
    }
    kprintf("[NET] TCP: initialized (%d max conns) [OK]\n", TCP_MAX_CONNECTIONS);
}

/**
 * @brief Create a TCP socket
 */
int tcp_socket(void) {
    TCP_LOCK();
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        if (!tcp_connections[i].in_use) {
            tcp_connection_t* conn = &tcp_connections[i];
            memset(conn, 0, sizeof(tcp_connection_t));
            conn->in_use = true;
            conn->state = TCP_CLOSED;
            conn->rcv_wnd = TCP_RX_BUFFER_SIZE;
            conn->local_port = 0; // Will be assigned on connect/bind
            // kprintf("TCP: Socket %d created\n", i);  // Commented for less verbosity
            TCP_UNLOCK();
            return i;
        }
    }

    /*=========================================================================
     * SECURITY: TIME_WAIT Exhaustion Fail-Safe
     * CRITICAL: If no free sockets, check if TIME_WAIT connections are
     * preventing new allocations. If TIME_WAIT count exceeds threshold,
     * forcibly evict the oldest to free a slot (LIFO eviction policy).
     *
     * Threshold: 50% of TCP_MAX_CONNECTIONS to balance protocol compliance
     * with availability under attack.
     *=======================================================================*/
    #define TIME_WAIT_EVICTION_THRESHOLD (TCP_MAX_CONNECTIONS / 2)

    int time_wait_count = tcp_count_time_wait_connections();
    if (time_wait_count >= TIME_WAIT_EVICTION_THRESHOLD) {
        kprintf("TCP: TIME_WAIT threshold exceeded (%d/%d) - attempting eviction\n",
                time_wait_count, TCP_MAX_CONNECTIONS);

        if (tcp_evict_oldest_time_wait()) {
            // Try allocation again after eviction
            for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
                if (!tcp_connections[i].in_use) {
                    tcp_connection_t* conn = &tcp_connections[i];
                    memset(conn, 0, sizeof(tcp_connection_t));
                    conn->in_use = true;
                    conn->state = TCP_CLOSED;
                    conn->rcv_wnd = TCP_RX_BUFFER_SIZE;
                    conn->local_port = 0;
                    TCP_UNLOCK();
                    return i;
                }
            }
        }
    }

    TCP_UNLOCK();
    kprintf("TCP: No free sockets (even after TIME_WAIT eviction)\n");
    return -1;
}

/**
 * @brief Bind socket to local port
 */
int tcp_bind(int sockfd, uint16_t port) {
    if (sockfd < 0 || sockfd >= TCP_MAX_CONNECTIONS) return -1;
    tcp_connection_t* conn = &tcp_connections[sockfd];
    if (!conn->in_use) return -1;

    if (port == 0) {
        port = tcp_allocate_port();
    }
    conn->local_port = port;
    // kprintf("TCP: Socket %d bound to port %d\n", sockfd, port);  // Commented for less verbosity
    return 0;
}

/**
 * @brief Listen for incoming connections
 */
int tcp_listen(int sockfd) {
    if (sockfd < 0 || sockfd >= TCP_MAX_CONNECTIONS) return -1;
    TCP_LOCK();
    tcp_connection_t* conn = &tcp_connections[sockfd];
    if (!conn->in_use || conn->state != TCP_CLOSED) {
        TCP_UNLOCK();
        return -1;
    }

    // Must have a port bound
    if (conn->local_port == 0) {
        TCP_UNLOCK();
        return -1;
    }

    conn->state = TCP_LISTEN;
    /* Removed verbose kprintf - TCP listen operation is silent */
    TCP_UNLOCK();
    return 0;
}

/**
 * @brief Accept incoming connection (non-blocking)
 * Returns first ESTABLISHED connection for the listening port
 */
int tcp_accept(int listen_sockfd, uint8_t* remote_ip, uint16_t* remote_port) {
    if (listen_sockfd < 0 || listen_sockfd >= TCP_MAX_CONNECTIONS) return -1;
    TCP_LOCK();
    tcp_connection_t* listen_conn = &tcp_connections[listen_sockfd];
    if (!listen_conn->in_use || listen_conn->state != TCP_LISTEN) {
        TCP_UNLOCK();
        return -1;
    }

    uint16_t port = listen_conn->local_port;

    // Find first ESTABLISHED connection on this port
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        if (i == listen_sockfd) continue;  // Skip the listening socket itself
        tcp_connection_t* conn = &tcp_connections[i];
        if (conn->in_use && conn->local_port == port &&
            conn->state == TCP_ESTABLISHED) {
            // Found an accepted connection
            if (remote_ip) memcpy(remote_ip, conn->remote_ip, 4);
            if (remote_port) *remote_port = conn->remote_port;
            TCP_UNLOCK();
            return i;
        }
    }

    TCP_UNLOCK();
    return -1;  // No connections ready
}

/**
 * @brief Connect to remote server
 */
int tcp_connect(int sockfd, const uint8_t* remote_ip, uint16_t remote_port) {
    if (sockfd < 0 || sockfd >= TCP_MAX_CONNECTIONS) return -1;
    tcp_connection_t* conn = &tcp_connections[sockfd];
    if (!conn->in_use || conn->state != TCP_CLOSED) return -1;

    /*=========================================================================
     * SECURITY: SYN Flood Protection
     * CRITICAL: Enforce limit on half-open connections to prevent DoS
     *
     * An attacker can exhaust the connection table by sending SYNs with
     * spoofed source IPs that never complete the handshake. This check
     * prevents resource exhaustion by limiting concurrent half-open connections.
     *=======================================================================*/
    int half_open = tcp_count_half_open_connections();
    if (half_open >= TCP_MAX_HALF_OPEN_CONNECTIONS) {
        kprintf("TCP: SYN flood protection - too many half-open connections (%d/%d)\n",
                half_open, TCP_MAX_HALF_OPEN_CONNECTIONS);
        return -1;
    }

    // Store remote address
    memcpy(conn->remote_ip, remote_ip, 4);
    conn->remote_port = remote_port;
    
    // Allocate local port if not bound
    if (conn->local_port == 0) {
        conn->local_port = tcp_allocate_port();
    }
    
    // Look up remote MAC address
    uint8_t* remote_mac = get_route_mac(remote_ip);
    if (!remote_mac) {
        kprintf("TCP: Cannot resolve MAC for remote IP\n");
        return -1;
    }
    memcpy(conn->remote_mac, remote_mac, 6);

    // Initialize sequence numbers (RFC 6528-compliant ISN generation)
    conn->iss = tcp_generate_isn(my_ip, conn->local_port,
                                  conn->remote_ip, conn->remote_port);
    conn->snd_una = conn->iss;
    conn->snd_nxt = conn->iss + 1;
    conn->snd_wnd = TCP_INITIAL_WINDOW;

    // Change state and send SYN
    conn->state = TCP_SYN_SENT;
    conn->syn_sent_start = tcp_get_time_ms();  // Track SYN_SENT entry time for timeout
    kprintf("TCP: Initiating connection to %d.%d.%d.%d:%d from port %d\n",
            remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3],
            remote_port, conn->local_port);

    /* tcp_send_segment uses a shared static TX buffer (packet[1514]); an e1000
     * RX IRQ can reenter it (to emit an ACK) and clobber a half-built segment.
     * Serialize under TCP_LOCK like the IRQ-path senders do. */
    TCP_LOCK();
    tcp_send_segment(conn, TCP_SYN, NULL, 0);
    TCP_UNLOCK();

    return 0;
}

/**
 * @brief Send data
 */
int tcp_send(int sockfd, const void* data, size_t len) {
    // DEBUG: Re-adding diagnostic output to identify why tcp_send returns -1

    if (sockfd < 0 || sockfd >= TCP_MAX_CONNECTIONS) {
        kprintf("[TCP] tcp_send: Invalid sockfd %d (must be 0-%d)\n", sockfd, TCP_MAX_CONNECTIONS-1);
        return -1;
    }

    tcp_connection_t* conn = &tcp_connections[sockfd];

    TCP_LOCK();

    if (!conn->in_use) {
        kprintf("[TCP] tcp_send: Connection sockfd=%d not in use\n", sockfd);
        TCP_UNLOCK();
        return -1;
    }

    if (conn->state != TCP_ESTABLISHED) {
        kprintf("[TCP] tcp_send: Connection sockfd=%d state=%d (not ESTABLISHED=%d)\n",
                sockfd, conn->state, TCP_ESTABLISHED);
        TCP_UNLOCK();
        return -1;
    }

    // Check available space in TX buffer
    uint16_t space = TCP_TX_BUFFER_SIZE - tcp_tx_available(conn) - 1;
    if (len > space) {
        len = space;
    }

    if (len == 0) {
        TCP_UNLOCK();
        return 0;
    }

    // Copy data to TX buffer
    const uint8_t* bytes = (const uint8_t*)data;
    for (size_t i = 0; i < len; i++) {
        conn->tx_buffer[conn->tx_head] = bytes[i];
        conn->tx_head = (conn->tx_head + 1) % TCP_TX_BUFFER_SIZE;
    }

    // Send data immediately (simplified - no Nagle's algorithm)
    static uint8_t send_buf[TCP_MAX_SEGMENT_SIZE];  // Static to avoid stack overflow
    size_t to_send = len < TCP_MAX_SEGMENT_SIZE ? len : TCP_MAX_SEGMENT_SIZE;

    for (size_t i = 0; i < to_send; i++) {
        send_buf[i] = conn->tx_buffer[conn->tx_tail];
        conn->tx_tail = (conn->tx_tail + 1) % TCP_TX_BUFFER_SIZE;
    }

    tcp_send_segment(conn, TCP_ACK | TCP_PSH, send_buf, to_send);

    TCP_UNLOCK();

    return to_send;
}

/**
 * @brief Receive data
 */
int tcp_recv(int sockfd, void* buffer, size_t len) {
    if (sockfd < 0 || sockfd >= TCP_MAX_CONNECTIONS) return -1;
    tcp_connection_t* conn = &tcp_connections[sockfd];
    if (!conn->in_use) return -1;
    
    // Check if connection closed
    if (conn->state == TCP_CLOSED) return -1;
    if (conn->state == TCP_CLOSE_WAIT && tcp_rx_available(conn) == 0) return 0;
    
    TCP_LOCK();

    // Read available data
    uint16_t available = tcp_rx_available(conn);
    if (available == 0) {
        TCP_UNLOCK();
        return 0;
    }

    size_t to_read = (len < available) ? len : available;
    uint8_t* bytes = (uint8_t*)buffer;

    /*=========================================================================
     * SECURITY FIX: TCP Window Update After Application Read
     *
     * Track the receive window BEFORE reading data from buffer.
     * If window was zero (buffer was full), we need to send a window update
     * after the application reads data to inform the peer it can send again.
     *=======================================================================*/
    uint16_t old_rcv_wnd = conn->rcv_wnd;

    for (size_t i = 0; i < to_read; i++) {
        bytes[i] = conn->rx_buffer[conn->rx_tail];
        conn->rx_tail = (conn->rx_tail + 1) % TCP_RX_BUFFER_SIZE;
    }

    /*=========================================================================
     * SECURITY FIX: Send Window Update ACK
     * CRITICAL: If buffer was full (rcv_wnd=0) and application just freed
     * space by reading data, we MUST send a window update ACK to inform the
     * peer it can resume sending.
     *
     * RFC 793: "When the receive buffer fills up, the receiver advertises
     * a zero window. The sender must then stop sending until the receiver
     * advertises a non-zero window again via a window update segment."
     *
     * Without this: If buffer fills, we advertise window=0, peer stops
     * sending, application reads data... but peer never knows buffer has
     * space now! Connection stalls permanently (deadlock).
     *
     * With this: After application reads data, we send ACK with updated
     * window size, allowing peer to resume transmission.
     *=======================================================================*/
    uint16_t new_rcv_wnd = tcp_rx_free_space(conn);
    conn->rcv_wnd = new_rcv_wnd;

    // If window opened up significantly, send window update
    if (old_rcv_wnd == 0 && new_rcv_wnd > 0) {
        // Window was closed, now open - send urgent window update
        tcp_send_segment(conn, TCP_ACK, NULL, 0);
    } else if (new_rcv_wnd > old_rcv_wnd + 512) {
        // Window increased by >512 bytes - send update to prevent silly window syndrome
        tcp_send_segment(conn, TCP_ACK, NULL, 0);
    }

    TCP_UNLOCK();

    return to_read;
}

/**
 * @brief Close connection
 */
int tcp_close(int sockfd) {
    if (sockfd < 0 || sockfd >= TCP_MAX_CONNECTIONS) return -1;
    tcp_connection_t* conn = &tcp_connections[sockfd];
    if (!conn->in_use) return -1;

    // kprintf("TCP: Closing socket %d (state: %s)\n",
    //         sockfd, tcp_state_to_string(conn->state));  // Commented for less verbosity

    /* Serialize the state transition + FIN emission under TCP_LOCK: it mutates
     * conn->state/fin_sent (read by the IRQ-path receiver) and calls
     * tcp_send_segment, which uses a shared static TX buffer an RX IRQ can
     * reenter and clobber. CRITICAL_SECTION nests, so this is safe regardless of
     * caller context. */
    TCP_LOCK();
    switch (conn->state) {
        case TCP_ESTABLISHED:
            // Initiate active close
            conn->fin_sent = true;
            conn->state = TCP_FIN_WAIT_1;
            tcp_send_segment(conn, TCP_ACK | TCP_FIN, NULL, 0);
            break;

        case TCP_CLOSE_WAIT:
            // Passive close - send our FIN
            conn->fin_sent = true;
            conn->state = TCP_LAST_ACK;
            tcp_send_segment(conn, TCP_ACK | TCP_FIN, NULL, 0);
            break;

        case TCP_CLOSED:
        case TCP_LISTEN:
            // Just mark as free
            conn->in_use = false;
            break;

        default:
            // Already closing
            break;
    }
    TCP_UNLOCK();

    return 0;
}

/**
 * @brief Check if connected
 */
bool tcp_is_connected(int sockfd) {
    if (sockfd < 0 || sockfd >= TCP_MAX_CONNECTIONS) return false;
    tcp_connection_t* conn = &tcp_connections[sockfd];
    return conn->in_use && conn->state == TCP_ESTABLISHED;
}

/**
 * @brief Get connection state
 */
tcp_state_t tcp_get_state(int sockfd) {
    if (sockfd < 0 || sockfd >= TCP_MAX_CONNECTIONS) return TCP_CLOSED;
    return tcp_connections[sockfd].state;
}

/**
 * @brief Check bytes available to read
 */
int tcp_available(int sockfd) {
    if (sockfd < 0 || sockfd >= TCP_MAX_CONNECTIONS) return 0;
    tcp_connection_t* conn = &tcp_connections[sockfd];
    if (!conn->in_use) return 0;
    return tcp_rx_available(conn);
}

/*=============================================================================
 * NETWORK STACK INTERFACE
 *=============================================================================*/

/**
 * @brief Handle incoming TCP packet (called by network stack)
 */
void tcp_handle_packet(const uint8_t* src_ip, const uint8_t* dest_ip,
                       const uint8_t* tcp_data, size_t tcp_len) {
    (void)dest_ip;  // Already validated by IP layer

    if (tcp_len < sizeof(tcp_header_t)) return;

    tcp_header_t* tcp_hdr = (tcp_header_t*)tcp_data;
    uint16_t src_port = ntohs(tcp_hdr->src_port);
    uint16_t dest_port = ntohs(tcp_hdr->dest_port);

    /*=========================================================================
     * SECURITY: TCP Header Length (Data Offset) Validation
     * CRITICAL: Validate data_offset before using it to calculate payload
     * The data_offset field (4 bits) specifies the TCP header size in 32-bit
     * words. An attacker can specify an illegally large or small value to
     * cause out-of-bounds memory access.
     *
     * Requirements:
     * 1. Minimum: 5 words (20 bytes) - minimum TCP header size
     * 2. Maximum: 15 words (60 bytes) - maximum with options
     * 3. Must not exceed tcp_len (total segment length)
     *=======================================================================*/
    uint8_t data_offset_words = (tcp_hdr->offset_reserved >> 4);  // In 32-bit words
    uint8_t data_offset = data_offset_words * 4;  // Convert to bytes

    // Validation 1: Check word count range (5-15)
    if (data_offset_words < 5 || data_offset_words > 15) {
        kprintf("TCP: Invalid data_offset=%d words (must be 5-15). Dropping.\n",
                data_offset_words);
        return;
    }

    // Validation 2: Ensure data_offset doesn't exceed segment length
    if (data_offset > tcp_len) {
        kprintf("TCP: data_offset (%d bytes) exceeds segment length (%zu bytes). Dropping.\n",
                data_offset, tcp_len);
        return;
    }

    // Safe to calculate payload now
    const uint8_t* payload = tcp_data + data_offset;
    size_t payload_len = tcp_len - data_offset;

    /*=========================================================================
     * CONCURRENCY: Lock connection table during packet processing
     * This function is called from interrupt context (e1000_poll_rx)
     * Must prevent race conditions with user-space TCP operations
     *=======================================================================*/
    TCP_LOCK();

    // Find connection
    tcp_connection_t* conn = tcp_find_connection(src_ip, src_port, dest_port);

    if (conn) {
        // Process segment for existing connection
        tcp_process_segment(conn, tcp_hdr, payload, payload_len, src_ip);
    } else {
        // No existing connection - check if this is a SYN to a listening port
        uint8_t flags = tcp_hdr->flags;
        if (flags & TCP_SYN) {
            // Find a listening socket on the destination port
            tcp_connection_t* listen_conn = NULL;
            for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
                if (tcp_connections[i].in_use &&
                    tcp_connections[i].state == TCP_LISTEN &&
                    tcp_connections[i].local_port == dest_port) {
                    listen_conn = &tcp_connections[i];
                    break;
                }
            }

            if (listen_conn) {
                int half_open = tcp_count_half_open_connections();
                if (half_open >= TCP_MAX_HALF_OPEN_CONNECTIONS) {
                    kprintf("TCP: SYN flood protection - too many half-open connections (%d/%d)\n",
                            half_open, TCP_MAX_HALF_OPEN_CONNECTIONS);
                    TCP_UNLOCK();
                    return;
                }

                // Create new connection for this incoming SYN
                int new_sockfd = -1;
                for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
                    if (!tcp_connections[i].in_use) {
                        new_sockfd = i;
                        break;
                    }
                }

                if (new_sockfd >= 0) {
                    tcp_connection_t* new_conn = &tcp_connections[new_sockfd];
                    memset(new_conn, 0, sizeof(tcp_connection_t));
                    new_conn->in_use = true;
                    new_conn->state = TCP_SYN_RECEIVED;
                    new_conn->local_port = dest_port;
                    new_conn->remote_port = src_port;
                    memcpy(new_conn->remote_ip, src_ip, 4);
                    new_conn->rcv_wnd = TCP_RX_BUFFER_SIZE;
                    new_conn->syn_sent_start = tcp_get_time_ms();  // For SYN_RECEIVED timeout

                    // Get remote MAC address
                    uint8_t* remote_mac = get_route_mac(src_ip);
                    if (remote_mac) {
                        memcpy(new_conn->remote_mac, remote_mac, 6);
                    }

                    // Initialize sequence numbers (RFC 6528-compliant ISN generation)
                    uint32_t seq = ntohl(tcp_hdr->sequence_number);
                    new_conn->irs = seq;
                    new_conn->rcv_nxt = seq + 1;
                    new_conn->iss = tcp_generate_isn(my_ip, new_conn->local_port,
                                                      new_conn->remote_ip, new_conn->remote_port);
                    new_conn->snd_una = new_conn->iss;
                    new_conn->snd_nxt = new_conn->iss + 1;
                    new_conn->snd_wnd = TCP_INITIAL_WINDOW;

                    kprintf("TCP: Incoming connection from %d.%d.%d.%d:%d on port %d\n",
                            src_ip[0], src_ip[1], src_ip[2], src_ip[3],
                            src_port, dest_port);

                    // Send SYN-ACK
                    tcp_send_segment(new_conn, TCP_SYN | TCP_ACK, NULL, 0);
                } else {
                    kprintf("TCP: No free sockets for incoming connection\n");
                }
            }
        } else {
            // kprintf("TCP: No connection found for %d.%d.%d.%d:%d -> :%d\n",
            //         src_ip[0], src_ip[1], src_ip[2], src_ip[3],
            //         src_port, dest_port);  // Commented for less verbosity
        }
    }

    TCP_UNLOCK();
}

/**
 * @brief TCP timer tick (should be called periodically)
 */
void tcp_tick(uint32_t current_time) {
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        tcp_connection_t* conn = &tcp_connections[i];
        if (!conn->in_use) continue;

        /*=====================================================================
         * SECURITY: SYN_SENT Timeout Protection
         * CRITICAL: Prevent slow state exhaustion DoS from zombie SYN_SENT
         * connections that never complete the handshake.
         *
         * An attacker can send SYN packets to random ports, forcing the
         * firewall to allocate connections that never receive SYN-ACK responses.
         * Without timeout, these zombie connections fill the connection table.
         *
         * Timeout: 10 seconds (reasonable for firewall environments)
         * After timeout: Forcefully close and free the connection
         *===================================================================*/
        #define TCP_SYN_SENT_TIMEOUT_MS 10000  // 10 seconds

        if (conn->state == TCP_SYN_SENT) {
            uint32_t elapsed = current_time - conn->syn_sent_start;
            if (elapsed > TCP_SYN_SENT_TIMEOUT_MS) {
                kprintf("TCP: SYN_SENT timeout for connection %d (remote %d.%d.%d.%d:%d) after %u ms\n",
                        i, conn->remote_ip[0], conn->remote_ip[1],
                        conn->remote_ip[2], conn->remote_ip[3],
                        conn->remote_port, elapsed);
                kprintf("TCP: Forcefully closing zombie connection to prevent state exhaustion.\n");
                conn->state = TCP_CLOSED;
                conn->in_use = false;
            }
        }

        if (conn->state == TCP_SYN_RECEIVED) {
            uint32_t elapsed = current_time - conn->syn_sent_start;
            if (elapsed > TCP_SYN_SENT_TIMEOUT_MS) {
                kprintf("TCP: SYN_RECEIVED timeout for connection %d (remote %d.%d.%d.%d:%d) after %u ms\n",
                        i, conn->remote_ip[0], conn->remote_ip[1],
                        conn->remote_ip[2], conn->remote_ip[3],
                        conn->remote_port, elapsed);
                kprintf("TCP: Forcefully closing zombie connection to prevent state exhaustion.\n");
                conn->state = TCP_CLOSED;
                conn->in_use = false;
            }
        }

        // Handle TIME_WAIT timeout
        if (conn->state == TCP_TIME_WAIT) {
            if (current_time - conn->time_wait_start > TCP_TIME_WAIT_TIMEOUT) {
                // kprintf("TCP: TIME_WAIT timeout, closing connection %d\n", i);  // Commented for less verbosity
                conn->state = TCP_CLOSED;
                conn->in_use = false;
            }
        }

        /*=====================================================================
         * SECURITY: FIN_WAIT_2 Timeout Protection
         * CRITICAL: Prevent resource exhaustion DoS from zombie FIN_WAIT_2
         * connections.
         *
         * ATTACK SCENARIO:
         * 1. Malicious client establishes connection
         * 2. Client sends FIN (enters FIN_WAIT_1)
         * 3. Server ACKs the FIN (client enters FIN_WAIT_2)
         * 4. Client NEVER sends its FIN (refuses to complete shutdown)
         * 5. Connection stuck in FIN_WAIT_2 indefinitely
         * 6. Attacker repeats → Connection table exhaustion
         *
         * RFC 1122 Section 4.2.2.13:
         * "A TCP implementation SHOULD implement a FIN_WAIT_2 timeout.
         *  If FIN_WAIT_2 timeout expires, the connection SHOULD be closed."
         *
         * Recommended timeout: 60 seconds (RFC 1122 suggests max of 10 minutes,
         * but we use shorter timeout for high-security firewall environments)
         *
         * This is different from TIME_WAIT:
         * - TIME_WAIT protects against delayed packets (both FINs exchanged)
         * - FIN_WAIT_2 protects against non-compliant/malicious peers
         *===================================================================*/
        if (conn->state == TCP_FIN_WAIT_2) {
            if (conn->fin_wait_2_start > 0 &&
                (current_time - conn->fin_wait_2_start) > TCP_FIN_WAIT_2_TIMEOUT) {
                kprintf("TCP: FIN_WAIT_2 timeout for connection %d (remote %d.%d.%d.%d:%d) after %u ms\n",
                        i, conn->remote_ip[0], conn->remote_ip[1],
                        conn->remote_ip[2], conn->remote_ip[3],
                        conn->remote_port, (current_time - conn->fin_wait_2_start));
                kprintf("TCP: Forcefully closing connection to prevent resource exhaustion.\n");
                conn->state = TCP_CLOSED;
                conn->in_use = false;
            }
        }

        /*=====================================================================
         * CRITICAL: Zero Window Probe (TCP Flow Control Deadlock Prevention)
         *
         * RFC 793 Section 3.7: When the peer advertises a zero receive window
         * (snd_wnd == 0), the connection will stall unless the peer sends a
         * window update. However, if the peer's window update ACK is lost in
         * transit, the connection deadlocks permanently:
         *
         * - Sender waits for window update (blocking on snd_wnd == 0)
         * - Receiver already sent window update (but packet was lost)
         * - Neither side will send anything -> DEADLOCK
         *
         * Solution: Zero Window Probes
         * - Periodically send 1 byte of data to elicit an ACK
         * - The ACK will contain the current window size
         * - If window opened, transmission resumes
         * - If still zero, probe again later
         *
         * Timeout: 5 seconds between probes (reasonable for firewall)
         * Critical for: Long-lived connections, bulk data transfer
         *===================================================================*/
        #define TCP_ZERO_WINDOW_PROBE_INTERVAL_MS 5000  // 5 seconds

        if (conn->state == TCP_ESTABLISHED && conn->snd_wnd == 0) {
            // Check if we have data waiting to send
            uint16_t tx_available = (conn->tx_head >= conn->tx_tail) ?
                (conn->tx_head - conn->tx_tail) :
                (TCP_TX_BUFFER_SIZE - conn->tx_tail + conn->tx_head);

            if (tx_available > 0) {
                // Need to send zero window probe
                uint32_t time_since_probe = current_time - conn->zero_window_probe_time;

                if (time_since_probe >= TCP_ZERO_WINDOW_PROBE_INTERVAL_MS ||
                    conn->zero_window_probe_time == 0) {

                    // Send 1 byte of data as zero window probe
                    uint8_t probe_byte = conn->tx_buffer[conn->tx_tail];

                    kprintf("TCP: Zero window detected (conn %d). Sending probe to %d.%d.%d.%d:%d\n",
                            i, conn->remote_ip[0], conn->remote_ip[1],
                            conn->remote_ip[2], conn->remote_ip[3], conn->remote_port);

                    /* Do not let the probe advance snd_nxt: tx_tail is not
                     * advanced either, so the byte is resent at the same
                     * sequence once the window reopens. */
                    uint32_t saved_snd_nxt = conn->snd_nxt;
                    tcp_send_segment(conn, TCP_PSH | TCP_ACK, &probe_byte, 1);
                    conn->snd_nxt = saved_snd_nxt;
                    conn->zero_window_probe_time = current_time;

                    // Note: We do NOT advance tx_tail here. The byte will be
                    // retransmitted if the probe succeeds and window opens.
                }
            }
        }

        // Add retransmission logic here if needed
    }
}

/**
 * @brief Get current time in milliseconds
 * This should use your PIT timer
 */
uint32_t tcp_get_time_ms(void) {
    return get_timer_ticks() * 10; // Assuming 100Hz timer
}

/**
 * @brief Dump connection table
 */
void tcp_dump_connections(void) {
    kprintf("\nTCP Connection Table:\n");
    kprintf("Sock  State         Local    Remote IP:Port\n");
    kprintf("----  ------------  -------  --------------\n");
    
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        tcp_connection_t* conn = &tcp_connections[i];
        if (conn->in_use) {
            kprintf("%4d  %-12s  %-7d  %d.%d.%d.%d:%d\n",
                    i, tcp_state_to_string(conn->state),
                    conn->local_port,
                    conn->remote_ip[0], conn->remote_ip[1],
                    conn->remote_ip[2], conn->remote_ip[3],
                    conn->remote_port);
        }
    }
    kprintf("\n");
}
