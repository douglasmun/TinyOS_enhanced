/*=============================================================================
 * tcp.h - TinyOS TCP Stack Header
 * 
 * A minimal but functional TCP implementation supporting:
 * - Full TCP state machine (RFC 793)
 * - Connection establishment and teardown
 * - Data transmission and reception
 * - Sequence number management
 * - Basic retransmission and timeouts
 * - Multiple simultaneous connections
 *=============================================================================*/
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*=============================================================================
 * TCP CONSTANTS
 *=============================================================================*/
#define TCP_MAX_CONNECTIONS    8      // Maximum simultaneous TCP connections
#define TCP_RX_BUFFER_SIZE     2048   // Per-connection receive buffer
#define TCP_TX_BUFFER_SIZE     2048   // Per-connection transmit buffer
#define TCP_MAX_SEGMENT_SIZE   1460   // MSS (1500 - 20 IP - 20 TCP)
#define TCP_INITIAL_WINDOW     4096   // Initial window size
#define TCP_RETRANSMIT_TIMEOUT 3000   // Initial RTO in milliseconds
#define TCP_MAX_RETRANSMITS    5      // Max retransmission attempts
#define TCP_TIME_WAIT_TIMEOUT  30000  // TIME_WAIT timeout (30 seconds)
#define TCP_FIN_WAIT_2_TIMEOUT 60000  // FIN_WAIT_2 timeout (60 seconds) - RFC 1122 recommendation
#define TCP_KEEPALIVE_INTERVAL 60000  // Keepalive interval (60 seconds)

/*=============================================================================
 * TCP SEQUENCE NUMBER COMPARISON (RFC 793 Section 3.3)
 * CRITICAL: Handle 32-bit wrap-around correctly
 *
 * TCP sequence numbers are 32-bit unsigned integers that wrap around.
 * Simple comparison (a < b) fails when sequence numbers cross the wrap boundary.
 *
 * ATTACK SCENARIO WITHOUT PROPER COMPARISON:
 * - Connection has rcv_nxt = 100
 * - Attacker sends packet with seq = (2^32 - 50) = 4294967246
 * - Simple comparison: 4294967246 > 100 → Accept (WRONG!)
 * - Correct comparison: (2^32 - 50) is BEFORE 100 in sequence space → Reject
 *
 * RFC 793 ALGORITHM:
 * Define sequence space as a circular ring. To compare a and b:
 * - SEQ_LT(a, b) = (int32_t)(a - b) < 0  (a is less than b)
 * - SEQ_GT(a, b) = (int32_t)(a - b) > 0  (a is greater than b)
 * - SEQ_LEQ(a, b) = (int32_t)(a - b) <= 0 (a is less than or equal to b)
 * - SEQ_GEQ(a, b) = (int32_t)(a - b) >= 0 (a is greater than or equal to b)
 *
 * This works because:
 * 1. Subtraction wraps correctly in unsigned arithmetic
 * 2. Casting to signed interprets the result relative to sequence space
 * 3. Valid for differences up to 2^31 (half the sequence space)
 *
 * EXAMPLE:
 * a = 4294967246 (near max), b = 100 (wrapped around)
 * a - b = 4294967146 (very large positive)
 * (int32_t)(4294967146) = -1150 (interpreted as negative)
 * → a < b (CORRECT: a is before b in sequence space)
 *============================================================================*/
#define TCP_SEQ_LT(a, b)  ((int32_t)((a) - (b)) < 0)   // a < b
#define TCP_SEQ_GT(a, b)  ((int32_t)((a) - (b)) > 0)   // a > b
#define TCP_SEQ_LEQ(a, b) ((int32_t)((a) - (b)) <= 0)  // a <= b
#define TCP_SEQ_GEQ(a, b) ((int32_t)((a) - (b)) >= 0)  // a >= b

/*=============================================================================
 * TCP STATE MACHINE (RFC 793)
 *=============================================================================*/
typedef enum {
    TCP_CLOSED = 0,      // No connection (initial state)
    TCP_LISTEN,          // Server waiting for connection
    TCP_SYN_SENT,        // Client sent SYN, waiting for SYN-ACK
    TCP_SYN_RECEIVED,    // Server received SYN, sent SYN-ACK
    TCP_ESTABLISHED,     // Connection established, data transfer
    TCP_FIN_WAIT_1,      // Sent FIN, waiting for ACK
    TCP_FIN_WAIT_2,      // Received ACK of FIN, waiting for peer's FIN
    TCP_CLOSE_WAIT,      // Received FIN, waiting for close()
    TCP_CLOSING,         // Both sides closing simultaneously
    TCP_LAST_ACK,        // Waiting for final ACK
    TCP_TIME_WAIT        // Waiting to ensure remote received ACK
} tcp_state_t;

/*=============================================================================
 * TCP CONNECTION CONTROL BLOCK (TCB)
 * 
 * Stores all state information for a TCP connection
 *=============================================================================*/
typedef struct {
    // Connection state
    tcp_state_t state;
    bool in_use;
    
    // Connection identification
    uint8_t remote_ip[4];
    uint8_t remote_mac[6];
    uint16_t local_port;
    uint16_t remote_port;
    
    // Sequence numbers (RFC 793)
    uint32_t snd_una;      // Send unacknowledged (oldest unacked seq)
    uint32_t snd_nxt;      // Send next (next seq to send)
    uint32_t snd_wnd;      // Send window (peer's receive window)
    uint32_t snd_wl1;      // Segment seq number used for last window update
    uint32_t snd_wl2;      // Segment ack number used for last window update
    uint32_t iss;          // Initial send sequence number
    
    uint32_t rcv_nxt;      // Receive next (next seq expected)
    uint32_t rcv_wnd;      // Receive window (our receive window)
    uint32_t irs;          // Initial receive sequence number
    
    // Timers
    uint32_t last_ack_time;     // Time when last ACK was sent
    uint32_t retransmit_time;   // Time for next retransmission
    uint32_t time_wait_start;   // Start time for TIME_WAIT state
    uint32_t fin_wait_2_start;  // Start time for FIN_WAIT_2 state (for timeout - prevents resource deadlock)
    uint32_t syn_sent_start;    // Start time for SYN_SENT state (for timeout)
    uint32_t zero_window_probe_time; // Time when last zero window probe was sent
    uint8_t retransmit_count;   // Number of retransmissions
    
    // Buffers
    uint8_t rx_buffer[TCP_RX_BUFFER_SIZE];
    uint16_t rx_head;      // Write position
    uint16_t rx_tail;      // Read position
    
    uint8_t tx_buffer[TCP_TX_BUFFER_SIZE];
    uint16_t tx_head;      // Write position
    uint16_t tx_tail;      // Read position (data to send)
    
    // Flags
    bool fin_sent;         // We sent FIN
    bool fin_received;     // We received FIN
    bool ack_pending;      // Need to send ACK
    
} tcp_connection_t;

/*=============================================================================
 * TCP API - Application Interface
 *=============================================================================*/

/**
 * @brief Initialize the TCP stack
 * Must be called before any other TCP functions
 */
void tcp_init(void);

/**
 * @brief Create a new TCP socket (allocate a connection)
 * @return Socket descriptor (0-7) or -1 on error
 */
int tcp_socket(void);

/**
 * @brief Connect to a remote TCP server
 * @param sockfd Socket descriptor from tcp_socket()
 * @param remote_ip Remote IP address (4 bytes)
 * @param remote_port Remote port number
 * @return 0 on success, -1 on error
 * 
 * This initiates the TCP 3-way handshake (SYN -> SYN-ACK -> ACK)
 * Connection is established when state reaches TCP_ESTABLISHED
 */
int tcp_connect(int sockfd, const uint8_t* remote_ip, uint16_t remote_port);

/**
 * @brief Send data over an established TCP connection
 * @param sockfd Socket descriptor
 * @param data Pointer to data to send
 * @param len Length of data
 * @return Number of bytes queued for sending, or -1 on error
 * 
 * Data is buffered and sent according to TCP flow control
 */
int tcp_send(int sockfd, const void* data, size_t len);

/**
 * @brief Receive data from a TCP connection
 * @param sockfd Socket descriptor
 * @param buffer Buffer to store received data
 * @param len Maximum bytes to receive
 * @return Number of bytes received, 0 if connection closed, -1 on error
 */
int tcp_recv(int sockfd, void* buffer, size_t len);

/**
 * @brief Close a TCP connection
 * @param sockfd Socket descriptor
 * @return 0 on success, -1 on error
 * 
 * Initiates graceful connection termination (FIN handshake)
 */
int tcp_close(int sockfd);

/**
 * @brief Check if a connection is established
 * @param sockfd Socket descriptor
 * @return true if connected, false otherwise
 */
bool tcp_is_connected(int sockfd);

/**
 * @brief Get the current state of a TCP connection
 * @param sockfd Socket descriptor
 * @return Current TCP state
 */
tcp_state_t tcp_get_state(int sockfd);

/**
 * @brief Check how many bytes are available to read
 * @param sockfd Socket descriptor
 * @return Number of bytes in receive buffer
 */
int tcp_available(int sockfd);

/**
 * @brief Bind a socket to a specific local port
 * @param sockfd Socket descriptor
 * @param port Local port number (or 0 for auto-assign)
 * @return 0 on success, -1 on error
 */
int tcp_bind(int sockfd, uint16_t port);

/**
 * @brief Listen for incoming connections on a port
 * @param sockfd Socket descriptor
 * @return 0 on success, -1 on error
 *
 * Puts the socket into LISTEN state to accept incoming connections
 */
int tcp_listen(int sockfd);

/**
 * @brief Accept an incoming connection (non-blocking)
 * @param listen_sockfd Listening socket descriptor
 * @param remote_ip Output: remote IP address (4 bytes)
 * @param remote_port Output: remote port number
 * @return Socket descriptor for new connection, or -1 if none available
 *
 * Returns immediately with -1 if no pending connections
 */
int tcp_accept(int listen_sockfd, uint8_t* remote_ip, uint16_t* remote_port);

/*=============================================================================
 * TCP INTERNAL FUNCTIONS - Called by Network Stack
 *=============================================================================*/

/**
 * @brief Handle incoming TCP packet
 * @param src_ip Source IP address
 * @param dest_ip Destination IP address (should be our IP)
 * @param tcp_data Pointer to TCP header and data
 * @param tcp_len Length of TCP segment (header + data)
 * 
 * Called by network stack when TCP packet is received
 */
void tcp_handle_packet(const uint8_t* src_ip, const uint8_t* dest_ip,
                       const uint8_t* tcp_data, size_t tcp_len);

/**
 * @brief Periodic timer tick for TCP stack
 * @param current_time Current time in milliseconds
 * 
 * Should be called periodically (e.g., every 100ms) to handle:
 * - Retransmissions
 * - Keepalives
 * - TIME_WAIT timeout
 * - ACK generation
 */
void tcp_tick(uint32_t current_time);

/**
 * @brief Get current system time in milliseconds
 * @return Current time in milliseconds
 * 
 * This should be implemented based on your PIT timer
 */
uint32_t tcp_get_time_ms(void);

/*=============================================================================
 * TCP UTILITY FUNCTIONS
 *=============================================================================*/

/**
 * @brief Print TCP connection table (for debugging)
 */
void tcp_dump_connections(void);

/**
 * @brief Get a string representation of TCP state
 * @param state TCP state enum value
 * @return String name of the state
 */
const char* tcp_state_to_string(tcp_state_t state);

