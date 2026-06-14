/*=============================================================================
net.h - TinyOS Network Stack Header
============================================================================*/
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*=============================================================================
BYTE ORDER CONVERSION (Network <-> Host)
=============================================================================*/
/*=============================================================================
 * SECURITY: Safe Byte-Order Conversion Macros
 * CRITICAL: Protection Against Undefined Behavior in Bitshift Operations
 *
 * C STANDARD UNDEFINED BEHAVIOR (ISO C99 6.5.7):
 * 1. Shifting by >= width of type (e.g., x << 32 for 32-bit int)
 * 2. Shifting negative values (left shift)
 * 3. Shifting into sign bit of signed integer
 * 4. Right-shifting negative signed integers (implementation-defined)
 *
 * ATTACK SCENARIO:
 * If an attacker can control input to bitshift operations (e.g., via
 * malformed packet headers), they may trigger UB, which the compiler can
 * exploit for arbitrary behavior (crashes, incorrect code generation, etc.)
 *
 * DEFENSE:
 * 1. Use ONLY unsigned types (uint16_t, uint32_t) - no signed integers
 * 2. Explicit casts to unsigned ensure no sign-extension
 * 3. Mask results to ensure bits don't overflow intended width
 * 4. Shift counts are compile-time constants (8, 16, 24) - always safe
 *============================================================================*/

// Convert 16-bit value from host to network byte order (big-endian)
static inline uint16_t htons(uint16_t hostshort) {
    /* Explicit unsigned operations - compiler cannot introduce UB */
    return ((uint16_t)(hostshort >> 8) | (uint16_t)(hostshort << 8));
}

// Convert 16-bit value from network to host byte order
static inline uint16_t ntohs(uint16_t netshort) {
    /* Same as htons for big-endian to little-endian (symmetric) */
    return ((uint16_t)(netshort >> 8) | (uint16_t)(netshort << 8));
}

// Convert 32-bit value from host to network byte order (big-endian)
static inline uint32_t htonl(uint32_t hostlong) {
    /*
     * Explicit casts ensure unsigned arithmetic (no sign extension)
     * Masking ensures each byte stays in its lane
     * Shift counts (8, 16, 24) are always < 32 → No UB
     */
    return (((uint32_t)hostlong >> 24) & 0x000000FFU) |
           (((uint32_t)hostlong >>  8) & 0x0000FF00U) |
           (((uint32_t)hostlong <<  8) & 0x00FF0000U) |
           (((uint32_t)hostlong << 24) & 0xFF000000U);
}

// Convert 32-bit value from network to host byte order
static inline uint32_t ntohl(uint32_t netlong) {
    /* Same as htonl (symmetric byte swap) */
    return (((uint32_t)netlong >> 24) & 0x000000FFU) |
           (((uint32_t)netlong >>  8) & 0x0000FF00U) |
           (((uint32_t)netlong <<  8) & 0x00FF0000U) |
           (((uint32_t)netlong << 24) & 0xFF000000U);
}


/*=============================================================================
NETWORK CONFIGURATION

DANGEROUS INVARIANT: Single-Threaded Network Stack Assumption

All network globals (my_mac, my_ip, ARP cache, TCP state, etc.) lack locking.
This is SAFE ONLY because:
- Network code runs exclusively in IRQ 11 handler (E1000 interrupt)
- No user-mode processes directly access network stack
- Scheduler doesn't preempt interrupt handlers

BREAKS IF:
- Multiple network cards are added (multiple IRQ handlers)
- User-mode syscalls access network state (e.g., socket API)
- Deferred processing moves network code to kernel threads
- SMP is enabled (multiple CPUs handling interrupts)

FIX REQUIRED: Add per-subsystem mutexes (arp_lock, tcp_lock, etc.) or
convert to lock-free data structures before adding concurrency.
============================================================================*/
extern uint8_t my_mac[6];         // Our MAC address
extern uint8_t my_ip[4];          // Our IP address
extern uint8_t subnet_mask[4];    // Subnet mask from DHCP
extern uint8_t gateway_ip[4];     // Gateway/Router IP from DHCP

/*=============================================================================
PROTOCOL CONSTANTS
============================================================================*/
#define IPPROTO_ICMP  1
#define IPPROTO_TCP   6
#define IPPROTO_UDP   17

// #define ICMP_ECHO_REQUEST  8
// #define ICMP_ECHO_REPLY    0

// EtherType constants
#define ETH_TYPE_IPV4      0x0800 // IPv4
#define ETH_TYPE_ARP       0x0806 // Address Resolution Protocol

// ARP constants
#define ARP_HTYPE_ETHERNET 1
#define ARP_PTYPE_IPV4     0x0800
#define ARP_OP_REQUEST     1
#define ARP_OP_REPLY       2

// TCP Flags
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

// Define Common Ports
#define DNS_PORT	53

/*=============================================================================
NETWORK STRUCTURES
============================================================================*/

// Ethernet Header (14 bytes)
typedef struct __attribute__((packed)) {
uint8_t  dest_mac[6];
uint8_t  src_mac[6];
uint16_t ethertype;
} eth_header_t;

// IP Header (simplified, minimum 20 bytes)
typedef struct __attribute__((packed)) {
uint8_t  version_ihl;      // Version (4 bits) + IHL (4 bits)
uint8_t  tos;              // Type of Service
uint16_t total_length;     // Total Length
uint16_t identification;   // Identification
uint16_t flags_fragment;   // Flags (3 bits) + Fragment Offset (13 bits)
uint8_t  ttl;              // Time To Live
uint8_t  protocol;         // Protocol (TCP=6, UDP=17, ICMP=1)
uint16_t checksum;         // IP Header Checksum
uint8_t  src_ip[4];        // Source IP Address
uint8_t  dest_ip[4];       // Destination IP Address
} ip_header_t;

// ICMP Header (8 bytes for Echo Request/Reply)
/*
typedef struct __attribute__((packed)) {
uint8_t  type;           // ICMP message type
uint8_t  code;           // ICMP message code
uint16_t checksum;
uint16_t id;             // Identifier (used for echo requests)
uint16_t sequence;       // Sequence Number (used for echo requests)
// Data follows (variable length)
} icmp_header_t;
*/

// ARP Header (28 bytes for Ethernet/IPv4)
typedef struct __attribute__((packed)) {
uint16_t hardware_type;   // HTYPE (1 for Ethernet)
uint16_t protocol_type;   // PTYPE (0x0800 for IPv4)
uint8_t  hardware_addr_len; // HLEN (6 for Ethernet)
uint8_t  protocol_addr_len; // PLEN (4 for IPv4)
uint16_t operation;       // OPER (1 for request, 2 for reply)
uint8_t  sender_mac[6];   // SHA
uint8_t  sender_ip[4];    // SPA
uint8_t  target_mac[6];   // THA
uint8_t  target_ip[4];    // TPA
} arp_header_t;

// TCP Header (min 20 bytes)
typedef struct __attribute__((packed)) {
uint16_t src_port;
uint16_t dest_port;
uint32_t sequence_number;
uint32_t acknowledgement_number;
uint8_t offset_reserved; // Data offset (4 bits) + Reserved (4 bits)
uint8_t flags;           // Control Flags (URG, ACK, PSH, RST, SYN, FIN)
uint16_t window_size;
uint16_t checksum;
uint16_t urgent_pointer;
// Options follow (variable length)
} tcp_header_t;

// UDP Header (8 bytes)
typedef struct __attribute__((packed)) {
uint16_t src_port;
uint16_t dest_port;
uint16_t length;
uint16_t checksum;
} udp_header_t;

/*=============================================================================
FUNCTION PROTOTYPES
============================================================================*/

void net_init(void);
void handle_packet(uint8_t* data, size_t len);

// Checksum Utilities
uint16_t calculate_checksum(void* addr, size_t len);
uint16_t calculate_l4_checksum(uint8_t* src_ip, uint8_t* dest_ip, uint8_t protocol, void* l4_segment, size_t l4_len);

// Helper Functions
void set_my_ip_from_array(const uint8_t* new_ip);
void set_network_config(const uint8_t* ip, const uint8_t* mask, const uint8_t* gateway);
uint8_t* get_route_mac(const uint8_t* dest_ip);
int parse_ip(const char *ip_str, uint8_t *ip_bytes);

// ARP Functions
void send_arp_announcement(void);
void send_arp_request(uint8_t* target_ip);
uint8_t* arp_lookup(const uint8_t* ip);
void arp_cache_dump(void);
void arp_cache_update(const uint8_t* ip, const uint8_t* mac);
void send_test_arp(const char *target_ip_str);

// Protocol Senders
// void send_icmp_ping(uint8_t* dest_ip);
void send_udp_packet(uint8_t* dest_ip, uint8_t* dest_mac,
uint16_t src_port, uint16_t dest_port,
void* data, size_t data_len);
void send_tcp_syn(uint8_t* dest_ip, uint8_t* dest_mac, uint16_t src_port, uint16_t dest_port);

// The updated TCP sender for the final ACK in the 3-way handshake
void send_tcp_ack(uint8_t* dest_ip, uint8_t* dest_mac, uint16_t src_port, uint16_t dest_port,
uint32_t our_seq_num, uint32_t peer_seq_num);

// PCI E1000 Discovery Function
bool pci_find_e1000(uint32_t* mmio_base);

// E1000 Driver Functions
void e1000_init(uint32_t base);
void e1000_send(void* data, size_t len);
void e1000_poll_rx(void);
void e1000_set_packet_dump(bool enable);
void e1000_get_stats(uint32_t* tx_count, uint32_t* rx_count);
