/*=============================================================================
 * icmp.h - ICMP Protocol Header
 *============================================================================*/
#pragma once

#include <stdint.h>
#include <stddef.h>

/*=============================================================================
 * ICMP DEFINITIONS
 *============================================================================*/
#define ICMP_ECHO_REPLY   0
#define ICMP_ECHO_REQUEST 8

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
} __attribute__((packed)) icmp_header_t;


/*=============================================================================
 * FUNCTION PROTOTYPES
 *============================================================================*/

/**
 * @brief Initialize ICMP subsystem (randomize ping identifier with CSPRNG)
 *
 * Must be called after crypto_init() during network initialization.
 */
void icmp_init(void);

/**
 * @brief Handle received ICMP packet with full context for proper replies
 * @param eth_frame Pointer to full Ethernet frame
 * @param eth_len Length of Ethernet frame
 * @param ip_hdr Pointer to IP header within the frame
 * @param ip_len Length of IP header
 * @param icmp_payload Pointer to ICMP payload
 * @param icmp_len Length of ICMP payload
 */
void handle_icmp_with_context(const uint8_t* eth_frame,
                              size_t eth_len,
                              const uint8_t* ip_hdr,
                              size_t ip_len,
                              const uint8_t* icmp_payload,
                              size_t icmp_len);

/**
 * @brief Send ICMP Echo Request (ping)
 * @param dest_ip Destination IP address (4 bytes)
 * @param dest_mac Destination MAC address (6 bytes)
 * @param seq Sequence number for this ping
 */
void send_icmp_ping(const uint8_t* dest_ip, const uint8_t* dest_mac, uint16_t seq);

/**
 * @brief Send test pings to a target IP address
 * @param target_ip_str Target IP address as string (e.g., "192.168.0.1")
 * @param count Number of pings to send
 */
void send_test_ping(const char* target_ip_str, int count);

/**
 * @brief Reset ping statistics
 */
void reset_ping_stats(void);
