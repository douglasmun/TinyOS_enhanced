/*=============================================================================
 * dhcp.h - DHCP Client Protocol Header
 *============================================================================*/
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*=============================================================================
 * DHCP CONSTANTS
 *============================================================================*/
#define DHCP_SERVER_PORT  67
#define DHCP_CLIENT_PORT  68

#define DHCP_OP_BOOTREQUEST  1
#define DHCP_OP_BOOTREPLY    2

#define DHCP_HTYPE_ETHERNET  1
#define DHCP_HLEN_ETHERNET   6

#define DHCP_MAGIC_COOKIE    0x63825363

// DHCP Message Types (Option 53)
#define DHCP_DISCOVER  1
#define DHCP_OFFER     2
#define DHCP_REQUEST   3
#define DHCP_DECLINE   4
#define DHCP_ACK       5
#define DHCP_NAK       6
#define DHCP_RELEASE   7
#define DHCP_INFORM    8

// DHCP Options
#define DHCP_OPTION_SUBNET_MASK      1
#define DHCP_OPTION_ROUTER           3
#define DHCP_OPTION_DNS_SERVER       6
#define DHCP_OPTION_HOSTNAME         12
#define DHCP_OPTION_REQUESTED_IP     50
#define DHCP_OPTION_LEASE_TIME       51
#define DHCP_OPTION_MESSAGE_TYPE     53
#define DHCP_OPTION_SERVER_ID        54
#define DHCP_OPTION_PARAM_REQUEST    55
#define DHCP_OPTION_RENEWAL_TIME     58
#define DHCP_OPTION_REBINDING_TIME   59
#define DHCP_OPTION_CLIENT_ID        61
#define DHCP_OPTION_END              255

/*=============================================================================
 * DHCP STRUCTURES
 *============================================================================*/
typedef struct __attribute__((packed)) {
    uint8_t  op;           // Message op code (1=request, 2=reply)
    uint8_t  htype;        // Hardware address type (1=Ethernet)
    uint8_t  hlen;         // Hardware address length (6 for Ethernet)
    uint8_t  hops;         // Client sets to zero
    uint32_t xid;          // Transaction ID
    uint16_t secs;         // Seconds elapsed
    uint16_t flags;        // Flags (bit 0 = broadcast)
    uint8_t  ciaddr[4];    // Client IP address
    uint8_t  yiaddr[4];    // 'Your' (client) IP address
    uint8_t  siaddr[4];    // Next server IP address
    uint8_t  giaddr[4];    // Relay agent IP address
    uint8_t  chaddr[16];   // Client hardware address
    uint8_t  sname[64];    // Optional server host name
    uint8_t  file[128];    // Boot file name
    uint32_t magic_cookie; // Magic cookie (0x63825363)
    // Options follow...
} dhcp_header_t;

typedef enum {
    DHCP_STATE_INIT,
    DHCP_STATE_SELECTING,
    DHCP_STATE_REQUESTING,
    DHCP_STATE_BOUND,
    DHCP_STATE_RENEWING,
    DHCP_STATE_REBINDING
} dhcp_state_t;

typedef struct {
    dhcp_state_t state;
    uint32_t xid;              // Transaction ID
    uint8_t  offered_ip[4];    // IP offered by server
    uint8_t  server_ip[4];     // DHCP server IP
    uint8_t  subnet_mask[4];   // Subnet mask
    uint8_t  router_ip[4];     // Default gateway
    uint8_t  dns_server[4];    // DNS server
    uint32_t lease_time;       // Lease time in seconds
    uint32_t lease_start;      // When lease was acquired (timer ticks)
    uint32_t renewal_time;     // When to renew (ticks) = lease_start + (T1 + jitter)
    bool     configured;       // Whether network is configured
} dhcp_client_t;

/*=============================================================================
 * FUNCTION PROTOTYPES
 *============================================================================*/

/**
 * @brief Initialize DHCP client
 */
void dhcp_init(void);

/**
 * @brief Start DHCP discovery process
 */
void dhcp_start(void);

/**
 * @brief Handle received DHCP packet
 * @param data Pointer to DHCP packet data
 * @param len Length of DHCP packet
 */
void handle_dhcp(const uint8_t* data, size_t len);

/**
 * @brief Get current DHCP state
 * @return Current DHCP state
 */
dhcp_state_t dhcp_get_state(void);

/**
 * @brief Check if DHCP has configured the network
 * @return true if network is configured, false otherwise
 */
bool dhcp_is_configured(void);

/**
 * @brief Get DHCP client info
 * @return Pointer to DHCP client structure
 */
const dhcp_client_t* dhcp_get_client_info(void);

/**
 * @brief DHCP periodic timer tick for lease renewal
 * @param current_time Current time in milliseconds
 *
 * Should be called periodically (e.g., every 10ms) to handle:
 * - Lease renewal at T1 (50% of lease time + jitter)
 * - Lease rebinding at T2 (87.5% of lease time)
 */
void dhcp_tick(uint32_t current_time);
