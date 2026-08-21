/*=============================================================================
 *  dns.h - TinyOS DNS protocol include 
 *=============================================================================*/
#pragma once

// ==============================================================================
// DNS STRUCT DEFINITIONS
// ==============================================================================

/*
 * DNS Header Structure (12 bytes)
 * The structure fields are defined using big-endian byte order (network order).
 */
typedef struct __attribute__((packed)) {
    uint16_t id;         // Identification number (Used to match responses)
    uint16_t flags;      // Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
    uint16_t qdcount;    // Number of questions
    uint16_t ancount;    // Number of answers (0 for query)
    uint16_t nscount;    // Number of authority records (0 for query)
    uint16_t arcount;    // Number of additional records (0 for query)
} dns_header_t;

// DNS Flag definitions
#define DNS_FLAGS_QUERY  0x0100 // Standard query (QD=0, Opcode=0) - Big Endian!

/*
 * DNS Question Structure
 * Note: QNAME (the domain name) is NOT part of this structure,
 * it is a variable-length, null-terminated series of labels that precedes this.
 */
typedef struct __attribute__((packed)) {
    uint16_t qtype;      // Query Type (1 for A record, 28 for AAAA)
    uint16_t qclass;     // Query Class (1 for IN, Internet)
} dns_question_t;

// Query Type (QTYPE) constants - Big Endian
#define DNS_QTYPE_A     0x0001 // A record (IPv4 address)
#define DNS_QTYPE_AAAA  0x001C // AAAA record (IPv6 address)

// Query Class (QCLASS) constants - Big Endian
#define DNS_QCLASS_IN   0x0001 // Internet class


size_t domain_to_dns_label(const char* domain, uint8_t* buffer, size_t buffer_size);

void send_dns_query(const char* domain);

void set_dns_server(const uint8_t* server_ip);

bool dns_get_resolved_ip(uint8_t* ip_out);

bool dns_is_resolved(void);

void handle_dns_response(uint8_t* dns_data, size_t dns_len, const uint8_t* source_ip);

/**
 * @brief RX-path counters that replaced handle_dns_response()'s per-packet
 *        kprintf sites. Surfaced by ifconfig.
 *
 * The three drop_* attack signatures are kept apart on purpose: a single
 * "dropped" total says something is being rejected while hiding which attack
 * is underway, and these three imply different attacker positions.
 *
 * @param responses       Responses accepted with an A record
 * @param drop_source_ip  Dropped: not from the configured DNS server (spoofing)
 * @param drop_tid        Dropped: transaction ID mismatch (cache poisoning)
 * @param drop_question   Dropped: question name mismatched or absent (injection)
 * @param drop_malformed  Dropped: short, truncated, or non-zero RCODE
 * @param drop_no_answer  Well-formed responses carrying no A record
 * @param drop_name_ptr   Dropped: hostile name-compression pointer
 * @param drop_name_label Dropped: invalid label length / label count
 */
void dns_get_rx_stats(uint32_t* responses, uint32_t* drop_source_ip,
                      uint32_t* drop_tid, uint32_t* drop_question,
                      uint32_t* drop_malformed, uint32_t* drop_no_answer,
                      uint32_t* drop_name_ptr, uint32_t* drop_name_label);

#ifdef TINYOS_FAULT_INJECT
/**
 * @brief Inject a synthetic DNS response (verify-dns-rx-counters.sh only).
 * @param which one of: valid, srcip, tid, question, malformed, noanswer
 *
 * Each variant differs from `valid` in exactly one respect, so a rise in one
 * counter identifies which branch ran. Requires a prior query (`dig`) to have
 * recorded a domain and transaction ID to echo.
 */
void dns_forge_response(const char* which);
#endif
