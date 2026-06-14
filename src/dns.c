/*=============================================================================
 * dns.c - TinyOS DNS protocol
 *=============================================================================*/
#include <stddef.h>
#include <stdint.h>
#include "dns.h"
#include "kernel.h"  // For get_timer_ticks()
#include "kprintf.h"
#include "net.h"
#include "util.h"
#include "crypto.h"  // For csprng_random_bytes()
#include "critical.h"  // SECURITY FIX: For TOCTOU race protection


// ==============================================================================
// DNS IMPLEMENTATION
// ==============================================================================

/* The domain name we are querying */
#define DNS_PORT 53
#define DNS_FLAGS_QUERY  0x0100 // Network byte order (big endian)

// DNS server will be retrieved from DHCP
// For external DNS (like 8.8.8.8), we route through the gateway
uint8_t dns_server_ip[4] = {8, 8, 8, 8};    // Will be set from DHCP

// Storage for last resolved IP address
static uint8_t last_resolved_ip[4] = {0, 0, 0, 0};
static bool dns_resolution_complete = false;

// SECURITY: Track last DNS query Transaction ID to prevent DNS cache poisoning
static uint16_t last_dns_tid = 0;

// SECURITY: Track last queried domain name for question validation
#define MAX_DOMAIN_NAME_LEN 253
static char last_queried_domain[MAX_DOMAIN_NAME_LEN + 1] = {0};

/*=============================================================================
 * INTERNAL DNS STRUCTURES (For Response Parsing)
 *============================================================================*/

// DNS Resource Record (Answer/Authority/Additional)
typedef struct __attribute__((packed)) {
    // Name field is variable/compressed and precedes this struct
    uint16_t type;     // Type of resource record (e.g., 1 for A)
    uint16_t class;    // Class (e.g., 1 for IN)
    uint32_t ttl;      // Time to live
    uint16_t data_len; // Length of RDATA (e.g., 4 for IPv4)
    // RDATA (variable length) follows this struct
} dns_rr_t;


/*=============================================================================
 * FUNCTION: set_dns_server
 *============================================================================*/
/**
 * @brief Sets the DNS server address (typically called by DHCP)
 * @param server_ip The DNS server IP address (4 bytes)
 *
 * SECURITY FIX: Protected against TOCTOU race condition
 * CRITICAL: This function can be called from interrupt context (DHCP handler
 * via network IRQ), while DNS queries read dns_server_ip from task context.
 * Without atomic protection, a race between memcpy write and DNS query reads
 * can result in corrupted/torn IP addresses (e.g., reading {1,2,8,8} during
 * transition from {1,2,3,4} to {8,8,8,8}).
 */
void set_dns_server(const uint8_t* server_ip) {
    /*=========================================================================
     * SECURITY FIX: Atomic Update of DNS Server IP
     * Use critical section to prevent torn reads by concurrent DNS queries.
     * Duration: ~4 memory writes (<10 CPU cycles), negligible latency impact.
     *=======================================================================*/
    CRITICAL_SECTION_ENTER();
    memcpy(dns_server_ip, server_ip, 4);
    CRITICAL_SECTION_EXIT();

    // kprintf("DNS: Server set to %d.%d.%d.%d\n",
    //         dns_server_ip[0], dns_server_ip[1],
    //         dns_server_ip[2], dns_server_ip[3]);
}

/*=============================================================================
 * HELPER: domain_to_dns_label
 *============================================================================*/
/**
 * @brief Converts a domain name string ("example.com") into the DNS label format (7example3com0).
 *
 * SECURITY FIX: Added RFC-compliant bounds checking to prevent buffer overflow
 *
 * @param domain The domain string (e.g., "example.com").
 * @param buffer The output buffer to store the label-encoded domain.
 * @param buffer_size Maximum size of the output buffer (typically 512 for DNS packets)
 * @return size_t The length of the encoded label (including the final zero byte), or 0 on error.
 *
 * RFC 1035 Limits:
 * - Maximum domain name length: 253 bytes
 * - Maximum label length: 63 bytes
 * - Each label is prefixed with a length byte (1-63)
 */
size_t domain_to_dns_label(const char* domain, uint8_t* buffer, size_t buffer_size) {
    if (!domain || !buffer) {
        return 0;  // Invalid input
    }

    size_t domain_len = strlen(domain);

    /*=========================================================================
     * SECURITY: Enforce RFC 1035 maximum domain name length (253 bytes)
     *
     * Prevents buffer overflow attack via long domain names.
     * RFC 1035 Section 2.3.4: Domain names must be ≤ 253 bytes
     *=======================================================================*/
    #define MAX_DOMAIN_NAME_LEN 253
    if (domain_len > MAX_DOMAIN_NAME_LEN) {
        kprintf("[DNS] SECURITY: Domain name too long (%zu > %d bytes). Rejecting.\n",
                domain_len, MAX_DOMAIN_NAME_LEN);
        return 0;
    }

    size_t i = 0;
    size_t start = 0;
    size_t buf_idx = 0;

    // Iterate through the domain string to find dots (label boundaries)
    for (i = 0; i < domain_len; i++) {
        if (domain[i] == '.') {
            size_t label_len = i - start;

            /*=================================================================
             * SECURITY: Enforce RFC 1035 maximum label length (63 bytes)
             *
             * RFC 1035 Section 2.3.1: Each label must be ≤ 63 bytes
             * Labels are 6-bit length field (max 0x3F = 63)
             *===============================================================*/
            #define MAX_DNS_LABEL_LEN 63
            if (label_len > MAX_DNS_LABEL_LEN) {
                kprintf("[DNS] SECURITY: Label length (%zu > %d bytes). Rejecting.\n",
                        label_len, MAX_DNS_LABEL_LEN);
                return 0;
            }

            /*=================================================================
             * SECURITY: Check buffer bounds before writing
             *
             * Prevents stack buffer overflow if encoded domain exceeds buffer
             *===============================================================*/
            if (buf_idx + 1 + label_len >= buffer_size) {
                kprintf("[DNS] SECURITY: Encoded domain exceeds buffer size (%zu). Rejecting.\n",
                        buffer_size);
                return 0;
            }

            // Write the length of the previous label
            buffer[buf_idx++] = (uint8_t)label_len;

            // Write the label characters
            memcpy(buffer + buf_idx, domain + start, label_len);
            buf_idx += label_len;

            // Move start to the character after the dot
            start = i + 1;
        }
    }

    // Process the final label (after the last dot, or the entire domain if no dots)
    size_t last_label_len = domain_len - start;

    /*=========================================================================
     * SECURITY: Validate final label length
     *=======================================================================*/
    if (last_label_len > MAX_DNS_LABEL_LEN) {
        kprintf("[DNS] SECURITY: Final label length (%zu > %d bytes). Rejecting.\n",
                last_label_len, MAX_DNS_LABEL_LEN);
        return 0;
    }

    /*=========================================================================
     * SECURITY: Check buffer bounds for final label + null terminator
     *=======================================================================*/
    if (buf_idx + 1 + last_label_len + 1 >= buffer_size) {
        kprintf("[DNS] SECURITY: Final label exceeds buffer size. Rejecting.\n");
        return 0;
    }

    // Write the length of the final label
    buffer[buf_idx++] = (uint8_t)last_label_len;
    memcpy(buffer + buf_idx, domain + start, last_label_len);
    buf_idx += last_label_len;

    // Null terminator (zero byte)
    buffer[buf_idx++] = 0;

    return buf_idx;
}

/*=============================================================================
 * HELPER: skip_dns_name
 *============================================================================*/
/**
 * @brief Skips a domain name in the DNS response data, handling compression.
 * @param packet_start Pointer to the start of the entire DNS message (needed for compression pointers).
 * @param packet_end Pointer to one byte past the end of the DNS message.
 * @param current_pos Pointer to the current position in the message (start of the name field).
 * @return size_t The number of bytes consumed by the name field, or 0 on error.
 *
 * SECURITY: Protects against DNS compression pointer attacks:
 * 1. Validates all pointers stay within packet bounds
 * 2. Limits maximum labels to prevent infinite loops
 * 3. Validates label lengths (max 63 bytes per DNS RFC 1035)
 * 4. Prevents buffer over-read attacks
 */
static size_t skip_dns_name(const uint8_t* packet_start, const uint8_t* packet_end,
                            const uint8_t* current_pos) {
    const uint8_t* original_pos = current_pos;
    uint8_t len;
    int label_count = 0;

    /*=========================================================================
     * SECURITY: DNS Compression Pointer Attack Protection
     * CRITICAL: DNS compression pointers can create infinite loops or point
     * outside the packet buffer, causing:
     * 1. CPU DoS via infinite loop
     * 2. Buffer over-read (information leakage)
     * 3. Kernel crash from invalid memory access
     *
     * Protection:
     * - Maximum 127 labels (DNS spec allows max 255 bytes, each label >= 2 bytes)
     * - All pointer accesses validated against packet bounds
     * - Label length validated (<= 63 bytes per DNS RFC 1035)
     *=======================================================================*/
    #define MAX_DNS_LABELS 127
    #define MAX_DNS_LABEL_LEN 63

    // Loop through labels until the null terminator (0) or a pointer is found
    while (label_count < MAX_DNS_LABELS) {
        // Boundary check: ensure we can read the length byte
        if (current_pos >= packet_end) {
            kprintf("[DNS] SECURITY: Name parsing exceeded packet boundary. Dropping.\n");
            return 0;  // Error: exceeded packet boundary
        }

        len = *current_pos;

        // Check for null terminator
        if (len == 0) {
            // Null terminator found. Advance by 1 byte for the terminator itself.
            return (current_pos - original_pos) + 1;
        }

        // Check for pointer/compression (starts with bits 11: 0xC0)
        if ((len & 0xC0) == 0xC0) {
            // It's a pointer (2 bytes total)
            // Boundary check: ensure we can read both bytes of the pointer
            if (current_pos + 1 >= packet_end) {
                kprintf("[DNS] SECURITY: Compression pointer at packet boundary. Dropping.\n");
                return 0;  // Error: pointer extends beyond packet
            }

            // Extract pointer offset (lower 14 bits of the 2-byte pointer)
            uint16_t offset = ((uint16_t)(len & 0x3F) << 8) | current_pos[1];

            /*=================================================================
             * SECURITY: Compression pointer bounds validation
             * CRITICAL: Validate pointer offset is:
             * 1. Within packet bounds (prevents out-of-bounds read)
             * 2. Points backward in packet (prevents forward loops)
             *
             * RFC 1035 Section 4.1.4: "The pointer takes the form of a two
             * octet sequence... The offset is measured from the start of
             * the message."
             *
             * By enforcing backward-only pointers, we prevent:
             * - Decompression bombs (forward-pointing circular references)
             * - Infinite loops in malformed packets
             * - Confusion attacks where pointer offsets create ambiguity
             *===============================================================*/

            // Validate pointer stays within packet bounds
            if (packet_start + offset >= packet_end) {
                kprintf("[DNS] SECURITY: Compression pointer (offset %u) points outside packet. Dropping.\n",
                        offset);
                return 0;  // Error: pointer points outside packet
            }

            // Validate pointer points backward (offset must be before current position)
            if (packet_start + offset >= current_pos) {
                kprintf("[DNS] SECURITY: Compression pointer (offset %u) points forward or self. Dropping.\n",
                        offset);
                return 0;  // Error: pointer must point backward to prevent loops
            }

            // Pointer is valid. We only need to advance by 2 bytes (the pointer itself).
            return (current_pos - original_pos) + 2;
        }

        // Normal label: validate length
        if (len > MAX_DNS_LABEL_LEN) {
            kprintf("[DNS] SECURITY: Label length (%u) exceeds max (%u). Dropping.\n",
                    len, MAX_DNS_LABEL_LEN);
            return 0;  // Error: invalid label length
        }

        // Boundary check: ensure we can read the entire label
        if (current_pos + len + 1 > packet_end) {
            kprintf("[DNS] SECURITY: Label extends beyond packet boundary. Dropping.\n");
            return 0;  // Error: label extends beyond packet
        }

        // Advance by (length byte + label length)
        current_pos += (len + 1);
        label_count++;
    }

    // Too many labels - possible infinite loop attack
    kprintf("[DNS] SECURITY: Exceeded max labels (%d). Possible infinite loop attack. Dropping.\n",
            MAX_DNS_LABELS);
    return 0;  // Error: too many labels
}

/*=============================================================================
 * HELPER: dns_label_to_domain
 *============================================================================*/
/**
 * @brief Converts a DNS label format name to a regular domain string.
 * @param packet_start Pointer to the start of the entire DNS message.
 * @param packet_end Pointer to one byte past the end of the DNS message.
 * @param label_start Pointer to the start of the DNS label.
 * @param domain_out Output buffer for the domain string.
 * @param domain_out_size Size of the output buffer.
 * @return true on success, false on error.
 *
 * SECURITY: This function safely handles DNS compression and validates all bounds.
 */
static bool dns_label_to_domain(const uint8_t* packet_start, const uint8_t* packet_end,
                                const uint8_t* label_start, char* domain_out,
                                size_t domain_out_size) {
    const uint8_t* current_pos = label_start;
    size_t out_idx = 0;
    uint8_t len;
    int label_count = 0;
    bool followed_pointer = false;

    #define MAX_DNS_LABELS 127
    #define MAX_DNS_LABEL_LEN 63

    while (label_count < MAX_DNS_LABELS) {
        // Boundary check
        if (current_pos >= packet_end) {
            return false;
        }

        len = *current_pos;

        // Null terminator - we're done
        if (len == 0) {
            // Remove trailing dot if present
            if (out_idx > 0 && domain_out[out_idx - 1] == '.') {
                out_idx--;
            }
            domain_out[out_idx] = '\0';
            return true;
        }

        // Check for compression pointer
        if ((len & 0xC0) == 0xC0) {
            if (current_pos + 1 >= packet_end) {
                return false;
            }

            uint16_t offset = ((uint16_t)(len & 0x3F) << 8) | current_pos[1];

            // Validate pointer
            if (packet_start + offset >= packet_end ||
                packet_start + offset >= current_pos) {
                return false;
            }

            // Track that we've followed a pointer (prevents loops)
            if (!followed_pointer) {
                followed_pointer = true;
            }

            // Follow the pointer
            current_pos = packet_start + offset;
            continue;
        }

        // Normal label
        if (len > MAX_DNS_LABEL_LEN) {
            return false;
        }

        // Boundary check
        if (current_pos + len + 1 > packet_end) {
            return false;
        }

        // Check output buffer space (label + dot + null terminator)
        if (out_idx + len + 2 >= domain_out_size) {
            return false;
        }

        // Copy label to output
        memcpy(domain_out + out_idx, current_pos + 1, len);
        out_idx += len;

        // Add dot separator
        domain_out[out_idx++] = '.';

        // Advance
        current_pos += (len + 1);
        label_count++;
    }

    return false;  // Too many labels
}

/*=============================================================================
 * FUNCTION: handle_dns_response (THE MISSING PIECE)
 *============================================================================*/
/**
 * @brief Parses an incoming DNS response payload to find the IP answer.
 * @param dns_data Pointer to the start of the DNS payload (right after UDP header).
 * @param dns_len Length of the DNS payload.
 * @param source_ip Source IP address of the DNS response packet (for validation).
 */
void handle_dns_response(uint8_t* dns_data, size_t dns_len, const uint8_t* source_ip) {
    // 1. Check minimum length
    if (dns_len < sizeof(dns_header_t)) {
        kprintf("[DNS] Error: Response too short (%zu bytes).\n", dns_len);
        return;
    }

    dns_header_t* hdr = (dns_header_t*)dns_data;

    /*=========================================================================
     * SECURITY FIX: Atomic Read of DNS Server IP for Validation
     * Take a consistent snapshot to prevent TOCTOU during source IP check.
     *=======================================================================*/
    uint8_t local_dns_server[4];
    CRITICAL_SECTION_ENTER();
    memcpy(local_dns_server, dns_server_ip, 4);
    CRITICAL_SECTION_EXIT();

    /*=========================================================================
     * SECURITY: Validate DNS Source IP Address
     * CRITICAL: Verify DNS response came from our configured DNS server.
     * This prevents DNS cache poisoning attacks where an attacker on the
     * same network sends forged DNS responses from a different IP address.
     *
     * Attack scenario:
     * 1. Victim sends DNS query to 8.8.8.8
     * 2. Attacker (at 192.168.1.100) intercepts query on local network
     * 3. Attacker sends forged response with malicious IP before real server
     * 4. Without source IP validation: Victim accepts attacker's response
     * 5. With source IP validation: Response rejected (not from 8.8.8.8)
     *
     * This check works in combination with Transaction ID validation to
     * provide defense-in-depth against DNS spoofing attacks.
     *=======================================================================*/
    if (memcmp(source_ip, local_dns_server, 4) != 0) {
        kprintf("[DNS] SECURITY: Response from unexpected IP: %d.%d.%d.%d (expected %d.%d.%d.%d)\n",
                source_ip[0], source_ip[1], source_ip[2], source_ip[3],
                local_dns_server[0], local_dns_server[1], local_dns_server[2], local_dns_server[3]);
        kprintf("[DNS] Possible DNS spoofing attack detected. Dropping response.\n");
        return;
    }

    /*=========================================================================
     * SECURITY: Validate DNS Transaction ID (TID)
     * This prevents DNS cache poisoning by off-path attackers who inject
     * forged DNS responses. Only accept responses matching our last query.
     *=======================================================================*/
    uint16_t response_tid = ntohs(hdr->id);
    if (response_tid != last_dns_tid) {
        kprintf("[DNS] SECURITY: Transaction ID mismatch! Expected 0x%x, got 0x%x\n",
                last_dns_tid, response_tid);
        kprintf("[DNS] Possible DNS cache poisoning attack detected. Dropping response.\n");
        return;
    }

    // Ã¢Å"â€œ CORRECT DNS Response Header Byte Order
    uint16_t flags = ntohs(hdr->flags);
    uint16_t q_count = ntohs(hdr->qdcount);
    uint16_t ans_count = ntohs(hdr->ancount);

    // Check if it's actually a response (QR bit is 1)
    if ((flags & 0x8000) == 0) {
        kprintf("[DNS] Error: Received DNS message is not a response.\n");
        return;
    }

    // Check for error code (RCODE - last 4 bits)
    uint8_t rcode = flags & 0x000F;
    if (rcode != 0) {
        kprintf("[DNS] Error: Non-zero RCODE (%u). DNS failure.\n", rcode);
        return;
    }

    // Ã¢Å“â€œ CORRECT DNS Response Header Byte Order
    // kprintf("[DNS] Success! Response ID: 0x%x, Answers: %u\n", ntohs(hdr->id), ans_count);  // Commented for less verbosity

    // 2. Process Question Section
    // The question section contains the encoded name + QTYPE + QCLASS
    uint8_t* current_ptr = dns_data + sizeof(dns_header_t);
    const uint8_t* packet_end = dns_data + dns_len;

    for (int i = 0; i < q_count; i++) {
        /*=====================================================================
         * SECURITY: Validate DNS Question Name
         * CRITICAL: Verify the question in the response matches our query.
         * This prevents DNS response injection where an attacker sends a
         * response for a different domain than we queried.
         *
         * Attack scenario:
         * 1. Victim queries "www.bank.com"
         * 2. Attacker intercepts query, sends forged response for "www.evil.com"
         * 3. Without validation: Response accepted, wrong IP cached
         * 4. With validation: Response rejected (question mismatch)
         *====================================================================*/
        char question_domain[MAX_DOMAIN_NAME_LEN + 1];
        if (!dns_label_to_domain(dns_data, packet_end, current_ptr,
                                 question_domain, sizeof(question_domain))) {
            kprintf("[DNS] SECURITY: Failed to parse question name. Dropping response.\n");
            return;
        }

        // Compare against our stored query (case-insensitive per DNS RFC)
        if (strcasecmp(question_domain, last_queried_domain) != 0) {
            kprintf("[DNS] SECURITY: Question name mismatch!\n");
            kprintf("[DNS] Expected: '%s', Got: '%s'\n", last_queried_domain, question_domain);
            kprintf("[DNS] Possible DNS response injection attack. Dropping response.\n");
            return;
        }

        // Skip the variable-length domain name
        size_t name_len = skip_dns_name(dns_data, packet_end, current_ptr);
        if (name_len == 0) {
            kprintf("[DNS] SECURITY: Invalid name in question section. Dropping response.\n");
            return;  // Error in skip_dns_name
        }
        current_ptr += name_len;

        /*=====================================================================
         * SECURITY: Validate question section bounds
         * CRITICAL: After skipping the variable-length name, we must verify
         * that there's enough space for the dns_question_t structure (QTYPE
         * + QCLASS = 4 bytes) before attempting to access it.
         *
         * Attack scenario: Attacker sends DNS response with truncated question
         * section (name ends at packet boundary). Without this check, we would
         * read 4 bytes past packet end, potentially leaking kernel memory.
         *====================================================================*/
        if (current_ptr + sizeof(dns_question_t) > packet_end) {
            kprintf("[DNS] SECURITY: Question section truncated. Dropping response.\n");
            return;
        }

        // Skip QTYPE and QCLASS (4 bytes total - same size as dns_question_t)
        current_ptr += sizeof(dns_question_t);
    }

    /*=========================================================================
     * SECURITY: Require a question section
     * A response with qdcount=0 would skip the question-name validation loop
     * above entirely, bypassing the anti-injection defense. Legitimate
     * responses always echo our question (qdcount=1).
     *=======================================================================*/
    if (q_count == 0) {
        kprintf("[DNS] SECURITY: Response has no question section. Dropping.\n");
        return;
    }

    // 3. Process Answer Section
    for (int i = 0; i < ans_count; i++) {

        // Skip the Name field (often a 2-byte pointer 0xC0 XX)
        size_t name_len = skip_dns_name(dns_data, packet_end, current_ptr);
        if (name_len == 0) {
            kprintf("[DNS] SECURITY: Invalid name in answer section. Dropping response.\n");
            return;  // Error in skip_dns_name
        }
        current_ptr += name_len;

        // Ensure we haven't read past the end of the packet for the RR header
        if (current_ptr + sizeof(dns_rr_t) > dns_data + dns_len) {
            kprintf("[DNS] Warning: Truncated RR in Answer section.\n");
            return;
        }

        // The Resource Record (RR) header starts here
        dns_rr_t* rr = (dns_rr_t*)current_ptr;

        // Ã¢Å“â€œ CORRECT The Resource Record (RR) header Byte Order
        uint16_t type = ntohs(rr->type);
        uint16_t data_len = ntohs(rr->data_len);

        current_ptr += sizeof(dns_rr_t);

        // Ensure the declared RDATA lies entirely within the packet
        if (current_ptr + data_len > packet_end) {
            kprintf("[DNS] SECURITY: Truncated RDATA. Dropping response.\n");
            return;
        }

        // We only care about A records (Type 1) with 4 bytes of data
        if (type == DNS_QTYPE_A && data_len == 4) {
            // The RDATA (the IP address) starts at current_ptr
            uint8_t* ip = current_ptr;

            // Save the resolved IP
            memcpy(last_resolved_ip, ip, 4);
            dns_resolution_complete = true;

            kprintf("[DNS] Resolved IP for domain: %d.%d.%d.%d\n",
                ip[0], ip[1], ip[2], ip[3]);

            return; // Found our answer
        }

        // Skip to the next Resource Record by advancing past the RDATA
        current_ptr += data_len;
    }

    kprintf("[DNS] Finished parsing response. No A (Type 1) record found.\n");
}


/*=============================================================================
* FUNCTION: send_dns_query
*============================================================================
*/

/**
 * @brief Constructs and sends a DNS A-record query for the specified domain.
 * @param domain The domain name to query (e.g., "www.google.com")
 */
void send_dns_query(const char* domain) {
    // Reset DNS resolution flag
    dns_resolution_complete = false;
    memset(last_resolved_ip, 0, 4);

    // Validate input
    if (!domain || strlen(domain) == 0) {
        kprintf("[DNS] Error: Invalid domain name.\n");
        return;
    }

    /*=========================================================================
     * SECURITY: Save queried domain name for response validation
     * This will be used in handle_dns_response() to verify the response
     * question matches our query, preventing DNS response injection attacks.
     *=======================================================================*/
    size_t domain_len = strlen(domain);
    if (domain_len > MAX_DOMAIN_NAME_LEN) {
        kprintf("[DNS] Error: Domain name too long (%zu > %d bytes).\n",
                domain_len, MAX_DOMAIN_NAME_LEN);
        return;
    }
    memset(last_queried_domain, 0, sizeof(last_queried_domain));
    memcpy(last_queried_domain, domain, domain_len);

    /*=========================================================================
     * SECURITY FIX: Atomic Read of DNS Server IP (TOCTOU Protection)
     * CRITICAL: Take a consistent snapshot of dns_server_ip to prevent torn
     * reads during concurrent DHCP updates from interrupt context.
     *
     * ATTACK SCENARIO WITHOUT FIX:
     * 1. Task starts DNS query, reads dns_server_ip[0]=1, dns_server_ip[1]=2
     * 2. Network IRQ fires, DHCP sets dns_server_ip={8,8,8,8}
     * 3. Task continues, reads dns_server_ip[2]=8, dns_server_ip[3]=8
     * 4. Query sent to corrupted IP 1.2.8.8 instead of intended server
     *
     * FIX: Copy dns_server_ip atomically under critical section, then use
     * local copy for all subsequent operations in this function.
     *=======================================================================*/
    uint8_t local_dns_server[4];
    CRITICAL_SECTION_ENTER();
    memcpy(local_dns_server, dns_server_ip, 4);
    CRITICAL_SECTION_EXIT();

    // Check if DNS server is configured (using local copy)
    if (local_dns_server[0] == 0 && local_dns_server[1] == 0 &&
        local_dns_server[2] == 0 && local_dns_server[3] == 0) {
        kprintf("[DNS] Error: DNS server not configured. Waiting for DHCP...\n");
        return;
    }
    
    // We'll use a local buffer for the DNS payload, maxing out at 512 for safety.
    uint8_t dns_packet[512];
    memset(dns_packet, 0, 512);
    
    // 1. DNS Header
    dns_header_t* header = (dns_header_t*)dns_packet;

    /*=========================================================================
     * SECURITY FIX: Generate Unpredictable Transaction ID Using CSPRNG
     * CRITICAL: Previous implementation used deterministic timer-based calculation:
     *   last_dns_tid = (ticks * 31337) ^ (ticks >> 16)
     *
     * Attack: DNS cache poisoning via TID prediction
     * 1. Attacker observes one DNS query TID (e.g., TID=0x1234 at T=100ms)
     * 2. Attacker reverse-engineers timer formula to predict future TIDs
     * 3. On victim's next query, attacker floods DNS server with forged responses
     *    using predicted TID before real server responds
     * 4. Victim accepts forged response, caches malicious IP (e.g., google.com→attacker-IP)
     * 5. Victim connects to attacker's server thinking it's google.com
     *
     * The fix: Use cryptographically strong random number generator (CSPRNG)
     * for unpredictable TID generation. ChaCha20-based CSPRNG provides:
     * - 2^16 possible TID values with uniform distribution
     * - Computationally infeasible to predict next TID even if attacker
     *   observes millions of previous TIDs
     *
     * This is the ONLY defense against DNS cache poisoning attacks in environments
     * without DNSSEC (which we don't have yet).
     *=======================================================================*/
    uint16_t tid_bytes[1];
    csprng_random_bytes(&global_csprng, (uint8_t*)tid_bytes, sizeof(uint16_t));
    last_dns_tid = tid_bytes[0];

    /* Ensure non-zero TID (zero is reserved/invalid in some DNS implementations) */
    if (last_dns_tid == 0) {
        last_dns_tid = 1;
    }

    // Identification: Use generated TID
    header->id = htons(last_dns_tid);

    // Flags: Standard query (QR=0, Opcode=0, RD=1 for Recursion Desired)
    // 0x0100 for query + 0x0001 for RD
    header->flags = htons(0x0100);

    // Question Count: 1
    header->qdcount = htons(1);
    
    // Other counts: 0
    header->ancount = htons(0);
    header->nscount = htons(0);
    header->arcount = htons(0);
    
    size_t current_offset = sizeof(dns_header_t);

    // 2.2. Add QNAME (The encoded domain name) - use the parameter instead of TARGET_DOMAIN
    size_t encoded_len = domain_to_dns_label(domain, dns_packet + current_offset,
                                             sizeof(dns_packet) - current_offset);
    if (encoded_len == 0) {
        kprintf("[DNS] ERROR: Failed to encode domain name '%s'. Query aborted.\n", domain);
        return;
    }
    current_offset += encoded_len;

    // 2.3. Add Question Footer (QTYPE and QCLASS)
    dns_question_t* question = (dns_question_t*)(dns_packet + current_offset);
    
    question->qtype = htons(DNS_QTYPE_A);
    question->qclass = htons(DNS_QCLASS_IN);
    
    current_offset += sizeof(dns_question_t);
    
    size_t payload_len = current_offset;

    // kprintf("DNS: Sending query for %s to %d.%d.%d.%d:%d (Length: %d bytes)\n",
    //        domain,  // Use the parameter here instead of TARGET_DOMAIN
    //        local_dns_server[0], local_dns_server[1], local_dns_server[2], local_dns_server[3],
    //        DNS_PORT, payload_len);  // Commented for less verbosity

    // 3. Get MAC address for next hop using proper routing (use local copy)
    // get_route_mac will use subnet mask to determine if DNS server is local or remote
    uint8_t* dest_mac = get_route_mac(local_dns_server);

    if (dest_mac) {
        /*=====================================================================
         * SECURITY: Generate random ephemeral source port for DNS query
         * CRITICAL: Randomizing the source port (in addition to transaction
         * ID) makes DNS cache poisoning attacks significantly harder by
         * increasing the search space attackers must guess.
         *
         * Port range: 49152-65535 (ephemeral port range per RFC 6335)
         * Bits of entropy: ~14 bits (16384 possible ports)
         *
         * Combined with 16-bit transaction ID = ~30 bits total entropy,
         * requiring ~1 billion guesses on average to poison the cache.
         *====================================================================*/
        uint16_t random_port_bytes[1];
        csprng_random_bytes(&global_csprng, (uint8_t*)random_port_bytes, sizeof(uint16_t));

        // Clamp to ephemeral port range: 49152 + (random % 16384)
        uint16_t src_port = 49152 + (random_port_bytes[0] % 16384);

        // Send UDP packet: IP header has DNS server IP, but Ethernet frame
        // uses next-hop MAC (gateway MAC for external DNS)
        // SECURITY FIX: Use local copy to prevent TOCTOU
        send_udp_packet(
            local_dns_server,          // Destination IP (in IP header) - using local copy
            dest_mac,                  // Next-hop MAC (in Ethernet header)
            src_port,                  // Random source port
            DNS_PORT,                  // Destination Port
            dns_packet,
            payload_len
        );
    } else {
        kprintf("[DNS] Error: Could not resolve MAC for DNS query.\n");
        kprintf("[DNS] Trying to send ARP request for DNS server...\n");
        send_arp_request(local_dns_server);  // SECURITY FIX: Use local copy
    }
}

/*=============================================================================
 * FUNCTION: dns_get_resolved_ip
 *============================================================================*/
/**
 * @brief Get the last resolved IP address
 * @param ip_out Buffer to store the IP address (must be at least 4 bytes)
 * @return true if a resolved IP is available, false otherwise
 */
bool dns_get_resolved_ip(uint8_t* ip_out) {
    if (!dns_resolution_complete || !ip_out) {
        return false;
    }

    memcpy(ip_out, last_resolved_ip, 4);
    return true;
}

/*=============================================================================
 * FUNCTION: dns_is_resolved
 *============================================================================*/
/**
 * @brief Check if DNS resolution is complete
 * @return true if resolution is complete, false otherwise
 */
bool dns_is_resolved(void) {
    return dns_resolution_complete;
}
