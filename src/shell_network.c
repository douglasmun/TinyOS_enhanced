/*=============================================================================
 * shell_network.c - Shell Network Commands Implementation
 *=============================================================================*/
#include "shell_network.h"
#include "kprintf.h"
#include "util.h"
#include "net.h"
#include "tcp.h"
#include "dns.h"
#include "dhcp.h"
#include "icmp.h"
#include "kernel.h"  /* For get_timer_ticks() */
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

/*=============================================================================
 * HELPER: Safe string append with bounds checking
 * SECURITY FIX: Prevents buffer overflow in string concatenation
 * Returns: true on success, false if buffer would overflow
 *=============================================================================*/
static bool safe_str_append(char* dest, size_t* current_len, size_t max_len, const char* src) {
    if (!dest || !src || !current_len) {
        return false;
    }

    size_t src_len = strlen(src);

    /* Check if append would overflow (leave room for null terminator) */
    if (*current_len + src_len >= max_len) {
        return false;  /* Would overflow */
    }

    /* Safe to append */
    for (size_t i = 0; i < src_len; i++) {
        dest[*current_len + i] = src[i];
    }
    *current_len += src_len;
    dest[*current_len] = '\0';  /* Ensure null termination */

    return true;
}

/*=============================================================================
 * HELPER: Safe integer parsing with overflow protection
 * SECURITY FIX: Strict mode - rejects whitespace, non-decimal input
 *=============================================================================*/
static bool safe_parse_int(const char* str, int* result) {
    if (!str || !*str) {
        return false;
    }

    int value = 0;
    const char* p = str;
    bool is_negative = false;

    /* SECURITY FIX: Reject leading/trailing whitespace (strict mode)
     * This prevents confusion attacks like " 123" or "123 " being accepted
     */
    if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        return false;  /* Reject leading whitespace */
    }

    /* SECURITY FIX: Handle negative sign */
    if (*p == '-') {
        is_negative = true;
        p++;
    } else if (*p == '+') {
        p++;
    }

    /* Ensure there's at least one digit after sign */
    if (!(*p >= '0' && *p <= '9')) {
        return false;
    }

    /* Parse digits with overflow/underflow checking */
    while (*p >= '0' && *p <= '9') {
        int digit = *p - '0';

        if (is_negative) {
            /* Check for underflow before multiplication */
            if (value < (INT_MIN / 10)) {
                return false;  /* Would underflow */
            }

            value *= 10;

            /* Check for underflow before subtraction */
            if (value < (INT_MIN + digit)) {
                return false;  /* Would underflow */
            }

            value -= digit;
        } else {
            /* Check for overflow before multiplication */
            if (value > (INT_MAX / 10)) {
                return false;  /* Would overflow */
            }

            value *= 10;

            /* Check for overflow before addition */
            if (value > (INT_MAX - digit)) {
                return false;  /* Would overflow */
            }

            value += digit;
        }

        p++;
    }

    /* Ensure we consumed the entire string */
    if (*p != '\0') {
        return false;  /* Invalid characters */
    }

    *result = value;
    return true;
}

/*=============================================================================
 * COMMAND: ifconfig - Display network configuration
 *=============================================================================*/
void cmd_ifconfig(void) {
    kprintf("\nNetwork Configuration:\n");
    kprintf("  MAC Address:  %02x:%02x:%02x:%02x:%02x:%02x\n",
            my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
    kprintf("  IP Address:   %d.%d.%d.%d\n",
            my_ip[0], my_ip[1], my_ip[2], my_ip[3]);
    kprintf("  Subnet Mask:  %d.%d.%d.%d\n",
            subnet_mask[0], subnet_mask[1], subnet_mask[2], subnet_mask[3]);
    kprintf("  Gateway:      %d.%d.%d.%d\n",
            gateway_ip[0], gateway_ip[1], gateway_ip[2], gateway_ip[3]);
    kprintf("\n");
}

/*=============================================================================
 * COMMAND: ping - Send ICMP ping to host
 *=============================================================================*/
void cmd_ping(int argc, char* argv[]) {
    if (argc < 2) {
        kprintf("Usage: ping <host>\n");
        kprintf("Example: ping 192.168.0.1\n");
        kprintf("         ping example.com\n");
        return;
    }

    char* target = argv[1];
    int count = 4;  // Default to 4 pings

    // Optional count argument with safe parsing
    if (argc >= 3) {
        int c = 0;
        if (!safe_parse_int(argv[2], &c)) {
            kprintf("ping: invalid count: '%s'\n", argv[2]);
            return;
        }
        if (c > 0 && c <= 100) {
            count = c;
        } else {
            kprintf("ping: count must be between 1 and 100\n");
            return;
        }
    }

    // Check if target is an IP address or domain name
    // Simple heuristic: if it contains only digits and dots, it's likely an IP
    bool is_ip = true;
    for (const char* p = target; *p; p++) {
        if (*p != '.' && (*p < '0' || *p > '9')) {
            is_ip = false;
            break;
        }
    }

    char resolved_ip[16];
    if (is_ip) {
        // It's already an IP address, use it directly
        kprintf("Pinging %s with %d packets...\n", target, count);
        reset_ping_stats();
        send_test_ping(target, count);
    } else {
        // It's a domain name, resolve it first
        kprintf("Resolving %s...\n", target);
        send_dns_query(target);

        uint32_t start = tcp_get_time_ms();
        uint8_t ip_bytes[4];
        bool resolved = false;

        while ((tcp_get_time_ms() - start) < 5000) {
            if (dns_is_resolved()) {
                if (dns_get_resolved_ip(ip_bytes)) {
                    // Format IP as string
                    int pos = 0;
                    for (int i = 0; i < 4; i++) {
                        uint8_t octet = ip_bytes[i];
                        if (octet >= 100) {
                            resolved_ip[pos++] = '0' + (octet / 100);
                            octet %= 100;
                        }
                        if (octet >= 10 || ip_bytes[i] >= 100) {
                            resolved_ip[pos++] = '0' + (octet / 10);
                            octet %= 10;
                        }
                        resolved_ip[pos++] = '0' + octet;
                        if (i < 3) resolved_ip[pos++] = '.';
                    }
                    resolved_ip[pos] = '\0';

                    kprintf("Resolved to %s\n", resolved_ip);
                    kprintf("Pinging %s with %d packets...\n", resolved_ip, count);
                    resolved = true;
                    break;
                }
            }
            for (volatile int i = 0; i < 100000; i++);
        }

        if (!resolved) {
            kprintf("DNS resolution failed (timeout)\n");
            return;
        }

        reset_ping_stats();
        send_test_ping(resolved_ip, count);
    }
}

/*=============================================================================
 * COMMAND: dig - DNS lookup utility (Unix-like)
 *=============================================================================*/
void cmd_dig(int argc, char* argv[]) {
    if (argc < 2) {
        kprintf("Usage: dig [@server] <hostname> [type] [options]\n");
        kprintf("\nOptions:\n");
        kprintf("  +short       Display only the IP address\n");
        kprintf("  +noall       Clear all display flags\n");
        kprintf("  +answer      Display answer section\n");
        kprintf("  +stats       Display query statistics\n");
        kprintf("  @server      Query specific DNS server (e.g., @8.8.8.8)\n");
        kprintf("\nQuery types:\n");
        kprintf("  A            IPv4 address (default)\n");
        kprintf("  AAAA         IPv6 address (not yet supported)\n");
        kprintf("\nExamples:\n");
        kprintf("  dig example.com\n");
        kprintf("  dig example.com +short\n");
        kprintf("  dig @8.8.8.8 example.com\n");
        kprintf("  dig example.com A +stats\n");
        return;
    }

    /* Parse options */
    bool short_output = false;
    bool show_answer = true;   /* Default: show answer */
    bool show_stats = false;
    bool noall = false;
    char* hostname = NULL;
    char* query_type = "A";    /* Default query type */
    uint8_t custom_dns[4] = {0, 0, 0, 0};
    bool use_custom_dns = false;

    /* Parse all arguments */
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '+') {
            /* Option flag */
            if (strcmp(argv[i], "+short") == 0) {
                short_output = true;
            } else if (strcmp(argv[i], "+noall") == 0) {
                noall = true;
                show_answer = false;
                show_stats = false;
            } else if (strcmp(argv[i], "+answer") == 0) {
                show_answer = true;
            } else if (strcmp(argv[i], "+stats") == 0) {
                show_stats = true;
            } else {
                kprintf("dig: unknown option: %s\n", argv[i]);
                return;
            }
        } else if (argv[i][0] == '@') {
            /* Custom DNS server */
            const char* server_str = argv[i] + 1;

            /* Parse IP address (simple validation) */
            int octets[4];
            int octet_idx = 0;
            int current_val = 0;
            bool has_digit = false;

            for (const char* p = server_str; *p && octet_idx < 4; p++) {
                if (*p >= '0' && *p <= '9') {
                    current_val = current_val * 10 + (*p - '0');
                    has_digit = true;
                    if (current_val > 255) {
                        kprintf("dig: invalid IP address: %s\n", server_str);
                        return;
                    }
                } else if (*p == '.') {
                    if (!has_digit) {
                        kprintf("dig: invalid IP address: %s\n", server_str);
                        return;
                    }
                    octets[octet_idx++] = current_val;
                    current_val = 0;
                    has_digit = false;
                } else {
                    kprintf("dig: invalid IP address: %s\n", server_str);
                    return;
                }
            }

            if (has_digit && octet_idx == 3) {
                octets[octet_idx] = current_val;
                custom_dns[0] = (uint8_t)octets[0];
                custom_dns[1] = (uint8_t)octets[1];
                custom_dns[2] = (uint8_t)octets[2];
                custom_dns[3] = (uint8_t)octets[3];
                use_custom_dns = true;
            } else {
                kprintf("dig: invalid IP address: %s\n", server_str);
                return;
            }
        } else if (strcmp(argv[i], "A") == 0 || strcmp(argv[i], "AAAA") == 0) {
            /* Query type */
            query_type = argv[i];
        } else if (!hostname) {
            /* First non-option argument is the hostname */
            hostname = argv[i];
        }
    }

    if (!hostname) {
        kprintf("dig: missing hostname\n");
        kprintf("Try 'dig' with no arguments for usage.\n");
        return;
    }

    /* Check for unsupported query types */
    if (strcmp(query_type, "AAAA") == 0) {
        kprintf("dig: AAAA (IPv6) queries not yet supported\n");
        return;
    }

    /* Save current DNS server and set custom one if specified */
    uint8_t saved_dns[4];
    if (use_custom_dns) {
        /* Get current DNS server */
        const dhcp_client_t* client = dhcp_get_client_info();
        if (client && client->configured) {
            memcpy(saved_dns, client->dns_server, 4);
        }
        set_dns_server(custom_dns);
    }

    /* Display query header (unless +short) */
    if (!short_output) {
        kprintf("\n; <<>> TinyOS dig 1.0 <<>> %s", hostname);
        if (use_custom_dns) {
            kprintf(" @%d.%d.%d.%d", custom_dns[0], custom_dns[1],
                    custom_dns[2], custom_dns[3]);
        }
        kprintf("\n");

        /* Global options */
        kprintf(";; global options: +cmd\n");

        /* Query info */
        kprintf(";; Got answer:\n");
    }

    /* Send query and measure time */
    uint32_t query_start = tcp_get_time_ms();
    send_dns_query(hostname);

    uint32_t start = tcp_get_time_ms();
    uint8_t resolved_ip[4];
    bool resolved = false;

    while ((tcp_get_time_ms() - start) < 5000) {
        if (dns_is_resolved()) {
            if (dns_get_resolved_ip(resolved_ip)) {
                resolved = true;
                break;
            }
        }
        for (volatile int i = 0; i < 100000; i++);
    }

    uint32_t query_time = tcp_get_time_ms() - query_start;

    /* Restore original DNS server if we changed it */
    if (use_custom_dns) {
        const dhcp_client_t* client = dhcp_get_client_info();
        if (client && client->configured) {
            set_dns_server(saved_dns);
        }
    }

    if (!resolved) {
        if (!short_output) {
            kprintf(";; connection timed out; no servers could be reached\n\n");
        } else {
            kprintf("Query failed\n");
        }
        return;
    }

    /* Display answer section */
    if (short_output) {
        /* Short format: just the IP */
        kprintf("%d.%d.%d.%d\n",
                resolved_ip[0], resolved_ip[1],
                resolved_ip[2], resolved_ip[3]);
    } else {
        /* Standard dig format */
        if (show_answer) {
            kprintf(";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 0\n");
            kprintf(";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0\n\n");

            /* Question section */
            kprintf(";; QUESTION SECTION:\n");
            kprintf(";%-30s IN      %s\n\n", hostname, query_type);

            /* Answer section */
            kprintf(";; ANSWER SECTION:\n");
            kprintf("%-30s 300     IN      A       %d.%d.%d.%d\n\n",
                    hostname, resolved_ip[0], resolved_ip[1],
                    resolved_ip[2], resolved_ip[3]);
        }

        /* Query statistics */
        if (show_stats || (!noall && !short_output)) {
            kprintf(";; Query time: %u msec\n", query_time);

            /* Get DNS server info */
            const dhcp_client_t* client = dhcp_get_client_info();
            if (use_custom_dns) {
                kprintf(";; SERVER: %d.%d.%d.%d#53\n",
                        custom_dns[0], custom_dns[1],
                        custom_dns[2], custom_dns[3]);
            } else if (client && client->configured) {
                kprintf(";; SERVER: %d.%d.%d.%d#53\n",
                        client->dns_server[0], client->dns_server[1],
                        client->dns_server[2], client->dns_server[3]);
            }

            /* Timestamp */
            uint32_t ticks = get_timer_ticks();
            kprintf(";; WHEN: System uptime %u ticks\n", ticks);
            kprintf(";; MSG SIZE  rcvd: 44\n\n");
        }
    }
}

/*=============================================================================
 * COMMAND: dhcp - Display DHCP client status and optionally renew lease
 *=============================================================================*/
void cmd_dhcp(int argc, char* argv[]) {
    const dhcp_client_t* client = dhcp_get_client_info();

    if (!client) {
        kprintf("DHCP client not initialized\n");
        return;
    }

    /* Check if renew was requested */
    bool renew_requested = false;
    if (argc >= 2 && strcmp(argv[1], "renew") == 0) {
        renew_requested = true;
    }

    /* Handle renew request */
    if (renew_requested) {
        kprintf("Requesting DHCP lease renewal...\n");
        dhcp_start();  /* Trigger DHCP discovery */

        /* Wait up to 10 seconds for DHCP to complete */
        kprintf("Waiting for DHCP response");
        for (int i = 0; i < 100; i++) {  /* 100 * 100ms = 10 seconds */
            /* Busy wait for ~100ms */
            for (volatile int j = 0; j < 1000000; j++);

            client = dhcp_get_client_info();
            if (client && client->configured) {
                kprintf(" OK\n");
                break;
            }

            /* Print progress dots */
            if (i % 10 == 0) {
                kprintf(".");
            }
        }

        /* Get updated client info */
        client = dhcp_get_client_info();
        if (!client || !client->configured) {
            kprintf(" TIMEOUT\n");
            kprintf("\nDHCP renewal failed. Please check:\n");
            kprintf("  - Network cable is connected\n");
            kprintf("  - DHCP server is running on the network\n");
            kprintf("  - Firewall is not blocking DHCP (ports 67/68)\n\n");
            return;
        }

        kprintf("\n");
    }

    /* Display current DHCP status */
    const char* state_names[] = {
        "INIT", "SELECTING", "REQUESTING", "BOUND", "RENEWING", "REBINDING"
    };

    /* Cute DHCP mascot */
    kprintf("\n");
    kprintf("   (\\_/) Hearty <3\n");
    kprintf("   (o.o) Thoughts ooO\n");
    kprintf("------------------------\n");
    kprintf("|  DHCP Lease Status   |\n");
    kprintf("------------------------\n");
    kprintf("\n");
    kprintf("  State:        %s\n", state_names[client->state]);
    kprintf("  Configured:   %s\n", client->configured ? "Yes" : "No");

    if (client->configured) {
        kprintf("  Offered IP:   %d.%d.%d.%d\n",
                client->offered_ip[0], client->offered_ip[1],
                client->offered_ip[2], client->offered_ip[3]);
        kprintf("  Server IP:    %d.%d.%d.%d\n",
                client->server_ip[0], client->server_ip[1],
                client->server_ip[2], client->server_ip[3]);
        kprintf("  Subnet Mask:  %d.%d.%d.%d\n",
                client->subnet_mask[0], client->subnet_mask[1],
                client->subnet_mask[2], client->subnet_mask[3]);
        kprintf("  Gateway:      %d.%d.%d.%d\n",
                client->router_ip[0], client->router_ip[1],
                client->router_ip[2], client->router_ip[3]);
        kprintf("  DNS Server:   %d.%d.%d.%d\n",
                client->dns_server[0], client->dns_server[1],
                client->dns_server[2], client->dns_server[3]);
        kprintf("  Lease Time:   %u seconds\n", client->lease_time);
    } else {
        kprintf("\nNo DHCP lease acquired. Run 'dhcp renew' to retry.\n");
    }
    kprintf("\n");
}

/*=============================================================================
 * COMMAND: curl - Fetch HTTP content from URL
 *=============================================================================*/
void cmd_curl(int argc, char* argv[]) {
    if (argc < 2) {
        kprintf("Usage: curl <url>\n");
        kprintf("Example: curl example.com\n");
        kprintf("         curl http://example.com/\n");
        return;
    }

    char* url = argv[1];

    /* Auto-prepend http:// if not present */
    char full_url[256];
    char* hostname_start;

    if (strstr(url, "http://") == url) {
        /* URL already starts with http:// */
        hostname_start = url + 7;
    } else if (strstr(url, "https://") == url) {
        /* HTTPS not supported */
        kprintf("Error: HTTPS not supported (use http:// or omit protocol)\n");
        return;
    } else {
        /* No protocol specified - prepend http:// */
        size_t url_len = strlen(url);
        if (url_len + 8 >= sizeof(full_url)) {
            kprintf("Error: URL too long\n");
            return;
        }
        /* Manually build "http://" + url */
        const char* prefix = "http://";
        size_t i;
        for (i = 0; prefix[i] != '\0'; i++) {
            full_url[i] = prefix[i];
        }
        for (size_t j = 0; j < url_len; j++) {
            full_url[i + j] = url[j];
        }
        full_url[i + url_len] = '\0';
        url = full_url;
        hostname_start = url + 7;
    }

    /* Find the path (everything after hostname) */
    char* path_start = strchr(hostname_start, '/');
    char* path = path_start ? path_start : "/";

    /* Extract hostname */
    char hostname[128];
    size_t hostname_len = path_start ? (size_t)(path_start - hostname_start) : strlen(hostname_start);
    if (hostname_len >= sizeof(hostname)) {
        kprintf("Error: Hostname too long\n");
        return;
    }

    for (size_t i = 0; i < hostname_len; i++) {
        hostname[i] = hostname_start[i];
    }
    hostname[hostname_len] = '\0';

    /*
     * Security: Sanitize path to prevent directory traversal attacks.
     * Check for dangerous sequences like ".." and non-printable characters.
     */
    for (const char* p = path; *p; p++) {
        /* Check for ".." sequence */
        if (p[0] == '.' && p[1] == '.') {
            kprintf("Error: Path contains unsafe '..' sequence\n");
            return;
        }
        /* Check for non-printable characters (except '/') */
        if (*p < 32 || *p > 126) {
            kprintf("Error: Path contains non-printable characters\n");
            return;
        }
    }

    kprintf("Fetching %s%s...\n", hostname, path);

    /* Resolve hostname */
    uint8_t server_ip[4];
    send_dns_query(hostname);

    uint32_t start = tcp_get_time_ms();
    bool resolved = false;

    while ((tcp_get_time_ms() - start) < 5000) {
        if (dns_is_resolved()) {
            if (dns_get_resolved_ip(server_ip)) {
                kprintf("Resolved to %d.%d.%d.%d\n",
                        server_ip[0], server_ip[1], server_ip[2], server_ip[3]);
                resolved = true;
                break;
            }
        }
        for (volatile int i = 0; i < 100000; i++);
    }

    if (!resolved) {
        kprintf("DNS resolution failed\n");
        return;
    }

    /* Create socket and connect */
    int sock = tcp_socket();
    if (sock < 0) {
        kprintf("Failed to create socket\n");
        return;
    }

    if (tcp_connect(sock, server_ip, 80) < 0) {
        kprintf("Failed to connect\n");
        tcp_close(sock);
        return;
    }

    /* Wait for connection */
    uint32_t timeout = tcp_get_time_ms() + 5000;
    bool connected = false;

    while (tcp_get_time_ms() < timeout) {
        if (tcp_is_connected(sock)) {
            connected = true;
            break;
        }
        for (volatile int i = 0; i < 100000; i++);
    }

    if (!connected) {
        kprintf("Connection timeout\n");
        tcp_close(sock);
        return;
    }

    /* SECURITY FIX: Build HTTP request using safe string append
     * Replaces manual character-by-character assembly that was prone to off-by-one errors
     */
    char request[256];
    size_t req_len = 0;
    const size_t max_len = sizeof(request);

    request[0] = '\0';  /* Initialize */

    /* Build request using safe append operations */
    if (!safe_str_append(request, &req_len, max_len, "GET ") ||
        !safe_str_append(request, &req_len, max_len, path) ||
        !safe_str_append(request, &req_len, max_len, " HTTP/1.0\r\n") ||
        !safe_str_append(request, &req_len, max_len, "Host: ") ||
        !safe_str_append(request, &req_len, max_len, hostname) ||
        !safe_str_append(request, &req_len, max_len, "\r\n") ||
        !safe_str_append(request, &req_len, max_len, "Connection: close\r\n\r\n")) {
        kprintf("HTTP request too large for buffer\n");
        tcp_close(sock);
        return;
    }

    if (tcp_send(sock, request, req_len) < 0) {
        kprintf("Failed to send request\n");
        tcp_close(sock);
        return;
    }

    /* Receive and display response */
    kprintf("\n--- Response ---\n");

    char buffer[512];
    int total = 0;
    timeout = tcp_get_time_ms() + 10000;

    while (tcp_get_time_ms() < timeout) {
        if (tcp_available(sock) > 0) {
            int n = tcp_recv(sock, buffer, sizeof(buffer) - 1);
            if (n > 0) {
                total += n;
                buffer[n] = '\0';
                kprintf("%s", buffer);
                timeout = tcp_get_time_ms() + 2000;
            } else if (n == 0) {
                break;
            }
        }
        for (volatile int i = 0; i < 50000; i++);
    }

    kprintf("\n--- End (%d bytes) ---\n", total);
    tcp_close(sock);
}
