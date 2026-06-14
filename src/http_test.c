/*=============================================================================
 * http_test.c - Simple HTTP Client Test for TinyOS TCP Stack
 *
 * This provides a reliable test of the TCP stack using HTTP, which is
 * universally supported and definitely works through QEMU user networking.
 *
 * SECURITY: Test code guarded with TINYOS_ENABLE_TESTS to prevent inclusion
 * in production builds. Define at compile time to enable test functionality.
 *=============================================================================*/
#ifdef TINYOS_ENABLE_TESTS

#include "tcp.h"
#include "net.h"
#include "dns.h"
#include "kprintf.h"
#include "kernel.h"
#include "util.h"
#include "http_test.h"

/**
 * @brief Simple HTTP GET request to example.com
 * This is a reliable test because:
 * - HTTP is universally supported
 * - example.com is maintained specifically for testing
 * - Works through QEMU user networking
 * - Port 80 is always open
 */
void test_http_get(void) {
    kprintf("\n");
    kprintf("╔════════════════════════════════════════════╗\n");
    kprintf("║     HTTP CLIENT TEST                       ║\n");
    kprintf("╚════════════════════════════════════════════╝\n");
    kprintf("\n");

    const char* hostname = "example.com";
    uint8_t server_ip[4];
    uint16_t port = 80;

    // Resolve hostname using DNS
    kprintf("Resolving hostname: %s\n", hostname);
    send_dns_query(hostname);

    // Wait for DNS resolution (max 5 seconds)
    uint32_t start = tcp_get_time_ms();
    uint32_t timeout_ms = 5000;
    bool resolved = false;

    while ((tcp_get_time_ms() - start) < timeout_ms) {
        if (dns_is_resolved()) {
            if (dns_get_resolved_ip(server_ip)) {
                kprintf("Resolved %s to %d.%d.%d.%d\n",
                        hostname,
                        server_ip[0], server_ip[1],
                        server_ip[2], server_ip[3]);
                resolved = true;
                break;
            }
        }
        // Small delay
        for (volatile int i = 0; i < 100000; i++);
    }

    if (!resolved) {
        kprintf("ERROR: DNS resolution timeout\n");
        kprintf("Falling back to hardcoded IP 23.215.0.136\n");
        server_ip[0] = 23;
        server_ip[1] = 215;
        server_ip[2] = 0;
        server_ip[3] = 136;
    }

    kprintf("Connecting to example.com (%d.%d.%d.%d)...\n",
            server_ip[0], server_ip[1], server_ip[2], server_ip[3]);
    
    // Create socket
    int sock = tcp_socket();
    if (sock < 0) {
        kprintf("ERROR: Failed to create socket\n");
        return;
    }
    kprintf("Socket created: %d\n", sock);
    
    // Connect
    if (tcp_connect(sock, server_ip, port) < 0) {
        kprintf("ERROR: Failed to connect\n");
        tcp_close(sock);
        return;
    }
    
    // Wait for connection with timeout
    kprintf("Waiting for connection...\n");
    uint32_t timeout = tcp_get_time_ms() + 5000;
    bool connected = false;
    
    while (tcp_get_time_ms() < timeout) {
        if (tcp_is_connected(sock)) {
            connected = true;
            break;
        }
        // Small delay
        for (volatile int i = 0; i < 100000; i++);
    }
    
    if (!connected) {
        kprintf("ERROR: Connection timeout\n");
        tcp_close(sock);
        return;
    }
    
    kprintf("Connected!\n\n");
    
    // Send HTTP GET request
    const char* request = 
        "GET / HTTP/1.0\r\n"
        "Host: example.com\r\n"
        "Connection: close\r\n"
        "\r\n";
    
    kprintf("Sending HTTP request...\n");
    int sent = tcp_send(sock, request, strlen(request));
    if (sent < 0) {
        kprintf("ERROR: Failed to send request\n");
        tcp_close(sock);
        return;
    }
    kprintf("Sent %d bytes\n\n", sent);
    
    // Receive response
    kprintf("Receiving response...\n");
    kprintf("────────────────────────────────────────────\n");
    
    char buffer[512];
    int total_received = 0;
    int display_limit = 1024; // Only display first 1KB
    
    timeout = tcp_get_time_ms() + 10000; // 10 second timeout
    
    while (tcp_get_time_ms() < timeout) {
        // Check if data available
        if (tcp_available(sock) > 0) {
            int n = tcp_recv(sock, buffer, sizeof(buffer) - 1);
            if (n > 0) {
                total_received += n;
                
                // Display received data (up to limit)
                if (total_received <= display_limit) {
                    buffer[n] = '\0';
                    kprintf("%s", buffer);
                }
                
                timeout = tcp_get_time_ms() + 2000; // Reset timeout on data
            } else if (n == 0) {
                // Connection closed by server
                kprintf("\n");
                break;
            }
        }
        
        // Check if connection closed
        tcp_state_t state = tcp_get_state(sock);
        if (state == TCP_CLOSE_WAIT || state == TCP_CLOSED) {
            break;
        }
        
        // Small delay
        for (volatile int i = 0; i < 100000; i++);
    }
    
    kprintf("────────────────────────────────────────────\n");
    kprintf("\nTotal received: %d bytes\n", total_received);
    
    if (total_received > 0) {
        kprintf("\n HTTP TEST PASSED!\n");
    } else {
        kprintf("\n✗ HTTP TEST FAILED (no data received)\n");
    }
    
    // Close connection
    kprintf("\nClosing connection...\n");
    tcp_close(sock);
    
    // Wait for clean close
    for (volatile int i = 0; i < 10000000; i++);
    
    kprintf("Test complete\n\n");
}

/**
 * @brief Quick HTTP test for kernel.c
 */
void quick_http_test(void) {
    test_http_get();
}

#endif /* TINYOS_ENABLE_TESTS */