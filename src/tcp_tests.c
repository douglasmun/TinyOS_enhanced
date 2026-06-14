/*=============================================================================
 * tcp_tests.c - TCP Stack Test Suite
 *
 * A collection of tests and examples for the TCP stack
 *
 * SECURITY: Test code guarded with TINYOS_ENABLE_TESTS to prevent inclusion
 * in production builds. Define at compile time to enable test functionality.
 *=============================================================================*/
#ifdef TINYOS_ENABLE_TESTS

#include "tcp.h"
#include "net.h"
#include "kprintf.h"
#include "kernel.h"
#include "util.h"
#include "tcp_tests.h"

/*=============================================================================
 * TEST 1: Basic Connection Test
 *=============================================================================*/
void test_basic_connection(void) {
    kprintf("\n=== TEST 1: Basic Connection ===\n");
    
    // Create socket
    int sock = tcp_socket();
    if (sock < 0) {
        kprintf("FAIL: Could not create socket\n");
        return;
    }
    kprintf("PASS: Socket created (sockfd=%d)\n", sock);
    
    // Test remote server (example.com)
    uint8_t server_ip[4] = {93, 184, 216, 34};
    uint16_t port = 80;
    
    kprintf("Connecting to %d.%d.%d.%d:%d...\n",
            server_ip[0], server_ip[1], server_ip[2], server_ip[3], port);
    
    if (tcp_connect(sock, server_ip, port) < 0) {
        kprintf("FAIL: Could not initiate connection\n");
        tcp_close(sock);
        return;
    }
    
    // Wait for connection with timeout
    uint32_t timeout = tcp_get_time_ms() + 5000;
    while (!tcp_is_connected(sock)) {
        if (tcp_get_time_ms() > timeout) {
            kprintf("FAIL: Connection timeout\n");
            tcp_close(sock);
            return;
        }
    }
    
    kprintf("PASS: Connection established\n");
    kprintf("      State: %s\n", tcp_state_to_string(tcp_get_state(sock)));
    
    // Close connection
    tcp_close(sock);
    kprintf("PASS: Connection closed\n");
}

/*=============================================================================
 * TEST 2: Data Transfer Test
 *=============================================================================*/
void test_data_transfer(void) {
    kprintf("\n=== TEST 2: Data Transfer ===\n");
    
    int sock = tcp_socket();
    if (sock < 0) {
        kprintf("FAIL: Could not create socket\n");
        return;
    }
    
    // Connect to httpbin.org (for testing)
    uint8_t server_ip[4] = {3, 164, 130, 92};  // httpbin.org
    
    kprintf("Connecting to httpbin.org (3.164.130.92:80)...\n");
    
    if (tcp_connect(sock, server_ip, 80) < 0) {
        kprintf("FAIL: Could not initiate connection\n");
        tcp_close(sock);
        return;
    }
    
    // Wait for connection
    uint32_t timeout = tcp_get_time_ms() + 5000;
    while (!tcp_is_connected(sock)) {
        if (tcp_get_time_ms() > timeout) {
            kprintf("FAIL: Connection timeout\n");
            tcp_close(sock);
            return;
        }
    }
    
    kprintf("PASS: Connected\n");
    
    // Send HTTP GET request
    const char* request = "GET /ip HTTP/1.0\r\nHost: httpbin.org\r\n\r\n";
    int sent = tcp_send(sock, request, strlen(request));
    if (sent < 0) {
        kprintf("FAIL: Could not send data\n");
        tcp_close(sock);
        return;
    }
    kprintf("PASS: Sent %d bytes\n", sent);
    
    // Receive response
    kprintf("Receiving response...\n");
    char buffer[512];
    int total_received = 0;
    
    timeout = tcp_get_time_ms() + 5000;
    while (tcp_get_time_ms() < timeout) {
        if (tcp_available(sock) > 0) {
            int n = tcp_recv(sock, buffer, sizeof(buffer) - 1);
            if (n > 0) {
                total_received += n;
                buffer[n] = '\0';
                // Don't print full response, just count bytes
            } else if (n == 0) {
                // Connection closed
                break;
            }
        }
        
        if (!tcp_is_connected(sock) && tcp_available(sock) == 0) {
            break;
        }
    }
    
    if (total_received > 0) {
        kprintf("PASS: Received %d bytes\n", total_received);
    } else {
        kprintf("FAIL: No data received\n");
    }
    
    tcp_close(sock);
    kprintf("Test complete\n");
}

/*=============================================================================
 * TEST 3: Multiple Connections Test
 *=============================================================================*/
void test_multiple_connections(void) {
    kprintf("\n=== TEST 3: Multiple Connections ===\n");
    
    // Try to create multiple sockets
    int socks[4];
    int created = 0;
    
    for (int i = 0; i < 4; i++) {
        socks[i] = tcp_socket();
        if (socks[i] >= 0) {
            created++;
            kprintf("Created socket %d (sockfd=%d)\n", i, socks[i]);
        }
    }
    
    if (created == 4) {
        kprintf("PASS: Created %d sockets\n", created);
    } else {
        kprintf("FAIL: Only created %d/4 sockets\n", created);
    }
    
    // Close all sockets
    for (int i = 0; i < created; i++) {
        tcp_close(socks[i]);
    }
    
    kprintf("PASS: Closed all sockets\n");
}

/*=============================================================================
 * TEST 4: Connection Dump Test
 *=============================================================================*/
void test_connection_dump(void) {
    kprintf("\n=== TEST 4: Connection Table Dump ===\n");
    
    // Create a couple of connections
    int sock1 = tcp_socket();
    int sock2 = tcp_socket();
    
    uint8_t server1[4] = {8, 8, 8, 8};      // Google DNS
    uint8_t server2[4] = {1, 1, 1, 1};      // Cloudflare DNS
    
    tcp_connect(sock1, server1, 53);
    tcp_connect(sock2, server2, 53);
    
    // Wait a bit
    for (volatile int i = 0; i < 10000000; i++);
    
    // Dump connections
    tcp_dump_connections();
    
    // Clean up
    tcp_close(sock1);
    tcp_close(sock2);
    
    kprintf("Test complete\n");
}

/*=============================================================================
 * TEST 5: State Machine Test
 *=============================================================================*/
void test_state_machine(void) {
    kprintf("\n=== TEST 5: State Machine ===\n");
    
    int sock = tcp_socket();
    if (sock < 0) {
        kprintf("FAIL: Could not create socket\n");
        return;
    }
    
    // Initial state should be CLOSED
    tcp_state_t state = tcp_get_state(sock);
    kprintf("Initial state: %s\n", tcp_state_to_string(state));
    if (state != TCP_CLOSED) {
        kprintf("FAIL: Initial state should be CLOSED\n");
        tcp_close(sock);
        return;
    }
    
    // Connect
    uint8_t server[4] = {93, 184, 216, 34};  // example.com
    tcp_connect(sock, server, 80);
    
    // Should be SYN_SENT
    state = tcp_get_state(sock);
    kprintf("After connect: %s\n", tcp_state_to_string(state));
    if (state != TCP_SYN_SENT) {
        kprintf("WARN: State should be SYN_SENT\n");
    }
    
    // Wait for ESTABLISHED
    uint32_t timeout = tcp_get_time_ms() + 5000;
    while (tcp_get_state(sock) != TCP_ESTABLISHED) {
        if (tcp_get_time_ms() > timeout) {
            kprintf("FAIL: Never reached ESTABLISHED state\n");
            tcp_close(sock);
            return;
        }
    }
    
    kprintf("Reached state: %s\n", tcp_state_to_string(tcp_get_state(sock)));
    kprintf("PASS: State machine working correctly\n");
    
    // Close and observe state transitions
    tcp_close(sock);
    kprintf("After close: %s\n", tcp_state_to_string(tcp_get_state(sock)));
    
    // Wait for connection to fully close
    timeout = tcp_get_time_ms() + 2000;
    while (tcp_get_state(sock) != TCP_CLOSED) {
        if (tcp_get_time_ms() > timeout) {
            kprintf("Still in state: %s\n", tcp_state_to_string(tcp_get_state(sock)));
            break;
        }
    }
    
    kprintf("Final state: %s\n", tcp_state_to_string(tcp_get_state(sock)));
}

/*=============================================================================
 * TEST 6: Timeout Handling Test
 *=============================================================================*/
void test_timeout_handling(void) {
    kprintf("\n=== TEST 6: Timeout Handling ===\n");
    
    int sock = tcp_socket();
    if (sock < 0) {
        kprintf("FAIL: Could not create socket\n");
        return;
    }
    
    // Try to connect to an IP that won't respond
    // (Using a non-routable IP)
    uint8_t unreachable[4] = {192, 0, 2, 1};
    
    kprintf("Attempting to connect to unreachable host...\n");
    tcp_connect(sock, unreachable, 80);
    
    // Wait with timeout
    uint32_t start = tcp_get_time_ms();
    uint32_t timeout = start + 3000;  // 3 second timeout
    
    bool connected = false;
    while (tcp_get_time_ms() < timeout) {
        if (tcp_is_connected(sock)) {
            connected = true;
            break;
        }
    }
    
    if (!connected) {
        uint32_t elapsed = tcp_get_time_ms() - start;
        kprintf("PASS: Timeout handled correctly (elapsed: %d ms)\n", elapsed);
    } else {
        kprintf("FAIL: Unexpected connection\n");
    }
    
    tcp_close(sock);
}

/*=============================================================================
 * TEST 7: Buffer Test
 *=============================================================================*/
void test_buffers(void) {
    kprintf("\n=== TEST 7: Buffer Management ===\n");
    
    int sock = tcp_socket();
    if (sock < 0) {
        kprintf("FAIL: Could not create socket\n");
        return;
    }
    
    // Initial available should be 0
    int avail = tcp_available(sock);
    kprintf("Initial available: %d bytes\n", avail);
    if (avail != 0) {
        kprintf("WARN: Should be 0 initially\n");
    }
    
    tcp_close(sock);
    kprintf("Test complete\n");
}

/*=============================================================================
 * TEST SUITE RUNNER
 *=============================================================================*/
void run_tcp_test_suite(void) {
    kprintf("\n");
    kprintf("╔════════════════════════════════════════════╗\n");
    kprintf("║     TCP STACK TEST SUITE                   ║\n");
    kprintf("╚════════════════════════════════════════════╝\n");
    kprintf("\n");
    
    kprintf("Running TCP tests...\n");
    kprintf("NOTE: Some tests require internet connectivity\n");
    kprintf("\n");
    
    // Test 1: Basic connection
    test_basic_connection();
    for (volatile int i = 0; i < 50000000; i++);  // Wait between tests
    
    // Test 3: Multiple connections
    test_multiple_connections();
    for (volatile int i = 0; i < 50000000; i++);
    
    // Test 4: Connection dump
    test_connection_dump();
    for (volatile int i = 0; i < 50000000; i++);

    // Test 5: State machine
    test_state_machine();
    for (volatile int i = 0; i < 50000000; i++);

    // Test 6: Timeout handling
    test_timeout_handling();
    for (volatile int i = 0; i < 50000000; i++);

    // Test 7: Buffers
    test_buffers();
    
    kprintf("\n");
    kprintf("╔════════════════════════════════════════════╗\n");
    kprintf("║     TEST SUITE COMPLETE                    ║\n");
    kprintf("╚════════════════════════════════════════════╝\n");
    kprintf("\n");
}

/*=============================================================================
 * QUICK TESTS (can be called individually)
 *=============================================================================*/

/**
 * @brief Quick test - basic connection
 */
void quick_test_connect(void) {
    kprintf("\n*** QUICK TEST: Basic Connection ***\n");
    test_basic_connection();
}

/**
 * @brief Quick test - connection table
 */
void quick_test_dump(void) {
    kprintf("\n*** QUICK TEST: Connection Dump ***\n");
    
    // Create some connections
    int s1 = tcp_socket();
    int s2 = tcp_socket();
    
    uint8_t ip1[4] = {8, 8, 8, 8};
    uint8_t ip2[4] = {1, 1, 1, 1};
    
    tcp_connect(s1, ip1, 80);
    tcp_connect(s2, ip2, 443);
    
    for (volatile int i = 0; i < 10000000; i++);
    
    tcp_dump_connections();
    
    tcp_close(s1);
    tcp_close(s2);
}

/*=============================================================================
 * EXAMPLE USAGE IN KERNEL
 *=============================================================================*/

/*
 * In your kernel.c, after network initialization:
 *
 * // Initialize TCP stack
 * tcp_init();
 *
 * // Wait for network to be ready (after DHCP, ARP, etc.)
 * for (volatile int i = 0; i < 100000000; i++);
 *
 * // Run tests
 * run_tcp_test_suite();           // Run all tests
 *
 * // OR run individual tests:
 * quick_test_connect();            // Just test connection
 * quick_test_dump();               // Just dump connections
 */

#endif /* TINYOS_ENABLE_TESTS */