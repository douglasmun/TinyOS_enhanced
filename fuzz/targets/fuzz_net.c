/* Fuzz target: the whole RX path, handle_packet() in src/net.c, linked against
 * the real firewall, IDS, ICMP, TCP, DNS and DHCP code.
 *
 * net.c is #included (not linked) so the harness can clear its ARP cache
 * between inputs; every other module has a public init that resets it.
 *
 * Input format:
 *   byte 0      flags (FL_* below)
 *   then up to MAX_FRAMES records of  [len: u16 big-endian][Ethernet frame]
 *
 * The harness does what a real peer would do so the fuzzer is not stuck at a
 * gate it cannot plausibly guess:
 *   - destination MAC rewritten to ours           (unless FL_RAW_MAC)
 *   - IPv4 header and TCP/UDP/ICMP checksums fixed (unless FL_RAW_CSUM)
 *   - with FL_TCP_CONN, a connection to 10.0.2.2:80 is opened first, and with
 *     FL_TCP_PATCH inbound TCP gets that connection's ports and ack = ISS+1.
 * The firewall, IDS and every validation check run unmodified. */
#include "net.c"

#include <stdlib.h>
#include "fuzz_common.h"
#include "dhcp.h"
#include "dns.h"
#include "firewall.h"
#include "icmp.h"
#include "ids.h"
#include "tcp.h"

#define FL_TCP_CONN   0x01
#define FL_DNS_QUERY  0x02
#define FL_RAW_MAC    0x04
#define FL_RAW_CSUM   0x08
#define FL_TCP_PATCH  0x10
#define FL_DHCP       0x20
#define FL_TICK       0x40
#define FL_NO_FW      0x80

#define MAX_FRAMES 8

static const uint8_t ME[4] = {10, 0, 2, 15};
static const uint8_t MASK[4] = {255, 255, 255, 0};
static const uint8_t GW[4] = {10, 0, 2, 2};
static const uint8_t DNS_SRV[4] = {10, 0, 2, 3};
static const uint8_t GW_MAC[6] = {0x52, 0x55, 0x0a, 0x00, 0x02, 0x02};

static uint16_t csum_add(uint32_t sum, const uint8_t* p, size_t n) {
    for (size_t i = 0; i + 1 < n; i += 2) sum += (uint32_t)p[i] << 8 | p[i + 1];
    if (n & 1) sum += (uint32_t)p[n - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)sum;
}

static void put16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint32_t get32(const uint8_t* p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static void put32(uint8_t* p, uint32_t v) { put16(p, (uint16_t)(v >> 16)); put16(p + 2, (uint16_t)v); }

/* Fix the IPv4 header checksum and, when the header is sane enough to locate
 * it, the L4 checksum. Never grows or shrinks the frame. */
static void fix_checksums(uint8_t* f, size_t len) {
    if (len < 14 + 20 || f[12] != 0x08 || f[13] != 0x00) return;
    uint8_t* ip = f + 14;
    size_t ihl = (size_t)(ip[0] & 0x0F) * 4;
    if (ihl < 20 || 14 + ihl > len) return;
    put16(ip + 10, 0);
    put16(ip + 10, (uint16_t)~csum_add(0, ip, ihl));

    size_t tot = (size_t)ip[2] << 8 | ip[3];
    if (tot < ihl || 14 + tot > len) return;
    uint8_t* l4 = ip + ihl;
    size_t l4len = tot - ihl;
    size_t off;
    switch (ip[9]) {
        case 1:  off = 2; break;
        case 6:  off = 16; break;
        case 17: off = 6; break;
        default: return;
    }
    if (l4len < off + 2) return;
    put16(l4 + off, 0);
    uint32_t sum = 0;
    if (ip[9] != 1) {
        sum = csum_add(sum, ip + 12, 8);
        sum += ip[9];
        sum += (uint32_t)l4len;
    }
    uint16_t c = (uint16_t)~csum_add(sum, l4, l4len);
    if (ip[9] == 17 && c == 0) c = 0xFFFF;
    put16(l4 + off, c);
}

/* The cache only learns answers to our own requests, so a peer the harness
 * pretends we already resolved is written straight in. */
static void arp_seed(int slot, const uint8_t* ip, const uint8_t* mac) {
    memcpy(arp_cache[slot].ip, ip, 4);
    memcpy(arp_cache[slot].mac, mac, 6);
    arp_cache[slot].last_used = fuzz_ticks;
    arp_cache[slot].valid = true;
}

static void reset_stack(uint8_t flags) {
    fuzz_reset();
    memset(arp_cache, 0, sizeof(arp_cache));
    memset(arp_pending_requests, 0, sizeof(arp_pending_requests));
    set_network_config(ME, MASK, GW);
    arp_seed(0, GW, GW_MAC);
    arp_seed(1, DNS_SRV, GW_MAC);
    set_dns_server(DNS_SRV);

    tcp_init();
    dhcp_init();
    icmp_init();
    firewall_init();
    if (!(flags & FL_NO_FW)) {
        /* The boot-time policy from kernel.c. */
        firewall_allow_outgoing();
        firewall_allow_established();
        firewall_allow_icmp();
    } else {
        firewall_clear_rules();
        firewall_allow_port(0, 0, "fuzz: allow all");
    }
    ids_init();
    ids_load_default_signatures();
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len) {
    if (len < 1) return 0;
    uint8_t flags = data[0];
    data++; len--;

    reset_stack(flags);

    uint16_t conn_port = 0;
    uint32_t conn_iss = 0;
    int sock = -1;
    if (flags & FL_TCP_CONN) {
        sock = tcp_socket();
        size_t before = fuzz_tx_count;
        if (sock >= 0 && tcp_connect(sock, GW, 80) == 0 && fuzz_tx_count > before &&
            fuzz_tx_last_len >= 14 + 20 + 20) {
            const uint8_t* tcp = fuzz_tx_last + 14 + (size_t)(fuzz_tx_last[14] & 0x0F) * 4;
            conn_port = (uint16_t)(tcp[0] << 8 | tcp[1]);
            conn_iss = get32(tcp + 4);
        }
    }
    if (flags & FL_DNS_QUERY) send_dns_query("example.com");
    if (flags & FL_DHCP) dhcp_start();

    for (int n = 0; n < MAX_FRAMES && len >= 2; n++) {
        size_t fl = (size_t)data[0] << 8 | data[1];
        data += 2; len -= 2;
        if (fl > len) fl = len;
        uint8_t* f = fuzz_dup(data, fl);
        data += fl; len -= fl;

        if (!(flags & FL_RAW_MAC) && fl >= 6) memcpy(f, my_mac, 6);
        if ((flags & FL_TCP_PATCH) && conn_port && fl >= 14 + 20 + 20 &&
            f[12] == 0x08 && f[13] == 0x00 && f[14 + 9] == 6) {
            size_t ihl = (size_t)(f[14] & 0x0F) * 4;
            if (ihl >= 20 && 14 + ihl + 20 <= fl) {
                uint8_t* tcp = f + 14 + ihl;
                put16(tcp + 0, 80);
                put16(tcp + 2, conn_port);
                put32(tcp + 8, conn_iss + 1);
                memcpy(f + 14 + 12, GW, 4);
                memcpy(f + 14 + 16, ME, 4);
            }
        }
        if (!(flags & FL_RAW_CSUM)) fix_checksums(f, fl);

        handle_packet(f, fl);
        free(f);

        if (flags & FL_TICK) {
            fuzz_ticks += 250;
            tcp_tick(fuzz_ticks);
            dhcp_tick(fuzz_ticks);
        }
    }

    if (sock >= 0) {
        uint8_t rx[512];
        while (tcp_available(sock) > 0 && tcp_recv(sock, rx, sizeof(rx)) > 0) {
        }
        tcp_close(sock);
    }
    return 0;
}
