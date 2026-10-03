/* Fuzz target: DHCP client, handle_dhcp() in src/dhcp.c.
 * One input = up to 4 replies, each prefixed by a 2-byte big-endian length,
 * so the fuzzer can drive OFFER -> REQUEST -> ACK. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "fuzz_common.h"
#include "dhcp.h"

uint8_t my_mac[6] = {0x52, 0x54, 0, 0x12, 0x34, 0x56};
uint8_t my_ip[4];

void firewall_allow_port(uint16_t p, uint8_t pr, const char* s) { (void)p; (void)pr; (void)s; }
void send_arp_request(uint8_t* ip) { (void)ip; }
void set_dns_server(const uint8_t* ip) { (void)ip; }

/* Oracle: whatever handle_dhcp() commits must satisfy the PR #138 rules. */
void set_network_config(const uint8_t* ip, const uint8_t* mask, const uint8_t* gw) {
    uint32_t i = (uint32_t)ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3];
    uint32_t m = (uint32_t)mask[0] << 24 | mask[1] << 16 | mask[2] << 8 | mask[3];
    uint32_t g = (uint32_t)gw[0] << 24 | gw[1] << 16 | gw[2] << 8 | gw[3];
    if (i == 0 || i == 0xFFFFFFFF) abort();               /* zero / broadcast address */
    if (m == 0 || (~m & (~m + 1)) != 0) abort();          /* non-contiguous mask */
    if (m != 0xFFFFFFFF && ((i & ~m) == 0 || (i & ~m) == ~m)) abort(); /* net/bcast */
    if (g != 0 && (g & m) != (i & m)) abort();            /* gateway off-subnet */
    memcpy(my_ip, ip, 4);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len) {
    fuzz_reset();
    dhcp_init();
    memset(my_ip, 0, 4);
    dhcp_start();                                   /* xid = 1 with the zero CSPRNG stub */
    for (int n = 0; n < 4 && len >= 2; n++) {
        size_t pl = (size_t)data[0] << 8 | data[1];
        data += 2; len -= 2;
        if (pl > len) pl = len;
        uint8_t* buf = fuzz_dup(data, pl);
        if (pl >= 8) { buf[0] = 2; buf[4] = 0; buf[5] = 0; buf[6] = 0; buf[7] = 1; }
        if (pl >= 240) { buf[236] = 0x63; buf[237] = 0x82; buf[238] = 0x53; buf[239] = 0x63; }
        handle_dhcp(buf, pl);
        free(buf);
        data += pl; len -= pl;
    }
    return 0;
}
