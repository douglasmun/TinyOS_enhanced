/* Fuzz target: DNS response parser, handle_dns_response() in src/dns.c.
 *
 * Each input is one UDP payload from the configured server. The harness
 * sends a real query first (so a query is outstanding and the source port is
 * bound) and forces the transaction ID to the one the deterministic CSPRNG
 * produced; the source-IP, port and TID gates are therefore always passed and
 * the fuzzer spends its time in the question/answer parsers. */
#include <stdlib.h>
#include <string.h>
#include "fuzz_common.h"
#include "dns.h"

static uint16_t query_port;
static uint8_t route_mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};

uint8_t* get_route_mac(const uint8_t* ip) { (void)ip; return route_mac; }
void send_udp_packet(uint8_t* ip, uint8_t* mac, uint16_t sp, uint16_t dp,
                     void* d, size_t l) {
    (void)ip; (void)mac; (void)dp; (void)d; (void)l;
    query_port = sp;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len) {
    static const uint8_t server[4] = {10, 0, 2, 3};
    fuzz_reset();
    set_dns_server(server);
    send_dns_query("example.com");
    uint8_t* buf = fuzz_dup(data, len);
    if (len >= 2) { buf[0] = 0; buf[1] = 1; }   /* TID: CSPRNG 0 -> 1 */
    handle_dns_response(buf, len, server, query_port);
    free(buf);
    return 0;
}
