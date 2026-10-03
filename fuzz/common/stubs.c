/* Hand-written stubs whose behaviour a fuzz target depends on.
 * Everything not defined here or in a harness gets a weak zero-returning
 * stub from gen_weak_stubs.py. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "fuzz_common.h"
#include "crypto.h"

uint32_t fuzz_ticks = 1000;
size_t fuzz_tx_count;
uint8_t fuzz_tx_last[2048];
size_t fuzz_tx_last_len;

/* Panics are findings: abort so libFuzzer records the input. */
void panic(const char* msg) { (void)msg; abort(); }
void kernel_panic(const char* msg) { (void)msg; abort(); }
void system_halt(void) { abort(); }

/* Deterministic CSPRNG: a counter stream reset per input, so a harness can
 * predict TIDs, XIDs, ports and ISNs. Starts at 0, which is what the
 * DNS/DHCP harnesses assume (TID 0 -> 1, XID 0 -> 1, port 49152). */
csprng_ctx_t global_csprng;
static uint8_t rng_next;
void csprng_random_bytes(csprng_ctx_t* ctx, uint8_t* out, size_t len) {
    (void)ctx;
    (void)rng_next;
    memset(out, 0, len);
}
uint32_t csprng_random_u32(csprng_ctx_t* ctx) { (void)ctx; return 0; }
uint64_t csprng_random_u64(csprng_ctx_t* ctx) { (void)ctx; return 0; }

/* One clock for every tick source, so a harness advancing fuzz_ticks moves
 * the firewall/IDS rate windows and TCP/DHCP timers together. */
uint32_t get_timer_ticks(void) { return fuzz_ticks; }
uint32_t pit_get_ticks(void) { return fuzz_ticks; }
uint32_t time_get_uptime_seconds(void) { return fuzz_ticks / 100; }

void e1000_send(void* data, size_t len) {
    fuzz_tx_count++;
    fuzz_tx_last_len = len < sizeof(fuzz_tx_last) ? len : sizeof(fuzz_tx_last);
    memcpy(fuzz_tx_last, data, fuzz_tx_last_len);
}

/* pmm_alloc() does not zero; neither does this (0xA5 fill makes reliance on
 * zeroed frames visible). Pages are 4 KB and 4 KB aligned like the PMM's. */
void* fuzz_page_alloc(void) {
    void* p = aligned_alloc(4096, 4096);
    if (p) memset(p, 0xA5, 4096);
    return p;
}
void fuzz_page_free(void* page) { free(page); }

uint8_t* fuzz_dup(const uint8_t* data, size_t len) {
    uint8_t* p = malloc(len ? len : 1);
    if (len) memcpy(p, data, len);
    return p;
}

void fuzz_reset(void) {
    rng_next = 0;
    fuzz_ticks = 1000;
    fuzz_tx_count = 0;
    fuzz_tx_last_len = 0;
}

/* src/stdio.h shadows the host's, so declare write(2) directly. */
extern long write(int fd, const void* buf, unsigned long n);
void fuzz_note(const char* msg) {
    if (!getenv("FUZZ_VERBOSE")) return;
    write(2, msg, strlen(msg));
    write(2, "\n", 1);
}
