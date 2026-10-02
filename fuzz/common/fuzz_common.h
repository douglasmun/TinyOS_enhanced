/* Shared helpers for TinyOS fuzz targets (host build only). */
#pragma once
#include <stddef.h>
#include <stdint.h>

/* Reset per-input stub state (CSPRNG stream, tick counter, page pool). */
void fuzz_reset(void);

/* The tick value get_timer_ticks() returns; harnesses may advance it. */
extern uint32_t fuzz_ticks;

/* Every frame e1000_send() was handed since the last fuzz_reset(). */
extern size_t fuzz_tx_count;
extern uint8_t fuzz_tx_last[2048];
extern size_t fuzz_tx_last_len;

/* Heap copy of exactly `len` bytes, so ASan flags any read past the input. */
uint8_t* fuzz_dup(const uint8_t* data, size_t len);
