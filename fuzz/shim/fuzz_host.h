/* Force-included into every host-built kernel source (fuzzing only). */
#pragma once
void* fuzz_page_alloc(void);
void fuzz_page_free(void* page);
