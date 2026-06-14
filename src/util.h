#pragma once
#include <stddef.h>
#include <stdint.h>

#define NORETURN __attribute__((noreturn))

/* Maximum path length for filesystem operations */
#define MAX_PATH 256

/* I/O port access functions (8-bit already defined in pic.h as inline) */
void outw(uint16_t port, uint16_t val);
uint16_t inw(uint16_t port);
void outl(uint16_t port, uint32_t val);
uint32_t inl(uint16_t port);

NORETURN void panic(const char* msg);
NORETURN void kernel_panic(const char* msg);
NORETURN void system_halt(void);  /* Clean system shutdown (no panic message) */

void* memset(void* dst, int val, size_t n);
void* memcpy(void* dst, const void* src, size_t n);
void* memmove(void* dst, const void* src, size_t n);  /* overlap-safe copy */

int memcmp(const void* s1, const void* s2, size_t n);

/**
 * @brief Secure memory zeroing that cannot be optimized away by compiler
 * @param v Pointer to memory to zero
 * @param n Number of bytes to zero
 *
 * SECURITY: Use this for sensitive data (passwords, keys, etc.) instead of memset.
 * Compilers can optimize away memset calls if they determine the memory is never
 * read again, leaving secrets in memory. This function uses volatile to prevent
 * that optimization.
 */
void secure_memzero(void* v, size_t n);

size_t strlen(const char* s);

int strcmp(const char* s1, const char* s2);

int strcasecmp(const char* s1, const char* s2);

int strncmp(const char* s1, const char* s2, size_t n);

char* strstr(const char* haystack, const char* needle);

char* strchr(const char* s, int c);

/**
 * @brief Safe string copy with bounds checking (like strlcpy)
 * @param dst Destination buffer
 * @param src Source string
 * @param size Size of destination buffer
 * @return Length of src (for truncation detection)
 *
 * SECURITY: Always null-terminates dst (unless size == 0)
 * If src length >= size, dst will be truncated
 */
size_t safe_strcpy(char* dst, const char* src, size_t size);
