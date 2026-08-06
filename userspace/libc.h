/*=============================================================================
 * libc.h - Minimal freestanding C library for TinyOS user programs
 *
 * Link order: crt0.o <program>.o libc.o (see userspace/Makefile).
 * crt0 sets up the user data segments and calls main(); returning from
 * main() exits with the returned status.
 *=============================================================================*/
#ifndef TINYOS_LIBC_H
#define TINYOS_LIBC_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

/* System call numbers (must match src/syscall.h) */
#define SYS_EXIT   0
#define SYS_WRITE  1
#define SYS_READ   2
#define SYS_GETPID 3
#define SYS_YIELD  4
#define SYS_GETUID 5
#define SYS_GETGID 6
#define SYS_SLEEP  17
#define SYS_WAITPID 18

/* Raw syscall wrappers */
int syscall0(int num);
int syscall1(int num, uint32_t arg1);
int syscall3(int num, uint32_t arg1, uint32_t arg2, uint32_t arg3);

/* Process */
void exit(int status) __attribute__((noreturn));
int  getpid(void);
int  getuid(void);
int  getgid(void);
void yield(void);
int  sleep_ms(uint32_t ms);      /* blocks; timer wakes the task */
int  waitpid(int pid);           /* blocks until pid exits; returns status */

/* I/O — fd 1 is the console; read is line-buffered and blocks */
int  write(int fd, const void* buf, size_t len);
int  read(int fd, void* buf, size_t len);
int  putchar(int c);
int  puts(const char* s);            /* appends newline */
void print(const char* s);           /* no newline */
int  getchar(void);
int  readline(char* buf, size_t size);  /* strips newline, NUL-terminates */
int  printf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
int  vprintf(const char* fmt, va_list ap);

/* Strings */
size_t strlen(const char* s);
int    strcmp(const char* a, const char* b);
int    strncmp(const char* a, const char* b, size_t n);
char*  strcpy(char* dst, const char* src);
char*  strncpy(char* dst, const char* src, size_t n);
char*  strchr(const char* s, int c);
void*  memcpy(void* dst, const void* src, size_t n);
void*  memmove(void* dst, const void* src, size_t n);
void*  memset(void* dst, int c, size_t n);
int    memcmp(const void* a, const void* b, size_t n);

/* Conversion */
int atoi(const char* s);

/* Heap — bump allocator over a static arena; free() is a no-op */
void* malloc(size_t size);
void  free(void* ptr);

#endif /* TINYOS_LIBC_H */
