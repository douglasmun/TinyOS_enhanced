/*=============================================================================
 * info.c - libc demo: printf, syscalls, malloc
 *=============================================================================*/
#include "libc.h"

int main(void) {
    printf("TinyOS user process: pid=%d uid=%d gid=%d\n",
           getpid(), getuid(), getgid());
    printf("printf test: %s %d %u 0x%x %c%c %%\n",
           "string", -42, 42u, 0xBEEF, 'o', 'k');

    char* p = malloc(64);
    if (p) {
        strcpy(p, "malloc works");
        printf("%s (%p)\n", p, (void*)p);
    } else {
        puts("malloc FAILED");
    }

    puts("sleeping 500 ms...");
    sleep_ms(500);
    puts("sleep done");

    return 0;
}
