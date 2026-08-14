/*=============================================================================
 * spawner.c - SYS_SPAWN test program
 *
 * Spawns /hello.elf with arguments, waits for it, and reports. This is the
 * end-to-end proof that a USER process (not the shell) can start another
 * process: the spawn goes through the syscall, so the path and the whole
 * argument vector make the trip from ring 3 into the kernel and back out
 * onto the child's stack.
 *
 * NOTE: the output strings are load-bearing — verify-spawn.sh greps for
 * "spawner: child pid=" and "spawner: done status=". Keep them byte-identical.
 *===========================================================================*/
#include "libc.h"

int main(int argc, char** argv) {
    (void)argc; (void)argv;

    print("spawner: starting\n");

    char* child_argv[] = { "hello.elf", "from", "spawn", 0 };
    int pid = spawn("/hello.elf", child_argv);
    if (pid < 0) {
        printf("spawner: spawn failed %d\n", pid);
        return 1;
    }
    printf("spawner: child pid=%d\n", pid);

    int status = waitpid(pid);
    printf("spawner: done status=%d\n", status);
    return 0;
}
