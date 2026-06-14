#include <stddef.h>
#include <stdio.h>
#include "process.h"

int main() {
    printf("Offset of page_directory in task_t: %zu\n", offsetof(task_t, page_directory));
    printf("Size of cpu_context_t: %zu\n", sizeof(cpu_context_t));
    printf("Size of task_t: %zu\n", sizeof(task_t));
    return 0;
}
