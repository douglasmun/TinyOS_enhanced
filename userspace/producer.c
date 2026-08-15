/*=============================================================================
 * producer.c - Pipeline producer half of the SYS_PIPE test
 *
 * Writes N numbered lines to stdout and exits. The count comes from argv[1]
 * (default 200) so the harness can push far more than one PIPE_BUFFER_SIZE
 * through and prove the pipe is a sliding window, not a 4 KB cap: at ~14 bytes
 * a line, 800 lines is roughly 11 KB, so the producer MUST block partway and
 * be woken by the consumer draining. A sequential implementation would either
 * truncate or deadlock there.
 *
 * NOTE: the "pipe-line NNNN" shape is load-bearing — verify-ring3-pipes.sh
 * counts these lines and checks the first and last are present. Keep it
 * byte-identical.
 *===========================================================================*/
#include "libc.h"

int main(int argc, char** argv) {
    int count = (argc > 1) ? atoi(argv[1]) : 200;
    if (count <= 0) {
        count = 200;
    }

    for (int i = 1; i <= count; i++) {
        printf("pipe-line %d\n", i);
    }

    /* Distinct from the numbered lines so the harness can tell "the producer
     * finished" from "the producer was cut off mid-stream". */
    print("producer: done\n");
    return 0;
}
