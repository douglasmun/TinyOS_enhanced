/*=============================================================================
 * test_tasks.h - Test Task Function Declarations
 *=============================================================================*/
#pragma once

/**
 * @brief Counter task A - prints messages periodically
 */
void task_counter_a(void);

/**
 * @brief Counter task B - prints messages periodically
 */
void task_counter_b(void);

/**
 * @brief Counter task C - prints messages periodically
 */
void task_counter_c(void);

/**
 * @brief Test task that exits immediately (for testing sys_exit)
 */
void task_exit_test(void);

/**
 * @brief Idle task - runs when no other tasks are ready
 */
void task_idle(void);
void task_ktimerd(void);  /* timer bottom-half task */
void task_knetd(void);    /* RX bottom-half task (doc/NETWORK_ISOLATION.md) */

#ifdef TINYOS_FAULT_INJECT
/* Set to 1 to make knetd exit at its next loop iteration; see test_tasks.c for
 * why the restart path cannot be tested without it. verify-supervisor.sh only. */
extern volatile int knetd_die_now;
#endif
