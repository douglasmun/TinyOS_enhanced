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
