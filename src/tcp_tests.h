/*=============================================================================
 * tcp_tests.h - TCP Stack Test Suite Header
 *=============================================================================*/
#pragma once

/**
 * @brief Run complete TCP test suite
 * 
 * Runs all TCP tests including:
 * - Basic connection test
 * - Data transfer test
 * - Multiple connections test
 * - Connection table dump
 * - Daytime protocol test
 * - State machine test
 * - Timeout handling test
 * - Buffer management test
 */
void run_tcp_test_suite(void);

/**
 * @brief Quick test: Daytime Protocol only
 */
void quick_test_daytime(void);

/**
 * @brief Quick test: Basic connection only
 */
void quick_test_connect(void);

/**
 * @brief Quick test: Connection table dump
 */
void quick_test_dump(void);

// Individual tests (can be called separately)
void test_basic_connection(void);
void test_data_transfer(void);
void test_multiple_connections(void);
void test_connection_dump(void);
void test_daytime_protocol(void);
void test_state_machine(void);
void test_timeout_handling(void);
void test_buffers(void);

