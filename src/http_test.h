/*=============================================================================
 * http_test.h - Simple HTTP Client Test Header
 *=============================================================================*/
#pragma once

/**
 * @brief Test HTTP connection to example.com
 * 
 * This is a more reliable test than daytime protocol because:
 * - HTTP is universally supported
 * - Works through QEMU user networking
 * - example.com is maintained for testing
 */
void test_http_get(void);

/**
 * @brief Quick HTTP test (alias)
 */
void quick_http_test(void);
