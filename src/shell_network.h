/*=============================================================================
 * shell_network.h - Shell Network Commands Module
 *
 * Commands: ifconfig, ping, dig, dhcp, curl
 *=============================================================================*/
#pragma once

/**
 * @brief Display network configuration
 */
void cmd_ifconfig(void);

/**
 * @brief Send ICMP ping to host
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = host, argv[2] = count optional)
 */
void cmd_ping(int argc, char* argv[]);

/**
 * @brief DNS lookup utility (Unix-like dig command)
 * @param argc Number of arguments
 * @param argv Argument array (supports: hostname, @server, +options, query types)
 */
void cmd_dig(int argc, char* argv[]);

/**
 * @brief Show DHCP client status and optionally renew lease
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = "renew" to trigger renewal)
 */
void cmd_dhcp(int argc, char* argv[]);

/**
 * @brief Fetch HTTP content from URL
 * @param argc Number of arguments
 * @param argv Argument array (argv[1] = url)
 */
void cmd_curl(int argc, char* argv[]);
