/*=============================================================================
 * shell_user.h - User Management Shell Commands
 *=============================================================================*/
#pragma once

/* User management commands */
void shell_cmd_whoami(const char* args);
void shell_cmd_id(const char* args);
void shell_cmd_su(const char* args);
void shell_cmd_passwd(const char* args);
void shell_cmd_useradd(const char* args);
void shell_cmd_userdel(const char* args);
void shell_cmd_users(const char* args);

/* Login system */
int shell_login_prompt(void);
