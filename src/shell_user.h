/*=============================================================================
 * shell_user.h - User Management Shell Commands
 *=============================================================================*/
#pragma once

/* User management commands */
void shell_cmd_whoami(const char* args);
void shell_cmd_id(const char* args);
void shell_cmd_su(const char* args);
/* The three credential commands return 0 or a negative errno instead of void:
 * they are reachable from ring 3 through SYS_CRED, which has to report an
 * outcome the caller can branch on. They print their own diagnostics to the
 * current stream either way, so a kernel-shell caller may ignore the value. */
int shell_cmd_passwd(const char* args);
int shell_cmd_useradd(const char* args);
int shell_cmd_userdel(const char* args);
void shell_cmd_users(const char* args);

/* Login system */
int shell_login_prompt(void);
