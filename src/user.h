/*=============================================================================
 * user.h - User and Group Management System
 *=============================================================================
 * STATUS: Production-ready (v1.13)
 *
 * SECURITY FEATURES:
 * - Password hashing (SHA-256 with salt, 100 iterations in dev mode)
 * - Proper uid/gid separation
 * - Root privilege checks
 * - Account lockout after failed attempts
 * - Session management
 *=============================================================================*/
#pragma once

#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * CONSTANTS
 *=============================================================================*/

#define USER_MAX_USERS       32
#define USER_MAX_USERNAME    32
#define USER_MAX_PASSWORD    64
#define USER_MAX_HOMEDIR     64
#define USER_PASSWORD_HASH_LEN 192  /* Self-describing PBKDF2 format: ~130 bytes actual */

/* Special UIDs */
#define USER_UID_ROOT        0
#define USER_UID_NOBODY      65534
#define USER_GID_ROOT        0
#define USER_GID_USERS       100

/* Account status flags */
#define USER_FLAG_ACTIVE     0x01
#define USER_FLAG_LOCKED     0x02
#define USER_FLAG_EXPIRED    0x04
#define USER_FLAG_NOLOGIN    0x08

/* Authentication */
#define USER_MAX_LOGIN_ATTEMPTS  3
#define USER_LOCKOUT_DURATION    60  /* seconds */

/*=============================================================================
 * DATA STRUCTURES
 *=============================================================================*/

/**
 * User account structure
 */
typedef struct {
    char username[USER_MAX_USERNAME];
    uint16_t uid;
    uint16_t gid;
    char password_hash[USER_PASSWORD_HASH_LEN];
    char home_dir[USER_MAX_HOMEDIR];
    char shell[USER_MAX_HOMEDIR];
    uint8_t flags;
    uint32_t failed_attempts;
    uint32_t last_failed_time;  /* Timestamp of last failed login */
    bool in_use;
} user_account_t;

/**
 * Group structure (simplified for now)
 */
typedef struct {
    char groupname[USER_MAX_USERNAME];
    uint16_t gid;
    bool in_use;
} group_t;

/*=============================================================================
 * FUNCTION PROTOTYPES
 *=============================================================================*/

/* Initialization */
void user_init(void);

/* User lookup */
user_account_t* user_find_by_uid(uint16_t uid);
user_account_t* user_find_by_username(const char* username);

/* User creation/deletion (root only) */
int user_create(const char* username, uint16_t uid, uint16_t gid, const char* password);
int user_delete(uint16_t uid);

/* Password management */
int user_set_password(uint16_t uid, const char* password);
bool user_verify_password(const char* username, const char* password);
void user_hash_password(const char* password, char* hash_out);
bool user_has_password(uint16_t uid);

/* Authentication.
 *
 * user_authenticate() is the LOGIN entry point: it records its outcome as
 * AUDIT_AUTH_LOGIN_SUCCESS / AUDIT_AUTH_LOGIN_FAILURE.
 *
 * Not every password check is a login. `su` and a password change also verify a
 * password, and must get the same policy (failed_attempts counter, lockout
 * expiry, locked/inactive checks) — but recording them as logins puts events in
 * the tamper-evident audit log that never happened, which is worse than no
 * record at all: the log is the thing an investigator trusts. Those callers use
 * user_authenticate_for(), which applies identical policy and lets the caller
 * name the operation being audited.
 *
 * The op selects the FAILURE event. Only USER_AUTH_OP_LOGIN also writes a
 * success record here: an su or a password change is not complete when the
 * password checks out, so its success is audited by the caller once the
 * operation actually commits (AUDIT_USER_SWITCH / AUDIT_USER_PASSWORD_CHANGE). */
typedef enum {
    USER_AUTH_OP_LOGIN = 0,   /* fail: AUDIT_AUTH_LOGIN_FAILURE  (also logs success) */
    USER_AUTH_OP_SU,          /* fail: AUDIT_AUTH_SU_FAILURE */
    USER_AUTH_OP_PASSWD       /* fail: AUDIT_AUTH_PASSWORD_CHANGE_FAILURE */
} user_auth_op_t;

int user_authenticate(const char* username, const char* password);
int user_authenticate_for(const char* username, const char* password,
                          user_auth_op_t op);
void user_lock_account(const char* username);
void user_unlock_account(const char* username);

/* Account management */
int user_set_home_dir(uint16_t uid, const char* home_dir);
int user_set_shell(uint16_t uid, const char* shell);
bool user_is_active(uint16_t uid);

/* Group management */
group_t* group_find_by_gid(uint16_t gid);
int group_create(const char* groupname, uint16_t gid);

/* Debugging */
void user_list_all(void);
void user_print_info(uint16_t uid);
int user_count(void);  /* Count number of users in database */

/* /etc directory structure */
void user_create_etc_structure(void);
