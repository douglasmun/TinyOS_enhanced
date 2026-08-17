/*=============================================================================
 * shell_user.c - User Management Shell Commands
 *=============================================================================
 * COMMANDS IMPLEMENTED:
 * - whoami: Display current username
 * - id: Display user/group IDs
 * - su: Switch user
 * - passwd: Change password
 * - useradd: Create new user (root only)
 * - userdel: Delete user (root only)
 * - users: List all users
 *=============================================================================*/
#include "kernel.h"
#include "shell.h"
#include "shell_user.h"
#include "kprintf.h"
#include "user.h"
#include "syscall.h"
#include "scheduler.h"
#include "util.h"
#include "keyboard.h"
#include "crypto.h"  /* For crypto_constant_time_compare() */
#include "pit.h"     /* For pit_get_ticks() - used in authentication delay */
#include "serial.h"  /* For serial debug output */
#include "stdio.h"   /* For stream_printf() - see cred_printf below */
#include "env.h"     /* For env_refresh_identity() - su changes identity */
#include "errno.h"   /* Credential commands return negative errnos to SYS_CRED */

/*=============================================================================
 * HELPER: Output for the credential commands
 *=============================================================================
 * passwd/useradd/userdel are reachable from BOTH shells: the kernel shell calls
 * them directly, and the ring-3 shell reaches them through SYS_CRED. So their
 * output cannot use kprintf, which writes to the kernel console and would leave
 * a ring-3 caller's own stream silent (the same routing bug already fixed once
 * for `ls C:`, see the FAT32 note in CLAUDE.md).
 *
 * stream_printf falls back to kprintf when there is no current stream context,
 * so kernel-shell and early-boot callers are unaffected.
 *
 * Only these three commands are converted. The rest of this file still uses
 * kprintf deliberately: they are not reachable from ring 3, and rewriting the
 * ~106 remaining call sites would be a large untested diff for no behaviour
 * change.
 *=============================================================================*/
#define cred_printf(...) stream_printf(get_current_streams(), __VA_ARGS__)

/*=============================================================================
 * HELPER: Get password input (hidden)
 *=============================================================================
 * NOTE: This function does NOT print a prompt. Callers must print their own
 * custom prompt before calling this function (e.g., "Enter new password: ")
 *
 * The keystrokes are taken straight from keyboard_getchar(), NOT from the
 * caller's stdin. That is deliberate and is what lets SYS_CRED keep a plaintext
 * password out of every user address space: the bytes go from the keyboard
 * driver into this kernel buffer and are hashed and wiped without ever being
 * copied out to ring 3. It also means a redirected or piped stdin cannot feed a
 * password in, which is the correct refusal for an interactive credential
 * change (and matches how real getpass() reads the terminal, not stdin).
 *
 * The echo uses the stream helper so a ring-3 caller sees its own asterisks;
 * with no stream context it falls back to kprintf, so login and su are
 * unchanged.
 *=============================================================================*/
static int read_password(char* buffer, size_t max_len) {
    size_t pos = 0;

    /* Caller has already printed prompt - just read the password */
    while (1) {
        char c = keyboard_getchar();

        if (c == '\n') {
            buffer[pos] = '\0';
            cred_printf("\n");
            return pos;
        } else if (c == '\b' || c == 0x7F) {  /* Backspace */
            if (pos > 0) {
                pos--;
                /* Erase the asterisk (v1.13: kbd driver no longer echoes) */
                cred_printf("\b \b");
            }
        } else if (c >= 32 && c < 127) {  /* Printable characters */
            if (pos < max_len - 1) {  /* Only write if space available */
                buffer[pos++] = c;
                cred_printf("*");  /* Echo asterisk instead of actual character */
            }
            /* Silently ignore characters that would overflow */
        }
    }
}

/*=============================================================================
 * COMMAND: whoami
 * Display current username
 *=============================================================================*/
void shell_cmd_whoami(const char* args) {
    (void)args;  /* Unused */

    task_t* current = scheduler_get_current_task();
    if (!current) {
        kprintf("Error: No current task\n");
        return;
    }

    user_account_t* user = user_find_by_uid(current->uid);
    if (user) {
        kprintf("%s\n", user->username);
    } else {
        kprintf("unknown (uid=%d)\n", current->uid);
    }
}

/*=============================================================================
 * COMMAND: id
 * Display user and group IDs
 *=============================================================================*/
void shell_cmd_id(const char* args) {
    task_t* current = scheduler_get_current_task();
    if (!current) {
        kprintf("Error: No current task\n");
        return;
    }

    /* Check if showing another user's ID */
    if (args && args[0] != '\0') {
        user_account_t* user = user_find_by_username(args);
        if (!user) {
            kprintf("id: '%s': no such user\n", args);
            return;
        }

        kprintf("uid=%d(%s) gid=%d\n",
                user->uid, user->username, user->gid);
        return;
    }

    /* Show current user's ID */
    user_account_t* user = user_find_by_uid(current->uid);
    const char* username = user ? user->username : "unknown";

    kprintf("uid=%d(%s) gid=%d euid=%d egid=%d\n",
            current->uid, username, current->gid,
            current->euid, current->egid);
}

/*=============================================================================
 * COMMAND: su [username]
 * Switch user (requires password)
 *=============================================================================*/
void shell_cmd_su(const char* args) {
    task_t* current = scheduler_get_current_task();
    if (!current) {
        kprintf("Error: No current task\n");
        return;
    }

    /* Determine target user */
    const char* target_username = args;
    if (!target_username || target_username[0] == '\0') {
        target_username = "root";  /* Default to root if no argument */
    }

    /* Find target user */
    user_account_t* target_user = user_find_by_username(target_username);
    if (!target_user) {
        kprintf("su: user '%s' does not exist\n", target_username);
        return;
    }

    /* Root can switch to any user without password */
    if (current->euid == 0) {
        /* Root skips the PASSWORD, not the account state. This path goes
         * straight to sys_setgid/sys_setuid, which enforce privilege rules but
         * know nothing about the user database, so without this check a locked
         * or deactivated account could still be entered as a live identity —
         * silently defeating an administrative lock. sys_switch_user() applies
         * the same check for every other caller. */
        if (target_user->flags & USER_FLAG_LOCKED) {
            kprintf("su: account '%s' is locked\n", target_username);
            return;
        }
        if (!(target_user->flags & USER_FLAG_ACTIVE)) {
            kprintf("su: account '%s' is inactive\n", target_username);
            return;
        }

        kprintf("Switching to %s (no password required for root)\n", target_username);

        /* Switch user via syscalls - CHECK RETURN VALUES for security.
         * Set GID before UID: setuid() drops euid, after which setgid() (which
         * needs euid==0 for an arbitrary gid) would fail. */
        if (sys_setgid(target_user->gid) < 0) {
            kprintf("su: failed to set GID (kernel error)\n");
            return;
        }
        if (sys_setuid(target_user->uid) < 0) {
            kprintf("su: failed to set UID (kernel error)\n");
            kprintf("su: WARNING: GID changed but UID failed (inconsistent state)\n");
            return;
        }

        /* The identity changed on THIS task, so the env page -- which is
         * per-task and therefore survives the switch -- still describes the
         * previous user. Re-point $USER/$HOME before returning, or the new
         * identity inherits the old one's. Cosmetic while env was kernel-only;
         * SYS_ENV now hands these to ring 3. */
        env_refresh_identity();

        kprintf("Now running as: ");
        shell_cmd_whoami(NULL);
        return;
    }

    /* Non-root users must provide password */
    kprintf("Switching to user '%s'\n", target_username);
    char password[USER_MAX_PASSWORD];
    kprintf("Password for %s: ", target_username);

    /* Read password without showing the prompt (we already printed it) */
    size_t pos = 0;
    while (pos < sizeof(password) - 1) {
        char c = keyboard_getchar();
        if (c == '\n') {
            password[pos] = '\0';
            kprintf("\n");
            break;
        } else if (c == '\b' || c == 0x7F) {  /* Backspace */
            if (pos > 0) {
                pos--;
                kprintf("\b \b");
            }
        } else if (c >= 32 && c < 127) {  /* Printable characters */
            password[pos++] = c;
            kprintf("*");  /* Echo asterisk instead of actual character */
        }
    }
    password[pos] = '\0';

    /* Authenticate (also maintains the per-account lockout counter). Audited as
     * an su, not a login — this verifies a password but establishes no session. */
    int auth_result = user_authenticate_for(target_username, password,
                                            USER_AUTH_OP_SU);

    if (auth_result < 0) {
        /* Clear password from memory */
        SECURE_ZERO_PASSWORD(password);

        /* SECURITY: Delay on failed authentication (prevent brute-force) */
        uint32_t delay_start = pit_get_ticks();

        switch (auth_result) {
            case -2:
                kprintf("su: user '%s' does not exist\n", target_username);
                break;
            case -3:
                kprintf("su: account locked (too many failed attempts)\n");
                break;
            case -4:
                kprintf("su: account inactive\n");
                break;
            case -5:
                kprintf("su: authentication failure\n");
                break;
            default:
                kprintf("su: authentication error\n");
                break;
        }

        /* Wait 3 seconds (150 ticks at 50 Hz) to slow down brute-force attacks */
        while (pit_get_ticks() < delay_start + 150) {
            scheduler_yield();
        }

        return;
    }

    /* Commit the switch. user_authenticate() above already verified the
     * password AND maintained the lockout counter, so use the preauth entry
     * point rather than sys_switch_user(), which would re-run the full PBKDF2
     * derivation (100k iterations, seconds under TCG) for the same password.
     * It still re-checks that the account is not locked or inactive. */
    int switch_result = sys_switch_user_preauth(target_username);

    /* Clear password from memory */
    SECURE_ZERO_PASSWORD(password);

    if (switch_result < 0) {
        kprintf("su: failed to switch user (kernel error)\n");
        return;
    }

    /* Same reason as the root branch above: the identity changed on this task,
     * so $USER/$HOME must follow it. Both branches need this -- fixing only the
     * one the harness happens to drive leaves the other lying. */
    env_refresh_identity();

    kprintf("Switched to user: %s\n", target_username);
}

/*=============================================================================
 * COMMAND: passwd [username]
 * Change password
 *=============================================================================*/
int shell_cmd_passwd(const char* args) {
    task_t* current = scheduler_get_current_task();
    if (!current) {
        cred_printf("Error: No current task\n");
        return -ESRCH;
    }

    /* Determine which user's password to change */
    const char* target_username = args;
    uint16_t target_uid;

    if (!target_username || target_username[0] == '\0') {
        /* Change own password */
        user_account_t* user = user_find_by_uid(current->uid);
        if (!user) {
            cred_printf("passwd: cannot find current user\n");
            return -ESRCH;
        }
        target_username = user->username;
        target_uid = current->uid;
    } else {
        /* Changing another user's password (requires root) */
        if (current->euid != 0) {
            cred_printf("passwd: only root can change other users' passwords\n");
            return -EPERM;
        }

        user_account_t* user = user_find_by_username(target_username);
        if (!user) {
            cred_printf("passwd: user '%s' does not exist\n", target_username);
            return -ESRCH;
        }
        target_uid = user->uid;
    }

    /* If changing own password, verify old password first */
    if (target_uid == current->uid && current->euid != 0) {
        char old_password[USER_MAX_PASSWORD];
        cred_printf("Changing password for %s\n", target_username);
        cred_printf("(current) ");
        read_password(old_password, sizeof(old_password));

        if (!user_verify_password(target_username, old_password)) {
            SECURE_ZERO_PASSWORD(old_password);
            cred_printf("passwd: authentication token manipulation error\n");
            return -EACCES;
        }
        SECURE_ZERO_PASSWORD(old_password);
    }

    /* Get new password */
    char new_password[USER_MAX_PASSWORD];
    char confirm_password[USER_MAX_PASSWORD];

    cred_printf("Enter new password: ");
    read_password(new_password, sizeof(new_password));

    cred_printf("Retype new password: ");
    read_password(confirm_password, sizeof(confirm_password));

    /* Verify passwords match (constant-time comparison to prevent timing attacks) */
    size_t pw1_len = strlen(new_password);
    size_t pw2_len = strlen(confirm_password);
    /* Check lengths match first, then use constant-time comparison */
    if (pw1_len != pw2_len || !crypto_constant_time_compare(new_password, confirm_password, pw1_len)) {
        SECURE_ZERO_PASSWORD(new_password);
        SECURE_ZERO_PASSWORD(confirm_password);
        cred_printf("passwd: passwords do not match\n");
        return -EINVAL;
    }

    /* Set new password */
    int rc = user_set_password(target_uid, new_password);
    if (rc == 0) {
        cred_printf("passwd: password updated successfully\n");
    } else {
        cred_printf("passwd: error updating password\n");
        rc = -EIO;
    }

    /* Clear passwords from memory */
    SECURE_ZERO_PASSWORD(new_password);
    SECURE_ZERO_PASSWORD(confirm_password);
    return rc;
}

/*=============================================================================
 * COMMAND: useradd <username>
 * Create new user (root only)
 *=============================================================================*/
int shell_cmd_useradd(const char* args) {
    task_t* current = scheduler_get_current_task();
    if (!current) {
        cred_printf("Error: No current task\n");
        return -ESRCH;
    }

    /* Check root permission */
    if (current->euid != 0) {
        cred_printf("useradd: permission denied (must be root)\n");
        return -EPERM;
    }

    if (!args || args[0] == '\0') {
        cred_printf("Usage: useradd <username>\n");
        return -EINVAL;
    }

    /* Check if user already exists */
    if (user_find_by_username(args)) {
        cred_printf("useradd: user '%s' already exists\n", args);
        return -EEXIST;
    }

    /* Find next available UID (start from 1002) */
    uint16_t new_uid = 1002;
    while (user_find_by_uid(new_uid) && new_uid < 60000) {
        new_uid++;
    }

    if (new_uid >= 60000) {
        cred_printf("useradd: no available UID\n");
        return -ENOSPC;
    }

    /* Get password */
    char password[USER_MAX_PASSWORD];
    cred_printf("Enter password for new user: ");
    read_password(password, sizeof(password));

    /* Create user */
    int result = user_create(args, new_uid, 100, password);  /* gid=100 (users group) */

    SECURE_ZERO_PASSWORD(password);

    if (result == 0) {
        cred_printf("useradd: user '%s' created (uid=%d, gid=100)\n", args, new_uid);
        return 0;
    }

    cred_printf("useradd: failed to create user (error %d)\n", result);
    return -EIO;
}

/*=============================================================================
 * COMMAND: userdel <username>
 * Delete user (root only)
 *=============================================================================*/
int shell_cmd_userdel(const char* args) {
    task_t* current = scheduler_get_current_task();
    if (!current) {
        cred_printf("Error: No current task\n");
        return -ESRCH;
    }

    /* Check root permission */
    if (current->euid != 0) {
        cred_printf("userdel: permission denied (must be root)\n");
        return -EPERM;
    }

    if (!args || args[0] == '\0') {
        cred_printf("Usage: userdel <username>\n");
        return -EINVAL;
    }

    /* Find user */
    user_account_t* user = user_find_by_username(args);
    if (!user) {
        cred_printf("userdel: user '%s' does not exist\n", args);
        return -ESRCH;
    }

    /* Refuse by UID, not by name: "root" is the name of uid 0 by convention
     * only, and an account created with uid 0 is root in every way that
     * matters. The old check compared the argument to the string "root", so
     * any other name for uid 0 deleted the system's only privileged account. */
    if (user->uid == 0) {
        cred_printf("userdel: cannot delete root user\n");
        return -EPERM;
    }

    /* Deleting the account you are logged in as leaves the session running with
     * credentials no user database entry backs any more — every later lookup on
     * that uid fails, and the uid is free to be handed to a new account that
     * then inherits this session. */
    if (user->uid == current->uid || user->uid == current->euid) {
        cred_printf("userdel: cannot delete the current user\n");
        return -EPERM;
    }

    /* Delete user */
    if (user_delete(user->uid) == 0) {
        cred_printf("userdel: user '%s' deleted\n", args);
        return 0;
    }

    cred_printf("userdel: failed to delete user\n");
    return -EIO;
}

/*=============================================================================
 * COMMAND: users
 * List all users in the system
 *=============================================================================*/
void shell_cmd_users(const char* args) {
    (void)args;  /* Unused */

    user_list_all();
}

/*=============================================================================
 * FIRST-BOOT PASSWORD SETUP
 * Checks if root account has no password and prompts to set it
 *
 * NOTE: Re-enabling stack protection to catch overflow
 *=============================================================================*/
static void first_boot_password_setup(void) {
    user_account_t* root = user_find_by_uid(USER_UID_ROOT);

    /* Check if root password is already set */
    if (!root || root->password_hash[0] != '\0') {
        return;  /* Password already set, skip setup */
    }

    /* Root has no password - run first-boot setup */
    kprintf("\n");
    kprintf("   (\\_/) <3\n");
    kprintf("   (o.o) Welcome to TinyOS!\n");
    kprintf("   (> <)\n");
    kprintf("~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~\n");
    kprintf(" First-Time Setup: Let's Create Your Password\n");
    kprintf("~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~\n");
    kprintf("\n");
    kprintf("This is your first time booting TinyOS!\n");
    kprintf("For security, let's set up a root password.\n");
    kprintf("\n");

    char new_password[USER_MAX_PASSWORD];
    char confirm_password[USER_MAX_PASSWORD];

    while (1) {
        kprintf("Enter new root password: ");
        read_password(new_password, sizeof(new_password));

        /* Check for empty password */
        if (strlen(new_password) == 0) {
            kprintf("Password cannot be empty. Please try again.\n\n");
            continue;
        }

        kprintf("Confirm new root password: ");
        read_password(confirm_password, sizeof(confirm_password));

        /* Verify passwords match */
        if (strcmp(new_password, confirm_password) != 0) {
            SECURE_ZERO_PASSWORD(new_password);
            SECURE_ZERO_PASSWORD(confirm_password);
            kprintf("Passwords do not match. Please try again.\n\n");
            continue;
        }

        /* Set root password */
        if (user_set_password(USER_UID_ROOT, new_password) == 0) {
            kprintf("\nRoot password set successfully!\n");
            kprintf("Root account is now active and unlocked.\n");
            kprintf("\n");
            kprintf("*********************************************************\n");
            kprintf("\n");
        } else {
            kprintf("\nERROR: Failed to set root password\n");
            kprintf("System security may be compromised. Please reboot.\n\n");
        }

        /* Clear passwords from memory */
        // kprintf("[DEBUG] About to zero new_password\n");
        SECURE_ZERO_PASSWORD(new_password);
        // kprintf("[DEBUG] About to zero confirm_password\n");
        SECURE_ZERO_PASSWORD(confirm_password);
        // kprintf("[DEBUG] About to break from loop\n");
        break;
    }

    // kprintf("[DEBUG] Returning from first_boot_password_setup\n");
    return;  /* Explicit return to ensure proper stack cleanup */
}

/*=============================================================================
 * SYSTEM: Interactive Login Prompt
 * Authenticates user before allowing shell access
 * Returns: 0 on success, -1 on failure
 *
 * NOTE: Stack protection disabled because it calls first_boot_password_setup()
 *       which has large password buffers and deep PBKDF2 call chain
 *=============================================================================*/
int shell_login_prompt(void) {
    char username[USER_MAX_USERNAME];
    char password[USER_MAX_PASSWORD];
    int attempts = 0;
    const int max_attempts = 3;

    /* Check for first-boot and set up root password if needed */
    // kprintf("[DEBUG] About to call first_boot_password_setup\n");
    first_boot_password_setup();
    // kprintf("[DEBUG] Returned from first_boot_password_setup\n");

    /* Clear screen and show login banner */
    kprintf("\033[2J\033[H");  /* ANSI clear screen */
    kprintf("\n");
    kprintf("   (\\_/) Hearty <3\n");
    kprintf("   (o.o) Thoughts ooO\n");
    kprintf("*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*\n");
    kprintf("  %s Login System\n", TINYOS_VERSION_NAME);
    kprintf("*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*\n");
    kprintf("\n");

    while (attempts < max_attempts) {
        /* The login prompt must be privileged (euid==0) so sys_setuid/setgid
         * can switch to ANY authenticated user. A previous successful login or
         * a failed attempt may have left this task with reduced credentials;
         * reset to root at the start of every attempt. Without this, the
         * second and later re-logins fail with "Unable to set credentials"
         * (a non-root task can only setuid to its own euid). This is privileged
         * kernel code in the login task, so set the fields directly. */
        {
            task_t* login_task = scheduler_get_current_task();
            if (login_task) {
                login_task->uid = 0;
                login_task->euid = 0;
                login_task->gid = 0;
                login_task->egid = 0;
            }
        }

        /* Clear username buffer at start of each attempt to prevent corruption */
        SECURE_ZERO_PASSWORD(username);

        /* Get username */
        kprintf("TinyOS login: ");
        size_t pos = 0;
        while (pos < USER_MAX_USERNAME - 1) {
            char c = keyboard_getchar();
            if (c == '\n') {
                username[pos] = '\0';
                kprintf("\n");
                break;
            } else if (c == '\b' || c == 0x7F) {  /* Backspace */
                if (pos > 0) {
                    pos--;
                    kprintf("\b \b");  /* Erase character on screen */
                }
            } else if (c >= 32 && c < 127) {  /* Printable characters */
                if (pos < USER_MAX_USERNAME - 1) {
                    username[pos++] = c;
                    kprintf("%c", c);  /* Echo character */
                }
            }
        }
        username[pos] = '\0';

        /* Skip empty username */
        if (username[0] == '\0') {
            continue;
        }

        /* Get password */
        kprintf("Password: ");
        read_password(password, sizeof(password));

        /* Authenticate */
        int auth_result = user_authenticate(username, password);

        /* Clear password from memory */
        SECURE_ZERO_PASSWORD(password);

        if (auth_result >= 0) {
            /* Success - find user and set credentials */
            user_account_t* user = user_find_by_username(username);
            if (user) {
                /* Set process credentials - CRITICAL: Check for errors.
                 * Set GID *before* UID: sys_setuid() drops euid to the target
                 * user, after which sys_setgid() (which requires euid==0 to
                 * pick an arbitrary gid) would fail. Doing setgid first, while
                 * still root, then setuid, is the standard Unix order and lets
                 * a non-root user log in (previously failed with "Unable to
                 * set credentials"). */
                if (sys_setgid(user->gid) < 0 || sys_setuid(user->uid) < 0) {
                    kprintf("\nLogin failed: Unable to set credentials (kernel error)\n");
                    kprintf("System security may be compromised. Please reboot.\n\n");
                    /* Credential switch failed - do NOT allow login */
                    continue;  /* Return to login prompt */
                }

                kprintf("\nLogin successful. Welcome, %s!\n\n", username);

                /*=============================================================
                 * POST-LOGIN SETUP: Create Regular User Account
                 *
                 * If only root exists (first login), prompt to create a
                 * regular user for daily use. This follows security best
                 * practice: don't run as root for normal operations.
                 *===========================================================*/
                if (user->uid == USER_UID_ROOT) {
                    /* If only root exists, this is likely first login */
                    if (user_count() == 1) {
                        kprintf("*********************************************************\n");
                        kprintf("* SECURITY RECOMMENDATION                               *\n");
                        kprintf("*********************************************************\n");
                        kprintf("\n");
                        kprintf("Running as root for daily tasks is a security risk.\n");
                        kprintf("Create a regular user account for normal operations.\n");
                        kprintf("\n");
                        kprintf("Would you like to create a regular user now? (y/n): ");

                        char response = keyboard_getchar();
                        kprintf("%c\n\n", response);

                        /* Consume the trailing newline after user's y/n response */
                        char trailing = keyboard_getchar();
                        if (trailing != '\n') {
                            /* If it wasn't a newline, it might be part of input - handle gracefully */
                            /* For now, we just consume one character which should be the newline */
                        }

                        if (response == 'y' || response == 'Y') {
                            char new_username[USER_MAX_USERNAME];
                            char new_password[USER_MAX_PASSWORD];
                            char confirm_password[USER_MAX_PASSWORD];

                            /* Get username */
                            kprintf("Enter username for new account: ");
                            size_t uname_pos = 0;
                            while (uname_pos < USER_MAX_USERNAME - 1) {
                                char c = keyboard_getchar();
                                if (c == '\n') {
                                    new_username[uname_pos] = '\0';
                                    kprintf("\n");
                                    break;
                                } else if (c == '\b' || c == 0x7F) {
                                    if (uname_pos > 0) {
                                        uname_pos--;
                                        kprintf("\b \b");
                                    }
                                } else if (c >= 32 && c < 127) {
                                    if (uname_pos < USER_MAX_USERNAME - 1) {
                                        new_username[uname_pos++] = c;
                                        kprintf("%c", c);
                                    }
                                }
                            }
                            new_username[uname_pos] = '\0';

                            /* Validate username */
                            if (strlen(new_username) == 0) {
                                kprintf("Username cannot be empty. Skipping user creation.\n\n");
                            } else if (user_find_by_username(new_username) != NULL) {
                                kprintf("User '%s' already exists. Skipping.\n\n", new_username);
                            } else {
                                /* Get password */
                                while (1) {
                                    kprintf("Enter password for %s: ", new_username);
                                    read_password(new_password, sizeof(new_password));

                                    if (strlen(new_password) == 0) {
                                        kprintf("Password cannot be empty. Try again.\n");
                                        continue;
                                    }

                                    kprintf("Confirm password: ");
                                    read_password(confirm_password, sizeof(confirm_password));

                                    if (strcmp(new_password, confirm_password) != 0) {
                                        SECURE_ZERO_PASSWORD(new_password);
                                        SECURE_ZERO_PASSWORD(confirm_password);
                                        kprintf("Passwords do not match. Try again.\n");
                                        continue;
                                    }

                                    break;
                                }

                                /* Create user (assign UID 1000, GID 100) */
                                if (user_create(new_username, 1000, USER_GID_USERS, new_password) == 0) {
                                    kprintf("\nUser '%s' created successfully!\n", new_username);
                                    kprintf("You can now login as '%s' for daily tasks.\n\n", new_username);
                                } else {
                                    kprintf("\nERROR: Failed to create user '%s'\n\n", new_username);
                                }

                                /* Clear passwords from memory */
                                SECURE_ZERO_PASSWORD(new_password);
                                SECURE_ZERO_PASSWORD(confirm_password);
                            }
                        } else {
                            kprintf("Skipping user creation.\n");
                            kprintf("You can create users later with: useradd <username>\n\n");
                        }

                        kprintf("*********************************************************\n\n");
                    }
                }

                return 0;
            } else {
                kprintf("\nLogin failed: user not found\n");
            }
        } else {
            /* Authentication failed */
            attempts++;
            int remaining = max_attempts - attempts;

            switch (auth_result) {
                case -2:
                    kprintf("\nLogin incorrect (user not found)\n");
                    break;
                case -3:
                    kprintf("\nAccount locked (too many failed attempts)\n");
                    kprintf("Please wait 60 seconds before trying again.\n");
                    return -1;  /* Locked out - refuse login */
                case -4:
                    kprintf("\nAccount is inactive\n");
                    break;
                case -5:
                    kprintf("\nLogin incorrect (bad password)\n");
                    break;
                case -6:
                    /*=========================================================
                     * No password set (should be rare - first-boot setup
                     * should have handled this)
                     *=======================================================*/
                    kprintf("\nAccount '%s' has no password set.\n", username);
                    kprintf("Contact your system administrator to set a password.\n");
                    return -1;  /* Cannot login without password */
                default:
                    kprintf("\nLogin failed\n");
                    break;
            }

            if (remaining > 0) {
                kprintf("%d login attempt%s remaining\n\n",
                        remaining, remaining == 1 ? "" : "s");
            }
        }
    }

    /* All attempts exhausted */
    kprintf("\nToo many login failures. Access denied.\n");
    return -1;
}
