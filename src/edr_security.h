/*=============================================================================
 * edr_security.h - EDR Security Helper Functions (Phase 1)
 *=============================================================================
 * Utility functions for managing process capabilities and syscall filtering.
 *
 * FEATURES:
 * - Capability management (grant/revoke/check)
 * - Syscall filter setup (allow/deny/allow_all)
 * - Sandboxing profiles (browser, network daemon, etc.)
 *
 * USAGE:
 *   // Create a sandboxed browser process
 *   task_t* browser = create_process("browser");
 *   edr_apply_browser_sandbox(browser);
 *
 *   // Or manually configure
 *   edr_syscall_filter_enable(browser);
 *   edr_syscall_allow(browser, SYS_READ);
 *   edr_syscall_allow(browser, SYS_WRITE);
 *=============================================================================*/
#ifndef EDR_SECURITY_H
#define EDR_SECURITY_H

#include "process.h"
#include "syscall.h"
#include <stdbool.h>

/*=============================================================================
 * CAPABILITY MANAGEMENT
 *=============================================================================*/

/**
 * @brief Grant a capability to a process
 * @param task Process to grant capability to
 * @param capability Capability flag (e.g., CAP_SYS_ADMIN)
 */
static inline void edr_capability_grant(task_t* task, uint32_t capability) {
    if (task) {
        task->capabilities |= capability;
    }
}

/**
 * @brief Revoke a capability from a process
 * @param task Process to revoke capability from
 * @param capability Capability flag to revoke
 */
static inline void edr_capability_revoke(task_t* task, uint32_t capability) {
    if (task) {
        task->capabilities &= ~capability;
    }
}

/**
 * @brief Check if a process has a specific capability
 * @param task Process to check
 * @param capability Capability flag to check
 * @return true if task has the capability, false otherwise
 */
static inline bool edr_capability_has(task_t* task, uint32_t capability) {
    return task && (task->capabilities & capability);
}

/**
 * @brief Grant all capabilities (for root processes)
 * @param task Process to grant all capabilities to
 */
static inline void edr_capability_grant_all(task_t* task) {
    if (task) {
        task->capabilities = CAP_ALL;
    }
}

/**
 * @brief Revoke all capabilities (for privilege dropping)
 * @param task Process to drop all capabilities from
 */
static inline void edr_capability_drop_all(task_t* task) {
    if (task) {
        task->capabilities = 0;
    }
}

/*=============================================================================
 * SYSCALL FILTERING
 *=============================================================================*/

/**
 * @brief Enable syscall filtering for a process (deny-all mode)
 * @param task Process to enable filtering for
 *
 * After calling this, all syscalls are DENIED by default.
 * Use edr_syscall_allow() to whitelist specific syscalls.
 */
static inline void edr_syscall_filter_enable(task_t* task) {
    if (task) {
        task->syscall_filter_enabled = true;
        /* Clear all bits (deny all syscalls) */
        for (int i = 0; i < SYSCALL_FILTER_SIZE; i++) {
            task->syscall_filter[i] = 0;
        }
    }
}

/**
 * @brief Disable syscall filtering (allow-all mode)
 * @param task Process to disable filtering for
 */
static inline void edr_syscall_filter_disable(task_t* task) {
    if (task) {
        task->syscall_filter_enabled = false;
    }
}

/**
 * @brief Allow a specific syscall
 * @param task Process to configure
 * @param syscall_num Syscall number to allow (e.g., SYS_READ)
 */
static inline void edr_syscall_allow(task_t* task, uint32_t syscall_num) {
    if (task && syscall_num <= MAX_SYSCALL_NUM) {
        uint32_t idx = syscall_num / 32;
        uint32_t bit = syscall_num % 32;
        task->syscall_filter[idx] |= (1 << bit);
    }
}

/**
 * @brief Deny a specific syscall
 * @param task Process to configure
 * @param syscall_num Syscall number to deny
 */
static inline void edr_syscall_deny(task_t* task, uint32_t syscall_num) {
    if (task && syscall_num <= MAX_SYSCALL_NUM) {
        uint32_t idx = syscall_num / 32;
        uint32_t bit = syscall_num % 32;
        task->syscall_filter[idx] &= ~(1 << bit);
    }
}

/**
 * @brief Allow all syscalls (whitelis all)
 * @param task Process to configure
 */
static inline void edr_syscall_allow_all(task_t* task) {
    if (task) {
        for (int i = 0; i < SYSCALL_FILTER_SIZE; i++) {
            task->syscall_filter[i] = 0xFFFFFFFF;
        }
    }
}

/*=============================================================================
 * SANDBOXING PROFILES
 *=============================================================================*/

/**
 * @brief Apply browser sandbox profile
 *
 * ALLOWED SYSCALLS:
 * - SYS_EXIT (can exit)
 * - SYS_READ (can read input)
 * - SYS_WRITE (can write output)
 * - SYS_YIELD (can yield CPU)
 * - SYS_GETPID/GETUID/GETGID (can query own identity)
 *
 * DENIED SYSCALLS:
 * - SYS_SETUID/SETGID (cannot change identity)
 * - Future: SYS_EXEC (cannot spawn processes)
 * - Future: SYS_MODULE_LOAD (cannot load kernel modules)
 *
 * CAPABILITIES:
 * - CAP_FS_READ: Can read files
 * - CAP_FS_WRITE: Can write files (except protected paths)
 * - CAP_NET_RAW: Can create network connections
 *
 * @param task Process to sandbox
 */
static inline void edr_apply_browser_sandbox(task_t* task) {
    if (!task) return;

    /* Enable syscall filtering */
    edr_syscall_filter_enable(task);

    /* Allow safe syscalls */
    edr_syscall_allow(task, SYS_EXIT);
    edr_syscall_allow(task, SYS_READ);
    edr_syscall_allow(task, SYS_WRITE);
    edr_syscall_allow(task, SYS_YIELD);
    edr_syscall_allow(task, SYS_GETPID);
    edr_syscall_allow(task, SYS_GETUID);
    edr_syscall_allow(task, SYS_GETGID);
    edr_syscall_allow(task, SYS_GETEUID);
    edr_syscall_allow(task, SYS_GETEGID);

    /* Deny dangerous syscalls (explicitly, for clarity) */
    edr_syscall_deny(task, SYS_SETUID);
    edr_syscall_deny(task, SYS_SETGID);
    edr_syscall_deny(task, SYS_SETEUID);
    edr_syscall_deny(task, SYS_SETEGID);

    /* Set capabilities */
    task->capabilities = CAP_FS_READ | CAP_FS_WRITE | CAP_NET_RAW;
}

/**
 * @brief Apply network daemon sandbox profile
 *
 * Suitable for web servers, SSH daemons, etc.
 *
 * ALLOWED SYSCALLS:
 * - Basic I/O (READ, WRITE, EXIT, YIELD)
 * - Identity queries (GETPID, GETUID, etc.)
 *
 * DENIED SYSCALLS:
 * - Identity changes (SETUID, SETGID)
 * - Future: Process spawning (EXEC, FORK)
 *
 * CAPABILITIES:
 * - CAP_FS_READ: Can read files
 * - CAP_NET_RAW: Can bind to network ports
 * - NO CAP_FS_WRITE: Cannot write files (prevents web shell uploads)
 * - NO CAP_SYS_ADMIN: Cannot modify system files
 *
 * @param task Process to sandbox
 */
static inline void edr_apply_network_daemon_sandbox(task_t* task) {
    if (!task) return;

    /* Enable syscall filtering */
    edr_syscall_filter_enable(task);

    /* Allow safe syscalls */
    edr_syscall_allow(task, SYS_EXIT);
    edr_syscall_allow(task, SYS_READ);
    edr_syscall_allow(task, SYS_WRITE);
    edr_syscall_allow(task, SYS_YIELD);
    edr_syscall_allow(task, SYS_GETPID);
    edr_syscall_allow(task, SYS_GETUID);
    edr_syscall_allow(task, SYS_GETGID);
    edr_syscall_allow(task, SYS_GETEUID);
    edr_syscall_allow(task, SYS_GETEGID);

    /* Set capabilities (READ-ONLY filesystem access) */
    task->capabilities = CAP_FS_READ | CAP_NET_RAW;
}

/**
 * @brief Apply unrestricted profile (for trusted system processes)
 *
 * ALLOWED: All syscalls
 * CAPABILITIES: All capabilities
 *
 * Use for:
 * - Init process
 * - System daemons
 * - Package managers
 * - Anything running as root (uid=0)
 *
 * @param task Process to grant full access
 */
static inline void edr_apply_unrestricted_profile(task_t* task) {
    if (!task) return;

    /* Disable filtering (allow all syscalls) */
    edr_syscall_filter_disable(task);

    /* Grant all capabilities */
    edr_capability_grant_all(task);
}

#endif /* EDR_SECURITY_H */
