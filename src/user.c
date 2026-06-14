/*=============================================================================
 * user.c - User and Group Management Implementation
 *=============================================================================*/
#include "user.h"
#include "kprintf.h"
#include "util.h"
#include "time.h"
#include "critical.h"
#include "mutex.h"
#include "sha256.h"  /* Changed from SHA-512 to SHA-256 */
#include "audit.h"
#include "crypto.h"   /* For CSPRNG salt generation (global_csprng) */
#include <stddef.h>

/*=============================================================================
 * GLOBAL STATE
 *=============================================================================*/

static user_account_t user_database[USER_MAX_USERS];
static group_t group_database[USER_MAX_USERS];
static bool user_system_initialized = false;

/*=============================================================================
 * CONCURRENCY PROTECTION - MUTEX (v1.13 Migration)
 *=============================================================================*/
static mutex_t user_db_mutex;

/*=============================================================================
 * PASSWORD HASHING - PBKDF2-HMAC-SHA256
 *===========================================================================*/

/*=============================================================================
 * SECURITY FIX: Complete Password Hash Overhaul
 *
 * PREVIOUS VULNERABILITIES:
 * 1. CRITICAL: Default credentials with fixed salt baked into image
 * 2. HIGH: Deterministic salt in dev mode (0xDE...) enables rainbow tables
 * 3. HIGH: Weak hashing (raw SHA-256, no HMAC, only 100-5000 iterations)
 * 4. MEDIUM: No self-describing format, can't upgrade algorithms
 *
 * NEW IMPLEMENTATION:
 * - Algorithm: PBKDF2-HMAC-SHA256 (NIST SP 800-132, RFC 2898)
 * - Iterations: 100,000 (production), 10,000 (dev) - meets OWASP 2023 guidance
 * - Salt: 16 bytes cryptographically random (always, even in dev mode)
 * - Format: Self-describing with algorithm + parameters
 * - Default accounts: LOCKED, no passwords - must be set on first boot
 *
 * HASH FORMAT (modular crypt format):
 * $pbkdf2-sha256$i=100000$<16-byte-salt-hex>$<32-byte-hash-hex>
 * Total length: ~130 bytes (fits in 192-byte buffer)
 *
 * REFERENCES:
 * - NIST SP 800-132: Recommendation for Password-Based Key Derivation
 * - OWASP Password Storage Cheat Sheet (2023)
 * - RFC 2898: PKCS #5: Password-Based Cryptography Specification v2.0
 *===========================================================================*/

#define PBKDF2_SALT_LEN 16
#define PBKDF2_HASH_LEN 32
/*
 * Iteration count is INDEPENDENT of the -DTINYOS_DEV build flag.
 *
 * Previously PBKDF2_ITERATIONS was tied to TINYOS_DEV, so the default
 * (dev) build silently weakened password hashing to 100 iterations — far
 * below any acceptable threshold — even though TINYOS_DEV only legitimately
 * means "fast build for testing." Password-hash strength is a runtime
 * security property and must not be a side effect of a build-speed flag.
 *
 * Default (including dev builds): OWASP 2023 minimum (100,000). The earlier
 * justification for a low count — that a long masked PBKDF2 loop was unsafe
 * under the timer-IRQ corruption bug — no longer applies: that ISR
 * corruption is fixed (context-switch / scheduler rewrite), so the full
 * iteration count runs reliably.
 *
 * Tests that genuinely need a fast KDF (and accept the weaker hash) can
 * opt in EXPLICITLY with -DTINYOS_FAST_KDF. This keeps the weakening
 * deliberate and visible, never the default.
 */
#ifdef TINYOS_FAST_KDF
#define PBKDF2_ITERATIONS 1000   /* TEST ONLY: weak, fast KDF. Never ship. */
#else
#define PBKDF2_ITERATIONS 100000 /* Production default: OWASP 2023 minimum */
#endif

/*=============================================================================
 * CRYPTO WORKSPACE: Dedicated global buffer for password hashing
 *
 * This workspace is used exclusively by password hashing functions to avoid
 * stack overflow. Access is protected by user_db_mutex (already held during
 * password operations), so no concurrent access is possible.
 *
 * Placed in .bss section, separate from user_database to avoid overlap.
 *===========================================================================*/
static struct crypto_workspace {
    /* HMAC buffers */
    uint8_t hmac_key_pad[64];
    uint8_t hmac_ipad[64];
    uint8_t hmac_opad[64];
    uint8_t hmac_inner_hash[32];
    sha256_ctx_t hmac_ctx;

    /* PBKDF2 buffers */
    uint8_t pbkdf2_U[32];
    uint8_t pbkdf2_T[32];
    uint8_t pbkdf2_salt_block[PBKDF2_SALT_LEN + 4];

    /* Safety padding to ensure no overlap with user_database */
    uint8_t _padding[4096];
} __attribute__((aligned(4096))) crypto_ws;

/**
 * @brief HMAC-SHA256 implementation for PBKDF2
 * RFC 2104: HMAC: Keyed-Hashing for Message Authentication
 */
static void hmac_sha256_pbkdf2(const uint8_t* key, size_t key_len,
                                const uint8_t* data, size_t data_len,
                                uint8_t* mac) {
    /* Use crypto workspace to avoid stack overflow */
    uint8_t* key_pad = crypto_ws.hmac_key_pad;
    uint8_t* ipad = crypto_ws.hmac_ipad;
    uint8_t* opad = crypto_ws.hmac_opad;
    uint8_t* inner_hash = crypto_ws.hmac_inner_hash;
    sha256_ctx_t* ctx = &crypto_ws.hmac_ctx;

    /* Prepare key: if longer than 64 bytes, hash it first */
    if (key_len > 64) {
        sha256(key, key_len, key_pad);
        memset(key_pad + 32, 0, 32);
    } else {
        memcpy(key_pad, key, key_len);
        memset(key_pad + key_len, 0, 64 - key_len);
    }

    /* Create ipad and opad */
    for (int i = 0; i < 64; i++) {
        ipad[i] = key_pad[i] ^ 0x36;
        opad[i] = key_pad[i] ^ 0x5C;
    }

    /* Inner hash: H(K XOR ipad || message) */
    sha256_init(ctx);
    sha256_update(ctx, ipad, 64);
    sha256_update(ctx, data, data_len);
    sha256_final(ctx, inner_hash);

    /* Outer hash: H(K XOR opad || inner_hash) */
    sha256_init(ctx);
    sha256_update(ctx, opad, 64);
    sha256_update(ctx, inner_hash, 32);
    sha256_final(ctx, mac);

    /* Workspace buffers (key_pad/ipad/opad/inner_hash/ctx) are wiped once by
     * pbkdf2_hmac_sha256() after its iteration loop; wiping here would cost
     * an extra zeroization per HMAC call (100k+ per password operation). */
}

/**
 * @brief PBKDF2-HMAC-SHA256 implementation
 * RFC 2898: PKCS #5: Password-Based Cryptography Specification v2.0
 *
 * @param password Password string
 * @param salt Salt bytes
 * @param salt_len Salt length (recommend 16 bytes minimum)
 * @param iterations Number of iterations (recommend 100,000+)
 * @param dk_len Derived key length in bytes
 * @param dk Output buffer for derived key
 *
 * NOTE: Re-enabling stack protection to catch overflow
 */
static void pbkdf2_hmac_sha256(const uint8_t* password, size_t password_len,
                                const uint8_t* salt, size_t salt_len,
                                uint32_t iterations,
                                size_t dk_len, uint8_t* dk) {
    /* Use crypto workspace to avoid stack overflow */
    uint8_t* U = crypto_ws.pbkdf2_U;
    uint8_t* T = crypto_ws.pbkdf2_T;
    uint8_t* salt_block = crypto_ws.pbkdf2_salt_block;
    uint32_t block_count = (dk_len + 31) / 32; /* Ceiling division */

    /* For each block */
    for (uint32_t block = 1; block <= block_count; block++) {
        /* Salt || INT_32_BE(i) */
        memcpy(salt_block, salt, salt_len);
        salt_block[salt_len + 0] = (block >> 24) & 0xFF;
        salt_block[salt_len + 1] = (block >> 16) & 0xFF;
        salt_block[salt_len + 2] = (block >> 8) & 0xFF;
        salt_block[salt_len + 3] = block & 0xFF;

        /* U_1 = HMAC(password, salt || block_index) */
        hmac_sha256_pbkdf2(password, password_len, salt_block, salt_len + 4, U);
        memcpy(T, U, 32);

        /* U_2 through U_iterations */
        for (uint32_t iter = 1; iter < iterations; iter++) {
            hmac_sha256_pbkdf2(password, password_len, U, 32, U);
            /* T = T XOR U */
            for (int j = 0; j < 32; j++) {
                T[j] ^= U[j];
            }
        }

        /* Copy T to output (handle last block which may be partial) */
        size_t offset = (block - 1) * 32;
        size_t to_copy = (offset + 32 <= dk_len) ? 32 : (dk_len - offset);
        memcpy(dk + offset, T, to_copy);
    }

    /* Zeroize the entire crypto workspace (HMAC pads/ctx and PBKDF2 U/T/
     * salt_block). U/T/salt_block are pointers, so sizeof() must not be
     * used on them. */
    crypto_secure_zero(&crypto_ws, sizeof(crypto_ws) - sizeof(crypto_ws._padding));
}

/**
 * @brief Convert byte array to hex string
 */
static void bytes_to_hex(const uint8_t* bytes, size_t len, char* hex) {
    const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i * 2] = hex_chars[(bytes[i] >> 4) & 0xF];
        hex[i * 2 + 1] = hex_chars[bytes[i] & 0xF];
    }
    hex[len * 2] = '\0';
}

/**
 * @brief Convert hex string to byte array
 * @return Number of bytes written, or -1 on error
 */
static int hex_to_bytes(const char* hex, uint8_t* bytes, size_t max_bytes) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > max_bytes) {
        return -1;
    }

    for (size_t i = 0; i < len / 2; i++) {
        char h1 = hex[i * 2];
        char h2 = hex[i * 2 + 1];

        uint8_t v1, v2;
        if (h1 >= '0' && h1 <= '9') v1 = h1 - '0';
        else if (h1 >= 'a' && h1 <= 'f') v1 = h1 - 'a' + 10;
        else if (h1 >= 'A' && h1 <= 'F') v1 = h1 - 'A' + 10;
        else return -1;

        if (h2 >= '0' && h2 <= '9') v2 = h2 - '0';
        else if (h2 >= 'a' && h2 <= 'f') v2 = h2 - 'a' + 10;
        else if (h2 >= 'A' && h2 <= 'F') v2 = h2 - 'A' + 10;
        else return -1;

        bytes[i] = (v1 << 4) | v2;
    }
    return len / 2;
}

/**
 * @brief Hash password with PBKDF2-HMAC-SHA256 and self-describing format
 *
 * @param password Plaintext password
 * @param hash_out Output buffer (must be at least 192 bytes)
 *
 * FORMAT: $pbkdf2-sha256$i=100000$<salt_hex>$<hash_hex>
 * Example: $pbkdf2-sha256$i=100000$a1b2c3...$d4e5f6...$
 *
 * NOTE: Re-enabling stack protection to catch overflow
 */
void user_hash_password(const char* password, char* hash_out) {
    // kprintf("[HASH_PWD] Called with password='%s' hash_out=%p\n", password, hash_out);

    if (!password || !hash_out) {
        kprintf("[HASH_PWD] NULL parameter\n");
        return;
    }

    /*=========================================================================
     * SECURITY FIX: Always use cryptographically random salt
     * Even in dev mode, salt must be random to prevent rainbow tables
     *=======================================================================*/
    /* Generate the salt and derive the key with interrupts MASKED.
     *
     * The masking is load-bearing and verified empirically: with it removed,
     * a preempted derivation leaves the system corrupted — login then fails
     * with "user not found" (user_database reads as empty) and/or the
     * set-time and verify-time hashes diverge. The exact mechanism is NOT
     * crypto_ws/user_database adjacency: PBKDF2/HMAC write only inside
     * crypto_ws (the _padding above already rules out an in-bounds overrun
     * reaching user_database), and access is single-CPU + mutex-serialized.
     * The corruption comes from the preempting context, not from this code
     * running long — consistent with shared CPU state (e.g. FPU/SSE not saved
     * across the preempting switch) or a residual save/restore gap. Masking
     * the whole derivation sidesteps it deterministically. Full PBKDF2 is
     * pure CPU (no I/O) and finishes in tens of ms even at 100k iterations,
     * so masking does not meaningfully delay the timer/scheduler. Verified:
     * set + login succeed at 100k masked.
     *
     * csprng_random_bytes() is now INSIDE the masked window too: salt
     * generation touches the same CSPRNG that the documented unmasked-reseed
     * race corrupts, and a preempting IRQ there produced the intermittent
     * boot-time #fault on the password-setup path. Masking the whole
     * salt+derive sequence removes that window. */
    uint8_t salt[PBKDF2_SALT_LEN];
    uint8_t dk[PBKDF2_HASH_LEN];
    CRITICAL_SECTION_ENTER();
    csprng_random_bytes(&global_csprng, salt, sizeof(salt));
    pbkdf2_hmac_sha256((const uint8_t*)password, strlen(password),
                       salt, sizeof(salt),
                       PBKDF2_ITERATIONS,
                       sizeof(dk), dk);
    CRITICAL_SECTION_EXIT();

    /* Convert to hex strings */
    char salt_hex[PBKDF2_SALT_LEN * 2 + 1];
    char hash_hex[PBKDF2_HASH_LEN * 2 + 1];
    bytes_to_hex(salt, sizeof(salt), salt_hex);
    bytes_to_hex(dk, sizeof(dk), hash_hex);

    /*=========================================================================
     * BOUNDS CHECKING FIX: Protect against buffer overflow
     * Maximum size needed: 18 + 6 + 1 + 32 + 1 + 64 + 1 + 1 = 124 bytes
     * Buffer size: USER_PASSWORD_HASH_LEN = 192 bytes
     * We use safe pointer arithmetic with bounds checking
     *=======================================================================*/
    char* out = hash_out;
    char* end = hash_out + USER_PASSWORD_HASH_LEN - 1;  /* Reserve 1 byte for null */

    /* Format: $pbkdf2-sha256$i=<iterations>$<salt>$<hash>$ */
    /* Manually construct string to avoid snprintf dependency */
    const char* prefix = "$pbkdf2-sha256$i=";
    while (*prefix && out < end) *out++ = *prefix++;

    /* Write iterations as decimal string */
    char iter_str[12];
    int iter_len = 0;
    uint32_t iter = PBKDF2_ITERATIONS;
    if (iter == 0) {
        iter_str[iter_len++] = '0';
    } else {
        char temp[12];
        int temp_len = 0;
        while (iter > 0) {
            temp[temp_len++] = '0' + (iter % 10);
            iter /= 10;
        }
        /* Reverse into iter_str */
        for (int i = temp_len - 1; i >= 0; i--) {
            iter_str[iter_len++] = temp[i];
        }
    }
    for (int i = 0; i < iter_len && out < end; i++) *out++ = iter_str[i];

    if (out < end) *out++ = '$';

    /* Copy salt hex */
    const char* s = salt_hex;
    while (*s && out < end) *out++ = *s++;

    if (out < end) *out++ = '$';

    /* Copy hash hex */
    const char* h = hash_hex;
    while (*h && out < end) *out++ = *h++;

    if (out < end) *out++ = '$';
    *out = '\0';

    // kprintf("[HASH_PWD] Written %d bytes to hash_out (max %d)\n",
    //         (int)(out - hash_out), USER_PASSWORD_HASH_LEN);
    /* Print hash in chunks to avoid format string issues */
    // kprintf("[HASH_PWD] Hash starts: $pbkdf2-sha256$i=%d$\n", PBKDF2_ITERATIONS);
    // kprintf("[HASH_PWD] Salt (first 32 chars): ");
    // for (int i = 0; i < 32 && salt_hex[i]; i++) kprintf("%c", salt_hex[i]);
    // kprintf("\n");

    /* Zeroize sensitive material */
    volatile unsigned char* p;

    p = (volatile unsigned char*)dk;
    for (size_t i = 0; i < sizeof(dk); i++) *p++ = 0;

    p = (volatile unsigned char*)salt;
    for (size_t i = 0; i < sizeof(salt); i++) *p++ = 0;

    p = (volatile unsigned char*)salt_hex;
    for (size_t i = 0; i < sizeof(salt_hex); i++) *p++ = 0;

    p = (volatile unsigned char*)hash_hex;
    for (size_t i = 0; i < sizeof(hash_hex); i++) *p++ = 0;
}

/*=============================================================================
 * USER DATABASE MANAGEMENT
 *=============================================================================*/

void user_init(void) {
    if (user_system_initialized) {
        kprintf("[USER] WARNING: Already initialized\n");
        return;
    }

    /* Initialize mutex for user database protection */
    mutex_init(&user_db_mutex, "user_db", 0);

    /* Initialize user database */
    for (int i = 0; i < USER_MAX_USERS; i++) {
        user_database[i].in_use = false;
        user_database[i].uid = 0;
        user_database[i].gid = 0;
        user_database[i].flags = 0;
        user_database[i].failed_attempts = 0;
        user_database[i].last_failed_time = 0;
    }

    /* Initialize group database */
    for (int i = 0; i < USER_MAX_USERS; i++) {
        group_database[i].in_use = false;
        group_database[i].gid = 0;
    }

    /*=========================================================================
     * CREATE DEFAULT GROUPS
     *=======================================================================*/
    group_create("root", USER_GID_ROOT);
    group_create("users", USER_GID_USERS);

    /*=========================================================================
     * SECURITY: Minimal Default Configuration - Root Account Only
     *
     * SECURITY RATIONALE:
     * - Principle of least privilege: Only create what's absolutely necessary
     * - Reduced attack surface: Fewer default accounts = fewer potential targets
     * - Explicit account creation: Administrator must consciously create users
     * - No default credentials: Root account has NO password until set
     *
     * DEFAULT SYSTEM STATE:
     * - Only root account (uid=0, gid=0) exists
     * - Root account is LOCKED with no password
     * - Administrator MUST set root password on first boot
     * - Additional users must be explicitly created via useradd command
     *
     * FIRST BOOT FLOW:
     * 1. System prompts to set root password
     * 2. After first successful root login, prompts to create regular user
     * 3. Administrator creates non-root accounts for daily use
     *
     * REFERENCES:
     * - CIS Benchmark: Minimize default accounts
     * - NIST SP 800-123: Principle of least privilege
     *=======================================================================*/

    /* Create root user (uid=0, gid=0) - LOCKED, no password */
    user_account_t* root = &user_database[0];
    root->in_use = true;
    safe_strcpy(root->username, "root", USER_MAX_USERNAME);
    root->uid = USER_UID_ROOT;
    root->gid = USER_GID_ROOT;
    root->flags = USER_FLAG_LOCKED;  /* LOCKED until password is set */
    root->failed_attempts = 0;
    root->last_failed_time = 0;
    memset(root->password_hash, 0, USER_PASSWORD_HASH_LEN);  /* No password */
    safe_strcpy(root->home_dir, "/root", USER_MAX_HOMEDIR);
    safe_strcpy(root->shell, "/bin/shell", USER_MAX_HOMEDIR);

    user_system_initialized = true;
    kprintf("[USER] Initialized (1 user, 2 groups). [OK]\n");
}

/*=============================================================================
 * USER LOOKUP
 *=============================================================================*/

user_account_t* user_find_by_uid(uint16_t uid) {
    for (int i = 0; i < USER_MAX_USERS; i++) {
        if (user_database[i].in_use && user_database[i].uid == uid) {
            return &user_database[i];
        }
    }
    return NULL;
}

user_account_t* user_find_by_username(const char* username) {
    if (!username) {
        // kprintf("[USER_FIND] NULL username passed\n");
        return NULL;
    }

    // kprintf("[USER_FIND] Looking for username: '%s'\n", username);

    for (int i = 0; i < USER_MAX_USERS; i++) {
        if (user_database[i].in_use) {
            if (strcmp(user_database[i].username, username) == 0) {
                return &user_database[i];
            }
        }
    }
    return NULL;
}

/*=============================================================================
 * USER CREATION/DELETION
 *=============================================================================*/

int user_create(const char* username, uint16_t uid, uint16_t gid, const char* password) {
    if (!username || !password) {
        return -1;  /* Invalid parameters */
    }

    /* Check if user already exists */
    if (user_find_by_uid(uid) || user_find_by_username(username)) {
        return -2;  /* User already exists */
    }

    /* Find free slot */
    mutex_lock(&user_db_mutex);

    int free_slot = -1;
    for (int i = 0; i < USER_MAX_USERS; i++) {
        if (!user_database[i].in_use) {
            free_slot = i;
            break;
        }
    }

    if (free_slot == -1) {
        mutex_unlock(&user_db_mutex);
        return -3;  /* User database full */
    }

    /* Create user */
    user_account_t* user = &user_database[free_slot];
    memset(user, 0, sizeof(user_account_t));

    safe_strcpy(user->username, username, USER_MAX_USERNAME);
    user->uid = uid;
    user->gid = gid;
    user->flags = USER_FLAG_ACTIVE;
    user->failed_attempts = 0;
    user->last_failed_time = 0;
    user->in_use = true;

    /* Hash password */
    user_hash_password(password, user->password_hash);

    /* Default home dir and shell */
    safe_strcpy(user->home_dir, "/", USER_MAX_HOMEDIR);
    safe_strcpy(user->shell, "/bin/shell", USER_MAX_HOMEDIR);

    mutex_unlock(&user_db_mutex);
    return 0;
}

int user_delete(uint16_t uid) {
    /* Cannot delete root */
    if (uid == USER_UID_ROOT) {
        return -1;
    }

    user_account_t* user = user_find_by_uid(uid);
    if (!user) {
        return -2;  /* User not found */
    }

    mutex_lock(&user_db_mutex);
    user->in_use = false;
    mutex_unlock(&user_db_mutex);

    return 0;
}

/*=============================================================================
 * PASSWORD MANAGEMENT
 *=============================================================================*/

/**
 * NOTE: Stack protection disabled because this calls user_hash_password()
 *       which has deep PBKDF2 call chain with large buffers
 *
 * SECURITY: The caller MUST zero the password buffer after calling this function
 *           using secure_memzero() or crypto_secure_zero() to prevent password
 *           from remaining in memory.
 */
int user_set_password(uint16_t uid, const char* password) {
    // kprintf("[USER_SET_PWD] Called for uid=%d\n", uid);

    if (!password) {
        kprintf("[USER_SET_PWD] NULL password\n");
        return -1;
    }

    user_account_t* user = user_find_by_uid(uid);
    if (!user) {
        kprintf("[USER_SET_PWD] user_find_by_uid returned NULL\n");
        return -2;  /* User not found */
    }

    // kprintf("[USER_SET_PWD] Found user: uid=%d username='%s' in_use=%d\n",
    //         user->uid, user->username, user->in_use);
    // kprintf("[USER_SET_PWD] User struct at %p, password_hash at %p\n",
    //         user, user->password_hash);

    mutex_lock(&user_db_mutex);

    // kprintf("[USER_SET_PWD] After mutex_lock, in_use=%d\n", user->in_use);

    /*=========================================================================
     * SECURITY FIX: Automatically unlock account when password is set
     *
     * Since default accounts are created LOCKED with no password, setting
     * a password should automatically unlock the account for use.
     *
     * This provides a smooth first-boot experience:
     * 1. System boots with all accounts locked
     * 2. Admin runs "passwd root" to set password
     * 3. Root account is now unlocked and usable
     *=======================================================================*/
    // kprintf("[USER_SET_PWD] About to hash password, in_use=%d\n", user->in_use);
    user_hash_password(password, user->password_hash);
    // kprintf("[USER_SET_PWD] Password hashed, first 16 chars: %.16s in_use=%d\n",
    //         user->password_hash, user->in_use);

    /* Unlock account if it was locked */
    if (user->flags & USER_FLAG_LOCKED) {
        user->flags &= ~USER_FLAG_LOCKED;  /* Clear LOCKED flag */
        kprintf("[USER] Account '%s' unlocked after password set\n", user->username);
    }

    /* Set account to active if not already */
    user->flags |= USER_FLAG_ACTIVE;

    // kprintf("[USER_SET_PWD] Password set successfully, in_use=%d active=%d\n",
    //         user->in_use, (user->flags & USER_FLAG_ACTIVE) ? 1 : 0);

    mutex_unlock(&user_db_mutex);

    /* Audit: Password change */
    audit_log(AUDIT_AUTH_PASSWORD_CHANGE, AUDIT_INFO, uid,
              "Password changed for UID %d (%s)", uid, user->username);

    return 0;
}

/**
 * @brief Verify password against stored hash
 *
 * Supports both new (PBKDF2-HMAC-SHA256) and legacy (raw SHA-256) formats
 * for backward compatibility during migration.
 *
 * @param username Username to authenticate
 * @param password Plaintext password to verify
 * @return true if password matches, false otherwise
 *
 * SECURITY: The caller MUST zero the password buffer after calling this function
 *           using secure_memzero() or crypto_secure_zero() to prevent password
 *           from remaining in memory.
 */
static bool user_verify_password_locked(const char* username, const char* password) {
    user_account_t* user = user_find_by_username(username);
    if (!user || !user->in_use) {
        kprintf("[VERIFY_PWD] User not found or not in_use\n");
        return false;
    }

    // kprintf("[VERIFY_PWD] User found, in_use=%d\n", user->in_use);

    /* Check if password hash is empty (account has no password set) */
    if (user->password_hash[0] == '\0') {
        kprintf("[VERIFY_PWD] Empty password hash\n");
        return false;  /* No password set, authentication fails */
    }

    /*=========================================================================
     * SECURITY FIX: Parse self-describing hash format
     *
     * NEW FORMAT: $pbkdf2-sha256$i=100000$<salt_hex>$<hash_hex>$
     * LEGACY FORMAT: raw bytes (first 16 bytes = salt, next 32 = hash)
     *
     * Auto-detect format and verify accordingly. This enables transparent
     * upgrade path: old hashes still work, new hashes use stronger algorithm.
     *=======================================================================*/

    if (user->password_hash[0] == '$') {
        /* New format: $pbkdf2-sha256$i=<iterations>$<salt>$<hash>$ */
        char* hash_copy = (char*)user->password_hash;

        /* Parse algorithm */
        if (strncmp(hash_copy, "$pbkdf2-sha256$", 15) != 0) {
            return false;  /* Unknown algorithm */
        }
        hash_copy += 15;

        /* Parse iterations */
        if (strncmp(hash_copy, "i=", 2) != 0) {
            return false;
        }
        hash_copy += 2;

        uint32_t iterations = 0;
        while (*hash_copy >= '0' && *hash_copy <= '9') {
            iterations = iterations * 10 + (*hash_copy - '0');
            hash_copy++;
        }
        if (*hash_copy != '$' || iterations == 0) {
            return false;
        }
        hash_copy++;  /* Skip $ */

        /* Parse salt */
        char* salt_start = hash_copy;
        while (*hash_copy != '$' && *hash_copy != '\0') {
            hash_copy++;
        }
        if (*hash_copy != '$') {
            return false;
        }

        size_t salt_hex_len = hash_copy - salt_start;
        hash_copy++;  /* Skip $ */

        /* Parse hash */
        char* hash_start = hash_copy;
        while (*hash_copy != '$' && *hash_copy != '\0') {
            hash_copy++;
        }
        size_t hash_hex_len = hash_copy - hash_start;

        /* Convert hex strings to bytes */
        uint8_t salt[PBKDF2_SALT_LEN];
        uint8_t stored_hash[PBKDF2_HASH_LEN];

        char salt_hex[PBKDF2_SALT_LEN * 2 + 1];
        char hash_hex[PBKDF2_HASH_LEN * 2 + 1];

        if (salt_hex_len > sizeof(salt_hex) - 1 || hash_hex_len > sizeof(hash_hex) - 1) {
            return false;
        }

        memcpy(salt_hex, salt_start, salt_hex_len);
        salt_hex[salt_hex_len] = '\0';
        memcpy(hash_hex, hash_start, hash_hex_len);
        hash_hex[hash_hex_len] = '\0';

        if (hex_to_bytes(salt_hex, salt, sizeof(salt)) != (int)sizeof(salt)) {
            return false;
        }
        if (hex_to_bytes(hash_hex, stored_hash, sizeof(stored_hash)) != (int)sizeof(stored_hash)) {
            return false;
        }

        /* Compute PBKDF2-HMAC-SHA256 with interrupts masked — see the note in
         * user_hash_password(): masking protects the shared crypto_ws /
         * user_database region from preemption and keeps the verify-time hash
         * identical to the set-time hash. */
        uint8_t computed_hash[PBKDF2_HASH_LEN];
        CRITICAL_SECTION_ENTER();
        pbkdf2_hmac_sha256((const uint8_t*)password, strlen(password),
                           salt, sizeof(salt),
                           iterations,
                           sizeof(computed_hash), computed_hash);
        CRITICAL_SECTION_EXIT();

        /* Constant-time comparison */
        int diff = 0;
        for (int i = 0; i < PBKDF2_HASH_LEN; i++) {
            diff |= (computed_hash[i] ^ stored_hash[i]);
        }

        /* Zeroize sensitive data */
        volatile unsigned char* p;

        p = (volatile unsigned char*)computed_hash;
        for (size_t i = 0; i < sizeof(computed_hash); i++) *p++ = 0;

        p = (volatile unsigned char*)stored_hash;
        for (size_t i = 0; i < sizeof(stored_hash); i++) *p++ = 0;

        p = (volatile unsigned char*)salt;
        for (size_t i = 0; i < sizeof(salt); i++) *p++ = 0;

        p = (volatile unsigned char*)salt_hex;
        for (size_t i = 0; i < sizeof(salt_hex); i++) *p++ = 0;

        p = (volatile unsigned char*)hash_hex;
        for (size_t i = 0; i < sizeof(hash_hex); i++) *p++ = 0;

        return (diff == 0);

    } else {
        /*=====================================================================
         * LEGACY FORMAT: Raw SHA-256 (for backward compatibility)
         * Format: salt[16] || hash[32]
         *
         * This path supports old password hashes during migration.
         * TODO: Remove this after all users have migrated to new format.
         *===================================================================*/

        /* Extract salt from stored hash (first 16 bytes) */
        uint8_t salt[16];
        for (int i = 0; i < 16; i++) {
            salt[i] = (uint8_t)user->password_hash[i];
        }

        /* Compute SHA-256 hash with same salt and password */
        sha256_ctx_t ctx;
        uint8_t hash[32];

        sha256_init(&ctx);
        sha256_update(&ctx, salt, 16);
        sha256_update(&ctx, password, strlen(password));
        sha256_final(&ctx, hash);

        /* Apply iterations (legacy used 100 or 5000) */
        int iterations = 100;  /* Assume dev mode iterations for legacy */
        for (int round = 0; round < iterations; round++) {
            sha256_init(&ctx);
            sha256_update(&ctx, hash, 32);
            sha256_final(&ctx, hash);
        }

        /* Constant-time comparison */
        int diff = 0;
        for (int i = 0; i < 32; i++) {
            diff |= (hash[i] ^ (uint8_t)user->password_hash[16 + i]);
        }

        /* Zeroize sensitive data */
        volatile unsigned char* p;

        p = (volatile unsigned char*)salt;
        for (size_t i = 0; i < sizeof(salt); i++) *p++ = 0;

        p = (volatile unsigned char*)hash;
        for (size_t i = 0; i < sizeof(hash); i++) *p++ = 0;

        return (diff == 0);
    }
}

bool user_verify_password(const char* username, const char* password) {
    // kprintf("[VERIFY_PWD] Called for username='%s', password='%s'\n", username, password);

    if (!username || !password) {
        kprintf("[VERIFY_PWD] NULL parameter\n");
        return false;
    }

    /* Serialize access to the shared crypto_ws workspace (see comment above
     * crypto_workspace): concurrent verify/passwd would corrupt each other's
     * PBKDF2 intermediate state. No caller holds user_db_mutex here. */
    mutex_lock(&user_db_mutex);
    bool match = user_verify_password_locked(username, password);
    mutex_unlock(&user_db_mutex);
    return match;
}

/*=============================================================================
 * AUTHENTICATION
 *=============================================================================*/

int user_authenticate(const char* username, const char* password) {
    if (!username || !password) {
        return -1;  /* Invalid parameters */
    }

    user_account_t* user = user_find_by_username(username);
    if (!user || !user->in_use) {
        /* Audit: Login failure - user not found */
        audit_log(AUDIT_AUTH_LOGIN_FAILURE, AUDIT_WARN, 0,
                  "Login failed: user '%s' not found", username);
        return -2;  /* User not found */
    }

    /*=========================================================================
     * SECURITY FIX: Distinguish between "no password set" and "failed attempts lockout"
     *
     * PREVIOUS BEHAVIOR:
     * Accounts created LOCKED with no password would show "Account locked
     * (too many failed attempts)" on first login attempt, confusing users.
     *
     * NEW BEHAVIOR:
     * Check if password is set BEFORE checking locked status. If no password
     * is set, return a distinct error code (-6) so the login prompt can
     * guide the user to set their password.
     *=======================================================================*/
    if (user->password_hash[0] == '\0') {
        /* Account has no password set yet */
        audit_log(AUDIT_AUTH_LOGIN_FAILURE, AUDIT_INFO, user->uid,
                  "Login failed: account '%s' has no password set", username);
        return -6;  /* No password set */
    }

    /* Check if account is locked (due to failed attempts or admin lock) */
    if (user->flags & USER_FLAG_LOCKED) {
        /* Check if a failed-attempts lockout expired. Administrative locks
         * (user_lock_account) leave failed_attempts at 0 and must persist
         * until user_unlock_account(). */
        uint32_t current_time = time_get_uptime_seconds();
        if (user->failed_attempts < USER_MAX_LOGIN_ATTEMPTS ||
            current_time - user->last_failed_time < USER_LOCKOUT_DURATION) {
            /* Audit: Login attempt on locked account */
            audit_log(AUDIT_AUTH_LOGIN_FAILURE, AUDIT_WARN, user->uid,
                      "Login failed: account '%s' is locked due to failed attempts", username);
            return -3;  /* Account locked */
        } else {
            /* Unlock account */
            mutex_lock(&user_db_mutex);
            user->flags &= ~USER_FLAG_LOCKED;
            user->failed_attempts = 0;
            mutex_unlock(&user_db_mutex);

            /* Audit: Automatic account unlock */
            audit_log(AUDIT_AUTH_ACCOUNT_UNLOCKED, AUDIT_INFO, user->uid,
                      "Account '%s' automatically unlocked after timeout", username);
        }
    }

    /* Check if account is active */
    if (!(user->flags & USER_FLAG_ACTIVE)) {
        /* Audit: Login attempt on inactive account */
        audit_log(AUDIT_AUTH_LOGIN_FAILURE, AUDIT_WARN, user->uid,
                  "Login failed: account '%s' is inactive", username);
        return -4;  /* Account inactive */
    }

    /* Verify password */
    if (!user_verify_password(username, password)) {
        /* Failed authentication */
        mutex_lock(&user_db_mutex);
        user->failed_attempts++;
        user->last_failed_time = time_get_uptime_seconds();

        /* Lock account after too many attempts */
        if (user->failed_attempts >= USER_MAX_LOGIN_ATTEMPTS) {
            user->flags |= USER_FLAG_LOCKED;
            kprintf("[USER] Account '%s' locked after %d failed attempts\n",
                    username, user->failed_attempts);

            /* Audit: Account locked due to failed attempts */
            audit_log(AUDIT_AUTH_ACCOUNT_LOCKED, AUDIT_ERROR, user->uid,
                      "Account '%s' locked after %lu failed login attempts",
                      username, (unsigned long)user->failed_attempts);
        } else {
            /* Audit: Failed login attempt */
            audit_log(AUDIT_AUTH_LOGIN_FAILURE, AUDIT_WARN, user->uid,
                      "Login failed: incorrect password for '%s' (attempt %lu/%d)",
                      username, (unsigned long)user->failed_attempts, USER_MAX_LOGIN_ATTEMPTS);
        }
        mutex_unlock(&user_db_mutex);

        return -5;  /* Wrong password */
    }

    /* Successful authentication */
    mutex_lock(&user_db_mutex);
    user->failed_attempts = 0;
    mutex_unlock(&user_db_mutex);

    /* Audit: Successful login */
    audit_log(AUDIT_AUTH_LOGIN_SUCCESS, AUDIT_INFO, user->uid,
              "User '%s' (UID %d) logged in successfully", username, user->uid);

    return user->uid;  /* Return uid on success */
}

void user_lock_account(const char* username) {
    user_account_t* user = user_find_by_username(username);
    if (user) {
        mutex_lock(&user_db_mutex);
        user->flags |= USER_FLAG_LOCKED;
        mutex_unlock(&user_db_mutex);

        /* Audit: Manual account lock */
        audit_log(AUDIT_AUTH_ACCOUNT_LOCKED, AUDIT_WARN, user->uid,
                  "Account '%s' locked manually", username);
    }
}

void user_unlock_account(const char* username) {
    user_account_t* user = user_find_by_username(username);
    if (user) {
        mutex_lock(&user_db_mutex);
        user->flags &= ~USER_FLAG_LOCKED;
        user->failed_attempts = 0;
        mutex_unlock(&user_db_mutex);

        /* Audit: Manual account unlock */
        audit_log(AUDIT_AUTH_ACCOUNT_UNLOCKED, AUDIT_INFO, user->uid,
                  "Account '%s' unlocked manually", username);
    }
}

/**
 * @brief Check if a user has a password set
 * @param uid User ID
 * @return true if password is set, false if empty or user not found
 *
 * SECURITY: Used to detect accounts without passwords (major vulnerability)
 */
bool user_has_password(uint16_t uid) {
    user_account_t* user = user_find_by_uid(uid);
    if (!user || !user->in_use) {
        return false;
    }

    /* Check if password hash is empty (all zeros or empty string) */
    /* Empty password is indicated by empty hash field */
    for (int i = 0; i < USER_PASSWORD_HASH_LEN; i++) {
        if (user->password_hash[i] != '\0') {
            return true;  /* Non-empty hash found */
        }
    }

    return false;  /* Password hash is empty */
}

/*=============================================================================
 * ACCOUNT MANAGEMENT
 *=============================================================================*/

int user_set_home_dir(uint16_t uid, const char* home_dir) {
    user_account_t* user = user_find_by_uid(uid);
    if (!user || !home_dir) {
        return -1;
    }

    mutex_lock(&user_db_mutex);
    safe_strcpy(user->home_dir, home_dir, USER_MAX_HOMEDIR);
    mutex_unlock(&user_db_mutex);

    return 0;
}

int user_set_shell(uint16_t uid, const char* shell) {
    user_account_t* user = user_find_by_uid(uid);
    if (!user || !shell) {
        return -1;
    }

    mutex_lock(&user_db_mutex);
    safe_strcpy(user->shell, shell, USER_MAX_HOMEDIR);
    mutex_unlock(&user_db_mutex);

    return 0;
}

bool user_is_active(uint16_t uid) {
    user_account_t* user = user_find_by_uid(uid);
    if (!user) {
        return false;
    }
    return (user->flags & USER_FLAG_ACTIVE) != 0;
}

/*=============================================================================
 * GROUP MANAGEMENT
 *=============================================================================*/

group_t* group_find_by_gid(uint16_t gid) {
    for (int i = 0; i < USER_MAX_USERS; i++) {
        if (group_database[i].in_use && group_database[i].gid == gid) {
            return &group_database[i];
        }
    }
    return NULL;
}

int group_create(const char* groupname, uint16_t gid) {
    if (!groupname) {
        return -1;
    }

    /* Check if group already exists */
    if (group_find_by_gid(gid)) {
        return -2;
    }

    /* Find free slot */
    mutex_lock(&user_db_mutex);

    int free_slot = -1;
    for (int i = 0; i < USER_MAX_USERS; i++) {
        if (!group_database[i].in_use) {
            free_slot = i;
            break;
        }
    }

    if (free_slot == -1) {
        mutex_unlock(&user_db_mutex);
        return -3;  /* Group database full */
    }

    group_t* group = &group_database[free_slot];
    safe_strcpy(group->groupname, groupname, USER_MAX_USERNAME);
    group->gid = gid;
    group->in_use = true;

    mutex_unlock(&user_db_mutex);
    return 0;
}

/*=============================================================================
 * DEBUGGING
 *=============================================================================*/

void user_list_all(void) {
    kprintf("[USER] User list:\n");
    for (int i = 0; i < USER_MAX_USERS; i++) {
        if (user_database[i].in_use) {
            user_account_t* u = &user_database[i];
            kprintf("  %-12s uid=%5d gid=%5d home=%s flags=0x%02x\n",
                    u->username, u->uid, u->gid, u->home_dir, u->flags);
        }
    }
}

void user_print_info(uint16_t uid) {
    user_account_t* user = user_find_by_uid(uid);
    if (!user) {
        kprintf("[USER] User with uid=%d not found\n", uid);
        return;
    }

    kprintf("[USER] User info:\n");
    kprintf("  Username:  %s\n", user->username);
    kprintf("  UID:       %d\n", user->uid);
    kprintf("  GID:       %d\n", user->gid);
    kprintf("  Home:      %s\n", user->home_dir);
    kprintf("  Shell:     %s\n", user->shell);
    kprintf("  Flags:     0x%02x ", user->flags);
    if (user->flags & USER_FLAG_ACTIVE) kprintf("[ACTIVE] ");
    if (user->flags & USER_FLAG_LOCKED) kprintf("[LOCKED] ");
    if (user->flags & USER_FLAG_NOLOGIN) kprintf("[NOLOGIN] ");
    kprintf("\n");
    kprintf("  Failed:    %d attempts\n", user->failed_attempts);
}

int user_count(void) {
    int count = 0;
    for (int i = 0; i < USER_MAX_USERS; i++) {
        if (user_database[i].in_use) {
            count++;
        }
    }
    return count;
}

/*=============================================================================
 * /ETC DIRECTORY STRUCTURE
 * Creates /etc directory with passwd, shadow, and group files
 * This provides Unix-like configuration structure (read-only for now)
 *=============================================================================*/

#include "ramfs.h"

/* Simple integer to string conversion */
static void int_to_str(int num, char* buf, int buf_size) {
    if (num == 0) {
        buf[0] = '0';
        buf[1] = '\0';
        return;
    }

    char temp[12];  /* Max int is 10 digits + sign + null */
    int i = 0;
    int is_neg = 0;

    if (num < 0) {
        is_neg = 1;
        num = -num;
    }

    while (num > 0 && i < 11) {
        temp[i++] = '0' + (num % 10);
        num /= 10;
    }

    int j = 0;
    if (is_neg && j < buf_size - 1) buf[j++] = '-';
    while (i > 0 && j < buf_size - 1) {
        buf[j++] = temp[--i];
    }
    buf[j] = '\0';
}

/*=============================================================================
 * SECURITY ENHANCEMENT: Kernel-Only Password Database
 *
 * TRADITIONAL UNIX/LINUX WEAKNESS:
 * - Password hashes stored in /etc/shadow on disk
 * - Even with restricted permissions (0600 root:root), can be stolen:
 *   * Boot from live USB and read /etc/shadow
 *   * Kernel exploits that read arbitrary files
 *   * Backup systems that copy /etc/shadow
 *   * Crash dumps that include filesystem state
 * - Once stolen, attackers can crack offline forever
 *
 * TINYOS SECURITY MODEL:
 * - Password hashes NEVER touch the filesystem
 * - Stored ONLY in kernel memory (user_database[] array)
 * - Cannot be read even with root filesystem access
 * - Must compromise running kernel to steal hashes
 * - Memory-only storage - lost on reboot (by design)
 *
 * COMPATIBILITY:
 * - /etc/passwd still exists for Unix compatibility
 * - Contains user info but 'x' in password field (standard)
 * - NO /etc/shadow file created
 * - Tools that read /etc/passwd work normally
 * - Authentication via kernel syscalls only
 *
 * IMPLICATIONS:
 * - Passwords don't persist across reboots (acceptable for embedded/live systems)
 * - For persistent passwords, add encrypted database with kernel-only decryption
 * - Superior security: offline attacks impossible
 *
 * REFERENCES:
 * - CIS Benchmark: Protect password hashes
 * - NIST SP 800-123: Minimize credential exposure
 *===========================================================================*/

void user_create_etc_structure(void) {
    char buffer[512];
    int fd;

    /* Create /etc directory */
    ramfs_mkdir("/etc");

    /*-------------------------------------------------------------------------
     * CREATE /etc/passwd (read-only compatibility view)
     * Format: username:x:uid:gid:comment:home:shell
     *
     * NOTE: 'x' in password field indicates passwords are not in this file
     *       (standard Unix convention for shadowed passwords)
     *-----------------------------------------------------------------------*/
    fd = ramfs_open("/etc/passwd", RAMFS_FLAG_WRITE);
    if (fd < 0) {
        kprintf("[USER] ERROR: Cannot create /etc/passwd\n");
        return;
    }

    /* Write header comment */
    ramfs_write(fd, "# /etc/passwd - User account information\n", 42);
    ramfs_write(fd, "# Format: username:x:uid:gid:comment:home:shell\n", 49);
    ramfs_write(fd, "#\n", 2);
    ramfs_write(fd, "# SECURITY: Password hashes are NOT in this file.\n", 51);
    ramfs_write(fd, "#           Passwords stored in kernel memory only.\n", 53);
    ramfs_write(fd, "#           Authentication via kernel syscalls.\n", 49);
    ramfs_write(fd, "#\n", 2);

    /* Write all users */
    for (int i = 0; i < USER_MAX_USERS; i++) {
        if (user_database[i].in_use) {
            user_account_t* user = &user_database[i];
            char uid_str[12], gid_str[12];

            int_to_str(user->uid, uid_str, sizeof(uid_str));
            int_to_str(user->gid, gid_str, sizeof(gid_str));

            /* Format: username:x:uid:gid:TinyOS User:home:shell */
            size_t pos = 0;
            /* username */
            for (const char* p = user->username; *p && pos < sizeof(buffer) - 10; p++)
                buffer[pos++] = *p;
            if (pos < sizeof(buffer) - 10) buffer[pos++] = ':';
            if (pos < sizeof(buffer) - 10) buffer[pos++] = 'x';
            if (pos < sizeof(buffer) - 10) buffer[pos++] = ':';
            /* uid */
            for (const char* p = uid_str; *p && pos < sizeof(buffer) - 10; p++)
                buffer[pos++] = *p;
            if (pos < sizeof(buffer) - 10) buffer[pos++] = ':';
            /* gid */
            for (const char* p = gid_str; *p && pos < sizeof(buffer) - 10; p++)
                buffer[pos++] = *p;
            /* :TinyOS User:home:shell\n */
            const char* suffix = ":TinyOS User:";
            for (const char* p = suffix; *p && pos < sizeof(buffer) - 10; p++)
                buffer[pos++] = *p;
            for (const char* p = user->home_dir; *p && pos < sizeof(buffer) - 10; p++)
                buffer[pos++] = *p;
            if (pos < sizeof(buffer) - 10) buffer[pos++] = ':';
            for (const char* p = user->shell; *p && pos < sizeof(buffer) - 10; p++)
                buffer[pos++] = *p;
            if (pos < sizeof(buffer) - 2) buffer[pos++] = '\n';
            buffer[pos] = '\0';

            ramfs_write(fd, buffer, pos);
        }
    }
    ramfs_close(fd);

    /*=========================================================================
     * /etc/shadow INTENTIONALLY NOT CREATED
     *
     * SECURITY DECISION: Break from legacy Unix/Linux design flaw
     *
     * TRADITIONAL UNIX/LINUX APPROACH:
     * - Store password hashes in /etc/shadow
     * - Protect with 0600 permissions (root-only)
     * - Hope that's enough security
     *
     * WHY THIS IS WEAK:
     * 1. Boot from live USB → read /etc/shadow (bypass permissions)
     * 2. Kernel exploits → read arbitrary files
     * 3. Backup systems → copy /etc/shadow to insecure locations
     * 4. Forensic tools → extract /etc/shadow from disk images
     * 5. Cloud snapshots → /etc/shadow in backup storage
     * 6. Container escape → read host /etc/shadow
     * 7. Memory dumps → filesystem cache contains /etc/shadow
     *
     * TINYOS SECURE APPROACH:
     * - Password hashes stored ONLY in kernel memory
     * - Never written to disk/filesystem
     * - Not accessible even with full filesystem access
     * - Attacker must compromise running kernel (much harder)
     * - Lost on reboot (acceptable for embedded/kiosk systems)
     *
     * ATTACK SURFACE COMPARISON:
     *
     * Traditional Unix/Linux:
     *   /etc/shadow exists on disk
     *   ↓
     *   Steal via: filesystem access, backups, forensics, live boot
     *   ↓
     *   Crack offline with GPU clusters forever
     *   ↓
     *   Game over
     *
     * TinyOS:
     *   Password hashes in kernel memory only
     *   ↓
     *   Must: exploit kernel, dump memory, bypass ASLR/DEP
     *   ↓
     *   Much harder attack, limited time window
     *   ↓
     *   Superior security posture
     *
     * FOR PERSISTENT PASSWORDS (future enhancement):
     * - Add encrypted password database
     * - Decrypt key derived from TPM/hardware
     * - Still never expose plaintext hashes to filesystem
     * - Decryption happens in kernel only
     *
     * UNIX COMPATIBILITY:
     * - /etc/passwd exists (standard format)
     * - Password field is 'x' (standard shadow convention)
     * - Tools that read /etc/passwd work fine
     * - Tools that need /etc/shadow will fail gracefully
     * - Authentication via kernel syscalls (transparent to apps)
     *
     * CONCLUSION:
     * We eliminate a 50+ year old Unix design flaw. Password hashes
     * never touch persistent storage, making offline attacks impossible.
     *=======================================================================*/

    /*-------------------------------------------------------------------------
     * CREATE /etc/group
     * Format: groupname:x:gid:members
     *-----------------------------------------------------------------------*/
    fd = ramfs_open("/etc/group", RAMFS_FLAG_WRITE);
    if (fd < 0) {
        kprintf("[USER] ERROR: Cannot create /etc/group\n");
        return;
    }

    /* Write header comment */
    ramfs_write(fd, "# /etc/group - Group information\n", 34);
    ramfs_write(fd, "# Format: groupname:x:gid:members\n", 35);
    ramfs_write(fd, "#\n", 2);

    /* Write all groups */
    for (int i = 0; i < USER_MAX_USERS; i++) {
        if (group_database[i].in_use) {
            group_t* group = &group_database[i];
            char gid_str[12];

            int_to_str(group->gid, gid_str, sizeof(gid_str));

            /* Find all members of this group */
            char members[256] = "";
            int member_count = 0;
            size_t members_len = 0;

            for (int j = 0; j < USER_MAX_USERS; j++) {
                if (user_database[j].in_use && user_database[j].gid == group->gid) {
                    if (member_count > 0 && members_len < sizeof(members) - 1) {
                        members[members_len++] = ',';
                        members[members_len] = '\0';
                    }
                    /* Append username */
                    const char* username = user_database[j].username;
                    while (*username && members_len < sizeof(members) - 1) {
                        members[members_len++] = *username++;
                    }
                    members[members_len] = '\0';
                    member_count++;
                }
            }

            /* Format: groupname:x:gid:member1,member2,... */
            size_t pos = 0;
            /* groupname */
            for (const char* p = group->groupname; *p && pos < sizeof(buffer) - 10; p++)
                buffer[pos++] = *p;
            if (pos < sizeof(buffer) - 10) buffer[pos++] = ':';
            if (pos < sizeof(buffer) - 10) buffer[pos++] = 'x';
            if (pos < sizeof(buffer) - 10) buffer[pos++] = ':';
            /* gid */
            for (const char* p = gid_str; *p && pos < sizeof(buffer) - 10; p++)
                buffer[pos++] = *p;
            if (pos < sizeof(buffer) - 10) buffer[pos++] = ':';
            /* members */
            for (const char* p = members; *p && pos < sizeof(buffer) - 10; p++)
                buffer[pos++] = *p;
            if (pos < sizeof(buffer) - 2) buffer[pos++] = '\n';
            buffer[pos] = '\0';

            ramfs_write(fd, buffer, pos);
        }
    }
    ramfs_close(fd);

    /*-------------------------------------------------------------------------
     * CREATE /etc/issue (login banner)
     *
     * SECURITY: Do NOT disclose default passwords in login banner!
     * This makes brute-force attacks trivial.
     *-----------------------------------------------------------------------*/
    fd = ramfs_open("/etc/issue", RAMFS_FLAG_WRITE);
    if (fd >= 0) {
        ramfs_write(fd, "TinyOS v1.10 - Multi-User Operating System\n", 44);
        ramfs_write(fd, "\n", 1);
#ifdef TINYOS_DEV
        /* Development mode: Show default credentials with warning */
        ramfs_write(fd, "=== DEVELOPMENT MODE - INSECURE ===\n", 36);
        ramfs_write(fd, "Default users:\n", 15);
        ramfs_write(fd, "  root  (password: root)\n", 26);
        ramfs_write(fd, "  user  (password: user)\n", 26);
        ramfs_write(fd, "WARNING: Change passwords before deployment!\n", 46);
#else
        /* Production mode: Generic login prompt without password hints */
        ramfs_write(fd, "Please login with your credentials.\n", 37);
        ramfs_write(fd, "Contact system administrator if you need assistance.\n", 54);
#endif
        ramfs_write(fd, "\n", 1);
        ramfs_close(fd);
    }

    /*-------------------------------------------------------------------------
     * CREATE /etc/motd (message of the day)
     *-----------------------------------------------------------------------*/
    fd = ramfs_open("/etc/motd", RAMFS_FLAG_WRITE);
    if (fd >= 0) {
        ramfs_write(fd, "Welcome to TinyOS v1.10!\n", 25);
        ramfs_write(fd, "\n", 1);
        ramfs_write(fd, "This is a multi-user operating system with:\n", 45);
        ramfs_write(fd, "  - User authentication and authorization\n", 43);
        ramfs_write(fd, "  - File permission enforcement\n", 34);
        ramfs_write(fd, "  - Process privilege separation\n", 35);
        ramfs_write(fd, "\n", 1);
        ramfs_write(fd, "Type 'help' for available commands.\n", 37);
        ramfs_write(fd, "\n", 1);
        ramfs_close(fd);
    }

    kprintf("[USER] Created /etc structure (passwd, shadow, group, issue, motd)\n");
}
