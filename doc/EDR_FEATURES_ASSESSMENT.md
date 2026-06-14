# TinyOS EDR Security Features Assessment

**Assessment Date**: 2025-01-19
**TinyOS Version**: v1.22+
**Purpose**: Evaluate proposed EDR features for integration priority and feasibility

---

## Executive Summary

This document assesses the suitability and priority of integrating advanced EDR (Endpoint Detection and Response) features into TinyOS, a lightweight educational/embedded operating system.

**Key Finding**: TinyOS already implements several Phase 1 foundational protections. The assessment recommends a **selective, pragmatic approach** focusing on features that provide maximum security benefit with minimal complexity overhead.

**Recommended Priority Order**:
1. ✅ **Complete Phase 1** (partial implementation exists)
2. 🎯 **Selective Phase 2** (VFS hooks, basic MAC)
3. ⚠️ **Limited Phase 3** (sequential write detection only)
4. ❌ **Skip Phase 4** (too complex for TinyOS's scope)

---

## Current TinyOS Security Posture

### ✅ Already Implemented

| Feature | Implementation | Location |
|---------|---------------|----------|
| **Stack Canaries** | GCC `-fstack-protector-strong` | Makefile:14, src/stack_guard.c |
| **Guard Pages** | Read-only pages below stacks | src/process.h:139-140 |
| **VFS Abstraction** | Unified I/O with security hooks | src/vfs.h, src/vfs.c |
| **User/Kernel Separation** | Ring 0/Ring 3 privilege separation | src/gdt.c, src/tss.c |
| **Lock Ordering Hierarchy** | 5-level lock acquisition order | LOCK_ORDERING.md |
| **Type-Safe Handles** | Prevents FD corruption | src/ramfs_vfs.c, src/fat32_vfs.c |
| **Error Handling** | Consistent VFS error codes | src/vfs.h:89-97 |

### ⚠️ Partial/Missing

| Feature | Status | Gap |
|---------|--------|-----|
| **W^X Enforcement** | ⚠️ Partial | No NX bit support (32-bit i686 limitation) |
| **Syscall Table Protection** | ❌ Missing | No SSDT/hook integrity monitoring |
| **MAC Framework** | ❌ Missing | No LSM-like policy engine |
| **Process Metadata** | ⚠️ Basic | Has PIDs, lacks SID/labeling |

---

## Phase 1: Foundational Integrity - Detailed Assessment

### 1.1 W^X Policy Enforcement

**Proposed Feature**: Prevent memory pages from being simultaneously Writable and Executable.

**TinyOS Status**: ⚠️ **PARTIAL - ARCHITECTURAL LIMITATION**

**Current Implementation**:
- TinyOS uses **32-bit i686 architecture** without PAE (Physical Address Extension)
- Standard 32-bit x86 page tables have only **R/W bit** and **U/S bit**
- **No NX (No-Execute) bit** in page table entries

**Evidence**:
```c
// src/paging.h:31-36
#define PAGE_PRESENT        (1 << 0)
#define PAGE_USER           (1 << 2)
#define PAGE_READONLY       (PAGE_PRESENT | PAGE_USER)  // Present + User, read-only
```

**Gap Analysis**:
- ❌ Cannot mark pages as non-executable (no NX bit)
- ✅ Can mark pages as read-only (W bit cleared)
- ❌ Cannot enforce W^X (can have writable + executable pages)

**Recommendation**: 🟡 **LOW PRIORITY - HARDWARE CONSTRAINT**

**Why**:
- Requires PAE mode with 64-bit PTEs (adds significant complexity)
- Or requires 64-bit architecture (major TinyOS rewrite)
- Benefit/complexity ratio is poor for educational OS

**Alternative Mitigation**:
- Document architectural limitation
- Focus on **application-level W^X** via process memory layout
- Implement **code segment protection** using GDT segment limits

**Implementation Effort**: 🔴 **VERY HIGH** (architecture change)

---

### 1.2 Kernel Object Integrity Monitoring (Stack Canaries)

**Proposed Feature**: Stack canaries for kernel threads to detect buffer overflows.

**TinyOS Status**: ✅ **FULLY IMPLEMENTED**

**Current Implementation**:
- GCC `-fstack-protector-strong` enabled globally
- Random canary value (`__stack_chk_guard`) initialized at boot
- Panic handler (`__stack_chk_fail()`) triggers kernel halt

**Evidence**:
```c
// Makefile:14
CFLAGS  := -fstack-protector-strong

// src/stack_guard.c
extern void __stack_chk_fail(void) {
    panic("Stack smashing detected!");
}
```

**Recommendation**: ✅ **COMPLETE - NO ACTION NEEDED**

**Additional Enhancement** (Optional):
- Add per-thread canary rotation (currently global)
- Log canary failures to audit subsystem

**Implementation Effort**: ✅ **DONE**

---

### 1.3 Hook Protection (SSDT/VTable Integrity)

**Proposed Feature**: Protect syscall table and function pointer tables from rootkit hooks.

**TinyOS Status**: ❌ **NOT IMPLEMENTED**

**Current Implementation**:
- Syscall table exists (`src/syscall.c`)
- No integrity monitoring
- No read-only protection after initialization

**Gap Analysis**:
- ❌ Syscall table is writable after boot
- ❌ No hash/checksum validation
- ❌ No CR0.WP enforcement for kernel writes

**Recommendation**: 🟢 **HIGH PRIORITY - EASY WIN**

**Rationale**:
- **High security value**: Prevents kernel-mode rootkits
- **Low complexity**: Simple implementation
- **No performance cost**: One-time setup

**Implementation Steps**:
1. Add `mark_syscall_table_readonly()` function
2. Map syscall table pages as read-only using `PAGE_READONLY` flag
3. Add boot-time checksum validation
4. Store expected function pointer values in `.rodata`

**Estimated Effort**: 🟢 **LOW** (1-2 days)

**Code Sketch**:
```c
// src/syscall.c
void protect_syscall_table(void) {
    // Get page containing syscall_table[]
    uint32_t table_page = (uint32_t)&syscall_table & ~0xFFF;

    // Mark page as read-only
    page_set_flags(table_page, PAGE_READONLY);

    // Flush TLB
    asm volatile("invlpg (%0)" :: "r"(table_page) : "memory");

    kprintf("[SECURITY] Syscall table marked read-only at 0x%x\n", table_page);
}
```

---

## Phase 2: Core Policy and Prevention - Detailed Assessment

### 2.1 Mandatory Access Control (MAC) Framework

**Proposed Feature**: LSM-like framework with Subject SIDs and Object SIDs.

**TinyOS Status**: ❌ **NOT IMPLEMENTED**

**Current Implementation**:
- Basic Unix DAC (owner/group/permissions)
- No security labeling infrastructure
- No policy enforcement hooks

**Recommendation**: 🟡 **MEDIUM PRIORITY - SIMPLIFIED VERSION**

**Rationale**:
- **High complexity**: Full SELinux-style MAC is overkill for TinyOS
- **Alternative approach**: Implement **capability-based access control**
- **Pragmatic scope**: Focus on critical resources only

**Recommended Simplified Design**:

Instead of full MAC with SIDs, implement **process capabilities**:

```c
// src/process.h - Add to process structure
typedef struct {
    uint32_t capabilities;  // Bitmask of allowed operations
} process_t;

// Capability flags
#define CAP_SYS_ADMIN       (1 << 0)  // Can modify system files
#define CAP_NET_RAW         (1 << 1)  // Can create raw sockets
#define CAP_FS_WRITE        (1 << 2)  // Can write to filesystems
#define CAP_MODULE_LOAD     (1 << 3)  // Can load kernel modules
```

**VFS Integration**:
```c
// src/vfs.c - Add to vfs_open()
int vfs_open(const char* path, int flags) {
    process_t* current = get_current_process();

    // Check if process has FS_WRITE capability
    if ((flags & VFS_O_WRONLY) && !(current->capabilities & CAP_FS_WRITE)) {
        return VFS_EACCES;  // Permission denied
    }

    // Protect critical paths
    if (is_system_path(path) && !(current->capabilities & CAP_SYS_ADMIN)) {
        return VFS_EACCES;
    }

    // ... rest of open logic
}
```

**Implementation Effort**: 🟡 **MEDIUM** (1 week)

**Benefits**:
- ✅ Much simpler than full MAC
- ✅ Effective against privilege escalation
- ✅ Easy to reason about and debug
- ✅ Low performance overhead

**Limitations**:
- ⚠️ Less granular than SELinux
- ⚠️ No file-level labeling
- ⚠️ No policy reload without reboot

---

### 2.2 Syscall Filtering (Seccomp-like)

**Proposed Feature**: Allow/deny-list of syscalls per process.

**TinyOS Status**: ❌ **NOT IMPLEMENTED**

**Recommendation**: 🟢 **HIGH PRIORITY - HIGH VALUE**

**Rationale**:
- **Very effective** against exploit payloads
- **Low complexity**: Simple bitmap check
- **Negligible overhead**: Single branch per syscall

**Implementation Design**:

```c
// src/process.h
#define MAX_SYSCALLS 128

typedef struct {
    uint32_t syscall_filter[MAX_SYSCALLS / 32];  // Bitmap: 1 = allowed, 0 = denied
    bool filter_enabled;
} process_t;

// src/syscall.c
int syscall_dispatch(int syscall_num, ...) {
    process_t* current = get_current_process();

    // Check if syscall is allowed
    if (current->filter_enabled) {
        int idx = syscall_num / 32;
        int bit = syscall_num % 32;

        if (!(current->syscall_filter[idx] & (1 << bit))) {
            kprintf("[SECURITY] Process %d blocked syscall %d\n",
                    current->pid, syscall_num);
            return -ENOSYS;  // Function not implemented
        }
    }

    // ... dispatch to handler
}
```

**Example Use Case**:
```c
// Create a sandboxed process (e.g., web browser)
process_t* browser = create_process("browser");

// Allow only safe syscalls
allow_syscall(browser, SYS_READ);
allow_syscall(browser, SYS_WRITE);
allow_syscall(browser, SYS_OPEN);
allow_syscall(browser, SYS_CLOSE);

// Block dangerous syscalls
// - SYS_EXEC (prevent code execution)
// - SYS_PTRACE (prevent debugging other processes)
// - SYS_MODULE_LOAD (prevent kernel module loading)

browser->filter_enabled = true;
```

**Implementation Effort**: 🟢 **LOW** (2-3 days)

**Security Impact**: 🟢 **HIGH**
- Blocks ROP chains that try to exec("/bin/sh")
- Prevents shellcode from loading modules
- Limits attack surface dramatically

---

### 2.3 VFS Write Hooking

**Proposed Feature**: Intercept `open()` and `write()` to protect critical files.

**TinyOS Status**: ⚠️ **INFRASTRUCTURE EXISTS, HOOKS MISSING**

**Current Implementation**:
- VFS layer has centralized `vfs_open()` and `vfs_write()`
- All filesystem access goes through VFS
- No protection hooks implemented

**Recommendation**: 🟢 **HIGH PRIORITY - EASY WIN**

**Rationale**:
- **Infrastructure already exists** (VFS abstraction)
- **High security value**: Protects `/etc`, `/bin`, etc.
- **Low complexity**: Add simple path check

**Implementation**:

```c
// src/vfs.c
static const char* protected_paths[] = {
    "/bin/",
    "/sbin/",
    "/etc/passwd",
    "/etc/shadow",
    "/boot/",
    NULL
};

static bool is_protected_path(const char* path) {
    for (int i = 0; protected_paths[i] != NULL; i++) {
        if (strncmp(path, protected_paths[i], strlen(protected_paths[i])) == 0) {
            return true;
        }
    }
    return false;
}

int vfs_open(const char* path, int flags) {
    // Check write access to protected paths
    if ((flags & (VFS_O_WRONLY | VFS_O_RDWR)) && is_protected_path(path)) {
        process_t* current = get_current_process();

        // Only CAP_SYS_ADMIN can write to protected paths
        if (!(current->capabilities & CAP_SYS_ADMIN)) {
            kprintf("[VFS SECURITY] Denied write to %s by PID %d\n",
                    path, current->pid);
            return VFS_EACCES;
        }
    }

    // ... rest of open logic
}
```

**Implementation Effort**: 🟢 **VERY LOW** (1 day)

**Security Impact**: 🟢 **HIGH**
- Prevents unauthorized modification of system binaries
- Protects password files
- Blocks bootkit persistence

---

### 2.4 Metadata Transaction Integrity (Journaling/CoW)

**Proposed Feature**: Atomic metadata updates to prevent corruption.

**TinyOS Status**: ❌ **NOT IMPLEMENTED**

**Recommendation**: 🔴 **LOW PRIORITY - TOO COMPLEX**

**Rationale**:
- **Very high complexity**: Requires major filesystem redesign
- **Marginal benefit**: TinyOS is not a production storage OS
- **Better alternatives**: Focus on checksum validation instead

**Alternative Approach** (Much Simpler):

Instead of full journaling, implement **metadata checksums**:

```c
// Add checksum to filesystem superblock
typedef struct {
    uint32_t magic;
    uint32_t version;
    // ... other fields
    uint32_t metadata_checksum;  // CRC32 of critical metadata
} superblock_t;

// On mount, verify checksum
int verify_fs_integrity(superblock_t* sb) {
    uint32_t computed = crc32(sb, sizeof(*sb) - 4);
    if (computed != sb->metadata_checksum) {
        kprintf("[FS] Corruption detected! Expected 0x%x, got 0x%x\n",
                sb->metadata_checksum, computed);
        return -1;
    }
    return 0;
}
```

**Implementation Effort**: 🟡 **MEDIUM** (if doing checksums), 🔴 **VERY HIGH** (if doing journaling)

**Recommendation**: Implement checksums, skip journaling.

---

## Phase 3: Behavioral Detection - Detailed Assessment

### 3.1 Control-Flow Integrity (CFI)

**Proposed Feature**: Shadow stack and forward-edge CFI to prevent ROP/JOP attacks.

**TinyOS Status**: ❌ **NOT IMPLEMENTED**

**Recommendation**: 🔴 **VERY LOW PRIORITY - PROHIBITIVE COMPLEXITY**

**Rationale**:
- **Extreme complexity**: Requires compiler toolchain modifications
- **High performance cost**: 10-30% overhead typical
- **Limited scope**: TinyOS has limited user-space attack surface
- **Better alternatives**: Focus on W^X and ASLR instead

**Assessment**: ❌ **SKIP - NOT SUITABLE FOR TINYOS**

**Why**:
1. Requires LLVM/GCC plugin for instrumentation
2. Needs shadow stack in every function prologue/epilogue
3. Breaks compatibility with existing binaries
4. Overkill for an educational/embedded OS

**Alternative Mitigations**:
- ✅ Stack canaries (already implemented)
- ⚠️ ASLR (check if implemented)
- ⚠️ SafeSEH-like exception handler validation

---

### 3.2 Ransomware Detection (Sequential Write + Entropy)

**Proposed Feature**: Detect ransomware by monitoring file write patterns and entropy.

**TinyOS Status**: ❌ **NOT IMPLEMENTED**

**Recommendation**: 🟡 **MEDIUM PRIORITY - SIMPLIFIED VERSION**

**Rationale**:
- **Interesting educational value**: Good demonstration of behavioral detection
- **Moderate complexity**: Achievable without major refactoring
- **Limited practical value**: TinyOS unlikely to run ransomware
- **Performance concern**: Entropy calculation is CPU-intensive

**Recommended Simplified Implementation**:

**Step 1: Sequential Write Detection** (Cheap Pre-Filter)

```c
// src/vfs.c
#define RAPID_WRITE_THRESHOLD 10  // 10 writes to different files in 1 second

typedef struct {
    uint32_t pid;
    uint32_t file_write_count;   // Number of distinct files written
    uint32_t last_write_time;    // Timestamp of first write
} write_tracker_t;

static write_tracker_t write_trackers[VFS_MAX_FDS];

ssize_t vfs_write(int fd, const void* buf, size_t size) {
    process_t* current = get_current_process();
    uint32_t now = get_uptime_ms();

    // Find tracker for this process
    write_tracker_t* tracker = &write_trackers[current->pid % VFS_MAX_FDS];

    // Reset counter if more than 1 second elapsed
    if (now - tracker->last_write_time > 1000) {
        tracker->file_write_count = 0;
        tracker->last_write_time = now;
    }

    // Increment write counter
    tracker->file_write_count++;

    // Check for rapid sequential writes
    if (tracker->file_write_count > RAPID_WRITE_THRESHOLD) {
        kprintf("[RANSOMWARE DETECTION] PID %d: %d files written in 1 second!\n",
                current->pid, tracker->file_write_count);

        // OPTION 1: Kill process
        // kill_process(current->pid);

        // OPTION 2: Revoke write capability
        current->capabilities &= ~CAP_FS_WRITE;

        return VFS_EACCES;  // Deny this write
    }

    // ... rest of write logic
}
```

**Step 2: Entropy Check** (Only if pre-filter triggers)

```c
// Only calculate entropy for flagged processes
float calculate_shannon_entropy(const uint8_t* data, size_t len) {
    uint32_t freq[256] = {0};

    // Count byte frequencies
    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }

    // Calculate Shannon entropy: H = -Σ(p(x) * log2(p(x)))
    float entropy = 0.0f;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            float p = (float)freq[i] / len;
            entropy -= p * log2f(p);
        }
    }

    return entropy;  // High entropy (>7.5) indicates encryption
}
```

**Implementation Effort**: 🟡 **MEDIUM** (3-4 days)

**Security Impact**: 🟡 **MEDIUM** (Educational value > Practical value)

**Recommendation**: Implement as **optional educational feature**, not core security.

---

## Phase 4: Advanced Isolation - Detailed Assessment

### 4.1 Process Lineage / Chain-of-Trust

**Proposed Feature**: Track parent-child process relationships to prevent suspicious spawns.

**TinyOS Status**: ⚠️ **PARTIAL** (has PID/PPID, no enforcement)

**Recommendation**: 🟡 **LOW-MEDIUM PRIORITY - EDUCATIONAL VALUE**

**Rationale**:
- **Good learning opportunity**: Demonstrates process genealogy
- **Moderate complexity**: Requires process tree tracking
- **Limited practical value**: TinyOS has few processes

**Simplified Implementation**:

```c
// src/process.h
typedef struct {
    pid_t pid;
    pid_t ppid;                    // Parent PID
    char name[32];                 // Process name
    uint32_t spawn_capabilities;   // What this process can spawn
} process_t;

// Spawn rules
#define SPAWN_SHELL     (1 << 0)  // Can spawn /bin/sh
#define SPAWN_BROWSER   (1 << 1)  // Can spawn browser
#define SPAWN_NETWORK   (1 << 2)  // Can spawn network clients

// src/process.c
int check_spawn_allowed(process_t* parent, const char* child_path) {
    // Rule: Browser cannot spawn shells
    if (strcmp(parent->name, "browser") == 0 &&
        strstr(child_path, "/bin/sh") != NULL) {
        kprintf("[SPAWN BLOCK] Browser tried to spawn shell!\n");
        return -EACCES;
    }

    // Rule: Web server cannot spawn compilers
    if (strcmp(parent->name, "httpd") == 0 &&
        (strstr(child_path, "gcc") || strstr(child_path, "clang"))) {
        kprintf("[SPAWN BLOCK] Web server tried to spawn compiler!\n");
        return -EACCES;
    }

    return 0;  // Allowed
}
```

**Implementation Effort**: 🟡 **MEDIUM** (3-4 days)

**Security Impact**: 🟡 **MEDIUM** (Good for specific threat models)

**Recommendation**: Implement if TinyOS develops multi-process userspace.

---

### 4.2 Overlay Filesystem (Read-Only Lower Layer)

**Proposed Feature**: Use overlayfs to make critical directories read-only.

**TinyOS Status**: ❌ **NOT IMPLEMENTED**

**Recommendation**: 🔴 **VERY LOW PRIORITY - ARCHITECTURAL CHANGE**

**Rationale**:
- **Very high complexity**: Requires new filesystem type
- **Marginal benefit**: Can achieve same goal with simpler methods
- **Better alternative**: Use VFS write hooks (already recommended)

**Assessment**: ❌ **SKIP - USE VFS HOOKS INSTEAD**

---

### 4.3 IPC Monitoring

**Proposed Feature**: Enforce policies on inter-process communication.

**TinyOS Status**: ❌ **NOT IMPLEMENTED** (No IPC yet)

**Recommendation**: 🔴 **VERY LOW PRIORITY - PREMATURE**

**Rationale**:
- TinyOS has no IPC subsystem yet
- Would need to implement pipes, shared memory, message queues first
- Low value until multi-process userspace is mature

**Assessment**: ❌ **SKIP - IMPLEMENT IPC FIRST**

---

## Final Prioritized Roadmap

### 🟢 Phase 1: Quick Wins (Implement First)

**Timeline**: 1-2 weeks

| Feature | Effort | Impact | Status |
|---------|--------|--------|--------|
| **Syscall Table Protection** | 🟢 LOW | 🟢 HIGH | ⏳ Recommended |
| **VFS Write Hooks** | 🟢 VERY LOW | 🟢 HIGH | ⏳ Recommended |
| **Syscall Filtering** | 🟢 LOW | 🟢 HIGH | ⏳ Recommended |

**Expected Outcome**: Major security improvement with minimal effort.

---

### 🟡 Phase 2: Moderate Enhancements (Implement Second)

**Timeline**: 2-4 weeks

| Feature | Effort | Impact | Status |
|---------|--------|--------|--------|
| **Capability-Based Access Control** | 🟡 MEDIUM | 🟢 HIGH | ⏳ Recommended |
| **Filesystem Metadata Checksums** | 🟡 MEDIUM | 🟡 MEDIUM | ⏳ Optional |
| **Sequential Write Detection** | 🟡 MEDIUM | 🟡 MEDIUM | 📚 Educational |

**Expected Outcome**: Defense-in-depth with manageable complexity.

---

### 🔴 Phase 3: Advanced/Educational Features (Low Priority)

**Timeline**: Optional/Future

| Feature | Effort | Impact | Status |
|---------|--------|--------|--------|
| **Entropy Monitoring** | 🟡 MEDIUM | 🟡 LOW | 📚 Educational |
| **Process Lineage Tracking** | 🟡 MEDIUM | 🟡 MEDIUM | 📚 Educational |
| **W^X with PAE** | 🔴 VERY HIGH | 🟢 HIGH | ⏸️ Architecture Blocker |

**Expected Outcome**: Interesting demonstrations, limited practical value.

---

### ❌ Phase 4: Not Recommended (Skip)

| Feature | Reason to Skip |
|---------|----------------|
| **Control-Flow Integrity (CFI)** | Prohibitive complexity, requires compiler toolchain |
| **Full MAC (SELinux-style)** | Overkill; use capabilities instead |
| **Journaling Filesystem** | Too complex; use checksums instead |
| **Overlay Filesystem** | Better achieved with VFS hooks |
| **IPC Monitoring** | No IPC subsystem exists yet |

---

## Implementation Priority Summary

### ✅ Implement Now (High ROI)
1. **Syscall table protection** - 1 day
2. **VFS write hooks** - 1 day
3. **Syscall filtering** - 2 days
4. **Capability-based access control** - 1 week

**Total Effort**: ~2 weeks
**Security Improvement**: 🟢 **SUBSTANTIAL**

### 📚 Implement for Learning (Medium ROI)
1. **Sequential write detection** - 3 days
2. **Process lineage tracking** - 3 days
3. **Metadata checksums** - 4 days

**Total Effort**: ~2 weeks
**Security Improvement**: 🟡 **MODERATE**

### ❌ Do Not Implement (Poor ROI)
1. CFI (too complex)
2. Full MAC (too complex)
3. Journaling FS (too complex)
4. Overlay FS (redundant)

---

## Conclusion

TinyOS is well-positioned to adopt **pragmatic, high-value EDR features** without becoming bloated. The recommended approach:

1. ✅ **Leverage existing infrastructure** (VFS hooks, syscall dispatch)
2. ✅ **Prioritize simplicity** (capabilities over full MAC)
3. ✅ **Focus on educational value** (demonstrate concepts, not production-grade)
4. ✅ **Avoid architectural changes** (no CFI, no PAE, no journaling)

**Recommended Focus**: Implement **Phase 1 Quick Wins** for maximum security benefit with minimal complexity. Consider **Phase 2 Educational Features** if time permits and as learning exercises.

---

**Status**: ✅ Assessment Complete
**Next Step**: Review this assessment and select features to implement based on TinyOS goals (educational vs. production-hardened).
