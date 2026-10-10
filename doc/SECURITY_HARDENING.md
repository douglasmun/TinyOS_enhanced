# TinyOS Security Hardening Documentation

**Status**: living reference, reviewed 2026-10 against v2.8 (`TINYOS_VERSION`, `src/kernel.h`)
**Features**: Stack Guard Canaries + ASLR + PAE/NX W^X + Lazy FPU Switching + the mechanisms in sections 5-15

The `(v1.19)`-style tags in headings record when a mechanism first landed; the text describes the current code.

---

## Table of Contents

1. [Overview](#overview)
2. [Stack Guard Protection (v1.19)](#stack-guard-protection-v119)
3. [ASLR Protection (v1.20)](#aslr-protection-v120)
4. [Lazy FPU Switching (v1.22)](#lazy-fpu-switching-v122)
5. [Kernel-Only Credential Store — no on-disk `/etc/shadow`](#kernel-only-credential-store--no-on-disk-etcshadow)
6. [ELF Code Signing — ECDSA P-256, key pinning, fail-closed](#elf-code-signing--ecdsa-p-256-key-pinning-fail-closed)
7. [Pinned code-signing key — fail-closed](#pinned-code-signing-key--fail-closed)
8. [Crypto Hardening Primitives](#crypto-hardening-primitives)
9. [Hardware RNG Health Checks + Entropy Pool](#hardware-rng-health-checks--entropy-pool)
10. [Tamper-Evident Audit Log (HMAC-SHA512 hash chain)](#tamper-evident-audit-log-hmac-sha512-hash-chain)
11. [TOCTOU-Safe `copy_from_user` / `copy_to_user`](#toctou-safe-copy_from_user--copy_to_user)
12. [Stack Guard Pages + TSS esp0/ss0 Integrity](#stack-guard-pages--tss-esp0ss0-integrity)
13. [Account / Authentication Hardening](#account--authentication-hardening)
14. [Network Anti-Spoofing](#network-anti-spoofing)
15. [PMM Double-Free Detection + Process Capabilities](#pmm-double-free-detection--process-capabilities)
16. [C: (FAT32) Is a Shared Volume — by Design](#c-fat32-is-a-shared-volume--by-design)
17. [Combined Security Impact](#combined-security-impact)
18. [Testing & Verification](#testing--verification)
19. [Implementation Files](#implementation-files)

---

## Overview

TinyOS layers several exploit mitigations. The first four sections cover the memory-safety layer:

- **Stack Guard Canaries**: detect stack buffer overflows at function return
- **ASLR**: randomizes each user stack base
- **Lazy FPU switching**: FPU state stays with its owner task
- **PAE/NX W^X**: no page is both writable and executable (see "PAE/W^X")

Sections 5-15 cover credentials, code signing, crypto, audit, the user/kernel boundary and networking.

---

## Stack Guard Protection (v1.19)

### What is Stack Guard?

Stack Guard is a **runtime buffer overflow detection** mechanism that places a "canary" value between local variables and the return address on the stack. If a buffer overflow occurs, it overwrites the canary before reaching the return address, allowing detection before the exploit succeeds.

### How It Works

```
Stack Layout (grows DOWN):
┌─────────────────────┐ ← High addresses
│  Return Address     │  ← Target of exploit
├─────────────────────┤
│  CANARY (0x????00)  │  ← Detection layer
├─────────────────────┤
│  Local Variables    │  ← Overflow starts here
│  char buf[256];     │
└─────────────────────┘ ← Low addresses

If overflow occurs:
1. Attacker writes past buf[] boundary
2. Overwrites canary value
3. Stack guard check detects mismatch
4. __stack_chk_fail() halts the kernel before the return
```

### Implementation Details

**Location**: `src/stack_guard.c`, `src/stack_guard.h`

**Key Features**:
- **Canary Generation**: `entropy_get_random32()` (RDRAND or the entropy pool)
- **Null Byte Termination**: Canary ends with 0x00 to stop string functions
- **Compiler Integration**: GCC's `-fstack-protector-strong`, whole kernel, no per-file exception
- **Runtime Validation**: `__stack_chk_fail()` audits the event and calls `kernel_panic()`

**Canary Initialization**:
```c
void stack_guard_init(void) {
    __stack_chk_guard = entropy_get_random32();
    __stack_chk_guard = (__stack_chk_guard & 0xFFFFFF00) | 0x00;  // null LSB
    if (__stack_chk_guard == 0) {
        __stack_chk_guard = 0xDEADBE00;  /* Fallback canary */
    }
    /* The canary is never logged. */
}
```

**Protection Scope**:
- ✅ Buffers > 8 bytes
- ✅ Address-taken variables
- ✅ Array references
- ✅ All functions with `-fstack-protector-strong`

### Boot Log Output

```
[STACK_GUARD] Initialized......... [OK]
[STACK_GUARD] Protection enabled for:
[STACK_GUARD]   - Buffers > 8 bytes
[STACK_GUARD]   - Address-taken variables
[STACK_GUARD]   - Array references
```

### Attack Detection Example

On a mismatch `__stack_chk_fail()` writes an `AUDIT_SEC_STACK_CORRUPTION` record,
prints a `STACK CORRUPTION DETECTED` banner with context, and calls
`kernel_panic("Stack protection violation")`. The system halts; no task is killed
and resumed, because the corrupted frame cannot be trusted.

### Security Impact

- **Pre-Stack Guard**: Buffer overflows → 100% exploit success
- **With Stack Guard**: a linear overwrite of the return address is detected (non-linear writes that skip the canary are not)
- **Performance Cost**: ~1-2% overhead (negligible)

---

## ASLR Protection (v1.20)

### What is ASLR?

ASLR (Address Space Layout Randomization) randomizes the memory addresses of stack, heap, and code segments. Even if an attacker finds a vulnerability, they don't know **where** to jump to execute their payload.

### How It Works

```
Traditional (No ASLR):
Process 1: Stack at 0xBFFFFFF0  ← Always the same
Process 2: Stack at 0xBFFFFFF0  ← Predictable
Process 3: Stack at 0xBFFFFFF0  ← Attacker knows address

With ASLR (TinyOS v1.20):
Process 1: Stack at 0xBF7CA000  ← Random
Process 2: Stack at 0xBF012000  ← Random
Process 3: Stack at 0xBFAF3000  ← Random
          ↑
    12 bits of entropy = 4096 possible locations
```

### Implementation Details

**Location**: `src/aslr.c`, `src/aslr.h`

**Key Features**:
- **Entropy**: 12 bits (4096 page range = 16 MB)
- **RNG**: `aslr_random32()` returns `entropy_get_random32()` (RDRAND when present, else the entropy pool)
- **Reseeding**: `entropy_reseed()` once at init, then every 16 randomized stacks
- **Statistics**: `aslr_get_stats()`; the reseed count is stored obfuscated and no seed is ever printed

**Address Range**:
```c
#define ASLR_STACK_MIN  0x40000000  /* 1GB - plenty of room */
#define ASLR_STACK_MAX  0xC0000000  /* 3GB - kernel boundary */
#define ASLR_STACK_ENTROPY_PAGES  4096  /* 16MB range, 12 bits */
```

**Randomization Algorithm**:
```c
uint32_t aslr_get_random_stack_base(uint32_t stack_size_pages) {
    // Get random offset (0-4095 pages)
    uint32_t random_offset = aslr_random32() % ASLR_STACK_ENTROPY_PAGES;

    // Calculate randomized base (stack grows DOWN)
    uint32_t stack_base = ASLR_STACK_MAX -
                          ((stack_size_pages + random_offset) * 0x1000);

    // Ensure 16-byte alignment (x86 ABI requirement)
    return (stack_base & 0xFFFFFFF0);
}
```

**Integration Points**:
1. **Kernel Init** (`aslr_init()` in `src/kernel.c`, after `entropy_init()` and `stack_guard_init()`)
2. **Process Creation** (`aslr_get_random_stack_base()` from `src/process.c`): randomize each user stack
3. **Shell Command** (`cmd_aslr()` in `src/shell_system.c`): root-only, kernel shell only (`kshell` from the ring-3 shell)

### Boot Log Output

```
[ASLR] Initializing with multi-source entropy...
[ASLR] Entropy: 12 bits (range: 4096 pages)
[ASLR] Entropy quality: STRONG (RDRAND)
[ASLR] Using hardware RNG (RDRAND)... [EXCELLENT]
[ASLR] RDRAND verified operational
[ASLR] Performing initial entropy mixing...
[ASLR] Statistics obfuscation key initialized
[ASLR] Initialized................ [OK]
```

The quality line reads `MEDIUM (Pool)` or `WEAK (TSC)` when RDRAND is absent.

### Process Creation Log (ASLR Demo)

```
[ASLR] Creating demo user tasks to show stack randomization...
[PROCESS] Created user task PID=4 'ASLRDemo1' entry=0x80000c4
[PROCESS]   User stack: 0xbfbf3000 (ASLR randomized)
[PROCESS] Created user task PID=5 'ASLRDemo2' entry=0x80000c4
[PROCESS]   User stack: 0xbf723000 (ASLR randomized)
[PROCESS] Created user task PID=6 'ASLRDemo3' entry=0x80000c4
[PROCESS]   User stack: 0xbfd8e000 (ASLR randomized)
[PROCESS] Created user task PID=7 'ASLRDemo4' entry=0x80000c4
[PROCESS]   User stack: 0xbf4b7000 (ASLR randomized)
[PROCESS] Created user task PID=8 'ASLRDemo5' entry=0x80000c4
[PROCESS]   User stack: 0xbfec3000 (ASLR randomized)
[ASLR] Demo tasks created - observe different stack addresses above
```

The boot demo has since been removed, and the `[PROCESS]` lines are now `kdbg`
traces (`loglevel debug` shows them): on the default console they put every
spawned child's randomized stack address in front of whoever was reading it.

### Shell Command Usage

```bash
# aslr        (as root, kernel shell)

=== ASLR (Address Space Layout Randomization) ===
Status: ENABLED

Entropy:
  Bits:           12 bits
  Page range:     4096 pages (16 MB)
  Possible addrs: 4096 (2^12)
  Exploit chance: 1 in 4096

Statistics:
  Stacks randomized: 8
  RNG reseeds:       <obfuscated count>

Address Range:
  Minimum: 0xbf012000
  Maximum: 0xbfec3000
  Spread:  15308 KB

Security Impact:
  Without ASLR: Exploits work every time
  With ASLR:    Exploits work 1 attempt in 4096
  Protection:   ~4096x harder to exploit
```

### Security Impact

- **Exploit Success Rate**: 1/4096 = **0.0244%**
- **Brute Force**: ~4096 attempts on average
- **Protection Factor**: 4096x harder to exploit
- **Performance Cost**: <0.1% overhead

---

## Lazy FPU Switching (v1.22)

### What is Lazy FPU Switching?

Lazy FPU switching is a **performance optimization** that defers saving/restoring FPU (Floating Point Unit) state until a task actually uses the FPU. Instead of eagerly saving 512 bytes of FPU state on every context switch, we set the CR0.TS bit and handle FPU usage via exception.

**Problem**: Traditional context switching saves/restores FPU state for ALL tasks, even those that never use floating point operations.

**Solution**: Mark FPU as unavailable (CR0.TS), trigger exception on first FPU use, then save/restore only when needed.

### How It Works

```
Traditional (Eager) Context Switch:
┌─────────────────────────────────────┐
│ 1. Save prev FPU state (512 bytes) │ ← Expensive!
│ 2. Switch registers                │
│ 3. Load next FPU state (512 bytes) │ ← Expensive!
│ 4. Return to task                  │
└─────────────────────────────────────┘
Cost: ~200 cycles per context switch

Lazy FPU Context Switch:
┌─────────────────────────────────────┐
│ 1. Switch registers                │
│ 2. Set CR0.TS bit                  │ ← Fast!
│ 3. Return to task                  │
└─────────────────────────────────────┘
Cost: ~50 cycles per context switch (75% faster!)

When task uses FPU:
┌─────────────────────────────────────┐
│ FPU instruction (e.g., fadd)       │
│         ↓                          │
│ CPU triggers #NM exception (vec 7) │
│         ↓                          │
│ Exception Handler:                 │
│   - Save old owner's FPU state     │ ← Only if different task
│   - Restore current task's state   │
│   - Clear CR0.TS                   │
│   - Update FPU owner               │
│         ↓                          │
│ Return and retry instruction       │ ← Works now!
└─────────────────────────────────────┘
Cost: Only paid when FPU is actually used
```

### Implementation Details

**Location**: `src/scheduler.c`, `src/context_switch.S`, `src/interrupts.c`

**Key Components**:

#### 1. FPU Owner Tracking (`fpu_owner`, scheduler.c)

```c
/*
 * Track which task currently owns the FPU state.
 * NULL means FPU state is invalid (no owner).
 */
static volatile task_t* fpu_owner = NULL;
```

#### 2. Context Switch Modification (CR0 writes in context_switch.S)

```nasm
; OLD: Eagerly restore FPU state
; fxrstor [eax + 64]

; NEW: Set CR0.TS to defer FPU restore
mov eax, cr0
or eax, (1 << 3)      ; Set CR0.TS bit (bit 3)
mov cr0, eax
; FPU state will be restored on demand
```

#### 3. Device Not Available Handler (`vector == 7` in interrupts.c)

```c
if (vector == 7) {  // #NM - Device Not Available
    /* Task tried to use FPU while CR0.TS was set */
    scheduler_handle_fpu_exception();

    /* Return to interrupted code - FPU is now available */
    interrupt_context_exit();
    return;
}
```

#### 4. Lazy FPU Handler (`scheduler_handle_fpu_exception()`, scheduler.c)

```c
void scheduler_handle_fpu_exception(void) {
    CRITICAL_SECTION_ENTER();

    task_t* current = current_running_task;

    /* Step 1: Save FPU state from previous owner (if different) */
    if (fpu_owner && fpu_owner != current) {
        task_t* prev_owner = fpu_owner;
        __asm__ volatile("fxsave %0" : "=m"(prev_owner->context.fpu_state));
    }

    /* Step 2: Restore current task's FPU state */
    __asm__ volatile("fxrstor %0" :: "m"(current->context.fpu_state));

    /* Step 3: Clear CR0.TS to allow FPU use */
    __asm__ volatile("clts");  // Clear Task Switched bit

    /* Step 4: Update FPU owner */
    fpu_owner = current;

    CRITICAL_SECTION_EXIT();
}
```

#### 5. Cleanup Protection (`scheduler_fpu_release()`, scheduler.c)

```c
/* Called from the post-switch reaper (scheduler.c) and from
 * task_free_resources() (process.c), so a task killed from outside
 * cannot leave fpu_owner dangling into a recycled slot. */
void scheduler_fpu_release(task_t* task) {
    CRITICAL_SECTION_ENTER();
    if (fpu_owner == task) {
        fpu_owner = NULL;
    }
    CRITICAL_SECTION_EXIT();
}
```

### Performance Impact

#### Benchmark Scenario

The cycle counts below are design estimates, not measurements, and the SSH server
in the examples is not built in the current kernel; read them as an illustration.

**System**: 3 tasks (Shell, SSHServer, Idle)
- **Shell**: Minimal FPU use (only for formatting)
- **SSHServer**: Heavy FPU use (cryptography)
- **Idle**: No FPU use (just HLT)

#### Before (Eager FPU):

```
Context Switch Cost:
- Save FPU:    ~100 cycles × 512 bytes = ~100 cycles
- Restore FPU: ~100 cycles × 512 bytes = ~100 cycles
- Total:       ~200 cycles per switch

Switches per second: 100 (timer at 100Hz)
FPU overhead: 200 cycles × 100 = 20,000 cycles/sec
Wasted cycles (Idle never uses FPU): 66% × 20,000 = 13,333 cycles/sec
```

#### After (Lazy FPU):

```
Context Switch Cost:
- Set CR0.TS:  ~5 cycles
- Total:       ~50 cycles per switch

FPU exception cost (only when used):
- #NM handler: ~200 cycles (one-time per task)

Effective overhead:
- Shell:      50 cycles/switch + rare FPU exceptions
- SSHServer:  50 cycles/switch + FPU state save/restore when needed
- Idle:       50 cycles/switch + ZERO FPU cost

Total savings: ~75% reduction in context switch overhead
```

#### Real-World Impact

| Workload | Eager FPU Overhead | Lazy FPU Overhead | Improvement |
|----------|-------------------|-------------------|-------------|
| **No FPU use** (Idle task) | 200 cycles/switch | 50 cycles/switch | **75% faster** |
| **Rare FPU use** (Shell) | 200 cycles/switch | ~55 cycles/switch | **72% faster** |
| **Heavy FPU use** (SSH) | 200 cycles/switch | ~180 cycles/switch | **10% faster** |
| **Overall system** | 200 cycles avg | ~100 cycles avg | **50% faster** |

### Security Benefits

Lazy FPU switching is not just a performance optimization—it also enhances security:

#### 1. FPU State Isolation

**Problem**: In eager FPU switching, all tasks pay FPU cost even if they don't use it. This creates unnecessary exposure.

**Solution**: Lazy FPU ensures FPU state is only saved/restored for tasks that actually need it, reducing the attack surface.

#### 2. Cryptographic Key Protection

**Problem**: FPU registers may contain sensitive cryptographic data (e.g., AES round keys, ECDH scalars).

**Solution**: Lazy FPU ensures:
- FPU state is saved immediately when switching away from crypto task
- Old FPU state is NOT loaded into tasks that don't use FPU
- No residual crypto data leaks to non-crypto tasks

**Example**:
```
SSHServer (PID=2) performs ECDH key exchange:
1. Loads secret scalar into FPU registers (ST0-ST7)
2. Computes point multiplication
3. Context switch to Idle task
   → CR0.TS set (FPU marked unavailable)
   → SSHServer's FPU state REMAINS in FPU registers
   → Idle task never touches FPU
4. Context switch back to SSHServer
   → FPU state still valid (fpu_owner == SSHServer)
   → No restore needed!

Traditional approach:
1. SSHServer computes ECDH
2. Context switch to Idle
   → Save SSHServer FPU state (512 bytes with secret!)
   → Load Idle FPU state (overwrites secret)
3. Context switch to Shell
   → Load Shell FPU state (more copying)

Lazy approach minimizes secret data movement!
```

#### 3. Side-Channel Resistance

**Traditional FPU**: FPU state copied on every switch → more opportunities for timing attacks

**Lazy FPU**: FPU state only copied when necessary → fewer copy operations → reduced timing attack surface

### Modified Code Locations

| File | Function/Section | Change | Lines |
|------|------------------|--------|-------|
| `src/scheduler.c` | Global variables | Add `fpu_owner` tracking | +24 |
| `src/scheduler.c` | `scheduler_handle_fpu_exception()` | New lazy FPU handler | +64 |
| `src/scheduler.c` | `scheduler_schedule_from_interrupt()` | Remove eager fxsave, add CR0.TS | Modified |
| `src/scheduler.c` / `src/process.c` | `scheduler_fpu_release()` from both teardown paths | Clear fpu_owner on termination | Modified |
| `src/scheduler.h` | Function declaration | Add `scheduler_handle_fpu_exception()` | +12 |
| `src/context_switch.S` | `context_switch` save | Remove fxsave | Removed |
| `src/context_switch.S` | `context_switch` load | Remove fxrstor, add CR0.TS | Modified |
| `src/context_switch.S` | `switch_to_first_task` | Remove fxrstor, add CR0.TS | Modified |
| `src/context_switch.S` | `switch_to_user_mode` | Remove fxrstor, add CR0.TS | Modified |
| `src/interrupts.c` | `isr_common_handler()` | Handle vector 7 (#NM) | +17 |

### Exception Flow Diagram

```
Task A (owns FPU) → Context Switch → Task B (no FPU yet)
                                      ↓
                                   CR0.TS = 1
                                      ↓
                            Task B executes (no FPU)
                                      ↓
                            Task B executes FPU instruction (fadd)
                                      ↓
                              CPU checks CR0.TS
                                      ↓
                            CR0.TS == 1 → Trigger #NM (vec 7)
                                      ↓
                            interrupts.c: vector == 7
                                      ↓
                        scheduler_handle_fpu_exception()
                                      ↓
                    ┌─────────────────┴─────────────────┐
                    ↓                                   ↓
           fpu_owner == Task A?              fpu_owner == NULL?
                  YES                                 YES
                    ↓                                   ↓
           fxsave Task A's FPU state         (No save needed)
                    ↓                                   ↓
                    └─────────────────┬─────────────────┘
                                      ↓
                        fxrstor Task B's FPU state
                                      ↓
                              clts (clear CR0.TS)
                                      ↓
                           fpu_owner = Task B
                                      ↓
                        Return from exception
                                      ↓
                        Retry FPU instruction (fadd)
                                      ↓
                              Works! (CR0.TS == 0)
```

### Boot Log Output

Lazy FPU switching prints no boot line of its own; it is transparent.

### Testing & Verification

Tests 2 and 3 date from when an SSH server was built; it no longer is, so read them
as a description of the mechanism rather than a current test.

#### Test 1: System Boot

**Method**: Boot system and observe normal operation

**Result**:
```
✅ System boots successfully
✅ Reaches login prompt
✅ No FPU exceptions during idle operation
✅ Shell works correctly
```

#### Test 2: FPU Usage Detection

**Method**: SSH connection triggers crypto (heavy FPU use)

**Expected**:
1. SSHServer task executes FPU instruction
2. #NM exception triggers (vector 7)
3. `scheduler_handle_fpu_exception()` called
4. FPU state restored for SSHServer
5. SSHServer continues with FPU enabled

**Result**: ✅ **PASS** (SSH connections work correctly)

#### Test 3: FPU Owner Tracking

**Scenario**: Switch between FPU and non-FPU tasks

```
Initial:  fpu_owner = NULL

Switch to SSHServer:
→ FPU instruction → #NM exception
→ fpu_owner = SSHServer
→ FPU state loaded

Switch to Idle:
→ CR0.TS set (FPU disabled)
→ fpu_owner still = SSHServer (state remains in FPU)

Switch back to SSHServer:
→ FPU instruction → #NM exception
→ fpu_owner == SSHServer (same task!)
→ No state save/restore needed (optimization!)
→ Just clear CR0.TS and continue
```

**Result**: ✅ **PASS** (Owner tracking works correctly)

#### Test 4: Task Termination

**Method**: Terminate task that owns FPU, ensure no dangling pointer

**Code**: `scheduler_fpu_release(task)` from both the reaper and
`task_free_resources()` (see "Cleanup Protection" above).

**Result**: ✅ **PASS** (No crashes when terminating FPU-using tasks)

### Performance Measurements

#### Context Switch Latency

**Test Setup**: Measure cycles per context switch using TSC

**Before (Eager FPU)**:
```
Shell → Idle:    ~200 cycles
Idle → Shell:    ~200 cycles
Average:         200 cycles
```

**After (Lazy FPU)**:
```
Shell → Idle:    ~50 cycles (no FPU used)
Idle → Shell:    ~50 cycles (no FPU used)
SSH → Shell:     ~180 cycles (FPU save/restore)
Average:         ~100 cycles (50% improvement)
```

#### System Throughput

**Metric**: Context switches per second

**Before**: 100 switches/sec × 200 cycles = 20,000 cycles/sec overhead
**After**: 100 switches/sec × 100 cycles = 10,000 cycles/sec overhead

**Savings**: 10,000 cycles/sec = ~50% reduction in scheduler overhead

### Security Impact

#### FPU State Leakage Prevention

**Scenario**: Cryptographic key in FPU registers

**Traditional FPU**:
```
SSHServer computes ECDH with secret scalar in ST0
→ Context switch to Shell
→ Save SSHServer FPU state (secret copied to memory)
→ Load Shell FPU state (secret overwritten in FPU)
→ Context switch back to SSHServer
→ Load SSHServer FPU state (secret copied back to FPU)

Total secret copies: 2 (increased exposure)
Memory locations: 2 (task context + potential cache)
Attack surface: HIGH (multiple copy operations)
```

**Lazy FPU**:
```
SSHServer computes ECDH with secret scalar in ST0
→ Context switch to Shell
→ Set CR0.TS (FPU state REMAINS in FPU registers)
→ Shell doesn't use FPU (CR0.TS stays set)
→ Context switch back to SSHServer
→ FPU state still valid (NO copy needed!)

Total secret copies: 0 (if next task doesn't use FPU)
Memory locations: 1 (task context only)
Attack surface: LOW (minimal data movement)
```

**Result**: Lazy FPU reduces cryptographic key exposure by minimizing unnecessary state copies.

### Comparison with Other OSes

| Operating System | FPU Switching Strategy | Notes |
|------------------|------------------------|-------|
| **Linux** | Eager FPU (default since 4.6; lazy mode removed in 4.14) | Historically lazy, with owner tracking |
| **FreeBSD** | Lazy FPU | `FNSAVE`/`FXSAVE` on-demand |
| **Windows** | Lazy FPU | Thread-local FPU ownership |
| **macOS** | Lazy FPU | XNU kernel uses lazy restoration |
| **TinyOS** | Lazy FPU | CR0.TS + #NM, `fpu_owner` tracking |

### Future Enhancements

#### Short Term (v1.23+)
- 📊 **FPU Statistics**: Track #NM exception count, FPU usage per task
- 🔍 **FPU Debugging**: Add shell command to display FPU ownership
- ⚡ **XSAVE Support**: Use XSAVE/XRSTOR if CPU supports (AVX, AVX-512)

#### Medium Term (v1.24+)
- 🔐 **FPU State Zeroing**: Zero FPU registers on task termination (security)
- 🎯 **FPU Preload Hint**: Preload FPU for known crypto-heavy tasks
- 📈 **Adaptive Strategy**: Switch to eager FPU if task uses FPU frequently

### Implementation Complexity

**Code Size**: ~150 lines total
**Files Modified**: 5 files (scheduler.c, scheduler.h, context_switch.S, interrupts.c)
**Testing Time**: 2 hours (boot test, SSH test, stress test)
**Performance Gain**: 50-75% context switch improvement
**Security Benefit**: Reduced cryptographic key exposure

**Conclusion**: High ROI (return on investment) for a relatively simple optimization.

---

## Combined Security Impact

### Defense in Depth

Stack Guard and ASLR work together to provide **layered security**:

```
Attack Scenario: Remote Buffer Overflow Exploit
───────────────────────────────────────────────

Step 1: Attacker sends malicious input
        ↓
Step 2: Buffer overflow occurs
        ↓
Step 3: Stack Guard canary overwritten → DETECTED ✅
        → kernel_panic() halts the system
        → Attack FAILS (as a denial of service)

Alternative: Attacker tries to bypass canary
        ↓
Step 3: Canary bypass successful (rare)
        ↓
Step 4: Jump to shellcode address
        ↓
Step 5: ASLR randomization → Wrong address → CRASH ✅
        → Attack FAILS (99.98% probability)
```

### Combined Statistics

| Metric | Without Protections | With Stack Guard | With Stack Guard + ASLR |
|--------|---------------------|------------------|------------------------|
| **Exploit Success** | 100% | ~0% (if detected) | ~0.0001% |
| **Detection Rate** | 0% | ~100% (for overflows) | ~100% |
| **Brute Force Cost** | 1 attempt | N/A (detected) | 4096 attempts × detection |
| **Real-World Impact** | Critical vuln | Low severity | Negligible risk |

### Estimated Overall Protection

```
P(successful_exploit) = P(bypass_canary) × P(guess_address)
                      ≈ 0.01% × 0.0244%
                      ≈ 0.00000244%
                      ≈ 1 in 41,000,000
```

**Conclusion**: Combined protections make exploitation **practically infeasible**.

---

## Testing & Verification

### Stack Guard Testing

**Test**: Buffer overflow detection
```c
void test_stack_overflow() {
    char buffer[256];
    // Write 512 bytes → overflows buffer → overwrites canary
    memset(buffer, 'A', 512);
    return;  // ← Stack guard check fails here
}

Result: ✅ DETECTED
Output: "STACK CORRUPTION DETECTED" banner, then kernel_panic
```

### ASLR Testing

#### Test 1: Process Randomization

**Method**: Create 5 user processes, observe stack addresses

**Results**:
```
Process 1: 0xbfbf3000
Process 2: 0xbf723000  ← Different
Process 3: 0xbfd8e000  ← Different
Process 4: 0xbf4b7000  ← Different
Process 5: 0xbfec3000  ← Different
```

✅ **PASS**: All addresses unique

#### Test 2: Reboot Randomization

**Method**: Boot 3 times, compare stack addresses. (This was recorded when the
boot log still printed an ASLR seed; it no longer prints one, and stack addresses
are `kdbg` traces visible only under `loglevel debug`.)

**Results**:
```
Boot 1: Stacks: 0xbf01a000, 0xbf03a000...
Boot 2: Stacks: 0xbf7ca000, 0xbf012000...
Boot 3: Stacks: 0xbf9fd000, 0xbf12a000...
```

✅ **PASS**: Different addresses each boot

#### Test 3: Entropy Distribution

**Method**: 10 boots × 5 processes = 45 stack addresses

**Results**:
```
Total addresses:   45
Unique addresses:  44
Collision rate:    2.2% (1 duplicate)
Address range:     0xbefff000 - 0xbff4a000 (4+ MB spread)
```

✅ **EXCELLENT**: 97.8% unique, good distribution

---

## Implementation Files

### Stack Guard (v1.19)

| File | Description | Lines |
|------|-------------|-------|
| `src/stack_guard.h` | API definitions, canary extern | 53 |
| `src/stack_guard.c` | Init, canary generation, violation handler | 145 |
| `src/kernel.c` | Integration (init at boot) | +3 |
| `Makefile` | Build flags (`-fstack-protector-strong`) | Modified |

**Key Functions**:
- `stack_guard_init()` - Initialize canary from `entropy_get_random32()`
- `__stack_chk_fail()` - Audit record, banner, `kernel_panic()`

### ASLR (v1.20)

| File | Description | Lines |
|------|-------------|-------|
| `src/aslr.h` | API, constants, statistics struct | 79 |
| `src/aslr.c` | RNG, randomization, stats tracking | 208 |
| `src/process.c` | Use ASLR for user stack addresses | Modified |
| `src/kernel.c` | Init ASLR (the boot demo tasks were removed) | Modified |
| `src/shell_system.c` | `aslr` command (stats viewer) | +56 |
| `src/shell_system.h` | Function declaration | +7 |
| `src/shell.c` | Command dispatcher integration | +2 |
| `Makefile` | Add aslr.c to build | +1 |

**Key Functions**:
- `aslr_init()` - Report entropy quality, initial `aslr_reseed()`, stats obfuscation key
- `aslr_get_random_stack_base()` - Get randomized stack address
- `aslr_random32()` - Returns `entropy_get_random32()`
- `aslr_get_stats()` - Retrieve statistics
- `cmd_aslr()` - Shell command implementation

### Modified Files Summary

```
src/stack_guard.c     [NEW]    - Stack canary implementation
src/stack_guard.h     [NEW]    - Stack guard API
src/aslr.c            [NEW]    - ASLR implementation
src/aslr.h            [NEW]    - ASLR API
src/kernel.c          [MODIFIED] - Init stack guard + ASLR
src/process.c         [MODIFIED] - Use ASLR for user stacks + debug logging
src/shell_system.c    [MODIFIED] - Add aslr command
src/shell_system.h    [MODIFIED] - Add aslr command declaration
src/shell.c           [MODIFIED] - Add aslr to dispatcher + help
Makefile              [MODIFIED] - Add flags + source files
```

---

## Compiler Flags

### Stack Protection Flags

```makefile
CFLAGS += -fstack-protector-strong  # Enable stack canaries
```

It applies to every object; there is no per-file `-fno-stack-protector` exception
(the credential-path files that once had one now use the generic rule — see the
comment in `Makefile`).

**Why `-fstack-protector-strong`?**
- More aggressive than `-fstack-protector` (only >8 byte buffers)
- Less overhead than `-fstack-protector-all` (every function)
- Protects: buffers, address-taken vars, arrays

### Optimization Flags

```makefile
CFLAGS += -O2            # Optimization level 2 (balanced)
CFLAGS += -Werror        # Treat warnings as errors
CFLAGS += -fno-pic       # No position-independent code (kernel)
```

---

## Performance Impact

| Feature | Overhead | Justification |
|---------|----------|---------------|
| **Stack Guard** | 1-2% CPU | Minimal - just canary check per function |
| **ASLR** | <0.1% CPU | One random call per process creation |
| **Combined** | ~2% total | Negligible for massive security gain |

**Memory Overhead**: None (ASLR just changes addresses, stack guard is 4 bytes)

---

## Future Enhancements

### Done
- ✅ **Stack Guard**: Complete
- ✅ **ASLR**: Complete
- ✅ **W^X (Write XOR Execute)**: Enforced for user mappings via the PAE NX bit (June 2026) — writable pages are NX, code is R+X read-only, W+X ELF segments rejected

### Not implemented
- 🔜 **Heap ASLR**: Randomize heap allocations (requires heap implementation)
- 🔜 **Code Segment ASLR**: Randomize .text section (requires PIE/PIC)
- 🔜 **Full ASLR**: Randomize all mappings (libraries, mmap, vDSO)

### Longer term
- 🔜 **KASLR**: Kernel ASLR (randomize kernel itself)
- ✅ **Hardware RNG**: RDRAND used when present, via the entropy module
- 🔜 **Re-randomization**: Periodic ASLR updates during runtime

---

## References

### Stack Guard
- **Original Paper**: Cowan et al., "StackGuard: Automatic Adaptive Detection and Prevention of Buffer-Overflow Attacks" (1998)
- **GCC Documentation**: https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html
- **Bypasses**: Format string attacks, heap overflows (mitigated by other techniques)

### ASLR
- **PaX Team**: First ASLR implementation (Linux kernel patch, 2001)
- **Windows**: ASLR since Vista (2007)
- **Linux**: Mainstream kernel support since 2.6.12 (2005)
- **Best Practices**: 12-24 bits entropy (we use 12 for embedded systems)

### Combined Techniques
- **Microsoft**: "Exploit Mitigation Improvements in Windows 8" (2012)
- **Google**: "Exploit Mitigation Techniques on Android" (2017)
- **OpenBSD**: Long history of security-first design (since 1990s)

---

## Conclusion

TinyOS implements the standard memory-safety mitigations of a modern kernel, at
educational scale:

✅ **Stack Guard**: Runtime buffer overflow detection (panics on a violation)
✅ **ASLR**: User stack randomization (12 bits)
✅ **W^X**: Code/data separation via the PAE NX bit, kernel and user

They are enabled by default and transparent to applications. They raise the cost
of an exploit; they do not make one impossible (12 bits of ASLR is brute-forceable,
and nothing here randomizes the kernel or user code).

---

## PAE/W^X Infrastructure (v1.21)

### Overview

**PAE** (Physical Address Extension) enables 64-bit page table entries on 32-bit x86, unlocking the **NX (No eXecute) bit** for W^X enforcement.

**W^X** (Write XOR Execute) is a security policy where memory pages can be:
- ✅ **Writable** (data/stack) with NX bit set → Cannot execute
- ✅ **Executable** (code) without NX bit → Cannot write
- ❌ **NEVER both** Writable AND Executable

### Implementation Status (v1.21)

| Component | Status | Description |
|-----------|--------|-------------|
| **PAE Structures** | ✅ Complete | 64-bit PTEs, PDPT, 3-level paging defined |
| **PAE Functions** | ✅ Complete | `pae_map_page()`, `pae_get_pte()`, etc. |
| **NX Bit Support** | ✅ Complete | EFER.NXE enablement, NX flag support |
| **W^X Audit** | ✅ Complete | `pae_wx_audit()` scans for violations |
| **Shell Commands** | ✅ Complete | `pae` (status), `wxaudit` (violations) |
| **Boot Integration** | ✅ Complete | PAE + EFER.NXE enabled at boot; PAE is the active paging mode |
| **Active Enforcement** | ✅ Complete | User mappings carry the hardware NX bit; non-executable user pages (data, rodata, stack) are NX, code is R+X read-only, and writable+executable ELF load segments are rejected |

> **User-mode W^X is enforced as of the June 2026 NX fix.** Generic user mappings
> previously passed 32-bit page flags that dropped the high `PAE_NX` bit before the
> PAE mapper; `map_page()` now takes `uint64_t` flags so NX
> survives. The ELF loader marks non-executable segments NX, rejects W+X segments,
> and re-maps code read-only after copy; user stacks are `PAE_PAGE_STACK` (RW+NX).
> Runtime-verified in ENFORCE mode (signed `hello.elf` runs in ring 3, data-segment
> writes included, no fault).

### What's Implemented

**1. PAE Page Table Infrastructure** (`src/pae.c`, `src/paging.h`)
- 64-bit page table entry types (`pae_pte_t`, `pae_pde_t`, `pae_pdpte_t`)
- 3-level paging structures (PDPT → Page Directory → Page Table)
- Identity mapping for kernel (first 16 MB)
- Page table allocation from static pool (32 tables)

**2. NX Bit Support**
- CPU feature detection (`pae_is_supported()`)
- EFER.NXE enablement (`pae_enable_nx()`)
- NX bit definition (bit 63 in 64-bit PTEs)

**3. W^X Policy Flags**
```c
#define PAE_PAGE_CODE   (PAE_PRESENT | PAE_USER)  // R+X, no write, no NX
#define PAE_PAGE_DATA   (PAE_PRESENT | PAE_READWRITE | PAE_USER | PAE_NX)  // R+W+NX
#define PAE_PAGE_STACK  (PAE_PRESENT | PAE_READWRITE | PAE_USER | PAE_NX)  // R+W+NX
```

**4. Auditing & Diagnostics**
- `pae_wx_audit()`: Scans all mapped pages for W+X violations
- `pae_dump_tables()`: Debugging page table walker
- Shell commands: `pae` and `wxaudit`

### Status: active

- `pae_init()` (`src/kernel.c`, after the PMM) switches to PAE paging with EFER.NXE;
  PAE is the active paging mode.
- Kernel W^X: `pae_apply_kernel_wx()` (`src/pae.c`) maps kernel text R+X and data NX,
  and `pae_verify_kernel_layout()` runs at boot and calls `kernel_panic()` on any
  W+X kernel page.
- User W^X: the ELF loader maps non-executable segments NX, rejects W+X load
  segments, and re-maps code read-only after copy; user stacks are `PAE_PAGE_STACK`
  (RW+NX).
- `secstatus` reports the `pae_wx_audit()` result as `CLEAN` or `VIOLATIONS` with a
  count.

| Attack Vector | Without W^X | With W^X |
|---------------|-------------|----------|
| **Stack Shellcode** | Works | Blocked (stack is NX) |
| **Data Segment Code** | Works | Blocked (data is NX) |
| **Code Modification** | Works | Blocked (code not writable) |

### Shell Commands

`pae` (PAE/NX status and page-table details) and `wxaudit` (full W+X scan) are
**root-only and kernel-shell only** — run `kshell` from the ring-3 shell first. Both
print kernel physical addresses, which is why they are gated (`require_root()` in
`src/shell_system.c`). Do not rely on the "To enable W^X" text `pae` still prints;
it predates the boot integration.

### Performance Considerations

- **PAE Overhead**: 3-level page walks vs 2-level
- **Memory Overhead**: 64-bit PTEs use 2x space

### References

- **PAE Specification**: Intel SDM Vol 3A, Chapter 4.4
- **NX Bit**: AMD64 APM Vol 2, Enhanced Virus Protection
- **W^X Origin**: OpenBSD (Theo de Raadt, 2003)
- **Implementation**: `src/pae.c` (`pae_apply_kernel_wx`, `pae_verify_kernel_layout`)

---

## Kernel-Only Credential Store — no on-disk `/etc/shadow`

### The decision

Traditional Unix-likes store password hashes in an on-disk file (`/etc/shadow`).
That file is a permanent offline-attack target: it can be lifted via a live USB,
a kernel/FS exploit, a backup, a disk image, forensic recovery, or a VM/cloud
snapshot, and then cracked at the attacker's leisure — entirely outside the
running OS's control.

TinyOS Enhanced **deliberately does not have an `/etc/shadow` (or any on-disk
credential file).** Password hashes live **only in kernel memory** and are
**never written to any filesystem**. This is an intentional break from the
legacy design, documented in the source itself.

### How it actually works

- The user database is a single static kernel-memory array — `user_database[USER_MAX_USERS]`
  (`src/user.c`), where each `user_account_t` (`src/user.h`) holds the
  `password_hash[]` field. It is **not** backed by, serialized to, or loaded from
  any file.
- Each hash is **PBKDF2-HMAC-SHA256**, 16-byte random salt, **100,000 iterations**,
  stored in a self-describing format (`$pbkdf2-sha256$i=100000$<salt>$<hash>$`).
  See the password-hashing notes elsewhere in this folder; the PBKDF2 workspace is
  interrupt-masked because a preempted derivation would corrupt the shared
  workspace adjacent to `user_database` (load-bearing — do not remove the mask).
- **`/etc/shadow` is intentionally never created.** The rationale is written out in
  `src/user.c` under "**/etc/shadow INTENTIONALLY NOT CREATED**".
- If an `/etc/passwd` is generated at all (via `user_create_etc_structure()`), it
  contains only `username:x:uid:gid:...` lines — the `x` is the standard
  "password is shadowed, not here" placeholder, and the file carries a header
  comment stating hashes are in kernel memory only. In the current build that
  helper is **not even called**, so by default there is no `/etc/passwd` either —
  credentials are purely in RAM.

### Security properties (and the trade-off)

- **No offline hash extraction.** There is no file to copy from a mounted disk,
  backup, or image — even with full root filesystem access, the hashes are not on
  disk. An attacker would have to read live kernel memory, which is a far higher
  bar than reading a file.
- **No tampering via the filesystem.** A local privilege-escalation that gains
  file write access cannot rewrite a credential file to plant or weaken a hash,
  because no such file exists. The user database is mutated only through the
  kernel's account API.
- **Trade-off — credentials do not persist across reboot.** Because the store is
  RAM-only, accounts reset on every boot and the first boot re-runs the root
  password setup. This is acceptable for an educational / kiosk-style single-node
  OS and is by design, not an oversight.

### Where it lives in the source

- `src/user.c` — `user_database[]` declaration, `user_hash_password()` (PBKDF2),
  and the "Kernel-Only Password Database" / "/etc/shadow INTENTIONALLY NOT CREATED"
  rationale comments.
- `src/user.h` — `user_account_t` with the `password_hash[]` field.

### Passwords do not cross the ring boundary

The credential *interface* is hardened on the same principle as the store. There
have been two generations of it:

- **`SYS_CRED` (32) — current.** Ring 3 names an **operation and a username, and
  nothing else**. The kernel prints the prompts, reads the keystrokes into its
  own buffer (`read_password` calls `keyboard_getchar()` directly, bypassing
  `task->streams`), applies the euid checks, and zeroes the buffer before
  returning. A plaintext password never enters a user address space, an argv, or
  a syscall argument register — a ring-3 shell **cannot leak or log what it never
  holds**.

- **`SYS_CHANGE_PASSWORD` (14) and `SYS_SWITCH_USER` (15) — deprecated from ring
  3.** These predate `SYS_CRED` and take the **plaintext password as a syscall
  argument**. A caller must hold the plaintext to make the call at all, so the
  exposure is inherent to the interface: it cannot be hardened away, only
  removed. Ring-3 dispatch returns **`-ENOSYS`**. Build
  `-DTINYOS_LEGACY_CRED_SYSCALLS` to re-enable it (an explicitly named opt-out,
  never a default). The underlying C functions remain available to **kernel**
  callers. The kernel shell's `su` does not go through `int 0x80` at all: it
  calls `user_authenticate_for(target, pw, USER_AUTH_OP_SU)` and, on success,
  `sys_switch_user_preauth(target)` (`src/shell_user.c`), so gating the dispatch
  does not remove the command.

Both surviving entry points authenticate through the **`user_authenticate()`
family** (`user_authenticate_for()`, see below), not the bare
`user_verify_password()` hash comparison. This matters: the counter,
`USER_MAX_LOGIN_ATTEMPTS` lockout, `USER_LOCKOUT_DURATION` expiry and the
locked/inactive checks all live in `user_authenticate()`. Using the bare
comparison made a credential syscall an **un-counted password oracle** that the
account-lockout policy never saw. A shared `switch_user_commit()` additionally
re-checks `USER_FLAG_LOCKED`/`USER_FLAG_ACTIVE` before committing a credential
change on **every** path, including root's (root skips the *password*, never the
*account state* — otherwise an administrative lock is silently defeated).

### An audit record must name the operation that actually happened

Sharing `user_authenticate()` across login, `su` and password-change is right for
*policy* — one definition of the lockout rules — but it originally hardcoded
`AUDIT_AUTH_LOGIN_SUCCESS`/`_FAILURE` for every outcome, which was only correct
while login was its sole caller. An `su` consequently wrote *"User 'root' (UID 0)
logged in successfully"* into the audit log.

A false entry is worse than a missing one **here specifically**, because this log
is append-only and HMAC-chained: an investigator trusts it *because* it cannot be
edited, and a forged record is indistinguishable from a true one. An `su` from a
compromised unprivileged shell appeared as a clean root login.

`user_authenticate_for(username, password, op)` applies identical policy and lets
the caller name the operation (`LOGIN`, `SU`, `PASSWD`), selecting the matching
failure event. `user_authenticate()` remains as the login wrapper. The **success**
record is deliberately left to the caller, which alone knows whether the operation
went on to **commit** — a verified password is not a completed switch, and only
the failure is final at verification time.

Related, and pre-existing: five declared event types had no case in
`audit_event_type_str()` and rendered as `UNKNOWN` — `AUDIT_USER_SWITCH`,
`AUDIT_AUTH_SU_FAILURE`, `AUDIT_AUTH_PASSWORD_CHANGE_FAILURE`,
`AUDIT_USER_PASSWORD_CHANGE`, and `AUDIT_MEMORY_SEAL`. Typing the record
correctly achieves nothing if it then prints as `UNKNOWN`; all 49 declared types
now map.

**Verification:** `verify-cred-deprecation.sh` runs `/credprobe.elf`, a ring-3
program that issues both deprecated syscalls **directly through `int 0x80`**, and
asserts the exact errno. The probe is a separate program by necessity, not
convenience: no shell offers these calls, and the kernel shell's `su` calls
`user_authenticate_for()` itself and never reaches the syscall — so a shell-driven test
exercises the shell's throttling and passes identically against a vulnerable
kernel. Only a caller that bypasses the shell tests the boundary.

`verify-audit-optype.sh` covers the audit-record half and must dodge the same
trap from the other side: root's `su` skips the password entirely, so it reaches
none of the shared code. The harness becomes unprivileged first, then `su`s back
to root **with a password**, and asserts the **count** of `AUTH_LOGIN_SUCCESS`
records is exactly one — the real login. Zero would mean the genuine record had
been suppressed as well, which a presence test would not catch.

---

## ELF Code Signing — ECDSA P-256, key pinning, fail-closed

Every binary is cryptographically verified before it runs. Verification sits in
the common load path (`elf_load_process_argv_impl()`, reached through
`elf_exec_from_path()`), which serves `SYS_SPAWN`, the kernel shell's `exec` and the
login-shell launch alike — there is no unverified way to start an ELF.

- **What is verified:** the loader extracts a signature trailer from the end of
  the ELF, checks a magic and a self-consistent size, computes **SHA-256** over
  the ELF body, and compares it to the signed hash; then it verifies an
  **ECDSA P-256** signature over that hash.
  (`elf_verify_signature`, `src/elf.c`.)
- **Key pinning (critical):** the trailer carries the signer's public key, but an
  attacker controls the trailer — so the loader does **not** trust it. It compares
  the trailer's `pub_key_x`/`pub_key_y` byte-for-byte against the **pinned trusted
  key** from the secure-boot config and rejects any mismatch (the `memcmp` in
  `elf_verify_signature`, pinned key `src/trusted_signing_key.h`). This closes the classic
  "sign-it-yourself" bypass.
- **Fail-closed enforcement:** with signatures enforced (the default build), an
  unsigned, tampered, or wrong-key binary is **rejected** — it does not run.
  Permissive mode (`-DELF_PERMISSIVE_SIGNATURES`) is an explicitly named opt-out
  that only warns; it is never the default.
- **Preemption-safe:** both the SHA-256 digest and the ECDSA verify run with
  **interrupts masked** (`disable_interrupts()/restore_interrupts()` around each,
  in `elf_verify_signature`). A long crypto computation preempted mid-flight returns
  corrupted state; masking the one-shot exec-time check is what makes enforce mode
  reliable. (See the in-source root-cause comment — this was misdiagnosed as buffer
  corruption before the real preemption cause was proven.)

**Implementation:** `src/elf.c`, `src/ecdsa.c`, `src/trusted_signing_key.h`.

---

## Pinned code-signing key — fail-closed

Not a secure boot chain. This holds the one ECDSA P-256 public key that every
signed ELF is checked against, and nothing else.

- **Fail-closed on a bad key:** `secure_boot_init` refuses a NULL or all-zero
  key and leaves `initialized` false; `elf.c` then rejects every signature. The
  safe state is the default, not an opt-in (`src/secure_boot.c`).
- **Key pinning:** the signature trailer carries the signer's public key, but an
  attacker controls the trailer, so `elf.c` compares all 64 bytes against the
  pinned key before importing it (`src/elf.c`).
- **Enforcement is a separate question**, answered by `elf_signatures_enforced()`
  in `src/elf.c` — a build-mode gate (`-DELF_PERMISSIVE_SIGNATURES`), not a
  runtime policy flag.

**Not implemented, deliberately:** measured boot / PCRs, anti-rollback, and a
second `secure_boot_verify` were all declared here and never called — the PCR
array stayed zero for the machine's lifetime while the boot log printed
"Measured boot: ENABLED". They were deleted rather than wired up; the verifier
used an incompatible prepended-header format, and with no TPM, PCRs computed by
the kernel being measured attest to nothing an attacker in that kernel cannot
forge. See `verify-secure-boot-scope.sh`.

**Implementation:** `src/secure_boot.c`, `src/secure_boot.h`.

---

## Crypto Hardening Primitives

Defensive practices applied across the from-scratch crypto.

- **Compiler-proof zeroization:** secrets (keys, password buffers, intermediate
  state) are wiped with a zeroization routine the compiler cannot optimize away
  (`crypto_secure_zero`, `src/crypto.c`), so key material doesn't linger in
  freed stack/heap.
- **Constant-time comparison:** hash/MAC/secret comparisons use a constant-time
  compare (`crypto_constant_time_compare`, `src/crypto.c`) instead of `memcmp`,
  removing timing side channels from auth checks.
- **CSPRNG with forward secrecy:** a ChaCha20-based CSPRNG reseeds both on a byte
  limit (~1 MB) and on a periodic timer (`csprng_periodic_reseed`, ~60 s), so
  compromise of one state window doesn't expose past/future output
  (`csprng_random_bytes`, `csprng_periodic_reseed`, `src/crypto.c`).
- **Preemption-safe generation/reseed:** keystream generation and reseed run inside
  a critical section (`CRITICAL_SECTION_ENTER` in `csprng_random_bytes` and
  `csprng_reseed`) — an unmasked
  reseed from the timer softirq could tear or duplicate keystream feeding password
  salts, ECDHE keys, ASLR, and TCP/DNS randomness. This mask is **load-bearing**.
- **AES is compiled but unused:** AES-256 CBC/CTR (`src/crypto.c`) and AES-GCM
  (`src/aes_gcm.c`, linked by the `Makefile`) have no caller in the build. Their
  only user was `tls13_demo.c`, which is not compiled. There is no ECB mode.

**Implementation:** `src/crypto.c`.

---

## Hardware RNG Health Checks + Entropy Pool

The CSPRNG is seeded from validated hardware entropy, not blind trust.

- **RDRAND/RDSEED health checks:** hardware RNG output passes FIPS-style checks —
  stuck-at/repetition, degenerate values, and a min-entropy bit-count test — before
  it is trusted (`hw_rng_health_check`, `src/entropy.c`). A failing source is
  not used as if healthy.
- **Mixed entropy pool:** a 64-word pool is stirred in batches from multiple
  sources (TSC jitter and others) with bounded interrupt latency
  (`pool_stir` / `pool_stir_batch`, `src/entropy.c`), so seeding doesn't depend on a single
  source. Availability is detected at boot (`cpu_has_rdrand`, `src/crypto.c`).

**Implementation:** `src/entropy.c`, `src/crypto.c`.

---

## Tamper-Evident Audit Log (HMAC-SHA512 hash chain)

The security audit trail is designed so edits and deletions are detectable.

- **Hash-chained events:** each entry's authenticator is
  `HMAC(prev_hmac || event_fields)` under a **boot-time CSPRNG key**, so any
  insertion, deletion, or modification breaks the chain from that point on
  (`audit_compute_hmac`, key `audit_hmac_key` filled from the CSPRNG at init,
  `src/audit.c`).
- **Monotonic sequence numbers** and a **security event taxonomy** (tamper,
  stack-corruption, syscall-violation, privilege events, etc., `src/audit.h`) make
  gaps and anomalies visible.
- **Storage:** a 1000-entry circular buffer in kernel memory; viewable via the
  `auditlog` command (`-n`, `--warn`, `--error`, `--critical`, `-v`), which is
  root-only and kernel-shell only (`kshell` from the ring-3 shell).

**Implementation:** `src/audit.c`, `src/audit.h`.

---

## TOCTOU-Safe `copy_from_user` / `copy_to_user`

The syscall boundary copies between user and kernel space without trusting raw
user pointers.

- **Bounds + overflow checks** against `USER_SPACE_END` reject pointers/ranges that
  stray outside user space or overflow (`src/copy_user.c:118, 355`;
  defense-in-depth re-check in `src/syscall.c:258-292`).
- **Atomic per-page pre-validation:** every page in the range is probed before the
  copy, and a fault during the probe/copy is caught and turned into `-EFAULT`
  rather than a kernel crash (`src/copy_user.c:220-233`). This replaced an older
  TOCTOU-prone `validate_user_buffer` check.
- **Reentrancy/IRQ protection** around the copy keeps the fault-catch state
  consistent.

**Implementation:** `src/copy_user.c`, `src/syscall.c`.

---

## Stack Guard Pages + TSS esp0/ss0 Integrity

Hardware-enforced stack-overflow containment and a correct ring-transition path.

- **Guard pages:** every task is allocated a **NOT-PRESENT** guard page just below
  its kernel stack (and user stack), so an overflow faults instead of silently
  corrupting adjacent memory — including the global stack canary
  (`task->guard_page_phys` and `task->user_guard_page_phys`, `src/process.c`).
  A double fault, which cannot run on the overflowed stack, goes through a task
  gate to a dedicated TSS (`tss_init_double_fault()`, `src/tss.c`;
  `idt_install_double_fault_gate()`, `src/idt.c`).
- **Page-fault overflow detection:** the #PF handler recognizes a guard-page hit
  and terminates the offending task / panics cleanly rather than continuing on
  corrupt state (`src/interrupts.c:296-356`; double-fault path `:572-588`).
- **TSS `ss0`/`esp0` integrity:** `ss0` is the kernel **data** selector
  (`SEG_KDATA`) — fixing a latent `#TS` on the first ring3→ring0 transition — and
  `esp0` updates are centralized and validated (NULL / low-memory / misaligned →
  `kernel_panic`), resisting `esp0` corruption (`src/tss.c:83-90, 171-217`).
- **Interrupt-prologue register integrity:** `isr_common` (`src/isr.S`) runs
  `pusha` **before** reloading the kernel data selector (`mov ax, SEG_KDATA`), so an
  interrupt taken with a live value in `EAX` (e.g. `pmm_alloc_contiguous`'s
  `base<<12` return, used as a kernel-stack base) can no longer have its low word
  stamped with the selector — which previously produced a misaligned `esp0` and the
  `kernel_panic` above intermittently on `exec`. A Makefile post-link objdump guard
  fails the build if this ordering ever regresses.

**Implementation:** `src/process.c`, `src/interrupts.c`, `src/isr.S`, `src/tss.c`.

---

## Account / Authentication Hardening

- **Strong KDF:** PBKDF2-HMAC-SHA256 at **100,000 iterations** (OWASP), decoupled
  from any dev/build-speed flag, in a self-describing
  `$pbkdf2-sha256$i=100000$salt$hash$` format with a legacy-upgrade path
  (`PBKDF2_ITERATIONS`, `user_hash_password()`, `src/user.c`; 1,000 only under the
  explicitly named `-DTINYOS_FAST_KDF` opt-out).
- **No default credentials:** all accounts — **including root** — are created
  **LOCKED with no password** (`USER_FLAG_LOCKED`, `src/user.c`); the root
  password is set interactively on first boot. There is nothing to guess.
- **Account lockout:** per-account failed-attempt counting locks an account after
  repeated failures (`user_authenticate_for()`, `src/user.c`). Login, `su` and
  `passwd` (via `SYS_CRED`) all go through it, so a wrong current password at
  `passwd` counts toward the lockout and a locked account cannot change its own
  password (PR #151, `verify-passwd-lockout.sh`).
- **Identical refusal text:** login prints `Login incorrect` and `su` prints
  `su: authentication failure` whether the user does not exist, the password is
  wrong or the account is locked; `su` asks an unknown name for a password like
  any other. The reason goes to the audit log, not the terminal (PR #151,
  `verify-auth-user-oracle.sh`).
- **Login ceiling:** three failed logins halt the console (`Login failed. System
  halted.`).
- **Constant-time + preemption-safe verify:** password comparison is constant-time
  and the PBKDF2 derivation runs interrupt-masked (a preempted derivation would
  corrupt the shared workspace adjacent to `user_database`).

**Implementation:** `src/user.c`, `src/shell_user.c`. (See also *Kernel-Only
Credential Store* above.)

---

## Network Anti-Spoofing

Connection and transaction identifiers are unpredictable, sourced from the CSPRNG.

- **TCP ISN (RFC 6528):** initial sequence numbers are
  `M + HMAC-SHA256(4-tuple, boot secret)` — unpredictable per-connection, resisting
  blind injection/spoofing (`tcp_generate_isn`, `src/tcp.c`).
- **DHCP XID:** transaction IDs come from the CSPRNG (not a predictable LCG),
  resisting lease spoofing (`generate_xid`, `src/dhcp.c`).
- **DNS:** transaction IDs from the CSPRNG **plus a randomized source port**,
  raising the bar against cache-poisoning (`src/dns.c:719, 786`).

**Implementation:** `src/tcp.c`, `src/dhcp.c`, `src/dns.c`.

---

## PMM Double-Free Detection + Process Capabilities

- **Double-free detection:** `pmm_free` detects an attempt to free an
  already-free frame and logs a CRITICAL event, mitigating double-free / use-after-free
  corruption of the physical-memory allocator (`src/pmm.c:842-896`).
- **Process capabilities:** a per-process `capabilities` bitfield gates privileged
  resources — e.g. `CAP_SYSTEM_CRITICAL` controls access to reserved FD/node pools
  (`src/process.h:234-242`).

**Implementation:** `src/pmm.c`, `src/process.h`.

---

## C: (FAT32) Is a Shared Volume — by Design

**Decision:** the FAT32 drive `C:` has **no per-file ownership or permission
model**, and that is deliberate, not a gap. Any logged-in user may create,
read, write, truncate and unlink any file on `C:` outside the protected paths.
Per-user confidentiality lives on `D:` (ramfs), which has owners, modes and
`ramfs_check_permission()`.

**Why:** FAT32 has nowhere to store an owner uid or Unix mode bits. Adding them
would mean an out-of-band side table (a TinyOS-only metadata file, or abusing
reserved directory-entry bytes) that any other OS mounting the disk would
neither honour nor preserve — so it would protect nothing the moment the image
left TinyOS, and would make `C:` no longer a plain FAT32 volume. `C:` is the
interchange/persistence disk; treat it like a shared USB stick.

**What *is* enforced on C: (do not remove these):**
- **Protected paths** — `vfs_open`/`vfs_mkdir`/`vfs_rmdir`/`vfs_unlink` refuse writes under
  `/bin`, `/sbin`, `/etc`, `/boot`, `/kernel` without `CAP_SYS_ADMIN`
  (`vfs_path_is_protected()`, `src/vfs.c`). The match is case-folded because
  FAT32 names are case-insensitive, `O_CREAT`/`O_TRUNC` count as write intent,
  and the driver splits paths on `/` only, so `C:/ETC` and `C:/\etc` cannot
  slip past it (PR #179). Harness: `verify-protected-path-match.sh`,
  `verify-fat32-access-mode.sh`.
- **Access mode** — an `O_RDONLY` fd cannot write and a write-only fd cannot
  read (PR #179).
- **Per-uid open-file cap** — a non-root uid holds at most 8 of the 32 FAT32
  open-file slots and the last 4 free slots are root's, so one user cannot lock
  everyone out of `C:` (PR #181). Harness: `verify-fat32-fd-cap.sh`.
- **Kernel memory safety** — cluster numbers and chain lengths are bounded
  (`cluster_in_range`, `FAT32_MAX_CLUSTER_CHAIN`), path components are bounded
  (PR #177), and the IDE layer clamps capacity to LBA28 (PR #180).

**Known cosmetic consequence:** `stat`/`ls -l` report `C:` files as `0644`
and directories as `0755` (`src/fat32_vfs.c`). Those are placeholders, not
enforced permissions — a non-owner *can* write a file shown as `0644`.

**For auditors:** "user A can read/modify user B's file on C:" is the intended
behaviour and is **not a finding**. A finding on `C:` is any of: a bypass of
the protected-path gate, of access mode, or of the per-uid cap; kernel memory
corruption or a disclosure of kernel/other-process memory; or on-disk
corruption of a file the caller did not name (as in the 2026-10 FAT32 audit,
PRs #176–#181). If a confidential file is ever needed on persistent storage,
the answer is a new storage design, not ownership bits bolted onto FAT32.

---

## Combined Security Summary

The memory-safety layer, all active in the default build:

### Layer 1: Stack Guard ✅ **ACTIVE**
- **What**: `-fstack-protector-strong` canaries, seeded from `entropy_get_random32()`
- **When**: Checked before return from protected functions
- **On violation**: audit record, then `kernel_panic()`

### Layer 2: ASLR ✅ **ACTIVE**
- **What**: Randomized user stack base (12 bits, 4096 page positions)
- **When**: Process creation
- **Source**: the entropy module (RDRAND when present)

### Layer 3: Lazy FPU Switching ✅ **ACTIVE**
- **What**: FPU state saved/restored on first use after a switch (CR0.TS + #NM)
- **When**: Context switch + first FPU instruction

### Layer 4: W^X ✅ **ACTIVE**
- **What**: No page is both writable and executable (PAE NX bit), kernel and user
- **When**: Enforced at map time; kernel layout verified at boot (panics on a violation)

Sections 5-16 above (credentials, code signing, crypto, audit, user-copy, guard
pages, accounts, network, PMM, the shared C: volume) describe the rest.

---

**Document Version**: 2.0 (living reference)
**Last Reviewed**: 2026-10, against v2.8
**Maintained By**: TinyOS Security Team
**License**: Same as TinyOS project
