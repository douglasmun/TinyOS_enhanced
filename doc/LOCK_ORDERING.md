# TinyOS Lock Ordering Policy

**Version**: 1.0
**Date**: 2025-01-18
**Purpose**: Prevent deadlocks through strict lock acquisition hierarchy
**Status**: ✅ Production Policy

---

## Executive Summary

This document defines the **global lock ordering hierarchy** for TinyOS to prevent deadlocks. All kernel code **MUST** acquire locks in the order specified below, from highest level (lowest number) to lowest level (highest number).

**CRITICAL RULE**: Once a lower-level lock is held, **NEVER** attempt to acquire a higher-level lock. This would create a circular dependency and cause deadlock.

---

## Lock Hierarchy Levels

```
┌──────────────────────────────────────────────────────────────────┐
│ Level 0: INTERRUPT DISABLE (cli/sti)                            │
│ └─ Highest priority - disables ALL concurrency                  │
├──────────────────────────────────────────────────────────────────┤
│ Level 1: SCHEDULER & TASK MANAGEMENT                            │
│ └─ scheduler.c: Global scheduler lock (future implementation)   │
├──────────────────────────────────────────────────────────────────┤
│ Level 2: MEMORY MANAGEMENT                                      │
│ └─ pmm.c: Physical Memory Manager lock (pmm_mutex)              │
│ └─ paging.c: Page table locks (future implementation)           │
├──────────────────────────────────────────────────────────────────┤
│ Level 3: VFS GLOBAL LAYER                                       │
│ └─ vfs.c: Global VFS FD table lock (vfs_global_lock)            │
├──────────────────────────────────────────────────────────────────┤
│ Level 4: FILESYSTEM DRIVERS                                     │
│ ├─ ramfs.c: RAMFS global lock (ramfs_mutex)                     │
│ └─ fat32.c: FAT32 global lock (fat32_mutex)                     │
├──────────────────────────────────────────────────────────────────┤
│ Level 5: DEVICE DRIVERS                                         │
│ ├─ ide.c: IDE/ATA controller lock (ide_mutex)                   │
│ ├─ e1000.c: Network device locks (tx_mutex, rx_mutex)           │
│ └─ keyboard.c: Keyboard buffer lock (future implementation)     │
└──────────────────────────────────────────────────────────────────┘
```

---

## Level Descriptions

### Level 0: Interrupt Disable
- **Mechanism**: `cli` (disable interrupts) / `sti` (enable interrupts)
- **Scope**: Entire CPU core - prevents ALL concurrency
- **Use Case**: Atomic register access (e.g., `ide_set_lba_atomic`)
- **Duration**: MUST be extremely short (< 100 CPU cycles)
- **Rule**: NEVER call blocking functions with interrupts disabled

### Level 1: Scheduler & Task Management
- **Lock**: Global scheduler lock (not yet implemented)
- **Purpose**: Protects ready queue, task state transitions
- **Held During**: `task_create`, `task_terminate`, `scheduler_add_task`
- **Critical Path**: Context switch code runs with this lock held

### Level 2: Memory Management
- **Lock**: `pmm_mutex` (Physical Memory Manager)
- **Purpose**: Protects frame bitmap, allocation/deallocation
- **Held During**: `pmm_alloc`, `pmm_free`, page table operations
- **Why Level 2**: Scheduler may allocate memory for new tasks

### Level 3: VFS Global Layer
- **Lock**: `vfs_global_lock` (VFS FD table)
- **Purpose**: Protects global file descriptor table
- **Held During**: `vfs_open`, `vfs_close`, FD allocation
- **Why Level 3**: VFS may allocate memory (buffers, structures)

### Level 4: Filesystem Drivers
- **Locks**: `ramfs_mutex`, `fat32_mutex`
- **Purpose**: Protects filesystem-specific data structures
- **Held During**: File operations (read, write, create, unlink)
- **Why Level 4**: Filesystems call VFS functions (which hold Level 3 locks)

### Level 5: Device Drivers
- **Locks**: `ide_mutex`, `e1000_tx_mutex`, `e1000_rx_mutex`
- **Purpose**: Protects hardware register access and DMA buffers
- **Held During**: Device I/O operations
- **Why Level 5 (Lowest)**: Called by filesystems (FAT32 → IDE)

---

## Deadlock Prevention Examples

### ❌ DEADLOCK SCENARIO (DO NOT DO THIS)

```c
/* WRONG: Thread A acquires locks in order: FAT32 → IDE */
void thread_a_copy_from_fat32_to_ramfs(void) {
    mutex_lock(&fat32_mutex);      // Level 4: FAT32
    // ... read from FAT32 ...
    mutex_lock(&ide_mutex);        // Level 5: IDE (OK - lower level)
    ide_read_sectors(...);
    mutex_unlock(&ide_mutex);

    mutex_lock(&ramfs_mutex);      // Level 4: RAMFS (OK - same level)
    ramfs_write(...);
    mutex_unlock(&ramfs_mutex);
    mutex_unlock(&fat32_mutex);
}

/* WRONG: Thread B acquires locks in order: RAMFS → FAT32 */
void thread_b_copy_from_ramfs_to_fat32(void) {
    mutex_lock(&ramfs_mutex);      // Level 4: RAMFS
    // ... read from RAMFS ...

    mutex_lock(&fat32_mutex);      // Level 4: FAT32 (OK - same level)
    fat32_write(...);
    mutex_lock(&ide_mutex);        // Level 5: IDE (OK - lower level)
    ide_write_sectors(...);
    mutex_unlock(&ide_mutex);
    mutex_unlock(&fat32_mutex);
    mutex_unlock(&ramfs_mutex);
}

/* RESULT: Potential deadlock!
   - Thread A holds fat32_mutex, waiting for ramfs_mutex
   - Thread B holds ramfs_mutex, waiting for fat32_mutex
   - CIRCULAR WAIT → DEADLOCK
*/
```

### ✅ CORRECT SOLUTION (ALWAYS DO THIS)

```c
/* Rule: Acquire both Level 4 locks in ALPHABETICAL ORDER */
void copy_between_filesystems(const char* src_fs, const char* dst_fs) {
    // ALWAYS acquire in consistent order: fat32 before ramfs (alphabetically)
    mutex_lock(&fat32_mutex);      // Level 4a (alphabetically first)
    mutex_lock(&ramfs_mutex);      // Level 4b (alphabetically second)

    // Perform copy operation
    // ...

    // Release in REVERSE order (ramfs before fat32)
    mutex_unlock(&ramfs_mutex);
    mutex_unlock(&fat32_mutex);
}

/* RESULT: No deadlock possible!
   - All threads acquire Level 4 locks in same order
   - No circular wait condition can occur
*/
```

---

## Same-Level Lock Ordering

When acquiring **multiple locks at the same level** (e.g., both `fat32_mutex` and `ramfs_mutex` are Level 4), use **alphabetical ordering** as a tiebreaker:

```c
Level 4 Alphabetical Order:
  1. e1000_rx_mutex    (if at Level 4)
  2. e1000_tx_mutex    (if at Level 4)
  3. fat32_mutex       ← Acquire first
  4. ramfs_mutex       ← Acquire second
```

**Example**:
```c
void safe_multi_filesystem_operation(void) {
    // CORRECT: Alphabetical order
    mutex_lock(&fat32_mutex);   // "fat32" comes before "ramfs"
    mutex_lock(&ramfs_mutex);

    // ... do work ...

    // Release in reverse order
    mutex_unlock(&ramfs_mutex);
    mutex_unlock(&fat32_mutex);
}
```

---

## Lock Hold Duration Limits

To prevent starvation and ensure system responsiveness:

```c
Level 0 (cli/sti):        < 100 CPU cycles     (~0.1 µs @ 1 GHz)
Level 1 (Scheduler):      < 10 µs              (critical path)
Level 2 (Memory):         < 50 µs              (allocation may scan bitmap)
Level 3 (VFS):            < 100 µs             (FD table lookup)
Level 4 (Filesystem):     < 1 ms               (disk I/O is blocking)
Level 5 (Device):         < 10 ms              (hardware operations)
```

**Rule**: If an operation will take longer than the hold duration limit, **release the lock** and **reacquire it later**.

---

## Lock Validation (Future Implementation)

### Runtime Validation
Add lock-order assertions in `mutex_lock`:

```c
void mutex_lock(mutex_t* mutex) {
    // Check if current task holds any higher-level locks
    task_t* current = task_current();

    for (int i = 0; i < mutex->level; i++) {
        if (current->held_locks_bitmap & (1 << i)) {
            kernel_panic("Lock ordering violation: "
                         "holding level %d lock while acquiring level %d",
                         i, mutex->level);
        }
    }

    // ... actual lock acquisition ...

    current->held_locks_bitmap |= (1 << mutex->level);
}
```

### Compile-Time Validation
Use static analysis tools (Coverity, Clang Static Analyzer) with custom rules:

```bash
# Example: Check for lock ordering violations
clang-tidy src/*.c --checks='concurrency-*' --config='{
  CheckOptions: [
    {key: concurrency.LockHierarchy, value: "scheduler:1,pmm:2,vfs:3,fat32:4,ramfs:4,ide:5"}
  ]
}'
```

---

## Current Lock Inventory

| Lock Name          | Level | File           | Protects                          |
|--------------------|-------|----------------|-----------------------------------|
| `pmm_mutex`        | 2     | pmm.c          | Frame bitmap, allocation state    |
| `vfs_global_lock`  | 3     | vfs.c          | Global FD table                   |
| `ramfs_mutex`      | 4     | ramfs.c        | RAMFS node tree, directory list   |
| `fat32_mutex`      | 4     | fat32.c        | FAT32 buffers, open files         |
| `ide_mutex`        | 5     | ide.c          | IDE controller registers          |
| `e1000_tx_mutex`   | 5     | e1000.c        | TX ring buffer                    |
| `e1000_rx_mutex`   | 5     | e1000.c        | RX ring buffer                    |

---

## Code Review Checklist

When reviewing code that uses locks, verify:

- [ ] Locks acquired in correct hierarchy order (Level 1 → 2 → 3 → 4 → 5)
- [ ] Same-level locks acquired in alphabetical order
- [ ] Locks released in reverse order (LIFO pattern)
- [ ] No lock held across blocking operations (sleep, I/O wait)
- [ ] Lock hold duration < specified limit for that level
- [ ] Error paths properly release all held locks
- [ ] No recursive locking (acquire same lock twice)

---

## References

- Linux Kernel Lock Ordering: https://www.kernel.org/doc/html/latest/locking/lockdep-design.html
- Windows NT Lock Hierarchy: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irql
- "The Art of Multiprocessor Programming" by Herlihy & Shavit (Chapter 10: Spin Locks and Contention)

---

## Version History

| Version | Date       | Changes                                    |
|---------|------------|--------------------------------------------|
| 1.0     | 2025-01-18 | Initial lock hierarchy documentation      |
