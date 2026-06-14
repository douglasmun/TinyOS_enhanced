/*=============================================================================
 * ide.c - IDE/ATA PIO Mode Driver Implementation
 * Provides basic disk I/O using PIO (Programmed I/O) mode
 *============================================================================*/
#include "ide.h"
#include "kprintf.h"
#include "util.h"
#include "pic.h"       /* For outb/inb inline functions */
#include "critical.h"  /* For atomic LBA register setting */
#include "mutex.h"     /* For IDE mutex protection */
#include "pit.h"       /* For get_timer_ticks() - timer-based timeout */
#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * GLOBAL VARIABLES
 *============================================================================*/
static bool ide_initialized = false;
static uint32_t total_sectors = 0;

/*=============================================================================
 * PRODUCTION FIX: IDE Driver Mutex
 *
 * ISSUE: ide_read_sectors() and ide_write_sectors() access IDE hardware
 * registers without synchronization. Multiple threads can simultaneously:
 * - Set different LBA addresses in IDE registers
 * - Issue conflicting commands
 * - Read/write data from/to different buffers
 * This causes data corruption and wrong sectors being accessed.
 *
 * FIX: Add mutex to serialize all IDE operations. Only one thread can access
 * the IDE controller at a time.
 *===========================================================================*/
static mutex_t ide_mutex;

/*=============================================================================
 * FUNCTION: ide_wait_bsy
 * PURPOSE: Wait for IDE drive to clear BSY flag
 *
 * SECURITY FIX (Issue 8.1): Timer-Based Timeout
 *
 * ISSUE: Previous implementation used CPU cycle counting (uint32_t timeout)
 * which is non-deterministic in preemptive multitasking environments. Under
 * high interrupt load or scheduler jitter, the timeout could expire prematurely
 * causing false I/O errors (DoS attack vector).
 *
 * FIX: Use PIT timer ticks for deterministic timeout measurement. At 100 Hz,
 * 10 ticks = 100ms. This ensures consistent timeout behavior regardless of
 * CPU load or context switches.
 *============================================================================*/
static bool ide_wait_bsy(void) {
    uint32_t start_ticks = pit_get_ticks();
    uint32_t timeout_ticks = 10;  // 100ms at 100 Hz

    while ((pit_get_ticks() - start_ticks) < timeout_ticks) {
        uint8_t status = inb(IDE_PRIMARY_BASE + IDE_REG_STATUS);
        if (!(status & IDE_STATUS_BSY)) {
            return true;  // Not busy anymore
        }

        // Prevent busy-wait monopolizing CPU - small delay between checks
        for (volatile int i = 0; i < 100; i++);
    }

    kprintf("[IDE] ERROR: Timeout waiting for BSY to clear (100ms elapsed)\n");
    return false;
}

/*=============================================================================
 * FUNCTION: ide_wait_drq
 * PURPOSE: Wait for IDE drive to set DRQ flag (data ready)
 *
 * SECURITY FIX (Issue 8.1): Timer-Based Timeout
 *============================================================================*/
static bool ide_wait_drq(void) {
    uint32_t start_ticks = pit_get_ticks();
    uint32_t timeout_ticks = 10;  // 100ms at 100 Hz

    while ((pit_get_ticks() - start_ticks) < timeout_ticks) {
        uint8_t status = inb(IDE_PRIMARY_BASE + IDE_REG_STATUS);
        if (status & IDE_STATUS_DRQ) {
            return true;  // Data ready
        }
        if (status & IDE_STATUS_ERR) {
            kprintf("[IDE] ERROR: Drive error while waiting for DRQ\n");
            return false;
        }

        // Prevent busy-wait monopolizing CPU - small delay between checks
        for (volatile int i = 0; i < 100; i++);
    }

    kprintf("[IDE] ERROR: Timeout waiting for DRQ (100ms elapsed)\n");
    return false;
}

/*=============================================================================
 * PRODUCTION FIX: Granular IDE Error Decoding
 *
 * ISSUE: Generic error returns don't provide diagnostic information.
 *
 * FIX: Read IDE Error Register and Status Register to determine the precise
 * cause of failure. This enables proper error handling and logging at higher
 * layers (VFS, filesystem drivers).
 *
 * CRITICAL: Only call this AFTER detecting an error condition (STATUS_ERR bit
 * set or STATUS_DF bit set). The Error Register is only valid when STATUS_ERR
 * is set.
 *============================================================================*/
static int ide_decode_error(const char* operation) {
    uint8_t status = inb(IDE_PRIMARY_BASE + IDE_REG_STATUS);

    // Check for drive fault first (catastrophic hardware failure)
    if (status & IDE_STATUS_DF) {
        kprintf("[IDE] CRITICAL: Drive fault during %s (hardware failure)\n", operation);
        return IDE_E_DRIVE_FAULT;
    }

    // If error bit not set, this is a timeout
    if (!(status & IDE_STATUS_ERR)) {
        kprintf("[IDE] ERROR: Timeout during %s (drive not responding)\n", operation);
        return IDE_E_TIMEOUT;
    }

    // Read Error Register to get specific failure cause
    uint8_t error = inb(IDE_PRIMARY_BASE + IDE_REG_ERROR);

    // Prioritize most critical errors first
    if (error & IDE_ERR_UNC) {
        kprintf("[IDE] ERROR: Uncorrectable data error during %s (bad sector)\n", operation);
        return IDE_E_UNCORRECTABLE;
    }

    if (error & IDE_ERR_BBK) {
        kprintf("[IDE] ERROR: Bad block detected during %s (media defect)\n", operation);
        return IDE_E_BAD_BLOCK;
    }

    if (error & IDE_ERR_IDNF) {
        kprintf("[IDE] ERROR: Sector ID not found during %s (invalid LBA?)\n", operation);
        return IDE_E_ID_NOT_FOUND;
    }

    if (error & IDE_ERR_ABRT) {
        kprintf("[IDE] ERROR: Command aborted during %s (unsupported/invalid)\n", operation);
        return IDE_E_ABORTED;
    }

    if (error & IDE_ERR_AMNF) {
        kprintf("[IDE] ERROR: Address mark not found during %s (alignment issue)\n", operation);
        return IDE_E_ADDR_MARK;
    }

    if (error & (IDE_ERR_MC | IDE_ERR_MCR)) {
        kprintf("[IDE] ERROR: Media changed during %s (disk removed?)\n", operation);
        return IDE_E_MEDIA_CHANGED;
    }

    // Unknown error (should never happen)
    kprintf("[IDE] ERROR: Unknown error during %s (status=0x%02X, error=0x%02X)\n",
            operation, status, error);
    return IDE_E_GENERIC;
}

/*=============================================================================
 * PRODUCTION FIX: Atomic LBA Register Setting
 *
 * ISSUE: Setting LBA registers with multiple outb() calls creates a TOCTOU
 * vulnerability. If an interrupt occurs between register writes, the drive
 * sees an inconsistent LBA address, potentially causing:
 * - Reading/writing wrong sectors (data corruption)
 * - Drive confusion leading to timeout or abort
 * - Security issue if wrong data is accessed
 *
 * EXAMPLE FAILURE SCENARIO:
 *   Thread wants to read LBA 0x12345678
 *   outb(LBA_LOW, 0x78);       // LBA = 0x??????78
 *   <INTERRUPT OCCURS>          // Timer fires, context switch
 *   <Other thread modifies drive state>
 *   outb(LBA_MID, 0x56);       // LBA = 0x????5678 (but drive may have moved)
 *   outb(LBA_HIGH, 0x34);      // LBA = 0x??345678
 *   outb(DRIVE, 0xE0 | 0x12);  // LBA = 0x12345678 (finally consistent)
 *
 * FIX: Disable interrupts during the entire LBA+sector+drive register sequence.
 * This ensures atomicity - all registers are set as a single indivisible operation.
 *
 * NOTE: We use disable_interrupts/restore_interrupts rather than critical
 * sections because this is a localized atomic operation, not a complex
 * nested critical section.
 *===========================================================================*/
static inline void ide_set_lba_atomic(uint32_t lba, uint8_t sector_count) {
    uint32_t flags = disable_interrupts();  // Save EFLAGS and disable interrupts

    // Atomically set all drive parameters
    // These 4 register writes MUST NOT be interrupted
    outb(IDE_PRIMARY_BASE + IDE_REG_DRIVE, IDE_DRIVE_MASTER | ((lba >> 24) & 0x0F));
    outb(IDE_PRIMARY_BASE + IDE_REG_SECTOR_CNT, sector_count);
    outb(IDE_PRIMARY_BASE + IDE_REG_LBA_LOW,  (uint8_t)(lba & 0xFF));
    outb(IDE_PRIMARY_BASE + IDE_REG_LBA_MID,  (uint8_t)((lba >> 8) & 0xFF));
    outb(IDE_PRIMARY_BASE + IDE_REG_LBA_HIGH, (uint8_t)((lba >> 16) & 0xFF));

    restore_interrupts(flags);  // Restore previous interrupt state
}

/*=============================================================================
 * FUNCTION: ide_identify
 * PURPOSE: Identify IDE drive and get capacity
 *============================================================================*/
bool ide_identify(void) {
    uint16_t identify_data[256];

    // Select master drive
    outb(IDE_PRIMARY_BASE + IDE_REG_DRIVE, IDE_DRIVE_MASTER);

    // Small delay after selecting drive
    for (volatile int i = 0; i < 1000; i++);

    // Check if drive exists (status = 0xFF means no drive)
    uint8_t status = inb(IDE_PRIMARY_BASE + IDE_REG_STATUS);
    if (status == 0xFF) {
        kprintf("[IDE] WARNING: No drive detected (status=0xFF)\n");
        return false;
    }

    // Wait for drive to be ready
    if (!ide_wait_bsy()) {
        return false;
    }

    // Send IDENTIFY command
    outb(IDE_PRIMARY_BASE + IDE_REG_COMMAND, IDE_CMD_IDENTIFY);

    // Small delay after command
    for (volatile int i = 0; i < 1000; i++);

    // Wait for data to be ready
    if (!ide_wait_drq()) {
        return false;
    }

    // Read 256 words (512 bytes) of identify data
    for (int i = 0; i < 256; i++) {
        identify_data[i] = inw(IDE_PRIMARY_BASE + IDE_REG_DATA);
    }

    // Get total sectors from identify data
    // Try LBA28 first (words 60-61) - 28-bit LBA sector count
    total_sectors = (uint32_t)identify_data[60] | ((uint32_t)identify_data[61] << 16);

    // If LBA28 is 0 or maxed out, try LBA48 (words 100-103)
    if (total_sectors == 0 || total_sectors == 0x0FFFFFFF) {
        // Check if LBA48 is supported (bit 10 of word 83)
        if (identify_data[83] & (1 << 10)) {
            // Read LBA48 capacity from words 100-103 (only use lower 32 bits)
            total_sectors = (uint32_t)identify_data[100] | ((uint32_t)identify_data[101] << 16);
        }
    }

    uint32_t size_mb = (total_sectors * IDE_SECTOR_SIZE) / (1024 * 1024);
    kprintf("[IDE] Disk capacity: %u MB (%u sectors)\n", size_mb, total_sectors);

    return true;
}

/*=============================================================================
 * FUNCTION: ide_init
 * PURPOSE: Initialize IDE driver
 *============================================================================*/
void ide_init(void) {
    kprintf("[IDE] Initializing IDE/ATA driver...\n");

    // Initialize IDE mutex for serializing disk operations
    mutex_init(&ide_mutex, "ide_driver", 0);

    // Reset the IDE controller (software reset)
    outb(IDE_PRIMARY_CTRL, 0x04);  // Set reset bit
    outb(IDE_PRIMARY_CTRL, 0x00);  // Clear reset bit

    // Wait a bit for reset to complete
    for (volatile int i = 0; i < 10000; i++);

    // Identify the drive
    if (!ide_identify()) {
        kprintf("[IDE] WARNING: No IDE drive detected or identify failed\n");
        kprintf("[IDE] Continuing without disk support\n");
        ide_initialized = false;
        return;
    }

    ide_initialized = true;
    kprintf("[IDE] Initialization complete [OK]\n");
}

/*=============================================================================
 * FUNCTION: ide_read_sectors
 * PURPOSE: Read sectors from disk using LBA28
 * RETURNS: 0 on success, -1 on error
 *============================================================================*/
int ide_read_sectors(uint32_t lba, uint8_t sector_count, void* buffer) {
    if (!ide_initialized) {
        kprintf("[IDE] ERROR: IDE not initialized\n");
        return IDE_E_GENERIC;
    }

    // kprintf("[IDE_DEBUG] === ide_read_sectors: lba=%u, count=%u, buf=%p ===\n", lba, (unsigned)sector_count, buffer);

    // Overflow-safe bounds check (lba + sector_count could wrap uint32_t);
    // sector_count == 0 is rejected (ATA treats it as 256 sectors)
    if (sector_count == 0 || lba > total_sectors || sector_count > total_sectors - lba) {
        kprintf("[IDE] ERROR: Read beyond disk capacity (LBA %u + %u)\n", lba, sector_count);
        return IDE_E_GENERIC;
    }

    mutex_lock(&ide_mutex);

    uint16_t* buf = (uint16_t*)buffer;

    // Wait for drive to be ready
    if (!ide_wait_bsy()) {
        int error = ide_decode_error("READ wait BSY");
        mutex_unlock(&ide_mutex);
        return error;
    }

    /*=========================================================================
     * PRODUCTION FIX: Use atomic LBA setting to prevent TOCTOU vulnerability
     * All drive/sector/LBA registers are set with interrupts disabled
     *=======================================================================*/
    ide_set_lba_atomic(lba, sector_count);

    // Send READ command
    outb(IDE_PRIMARY_BASE + IDE_REG_COMMAND, IDE_CMD_READ_PIO);

    // Read each sector
    // kprintf("[IDE_DEBUG] Starting sector read loop, sector_count=%u\n", (unsigned)sector_count);
    for (uint8_t i = 0; i < sector_count; i++) {
        // kprintf("[IDE_DEBUG] Reading sector %u/%u, writing to buf+%u\n",
        //         (unsigned)i, (unsigned)sector_count, (unsigned)(i * 256));

        // Wait for data to be ready
        if (!ide_wait_drq()) {
            int error = ide_decode_error("READ wait DRQ");
            mutex_unlock(&ide_mutex);
            return error;
        }

        // Read 256 words (512 bytes) per sector
        for (int j = 0; j < 256; j++) {
            buf[i * 256 + j] = inw(IDE_PRIMARY_BASE + IDE_REG_DATA);
        }

        // kprintf("[IDE_DEBUG] Sector %u read complete\n", (unsigned)i);
    }

    // kprintf("[IDE_DEBUG] ALL sectors read complete, total=%u\n", (unsigned)sector_count);
    mutex_unlock(&ide_mutex);
    return IDE_SUCCESS;
}

/*=============================================================================
 * FUNCTION: ide_write_sectors
 * PURPOSE: Write sectors to disk using LBA28
 * RETURNS: 0 on success, -1 on error
 *============================================================================*/
int ide_write_sectors(uint32_t lba, uint8_t sector_count, const void* buffer) {
    if (!ide_initialized) {
        kprintf("[IDE] ERROR: IDE not initialized\n");
        return IDE_E_GENERIC;
    }

    // Overflow-safe bounds check (lba + sector_count could wrap uint32_t);
    // sector_count == 0 is rejected (ATA treats it as 256 sectors)
    if (sector_count == 0 || lba > total_sectors || sector_count > total_sectors - lba) {
        kprintf("[IDE] ERROR: Write beyond disk capacity (LBA %u + %u)\n", lba, sector_count);
        return IDE_E_GENERIC;
    }

    mutex_lock(&ide_mutex);

    const uint16_t* buf = (const uint16_t*)buffer;

    // Wait for drive to be ready
    if (!ide_wait_bsy()) {
        int error = ide_decode_error("WRITE wait BSY");
        mutex_unlock(&ide_mutex);
        return error;
    }

    /*=========================================================================
     * PRODUCTION FIX: Use atomic LBA setting to prevent TOCTOU vulnerability
     * All drive/sector/LBA registers are set with interrupts disabled
     *=======================================================================*/
    ide_set_lba_atomic(lba, sector_count);

    // Send WRITE command
    outb(IDE_PRIMARY_BASE + IDE_REG_COMMAND, IDE_CMD_WRITE_PIO);

    // Write each sector
    for (uint8_t i = 0; i < sector_count; i++) {
        // Wait for data request
        if (!ide_wait_drq()) {
            int error = ide_decode_error("WRITE wait DRQ");
            mutex_unlock(&ide_mutex);
            return error;
        }

        // Write 256 words (512 bytes) per sector
        for (int j = 0; j < 256; j++) {
            outw(IDE_PRIMARY_BASE + IDE_REG_DATA, buf[i * 256 + j]);
        }
    }

    // Wait for write to complete
    if (!ide_wait_bsy()) {
        int error = ide_decode_error("WRITE completion");
        mutex_unlock(&ide_mutex);
        return error;
    }

    // Flush cache (optional, but good practice)
    outb(IDE_PRIMARY_BASE + IDE_REG_COMMAND, 0xE7);  // FLUSH CACHE command
    ide_wait_bsy();

    mutex_unlock(&ide_mutex);
    return IDE_SUCCESS;
}

/*=============================================================================
 * FUNCTION: ide_get_sector_count
 * PURPOSE: Get total number of sectors on disk
 *============================================================================*/
uint32_t ide_get_sector_count(void) {
    return total_sectors;
}
