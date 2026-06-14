/*=============================================================================
 * ide.h - IDE/ATA PIO Mode Driver Header
 * Simple driver for reading/writing disk sectors via PIO mode
 *============================================================================*/
#ifndef IDE_H
#define IDE_H

#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * IDE REGISTER DEFINITIONS
 *============================================================================*/
// Primary IDE bus I/O ports
#define IDE_PRIMARY_BASE    0x1F0
#define IDE_PRIMARY_CTRL    0x3F6

// IDE registers (offsets from base)
#define IDE_REG_DATA        0x00  // Data register (16-bit)
#define IDE_REG_ERROR       0x01  // Error register (read)
#define IDE_REG_FEATURES    0x01  // Features register (write)
#define IDE_REG_SECTOR_CNT  0x02  // Sector count
#define IDE_REG_LBA_LOW     0x03  // LBA bits 0-7
#define IDE_REG_LBA_MID     0x04  // LBA bits 8-15
#define IDE_REG_LBA_HIGH    0x05  // LBA bits 16-23
#define IDE_REG_DRIVE       0x06  // Drive/head register
#define IDE_REG_STATUS      0x07  // Status register (read)
#define IDE_REG_COMMAND     0x07  // Command register (write)

// Status register bits
#define IDE_STATUS_ERR      0x01  // Error
#define IDE_STATUS_DRQ      0x08  // Data request ready
#define IDE_STATUS_SRV      0x10  // Service request
#define IDE_STATUS_DF       0x20  // Drive fault
#define IDE_STATUS_RDY      0x40  // Drive ready
#define IDE_STATUS_BSY      0x80  // Busy

/*=============================================================================
 * PRODUCTION FIX: Granular IDE Error Codes
 *
 * ISSUE: Generic -1 return value does not distinguish between different
 * hardware failure modes (CRC error vs uncorrectable data vs timeout).
 * This prevents proper error handling and logging at higher layers.
 *
 * FIX: Define granular error codes mapped to ATA Error Register bits.
 * These enable precise diagnosis of IDE failures for filesystem and
 * logging subsystems.
 *
 * Error Register Bits (ATA Specification):
 * - Bit 0: AMNF - Address Mark Not Found
 * - Bit 1: TK0NF - Track 0 Not Found
 * - Bit 2: ABRT - Aborted Command
 * - Bit 3: MCR - Media Change Request
 * - Bit 4: IDNF - ID Not Found
 * - Bit 5: MC - Media Changed
 * - Bit 6: UNC - Uncorrectable Data Error
 * - Bit 7: BBK - Bad Block Detected
 *===========================================================================*/

// IDE Error Register bits (read from IDE_REG_ERROR after status ERR bit set)
#define IDE_ERR_AMNF        0x01  // Address Mark Not Found
#define IDE_ERR_TK0NF       0x02  // Track 0 Not Found
#define IDE_ERR_ABRT        0x04  // Aborted Command
#define IDE_ERR_MCR         0x08  // Media Change Request
#define IDE_ERR_IDNF        0x10  // ID Not Found
#define IDE_ERR_MC          0x20  // Media Changed
#define IDE_ERR_UNC         0x40  // Uncorrectable Data Error
#define IDE_ERR_BBK         0x80  // Bad Block Detected

// Granular error codes for ide_read_sectors() and ide_write_sectors()
#define IDE_SUCCESS         0     // Operation successful
#define IDE_E_TIMEOUT       -1    // Drive did not respond (BSY/DRQ timeout)
#define IDE_E_DRIVE_FAULT   -2    // Drive fault (STATUS_DF bit set)
#define IDE_E_UNCORRECTABLE -3    // Uncorrectable data error (ERR_UNC)
#define IDE_E_BAD_BLOCK     -4    // Bad block detected (ERR_BBK)
#define IDE_E_ID_NOT_FOUND  -5    // Sector ID not found (ERR_IDNF)
#define IDE_E_ABORTED       -6    // Command aborted by drive (ERR_ABRT)
#define IDE_E_ADDR_MARK     -7    // Address mark not found (ERR_AMNF)
#define IDE_E_MEDIA_CHANGED -8    // Media was changed (ERR_MC/MCR)
#define IDE_E_GENERIC       -9    // Generic error (unknown cause)

// IDE commands
#define IDE_CMD_READ_PIO    0x20  // Read sectors with retry
#define IDE_CMD_WRITE_PIO   0x30  // Write sectors with retry
#define IDE_CMD_IDENTIFY    0xEC  // Identify device

// Drive selection
#define IDE_DRIVE_MASTER    0xE0  // Master drive, LBA mode
#define IDE_DRIVE_SLAVE     0xF0  // Slave drive, LBA mode

// Sector size
#define IDE_SECTOR_SIZE     512

/*=============================================================================
 * FUNCTION PROTOTYPES
 *============================================================================*/
void ide_init(void);
bool ide_identify(void);
int ide_read_sectors(uint32_t lba, uint8_t sector_count, void* buffer);
int ide_write_sectors(uint32_t lba, uint8_t sector_count, const void* buffer);
uint32_t ide_get_sector_count(void);

#endif // IDE_H
