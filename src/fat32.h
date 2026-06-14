/*=============================================================================
 * fat32.h - FAT32 Filesystem Driver Header
 * Implements FAT32 filesystem for persistent storage
 *============================================================================*/
#ifndef FAT32_H
#define FAT32_H

#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * FAT32 CONSTANTS
 *============================================================================*/
#define FAT32_MAX_PATH          256
#define FAT32_MAX_OPEN_FILES    32
#define FAT32_SECTOR_SIZE       512
#define FAT32_DIR_ENTRY_SIZE    32

/*=============================================================================
 * SECURITY FIX (Issue 5.2): FAT32 Infinite Loop DoS Protection
 *
 * VULNERABILITY: A corrupted or malicious FAT32 filesystem could contain
 * cyclic cluster chains (e.g., cluster 100 → 101 → 102 → 100), causing
 * the kernel to loop forever, resulting in a Denial of Service.
 *
 * MITIGATION: Limit cluster chain traversal to a maximum number of iterations.
 * The limit should be:
 * - At least the total number of clusters in the filesystem (for valid chains)
 * - Bounded to prevent excessive loops (2 million iterations = ~1GB file at 512 bytes/cluster)
 *
 * If a chain exceeds this limit, it indicates corruption and we return -EIO.
 *============================================================================*/
#define FAT32_MAX_CLUSTER_CHAIN 2000000  // Maximum clusters to traverse before detecting cycle

// FAT entry values
#define FAT32_FREE              0x00000000
#define FAT32_EOC               0x0FFFFFF8  // End of cluster chain
#define FAT32_BAD_CLUSTER       0x0FFFFFF7

// File attributes
#define FAT32_ATTR_READ_ONLY    0x01
#define FAT32_ATTR_HIDDEN       0x02
#define FAT32_ATTR_SYSTEM       0x04
#define FAT32_ATTR_VOLUME_ID    0x08
#define FAT32_ATTR_DIRECTORY    0x10
#define FAT32_ATTR_ARCHIVE      0x20
#define FAT32_ATTR_LONG_NAME    0x0F

/*=============================================================================
 * FAT32 BOOT SECTOR STRUCTURE
 *============================================================================*/
typedef struct {
    uint8_t  jump_boot[3];
    uint8_t  oem_name[8];
    uint16_t bytes_per_sector;
    uint8_t  sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t  num_fats;
    uint16_t root_entry_count;      // Must be 0 for FAT32
    uint16_t total_sectors_16;      // Must be 0 for FAT32
    uint8_t  media_type;
    uint16_t fat_size_16;           // Must be 0 for FAT32
    uint16_t sectors_per_track;
    uint16_t num_heads;
    uint32_t hidden_sectors;
    uint32_t total_sectors_32;

    // FAT32-specific fields
    uint32_t fat_size_32;
    uint16_t ext_flags;
    uint16_t fs_version;
    uint32_t root_cluster;
    uint16_t fs_info;
    uint16_t backup_boot_sector;
    uint8_t  reserved[12];
    uint8_t  drive_number;
    uint8_t  reserved1;
    uint8_t  boot_signature;
    uint32_t volume_id;
    uint8_t  volume_label[11];
    uint8_t  fs_type[8];
} __attribute__((packed)) fat32_boot_sector_t;

/*=============================================================================
 * FAT32 DIRECTORY ENTRY STRUCTURE
 *============================================================================*/
typedef struct {
    uint8_t  name[11];              // 8.3 filename
    uint8_t  attributes;
    uint8_t  reserved;
    uint8_t  creation_time_tenths;
    uint16_t creation_time;
    uint16_t creation_date;
    uint16_t last_access_date;
    uint16_t first_cluster_high;
    uint16_t last_write_time;
    uint16_t last_write_date;
    uint16_t first_cluster_low;
    uint32_t file_size;
} __attribute__((packed)) fat32_dir_entry_t;

/*=============================================================================
 * FAT32 FILE DESCRIPTOR
 *============================================================================*/
typedef struct {
    bool     in_use;
    uint32_t first_cluster;
    uint32_t current_cluster;
    uint32_t file_size;
    uint32_t position;
    uint8_t  attributes;
    char     filename[12];          // 8.3 + null
    bool     is_directory;
} fat32_file_t;

/*=============================================================================
 * FUNCTION PROTOTYPES
 *============================================================================*/
// Initialization
int fat32_init(void);
int fat32_mount(void);

// File operations
int fat32_open(const char* path);
int fat32_close(int fd);
int fat32_read(int fd, void* buffer, uint32_t size);
int fat32_write(int fd, const void* buffer, uint32_t size);
int fat32_seek(int fd, uint32_t offset);

// Directory operations
int fat32_opendir(const char* path);
int fat32_readdir(int fd, char* name, uint32_t* size, uint8_t* attributes);
int fat32_mkdir(const char* path);
int fat32_rmdir(const char* path);

// File management
int fat32_create(const char* path);
int fat32_unlink(const char* path);
int fat32_stat(const char* path, uint32_t* size, uint8_t* attributes);

// Utility
void fat32_list_root(void);  /* lists to kernel console (kprintf) */

/* Per-entry callback for fat32_list_root_cb: receives the formatted 8.3 name,
 * file size, and whether it's a directory. Lets the caller route output
 * anywhere (kernel console, shell stream) without the driver depending on
 * stdio. */
typedef void (*fat32_dir_emit_t)(void* ctx, const char* name, uint32_t size, bool is_dir);

/* Walk the root directory, delivering each visible entry to `emit`.
 * Returns 0 on success, -1 if not mounted / on read error. */
int fat32_list_root_cb(fat32_dir_emit_t emit, void* ctx);

#endif // FAT32_H
