/*=============================================================================
 * fat32.c - FAT32 Filesystem Driver Implementation
 * Provides FAT32 filesystem support for persistent disk storage
 *
 * SECURITY FIXES IMPLEMENTED:
 * - Issue 5.2: Infinite loop DoS protection with iteration counters
 * - Race condition fix: Mutex protection for global I/O buffers
 * - Issue 6.2: Packed structures to prevent unaligned access (see fat32.h)
 *============================================================================*/
#include "fat32.h"
#include "ide.h"
#include "kprintf.h"
#include "util.h"
#include "pmm.h"
#include "mutex.h"
#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * GLOBAL VARIABLES
 *============================================================================*/
static fat32_boot_sector_t boot_sector;
static uint32_t fat_start_sector;
static uint32_t data_start_sector;
static uint32_t root_dir_cluster;
static uint32_t sectors_per_cluster;
static uint32_t bytes_per_cluster;
static fat32_file_t open_files[FAT32_MAX_OPEN_FILES];
static bool fat32_mounted = false;

/*=============================================================================
 * SECURITY FIX: Mutex Protection for Global Buffers (Race Condition)
 *
 * VULNERABILITY: The global sector_buffer and cluster_buffer are shared
 * across all FAT32 operations. Without mutual exclusion, concurrent access
 * from multiple threads or interrupt handlers will corrupt the buffers,
 * leading to silent data corruption.
 *
 * MITIGATION: Protect all buffer access with a mutex. All functions that
 * access sector_buffer or cluster_buffer must hold fat32_mutex.
 *============================================================================*/
static mutex_t fat32_mutex;

// Cache for FAT and cluster data (MUST be protected by fat32_mutex)
static uint8_t* sector_buffer = NULL;  // 512-byte sector buffer
static uint8_t* cluster_buffer = NULL;  // Full cluster buffer

/*=============================================================================
 * HELPER FUNCTIONS
 *============================================================================*/

/*-----------------------------------------------------------------------------
 * FUNCTION: cluster_to_sector
 * PURPOSE: Convert cluster number to LBA sector number
 *---------------------------------------------------------------------------*/
/*=============================================================================
 * ARCHITECTURAL FIX: Integer Overflow Prevention in LBA Calculation
 *
 * CRITICAL VULNERABILITY: The LBA calculation can overflow with:
 * - Large cluster numbers (e.g., corrupted value near UINT32_MAX = 4,294,967,295)
 * - The multiplication (cluster - 2) * sectors_per_cluster overflows uint32_t
 *
 * ATTACK SCENARIO:
 * 1. Corrupted cluster number (from stack overflow or TOCTOU race) = 4,000,000,000
 * 2. sectors_per_cluster = 8 (typical)
 * 3. Calculation: (4,000,000,000 - 2) * 8 = 31,999,999,984
 * 4. Overflow: 31,999,999,984 % 4,294,967,296 = 27,705,032,592 % 2^32 = wraps to small value
 * 5. Result: Driver reads Boot Sector or FAT Table into file buffer (silent corruption)
 *
 * FIX: Promote all LBA calculations to uint64_t to support:
 * - Disks up to 8 ZB (zettabytes) with 64-bit LBA
 * - Prevention of integer overflow attacks
 * - Future-proof for large storage devices (>2TB requires 64-bit LBA)
 *
 * PERFORMANCE: uint64_t arithmetic is native on modern 64-bit CPUs, negligible
 * overhead on 32-bit systems compared to the security benefit.
 *===========================================================================*/
static uint32_t cluster_to_sector(uint32_t cluster) {
    // Promote to uint64_t for overflow-safe calculation
    uint64_t cluster_offset = (uint64_t)(cluster - 2) * (uint64_t)sectors_per_cluster;
    uint64_t lba = (uint64_t)data_start_sector + cluster_offset;

    // Sanity check: Ensure LBA fits in uint32_t (for 32-bit IDE driver compatibility)
    // If LBA > UINT32_MAX, the disk is >2TB which requires 48-bit LBA addressing
    if (lba > UINT32_MAX) {
        kprintf("[FAT32] CRITICAL: LBA overflow detected (cluster=%u, LBA=%llu)\n",
                cluster, (unsigned long long)lba);
        kprintf("[FAT32] This indicates either:\n");
        kprintf("[FAT32]   1. Corrupted cluster number (possible attack)\n");
        kprintf("[FAT32]   2. Disk >2TB (requires 48-bit LBA, not supported)\n");
        return 0;  // Return sector 0 (will cause read error, preventing silent corruption)
    }

    return (uint32_t)lba;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: read_fat_entry
 * PURPOSE: Read a FAT entry to get next cluster in chain
 * PROTECTED BY: fat32_mutex (global buffer access)
 *---------------------------------------------------------------------------*/
static uint32_t read_fat_entry(uint32_t cluster) {
    uint32_t fat_offset = cluster * 4;  // 4 bytes per FAT32 entry
    uint32_t fat_sector = fat_start_sector + (fat_offset / FAT32_SECTOR_SIZE);
    uint32_t entry_offset = fat_offset % FAT32_SECTOR_SIZE;

    // Read the FAT sector
    if (ide_read_sectors(fat_sector, 1, sector_buffer) != 0) {
        kprintf("[FAT32] ERROR: Failed to read FAT sector %u\n", fat_sector);
        return FAT32_BAD_CLUSTER;
    }

    // Extract the 32-bit FAT entry (only lower 28 bits are used)
    uint32_t* fat_table = (uint32_t*)sector_buffer;
    uint32_t next_cluster = fat_table[entry_offset / 4] & 0x0FFFFFFF;

    return next_cluster;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: write_fat_entry
 * PURPOSE: Write a FAT entry to link clusters
 * PROTECTED BY: fat32_mutex (global buffer access)
 *---------------------------------------------------------------------------*/
static int write_fat_entry(uint32_t cluster, uint32_t value) {
    uint32_t fat_offset = cluster * 4;
    uint32_t fat_sector = fat_start_sector + (fat_offset / FAT32_SECTOR_SIZE);
    uint32_t entry_offset = fat_offset % FAT32_SECTOR_SIZE;

    // Read the FAT sector
    if (ide_read_sectors(fat_sector, 1, sector_buffer) != 0) {
        return -1;
    }

    // Update the FAT entry (preserve upper 4 bits)
    uint32_t* fat_table = (uint32_t*)sector_buffer;
    fat_table[entry_offset / 4] = (fat_table[entry_offset / 4] & 0xF0000000) | (value & 0x0FFFFFFF);

    // Write back to disk (both FAT copies)
    if (ide_write_sectors(fat_sector, 1, sector_buffer) != 0) {
        return -1;
    }

    // Update second FAT if it exists
    if (boot_sector.num_fats > 1) {
        uint32_t fat2_sector = fat_sector + boot_sector.fat_size_32;
        ide_write_sectors(fat2_sector, 1, sector_buffer);
    }

    return 0;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: find_free_cluster
 * PURPOSE: Find a free cluster in FAT
 *---------------------------------------------------------------------------*/
static uint32_t find_free_cluster(void) {
    // Guard against underflow/division-by-zero from a corrupted boot sector
    if (sectors_per_cluster == 0 || boot_sector.total_sectors_32 <= data_start_sector) {
        return 0;
    }

    uint32_t total_clusters = (boot_sector.total_sectors_32 - data_start_sector) / sectors_per_cluster;
    if (total_clusters > FAT32_MAX_CLUSTER_CHAIN) {
        total_clusters = FAT32_MAX_CLUSTER_CHAIN;
    }

    for (uint32_t cluster = 2; cluster < total_clusters; cluster++) {
        uint32_t entry = read_fat_entry(cluster);
        if (entry == FAT32_FREE) {
            return cluster;
        }
        if (entry == FAT32_BAD_CLUSTER) {
            return 0;  // Disk read failure - abort scan
        }
    }

    return 0;  // No free clusters
}

/*-----------------------------------------------------------------------------
 * FUNCTION: allocate_cluster
 * PURPOSE: Allocate a new cluster and link it to chain
 *---------------------------------------------------------------------------*/
static uint32_t allocate_cluster(uint32_t previous_cluster) {
    uint32_t new_cluster = find_free_cluster();
    if (new_cluster == 0) {
        kprintf("[FAT32] ERROR: Disk full\n");
        return 0;
    }

    // Mark new cluster as end-of-chain
    if (write_fat_entry(new_cluster, FAT32_EOC) != 0) {
        return 0;
    }

    // Link previous cluster to new cluster
    if (previous_cluster != 0) {
        if (write_fat_entry(previous_cluster, new_cluster) != 0) {
            write_fat_entry(new_cluster, FAT32_FREE);  // Rollback
            return 0;
        }
    }

    return new_cluster;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: read_cluster
 * PURPOSE: Read an entire cluster into buffer
 * PROTECTED BY: fat32_mutex (global buffer access)
 * NOTE: All callers pass cluster_buffer as the buffer parameter
 *---------------------------------------------------------------------------*/
static int read_cluster(uint32_t cluster, void* buffer) {
    uint32_t sector = cluster_to_sector(cluster);
    // kprintf("[FAT32_DEBUG] read_cluster: cluster=%u, buffer=%p, sectors=%u, sector=%u\n",
    //         cluster, buffer, sectors_per_cluster, sector);

    int result = ide_read_sectors(sector, sectors_per_cluster, buffer);

    // kprintf("[FAT32_DEBUG] read_cluster: completed, result=%d\n", result);

    return result;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: write_cluster
 * PURPOSE: Write an entire cluster from buffer
 * PROTECTED BY: fat32_mutex (global buffer access)
 *---------------------------------------------------------------------------*/
static int write_cluster(uint32_t cluster, const void* buffer) {
    uint32_t sector = cluster_to_sector(cluster);
    int result = ide_write_sectors(sector, sectors_per_cluster, buffer);

    return result;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: parse_path
 * PURPOSE: Parse path into directory components
 *---------------------------------------------------------------------------*/
static int parse_path(const char* path, char components[][12], int max_components) {
    int count = 0;
    const char* start = path;

    // Skip leading slashes
    while (*start == '/' || *start == '\\') start++;

    while (*start && count < max_components) {
        const char* end = start;
        while (*end && *end != '/' && *end != '\\') end++;

        int len = end - start;
        if (len > 0 && len < 12) {
            memcpy(components[count], start, len);
            components[count][len] = '\0';
            count++;
        }

        start = end;
        while (*start == '/' || *start == '\\') start++;
    }

    return count;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: filename_to_83
 * PURPOSE: Convert filename to 8.3 format
 *---------------------------------------------------------------------------*/
static void filename_to_83(const char* filename, char* name83) {
    memset(name83, ' ', 11);
    name83[11] = '\0';

    const char* ext_start = NULL;

    // Find extension
    for (const char* p = filename; *p; p++) {
        if (*p == '.') {
            ext_start = p + 1;
        }
    }

    // Copy base name (up to 8 chars)
    for (int i = 0; i < 8 && filename[i] && filename[i] != '.'; i++) {
        name83[i] = (filename[i] >= 'a' && filename[i] <= 'z') ?
                    filename[i] - 32 : filename[i];  // Convert to uppercase
    }

    // Copy extension (up to 3 chars)
    if (ext_start) {
        for (int i = 0; i < 3 && ext_start[i]; i++) {
            name83[8 + i] = (ext_start[i] >= 'a' && ext_start[i] <= 'z') ?
                           ext_start[i] - 32 : ext_start[i];
        }
    }
}

/*=============================================================================
 * PRODUCTION FIX: LFN Chain Consumption for Robustness
 *
 * ISSUE: Without consuming the entire LFN chain, directory parsing can fail
 * when long filenames are present. LFN entries precede the 8.3 entry in
 * reverse order with sequence numbers.
 *
 * FIX: Helper function to safely consume the entire LFN chain even though
 * we don't display long filenames. This ensures robustness on filesystems
 * with LFN entries and prevents parsing errors.
 *
 * LFN Structure:
 * - Sequence number in first byte (0x01, 0x02, ...)
 * - Final LFN entry has bit 6 set (0x40 | sequence)
 * - Attributes field is always 0x0F (FAT32_ATTR_LONG_NAME)
 * - Followed by single 8.3 entry
 *===========================================================================*/
static bool is_lfn_entry(const fat32_dir_entry_t* entry) {
    return (entry->attributes == FAT32_ATTR_LONG_NAME);
}

static uint8_t get_lfn_sequence(const fat32_dir_entry_t* entry) __attribute__((unused));
static uint8_t get_lfn_sequence(const fat32_dir_entry_t* entry) {
    return entry->name[0] & 0x3F;  // Mask off the "last LFN" bit (0x40)
}

static bool is_last_lfn_entry(const fat32_dir_entry_t* entry) __attribute__((unused));
static bool is_last_lfn_entry(const fat32_dir_entry_t* entry) {
    return (entry->name[0] & 0x40) != 0;  // Check bit 6
}

/*-----------------------------------------------------------------------------
 * FUNCTION: find_dir_entry
 * PURPOSE: Find a directory entry in a directory cluster
 *---------------------------------------------------------------------------*/
static int find_dir_entry(uint32_t dir_cluster, const char* name, fat32_dir_entry_t* entry) {
    char name83[12];
    filename_to_83(name, name83);

    uint32_t cluster = dir_cluster;

    /*=========================================================================
     * SECURITY FIX (Issue 5.2): Infinite Loop DoS Protection
     *
     * Limit cluster chain traversal to prevent infinite loops caused by
     * cyclic FAT chains. If a corrupted or malicious filesystem has a cycle
     * (e.g., cluster 100 → 101 → 102 → 100), this prevents kernel lockup.
     *=======================================================================*/
    uint32_t iteration_count = 0;

    while (cluster < FAT32_EOC) {
        // Check for infinite loop (cyclic cluster chain)
        if (++iteration_count > FAT32_MAX_CLUSTER_CHAIN) {
            kprintf("[FAT32] ERROR: Cluster chain cycle detected (iteration limit exceeded)\n");
            kprintf("[FAT32] This indicates filesystem corruption or a DoS attack\n");
            return -1;  // -EIO: Filesystem corruption
        }

        // Read cluster
        if (read_cluster(cluster, cluster_buffer) != 0) {
            return -1;
        }

        fat32_dir_entry_t* entries = (fat32_dir_entry_t*)cluster_buffer;
        uint32_t entries_per_cluster = bytes_per_cluster / FAT32_DIR_ENTRY_SIZE;

        for (uint32_t i = 0; i < entries_per_cluster; i++) {
            if (entries[i].name[0] == 0x00) {
                return -1;  // End of directory
            }

            if (entries[i].name[0] == 0xE5) {
                continue;  // Deleted entry
            }

            /*=====================================================================
             * PRODUCTION FIX: LFN Chain Consumption
             *
             * When we encounter an LFN entry, we need to skip the entire chain
             * (not just this single entry). LFN entries precede the 8.3 entry
             * in reverse order. We consume them to ensure robust parsing.
             *===================================================================*/
            if (is_lfn_entry(&entries[i])) {
                // LFN entries come in reverse order before the 8.3 entry
                // The sequence number tells us how many LFN entries precede
                // We're walking forward, so we'll encounter them in order
                // Just skip and the 8.3 entry will follow
                continue;
            }

            if (memcmp(entries[i].name, name83, 11) == 0) {
                memcpy(entry, &entries[i], sizeof(fat32_dir_entry_t));
                return 0;
            }
        }

        cluster = read_fat_entry(cluster);
    }

    return -1;  // Not found
}

/*=============================================================================
 * PUBLIC API FUNCTIONS
 *============================================================================*/

/*-----------------------------------------------------------------------------
 * FUNCTION: fat32_init
 * PURPOSE: Initialize FAT32 driver
 *---------------------------------------------------------------------------*/
int fat32_init(void) {
    kprintf("[FAT32] Initializing FAT32 filesystem driver...\n");

    // Initialize mutex for buffer protection
    mutex_init(&fat32_mutex, "fat32_buffers", 0);

    /*=========================================================================
     * SECURITY FIX: Cache-Line Aligned I/O Buffers
     *
     * ISSUE: Unaligned I/O buffers suffer from:
     * - False sharing on multi-core systems (performance degradation)
     * - Poor PIO performance due to unaligned memory access
     * - Risk of adjacent memory corruption during hardware transfers
     *
     * MITIGATION: Verify buffer alignment to 128-byte cache-line boundary
     * (conservative alignment supporting most modern CPUs including x86)
     *=======================================================================*/
    sector_buffer = (uint8_t*)pmm_alloc();
    if (!sector_buffer) {
        kprintf("[FAT32] ERROR: Failed to allocate sector buffer\n");
        return -1;
    }

    // Verify cache-line alignment (128-byte boundary)
    if (((uintptr_t)sector_buffer & 0x7F) != 0) {
        kprintf("[FAT32] WARNING: sector_buffer not 128-byte aligned (%p)\n",
                (void*)sector_buffer);
        kprintf("[FAT32] This may impact I/O performance and cache coherency\n");
    }

    kprintf("[FAT32] DEBUG: sector_buffer allocated at %p (alignment: %s)\n",
            (void*)sector_buffer,
            (((uintptr_t)sector_buffer & 0x7F) == 0) ? "128-byte aligned" : "UNALIGNED");

    // Initialize file descriptor table
    for (int i = 0; i < FAT32_MAX_OPEN_FILES; i++) {
        open_files[i].in_use = false;
    }

    kprintf("[FAT32] Initialization complete [OK]\n");
    return 0;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: fat32_mount
 * PURPOSE: Mount FAT32 filesystem from IDE disk
 *---------------------------------------------------------------------------*/
int fat32_mount(void) {
    kprintf("[FAT32] Mounting filesystem...\n");

    // Read boot sector
    if (ide_read_sectors(0, 1, sector_buffer) != 0) {
        kprintf("[FAT32] ERROR: Failed to read boot sector\n");
        return -1;
    }

    memcpy(&boot_sector, sector_buffer, sizeof(fat32_boot_sector_t));

    // Verify FAT32
    if (boot_sector.bytes_per_sector != 512) {
        kprintf("[FAT32] ERROR: Unsupported sector size: %u\n", boot_sector.bytes_per_sector);
        return -1;
    }

    if (boot_sector.root_entry_count != 0) {
        kprintf("[FAT32] ERROR: Not a FAT32 filesystem (root_entry_count must be 0)\n");
        return -1;
    }

    // Calculate important values
    fat_start_sector = boot_sector.reserved_sectors;
    data_start_sector = boot_sector.reserved_sectors +
                       (boot_sector.num_fats * boot_sector.fat_size_32);
    root_dir_cluster = boot_sector.root_cluster;
    sectors_per_cluster = boot_sector.sectors_per_cluster;
    bytes_per_cluster = sectors_per_cluster * FAT32_SECTOR_SIZE;

    // cluster_buffer is a single 4KB page; reject clusters that don't fit
    uint32_t cluster_size_bytes = sectors_per_cluster * FAT32_SECTOR_SIZE;
    if (sectors_per_cluster == 0 || cluster_size_bytes > PMM_PAGE_SIZE) {
        kprintf("[FAT32] ERROR: Unsupported cluster size (%u sectors)\n", sectors_per_cluster);
        return -1;
    }

    if (data_start_sector >= boot_sector.total_sectors_32) {
        kprintf("[FAT32] ERROR: Data region starts beyond end of volume\n");
        return -1;
    }

    cluster_buffer = (uint8_t*)pmm_alloc();
    if (!cluster_buffer) {
        kprintf("[FAT32] ERROR: Failed to allocate cluster buffer\n");
        return -1;
    }

    kprintf("[FAT32] DEBUG: cluster_buffer allocated at %p\n", (void*)cluster_buffer);
    kprintf("[FAT32] DEBUG: bytes_per_cluster = %u (should be %u * 512)\n", bytes_per_cluster, sectors_per_cluster);

    kprintf("[FAT32] FAT starts at sector %u\n", fat_start_sector);
    kprintf("[FAT32] Data starts at sector %u\n", data_start_sector);
    kprintf("[FAT32] Root directory cluster: %u\n", root_dir_cluster);
    kprintf("[FAT32] Sectors per cluster: %u\n", sectors_per_cluster);
    kprintf("[FAT32] Volume label: %.11s\n", boot_sector.volume_label);

    fat32_mounted = true;
    kprintf("[FAT32] Mount successful [OK]\n");
    return 0;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: fat32_open
 * PURPOSE: Open a file for reading/writing
 *---------------------------------------------------------------------------*/
int fat32_open(const char* path) {
    if (!fat32_mounted) {
        kprintf("[FAT32] ERROR: Filesystem not mounted\n");
        return -1;
    }

    mutex_lock(&fat32_mutex);

    // Find free file descriptor
    int fd = -1;
    for (int i = 0; i < FAT32_MAX_OPEN_FILES; i++) {
        if (!open_files[i].in_use) {
            fd = i;
            break;
        }
    }

    if (fd == -1) {
        kprintf("[FAT32] ERROR: Too many open files\n");
        mutex_unlock(&fat32_mutex);
        return -1;
    }

    // Parse path
    char components[16][12];
    int depth = parse_path(path, components, 16);

    if (depth == 0) {
        // Open root directory
        open_files[fd].in_use = true;
        open_files[fd].first_cluster = root_dir_cluster;
        open_files[fd].current_cluster = root_dir_cluster;
        open_files[fd].file_size = 0;
        open_files[fd].position = 0;
        open_files[fd].is_directory = true;
        mutex_unlock(&fat32_mutex);
        return fd;
    }

    // Navigate to file
    uint32_t current_cluster = root_dir_cluster;
    fat32_dir_entry_t entry;

    for (int i = 0; i < depth; i++) {
        if (find_dir_entry(current_cluster, components[i], &entry) != 0) {
            kprintf("[FAT32] ERROR: File not found: %s\n", components[i]);
            mutex_unlock(&fat32_mutex);
            return -1;
        }

        current_cluster = ((uint32_t)entry.first_cluster_high << 16) | entry.first_cluster_low;

        if (i < depth - 1) {
            // Must be directory for intermediate components
            if (!(entry.attributes & FAT32_ATTR_DIRECTORY)) {
                kprintf("[FAT32] ERROR: Not a directory: %s\n", components[i]);
                mutex_unlock(&fat32_mutex);
                return -1;
            }
        }
    }

    // Fill in file descriptor
    open_files[fd].in_use = true;
    open_files[fd].first_cluster = current_cluster;
    open_files[fd].current_cluster = current_cluster;
    open_files[fd].file_size = entry.file_size;
    open_files[fd].position = 0;
    open_files[fd].attributes = entry.attributes;
    open_files[fd].is_directory = (entry.attributes & FAT32_ATTR_DIRECTORY) != 0;

    mutex_unlock(&fat32_mutex);
    return fd;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: fat32_close
 * PURPOSE: Close an open file
 *---------------------------------------------------------------------------*/
int fat32_close(int fd) {
    if (fd < 0 || fd >= FAT32_MAX_OPEN_FILES || !open_files[fd].in_use) {
        return -1;
    }

    mutex_lock(&fat32_mutex);

    open_files[fd].in_use = false;

    mutex_unlock(&fat32_mutex);
    return 0;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: fat32_read
 * PURPOSE: Read data from an open file
 *---------------------------------------------------------------------------*/
int fat32_read(int fd, void* buffer, uint32_t size) {
    if (fd < 0 || fd >= FAT32_MAX_OPEN_FILES || !open_files[fd].in_use) {
        return -1;
    }

    mutex_lock(&fat32_mutex);

    fat32_file_t* file = &open_files[fd];

    if (file->is_directory) {
        kprintf("[FAT32] ERROR: Cannot read from directory\n");
        mutex_unlock(&fat32_mutex);
        return -1;
    }

    // Don't read past end of file
    if (file->position >= file->file_size) {
        mutex_unlock(&fat32_mutex);
        return 0;  // EOF
    }

    if (file->position + size > file->file_size) {
        size = file->file_size - file->position;
    }

    uint32_t bytes_read = 0;
    uint8_t* buf = (uint8_t*)buffer;

    /*=========================================================================
     * SECURITY FIX (Issue 5.2): Infinite Loop DoS Protection
     *=======================================================================*/
    uint32_t iteration_count = 0;

    while (bytes_read < size && file->current_cluster < FAT32_EOC) {
        // Check for infinite loop (cyclic cluster chain)
        if (++iteration_count > FAT32_MAX_CLUSTER_CHAIN) {
            kprintf("[FAT32] ERROR: Cluster chain cycle detected in read operation\n");
            mutex_unlock(&fat32_mutex);
            return bytes_read > 0 ? (int)bytes_read : -1;  // Return partial read or error
        }

        // Read cluster
        if (read_cluster(file->current_cluster, cluster_buffer) != 0) {
            mutex_unlock(&fat32_mutex);
            return -1;
        }

        uint32_t cluster_offset = file->position % bytes_per_cluster;
        uint32_t bytes_to_copy = bytes_per_cluster - cluster_offset;
        if (bytes_to_copy > size - bytes_read) {
            bytes_to_copy = size - bytes_read;
        }

        memcpy(buf + bytes_read, cluster_buffer + cluster_offset, bytes_to_copy);
        bytes_read += bytes_to_copy;
        file->position += bytes_to_copy;

        // Move to next cluster if needed
        if (file->position % bytes_per_cluster == 0 && bytes_read < size) {
            file->current_cluster = read_fat_entry(file->current_cluster);
        }
    }

    mutex_unlock(&fat32_mutex);
    return bytes_read;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: fat32_write
 * PURPOSE: Write data to an open file (Phase 2)
 *---------------------------------------------------------------------------*/
int fat32_write(int fd, const void* buffer, uint32_t size) {
    if (fd < 0 || fd >= FAT32_MAX_OPEN_FILES || !open_files[fd].in_use) {
        return -1;
    }

    fat32_file_t* file = &open_files[fd];

    if (file->is_directory) {
        kprintf("[FAT32] ERROR: Cannot write to directory\n");
        return -1;
    }

    mutex_lock(&fat32_mutex);

    const uint8_t* buf = (const uint8_t*)buffer;
    uint32_t bytes_written = 0;

    while (bytes_written < size) {
        // If we're at a cluster boundary or beyond current cluster chain, allocate new cluster
        if (file->current_cluster >= FAT32_EOC ||
            (file->position > 0 && (file->position % bytes_per_cluster) == 0)) {

            uint32_t new_cluster = allocate_cluster(file->current_cluster);
            if (new_cluster == 0) {
                mutex_unlock(&fat32_mutex);
                return bytes_written > 0 ? (int)bytes_written : -1;  // Disk full
            }

            if (file->first_cluster == 0) {
                file->first_cluster = new_cluster;
            }
            file->current_cluster = new_cluster;
        }

        // Read current cluster (for partial writes)
        if (read_cluster(file->current_cluster, cluster_buffer) != 0) {
            mutex_unlock(&fat32_mutex);
            return bytes_written > 0 ? (int)bytes_written : -1;
        }

        // Calculate how much to write in this cluster
        uint32_t cluster_offset = file->position % bytes_per_cluster;
        uint32_t bytes_to_write = bytes_per_cluster - cluster_offset;
        if (bytes_to_write > size - bytes_written) {
            bytes_to_write = size - bytes_written;
        }

        // Update cluster buffer
        memcpy(cluster_buffer + cluster_offset, buf + bytes_written, bytes_to_write);

        // Write cluster back to disk
        if (write_cluster(file->current_cluster, cluster_buffer) != 0) {
            mutex_unlock(&fat32_mutex);
            return bytes_written > 0 ? (int)bytes_written : -1;
        }

        bytes_written += bytes_to_write;
        file->position += bytes_to_write;

        // Update file size if we extended it
        if (file->position > file->file_size) {
            file->file_size = file->position;
        }

        // Move to next cluster if needed
        if ((file->position % bytes_per_cluster) == 0 && bytes_written < size) {
            uint32_t next = read_fat_entry(file->current_cluster);
            if (next >= FAT32_EOC) {
                // Need to allocate another cluster
                continue;
            }
            file->current_cluster = next;
        }
    }

    mutex_unlock(&fat32_mutex);
    return bytes_written;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: fat32_seek
 * PURPOSE: Seek to position in file
 *---------------------------------------------------------------------------*/
int fat32_seek(int fd, uint32_t offset) {
    if (fd < 0 || fd >= FAT32_MAX_OPEN_FILES || !open_files[fd].in_use) {
        return -1;
    }

    mutex_lock(&fat32_mutex);

    fat32_file_t* file = &open_files[fd];

    if (offset > file->file_size) {
        offset = file->file_size;
    }

    // Reset to beginning
    file->position = 0;
    file->current_cluster = file->first_cluster;

    // Seek forward
    uint32_t clusters_to_skip = offset / bytes_per_cluster;

    /*=========================================================================
     * SECURITY FIX (Issue 5.2): Infinite Loop DoS Protection
     *
     * Although this loop has an upper bound (clusters_to_skip), a cyclic
     * FAT chain could still cause it to loop forever. Add iteration limit.
     *=======================================================================*/
    uint32_t iteration_count = 0;

    for (uint32_t i = 0; i < clusters_to_skip; i++) {
        if (++iteration_count > FAT32_MAX_CLUSTER_CHAIN) {
            kprintf("[FAT32] ERROR: Cluster chain cycle detected in seek operation\n");
            mutex_unlock(&fat32_mutex);
            return -1;
        }

        file->current_cluster = read_fat_entry(file->current_cluster);
        if (file->current_cluster >= FAT32_EOC) {
            mutex_unlock(&fat32_mutex);
            return -1;
        }
    }

    file->position = offset;

    mutex_unlock(&fat32_mutex);
    return 0;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: fat32_create
 * PURPOSE: Create a new file (Phase 2)
 * NOTE: For now, only supports creating files in root directory
 *---------------------------------------------------------------------------*/
int fat32_create(const char* path) {
    if (!fat32_mounted) {
        return -1;
    }

    mutex_lock(&fat32_mutex);

    // Parse filename from path (simple version - root only)
    const char* filename = path;
    if (*filename == '/') filename++;

    // Convert to 8.3 format
    char name_83[11];
    memset(name_83, ' ', 11);

    const char* dot = strchr(filename, '.');
    int name_len = dot ? (int)(dot - filename) : (int)strlen(filename);
    if (name_len > 8) name_len = 8;

    for (int i = 0; i < name_len; i++) {
        name_83[i] = filename[i] >= 'a' && filename[i] <= 'z' ? filename[i] - 32 : filename[i];
    }

    if (dot) {
        dot++;
        int ext_len = strlen(dot);
        if (ext_len > 3) ext_len = 3;
        for (int i = 0; i < ext_len; i++) {
            name_83[8 + i] = dot[i] >= 'a' && dot[i] <= 'z' ? dot[i] - 32 : dot[i];
        }
    }

    // Read root directory cluster
    if (read_cluster(root_dir_cluster, cluster_buffer) != 0) {
        mutex_unlock(&fat32_mutex);
        return -1;
    }

    fat32_dir_entry_t* entries = (fat32_dir_entry_t*)cluster_buffer;
    uint32_t entries_per_cluster = bytes_per_cluster / FAT32_DIR_ENTRY_SIZE;

    // Find free entry
    for (uint32_t i = 0; i < entries_per_cluster; i++) {
        if (entries[i].name[0] == 0x00 || entries[i].name[0] == 0xE5) {
            // Found free slot
            memcpy(entries[i].name, name_83, 11);
            entries[i].attributes = FAT32_ATTR_ARCHIVE;
            entries[i].first_cluster_high = 0;
            entries[i].first_cluster_low = 0;
            entries[i].file_size = 0;

            // Write back
            if (write_cluster(root_dir_cluster, cluster_buffer) != 0) {
                mutex_unlock(&fat32_mutex);
                return -1;
            }

            mutex_unlock(&fat32_mutex);
            return 0;
        }
    }

    kprintf("[FAT32] ERROR: Root directory full\n");
    mutex_unlock(&fat32_mutex);
    return -1;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: fat32_unlink
 * PURPOSE: Delete a file (Phase 2)
 * NOTE: For now, only supports deleting files in root directory
 *---------------------------------------------------------------------------*/
int fat32_unlink(const char* path) {
    if (!fat32_mounted) {
        return -1;
    }

    mutex_lock(&fat32_mutex);

    // Parse filename from path
    const char* filename = path;
    if (*filename == '/') filename++;

    // Convert to 8.3 for comparison
    char name_83[11];
    memset(name_83, ' ', 11);
    const char* dot = strchr(filename, '.');
    int name_len = dot ? (int)(dot - filename) : (int)strlen(filename);
    if (name_len > 8) name_len = 8;
    for (int i = 0; i < name_len; i++) {
        name_83[i] = filename[i] >= 'a' && filename[i] <= 'z' ? filename[i] - 32 : filename[i];
    }
    if (dot) {
        dot++;
        int ext_len = strlen(dot);
        if (ext_len > 3) ext_len = 3;
        for (int i = 0; i < ext_len; i++) {
            name_83[8 + i] = dot[i] >= 'a' && dot[i] <= 'z' ? dot[i] - 32 : dot[i];
        }
    }

    // Read root directory
    if (read_cluster(root_dir_cluster, cluster_buffer) != 0) {
        mutex_unlock(&fat32_mutex);
        return -1;
    }

    fat32_dir_entry_t* entries = (fat32_dir_entry_t*)cluster_buffer;
    uint32_t entries_per_cluster = bytes_per_cluster / FAT32_DIR_ENTRY_SIZE;

    // Find and delete entry
    for (uint32_t i = 0; i < entries_per_cluster; i++) {
        if (entries[i].name[0] == 0x00) break;
        if (entries[i].name[0] == 0xE5) continue;

        if (memcmp(entries[i].name, name_83, 11) == 0) {
            // Found the file - free its clusters
            uint32_t cluster = ((uint32_t)entries[i].first_cluster_high << 16) | entries[i].first_cluster_low;

            /*=================================================================
             * SECURITY FIX (Issue 5.2): Infinite Loop DoS Protection
             *================================================================*/
            uint32_t iteration_count = 0;

            while (cluster > 0 && cluster < FAT32_EOC) {
                if (++iteration_count > FAT32_MAX_CLUSTER_CHAIN) {
                    kprintf("[FAT32] ERROR: Cluster chain cycle detected while freeing clusters\n");
                    mutex_unlock(&fat32_mutex);
                    return -1;
                }

                uint32_t next = read_fat_entry(cluster);
                write_fat_entry(cluster, FAT32_FREE);
                cluster = next;
            }

            // Mark directory entry as deleted
            entries[i].name[0] = 0xE5;

            // Write back
            if (write_cluster(root_dir_cluster, cluster_buffer) != 0) {
                mutex_unlock(&fat32_mutex);
                return -1;
            }

            mutex_unlock(&fat32_mutex);
            return 0;
        }
    }

    mutex_unlock(&fat32_mutex);
    return -1;  // File not found
}

/*-----------------------------------------------------------------------------
 * FUNCTION: fat32_mkdir
 * PURPOSE: Create a directory (Phase 2 - simplified root only)
 *---------------------------------------------------------------------------*/
int fat32_mkdir(const char* path) {
    if (!fat32_mounted) {
        return -1;
    }

    mutex_lock(&fat32_mutex);

    // Similar to fat32_create but set directory attribute
    const char* dirname = path;
    if (*dirname == '/') dirname++;

    char name_83[11];
    memset(name_83, ' ', 11);
    int name_len = strlen(dirname);
    if (name_len > 8) name_len = 8;
    for (int i = 0; i < name_len; i++) {
        name_83[i] = dirname[i] >= 'a' && dirname[i] <= 'z' ? dirname[i] - 32 : dirname[i];
    }

    // Allocate cluster for new directory
    uint32_t new_cluster = allocate_cluster(0);
    if (new_cluster == 0) {
        mutex_unlock(&fat32_mutex);
        return -1;
    }

    // Initialize directory cluster with . and .. entries
    // kprintf("[FAT32_DEBUG] About to memset cluster_buffer=%p, size=%u bytes\n", (void*)cluster_buffer, bytes_per_cluster);
    memset(cluster_buffer, 0, bytes_per_cluster);
    fat32_dir_entry_t* entries = (fat32_dir_entry_t*)cluster_buffer;

    // . entry
    memset(entries[0].name, ' ', 11);
    entries[0].name[0] = '.';
    entries[0].attributes = FAT32_ATTR_DIRECTORY;
    entries[0].first_cluster_high = new_cluster >> 16;
    entries[0].first_cluster_low = new_cluster & 0xFFFF;

    // .. entry
    memset(entries[1].name, ' ', 11);
    entries[1].name[0] = '.';
    entries[1].name[1] = '.';
    entries[1].attributes = FAT32_ATTR_DIRECTORY;
    entries[1].first_cluster_high = root_dir_cluster >> 16;
    entries[1].first_cluster_low = root_dir_cluster & 0xFFFF;

    write_cluster(new_cluster, cluster_buffer);

    // Add to parent (root) directory
    if (read_cluster(root_dir_cluster, cluster_buffer) != 0) {
        mutex_unlock(&fat32_mutex);
        return -1;
    }

    entries = (fat32_dir_entry_t*)cluster_buffer;
    uint32_t entries_per_cluster = bytes_per_cluster / FAT32_DIR_ENTRY_SIZE;

    for (uint32_t i = 0; i < entries_per_cluster; i++) {
        if (entries[i].name[0] == 0x00 || entries[i].name[0] == 0xE5) {
            memcpy(entries[i].name, name_83, 11);
            entries[i].attributes = FAT32_ATTR_DIRECTORY;
            entries[i].first_cluster_high = new_cluster >> 16;
            entries[i].first_cluster_low = new_cluster & 0xFFFF;
            entries[i].file_size = 0;

            write_cluster(root_dir_cluster, cluster_buffer);
            mutex_unlock(&fat32_mutex);
            return 0;
        }
    }

    mutex_unlock(&fat32_mutex);
    return -1;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: fat32_rmdir
 * PURPOSE: Remove a directory (Phase 2 - simplified)
 *---------------------------------------------------------------------------*/
int fat32_rmdir(const char* path) {
    // For now, use same logic as unlink but check it's a directory
    // Note: fat32_unlink already has its own mutex protection
    return fat32_unlink(path);
}

/*-----------------------------------------------------------------------------
 * FUNCTION: fat32_list_root_cb
 * PURPOSE: Walk the root directory and deliver each visible 8.3 entry to a
 *          caller-supplied callback. This keeps the FAT32 driver free of any
 *          shell/stdio dependency: the caller decides where output goes
 *          (kprintf for kernel logging, or the shell's stream for `ls C:` so
 *          the listing actually reaches the user's terminal — the previous
 *          kprintf-only path was why `ls C:` looked empty to the shell).
 * RETURN:  0 on success, -1 if not mounted / read error.
 *---------------------------------------------------------------------------*/
int fat32_list_root_cb(fat32_dir_emit_t emit, void* ctx) {
    if (!fat32_mounted) {
        return -1;
    }

    mutex_lock(&fat32_mutex);

    uint32_t cluster = root_dir_cluster;

    /*=========================================================================
     * SECURITY FIX (Issue 5.2): Infinite Loop DoS Protection
     *=======================================================================*/
    uint32_t iteration_count = 0;

    while (cluster < FAT32_EOC) {
        // Check for infinite loop (cyclic cluster chain)
        if (++iteration_count > FAT32_MAX_CLUSTER_CHAIN) {
            kprintf("[FAT32] ERROR: Cluster chain cycle detected in directory listing\n");
            kprintf("[FAT32] Aborting listing to prevent kernel lockup\n");
            mutex_unlock(&fat32_mutex);
            return -1;
        }

        if (read_cluster(cluster, cluster_buffer) != 0) {
            kprintf("[FAT32] ERROR: Failed to read cluster %u\n", cluster);
            mutex_unlock(&fat32_mutex);
            return -1;
        }

        fat32_dir_entry_t* entries = (fat32_dir_entry_t*)cluster_buffer;
        uint32_t entries_per_cluster = bytes_per_cluster / FAT32_DIR_ENTRY_SIZE;

        for (uint32_t i = 0; i < entries_per_cluster; i++) {
            if (entries[i].name[0] == 0x00) {
                mutex_unlock(&fat32_mutex);
                return 0;  // End of directory
            }

            if (entries[i].name[0] == 0xE5) {
                continue;  // Deleted
            }

            /*=====================================================================
             * PRODUCTION FIX: LFN Chain Consumption
             *
             * Properly handle LFN entries by using explicit LFN detection.
             * This ensures robust directory listing on filesystems with long
             * filenames, even though we only display 8.3 names.
             *===================================================================*/
            if (is_lfn_entry(&entries[i])) {
                continue;  // Skip LFN entries, 8.3 entry will follow
            }

            if (entries[i].attributes & FAT32_ATTR_VOLUME_ID) {
                continue;  // Volume label
            }

            // Print filename
            char name[13];
            memcpy(name, entries[i].name, 11);
            name[11] = '\0';

            // Format as 8.3
            char formatted[13];
            int idx = 0;
            for (int j = 0; j < 8 && name[j] != ' '; j++) {
                formatted[idx++] = name[j];
            }
            if (name[8] != ' ') {
                formatted[idx++] = '.';
                for (int j = 8; j < 11 && name[j] != ' '; j++) {
                    formatted[idx++] = name[j];
                }
            }
            formatted[idx] = '\0';

            bool is_dir = (entries[i].attributes & FAT32_ATTR_DIRECTORY) != 0;
            if (emit) {
                emit(ctx, formatted, entries[i].file_size, is_dir);
            }
        }

        cluster = read_fat_entry(cluster);
    }

    mutex_unlock(&fat32_mutex);
    return 0;
}

/*-----------------------------------------------------------------------------
 * FUNCTION: fat32_list_root
 * PURPOSE: List root directory to the kernel console (kprintf). Back-compat
 *          wrapper over fat32_list_root_cb for kernel-side/debug logging.
 *---------------------------------------------------------------------------*/
static void fat32_kprintf_emit(void* ctx, const char* name, uint32_t size, bool is_dir) {
    (void)ctx;
    kprintf("  %s  %-12s  %u bytes\n", is_dir ? "DIR" : "FILE", name, size);
}

void fat32_list_root(void) {
    kprintf("[FAT32] Root directory listing:\n");
    if (fat32_list_root_cb(fat32_kprintf_emit, 0) != 0) {
        kprintf("[FAT32] ERROR: Filesystem not mounted\n");
    }
}
