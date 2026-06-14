/*=============================================================================
 * elf.h - ELF File Format Definitions and Loader Interface
 *=============================================================================*/
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*=============================================================================
 * ELF MAGIC NUMBER AND IDENTIFICATION
 *=============================================================================*/
#define ELF_MAGIC 0x464C457F  // "\x7FELF" in little-endian

/*=============================================================================
 * ELF CLASS (32-bit vs 64-bit)
 *=============================================================================*/
#define ELFCLASS32 1  // 32-bit objects
#define ELFCLASS64 2  // 64-bit objects

/*=============================================================================
 * ELF DATA ENCODING (Endianness)
 *=============================================================================*/
#define ELFDATA2LSB 1  // Little-endian
#define ELFDATA2MSB 2  // Big-endian

/*=============================================================================
 * ELF VERSION
 *=============================================================================*/
#define EV_CURRENT 1  // Current version

/*=============================================================================
 * ELF MACHINE TYPES
 *=============================================================================*/
#define EM_386 3  // Intel x86

/*=============================================================================
 * ELF FILE TYPES
 *=============================================================================*/
#define ET_NONE   0  // No file type
#define ET_REL    1  // Relocatable file
#define ET_EXEC   2  // Executable file
#define ET_DYN    3  // Shared object file
#define ET_CORE   4  // Core file

/*=============================================================================
 * PROGRAM HEADER TYPES
 *=============================================================================*/
#define PT_NULL    0  // Unused entry
#define PT_LOAD    1  // Loadable segment
#define PT_DYNAMIC 2  // Dynamic linking information
#define PT_INTERP  3  // Interpreter path
#define PT_NOTE    4  // Auxiliary information
#define PT_SHLIB   5  // Reserved
#define PT_PHDR    6  // Program header table

/*=============================================================================
 * PROGRAM HEADER FLAGS
 *=============================================================================*/
#define PF_X 0x1  // Executable
#define PF_W 0x2  // Writable
#define PF_R 0x4  // Readable

/*=============================================================================
 * SECTION HEADER TYPES
 *=============================================================================*/
#define SHT_NULL     0   // Unused
#define SHT_PROGBITS 1   // Program data
#define SHT_SYMTAB   2   // Symbol table
#define SHT_STRTAB   3   // String table
#define SHT_RELA     4   // Relocation entries with addends
#define SHT_HASH     5   // Symbol hash table
#define SHT_DYNAMIC  6   // Dynamic linking information
#define SHT_NOTE     7   // Notes
#define SHT_NOBITS   8   // Uninitialized space (BSS)
#define SHT_REL      9   // Relocation entries
#define SHT_SHLIB    10  // Reserved
#define SHT_DYNSYM   11  // Dynamic symbol table

/*=============================================================================
 * ELF32 HEADER (52 bytes)
 *=============================================================================*/
typedef struct {
    uint8_t  e_ident[16];    // Magic number and other info
    uint16_t e_type;         // Object file type
    uint16_t e_machine;      // Architecture
    uint32_t e_version;      // Object file version
    uint32_t e_entry;        // Entry point virtual address
    uint32_t e_phoff;        // Program header table file offset
    uint32_t e_shoff;        // Section header table file offset
    uint32_t e_flags;        // Processor-specific flags
    uint16_t e_ehsize;       // ELF header size in bytes
    uint16_t e_phentsize;    // Program header table entry size
    uint16_t e_phnum;        // Program header table entry count
    uint16_t e_shentsize;    // Section header table entry size
    uint16_t e_shnum;        // Section header table entry count
    uint16_t e_shstrndx;     // Section header string table index
} __attribute__((packed)) elf32_ehdr_t;

/*=============================================================================
 * ELF32 PROGRAM HEADER (32 bytes)
 *=============================================================================*/
typedef struct {
    uint32_t p_type;    // Segment type
    uint32_t p_offset;  // Segment file offset
    uint32_t p_vaddr;   // Segment virtual address
    uint32_t p_paddr;   // Segment physical address
    uint32_t p_filesz;  // Segment size in file
    uint32_t p_memsz;   // Segment size in memory
    uint32_t p_flags;   // Segment flags
    uint32_t p_align;   // Segment alignment
} __attribute__((packed)) elf32_phdr_t;

/*=============================================================================
 * ELF32 SECTION HEADER (40 bytes)
 *=============================================================================*/
typedef struct {
    uint32_t sh_name;      // Section name (string table index)
    uint32_t sh_type;      // Section type
    uint32_t sh_flags;     // Section flags
    uint32_t sh_addr;      // Section virtual address at execution
    uint32_t sh_offset;    // Section file offset
    uint32_t sh_size;      // Section size in bytes
    uint32_t sh_link;      // Link to another section
    uint32_t sh_info;      // Additional section information
    uint32_t sh_addralign; // Section alignment
    uint32_t sh_entsize;   // Entry size if section holds table
} __attribute__((packed)) elf32_shdr_t;

/*=============================================================================
 * ELF E_IDENT INDICES
 *=============================================================================*/
#define EI_MAG0    0  // File identification byte 0 index
#define EI_MAG1    1  // File identification byte 1 index
#define EI_MAG2    2  // File identification byte 2 index
#define EI_MAG3    3  // File identification byte 3 index
#define EI_CLASS   4  // File class byte index
#define EI_DATA    5  // Data encoding byte index
#define EI_VERSION 6  // File version byte index
#define EI_PAD     7  // Byte index of padding bytes

/*=============================================================================
 * ELF LOADER FUNCTIONS
 *=============================================================================*/

/**
 * @brief Validate ELF header
 * @param elf_data Pointer to ELF file data in memory
 * @return true if valid ELF32 x86 executable, false otherwise
 */
bool elf_validate(const void* elf_data);

/**
 * @brief Verify ECDSA P-256 signature on ELF binary
 * @param elf_data Pointer to ELF file data in memory (may include appended signature)
 * @param elf_size Total size of ELF file buffer (including signature if present)
 * @return true if valid signature found and verified, false otherwise
 */
bool elf_verify_signature(const void* elf_data, size_t elf_size);

/**
 * @brief Load ELF executable and create a process
 * @param elf_data Pointer to ELF file data in memory
 * @param elf_size Actual size of ELF file buffer (SECURITY: prevents out-of-bounds reads)
 * @param name Name for the process
 * @return Process ID (PID) on success, -1 on failure
 */
int elf_load_process(const void* elf_data, size_t elf_size, const char* name);

/**
 * @brief Get entry point address from ELF
 * @param elf_data Pointer to ELF file data in memory
 * @return Entry point virtual address, or 0 on error
 */
uint32_t elf_get_entry(const void* elf_data);

/**
 * @brief Print ELF header information (debug)
 * @param elf_data Pointer to ELF file data in memory
 */
void elf_dump_header(const void* elf_data);
