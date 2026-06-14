/*=============================================================================
 * elf.c - ELF File Format Loader Implementation
 *=============================================================================*/
#include "elf.h"
#include "kprintf.h"
#include "process.h"
#include "pmm.h"
#include "paging.h"
#include "util.h"
#include "ramfs.h"  /* PHASE 13: For close-on-exec FD cleanup */
#include "ecdsa.h"  /* PHASE 17: ELF signature verification */
#include "sha256.h" /* PHASE 17: Hash computation */
#include "secure_boot.h" /* Pinned trusted signing key */
#include "critical.h"    /* disable_interrupts/restore_interrupts around ecdsa_verify */
#include <stddef.h>

/*=============================================================================
 * ELF Signature Format Constants
 *=============================================================================*/
#define ELF_SIG_MAGIC "TINYOS_SIG_V1\x00\x00\x00"
#define ELF_SIG_SIZE 184  /* magic(16) + offset(4) + size(4) + pubkey(64) + sig(64) + hash(32) */

/* ELF signature structure (packed, little-endian for x86) */
typedef struct __attribute__((packed)) {
    uint8_t magic[16];           /* "TINYOS_SIG_V1\0\0\0" */
    uint32_t sig_offset;         /* Offset to signature data from file start */
    uint32_t elf_size;           /* Size of ELF without signature */
    uint8_t pub_key_x[32];       /* Public key X coordinate (big-endian) */
    uint8_t pub_key_y[32];       /* Public key Y coordinate (big-endian) */
    uint8_t signature_r[32];     /* Signature R component (big-endian) */
    uint8_t signature_s[32];     /* Signature S component (big-endian) */
    uint8_t hash[32];            /* SHA-256 hash of ELF */
} elf_signature_t;

/*=============================================================================
 * FUNCTION: elf_validate
 * PURPOSE: Validate ELF header
 *=============================================================================*/
bool elf_validate(const void* elf_data) {
    if (!elf_data) {
        kprintf("[ELF] ERROR: NULL elf_data\n");
        return false;
    }

    const elf32_ehdr_t* ehdr = (const elf32_ehdr_t*)elf_data;

    // Check magic number
    if (ehdr->e_ident[EI_MAG0] != 0x7F ||
        ehdr->e_ident[EI_MAG1] != 'E' ||
        ehdr->e_ident[EI_MAG2] != 'L' ||
        ehdr->e_ident[EI_MAG3] != 'F') {
        kprintf("[ELF] ERROR: Invalid ELF magic number\n");
        return false;
    }

    // Check 32-bit
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS32) {
        kprintf("[ELF] ERROR: Not a 32-bit ELF file\n");
        return false;
    }

    // Check little-endian
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        kprintf("[ELF] ERROR: Not little-endian\n");
        return false;
    }

    // Check version
    if (ehdr->e_ident[EI_VERSION] != EV_CURRENT) {
        kprintf("[ELF] ERROR: Invalid ELF version\n");
        return false;
    }

    // Check machine type (x86)
    if (ehdr->e_machine != EM_386) {
        kprintf("[ELF] ERROR: Not an x86 executable (machine=%d)\n", ehdr->e_machine);
        return false;
    }

    // Check file type (executable)
    if (ehdr->e_type != ET_EXEC) {
        kprintf("[ELF] ERROR: Not an executable file (type=%d)\n", ehdr->e_type);
        return false;
    }

    // Check entry point
    if (ehdr->e_entry == 0) {
        kprintf("[ELF] ERROR: No entry point\n");
        return false;
    }

    kprintf("[ELF] Validation passed: 32-bit x86 executable\n");
    return true;
}

/*=============================================================================
 * FUNCTION: elf_get_entry
 * PURPOSE: Get entry point address from ELF
 *=============================================================================*/
uint32_t elf_get_entry(const void* elf_data) {
    if (!elf_data) {
        return 0;
    }

    const elf32_ehdr_t* ehdr = (const elf32_ehdr_t*)elf_data;
    return ehdr->e_entry;
}

/*=============================================================================
 * FUNCTION: elf_dump_header
 * PURPOSE: Print ELF header information (debug)
 *=============================================================================*/
void elf_dump_header(const void* elf_data) {
    if (!elf_data) {
        kprintf("[ELF] Cannot dump NULL header\n");
        return;
    }

    const elf32_ehdr_t* ehdr = (const elf32_ehdr_t*)elf_data;

    kprintf("\n=== ELF HEADER ===\n");
    kprintf("Magic:       0x%02x %c%c%c\n",
            ehdr->e_ident[EI_MAG0],
            ehdr->e_ident[EI_MAG1],
            ehdr->e_ident[EI_MAG2],
            ehdr->e_ident[EI_MAG3]);
    kprintf("Class:       %s\n", ehdr->e_ident[EI_CLASS] == ELFCLASS32 ? "32-bit" : "64-bit");
    kprintf("Data:        %s\n", ehdr->e_ident[EI_DATA] == ELFDATA2LSB ? "Little-endian" : "Big-endian");
    kprintf("Type:        %d (", ehdr->e_type);
    switch (ehdr->e_type) {
        case ET_NONE: kprintf("None"); break;
        case ET_REL:  kprintf("Relocatable"); break;
        case ET_EXEC: kprintf("Executable"); break;
        case ET_DYN:  kprintf("Shared object"); break;
        case ET_CORE: kprintf("Core"); break;
        default:      kprintf("Unknown"); break;
    }
    kprintf(")\n");
    kprintf("Machine:     %d (", ehdr->e_machine);
    if (ehdr->e_machine == EM_386) {
        kprintf("Intel x86");
    } else {
        kprintf("Unknown");
    }
    kprintf(")\n");
    kprintf("Entry:       0x%08x\n", ehdr->e_entry);
    kprintf("Prog Hdr:    offset=0x%08x, count=%d, size=%d\n",
            ehdr->e_phoff, ehdr->e_phnum, ehdr->e_phentsize);
    kprintf("Sect Hdr:    offset=0x%08x, count=%d, size=%d\n",
            ehdr->e_shoff, ehdr->e_shnum, ehdr->e_shentsize);
    kprintf("==================\n\n");
}

/*=============================================================================
 * FUNCTION: elf_verify_signature
 * PURPOSE: Verify ECDSA P-256 signature on ELF binary
 *===========================================================================*/
bool elf_verify_signature(const void* elf_data, size_t elf_size) {
    /* Check if file is large enough to contain signature */
    if (elf_size < ELF_SIG_SIZE) {
        kprintf("[ELF] No signature (file too small: %zu < %d)\n", elf_size, ELF_SIG_SIZE);
        return false;
    }

    /* Extract signature from end of file */
    const uint8_t* file_end = (const uint8_t*)elf_data + elf_size;
    const elf_signature_t* sig = (const elf_signature_t*)(file_end - ELF_SIG_SIZE);

    /* Check magic */
    if (memcmp(sig->magic, ELF_SIG_MAGIC, 16) != 0) {
        kprintf("[ELF] No valid signature magic found\n");
        return false;
    }

    /* Verify ELF size matches signature */
    if ((uint64_t)sig->elf_size + ELF_SIG_SIZE != (uint64_t)elf_size) {
        kprintf("[ELF] Size mismatch: sig says %u, actual %zu\n",
                sig->elf_size, elf_size - ELF_SIG_SIZE);
        return false;
    }

    kprintf("[ELF] Found signature (offset=%u, elf_size=%u)\n",
            sig->sig_offset, sig->elf_size);

    /* Compute SHA-256 hash of ELF (without signature) with interrupts MASKED.
     *
     * ROOT CAUSE (proven 2026-06-14): the intermittent "first exec after login
     * fails with Hash mismatch" was NOT exec_buffer corruption — a timing-neutral
     * per-page checksum showed the input buffer is byte-for-byte CORRECT on a
     * failing run (all page-sums match a passing run), yet sha256() produced a
     * wrong (and run-to-run DIFFERENT) digest. The hash's in-flight state lives
     * in a stack-local sha256_ctx_t (state[8] + 64-byte block) across
     * init/update/final; an IRQ / softirq / context-switch preempting this
     * long-running computation corrupts that working state — the same
     * preemption-corruption class already masked for ecdsa_verify (just below)
     * and PBKDF2 (user.c). Run the digest non-preemptibly. exec-time signature
     * checking is a one-shot cold path, so masking for its duration is fine. */
    uint8_t computed_hash[32];
    uint32_t hash_flags = disable_interrupts();
    sha256((const uint8_t*)elf_data, sig->elf_size, computed_hash);
    restore_interrupts(hash_flags);

    /* Verify hash matches */
    if (memcmp(computed_hash, sig->hash, 32) != 0) {
        kprintf("[ELF] ERROR: Hash mismatch!\n");
        kprintf("[ELF]   Stored:   ");
        for (int i = 0; i < 32; i++) kprintf("%02x", sig->hash[i]);
        kprintf("\n[ELF]   Computed: ");
        for (int i = 0; i < 32; i++) kprintf("%02x", computed_hash[i]);
        kprintf("\n");
        return false;
    }

    kprintf("[ELF] Hash verification: PASS\n");

    /* SECURITY: Pin the verification key. The trailer carries the signer's
     * public key, but an attacker controls the trailer; only accept the
     * trusted key configured via secure boot. */
    secure_boot_config_t sb_config;
    secure_boot_get_config(&sb_config);
    if (!sb_config.initialized) {
        kprintf("[ELF] ERROR: No trusted signing key configured\n");
        return false;
    }
    if (memcmp(sig->pub_key_x, sb_config.public_key, 32) != 0 ||
        memcmp(sig->pub_key_y, sb_config.public_key + 32, 32) != 0) {
        kprintf("[ELF] ERROR: Signature public key does not match trusted key\n");
        return false;
    }

    /* Import public key from signature */
    p256_point_t public_key;
    ecdsa_import_public_key(&public_key, sig->pub_key_x);

    /* Import signature (r, s) */
    ecdsa_signature_t signature;
    ecdsa_import_signature(&signature, sig->signature_r);

    /* Verify ECDSA signature with interrupts MASKED.
     *
     * The P-256 math is correct (validated on host and on-target), but a
     * long-running verify preempted mid-flight comes back with corrupted
     * intermediate state — non-deterministic wrong results or a #UD on a
     * clobbered return address. Same hazard as the PBKDF2 path in user.c;
     * the proven fix is to run the derivation non-preemptibly. exec-time
     * signature checking is a one-shot, non-hot path, so masking for the
     * duration is acceptable. This is what makes -DELF_ENFORCE_SIGNATURES
     * usable. */
    uint32_t verify_flags = disable_interrupts();
    bool valid = ecdsa_verify(&signature, computed_hash, &public_key);
    restore_interrupts(verify_flags);

    if (valid) {
        kprintf("[ELF] Signature verification: PASS\n");
        kprintf("[ELF] Public key X: ");
        for (int i = 0; i < 8; i++) kprintf("%02x", sig->pub_key_x[i]);
        kprintf("...\n");
    } else {
        kprintf("[ELF] ERROR: Signature verification FAILED!\n");
    }

    return valid;
}

/*=============================================================================
 * FUNCTION: elf_load_process
 * PURPOSE: Load ELF executable and create a process
 *=============================================================================*/
int elf_load_process(const void* elf_data, size_t elf_size, const char* name) {
    kprintf("[ELF] Loading process '%s' (file size: %zu bytes)...\n", name, elf_size);

    /*=========================================================================
     * SECURITY FIX: Validate Actual File Size
     * CRITICAL: Previous code used ELF_MAX_PHOFF (1MB) as surrogate for file
     * size, creating "read arbitrary kernel memory" vulnerability:
     *
     * Attack scenario without this check:
     * 1. Attacker creates 64KB ELF file with offset=128KB, filesz=32KB
     * 2. File passes offset < ELF_MAX_PHOFF check (128KB < 1MB )
     * 3. memcpy(dest, elf_data + 128KB, 32KB) reads 32KB *past* the buffer
     * 4. Kernel memory (potentially containing crypto keys, passwords, etc.)
     *    gets copied into attacker's process address space
     * 5. Attacker reads /proc/self/mem → arbitrary kernel memory disclosure
     *
     * The fix: Use ACTUAL file size, not synthetic limit. ELF_MAX_PHOFF
     * remains as secondary sanity bound ("also require <= 1MB"), but we
     * validate against elf_size first.
     *=======================================================================*/

    /* Validate minimum ELF size (header must fit) */
    if (elf_size < sizeof(elf32_ehdr_t)) {
        kprintf("[ELF] SECURITY: File too small for ELF header (%zu bytes)\n", elf_size);
        return -1;
    }

    /* Enforce maximum file size (defense in depth) */
    #define ELF_MAX_FILE_SIZE (1024 * 1024)  // 1MB
    if (elf_size > ELF_MAX_FILE_SIZE) {
        kprintf("[ELF] SECURITY: File exceeds maximum size (%zu > %u)\n",
                elf_size, ELF_MAX_FILE_SIZE);
        return -1;
    }

    // Validate ELF
    if (!elf_validate(elf_data)) {
        kprintf("[ELF] Validation failed\n");
        return -1;
    }

    /*=========================================================================
     * PHASE 17: ELF Signature Verification (Modern Linux Signed Module Feature)
     *
     * TRADITIONAL WEAKNESS:
     * - Any binary can be loaded and executed
     * - Malware/rootkits can be loaded if attacker gains write access
     * - No verification of binary integrity or authenticity
     *
     * MODERN LINUX SOLUTION:
     * - Signed kernel modules (CONFIG_MODULE_SIG)
     * - Requires digital signature on all loadable code
     * - Uses X.509 certificates and RSA/ECDSA signatures
     * - Prevents loading of unsigned/modified binaries
     *
     * TINYOS IMPLEMENTATION:
     * - ECDSA P-256 signature verification for ELF binaries
     * - Signature appended to end of ELF file (184-byte structure)
     * - PERMISSIVE MODE: Warns but allows unsigned binaries
     * - ENFORCE MODE: Set elf_require_signatures = true to block unsigned
     *
     * SECURITY BENEFITS:
     * - Prevents loading of tampered binaries
     * - Detects rootkits and malware
     * - Ensures only trusted code executes
     * - Complements secure boot chain
     *
     * IMPLEMENTATION: Full ECDSA verification using ecdsa.c
     *=======================================================================*/
    /*
     * ENFORCED (fail-closed) by default: unsigned or tampered binaries are
     * rejected. The P-256 verify runs interrupts-masked (elf_verify_signature),
     * which fixed the preemption-corruption that used to #UD mid-verify, so
     * enforcement works end to end (verified in QEMU: hash PASS -> signature
     * PASS -> binary runs). The embedded userspace binaries (hello/shell) carry
     * a TINYOS_SIG_V1 trailer signed by the pinned trusted key, so a normal
     * build still boots and execs them.
     *
     * The masked verify is milliseconds on real hardware but minutes under
     * TCG/QEMU. For fast local dev that can tolerate running unsigned binaries,
     * build with -DELF_PERMISSIVE_SIGNATURES to downgrade to warn-and-load.
     * That opt-out is deliberately named and must never be the default.
     */
#ifdef ELF_PERMISSIVE_SIGNATURES
    static bool elf_require_signatures = false;
#else
    static bool elf_require_signatures = true;
#endif

    /* Verify signature (skipped only in the explicit permissive opt-out) */
    bool has_valid_signature = elf_require_signatures
                                   ? elf_verify_signature(elf_data, elf_size)
                                   : false;

    if (has_valid_signature) {
        kprintf("[ELF]  Binary '%s' has valid ECDSA signature\n", name);
    } else {
        /* No signature or verification failed */
        if (elf_require_signatures) {
            /* ENFORCE mode: Block unsigned/invalid binaries */
            kprintf("[ELF] SECURITY: Rejecting unsigned/invalid binary '%s'\n", name);
            kprintf("[ELF] ERROR: Signature verification required (enforce mode)\n");
            kprintf("[ELF] HINT: Sign with tools/sign_elf.py\n");
            return -1;
        } else {
            /* PERMISSIVE mode: Warn but allow */
            kprintf("[ELF] WARNING: Loading unsigned binary '%s' (permissive mode)\n", name);
        }
    }

    // Dump header for debugging
    elf_dump_header(elf_data);

    const elf32_ehdr_t* ehdr = (const elf32_ehdr_t*)elf_data;

    /*=========================================================================
     * SECURITY: Validate Program Header Count and Size
     * CRITICAL: Attacker-controlled e_phnum could cause out-of-bounds access
     * or resource exhaustion. Limit to reasonable maximum (typical binaries
     * have < 10 program headers; 128 is extremely generous upper bound).
     *=========================================================================*/
    #define ELF_MAX_PROGRAM_HEADERS 128

    if (ehdr->e_phnum == 0 || ehdr->e_phnum > ELF_MAX_PROGRAM_HEADERS) {
        kprintf("[ELF] SECURITY: Invalid program header count: %d (max %d)\n",
                ehdr->e_phnum, ELF_MAX_PROGRAM_HEADERS);
        return -1;
    }

    /*=========================================================================
     * SECURITY: Validate Program Header Entry Size
     * CRITICAL: e_phentsize must match expected sizeof(elf32_phdr_t) to
     * prevent mis-parsing of header structures.
     *=========================================================================*/
    if (ehdr->e_phentsize != sizeof(elf32_phdr_t)) {
        kprintf("[ELF] SECURITY: Invalid program header entry size: %d (expected %d)\n",
                ehdr->e_phentsize, sizeof(elf32_phdr_t));
        return -1;
    }

    /*=========================================================================
     * SECURITY: Validate Program Header Offset
     * CRITICAL: e_phoff must be within reasonable bounds to prevent:
     * 1. Integer overflow when calculating phdr pointer
     * 2. Reading program headers from beyond ELF file buffer
     * 3. Pointer wrapping to low memory addresses
     *
     * We enforce conservative limit: phoff < 1MB (typical ELFs have phoff
     * around 52-64 bytes for headers at start of file).
     *=========================================================================*/
    #define ELF_MAX_PHOFF (1024 * 1024)  // 1MB

    if (ehdr->e_phoff == 0 || ehdr->e_phoff > ELF_MAX_PHOFF) {
        kprintf("[ELF] SECURITY: Invalid program header offset: 0x%x (max 0x%x)\n",
                ehdr->e_phoff, ELF_MAX_PHOFF);
        return -1;
    }

    /*=========================================================================
     * SECURITY: Validate Program Header Table Size
     * CRITICAL: Ensure e_phoff + (e_phnum * e_phentsize) doesn't overflow
     * and remains within reasonable file size bounds.
     *=========================================================================*/
    uint32_t phdr_table_size = ehdr->e_phnum * ehdr->e_phentsize;
    if (phdr_table_size > ELF_MAX_PHOFF ||  // Sanity check
        ehdr->e_phoff > (ELF_MAX_PHOFF - phdr_table_size)) {  // Overflow check
        kprintf("[ELF] SECURITY: Program header table extends beyond safe bounds\n");
        return -1;
    }

    const elf32_phdr_t* phdr = (const elf32_phdr_t*)((uint8_t*)elf_data + ehdr->e_phoff);

    kprintf("[ELF] Found %d program headers\n", ehdr->e_phnum);

    /*=========================================================================
     * SECURITY: Memory Limits for Process Segments
     * CRITICAL: Prevent resource exhaustion by limiting total memory per
     * process and validating that all segments are in user space.
     *=========================================================================*/
    #define ELF_USER_SPACE_END 0xC0000000  // Kernel starts at 3GB
    #define ELF_MAX_PROCESS_MEMORY (16 * 1024 * 1024)  // 16MB per process

    // Find highest virtual address to determine total memory needed
    uint32_t min_vaddr = 0xFFFFFFFF;
    uint32_t max_vaddr = 0;
    uint32_t total_mem = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            uint32_t start = phdr[i].p_vaddr;
            uint32_t memsz = phdr[i].p_memsz;
            uint32_t filesz = phdr[i].p_filesz;
            uint32_t offset = phdr[i].p_offset;

            /*=================================================================
             * SECURITY: Validate User Space Address Range
             * CRITICAL: Prevent mapping segments into kernel space (>= 3GB).
             *=================================================================*/
            if (start >= ELF_USER_SPACE_END) {
                kprintf("[ELF] SECURITY: Segment %d starts in kernel space: 0x%x\n",
                        i, start);
                return -1;
            }

            /*=================================================================
             * SECURITY: Validate Integer Overflow in Address Calculations
             * CRITICAL: start + memsz must not overflow or wrap into kernel
             * space. This prevents:
             * 1. end address wrapping around to low memory
             * 2. Segment extending into kernel space via overflow
             *=================================================================*/
            if (memsz > (ELF_USER_SPACE_END - start)) {
                kprintf("[ELF] SECURITY: Segment %d extends beyond user space (overflow)\n", i);
                return -1;
            }

            uint32_t end = start + memsz;  // Now safe - cannot overflow

            /*=================================================================
             * SECURITY: Validate File Size vs Memory Size
             * CRITICAL: filesz must not exceed memsz (BSS validation).
             *=================================================================*/
            if (filesz > memsz) {
                kprintf("[ELF] SECURITY: Segment %d has filesz > memsz\n", i);
                return -1;
            }

            /*=================================================================
             * SECURITY FIX (AUDIT 8D): Null Page Protection
             *
             * VULNERABILITY: Null Pointer Dereference Exploitation
             *
             * PROBLEM: Segments Can Be Mapped at Address 0x0
             * The ELF loader does not validate that segments start above the
             * "null page" region (typically first 4KB of virtual address space).
             * Modern operating systems leave this region unmapped to catch
             * null pointer dereferences at runtime.
             *
             * ATTACK SCENARIO: Weaponizing Null Pointer Bugs
             * 1. Attacker finds null pointer dereference in kernel code:
             *    struct ops *ptr = NULL;
             *    ptr->callback();  // Dereferences offset +0x10 from NULL
             * 2. Attacker crafts ELF with PT_LOAD segment at vaddr=0x0
             * 3. ELF maps attacker-controlled shellcode at address 0x0
             * 4. Kernel dereferences NULL + offset
             * 5. CPU fetches from attacker's mapped page instead of faulting
             * 6. Shellcode executes with kernel privileges
             *
             * REAL-WORLD EXAMPLES:
             * - CVE-2009-2692: Linux sock_sendpage NULL deref → root exploit
             * - CVE-2010-2959: Linux CAN protocol NULL deref → privilege escalation
             * - Android mmap(0) abuse for kernel exploits (pre-4.x)
             *
             * FIX: Reject Segments Below Minimum User Address
             * - Define USER_MIN_ADDR = 0x1000 (4KB, one page)
             * - Reject any PT_LOAD segment with vaddr < USER_MIN_ADDR
             * - Prevents attacker from mapping executable code at low addresses
             *
             * LIMITATION: Does not protect against kernel bugs that:
             * - Dereference offsets > 4KB (e.g., ptr->field_at_offset_8KB)
             * - Use mmap() directly to map null page (requires separate fix)
             *
             * REFERENCES:
             * - CVE-2009-2692: Linux sock_sendpage Exploit
             * - ASLR Bypass Techniques via NULL Page Mapping
             * - PaX Project: MPROTECT and PAGEEXEC
             *===============================================================*/

            #define USER_MIN_ADDR 0x1000  /* 4KB - protect null page */

            /* Check if segment starts in null page region */
            if (start < USER_MIN_ADDR) {
                kprintf("[ELF] SECURITY: Segment %d maps null page (vaddr=0x%08x < 0x%08x)\n",
                        i, start, USER_MIN_ADDR);
                return -1;
            }

            /* Also check if segment extends into null page from above */
            if (start < USER_MIN_ADDR + memsz && start + memsz > USER_MIN_ADDR) {
                if (start + memsz < USER_MIN_ADDR) {
                    /* Wraparound check: start + memsz wrapped to small value */
                    kprintf("[ELF] SECURITY: Segment %d wraps into null page\n", i);
                    return -1;
                }
            }

            /*=================================================================
             * SECURITY: Validate File Offset Against Actual File Size
             * CRITICAL: Prevent reading beyond ELF file buffer. This check
             * uses the actual file size instead of a synthetic limit to
             * ensure we never read past the end of the buffer.
             *
             * Attack scenario: Attacker creates 64KB ELF with offset=128KB,
             * filesz=32KB. Without this check, memcpy() would read 32KB past
             * the buffer end, potentially leaking kernel memory (crypto keys,
             * passwords) into the process address space.
             *=================================================================*/
            if (offset > elf_size || filesz > (elf_size - offset)) {
                kprintf("[ELF] SECURITY: Segment %d file offset/size exceeds file bounds\n", i);
                return -1;
            }

            if (start < min_vaddr) min_vaddr = start;
            if (end > max_vaddr) max_vaddr = end;

            kprintf("[ELF]   LOAD segment %d: vaddr=0x%08x memsz=0x%x filesz=0x%x flags=0x%x\n",
                    i, phdr[i].p_vaddr, phdr[i].p_memsz, phdr[i].p_filesz, phdr[i].p_flags);
        }
    }

    /*=========================================================================
     * SECURITY FIX (AUDIT 7B): ELF Segment Overlap Detection
     *
     * VULNERABILITY: Time-of-Check to Time-of-Use (ToCToU) Overlapping Segments
     *
     * PROBLEM: No Validation of Segment Overlap
     * The ELF loader validates each segment individually but does not check
     * if multiple PT_LOAD segments map to the same virtual address range.
     *
     * ATTACK SCENARIO: W^X Bypass via Overlapping Segments
     * 1. Attacker crafts ELF with two PT_LOAD segments:
     *    - Segment A: vaddr=0x08048000, memsz=0x1000, flags=PF_R|PF_X (RX, code)
     *    - Segment B: vaddr=0x08048000, memsz=0x1000, flags=PF_R|PF_W (RW, data)
     * 2. Kernel loads Segment A, marks pages as Read+Execute
     * 3. Kernel loads Segment B at SAME address, overwrites with attacker data
     * 4. Pages remain executable (from Segment A) but now contain shellcode
     * 5. Result: W^X protection bypassed, executable shellcode in "data" pages
     *
     * ALTERNATIVE ATTACK: Partial Overlap
     * 1. Segment A: vaddr=0x08048000, memsz=0x2000 (code section)
     * 2. Segment B: vaddr=0x08048800, memsz=0x1000 (overlaps last half)
     * 3. Segment B partially overwrites Segment A's code
     * 4. Result: Corrupted code execution, possible ROP gadget injection
     *
     * FIX: Detect and Reject Overlapping Segments
     * For each PT_LOAD segment, check if it overlaps with any previous segment:
     * - Two ranges [A_start, A_end) and [B_start, B_end) overlap if:
     *   (A_start < B_end) AND (B_start < A_end)
     * - Reject ELF if any overlap detected
     *
     * REFERENCES:
     * - ELF Specification: PT_LOAD segments must not overlap
     * - W^X (Write XOR Execute): Memory pages cannot be both writable and executable
     *=========================================================================*/
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) continue;
        uint32_t seg_i_start = phdr[i].p_vaddr;
        uint32_t seg_i_end = seg_i_start + phdr[i].p_memsz;

        /* Check for overlap with all subsequent segments */
        for (int j = i + 1; j < ehdr->e_phnum; j++) {
            if (phdr[j].p_type != PT_LOAD) continue;
            uint32_t seg_j_start = phdr[j].p_vaddr;
            uint32_t seg_j_end = seg_j_start + phdr[j].p_memsz;

            /* Overlap condition: (seg_i_start < seg_j_end) AND (seg_j_start < seg_i_end) */
            if (seg_i_start < seg_j_end && seg_j_start < seg_i_end) {
                kprintf("[ELF] SECURITY: Segments %d and %d overlap!\n", i, j);
                kprintf("[ELF]   Segment %d: [0x%08x - 0x%08x)\n", i, seg_i_start, seg_i_end);
                kprintf("[ELF]   Segment %d: [0x%08x - 0x%08x)\n", j, seg_j_start, seg_j_end);
                return -1;
            }
        }
    }

    /*=========================================================================
     * SECURITY: Validate Total Process Memory
     * CRITICAL: Prevent single process from exhausting all physical memory.
     *=========================================================================*/
    total_mem = max_vaddr - min_vaddr;

    if (total_mem > ELF_MAX_PROCESS_MEMORY) {
        kprintf("[ELF] SECURITY: Process memory exceeds limit: %u bytes (max %u)\n",
                total_mem, ELF_MAX_PROCESS_MEMORY);
        return -1;
    }

    kprintf("[ELF] Memory range: 0x%08x - 0x%08x (total: %d bytes)\n",
            min_vaddr, max_vaddr, total_mem);

    // Create process FIRST so we have a user page directory to map into
    kprintf("[ELF] Creating process with entry point 0x%08x\n", ehdr->e_entry);
    int pid = task_create_user((uint32_t)ehdr->e_entry, name);
    if (pid < 0) {
        kprintf("[ELF] ERROR: Failed to create process\n");
        return -1;
    }

    // Get the task to access its page directory. Use task_get_any (no state
    // filter): we just created this PID and own it. A plain task_get would
    // return NULL if the brand-new task was flipped to TERMINATED in this
    // window (e.g. an EDR periodic check on the timer softirq flagged it),
    // which previously aborted exec with a misleading "Failed to get task
    // structure" even though the task existed.
    task_t* task = task_get_any(pid);
    if (!task) {
        kprintf("[ELF] ERROR: Failed to get task structure (pid=%d)\n", pid);
        return -1;
    }
    if (task->state == TASK_STATE_TERMINATED) {
        /* The fresh task was killed during load (likely an EDR false positive
         * on a not-yet-running process). Don't map an ELF into a dead task;
         * report clearly. The terminated slot is reclaimed by the scheduler. */
        kprintf("[ELF] ERROR: task pid=%d was terminated during load (EDR?) — aborting exec\n", pid);
        return -1;
    }

    // Save current CR3 (kernel page directory)
    uint32_t kernel_cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(kernel_cr3));

    // Switch to user page directory to map pages there
    kprintf("[ELF] Switching to user page directory (CR3=0x%08x)\n", task->page_directory);
    __asm__ volatile("mov %0, %%cr3" :: "r"(task->page_directory) : "memory");

    /*=========================================================================
     * SECURITY FIX: Resource Leak Prevention on Partial Load Failure
     * CRITICAL: Track all allocated physical pages so we can free them if
     * a later segment fails to allocate. Without this, an attacker can:
     *
     * 1. Create ELF with multiple PT_LOAD segments
     * 2. First segment(s) allocate successfully (e.g., 100 pages)
     * 3. Later segment fails (pmm_alloc() returns 0 due to exhaustion)
     * 4. elf_load_process() returns -1, but allocated pages are never freed
     * 5. Repeat attack → slow memory leak exhausts all physical memory
     *
     * We use a simple array to track all allocated physical frames. On any
     * error, we free all frames before returning. Maximum 4096 pages tracked
     * (16MB worth), which matches our ELF_MAX_PROCESS_MEMORY limit.
     *=========================================================================*/
    #define MAX_TRACKED_PAGES 4096
    /* Static, not stack: a 16KB array would overflow the caller's kernel-task
     * stack (cmd_exec -> elf_load_process -> ECDSA verify is a deep chain).
     * elf_load_process is only invoked from the single-threaded shell. */
    static uint32_t allocated_frames[MAX_TRACKED_PAGES];
    uint32_t num_allocated = 0;

    // Allocate memory for each LOAD segment
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) {
            continue;
        }

        uint32_t vaddr = phdr[i].p_vaddr;
        uint32_t memsz = phdr[i].p_memsz;
        uint32_t filesz = phdr[i].p_filesz;
        uint32_t offset = phdr[i].p_offset;
        uint32_t p_flags = phdr[i].p_flags;

        /*=====================================================================
         * SECURITY FIX (AUDIT 8C): W^X Protection - Parse ELF p_flags
         *
         * VULNERABILITY: All Segments Mapped as Writable+Executable
         *
         * PROBLEM: Hardcoded Page Table Flags Ignore ELF Permissions
         * The original code used hardcoded flags 0x7 (PRESENT | READWRITE | USER)
         * for all segments, making both .text (code) and .data sections writable.
         * This violates the W^X (Write XOR Execute) security principle.
         *
         * ELF p_flags Field (Program Header):
         * - PF_X (0x1) = Segment is executable
         * - PF_W (0x2) = Segment is writable
         * - PF_R (0x4) = Segment is readable
         *
         * x86 Page Table Flags (32-bit):
         * - PAGE_PRESENT (0x1) = Page is present in memory
         * - PAGE_READWRITE (0x2) = Page is writable (R/W bit)
         * - PAGE_USER (0x4) = Accessible from user mode (U/S bit)
         *
         * ATTACK SCENARIO WITHOUT W^X:
         * 1. Attacker exploits buffer overflow in .data section
         * 2. Overwrites .text section with shellcode
         * 3. Redirects execution to modified .text
         * 4. Gains arbitrary code execution
         *
         * FIX: Map Pages According to ELF p_flags
         * - Read p_flags from program header
         * - Set PAGE_READWRITE only if PF_W (writable) is set
         * - Always set PAGE_PRESENT | PAGE_USER for user processes
         *
         * LIMITATION: x86-32 without PAE has no NX (No Execute) bit
         * - Cannot enforce execute-disable at hardware level
         * - All readable pages are implicitly executable
         * - W^X partially enforced: writable pages should not be executable
         * - Full W^X requires PAE or x86-64 (NX bit support)
         *
         * REFERENCES:
         * - ELF Specification: Program Header p_flags
         * - Intel SDM Vol 3A: Page Table Entry Format
         * - PaX Project: PAGEEXEC and SEGMEXEC
         *=====================================================================*/

        /* Convert ELF p_flags to x86 page table flags */
        uint32_t page_flags = 0x1 | 0x4;  /* PAGE_PRESENT | PAGE_USER (always set) */
        if (p_flags & 0x2) {  /* PF_W: Writable */
            page_flags |= 0x2;  /* PAGE_READWRITE */
        }
        /* Note: PF_X (executable) cannot be enforced on x86-32 without PAE/NX bit */

        /*=====================================================================
         * SECURITY FIX (AUDIT 10D): Correct ELF Segment Page Alignment
         *
         * VULNERABILITY: Unaligned Segment Page Calculation
         *
         * OLD CODE (VULNERABLE):
         * num_pages = (memsz + 0xFFF) / 0x1000;  // Based on SIZE only!
         *
         * PROBLEM: Off-By-One for Unaligned Segments
         * The old code calculated pages based only on segment size (memsz),
         * ignoring the starting address alignment. This causes incorrect
         * page counts when segments don't start on page boundaries.
         *
         * ATTACK SCENARIO: Memory Corruption via Unmapped Pages
         * 1. ELF segment: vaddr=0x8000FFF, memsz=0x2 (2 bytes)
         * 2. OLD CODE calculates:
         *    num_pages = (0x2 + 0xFFF) / 0x1000 = 0x1001 / 0x1000 = 1 page
         * 3. Maps single page at 0x8000000 (page-aligned base)
         * 4. BUT segment ACTUALLY spans TWO pages:
         *    - Page 1: 0x8000000-0x8000FFF (contains byte at 0x8000FFF)
         *    - Page 2: 0x8001000-0x8001FFF (contains byte at 0x8001000)
         * 5. When loader writes 2nd byte at 0x8001000 → PAGE FAULT!
         * 6. Or worse: If adjacent page is already mapped with different
         *    permissions, corrupts unrelated memory
         *
         * REAL-WORLD EXAMPLE:
         * - Segment .data at 0x8048FFC with 8-byte global variable
         * - Old code maps 1 page: 0x8048000-0x8048FFF
         * - Variable spans 0x8048FFC-0x8049003 (crosses page boundary!)
         * - Writes to 0x8049000-0x8049003 hit unmapped page → crash
         *
         * ROOT CAUSE: Size-Based vs Range-Based Calculation
         * - Size-based: num_pages = round_up(memsz / pagesize)
         *   ✗ Assumes segment starts at page boundary
         * - Range-based: num_pages = (end_page - start_page) / pagesize
         *    Accounts for starting address offset
         *
         * NEW CODE (SECURE): Calculate from Address Range
         * 1. start_page = vaddr & ~0xFFF (round DOWN to page boundary)
         * 2. end_addr = vaddr + memsz (last byte + 1)
         * 3. end_page = (end_addr + 0xFFF) & ~0xFFF (round UP to page)
         * 4. num_pages = (end_page - start_page) / 0x1000
         *
         * VERIFICATION:
         * Example 1: vaddr=0x8000FFF, memsz=0x2
         *   start_page = 0x8000FFF & ~0xFFF = 0x8000000
         *   end_addr = 0x8000FFF + 0x2 = 0x8001001
         *   end_page = (0x8001001 + 0xFFF) & ~0xFFF = 0x8002000
         *   num_pages = (0x8002000 - 0x8000000) / 0x1000 = 2  CORRECT
         *
         * Example 2: vaddr=0x1000, memsz=0x1000 (aligned)
         *   start_page = 0x1000 & ~0xFFF = 0x1000
         *   end_addr = 0x1000 + 0x1000 = 0x2000
         *   end_page = (0x2000 + 0xFFF) & ~0xFFF = 0x2000
         *   num_pages = (0x2000 - 0x1000) / 0x1000 = 1  CORRECT
         *
         * OVERFLOW SAFETY:
         * - vaddr + memsz might overflow 32-bit address space
         * - Check if (vaddr + memsz) < vaddr to detect wraparound
         * - Reject such segments (no valid segment wraps around 4GB)
         *
         * REFERENCES:
         * - ELF Specification: Program Header p_vaddr and p_memsz
         * - Linux kernel: load_elf_binary() in fs/binfmt_elf.c
         *===================================================================*/

        /* Calculate page-aligned start and end addresses */
        uint32_t start_page = vaddr & ~0xFFF;  /* Round DOWN to page boundary */

        /* Check for address overflow: vaddr + memsz */
        uint32_t segment_end;
        if (memsz > (0xFFFFFFFF - vaddr)) {
            kprintf("[ELF] ERROR: Segment address range overflows (vaddr=0x%08x, memsz=0x%x)\n",
                    vaddr, memsz);

            /*=============================================================
             * CLEANUP: Free all previously allocated frames
             *===========================================================*/
            kprintf("[ELF] Cleaning up %u allocated frames...\n", num_allocated);
            for (uint32_t j = 0; j < num_allocated; j++) {
                pmm_free(allocated_frames[j]);
            }

            /*=============================================================
             * SECURITY FIX (AUDIT 10E): Free Page Tables
             * Unmap entire user address space to free any page tables
             * that were allocated by map_page().
             *===========================================================*/
            unmap_page_range(USER_MIN_ADDR, max_vaddr);

            // Switch back to kernel page directory before returning
            __asm__ volatile("mov %0, %%cr3" :: "r"(kernel_cr3) : "memory");
            return -1;
        }
        segment_end = vaddr + memsz;

        /* Round UP end address to next page boundary */
        uint32_t end_page = (segment_end + 0xFFF) & ~0xFFF;

        /* Calculate number of pages from address range */
        uint32_t num_pages = (end_page - start_page) / 0x1000;

        kprintf("[ELF] Loading segment %d: vaddr=0x%08x, pages=%d, flags=0x%x (p_flags=0x%x)\n",
                i, vaddr, num_pages, page_flags, p_flags);

        // Allocate physical pages and map them
        uint32_t seg_first_frame = num_allocated;
        for (uint32_t page = 0; page < num_pages; page++) {
            uint32_t page_vaddr = start_page + (page * 0x1000);

            // Allocate physical page
            uint32_t phys_frame = pmm_alloc();
            if (phys_frame == 0) {
                kprintf("[ELF] ERROR: Failed to allocate physical page\n");

                /*=============================================================
                 * CLEANUP: Free all previously allocated frames
                 *===========================================================*/
                kprintf("[ELF] Cleaning up %u allocated frames...\n", num_allocated);
                for (uint32_t j = 0; j < num_allocated; j++) {
                    pmm_free(allocated_frames[j]);
                }

                /*=============================================================
                 * SECURITY FIX (AUDIT 10E): Free Page Tables
                 * Unmap entire user address space to free any page tables
                 * that were allocated by map_page().
                 *===========================================================*/
                unmap_page_range(USER_MIN_ADDR, max_vaddr);

                // Switch back to kernel page directory before returning
                __asm__ volatile("mov %0, %%cr3" :: "r"(kernel_cr3) : "memory");
                return -1;
            }

            /*=================================================================
             * Track allocated frame for cleanup on failure
             *===============================================================*/
            if (num_allocated >= MAX_TRACKED_PAGES) {
                kprintf("[ELF] ERROR: Exceeded maximum trackable pages (%d)\n",
                        MAX_TRACKED_PAGES);

                // Free all previously allocated frames
                for (uint32_t j = 0; j < num_allocated; j++) {
                    pmm_free(allocated_frames[j]);
                }
                // Free the frame we just allocated
                pmm_free(phys_frame);

                /*=============================================================
                 * SECURITY FIX (AUDIT 10E): Free Page Tables
                 * Unmap entire user address space to free any page tables
                 * that were allocated by map_page().
                 *===========================================================*/
                unmap_page_range(USER_MIN_ADDR, max_vaddr);

                __asm__ volatile("mov %0, %%cr3" :: "r"(kernel_cr3) : "memory");
                return -1;
            }

            allocated_frames[num_allocated++] = phys_frame;

            /* Map writable for the copy below (CR0.WP=1 faults supervisor
             * writes to read-only pages); final permissions applied after. */
            map_page(page_vaddr, phys_frame, page_flags | 0x2);
        }

        // Copy segment data from ELF file to memory
        const uint8_t* src = (const uint8_t*)elf_data + offset;
        uint8_t* dest = (uint8_t*)vaddr;

        // Copy file data
        memcpy(dest, src, filesz);

        // Zero BSS section (memsz > filesz)
        if (memsz > filesz) {
            memset(dest + filesz, 0, memsz - filesz);
        }

        /*=====================================================================
         * SECURITY FIX (AUDIT 9F): Zero Dirty Page Tail (Information Leak)
         *
         * VULNERABILITY: Uninitialized Memory Disclosure
         *
         * PROBLEM: Partial Page Initialization Leaks Kernel Secrets
         * The ELF loader allocates full 4096-byte pages via pmm_alloc() but
         * only initializes bytes [0, memsz). The remainder [memsz, 4096) is
         * NEVER ZEROED. Since pmm_alloc() recycles physical frames from
         * previous processes/kernel, this tail contains "dirty" data:
         * - Old passwords from login processes
         * - Cryptographic keys from SSH sessions
         * - File fragments from disk buffers
         *
         * ATTACK SCENARIO:
         * 1. Kernel allocates page for .bss section (memsz = 100 bytes)
         * 2. Physical frame was previously used by SSH (contains AES keys)
         * 3. ELF loader zeros bytes 0-99, leaves bytes 100-4095 untouched
         * 4. User process scans its own heap: for (i=0; i<4096; i++) read(ptr[i])
         * 5. Bytes 100-4095 leak the old AES keys from SSH session
         *
         * REAL-WORLD IMPACT:
         * - Similar bug in Linux kernel (CVE-2009-0835): brk() leaked data
         * - Android memory disclosure (CVE-2016-2060): GPU memory not zeroed
         * - Windows 10 info leak (CVE-2020-1589): Registry data in heap
         *
         * FIX: Zero Entire Remainder of Last Page
         * Calculate the end of the last allocated page and zero everything
         * from memsz to the page boundary.
         *
         * REFERENCES:
         * - CWE-908: Use of Uninitialized Resource
         * - CERT MEM30-C: Do not access freed memory
         *===================================================================*/
        uint32_t end_addr = vaddr + memsz;
        uint32_t page_end = (end_addr + 0xFFF) & ~0xFFF;  /* Round up to next page */
        uint32_t tail_size = page_end - end_addr;

        if (tail_size > 0) {
            memset((uint8_t*)end_addr, 0, tail_size);
        }

        /* SECURITY: Re-map non-writable segments with final permissions,
         * dropping the temporary RW bit used for the copy above. */
        if (!(p_flags & 0x2)) {
            for (uint32_t page = 0; page < num_pages; page++) {
                uint32_t page_vaddr = start_page + (page * 0x1000);
                map_page(page_vaddr, allocated_frames[seg_first_frame + page],
                         page_flags);
            }
        }

        kprintf("[ELF]   Copied %d bytes, zeroed BSS %d bytes, zeroed page tail %d bytes\n",
                filesz, memsz - filesz, tail_size);
    }

    // Switch back to kernel page directory
    kprintf("[ELF] Switching back to kernel page directory\n");
    __asm__ volatile("mov %0, %%cr3" :: "r"(kernel_cr3) : "memory");

    /*=========================================================================
     * PHASE 13: Close-on-Exec Cleanup (Secure FD Inheritance)
     *
     * SECURITY: Before the new program starts executing, close all file
     * descriptors that have close_on_exec == true (which is the default).
     *
     * TRADITIONAL UNIX/LINUX WEAKNESS:
     * - Child processes inherit ALL parent FDs by default
     * - Developer must explicitly set O_CLOEXEC flag to prevent leaks
     * - Easy to forget → sensitive FDs leak to untrusted children
     * - Examples: database connections, password files, network sockets
     *
     * TINYOS INNOVATION:
     * - All FDs closed on exec by default (reversed semantics)
     * - Must explicitly set RAMFS_FLAG_INHERIT to keep FD open
     * - Fail-secure: Forget to set flag? Still secure.
     *
     * TIMING: Called AFTER program is loaded but BEFORE it starts executing.
     * This ensures the new program begins with a clean FD table (except for
     * explicitly inherited FDs like stdin/stdout/stderr).
     *=======================================================================*/
    ramfs_close_on_exec();

    kprintf("[ELF] Process created successfully: PID=%d\n", pid);
    return pid;
}
