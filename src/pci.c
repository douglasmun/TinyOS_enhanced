/*=============================================================================
 * pci.c - PCI Configuration Space Access with Interrupt Support
 *============================================================================*/
#include <stddef.h>
#include <stdbool.h>
#include "net.h"
#include "util.h"
#include "kernel.h"
#include "kprintf.h"
#include "critical.h"  /* For proper nested critical section support */

/*=============================================================================
 * PCI CONFIGURATION REGISTERS
 *============================================================================*/
#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

#define E1000_VENDOR_ID 0x8086
#define E1000_DEVICE_ID 0x100E

/*=============================================================================
 * PCI CONFIGURATION SPACE OFFSETS
 *============================================================================*/
#define PCI_VENDOR_ID      0x00  // 2 bytes
#define PCI_DEVICE_ID      0x02  // 2 bytes
#define PCI_COMMAND        0x04  // 2 bytes
#define PCI_STATUS         0x06  // 2 bytes
#define PCI_CLASS_CODE     0x0B  // 1 byte
#define PCI_HEADER_TYPE    0x0E  // 1 byte
#define PCI_BAR0           0x10  // 4 bytes
#define PCI_INTERRUPT_LINE 0x3C  // 1 byte
#define PCI_INTERRUPT_PIN  0x3D  // 1 byte

/*=============================================================================
 * PCI COMMAND REGISTER BITS
 *============================================================================*/
#define PCI_COMMAND_IO              0x0001  // Enable I/O Space
#define PCI_COMMAND_MEMORY          0x0002  // Enable Memory Space
#define PCI_COMMAND_BUS_MASTER      0x0004  // Enable Bus Mastering
#define PCI_COMMAND_SPECIAL_CYCLES  0x0008  // Enable Special Cycles
#define PCI_COMMAND_MEMORY_WI       0x0010  // Memory Write and Invalidate
#define PCI_COMMAND_VGA_SNOOP       0x0020  // VGA Palette Snoop
#define PCI_COMMAND_PARITY_ERROR    0x0040  // Parity Error Response
#define PCI_COMMAND_SERR            0x0100  // Enable SERR#
#define PCI_COMMAND_FAST_B2B        0x0200  // Fast Back-to-Back Enable
#define PCI_COMMAND_INT_DISABLE     0x0400  // Interrupt Disable

/*=============================================================================
 * PCI I/O SERIALIZATION PORT
 * Port 0x80 is a diagnostic port used for POST codes on PC hardware.
 * Writing to it causes a slight delay and forces I/O ordering, preventing
 * timing attacks and ensuring proper instruction retirement.
 *============================================================================*/
#define PCI_IO_DELAY_PORT 0x80

/*=============================================================================
 * SECURITY: PCI Configuration Space Access Synchronization
 *
 * VULNERABILITY: The two-phase access to PCI config space (write address to
 * 0xCF8, then read/write data at 0xCFC) is NOT atomic. Without protection:
 * - Interrupts could interleave between the two operations
 * - On SMP systems, another CPU could access PCI concurrently
 * - SMI/NMI handlers could corrupt the address register
 * - Timing attacks could infer system state from I/O delays
 *
 * FIX: Disable interrupts during the critical section (single-CPU safety).
 * For multi-CPU systems, a spinlock would be required in addition.
 *
 * SERIALIZATION: Writing to port 0x80 after setting the address forces
 * instruction ordering and prevents certain chipset-level race conditions.
 *============================================================================*/

/*=============================================================================
 * FUNCTION: pci_read_config (32-bit read)
 *============================================================================*/
static uint32_t pci_read_config(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t address = (1 << 31) |           // Enable bit
                       (bus << 16) |          // Bus number
                       (slot << 11) |         // Device number
                       (func << 8) |          // Function number
                       (offset & 0xFC);       // Register offset (aligned to 4 bytes)

    /* CRITICAL SECTION: Use proper nested-safe critical section */
    CRITICAL_SECTION_ENTER();

    /* Write address to CONFIG_ADDRESS register */
    outl(PCI_CONFIG_ADDRESS, address);

    /* SECURITY: Force I/O ordering and prevent timing attacks
     * Initialize AL to 0 before writing to diagnostic port 0x80 */
    __asm__ volatile("xorb %%al, %%al\n\t"
                     "outb %%al, %0" : : "N"(PCI_IO_DELAY_PORT) : "al");

    /* Read data from CONFIG_DATA register */
    uint32_t result = inl(PCI_CONFIG_DATA);

    /* Exit critical section (restores interrupts if outermost) */
    CRITICAL_SECTION_EXIT();

    return result;
}

/*=============================================================================
 * FUNCTION: pci_write_config (32-bit write)
 *============================================================================*/
static void pci_write_config(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t value) {
    uint32_t address = (1 << 31) |           // Enable bit
                       (bus << 16) |          // Bus number
                       (slot << 11) |         // Device number
                       (func << 8) |          // Function number
                       (offset & 0xFC);       // Register offset (aligned to 4 bytes)

    /* CRITICAL SECTION: Use proper nested-safe critical section */
    CRITICAL_SECTION_ENTER();

    /* Write address to CONFIG_ADDRESS register */
    outl(PCI_CONFIG_ADDRESS, address);

    /* SECURITY: Force I/O ordering and prevent timing attacks
     * Initialize AL to 0 before writing to diagnostic port 0x80 */
    __asm__ volatile("xorb %%al, %%al\n\t"
                     "outb %%al, %0" : : "N"(PCI_IO_DELAY_PORT) : "al");

    /* Write data to CONFIG_DATA register */
    outl(PCI_CONFIG_DATA, value);

    /* Exit critical section (restores interrupts if outermost) */
    CRITICAL_SECTION_EXIT();
}

/*=============================================================================
 * FUNCTION: pci_read_config_word (16-bit read)
 *============================================================================*/
static uint16_t pci_read_config_word(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t data = pci_read_config(bus, slot, func, offset & 0xFC);
    return (uint16_t)((data >> ((offset & 2) * 8)) & 0xFFFF);
}

/*=============================================================================
 * FUNCTION: pci_write_config_word (16-bit write)
 *============================================================================*/
static void pci_write_config_word(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint16_t value) {
    uint32_t old_data = pci_read_config(bus, slot, func, offset & 0xFC);
    uint32_t shift = (offset & 2) * 8;
    uint32_t mask = 0xFFFF << shift;
    uint32_t new_data = (old_data & ~mask) | ((uint32_t)value << shift);
    pci_write_config(bus, slot, func, offset & 0xFC, new_data);
}

/*=============================================================================
 * FUNCTION: pci_read_config_byte (8-bit read)
 *============================================================================*/
static uint8_t pci_read_config_byte(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t data = pci_read_config(bus, slot, func, offset & 0xFC);
    return (uint8_t)((data >> ((offset & 3) * 8)) & 0xFF);
}

/*=============================================================================
 * FUNCTION: pci_enable_bus_mastering
 * PURPOSE: Enable bus mastering and memory access for DMA operations
 *============================================================================*/
static void pci_enable_bus_mastering(uint8_t bus, uint8_t slot, uint8_t func) {
    // Read current command register
    uint16_t command = pci_read_config_word(bus, slot, func, PCI_COMMAND);

    // kprintf("[PCI] Current command register: 0x%04x\n", command);

    // Enable: I/O Space, Memory Space, Bus Mastering
    // Disable: Interrupt Disable bit (to allow interrupts)
    command |= PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER;
    command &= ~PCI_COMMAND_INT_DISABLE;  // Clear interrupt disable bit

    // Write back
    pci_write_config_word(bus, slot, func, PCI_COMMAND, command);

    // Verify
    uint16_t new_command = pci_read_config_word(bus, slot, func, PCI_COMMAND);
    // kprintf("[PCI] Updated command register: 0x%04x\n", new_command);

    if (new_command & PCI_COMMAND_BUS_MASTER) {
        // kprintf("[PCI] Bus mastering enabled\n");
    } else {
        kprintf("[PCI] WARNING: Bus mastering failed to enable!\n");
    }

    if (new_command & PCI_COMMAND_INT_DISABLE) {
        kprintf("[PCI] WARNING: Interrupts are disabled in PCI command register!\n");
    } else {
        // kprintf("[PCI] Interrupts enabled in PCI command register\n");
    }
}

/*=============================================================================
 * FUNCTION: pci_find_e1000
 * PURPOSE: Find E1000 NIC and configure it for operation
 *============================================================================*/
bool pci_find_e1000(uint32_t* mmio_base_out) {
    kprintf("[PCI] Scanning for E1000 NIC........ [OK]\n");

    /*=========================================================================
     * SECURITY FIX: Use Unsigned Types for Loop Bounds
     * CRITICAL: Avoid signed/unsigned comparison issues by using proper
     * unsigned types (uint16_t) for loop counters that represent hardware
     * indices (PCI bus 0-255, slot 0-31).
     *=======================================================================*/
    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint8_t slot = 0; slot < 32; slot++) {
            uint32_t id = pci_read_config(bus, slot, 0, PCI_VENDOR_ID);
            uint16_t vendor = id & 0xFFFF;
            uint16_t device = (id >> 16) & 0xFFFF;
            
            if (vendor == 0xFFFF) {
                // No device in this slot
                continue;
            }
            
            if (vendor == E1000_VENDOR_ID && device == E1000_DEVICE_ID) {
                kprintf("[PCI] E1000 at bus=%d, slot=%d, func=0 [OK]\n", bus, slot);

                // Read BAR0 (Memory-Mapped I/O base address)
                uint32_t bar0 = pci_read_config(bus, slot, 0, PCI_BAR0);
                *mmio_base_out = bar0 & 0xFFFFFFF0;  // Mask off lower 4 bits
                kprintf("[PCI] BAR0 (MMIO base): 0x%08x   [OK]\n", *mmio_base_out);

                // *** Silenced debug message ***
                // kprintf("\n*** E1000 IRQ: %d ***\n\n", pci_read_config(bus, slot, 0, 0x3C) & 0xFF);

                // Read interrupt configuration
                uint8_t int_line = pci_read_config_byte(bus, slot, 0, PCI_INTERRUPT_LINE);
                uint8_t int_pin = pci_read_config_byte(bus, slot, 0, PCI_INTERRUPT_PIN);
                // kprintf("[PCI] Interrupt Line: %d, Interrupt Pin: %d\n", int_line, int_pin);
                
                if (int_pin == 0) {
                    kprintf("[PCI] WARNING: Device reports no interrupt pin!\n");
                } else if (int_line == 0xFF) {
                    kprintf("[PCI] WARNING: Interrupt line not assigned!\n");
                } else if (int_line != 11) {
                    kprintf("[PCI] WARNING: E1000 is on IRQ %d, expected IRQ 11\n", int_line);
                    kprintf("[PCI] Your interrupt handler may need adjustment!\n");
                }
                
                // Enable bus mastering and interrupts
                pci_enable_bus_mastering(bus, slot, 0);

                // kprintf("[PCI] E1000 configuration complete\n");
                return true;
            }
        }
    }
    
    kprintf("[PCI] E1000 not found\n");
    return false;
}
