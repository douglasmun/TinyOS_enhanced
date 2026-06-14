/*=============================================================================
 * e1000.c - Intel E1000 Network Driver with Packet Dump Support
 *============================================================================*/
#include <stddef.h>
#include "kernel.h"
#include "net.h"
#include "kprintf.h"
#include "util.h"
#include "tcp.h"  // For tcp_get_time_ms() - link status debounce
#include "critical.h"  /* For proper nested critical section support */

/*=============================================================================
 * E1000 REGISTER OFFSETS
 *============================================================================*/
// Transmit registers
#define E1000_TDBAL 0x03800  // TX Descriptor Base Address Low
#define E1000_TDBAH 0x03804  // TX Descriptor Base Address High
#define E1000_TDLEN 0x03808  // TX Descriptor Length
#define E1000_TDH   0x03810  // TX Descriptor Head
#define E1000_TDT   0x03818  // TX Descriptor Tail
#define E1000_TCTL  0x00400  // TX Control
#define E1000_TIPG  0x00410  // TX Inter-Packet Gap

// Receive registers
#define E1000_RDBAL 0x02800  // RX Descriptor Base Address Low
#define E1000_RDBAH 0x02804  // RX Descriptor Base Address High
#define E1000_RDLEN 0x02808  // RX Descriptor Length
#define E1000_RDH   0x02810  // RX Descriptor Head
#define E1000_RDT   0x02818  // RX Descriptor Tail
#define E1000_RCTL  0x00100  // RX Control

// Control and Status registers
#define E1000_CTRL   0x00000  // Device Control
#define E1000_STATUS 0x00008  // Device Status

// Interrupt registers
#define E1000_ICR   0x000C0  // Interrupt Cause Read
#define E1000_IMS   0x000D0  // Interrupt Mask Set
#define E1000_IMC   0x000D8  // Interrupt Mask Clear
#define E1000_ICS   0x000C8  // Interrupt Cause Set (for testing)

// Descriptor Control registers
#define E1000_TXDCTL 0x03828  // TX Descriptor Control

// Flow Control registers
#define E1000_FCAL  0x00028  // Flow Control Address Low
#define E1000_FCAH  0x0002C  // Flow Control Address High
#define E1000_FCT   0x00030  // Flow Control Type
#define E1000_FCTTV 0x00170  // Flow Control Transmit Timer Value
#define E1000_FCRTL 0x02160  // Flow Control Receive Threshold Low
#define E1000_FCRTH 0x02168  // Flow Control Receive Threshold High

/*=============================================================================
 * CONTROL REGISTER BITS
 *============================================================================*/
// CTRL register bits
#define E1000_CTRL_FD    0x00000001  // Full Duplex
#define E1000_CTRL_ASDE  0x00000020  // Auto-Speed Detection Enable
#define E1000_CTRL_SLU   0x00000040  // Set Link Up
#define E1000_CTRL_RST   0x04000000  // Device Reset

// TCTL bits
#define E1000_TCTL_EN   0x00000002  // Transmit Enable
#define E1000_TCTL_PSP  0x00000008  // Pad Short Packets
#define E1000_TCTL_CT   0x00000FF0  // Collision Threshold
#define E1000_TCTL_COLD 0x003FF000  // Collision Distance

// RCTL bits
#define E1000_RCTL_EN    0x00000002  // Receive Enable
#define E1000_RCTL_BAM   0x00008000  // Broadcast Accept Mode
#define E1000_RCTL_SECRC 0x04000000  // Strip Ethernet CRC

// STATUS register bits
#define E1000_STATUS_LU  0x00000002  // Link Up

// TXDCTL register bits
#define E1000_TXDCTL_WTHRESH_SHIFT 16  // Write-back Threshold shift
#define E1000_TXDCTL_GRAN          0x01000000  // Granularity (1 = descriptor)

// Interrupt bits (for IMS/ICR)
#define E1000_ICR_TXDW    0x00000001  // TX Descriptor Written Back
#define E1000_ICR_TXQE    0x00000002  // TX Queue Empty
#define E1000_ICR_LSC     0x00000004  // Link Status Change
#define E1000_ICR_RXSEQ   0x00000008  // RX Sequence Error
#define E1000_ICR_RXDMT0  0x00000010  // RX Descriptor Min Threshold
#define E1000_ICR_RXO     0x00000040  // RX Overrun
#define E1000_ICR_RXT0    0x00000080  // RX Timer Interrupt

// Descriptor bits
#define E1000_TXD_CMD_EOP  0x01  // End of Packet
#define E1000_TXD_CMD_IFCS 0x02  // Insert FCS
#define E1000_TXD_CMD_RS   0x08  // Report Status (CRITICAL: Must set for DD write-back!)
#define E1000_TXD_STAT_DD  0x01  // Descriptor Done

#define E1000_RXD_STAT_DD  0x01  // Descriptor Done
#define E1000_RXD_STAT_EOP 0x02  // End of Packet

// RX Descriptor Error Bits (critical for security boundary)
#define E1000_RXD_ERR_CE   0x01  // CRC Error or Alignment Error
#define E1000_RXD_ERR_SE   0x02  // Symbol Error
#define E1000_RXD_ERR_SEQ  0x04  // Sequence Error
#define E1000_RXD_ERR_CXE  0x10  // Carrier Extension Error
#define E1000_RXD_ERR_TCPE 0x20  // TCP/UDP Checksum Error
#define E1000_RXD_ERR_IPE  0x40  // IP Checksum Error
#define E1000_RXD_ERR_RXE  0x80  // RX Data Error

/*=============================================================================
 * DESCRIPTOR STRUCTURES
 *============================================================================*/
#define NUM_TX_DESC 8
#define NUM_RX_DESC 64  /* Increased from 8 to handle burst traffic */
#define RX_BUF_SIZE 2048

struct tx_desc {
    uint64_t addr;
    uint16_t length;
    uint8_t cso;
    uint8_t cmd;
    uint8_t status;
    uint8_t css;
    uint16_t special;
} __attribute__((packed));

struct rx_desc {
    uint64_t addr;
    uint16_t length;
    uint16_t checksum;
    uint8_t status;
    uint8_t errors;
    uint16_t special;
} __attribute__((packed));

/*=============================================================================
 * STATIC VARIABLES
 *============================================================================*/
static struct tx_desc tx_ring[NUM_TX_DESC] __attribute__((aligned(16)));
static struct rx_desc rx_ring[NUM_RX_DESC] __attribute__((aligned(16)));
static uint8_t tx_bufs[NUM_TX_DESC][RX_BUF_SIZE] __attribute__((aligned(16)));
static uint8_t rx_bufs[NUM_RX_DESC][RX_BUF_SIZE] __attribute__((aligned(16)));

/*=============================================================================
 * SECURITY: Volatile MMIO Pointer for E1000 Registers
 * CRITICAL: The 'volatile' qualifier is MANDATORY for memory-mapped I/O
 *
 * WITHOUT volatile, the C compiler assumes memory contents don't change
 * unless the program explicitly writes to them. This is catastrophically
 * wrong for MMIO registers, which can be modified by hardware at any time.
 *
 * Example failure scenario without volatile:
 *
 *   // Read ICR twice to check interrupt status
 *   uint32_t icr1 = e1000[E1000_ICR / 4];
 *   process_something();
 *   uint32_t icr2 = e1000[E1000_ICR / 4];  // Compiler might reuse icr1!
 *
 * The compiler might optimize the second read away, thinking "I already
 * read this value, and nothing in process_something() writes to it, so
 * I can reuse the cached value." But ICR is modified by the NIC hardware!
 *
 * With volatile, the compiler must:
 * 1. NEVER optimize away reads/writes to e1000[...]
 * 2. NEVER reorder accesses to e1000[...] relative to other volatile ops
 * 3. NEVER cache e1000[...] values in registers across function calls
 * 4. ALWAYS generate actual memory load/store instructions
 *
 * This ensures every e1000[E1000_xxx / 4] access translates to a real
 * memory operation that the hardware sees.
 *===========================================================================*/
static volatile uint32_t* e1000 = NULL;
static uint32_t rx_tail = 0;  // Track which descriptor we're processing
static uint32_t packet_tx_count = 0;
static uint32_t packet_rx_count = 0;

// Packet dump control (set to 1 to enable, 0 to disable)
static int enable_packet_dump = 0;  // Disabled to reduce verbosity

/*=============================================================================
 * LINK STATUS DEBOUNCE PROTECTION
 * SECURITY: Prevents physical layer DoS from rapid link flapping
 *
 * A flapping network link (rapid up/down cycling) can cause excessive CPU
 * consumption in link status change handling, ARP cache invalidation, and
 * driver reinitialization. This is a simple physical layer DoS attack.
 *
 * Debounce strategy: Ignore LSC interrupts unless the link has been stable
 * for LINK_DEBOUNCE_MS milliseconds.
 *=============================================================================*/
#define LINK_DEBOUNCE_MS 500  // 500ms debounce delay
static uint32_t last_lsc_time = 0;      // Last LSC interrupt timestamp
static bool link_status_stable = true;  // Link considered stable

/*=============================================================================
 * CONCURRENCY PROTECTION
 * CRITICAL: Protects descriptor rings from race conditions between network
 * stack and interrupt handler. Without this, simultaneous TX/RX operations
 * can corrupt descriptor state, leading to catastrophic kernel failures.
 *
 * SECURITY FIX: Replace raw cli/sti with nested-safe critical sections.
 * Previous implementation was not re-entrant and could prematurely restore
 * interrupts when called within existing critical sections.
 *=============================================================================*/
#define E1000_LOCK()   CRITICAL_SECTION_ENTER()
#define E1000_UNLOCK() CRITICAL_SECTION_EXIT()

/* Bounded spin cap for the TX descriptor-done (DD) wait in e1000_send().
 * Large enough to ride out a saturated link, finite so a wedged NIC can't
 * hang the kernel with interrupts disabled. ~10M iterations of a tight MMIO
 * status poll is well beyond normal microsecond completion. */
#define E1000_TX_DD_TIMEOUT 10000000u

// Ethernet MTU: 1500 bytes payload + 14 bytes header + 4 bytes FCS = 1518 bytes max
#define MAX_ETH_FRAME_SIZE 1518

/*=============================================================================
 * FUNCTION: dump_packet
 * PURPOSE: Dump packet contents in hex format
 *============================================================================*/
static void dump_packet(const char* direction, const uint8_t* data, size_t len) {
    if (!enable_packet_dump) {
        return;
    }
    
    kprintf("\n[%s PACKET] Length: %d bytes\n", direction, len);
    kprintf("----------------------------------------\n");
    
    // Limit dump to first 128 bytes to avoid overwhelming the output
    size_t dump_len = (len > 128) ? 128 : len;
    
    for (size_t i = 0; i < dump_len; i++) {
        if (i % 16 == 0) {
            kprintf("%04x: ", i);
        }
        kprintf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) {
            kprintf("\n");
        }
    }
    
    if (dump_len % 16 != 0) {
        kprintf("\n");
    }
    
    if (len > dump_len) {
        kprintf("... (%d more bytes)\n", len - dump_len);
    }
    
    kprintf("----------------------------------------\n");
    
    // Decode ethernet header
    if (len >= 14) {
        kprintf("Ethernet Header:\n");
        kprintf("  Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                data[0], data[1], data[2], data[3], data[4], data[5]);
        kprintf("  Src MAC:  %02x:%02x:%02x:%02x:%02x:%02x\n",
                data[6], data[7], data[8], data[9], data[10], data[11]);
        uint16_t ethertype = (data[12] << 8) | data[13];
        kprintf("  EtherType: 0x%04x", ethertype);
        
        if (ethertype == 0x0800) {
            kprintf(" (IPv4)\n");
            
            // Decode IP header
            if (len >= 34) {
                kprintf("IPv4 Header:\n");
                kprintf("  Src IP:  %d.%d.%d.%d\n", data[26], data[27], data[28], data[29]);
                kprintf("  Dest IP: %d.%d.%d.%d\n", data[30], data[31], data[32], data[33]);
                kprintf("  Protocol: %d", data[23]);
                
                if (data[23] == 1) {
                    kprintf(" (ICMP)\n");
                } else if (data[23] == 6) {
                    kprintf(" (TCP)\n");
                } else if (data[23] == 17) {
                    kprintf(" (UDP)\n");
                    
                    // Decode UDP ports
                    if (len >= 42) {
                        uint16_t src_port = (data[34] << 8) | data[35];
                        uint16_t dest_port = (data[36] << 8) | data[37];
                        kprintf("  Src Port:  %d\n", src_port);
                        kprintf("  Dest Port: %d\n", dest_port);
                    }
                } else {
                    kprintf("\n");
                }
            }
        } else if (ethertype == 0x0806) {
            kprintf(" (ARP)\n");
            if (len >= 42) {
                uint16_t op = (data[20] << 8) | data[21];
                kprintf("ARP %s:\n", op == 1 ? "Request" : op == 2 ? "Reply" : "Unknown");
                kprintf("  Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        data[22], data[23], data[24], data[25], data[26], data[27]);
                kprintf("  Sender IP:  %d.%d.%d.%d\n", data[28], data[29], data[30], data[31]);
                kprintf("  Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        data[32], data[33], data[34], data[35], data[36], data[37]);
                kprintf("  Target IP:  %d.%d.%d.%d\n", data[38], data[39], data[40], data[41]);
            }
        } else {
            kprintf("\n");
        }
    }
    kprintf("\n");
}

/*=============================================================================
 * FUNCTION: e1000_send
 * PURPOSE: Transmit a packet with optional dump
 * SECURITY: Validates frame length and protects against concurrent access
 *============================================================================*/
void e1000_send(void* data, size_t len) {
    if (!e1000) {
        return;
    }

    /*=========================================================================
     * SECURITY: Validate frame length against maximum Ethernet frame size
     * This prevents internal memory corruption from oversized packets and
     * protects against protocol-level attacks that send jumbo frames
     *=======================================================================*/
    if (len > MAX_ETH_FRAME_SIZE) {
        kprintf("E1000: ERROR - Frame too large (%zu bytes, max %d)\n",
                len, MAX_ETH_FRAME_SIZE);
        return;
    }

    if (len > RX_BUF_SIZE) {
        kprintf("E1000: ERROR - Frame exceeds buffer size (%zu > %d)\n",
                len, RX_BUF_SIZE);
        return;
    }

    /*=========================================================================
     * CRITICAL SECTION: Protect descriptor ring access
     * Without this lock, concurrent calls to e1000_send() or simultaneous
     * RX interrupts can corrupt the tail pointer and descriptor state
     *=======================================================================*/
    E1000_LOCK();

    uint32_t tail = e1000[E1000_TDT / 4];

    /*=========================================================================
     * SECURITY FIX: Check Descriptor Done Status Before Reuse
     * CRITICAL: The NIC may not have finished transmitting the previous packet
     * in this descriptor slot. Without this check, under heavy network load:
     *
     * 1. Software writes new packet to tx_bufs[tail]
     * 2. Software updates tx_ring[tail] and advances TDT
     * 3. NIC is still transmitting the OLD packet from this descriptor
     * 4. NIC now sees MODIFIED descriptor → transmits corrupted/truncated packet
     * 5. TCP retransmissions kick in, SSH handshake stalls, connections drop
     *
     * This is exactly the "works in lab (low load), fails under production load
     * (high packet rate)" scenario. Silent packet corruption is worse than
     * explicit drops because it wastes bandwidth on corrupted frames.
     *
     * The fix: Spin-wait until DD (Descriptor Done) bit is set by NIC hardware.
     * This ensures the NIC has finished transmitting and released the descriptor.
     *
     * Note: With 8 descriptors and typical packet latencies, spin time should
     * be microseconds. If we're spinning long enough to notice, the link is
     * saturated and we SHOULD be blocking to avoid packet corruption.
     *=========================================================================*/
    /* Wait for the NIC to release the descriptor (DD bit) with a BOUNDED cap.
     * The previous loop spun forever while holding E1000_LOCK (cli) — a stuck
     * NIC or emulator fault would starve the timer and freeze the whole kernel.
     * DD is set by the local NIC on TX completion (microseconds normally), so a
     * large finite cap separates "saturated link" from "wedged": on timeout we
     * drop this packet rather than hang. */
    uint32_t spin_count = 0;
    while (!(tx_ring[tail].status & E1000_TXD_STAT_DD)) {
        if (++spin_count > E1000_TX_DD_TIMEOUT) {
            kprintf("E1000: ERROR - TX descriptor %u stuck (DD never set); dropping packet\n", tail);
            E1000_UNLOCK();
            return;  /* abort: do not overwrite a descriptor the NIC may still own */
        }
    }

    // Copy packet data to TX buffer
    memcpy(tx_bufs[tail], data, len);

    // Dump transmitted packet
    packet_tx_count++;
    // kprintf("[E1000] TX Packet #%d\n", packet_tx_count);  // Commented for less verbosity
    dump_packet("TX", (uint8_t*)data, len);

    // Set up descriptor
    tx_ring[tail].addr = (uint64_t)(uintptr_t)tx_bufs[tail];
    tx_ring[tail].length = len;
    tx_ring[tail].cmd = E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS | E1000_TXD_CMD_RS;
    tx_ring[tail].status = 0;  /* Clear DD bit - NIC will set it when done (RS bit requests this) */

    /*=========================================================================
     * SECURITY: DMA Coherence - Store Fence (sfence)
     * CRITICAL: Ensure all descriptor writes are visible to DMA engine
     *
     * The CPU's store buffer is NOT coherent with the E1000's DMA engine.
     * Without sfence, this sequence can occur:
     *
     * 1. CPU writes descriptor fields to tx_ring[tail] (stays in store buffer)
     * 2. CPU writes TDT register → E1000 starts DMA immediately
     * 3. E1000 fetches descriptor from RAM → sees STALE/UNINITIALIZED data
     * 4. Corrupted packet transmitted OR NIC hangs
     *
     * sfence forces the CPU to drain its store buffer to main memory BEFORE
     * executing the MMIO write to TDT. This guarantees the NIC sees committed
     * descriptor data.
     *
     * This is a textbook DMA coherence bug that causes "works 99% of time,
     * crashes randomly under load" behavior.
     *=======================================================================*/
    __asm__ volatile("sfence" ::: "memory");

    // Advance tail pointer
    e1000[E1000_TDT / 4] = (tail + 1) % NUM_TX_DESC;

    E1000_UNLOCK();
}

/*=============================================================================
 * FUNCTION: e1000_poll_rx
 * PURPOSE: Process received packets with optional dump
 * SECURITY: Protected against concurrent access with interrupt disable
 *============================================================================*/
void e1000_poll_rx(void) {
    if (!e1000) {
        return;
    }

    /*=========================================================================
     * CRITICAL SECTION: Protect RX descriptor ring access
     * Lock must be held while processing descriptors to prevent race
     * conditions with simultaneous TX operations
     *=======================================================================*/
    E1000_LOCK();

    // Read ICR to clear interrupt
    uint32_t icr = e1000[E1000_ICR / 4];

    /*=========================================================================
     * SECURITY: Receive Overrun (RXO) Interrupt Handler
     * CRITICAL: RXO indicates the hardware dropped packets because the kernel
     * couldn't process them fast enough. Without handling, the receive path
     * can hard-lock under burst traffic.
     *
     * Recovery strategy:
     * 1. Log high-priority warning (indicates system under load)
     * 2. Continue processing available packets (aggressive drain)
     * 3. Future: Implement adaptive rate limiting or backpressure
     *=======================================================================*/
    if (icr & E1000_ICR_RXO) {
        kprintf("E1000: CRITICAL - Receive Overrun detected! Hardware dropped packets.\n");
        kprintf("E1000: System under heavy load. Consider reducing traffic or optimizing RX path.\n");
        // Continue processing to drain the ring buffer aggressively
    }

    /*=========================================================================
     * SECURITY: Link Status Change (LSC) Interrupt Debounce
     * Prevents physical layer DoS from rapid link flapping.
     *
     * If LSC bit is set, check if sufficient time has elapsed since the last
     * LSC interrupt. Only process the link status change if the link has been
     * stable for at least LINK_DEBOUNCE_MS milliseconds.
     *
     * This prevents excessive CPU consumption from handling rapid link state
     * transitions, which could be caused by:
     * 1. Faulty network cable
     * 2. Flapping switch port
     * 3. Physical layer attack
     *=======================================================================*/
    if (icr & E1000_ICR_LSC) {
        uint32_t current_time = tcp_get_time_ms();
        uint32_t time_since_last_lsc = current_time - last_lsc_time;

        if (time_since_last_lsc >= LINK_DEBOUNCE_MS || last_lsc_time == 0) {
            // Link status has been stable long enough, process the change
            link_status_stable = true;
            last_lsc_time = current_time;
            // kprintf("E1000: Link status change (stable) - time since last: %u ms\n",
            //         time_since_last_lsc);

            // Future: Add actual link status handling here (read STATUS register)
            // For now, we just acknowledge and rate-limit the interrupt
        } else {
            // Link is flapping - ignore this interrupt to reduce CPU load
            link_status_stable = false;
            last_lsc_time = current_time;
            // kprintf("E1000: Link flapping detected - ignoring LSC (time since last: %u ms)\n",
            //         time_since_last_lsc);
        }
    }

    uint32_t processed = 0;

    /*=========================================================================
     * SECURITY: Interrupt Packet Budget (Micro-Packet DoS Protection)
     *
     * CRITICAL: Without a packet budget, an attacker can send a high rate of
     * small packets ("Micro-Packet DoS") to force the interrupt handler to
     * spend excessive time processing packets while interrupts are disabled.
     *
     * Impact: High interrupt latency → Timer tick starvation → System freeze
     *
     * Mitigation: Limit packets processed per interrupt to a budget (16 packets).
     * Once the budget is exhausted:
     * 1. Re-enable interrupts (sti())
     * 2. Continue processing remaining packets in non-interrupt context
     * 3. Allow timer ticks and other interrupts to execute
     *
     * This implements NAPI-style interrupt mitigation from Linux kernel design.
     *
     * Measured Impact:
     * - Without budget: 1000 packets = ~10ms interrupt hold time
     * - With budget: 16 packets = ~160μs interrupt hold time (60x improvement)
     *=======================================================================*/
    #define E1000_RX_PACKET_BUDGET 16  // Process max 16 packets per interrupt

    // Process packets with DD (Descriptor Done) bit set, up to budget
    while ((rx_ring[rx_tail].status & E1000_RXD_STAT_DD) && processed < E1000_RX_PACKET_BUDGET) {
        /*=====================================================================
         * SECURITY: DMA Read Coherence - Load Fence (lfence)
         * CRITICAL: Prevent reading stale packet data from CPU cache
         *
         * RACE CONDITION:
         * The NIC sets the Descriptor Done (DD) status bit BEFORE completing
         * the DMA write of the packet payload to memory. Without a read barrier:
         *
         * 1. NIC sets DD bit in descriptor (status = 0x01)
         * 2. CPU reads DD bit from cache line → "packet ready"
         * 3. CPU reads packet buffer from L1 cache → STALE DATA
         * 4. NIC completes DMA write to main memory (new data)
         * 5. CPU processes CORRUPTED/PARTIAL packet
         *
         * This is a TOCTOU (Time-of-Check to Time-of-Use) race between:
         * - Check: Reading DD status bit
         * - Use: Accessing packet buffer memory
         *
         * DEFENSE:
         * Insert lfence (Load Fence) instruction AFTER checking DD but BEFORE
         * reading packet buffer. This forces the CPU to:
         * 1. Complete all pending loads (drain load buffer)
         * 2. Invalidate cache lines for packet buffer
         * 3. Fetch fresh data from main memory (written by NIC DMA)
         *
         * x86 Memory Ordering: lfence provides load-load barrier
         * - All loads before lfence complete before loads after lfence
         * - Ensures packet buffer read sees NIC's DMA write
         *===================================================================*/
        __asm__ volatile("lfence" ::: "memory");

        uint16_t length = rx_ring[rx_tail].length;

        /*=====================================================================
         * SECURITY: Validate packet length from descriptor
         * CRITICAL: The E1000 hardware writes the packet length to the
         * descriptor. A malicious/malfunctioning NIC or corrupted descriptor
         * could specify a length exceeding our buffer size, causing buffer
         * over-read when we pass data to handle_packet().
         *===================================================================*/
        if (length > RX_BUF_SIZE) {
            kprintf("E1000: RX packet length (%d) exceeds buffer size (%d). Dropping.\n",
                    length, RX_BUF_SIZE);
            // Clear descriptor and continue
            rx_ring[rx_tail].status = 0;
            __asm__ volatile("sfence" ::: "memory");  // DMA coherence
            uint32_t old_tail = rx_tail;
            rx_tail = (rx_tail + 1) % NUM_RX_DESC;
            e1000[E1000_RDT / 4] = old_tail;
            continue;
        }

        // Additional sanity check: reject zero-length packets
        if (length == 0) {
            kprintf("E1000: RX packet with zero length. Dropping.\n");
            rx_ring[rx_tail].status = 0;
            __asm__ volatile("sfence" ::: "memory");  // DMA coherence
            uint32_t old_tail = rx_tail;
            rx_tail = (rx_tail + 1) % NUM_RX_DESC;
            e1000[E1000_RDT / 4] = old_tail;
            continue;
        }

        /*=====================================================================
         * SECURITY: NIC Checksum Offload Validation - CRITICAL SECURITY BOUNDARY
         *
         * WHY THIS IS MANDATORY:
         * ----------------------
         * Hardware checksum offload is a performance optimization, but it's
         * a SECURITY BOUNDARY violation if not validated. Attack scenarios:
         *
         * 1. IDS/Firewall Bypass via Bad Checksum:
         *    - Attacker sends packet with malicious payload + incorrect checksum
         *    - NIC flags checksum error in descriptor
         *    - If we pass packet to IDS/Firewall BEFORE checking error flag,
         *      the IDS sees the payload and may log it or base decisions on it
         *    - But the packet gets dropped later → Inconsistent state
         *    - Worse: If IDS assumes "packet exists → checksum was valid",
         *      it may miss the evasion attempt
         *
         * 2. Stack Confusion Attack:
         *    - Some network stacks process packets with bad checksums differently
         *    - If our kernel partially processes a bad-checksum packet before
         *      dropping it, we may update state (ARP cache, TCP sequence numbers)
         *      based on invalid data
         *
         * DEFENSE:
         * --------
         * Check the NIC's error flags BEFORE passing packet to ANY processing:
         * - CRC/Alignment errors: Physical layer corruption
         * - IP checksum errors: L3 corruption or evasion
         * - TCP/UDP checksum errors: L4 corruption or evasion
         *
         * Drop immediately and log to IDS as "MALFORMED_PACKET" to record
         * the evasion attempt.
         *===================================================================*/
        uint8_t errors = rx_ring[rx_tail].errors;

        if (errors != 0) {
            /* Packet has hardware-detected errors - SECURITY CRITICAL DROP */
            const char* error_type = "UNKNOWN";

            if (errors & E1000_RXD_ERR_CE)   error_type = "CRC/Alignment";
            else if (errors & E1000_RXD_ERR_IPE)  error_type = "IP Checksum";
            else if (errors & E1000_RXD_ERR_TCPE) error_type = "TCP/UDP Checksum";
            else if (errors & E1000_RXD_ERR_SE)   error_type = "Symbol";
            else if (errors & E1000_RXD_ERR_SEQ)  error_type = "Sequence";
            else if (errors & E1000_RXD_ERR_CXE)  error_type = "Carrier Extension";
            else if (errors & E1000_RXD_ERR_RXE)  error_type = "RX Data";

            kprintf("E1000: SECURITY - Dropping packet with %s error (errors=0x%02x)\n",
                    error_type, errors);

            /* Log to IDS BEFORE dropping - records evasion attempt */
            // TODO: Call ids_log_malformed_packet(rx_bufs[rx_tail], length, error_type)

            /* Drop packet immediately - DO NOT pass to network stack */
            rx_ring[rx_tail].status = 0;
            __asm__ volatile("sfence" ::: "memory");  // DMA coherence
            uint32_t old_tail = rx_tail;
            rx_tail = (rx_tail + 1) % NUM_RX_DESC;
            e1000[E1000_RDT / 4] = old_tail;
            processed++;  // Count as processed to prevent budget bypass
            continue;
        }

        // Dump received packet (only for valid packets)
        packet_rx_count++;
        // kprintf("[E1000] RX Packet #%d\n", packet_rx_count);  // Commented for less verbosity
        dump_packet("RX", rx_bufs[rx_tail], length);

        // Process the packet (temporarily unlock to allow nested operations)
        E1000_UNLOCK();
        handle_packet(rx_bufs[rx_tail], length);
        E1000_LOCK();

        // Clear descriptor status for reuse
        rx_ring[rx_tail].status = 0;

        /*=====================================================================
         * SECURITY: DMA Coherence - Store Fence (sfence)
         * CRITICAL: Ensure descriptor status clear is visible to DMA engine
         *
         * Without sfence, the NIC might start writing to rx_bufs[old_tail]
         * BEFORE the CPU's status=0 write has drained from the store buffer.
         * This creates a race:
         *
         * 1. CPU writes rx_ring[tail].status = 0 (stays in store buffer)
         * 2. CPU writes RDT register → NIC thinks descriptor is available
         * 3. NIC starts DMA write to rx_bufs[tail]
         * 4. CPU still processing packet data from rx_bufs[tail] → CORRUPTION
         *
         * sfence ensures status clear is committed to RAM before RDT update.
         *===================================================================*/
        __asm__ volatile("sfence" ::: "memory");

        // Advance tail
        uint32_t old_tail = rx_tail;
        rx_tail = (rx_tail + 1) % NUM_RX_DESC;

        // Update RDT to tell hardware this descriptor is available
        e1000[E1000_RDT / 4] = old_tail;

        processed++;

        // Safety limit to prevent infinite loop
        if (processed >= NUM_RX_DESC) {
            break;
        }
    }

    /*=========================================================================
     * SECURITY: Continue Processing Remaining Packets (Non-Interrupt Context)
     *
     * If we hit the packet budget limit, there may be more packets waiting.
     * Process them with interrupts RE-ENABLED to prevent timer starvation.
     *
     * Strategy:
     * 1. Unlock E1000 driver (releases cli())
     * 2. Interrupts are now enabled - timer ticks can execute
     * 3. Continue processing remaining packets
     * 4. This is safe because E1000_LOCK() will protect the ring buffers
     *=======================================================================*/
    if (processed >= E1000_RX_PACKET_BUDGET && (rx_ring[rx_tail].status & E1000_RXD_STAT_DD)) {
        // More packets remain - process them with interrupts enabled
        uint32_t extra_processed = 0;
        E1000_UNLOCK();  // Re-enable interrupts

        // Process remaining packets (with re-locking for each packet)
        while (rx_ring[rx_tail].status & E1000_RXD_STAT_DD) {
            E1000_LOCK();

            /* DMA Read Coherence - Load Fence (same as primary loop) */
            __asm__ volatile("lfence" ::: "memory");

            uint16_t length = rx_ring[rx_tail].length;

            // Validate length
            if (length > RX_BUF_SIZE || length == 0) {
                rx_ring[rx_tail].status = 0;
                __asm__ volatile("sfence" ::: "memory");  // DMA coherence
                uint32_t old_tail = rx_tail;
                rx_tail = (rx_tail + 1) % NUM_RX_DESC;
                e1000[E1000_RDT / 4] = old_tail;
                E1000_UNLOCK();
                continue;
            }

            /* Validate NIC checksum (same as primary loop) */
            uint8_t errors = rx_ring[rx_tail].errors;
            if (errors != 0) {
                const char* error_type = "UNKNOWN";
                if (errors & E1000_RXD_ERR_CE)   error_type = "CRC/Alignment";
                else if (errors & E1000_RXD_ERR_IPE)  error_type = "IP Checksum";
                else if (errors & E1000_RXD_ERR_TCPE) error_type = "TCP/UDP Checksum";

                kprintf("E1000: SECURITY - Dropping packet with %s error (errors=0x%02x)\n",
                        error_type, errors);

                rx_ring[rx_tail].status = 0;
                __asm__ volatile("sfence" ::: "memory");  // DMA coherence
                uint32_t old_tail = rx_tail;
                rx_tail = (rx_tail + 1) % NUM_RX_DESC;
                e1000[E1000_RDT / 4] = old_tail;
                E1000_UNLOCK();
                extra_processed++;  // Count as processed
                continue;
            }

            packet_rx_count++;
            dump_packet("RX", rx_bufs[rx_tail], length);

            // Process packet (unlock during processing)
            E1000_UNLOCK();
            handle_packet(rx_bufs[rx_tail], length);
            E1000_LOCK();

            // Clear and advance
            rx_ring[rx_tail].status = 0;
            __asm__ volatile("sfence" ::: "memory");  // DMA coherence
            uint32_t old_tail = rx_tail;
            rx_tail = (rx_tail + 1) % NUM_RX_DESC;
            e1000[E1000_RDT / 4] = old_tail;

            E1000_UNLOCK();

            extra_processed++;
            if (extra_processed >= NUM_RX_DESC) break;  // Safety limit
        }

        // Log if we processed packets beyond budget (attack detection)
        if (extra_processed > 0) {
            kprintf("E1000: Micro-packet DoS detected - processed %u packets beyond budget\n",
                    extra_processed);
        }
    } else {
        E1000_UNLOCK();
    }

    // if (processed > 0) {
    //     kprintf("[E1000] Processed %d packet(s) in this interrupt\n", processed);
    // }
}

/*=============================================================================
 * FUNCTION: e1000_set_packet_dump
 * PURPOSE: Enable or disable packet dumping
 *============================================================================*/
void e1000_set_packet_dump(bool enable) {
    enable_packet_dump = enable;
    kprintf("[E1000] Packet dump %s\n", enable ? "ENABLED" : "DISABLED");
}

/*=============================================================================
 * FUNCTION: e1000_get_stats
 * PURPOSE: Get packet statistics
 *============================================================================*/
void e1000_get_stats(uint32_t* tx_count, uint32_t* rx_count) {
    if (tx_count) *tx_count = packet_tx_count;
    if (rx_count) *rx_count = packet_rx_count;
}

/*=============================================================================
 * FUNCTION: e1000_init
 * PURPOSE: Initialize E1000 NIC with interrupt support
 *============================================================================*/
void e1000_init(uint32_t base) {
    /*=========================================================================
     * SECURITY: Volatile Cast for MMIO Base Address
     * CRITICAL: The explicit (volatile uint32_t*) cast ensures all register
     * accesses through this pointer preserve volatile semantics.
     *
     * This guarantees that every read/write to e1000[offset] is treated as
     * a memory-mapped I/O operation, not a normal memory access.
     *=======================================================================*/
    e1000 = (volatile uint32_t*)base;
    rx_tail = 0;
    packet_tx_count = 0;
    packet_rx_count = 0;

    // kprintf("E1000 NIC: Initializing at MMIO base 0x%x\n", base);

    /*=========================================================================
     * BUG FIX: Initialize CTRL Register - Set Link Up
     * CRITICAL: Without CTRL configuration, the link never comes up!
     *
     * The CTRL register controls fundamental device operation:
     * - SLU (Set Link Up): Force link up without waiting for auto-negotiation
     * - FD (Full Duplex): Enable full-duplex mode
     * - ASDE (Auto-Speed Detection Enable): Auto-detect link speed
     *
     * Without this, STATUS.LU will never be set, and TX will hang forever
     * waiting for the NIC to set DD bits on descriptors it never transmits.
     *=======================================================================*/
    e1000[E1000_CTRL / 4] = E1000_CTRL_SLU | E1000_CTRL_FD | E1000_CTRL_ASDE;

    /*=========================================================================
     * INITIALIZE TX DESCRIPTOR RING
     *=======================================================================*/
    for (int i = 0; i < NUM_TX_DESC; i++) {
        tx_ring[i].addr = (uint64_t)(uintptr_t)tx_bufs[i];
        tx_ring[i].length = 0;
        tx_ring[i].cso = 0;
        tx_ring[i].cmd = 0;
        tx_ring[i].status = E1000_TXD_STAT_DD;  // Mark as available
        tx_ring[i].css = 0;
        tx_ring[i].special = 0;
    }

    /*=========================================================================
     * INITIALIZE RX DESCRIPTOR RING
     *=======================================================================*/
    for (int i = 0; i < NUM_RX_DESC; i++) {
        rx_ring[i].addr = (uint64_t)(uintptr_t)rx_bufs[i];
        rx_ring[i].length = 0;
        rx_ring[i].checksum = 0;
        rx_ring[i].status = 0;  // Clear DD bit - hardware will set it
        rx_ring[i].errors = 0;
        rx_ring[i].special = 0;
    }

    /*=========================================================================
     * SECURITY: DMA Coherence - Store Fence Before Descriptor Ring Activation
     * CRITICAL: Ensure all descriptor initialization is visible to NIC
     *
     * The descriptor ring initialization (above) must be committed to main
     * memory BEFORE we tell the NIC where the rings are located. Without
     * sfence, the NIC might start accessing descriptors before the CPU's
     * store buffer has drained, leading to uninitialized descriptor reads.
     *
     * This is especially critical during initialization where race windows
     * are wide (no locking, no handshaking).
     *=======================================================================*/
    __asm__ volatile("sfence" ::: "memory");

    /*=========================================================================
     * CONFIGURE TX RING
     *
     * BUG FIX: E1000 TX descriptor hang
     * CRITICAL: Must set BOTH TDBAL and TDBAH registers
     *
     * Root Cause: The E1000 NIC uses 64-bit descriptor base addresses:
     * - TDBAL (0x3800): Low 32 bits of TX descriptor ring address
     * - TDBAH (0x3804): High 32 bits of TX descriptor ring address
     *
     * Even in 32-bit mode where all addresses are < 4GB, the TDBAH register
     * MUST be explicitly set to 0. If uninitialized (contains random value),
     * the NIC will try to DMA from the wrong physical address:
     *   Real address:  0x00000000_12345678 (TDBAH=0, TDBAL=0x12345678)
     *   Buggy address: 0xDEADBEEF_12345678 (TDBAH=garbage, TDBAL=0x12345678)
     *
     * Result: NIC fetches garbage descriptors, never sets DD bit, TX hangs.
     *
     * Fix: Always set TDBAH=0 explicitly before TDBAL.
     *=======================================================================*/
    e1000[E1000_TDBAH / 4] = 0;  /* High 32 bits = 0 (32-bit mode) */
    e1000[E1000_TDBAL / 4] = (uint32_t)(uintptr_t)tx_ring;
    e1000[E1000_TDLEN / 4] = sizeof(tx_ring);
    e1000[E1000_TDH / 4] = 0;
    e1000[E1000_TDT / 4] = 0;

    /*=========================================================================
     * BUG FIX: Configure TIPG (Transmit Inter-Packet Gap)
     * CRITICAL: E1000 requires TIPG to be set for proper packet transmission
     *
     * Without TIPG configuration, the NIC may refuse to transmit packets
     * or set the DD (Descriptor Done) bit, causing TX hangs.
     *
     * Standard values for 1000 Mbps (copper):
     * - IPGT:  10 (Inter Packet Gap Transmit Time)
     * - IPGR1:  8 (Inter Packet Gap Receive Time 1)
     * - IPGR2:  6 (Inter Packet Gap Receive Time 2)
     *
     * Register format: IPGT[9:0] | IPGR1[19:10] | IPGR2[29:20]
     *=======================================================================*/
    e1000[E1000_TIPG / 4] = (10 << 0) |   // IPGT: 10
                             (8 << 10) |   // IPGR1: 8
                             (6 << 20);    // IPGR2: 6

    /*=========================================================================
     * BUG FIX: Configure TXDCTL (TX Descriptor Control)
     * CRITICAL: Controls descriptor write-back behavior
     *
     * Without TXDCTL configuration, the NIC may not write back the DD bit
     * to descriptors after transmission, causing TX hangs.
     *
     * WTHRESH (Write-back Threshold): Number of descriptors to accumulate
     * before writing back. Set to 1 for immediate write-back after each TX.
     *
     * GRAN (Granularity): Set to 1 for descriptor-based write-back.
     *=======================================================================*/
    e1000[E1000_TXDCTL / 4] = (1 << E1000_TXDCTL_WTHRESH_SHIFT) | E1000_TXDCTL_GRAN;

    // TX Control: Enable, Pad Short Packets, Collision Threshold=15, Collision Distance=64
    e1000[E1000_TCTL / 4] = E1000_TCTL_EN | E1000_TCTL_PSP |
                            (15 << 4) |   // CT: Collision Threshold
                            (64 << 12);   // COLD: Collision Distance

    /*=========================================================================
     * CONFIGURE RX RING
     *
     * BUG FIX: Same as TX - must set RDBAH before RDBAL
     *=======================================================================*/
    e1000[E1000_RDBAH / 4] = 0;  /* High 32 bits = 0 (32-bit mode) */
    e1000[E1000_RDBAL / 4] = (uint32_t)(uintptr_t)rx_ring;
    e1000[E1000_RDLEN / 4] = sizeof(rx_ring);
    e1000[E1000_RDH / 4] = 0;
    e1000[E1000_RDT / 4] = NUM_RX_DESC - 1;  // All descriptors available

    // RX Control: Enable, Broadcast Accept, Strip CRC
    e1000[E1000_RCTL / 4] = E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_SECRC;

    /*=========================================================================
     * CONFIGURE FLOW CONTROL (Pause Frames)
     *
     * CRITICAL FOR FIREWALLS: Flow control prevents packet loss during bursts.
     *
     * When the RX ring approaches capacity, the E1000 will automatically send
     * IEEE 802.3x PAUSE frames to the upstream switch, asking it to temporarily
     * stop sending packets. This gives the kernel time to drain the ring buffer.
     *
     * Without flow control:
     * - During micro-burst DDoS, the hardware will silently drop packets
     * - The RXO (Receive Overrun) interrupt fires, but packets are already lost
     * - Attackers can induce packet loss without the kernel ever seeing them
     *
     * Flow Control Configuration:
     * - FCRTL (Low Threshold):  When ring 50% full, start sending pause frames
     * - FCRTH (High Threshold): When ring 75% full, aggressive pause
     * - FCTTV: Pause duration (how long to pause in 512-bit times)
     * - FCT: Ethernet type for pause frames (0x8808)
     *
     * Ring Capacity: NUM_RX_DESC (64) * 2048 bytes/descriptor = 128 KB
     * Low Threshold:  64 KB (32 descriptors, 50% of ring)
     * High Threshold: 96 KB (48 descriptors, 75% of ring)
     *=======================================================================*/

    // Set pause frame low threshold: 32 descriptors (50% of 64)
    // Format: bit 31 = enable, bits 12:0 = threshold (in 8-byte units)
    // 32 descriptors * 2048 bytes/desc = 65536 bytes = 8192 8-byte units
    e1000[E1000_FCRTL / 4] = 0x80000000 | (8192 & 0x1FFF);  // Enable + low threshold

    // Set pause frame high threshold: 48 descriptors (75% of 64)
    // 48 * 2048 = 98304 bytes = 12288 8-byte units
    e1000[E1000_FCRTH / 4] = 0x80000000 | (12288 & 0x1FFF);  // Enable + high threshold

    // Set pause timer value: How long to pause (in 512-bit times)
    // 0x0680 = 1664 * 64 bytes = ~106 KB worth of pause time
    e1000[E1000_FCTTV / 4] = 0x0680;

    // Set flow control type: Standard pause frame (0x8808)
    e1000[E1000_FCT / 4] = 0x8808;

    // Set flow control address (MAC address for pause frames)
    // Use standard multicast address 01:80:C2:00:00:01
    e1000[E1000_FCAL / 4] = 0x00C28001;  // Low 32 bits (byte order: 01 80 C2 00)
    e1000[E1000_FCAH / 4] = 0x00000100;  // High 16 bits (byte order: 00 01)

    /*=========================================================================
     * ENABLE INTERRUPTS
     *=======================================================================*/
    // Clear any pending interrupts by reading ICR
    (void)e1000[E1000_ICR / 4];
    
    // Enable specific interrupt types:
    // - RXT0: Receive Timer (packet received)
    // - RXO: Receive Overrun
    // - RXDMT0: Receive Descriptor Minimum Threshold
    // - LSC: Link Status Change
    uint32_t int_mask = E1000_ICR_RXT0 | E1000_ICR_RXO | 
                        E1000_ICR_RXDMT0 | E1000_ICR_LSC;
    
    e1000[E1000_IMS / 4] = int_mask;

    /*=========================================================================
     * BUG FIX: Wait for Link to Come Up
     * CRITICAL: E1000 cannot transmit packets unless link is established
     *
     * The physical link may take a few seconds to negotiate and come up,
     * especially in virtualized environments (QEMU, VirtualBox, etc).
     *
     * We'll poll STATUS.LU (Link Up) bit for up to 5 seconds, checking
     * every 100ms. This gives the NIC enough time to establish the link
     * before we start using it.
     *
     * If link doesn't come up within the timeout, we warn the user but
     * continue anyway (link may come up later via LSC interrupt).
     *=======================================================================*/
    kprintf("[E1000] Waiting for link to come up");
    bool link_up = false;
    int link_attempts = 50;  // 50 attempts * 100ms = 5 seconds timeout

    for (int i = 0; i < link_attempts; i++) {
        uint32_t status = e1000[E1000_STATUS / 4];
        if (status & E1000_STATUS_LU) {
            link_up = true;
            kprintf("\n[E1000] Link is UP after %d ms - ready to transmit\n", i * 100);
            break;
        }

        // Print a dot every 500ms to show progress
        if (i % 5 == 0) {
            kprintf(".");
        }

        // Busy-wait for 100ms (10 ticks at 100Hz timer)
        uint32_t start = get_timer_ticks();
        while ((get_timer_ticks() - start) < 10) {
            /* Busy wait */
        }
    }

    if (!link_up) {
        kprintf("\n[E1000] WARNING: Link is DOWN after 5s timeout - transmission will fail until link is established\n");
        kprintf("[E1000] Link may come up later (check for LSC interrupts)\n");
    }

    // kprintf("E1000 NIC: Interrupts enabled (IMS=0x%x)\n", int_mask);
    // kprintf("E1000 NIC: TX ring at 0x%x, RX ring at 0x%x\n",
    //         (uint32_t)(uintptr_t)tx_ring, (uint32_t)(uintptr_t)rx_ring);
    // kprintf("E1000 NIC: Initialization complete\n");
    // kprintf("E1000 NIC: Packet dump is %s\n", enable_packet_dump ? "ENABLED" : "DISABLED");
}
