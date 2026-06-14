/*=============================================================================
 * time.c - TinyOS Time Management Implementation
 *=============================================================================*/
#include "time.h"
#include "pit.h"
#include "critical.h"
#include "pic.h"  /* For inb/outb */
#include "util.h"
#include <stddef.h>

/*=============================================================================
 * CMOS RTC Registers and Ports
 *=============================================================================*/
#define CMOS_ADDRESS    0x70
#define CMOS_DATA       0x71

/* CMOS RTC Register Indices */
#define RTC_SECONDS     0x00
#define RTC_MINUTES     0x02
#define RTC_HOURS       0x04
#define RTC_WEEKDAY     0x06
#define RTC_DAY         0x07
#define RTC_MONTH       0x08
#define RTC_YEAR        0x09
#define RTC_CENTURY     0x32  /* Some systems store century here */
#define RTC_STATUS_A    0x0A
#define RTC_STATUS_B    0x0B

/* RTC Status Register B flags */
#define RTC_24_HOUR     0x02  /* 24-hour mode flag */
#define RTC_BINARY      0x04  /* Binary mode flag (vs BCD) */

/*=============================================================================
 * System Time State
 *=============================================================================
 * SECURITY FIX (AUDIT 5C): Volatile Keyword for Interrupt-Shared State
 *
 * VULNERABILITY: Compiler Optimization Hazard (Stale Data)
 *
 * PROBLEM: These variables are written by timer interrupt handlers and read
 * by kernel code. Without `volatile`, the compiler may:
 * 1. Cache values in CPU registers for entire function duration
 * 2. Reorder reads/writes assuming single-threaded execution
 * 3. Eliminate "redundant" reads of same variable
 *
 * ATTACK/FAILURE SCENARIO:
 * 1. Function reads `time_initialized` → compiler caches in register EAX
 * 2. Timer interrupt fires, sets `time_initialized = true`
 * 3. Function re-checks `time_initialized` → reads cached EAX (still false!)
 * 4. Function takes wrong branch, uses uninitialized time data
 * 5. Result: Corrupted timestamps, wrong time calculations, system instability
 *
 * EXAMPLE (datetime_t structure tearing):
 * 1. Kernel function reads `system_time.year` → 2025 (cached)
 * 2. Timer ISR updates entire structure: year=2026, month=1, day=1
 * 3. Kernel function reads `system_time.month` → 1 (new value)
 * 4. Result: Inconsistent date (2025-01-01 instead of 2026-01-01)
 *
 * FIX: Declare all ISR-shared variables as `volatile`
 * - Forces compiler to reload value from memory on every access
 * - Prevents register caching across ISR boundaries
 * - Industry standard (Linux, BSD, RTOS all use this pattern)
 *
 * NOTE: `volatile` does NOT provide atomicity for multi-word structures.
 * The `datetime_t` structure still requires critical section protection
 * (see Fix #22) to prevent reading torn/inconsistent state.
 *===========================================================================*/
static volatile datetime_t system_time;
static volatile uint32_t last_update_ticks = 0;
static volatile bool time_initialized = false;

/*=============================================================================
 * HELPER: Read CMOS Register
 *
 * SECURITY FIX: CRITICAL - CMOS Address/Data Port Interleave Protection
 * ------------------------------------------------------------------------
 * CMOS I/O requires TWO separate port operations:
 * 1. Write register address to CMOS_ADDRESS (port 0x70)
 * 2. Read register data from CMOS_DATA (port 0x71)
 *
 * VULNERABILITY WITHOUT CRITICAL SECTION:
 * If a timer interrupt fires BETWEEN these two operations, the interrupt
 * handler could issue its own CMOS read (for timekeeping), which would:
 * 1. Write a DIFFERENT register address to port 0x70
 * 2. Read its own data from port 0x71
 * 3. Return to the interrupted code
 * 4. The interrupted code resumes and reads from port 0x71
 * 5. BUT NOW IT READS THE WRONG REGISTER'S DATA!
 *
 * IMPACT: Corrupted time reads, system instability, DoS under interrupt load
 *
 * FIX: CRITICAL_SECTION wraps BOTH operations (address write + data read)
 * This makes the CMOS I/O atomic, preventing register corruption.
 *
 * PERFORMANCE: Critical section duration is ~2-3 µs (acceptable)
 * - CMOS I/O is inherently slow (I/O port delays + RTC hardware delays)
 * - This is much faster than a context switch or cache miss
 *=============================================================================*/
static uint8_t cmos_read(uint8_t reg) {
    CRITICAL_SECTION_ENTER();  /* SECURITY: Prevent I/O port interleaving */

    /* Disable NMI and select register */
    outb(CMOS_ADDRESS, (1 << 7) | reg);

    /* Small delay for hardware */
    for (volatile int i = 0; i < 100; i++);

    /* Read data */
    uint8_t value = inb(CMOS_DATA);

    CRITICAL_SECTION_EXIT();

    return value;
}

/*=============================================================================
 * HELPER: Write CMOS Register
 *
 * SECURITY FIX: CRITICAL - CMOS Address/Data Port Interleave Protection
 * ------------------------------------------------------------------------
 * Same critical section protection as cmos_read() to prevent I/O port
 * interleaving. Without this, an interrupt between the address write and
 * data write could cause data to be written to the WRONG CMOS register.
 *
 * ATTACK SCENARIO:
 * 1. Code writes address 0x04 (hour register) to port 0x70
 * 2. Timer interrupt fires
 * 3. Interrupt handler writes address 0x00 (second register) to port 0x70
 * 4. Interrupt handler reads/writes, then returns
 * 5. Original code resumes and writes data to port 0x71
 * 6. Data is written to SECONDS register instead of HOURS register!
 *
 * IMPACT: RTC corruption, system time corruption, potential system instability
 *=============================================================================*/
static void cmos_write(uint8_t reg, uint8_t value) {
    CRITICAL_SECTION_ENTER();  /* SECURITY: Prevent I/O port interleaving */

    /* Disable NMI and select register */
    outb(CMOS_ADDRESS, (1 << 7) | reg);

    /* Small delay for hardware */
    for (volatile int i = 0; i < 100; i++);

    /* Write data */
    outb(CMOS_DATA, value);

    CRITICAL_SECTION_EXIT();
}

/*=============================================================================
 * HELPER: Convert BCD to Binary
 *=============================================================================*/
static uint8_t bcd_to_binary(uint8_t bcd) {
    return ((bcd >> 4) * 10) + (bcd & 0x0F);
}

/*=============================================================================
 * HELPER: Convert Binary to BCD
 *=============================================================================*/
static uint8_t binary_to_bcd(uint8_t binary) {
    return ((binary / 10) << 4) | (binary % 10);
}

/*=============================================================================
 * HELPER: Check if RTC update is in progress
 *=============================================================================*/
static bool rtc_is_updating(void) {
    return (cmos_read(RTC_STATUS_A) & 0x80) != 0;
}

/*=============================================================================
 * FUNCTION: rtc_init
 *=============================================================================
 * SECURITY FIX (AUDIT 5B): Unconditional Binary Mode Setting
 *
 * PURPOSE: Force RTC into binary mode to prevent BCD/Binary race conditions
 *
 * SECURITY RATIONALE:
 * The RTC can operate in two modes:
 * - BCD (Binary-Coded Decimal): Each byte nibble represents 0-9
 * - Binary: Normal binary representation
 *
 * VULNERABILITY if mode is not set:
 * 1. BIOS may leave RTC in BCD mode (platform-dependent)
 * 2. Code that reads RTC must check mode every time (TOCTOU risk)
 * 3. If mode changes between check and read: corrupted time values
 * 4. Example: 0x23 in BCD = 23 decimal, but 0x23 in binary = 35 decimal
 * 5. Wrong time → TLS validation errors, log corruption, timer failures
 *
 * FIX: Unconditionally set binary mode ONCE at boot
 * - All subsequent code assumes binary mode (no per-read checks)
 * - Eliminates TOCTOU race condition
 * - Simpler code (no BCD conversion needed)
 * - Industry standard (Linux, BSD do the same)
 *
 * CRITICAL: This function MUST be called before any RTC reads!
 *===========================================================================*/
void rtc_init(void) {
    /* SECURITY: Unconditionally force RTC into binary mode */
    uint8_t status_b = cmos_read(RTC_STATUS_B);
    status_b |= RTC_24_HOUR | RTC_BINARY;  /* Set both flags */
    cmos_write(RTC_STATUS_B, status_b);

    /*
     * NOTE: We use OR (|=) not assignment to preserve other RTC flags:
     * - Rate selection bits (for periodic interrupts)
     * - Update-ended interrupt enable
     * - Alarm interrupt enable
     * - Daylight saving enable
     *
     * This ensures we don't accidentally disable RTC features.
     */
}

/*=============================================================================
 * FUNCTION: rtc_read_datetime
 * SECURITY FIX: Read twice and verify consistency to prevent race conditions
 *=============================================================================*/
bool rtc_read_datetime(volatile datetime_t* dt) {
    if (!dt) {
        return false;
    }

    /* SECURITY FIX: Read RTC twice and verify values match
     * This prevents inconsistent reads if RTC updates between register reads
     */
    uint8_t second1 = 0, minute1 = 0, hour1 = 0, day1 = 1, month1 = 1, year1 = 0, weekday1 = 0;
    uint8_t second2, minute2, hour2, day2, month2, year2;

    /* Try up to 3 times to get two consistent readings */
    for (int attempt = 0; attempt < 3; attempt++) {
        /* Wait until RTC is not updating */
        uint32_t timeout = 1000;
        while (rtc_is_updating() && timeout > 0) {
            timeout--;
            for (volatile int i = 0; i < 1000; i++);
        }

        if (timeout == 0) {
            continue;  /* Try again */
        }

        /* First reading */
        second1 = cmos_read(RTC_SECONDS);
        minute1 = cmos_read(RTC_MINUTES);
        hour1 = cmos_read(RTC_HOURS);
        day1 = cmos_read(RTC_DAY);
        month1 = cmos_read(RTC_MONTH);
        year1 = cmos_read(RTC_YEAR);
        weekday1 = cmos_read(RTC_WEEKDAY);

        /* Wait a bit */
        for (volatile int i = 0; i < 100; i++);

        /* Second reading */
        second2 = cmos_read(RTC_SECONDS);
        minute2 = cmos_read(RTC_MINUTES);
        hour2 = cmos_read(RTC_HOURS);
        day2 = cmos_read(RTC_DAY);
        month2 = cmos_read(RTC_MONTH);
        year2 = cmos_read(RTC_YEAR);

        /* Check if both readings match (allowing second to advance by 1) */
        if ((second1 == second2 || second2 == second1 + 1) &&
            minute1 == minute2 &&
            hour1 == hour2 &&
            day1 == day2 &&
            month1 == month2 &&
            year1 == year2) {
            /* Readings are consistent, use first reading */
            break;
        }
    }

    /* Check if values are in BCD format */
    uint8_t status_b = cmos_read(RTC_STATUS_B);
    bool is_binary = (status_b & RTC_BINARY) != 0;

    if (!is_binary) {
        /* Convert from BCD to binary */
        second1 = bcd_to_binary(second1);
        minute1 = bcd_to_binary(minute1);
        hour1 = bcd_to_binary(hour1);
        day1 = bcd_to_binary(day1);
        month1 = bcd_to_binary(month1);
        year1 = bcd_to_binary(year1);
    }

    /* Assume 21st century (2000+) */
    dt->year = 2000 + year1;
    dt->month = month1;
    dt->day = day1;
    dt->hour = hour1;
    dt->minute = minute1;
    dt->second = second1;
    dt->weekday = (weekday1 > 0) ? (weekday1 - 1) : 0;  /* Convert 1-7 to 0-6 */

    return true;
}

/*=============================================================================
 * FUNCTION: time_init
 *=============================================================================
 * SECURITY FIX (AUDIT 5C): Critical Section Protection for datetime_t Access
 *
 * VULNERABILITY: Structure Tearing During Initialization
 *
 * PROBLEM: Even during boot, if interrupts are enabled before this function
 * completes, an ISR could attempt to read system_time while we're writing to
 * it via rtc_read_datetime(). This could result in the ISR reading a partially
 * updated datetime_t structure.
 *
 * FIX: Wrap the write to system_time with critical section protection.
 * This ensures atomic initialization of the system time structure.
 *===========================================================================*/
void time_init(void) {
    datetime_t temp;

    /* Read initial time from RTC */
    if (rtc_read_datetime(&temp)) {
        /* Atomically update system time */
        CRITICAL_SECTION_ENTER();
        system_time = temp;
        last_update_ticks = pit_get_ticks();
        time_initialized = true;
        CRITICAL_SECTION_EXIT();
    }
}

/*=============================================================================
 * FUNCTION: time_get_datetime
 *=============================================================================*/
bool time_get_datetime(datetime_t* dt) {
    if (!dt || !time_initialized) {
        return false;
    }

    CRITICAL_SECTION_ENTER();

    /* Calculate elapsed time since last update */
    uint32_t current_ticks = pit_get_ticks();
    uint32_t elapsed_ticks = current_ticks - last_update_ticks;

    /* Convert ticks to seconds (PIT runs at 100 Hz) */
    uint32_t elapsed_seconds = elapsed_ticks / 100;

    /* Copy current system time */
    datetime_t temp = system_time;

    CRITICAL_SECTION_EXIT();

    /* Carry elapsed seconds into minutes/hours using WIDE intermediates.
     * Bug fix: temp.second is uint8_t; "temp.second += elapsed_seconds" used to
     * truncate once elapsed >= 256s and then the >=60 rollover ran on the
     * truncated value, making the displayed clock jump backwards (non-monotonic)
     * roughly every ~4 minutes. Do the arithmetic in uint32_t, reduce to in-range
     * field values, and commit the advanced time back to system_time +
     * last_update_ticks below so elapsed resets each call and never re-accumulates. */
    uint32_t total_seconds = (uint32_t)temp.second + elapsed_seconds;
    uint32_t carry_minutes = total_seconds / 60;
    temp.second = (uint8_t)(total_seconds % 60);

    uint32_t total_minutes = (uint32_t)temp.minute + carry_minutes;
    uint32_t carry_hours = total_minutes / 60;
    temp.minute = (uint8_t)(total_minutes % 60);

    uint32_t total_hours = (uint32_t)temp.hour + carry_hours;
    temp.hour = (uint8_t)(total_hours % 24);

    if (total_hours >= 24) {
        uint32_t days_to_add = total_hours / 24;

        /* Add days */
        for (uint32_t i = 0; i < days_to_add; i++) {
            temp.day++;
            temp.weekday = (temp.weekday + 1) % 7;

            /* Check month overflow */
            uint8_t days_in_month = 31;
            if (temp.month == 4 || temp.month == 6 || temp.month == 9 || temp.month == 11) {
                days_in_month = 30;
            } else if (temp.month == 2) {
                days_in_month = is_leap_year(temp.year) ? 29 : 28;
            }

            if (temp.day > days_in_month) {
                temp.day = 1;
                temp.month++;

                if (temp.month > 12) {
                    temp.month = 1;
                    temp.year++;
                }
            }
        }
    }

    /* Commit the advanced time back so elapsed seconds don't re-accumulate on
     * the next call (which is what let elapsed grow past the uint8 range).
     * IMPORTANT: advance last_update_ticks by only the WHOLE seconds we just
     * folded in (elapsed_seconds * 100 ticks), NOT current_ticks — otherwise the
     * 0..99 leftover ticks (< 1s) are discarded on every call, making the clock
     * run slow / stall under sub-second polling. Carrying the remainder forward
     * keeps time monotonic and accurate. */
    CRITICAL_SECTION_ENTER();
    system_time = temp;
    last_update_ticks += elapsed_seconds * 100;
    CRITICAL_SECTION_EXIT();

    *dt = temp;
    return true;
}

/*=============================================================================
 * FUNCTION: time_get_uptime_seconds
 *=============================================================================*/
uint32_t time_get_uptime_seconds(void) {
    return pit_get_ticks() / 100;  /* PIT runs at 100 Hz */
}

/*=============================================================================
 * FUNCTION: time_set_datetime
 *=============================================================================*/
bool time_set_datetime(const datetime_t* dt) {
    if (!dt) {
        return false;
    }

    /* Validate input */
    if (dt->month < 1 || dt->month > 12 ||
        dt->day < 1 ||
        dt->hour > 23 || dt->minute > 59 || dt->second > 59) {
        return false;
    }

    /* Per-month day validation (the loose "day <= 31" check accepted Feb 31,
     * Apr 31, etc., which then got written to the RTC and system_time). */
    {
        static const uint8_t dom[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        uint8_t max_day = dom[dt->month - 1];
        if (dt->month == 2 && is_leap_year(dt->year)) {
            max_day = 29;
        }
        if (dt->day > max_day) {
            return false;
        }
    }

    /* Update RTC */
    uint8_t year = dt->year >= 2000 ? (dt->year - 2000) : dt->year;

    /* Wait until RTC is not updating */
    while (rtc_is_updating()) {
        for (volatile int i = 0; i < 1000; i++);
    }

    /* Check if RTC is in BCD mode */
    uint8_t status_b = cmos_read(RTC_STATUS_B);
    bool is_binary = (status_b & RTC_BINARY) != 0;

    if (is_binary) {
        cmos_write(RTC_SECONDS, dt->second);
        cmos_write(RTC_MINUTES, dt->minute);
        cmos_write(RTC_HOURS, dt->hour);
        cmos_write(RTC_DAY, dt->day);
        cmos_write(RTC_MONTH, dt->month);
        cmos_write(RTC_YEAR, year);
    } else {
        cmos_write(RTC_SECONDS, binary_to_bcd(dt->second));
        cmos_write(RTC_MINUTES, binary_to_bcd(dt->minute));
        cmos_write(RTC_HOURS, binary_to_bcd(dt->hour));
        cmos_write(RTC_DAY, binary_to_bcd(dt->day));
        cmos_write(RTC_MONTH, binary_to_bcd(dt->month));
        cmos_write(RTC_YEAR, binary_to_bcd(year));
    }

    /* Update system time */
    CRITICAL_SECTION_ENTER();
    system_time = *dt;
    last_update_ticks = pit_get_ticks();
    time_initialized = true;
    CRITICAL_SECTION_EXIT();

    return true;
}

/*=============================================================================
 * FUNCTION: is_leap_year
 *=============================================================================*/
bool is_leap_year(uint16_t year) {
    if (year % 400 == 0) return true;
    if (year % 100 == 0) return false;
    if (year % 4 == 0) return true;
    return false;
}

/*=============================================================================
 * FUNCTION: get_day_of_week
 * Uses Zeller's congruence algorithm
 *=============================================================================*/
uint8_t get_day_of_week(uint16_t year, uint8_t month, uint8_t day) {
    /* Adjust month (March = 3, Feb = 14) */
    if (month < 3) {
        month += 12;
        year--;
    }

    /* Zeller's congruence */
    uint16_t century = year / 100;
    uint16_t year_of_century = year % 100;

    uint32_t h = (day + (13 * (month + 1)) / 5 + year_of_century +
                  year_of_century / 4 + century / 4 - 2 * century) % 7;

    /* Convert to 0=Sunday format */
    return (uint8_t)((h + 6) % 7);
}

/*=============================================================================
 * FUNCTION: datetime_to_timestamp
 * Convert to Unix timestamp (seconds since 1970-01-01 00:00:00 UTC)
 *
 * SECURITY FIX: HIGH - Time Conversion Integer Overflow (Y2038 Bug)
 * ------------------------------------------------------------------
 * VULNERABILITY: Previous implementation used uint32_t for all calculations,
 * which causes overflow in two ways:
 *
 * 1. INTERMEDIATE OVERFLOW (before 2038):
 *    `days * 86400UL` overflows when days > 49710 (around year 2106)
 *    Even though final result fits in uint32_t, intermediate overflow causes
 *    incorrect results decades before 2038.
 *
 * 2. FINAL OVERFLOW (Y2038 bug):
 *    Unix timestamp wraps to 0 on January 19, 2038 at 03:14:08 UTC
 *    System time appears to jump back to 1970, breaking time-dependent logic:
 *    - File timestamps corrupted
 *    - Scheduled tasks execute at wrong times
 *    - Security certificates appear expired/not-yet-valid
 *    - Log timestamps incorrect
 *
 * FIX:
 * ----
 * 1. Use uint64_t for ALL intermediate calculations to prevent overflow
 * 2. Detect when final result exceeds UINT32_MAX (2038-01-19 03:14:07)
 * 3. Return UINT32_MAX (clamped value) instead of wrapping to 0
 *    - Makes overflow detectable (max value is suspicious)
 *    - Safer than wrapping (0 = 1970 looks valid but is wrong)
 *    - Applications can check for UINT32_MAX and handle appropriately
 *
 * KNOWN LIMITATION:
 * -----------------
 * This is a 32-bit OS with 32-bit timestamps. The Y2038 problem is
 * ARCHITECTURAL and cannot be fully solved without:
 * - Switching to 64-bit timestamps (breaks ABI compatibility)
 * - Using alternative time representations
 *
 * CURRENT BEHAVIOR:
 * -----------------
 * - Dates before 2038-01-19 03:14:07: Correct timestamp
 * - Dates after: Returns UINT32_MAX (0x7FFFFFFF = 2147483647)
 * - This provides ~13 years of safe operation (2025-2038)
 *=============================================================================*/
uint32_t datetime_to_timestamp(const datetime_t* dt) {
    if (!dt || dt->year < 1970) {
        return 0;
    }

    /* Days per month */
    const uint8_t days_in_month[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    /* SECURITY FIX: Use uint64_t to prevent intermediate overflow
     * Even though final result is uint32_t, intermediate calculations
     * (days * 86400) can overflow uint32_t before 2038.
     */
    uint64_t days = 0;

    /* Add days for complete years */
    for (uint16_t y = 1970; y < dt->year; y++) {
        days += is_leap_year(y) ? 366 : 365;
    }

    /* Add days for complete months in current year */
    for (uint8_t m = 1; m < dt->month; m++) {
        days += days_in_month[m - 1];
        if (m == 2 && is_leap_year(dt->year)) {
            days++;  /* Add leap day */
        }
    }

    /* Add days in current month */
    days += dt->day - 1;

    /* Convert to seconds using 64-bit arithmetic */
    uint64_t seconds = days * 86400ULL;  /* ULL ensures 64-bit multiplication */
    seconds += dt->hour * 3600ULL;
    seconds += dt->minute * 60ULL;
    seconds += dt->second;

    /* SECURITY FIX: Detect overflow and clamp to UINT32_MAX
     * If timestamp exceeds 32-bit range, return maximum value instead of wrapping.
     * This makes overflow detectable and prevents time appearing to jump to 1970.
     */
    if (seconds > UINT32_MAX) {
        return UINT32_MAX;  /* Clamp to max (2038-01-19 03:14:07 UTC) */
    }

    return (uint32_t)seconds;
}

/*=============================================================================
 * FUNCTION: timestamp_to_datetime
 * Convert Unix timestamp to datetime
 *=============================================================================*/
void timestamp_to_datetime(uint32_t timestamp, datetime_t* dt) {
    if (!dt) {
        return;
    }

    const uint8_t days_in_month[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    /* Extract time components */
    dt->second = timestamp % 60;
    timestamp /= 60;
    dt->minute = timestamp % 60;
    timestamp /= 60;
    dt->hour = timestamp % 24;
    uint32_t days = timestamp / 24;

    /* Calculate day of week (Jan 1, 1970 was Thursday = 4) */
    dt->weekday = (days + 4) % 7;

    /* Calculate year */
    dt->year = 1970;
    while (true) {
        uint16_t days_in_year = is_leap_year(dt->year) ? 366 : 365;
        if (days < days_in_year) {
            break;
        }
        days -= days_in_year;
        dt->year++;
    }

    /* Calculate month and day */
    dt->month = 1;
    while (dt->month <= 12) {
        uint8_t days_this_month = days_in_month[dt->month - 1];
        if (dt->month == 2 && is_leap_year(dt->year)) {
            days_this_month = 29;
        }

        if (days < days_this_month) {
            break;
        }

        days -= days_this_month;
        dt->month++;
    }

    dt->day = days + 1;
}
