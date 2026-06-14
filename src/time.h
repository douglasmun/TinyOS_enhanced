/*=============================================================================
 * time.h - TinyOS Time Management
 *=============================================================================*/
#pragma once
#include <stdint.h>
#include <stdbool.h>

/*=============================================================================
 * Time Structures
 *=============================================================================*/

/**
 * @brief Broken-down time structure (similar to struct tm)
 */
typedef struct {
    uint16_t year;       /* Year (e.g., 2025) */
    uint8_t  month;      /* Month (1-12) */
    uint8_t  day;        /* Day of month (1-31) */
    uint8_t  hour;       /* Hour (0-23) */
    uint8_t  minute;     /* Minute (0-59) */
    uint8_t  second;     /* Second (0-59) */
    uint8_t  weekday;    /* Day of week (0=Sunday, 6=Saturday) */
} datetime_t;

/*=============================================================================
 * RTC (Real-Time Clock) Functions
 *=============================================================================*/

/**
 * @brief Initialize the Real-Time Clock
 */
void rtc_init(void);

/**
 * @brief Read current date/time from RTC
 * @param dt Pointer to datetime structure to fill (may be volatile for ISR-shared state)
 * @return true on success, false on error
 */
bool rtc_read_datetime(volatile datetime_t* dt);

/*=============================================================================
 * System Time Functions
 *=============================================================================*/

/**
 * @brief Initialize the time system (must be called after RTC and PIT init)
 */
void time_init(void);

/**
 * @brief Get current system time
 * @param dt Pointer to datetime structure to fill
 * @return true on success, false on error
 */
bool time_get_datetime(datetime_t* dt);

/**
 * @brief Get system uptime in seconds
 * @return Number of seconds since boot
 */
uint32_t time_get_uptime_seconds(void);

/**
 * @brief Set system time (updates RTC and system time)
 * @param dt Pointer to datetime structure with new time
 * @return true on success, false on error
 */
bool time_set_datetime(const datetime_t* dt);

/**
 * @brief Convert datetime to Unix timestamp
 * @param dt Pointer to datetime structure
 * @return Unix timestamp (seconds since 1970-01-01 00:00:00 UTC)
 */
uint32_t datetime_to_timestamp(const datetime_t* dt);

/**
 * @brief Convert Unix timestamp to datetime
 * @param timestamp Unix timestamp
 * @param dt Pointer to datetime structure to fill
 */
void timestamp_to_datetime(uint32_t timestamp, datetime_t* dt);

/**
 * @brief Get day of week for a given date
 * @param year Year (e.g., 2025)
 * @param month Month (1-12)
 * @param day Day (1-31)
 * @return Day of week (0=Sunday, 6=Saturday)
 */
uint8_t get_day_of_week(uint16_t year, uint8_t month, uint8_t day);

/**
 * @brief Check if a year is a leap year
 * @param year Year to check
 * @return true if leap year, false otherwise
 */
bool is_leap_year(uint16_t year);
