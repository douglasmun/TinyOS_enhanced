/*=============================================================================
 *  serial.h â€” TinyOS Serial Port Output
 *============================================================================*/
#pragma once
#include <stdint.h>
void serial_init(void);
void serial_putc(char c);
void serial_puts(const char* s);
char serial_getc(void);
int serial_has_data(void);
