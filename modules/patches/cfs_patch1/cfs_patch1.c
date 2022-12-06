#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>

void OS_printf(const char *string, ...)
{
	char msg_buffer[4096];
	va_list va;
	int sz;

	va_start(va, string);
	sz = vsnprintf(msg_buffer, sizeof(msg_buffer), string, va);
	va_end(va);
	msg_buffer[sz] = '\0';
	printf("[PATCHED :)]: %s\n", msg_buffer);
}

