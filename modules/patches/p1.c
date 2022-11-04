#include <sys/types.h>
#include <stdint.h>
#include <string.h>

extern char bss_buffer[256];
const int ro_val = 111;
int new_var = 0xff;

int bar(void *p)
{
	new_var = 0x3;
	new_var = 1 << 0x3;
	return 1;
}

int foo(const char *path, size_t mode)
{
	if (strcmp(bss_buffer, "SOME_STRING") == 0)
		return 1;
	bar(NULL);
}
