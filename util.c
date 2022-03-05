#include "shiva.h"

char *
shiva_strdup(const char *s)
{
	char *p = strdup(s);
	if (p == NULL) {
		perror("strdup");
		exit(EXIT_FAILURE);
	}
	return p;
}

char *
shiva_fmtstrdup(char *fmt, ...)
{
	char buf[512];
	char *s;
	va_list va;
	
	va_start(va, fmt);
	vsnprintf(buf, sizeof(buf), fmt, va);
	s = shiva_strdup(buf);
	return s;
}

void *
shiva_malloc(size_t len)
{
	uint8_t *mem = malloc(len);
	if (mem == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	return mem;
}


