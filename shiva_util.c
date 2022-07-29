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
shiva_xfmtstrdup(char *fmt, ...)
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


char * shiva_itoa(long x, char *t)
{
	int i;
	int j;

	i = 0;
	do
	{
		t[i] = (x % 10) + '0';
		x /= 10;
		i++;
	} while (x!=0);

	t[i] = 0;

	for (j=0; j < i / 2; j++) {
		t[j] ^= t[i - j - 1];
		t[i - j - 1] ^= t[j];
		t[j] ^= t[i - j - 1];
	}

	return t;
}

