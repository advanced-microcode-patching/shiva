#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/shiva_module.h"

SHIVA_MODULE_FORCE_MUSL_RESOLUTION;

extern const char my_string[];

size_t _strlen(const char *s) { return *s ? 1 + _strlen(s + 1) : 0; }

int print_banner(char *addstr)
{
	char *buf;

	printf("print_banner(%s)\n", my_string);
	printf("strlen(my_string): %d strlen(addstr): %d\n", _strlen(my_string), _strlen(addstr));
	buf = malloc(_strlen(my_string) + _strlen(addstr) + 1);
	if (buf == NULL) {
		perror("malloc");
		return -1;
	}
	strcpy(buf, my_string);
	printf("buf: %s\n", buf);
	strcat(buf, addstr);
	printf("buf: %s\n", buf);
	return 0;
}
