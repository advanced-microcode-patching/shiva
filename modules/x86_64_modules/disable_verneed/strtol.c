// shim_isoc23.c
#define _GNU_SOURCE
#include <stdlib.h>

long __isoc23_strtol(const char *restrict nptr, char **restrict endptr, int base) {
   	printf("Calling strtol :)?\n");
	 return strtol(nptr, endptr, base);
}

