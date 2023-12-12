#include <stdint.h>
#include <stdio.h>
#include "shiva_module.h"

int data_val = 7;

SHIVA_T_SPLICE_FUNCTION(foo, 0x760, 0x76c)
{
	/*
	 * Attach x1 (char *str) to a use-able variable. (Which
	 * will live in the .bss).
	 */
	SHIVA_T_PAIR_X1(str);
	if (str != NULL) {
		fprintf(stdout, "Printing str: %s\n", str);
	}
	bar();
}

int bar(void)
{
	data_val = data_val + 1;
	printf("I am the new bar, and I am here to say data_val = %d\n", data_val);
}
