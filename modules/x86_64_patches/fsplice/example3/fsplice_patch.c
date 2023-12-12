#include <stdint.h>
#include <stdio.h>
#include "shiva_module.h"


SHIVA_T_SPLICE_FUNCTION(foo, 0x740, 0x74c)
{
	/*
	 * Attach register x1 to a variable name 'char *str'.
	 */
	SHIVA_T_PAIR_X1(str);
	if (str != NULL) {
		fprintf(stdout, "Printing str: %s\n", str);
	}
	bar();
}

int bar(void)
{
	printf("I am the new bar\n");
}
