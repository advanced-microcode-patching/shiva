#include <stdint.h>
#include <stdio.h>
#include "shiva_module.h"


SHIVA_T_SPLICE_FUNCTION(foo, 0x72c, 0x73c)
{
	/*
	 * Attach x0 (arg1) to a use-able variable. (Which
	 * will live in the .bss).
	 */
	SHIVA_T_PAIR_X0(str);
	fprintf(stdout, "(fprintf version): Printing arg: %s\n", str);
	bar();
}

int bar(void)
{
	printf("I am the new bar\n");
}
