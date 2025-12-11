#include <stdint.h>
#include <stdio.h>
#include "shiva_module.h"


SHIVA_T_SPLICE_FUNCTION_REPLACE_SRCLINE(foo, 5)
{
	/*
	 * Attach x0 (arg1) to a use-able variable. (Which
	 * will live in the .bss).
	 */
	SHIVA_T_PAIR_RDI(str);
	fprintf(stdout, "(fprintf version): Printing arg: %s\n", str);
	bar();
}

int bar(void)
{
	printf("I am the new bar\n");
}
