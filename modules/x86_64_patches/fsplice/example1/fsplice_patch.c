#include <stdint.h>
#include <stdio.h>
#include "shiva_module.h"


SHIVA_T_SPLICE_FUNCTION(foo, 0x114c, 0x115a)
{
	SHIVA_T_PAIR_RDI(str);
	fprintf(stdout, "(fprintf version): Printing arg: %s\n", str);
	bar();
}

int bar(void)
{
	printf("I am the new bar\n");
}
