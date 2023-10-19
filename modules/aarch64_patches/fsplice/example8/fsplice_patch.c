
#include <stdint.h>
#include <stdio.h>
#include "shiva_module.h"

SHIVA_T_SPLICE_FUNCTION(foo, 0x7e8, 0x7ec)
{
	SHIVA_T_PUSH64_X0;
	SHIVA_T_PUSH64_X1;
	printf("I'm a new line of C code hi\n");
	SHIVA_T_POP64_X1;
	SHIVA_T_POP64_X0;
}
