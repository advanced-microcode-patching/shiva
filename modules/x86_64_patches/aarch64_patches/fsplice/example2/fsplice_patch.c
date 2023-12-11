#include <stdint.h>
#include <stdio.h>
#include "shiva_module.h"

/*
 * Splice C code into function foo()
 * At Offset 0x72c - 0x73c
 */

SHIVA_T_SPLICE_FUNCTION(foo, 0x72c, 0x73c)
{
	SHIVA_T_PAIR_X0(str); // register char *str asm("x0");
	if (str != NULL) {
		fprintf(stdout, "Printing str: %s\n", str);
	}
}





