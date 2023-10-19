
#include <stdint.h>
#include <stdio.h>
#include "shiva_module.h"

SHIVA_T_SPLICE_FUNCTION(foo, 0x7e8, 0x7ec)
{
	printf("I'm a new line of C code hi\n");
}
