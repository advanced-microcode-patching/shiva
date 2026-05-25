/*
 * Splice code in to function parse_string() to fix
 * the vulnerable strcpy.
 */

#include <stdint.h>
#include <stdio.h>
#include "shiva_module.h"

#define BUFLEN 16

SHIVA_MODULE_FORCE_MUSL_RESOLUTION;

SHIVA_T_SPLICE_FUNCTION(parse_string, 0x1175, 0x118c)
{
	SHIVA_T_PAIR_RDI(src);
	SHIVA_T_LEA_BP(dst, -16);
	strncpy(dst, src, BUFLEN-1);
}

