#include <stdint.h>
#include <stdio.h>
#include "shiva_module.h"

int data_val = 7;
extern char global_buf[255];

SHIVA_T_SPLICE_FUNCTION(foo, 0x818, 0x828)
{
	SHIVA_T_PAIR_BP_16(str);
	if (str != NULL) {
		fprintf(stdout, "Printing str: %s\n", str);
	}
	fprintf(stdout, "global_buf: %s\n", global_buf);
	bar();
}

int bar(void)
{
	data_val = data_val + 1;
	printf("I am the new bar, and I am here to say data_val = %d\n", data_val);
}
