#include "shiva_module.h"
#include <stdio.h>


SHIVA_T_SPLICE_FUNCTION(real_target, 0x401186, 0x4011a0)
{
	//register int secret __attribute__((unused));   // or volatile or something
	//register int counter __attribute__((unused));
	// This code will run INSIDE real_target's stack frame
	secret += 0xBEEF;
	counter += 100;
	printf("SPLICED CODE RAN — secret modified to 0x%x\n", secret);
}
