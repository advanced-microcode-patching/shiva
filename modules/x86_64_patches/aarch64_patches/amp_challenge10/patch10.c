#include <stdint.h>
#include <stdio.h>
#include "shiva_module.h"

/*
 * These are external .bss variables.
 */
extern uint16_t size;
extern uint8_t num_packets;

/*
 * Example of using a "Shiva Transformation". The
 * Splice transformation allows us to splice C code
 * into an existing function.
 */
SHIVA_T_SPLICE_FUNCTION(transport_handler, 0x9b6c, 0x9b94)
{
	if ((num_packets * 7) != size) {
		printf("RTS mismatch detected\n");
		return 0;
	}
}
