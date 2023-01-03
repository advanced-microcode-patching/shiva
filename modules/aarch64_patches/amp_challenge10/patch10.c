#include <stdint.h>
#include <stdio.h>

/*
 * These are external .bss variables.
 */
extern uint16_t size;
extern uint8_t num_packets;

/*
 * In the future a gcc plugin will offer 
 * __attribute__((shiva_patch(start_vaddr, len))
 */
uint64_t shiva_insert_patch1_start_0x9b74 = 0;
uint64_t shiva_insert_patch1_end_0x9b8c = 0;

void * __attribute__((naked)) shiva_insert_patch1(void)
{
	if ((num_packets * 7) != size) {
		printf("RTS mismatch detected\n");
		return 0;
	}
}
