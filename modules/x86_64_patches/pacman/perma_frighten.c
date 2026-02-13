/*
 * Patch code for Pacman to make enemies all scared.
 * 
 * How it works: It modifies fgState->idle callback ptr
 * to &my_idle(). When my_idle() is invoked it resets
 * two global variables: frighten and frightenTick.
 *
 * Look into libglut.so:glutIdleFunc() for more
 * understanding.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "/opt/shiva/include/shiva_module.h"

extern uint8_t fgState;
extern bool frighten;
extern int frightenTick;

void my_idle(void)
{
	frighten = true;
	frightenTick = 0;
	_Z4idlev(); // C++ mangled name for idle()
}

void glutIdleFunc(void)
{
	uint8_t *fptr = (uint8_t *)&fgState + 104;

	*(uint64_t *)fptr = &my_idle;
}
