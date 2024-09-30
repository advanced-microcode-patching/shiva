/*
 * Patch code that gives the ability to never die.
 * No enemy can harm you with this incredible patch
 * of holy armor.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "/opt/shiva/include/shiva_module.h"

typedef enum {BEGIN, PLAY, DIE, OVER} gameState;

/*
 * Externs from the pacman executable
 */
extern gameState stateGame;
extern uint8_t fgState;

void my_idle(void)
{
	if (stateGame == DIE)
		stateGame = PLAY;
	_Z4idlev();
}

void glutIdleFunc(void)
{
	uint8_t *fptr = (uint8_t *)&fgState + 104;

	*(uint64_t *)fptr = &my_idle;
}
