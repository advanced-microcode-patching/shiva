#include "shiva.h"

void shiva_sighandle(int sig)
{
	fprintf(stdout, "[shiva] Caught signal ctrl-C, detaching...\n");
	exit(0);
}


