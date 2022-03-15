#include "shiva.h"

void shiva_sighandle(int sig)
{
	fprintf(stdout, "Caught signal ctrl-C, detaching...\n");
	exit(0);
}

