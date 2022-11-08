#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int abc;
int abc2;
uint32_t abc3[4096];

void print_string(const char *s)
{
	struct timespec tps, tpe;
	char buf[4096];

	strcpy(buf, s);
	clock_gettime(CLOCK_MONOTONIC_RAW, &tps);
	puts(s);
	clock_gettime(CLOCK_MONOTONIC_RAW, &tpe);
	//printf("%lu s, %lu ns\n", tpe.tv_sec - tps.tv_sec,
	 //   tpe.tv_nsec - tps.tv_nsec);

	return;
}
int main(int argc, char **argv)
{
	int i;
	char *var;

	for (i = 0; i < 10; i++)
		print_string("Hello World");
	if (argc > 1)
		print_string(argv[1]);
	abc = 5;
	exit(0);
}
