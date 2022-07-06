#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void print_string(const char *s)
{
	struct timespec tps, tpe;
	//clock_gettime(CLOCK_MONOTONIC_RAW, &tps);
	puts(s);
	//clock_gettime(CLOCK_MONOTONIC_RAW, &tpe);
	//printf("%lu s, %lu ns\n", tpe.tv_sec - tps.tv_sec,
	 //   tpe.tv_nsec - tps.tv_nsec);

	return;
}
int main(int argc, char **argv)
{
	int i;

	for (i = 0; i < 10; i++)
		print_string("Hello World");
	print_string(argv[1]);
	exit(0);
}
