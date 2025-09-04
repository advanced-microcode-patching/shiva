#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int foo(int arg1)
{
	if (arg1 == 10)
		return 1;
	printf("Your arg1 value is incorrect\n");
}

int main(int argc, char **argv)
{
	int val = atoi(argv[1]);

	if (foo(val) == 1) {
		printf("Your arg1 value was correct!\n");
	}
	return 0;
}
