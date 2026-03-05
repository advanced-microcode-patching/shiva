#include <stdio.h>
#include <stdlib.h>

int test1(void)
{
	int i = 0;
	return 0;
}

static int ignore_me(void) // gASLR.o will not relocate static functions
{
	int i = 7;
	return 0;
}

int main(void)
{
	printf("base address: %#lx\n", (unsigned long)&ignore_me & ~4095);
	printf("main() is at %p\n", &main);
	printf("test1() is at %p\n", &test1);
	test1();
}

