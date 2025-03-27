#include <stdio.h>
#include <stdlib.h>

int test1(void)
{
	int i = 0;
	printf("Hello\n");
	return 0;
}

static int ignore_me(void)
{
	int i = 7;
	return 3;
}

int main(void)
{
	char *p = malloc(10);
	printf("base address: %p\n", (unsigned long)&ignore_me & ~4095);
	printf("main() is at %p\n", &main);
	printf("test1() is at %p\n", &test1);
	test1();
}
