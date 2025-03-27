#include <stdio.h>
#include <stdlib.h>
#if 0
int test1(void)
{
	int i = 0;
	printf("Hello\n");
	return 0;
}
#endif
int main(void)
{
	char *p = malloc(10);
	printf("main is at %p\n", &main);
}
