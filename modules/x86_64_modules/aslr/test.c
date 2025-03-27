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
	printf("main is at %p\n", &main);
}
