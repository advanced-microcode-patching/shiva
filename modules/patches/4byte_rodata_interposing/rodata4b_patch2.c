#include <stdio.h>

char rodata_var[] = "\xef\xbe\xad\xde";

int foo(void)
{
	printf("I'm the new foo() function!\n");
	printf("The new value of rodata_var is %d\n", rodata_var);
	return 0;
}
