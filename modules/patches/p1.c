#include <stdio.h>

int data_var = 0x31337;

int foo(void)
{
	printf("I am the new function foo, and the new data_var is :%#x\n", data_var);
	return 0;
}


