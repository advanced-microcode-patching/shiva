#include <stdio.h>

extern int data_var;

void foo(void)
{
	int *ptr = &data_var;

	*ptr = 0xdeadbeef;

	//printf("Hi, I am the new foo() function, foo_v2!\n");
	//printf("The new value of data_var is %#x\n", data_var);

}

