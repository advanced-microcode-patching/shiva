#include <stdio.h>

int data_var = 0xdeadbeef;

void foo(void)
{
	printf("Hi, I am the new foo() function, foo_v2!\n");
	printf("The new value of data_var is %#x\n", data_var);

}

