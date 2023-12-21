#include <stdio.h>

int data_var = 7;

int foo(void)
{
	printf("I'm the original foo() function!\n");
	printf("The value of data_var is %d\n", data_var);
	return 0;
}

int bar(void)
{
	printf("I am a function that won't be patched\n");
	printf("I'm accessing data_var and its value is %#x\n", data_var);
	return 0;
}

int main(void)
{
	foo();
	bar();
}
