#include <stdio.h>

const int rodata_var = 5;

int foo(void)
{
	printf("I'm the original foo() function!\n");
	printf("The value of rodata_var is %d\n", rodata_var);
	return 0;
}

int bar(void)
{
	printf("I am a function that won't be patched\n");
	printf("I'm accessing rodata_var and its value is %#lx\n", rodata_var);
	return 0;
}

int main(void)
{
	foo();
	bar();
}
