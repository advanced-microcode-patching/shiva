#include <stdio.h>

int bss_var = 5;

int foo(void)
{
	printf("I'm the original foo() function!\n");
	printf("The value of bss_var is %x\n", bss_var);
	return 0;
}

int bar(void)
{
	printf("I am a function that won't be patched\n");
	printf("I'm accessing bss_var and its value is %#x\n", bss_var);
	return 0;
}

int main(void)
{
	foo();
	bar();
}
