#include <stdio.h>
#include <errno.h>
#include <string.h>

int data_var = 0x1000;

int foo(void)
{
	printf("I'm the original foo(), and here's my data_var: %#lx\n", data_var);
	return 0;
}

int main(void)
{
	foo();
}
