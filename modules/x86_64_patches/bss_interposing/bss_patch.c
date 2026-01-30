#include <stdio.h>
#include <string.h>

int bss_var; // shiva will re-link the programs bss_var to this one

int foo(void) // shiva will re-link the programs foo() function to this one
{
	char *p;
	bss_var = 0x31337; // This will of course assign 0x31337 to the patches bss_var
	printf("I'm the new foo() function!\n");
	printf("The new value of bss_var is %x\n", bss_var);

	p = strdup("I was born on the heap");
	printf("p: %s\n", p);
	bar();
	return 0;
}
