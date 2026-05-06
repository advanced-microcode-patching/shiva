#include <stdio.h>
#include <string.h>

int bss_var; // shiva will re-link the programs bss_var to this one

int foo(void) // shiva will re-link the programs foo() function to this one
{
	bss_var = 0x31337; // This will of course assign 0x31337 to the patches bss_var
	printf("I'm the new foo() function!\n");
	printf("The new value of bss_var is %x\n", bss_var);
	printf("calling foo() from self\n");
	foo();
	return 0;
}
