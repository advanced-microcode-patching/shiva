/*
 * Patch code.
 * Patch 1. Create a new .data variable, data_val
 * Patch 2. Splice code into function foo() (Very intensive operation)
 * Patch 3. Rewrite function bar() via symbol interposition
 */

#include <stdint.h>
#include <stdio.h>
#include "shiva_module.h"

int bar(void);

int data_val = 7; // adds in a new .data global variable
extern char global_buf[255]; // links to external global_buf[] variable

/*
 * The SHIVA_T_SPLICE_FUNCTION will splice it's body of C code
 * into the function foo() at address 0x818. It won't fit between
 * 0x818 and 0x828 so it extends the size of the function.
 */
SHIVA_T_SPLICE_FUNCTION(foo, 0x11bb, 0x11d6)
{
	register char *str asm ("r15");
	__asm__("mov -0x10(%rbp), %r15");

	if (str != NULL) {
		fprintf(stdout, "Printing str: %s\n", str);
	}
	fprintf(stdout, "global_buf: %s\n", global_buf);
	bar();
}

/*
 * Completely re-writes the function bar() so that it
 * prints data_val + 1
 */
int bar(void)
{
	data_val = data_val + 1;
	printf("I am the new bar, and I am here to say data_val = %d\n", data_val);
}
