#include <stdio.h>

/*
 * .rodata string
 */
const char *banner = "ElfMaster";

/*
 * .bss static buffer
 */
char global_buf[255];

int foo(int num, char *str)
{
	if (num == 7)
		goto done;
	strcpy(global_buf, banner);
	printf("Printing str: %s\n", str); // <- replace with patch
done:
	return 0;
}

int bar(void)
{
	printf("bar\n");
}

int main(int argc, char **argv)
{
	foo(argc, argv[1]);
	bar();
}

