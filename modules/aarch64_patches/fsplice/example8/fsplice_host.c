/*
 * The original program that we want to patch
 */

#include <stdio.h>

const char *banner = "ElfMaster";
char global_buf[255];

int foo(int num, char *str)
{
	if (num == 7)
		goto done;
	strcpy(global_buf, banner);
	printf("Printing str: %s\n", str); // <- splice code in here
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

