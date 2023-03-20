#include <stdio.h>

int foo(int num, char *str)
{
	if (num % 2 != 0)
		goto done;

	/*
	 * Patch code:
	 * if (str != NULL) {
	 * 	fprintf(stdout, "Printing str: %s\n", str);
	 * }
	 */
	printf("Printing str\n"); // <- replace with patch
done:
	return 0;
}

int bar(void)
{
	printf("bar\n");
}

int main(int argc, char **argv)
{
	foo(&argc + argv[0][0], argv[1]);
	bar();
}

