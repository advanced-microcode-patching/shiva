#include <stdio.h>

int foo(int num, char *str)
{
	if (num == 7)
		goto done;

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
	foo(argc, argv[1]);
	bar();
}

