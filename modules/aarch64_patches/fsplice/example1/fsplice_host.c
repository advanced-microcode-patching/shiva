#include <stdio.h>

int foo(char *str)
{
	printf("Printing str\n"); // <- replace with patch
}

int bar(void)
{
	printf("bar\n");
}

int main(int argc, char **argv)
{
	foo(argv[1]);
	bar();
}

