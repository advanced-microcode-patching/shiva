#include <stdio.h>
#include <stdlib.h>


void print_string(const char *s)
{
	puts(s);
	return;
}
int main(int argc, char **argv)
{
	int i;

	for (i = 0; i < 5; i++)
		print_string("Hello World");
	print_string(argv[1]);
	exit(0);
}
