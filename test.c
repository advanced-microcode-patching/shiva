#include <stdio.h>
#include <stdlib.h>

void print_string(const char *s)
{
	printf("%s\n", s);
	return;
}
int main(int argc, char **argv)
{
	print_string("Hello World");
	exit(0);
}
