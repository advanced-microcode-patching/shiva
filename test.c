#include <stdio.h>
#include <stdlib.h>

__thread int tls_i;

void print_string(const char *s)
{
	printf("%s\n", s);
	return;
}
int main(int argc, char **argv)
{
	print_string("Hello World");
	print_string(argv[1]);
	exit(0);
}
