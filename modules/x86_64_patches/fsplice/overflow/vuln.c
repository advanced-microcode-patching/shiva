/*
 * The original program that we want to patch
 */

#include <stdio.h>
#include <string.h>

int parse_string(char *s)
{
	char buf[16];
	char *p;

	strcpy(buf, s);

	printf("buf: %s\n", buf);
}

int main(int argc, char **argv)
{
	parse_string(argv[1]);
}
