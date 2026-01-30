#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char my_string[] = "Arcana Technologies ";

#define BUFLEN 50

int print_banner(char *addstr)
{
	char buf[BUFLEN];

	printf("my_string: %s\n", my_string);
	strcpy(buf, my_string);
	printf("buf: %s\n", buf);
	strcat(buf, addstr);
	printf("%s\n", buf);
}

int main(int argc, char **argv)
{
	print_banner(argc < 2 ? "ElfMaster" : argv[1]);
	(void)malloc(1);
	exit(0);
}
