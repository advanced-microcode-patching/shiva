#include <stdio.h>

#define MAX_BUF_LEN 32

void vuln(char *string)
{
	char buf[MAX_BUF_LEN];

	strcpy(buf, string);
	printf("buf: %s\n", buf);
}

int main(int argc, char **argv)
{
	vuln(argv[1]);
}


