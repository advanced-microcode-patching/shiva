#include <stdio.h>
#include <errno.h>
#include <string.h>

char bss_buffer[256];
const int ro_val = 111;

int foo(void)
{
	return 0;
}

int main(int argc, char **argv)
{
	strcpy(bss_buffer, "HELLO");
	if (argc > 1) {
		if (strcmp(argv[1], "test") == 0)
			printf("Found test string\n");
	}
	foo();
}
