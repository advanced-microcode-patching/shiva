#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

const char *string = "/bin/sh";

int do_nothing(void)
{
	system("/bin/ls");
}
int main(int argc, char **argv)
{
	long *ret;
	ret = (long *)&ret + 3;
	setuid(0);
	__asm__ __volatile__("movq %0, %%rdi\n\t" :: "r"(string));
	(*(uint64_t *)ret) = 0x0000555555554000 + 0x1030;
	ret = (long *)&ret + 2;
	(*(uint64_t *)ret) = 0x0000555555554000 + 0x101a;
	//(*ret) = 0x40000000 + 0x1030;
	return 0;
}
