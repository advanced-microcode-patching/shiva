#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	char buf[512];

	sprintf(buf, "ls %s", argv[1]);
	system(buf);
	return 0;
}
