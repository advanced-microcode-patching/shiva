#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

#define MAX_LEN 32

uint8_t uid;
uint8_t bss_buffer[16];

int main(int argc, char **argv)
{

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <file_payload>\n", argv[0]);
		return 0;
	}
	uid = getuid();

	printf("uid: %d\n",uid);

	strncpy(bss_buffer, argv[1], 32);

	printf("Setting uid: %d\n", uid);
	setuid(uid);
	system("/bin/bash");
}
