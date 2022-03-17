#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
	int i;
	char text[255];
	uint64_t val = 5;

	for (i = 0; i < 255; i++) {
		text[i] = 0xff;
	}
	memcpy(text, &val, 1);
	for (i = 0; i < 255; i++)
		printf("%02x", text[i]);
	printf("\n");

}
