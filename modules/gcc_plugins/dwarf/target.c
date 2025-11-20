#include <stdio.h>

void real_target(void) {
    int secret = 0x1337;
    int counter = 0;

    // This is where we want to splice code into (exact address we'll use)
    __asm__("# SHIVA_INSERT_HERE");

    printf("real_target: secret = 0x%x, counter = %d\n", secret, counter);
}

int main(void)
{
	real_target();
}

