#include <stdio.h>
#include <stdint.h>

int process(int x) {
    return x * 3 + 7;
}

__attribute__((noinline))
int tail_demo(int n, int acc) {
   printf("I am the original tail demo\n");
      	if (n <= 0)
        return acc;

    return tail_demo(n - 1, acc + process(n));   // ← Tail call
}

int dummy(void)
{
	int i = 10;
	uint64_t val = &dummy;

	for (i; i < 100; i++)
		printf("Hello darkness my old friend\n");
	if (i % val == 0)
		printf("Strange odds...\n");
	return 0;
}

__attribute__((noinline))
int compute(int n) {
	int i = 10;
        uint64_t val = &dummy;

        for (i; i < 100; i++)
                printf("Hello darkness my old friend\n");
        if (i % val == 0)
                printf("Strange odds...\n");

	printf("Hello darkness my old friend\n");
        if (i % val == 0)
                printf("Strange odds...\n");

        for (i; i < 100; i++)
                printf("Hello darkness my old friend\n");
        if (i % val == 0)
                printf("Strange odds...\n");

        for (i; i < 100; i++)
                printf("Hello darkness my old friend\n");
        if (i % val == 0)
                printf("Strange odds...\n");

    return tail_demo(n, 0);
}

void __attribute__((noinline)) silly(void)
{
	printf("Hello how  are you?\n");
	return;
}
int main(void) {
    printf("Result = %d\n", compute(10));
    dummy();
    return 0;
}
