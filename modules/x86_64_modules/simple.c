#include "../shiva.h"

int data_var = 5;

int
shakti_main(shiva_ctx_t *ctx)
{

	printf("I am a Shiva module, ctx: %p data_var: %p\n", ctx, &data_var);
}
