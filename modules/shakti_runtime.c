/*
 * This plugin/module is the default one. It is an interactive
 * debugging engine.
 */

#include "../shiva.h"

int
shakti_handler(shiva_ctx_t *ctx)
{
	
}

int
shakti_main(shiva_ctx_t *ctx)
{
	bool res;
	shiva_error_t error;
	uint64_t data = 0xdeadbeef;
	uint64_t out;

	printf("Shakti debugging module\n");
	printf("ctx: %p\n", ctx);

	res = shiva_trace(ctx, 0, SHIVA_TRACE_OP_POKE,
	    (void *)ctx->ulexec.base_vaddr, &data, &error);
	if (res == false) {
		printf("shiva_trace 1 failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	printf("peek. data var is at address: %#lx\n", &out);
	res = shiva_trace(ctx, 0, SHIVA_TRACE_OP_PEEK,
	    (void *)ctx->ulexec.base_vaddr, &out, &error);
	if (res == false) {
		printf("shiva_trace 2 failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	fprintf(stderr, "Read value: %#lx\n", out);
	return 0;
}

