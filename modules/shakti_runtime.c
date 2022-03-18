/*
 * This plugin/module is the default one. It is an interactive
 * debugging engine.
 */

#include "../shiva_trace.h"

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
	res = shiva_trace(ctx, 0, SHIVA_TRACE_OP_ATTACH,
	    NULL, NULL, &error);
	if (res == false) {
		printf("shiva_trace failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	res = shiva_trace(ctx, 0, SHIVA_TRACE_OP_POKE,
	    (void *)ctx->ulexec.base_vaddr, &data, &error);
	if (res == false) {
		printf("shiva_trace 1 failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	res = shiva_trace(ctx, 0, SHIVA_TRACE_OP_PEEK,
	    (void *)ctx->ulexec.base_vaddr, &out, &error);
	if (res == false) {
		printf("shiva_trace 2 failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	printf("Successfully returned\n");
	printf("Read value: %#lx\n", out);
	printf("\n");
	return 0;
}

