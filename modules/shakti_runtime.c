/*
 * This plugin/module is the default one. It is an interactive
 * debugging engine.
 */

#include "../shiva_trace.h"

void *
shakti_handler(shiva_ctx_t *ctx)
{
	uint64_t retaddr = __builtin_return_address(0);
	struct shiva_trace_handler *current;
	struct shiva_trace_bp *bp;
	uint64_t o_target;

	printf("handler retaddr: %#lx\n", retaddr);
	TAILQ_FOREACH(current, &ctx->tailq.trace_handlers_tqlist, _linkage) {
		if (current->handler_fn != &shakti_handler)
			continue;
		printf("Searching breakpoint list\n");
		TAILQ_FOREACH(bp, &current->bp_tqlist,  _linkage) {
			if (bp->retaddr == retaddr) {
				printf("Found breakpoint!\n");
				o_target = bp->o_target;
			}
		}
	}
	printf("handler called!\n");

	return NULL;
}

int
shakti_main(shiva_ctx_t *ctx)
{
	bool res;
	shiva_error_t error;
	shiva_callsite_iterator_t call_iter;
	struct shiva_branch_site branch;
	struct shiva_trace_handler trace_handler;
	uint64_t data = 0xdeadbeef;
	uint64_t out;
#if 0
	printf("shakti_handler is at %#lx\n", shakti_handler);
	res = shiva_trace(ctx, 0, SHIVA_TRACE_OP_ATTACH,
	    NULL, NULL, &error);
	if (res == false) {
		printf("shiva_trace failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
#endif
	res = shiva_trace_register_handler(ctx, &shakti_handler,
	    SHIVA_TRACE_BP_CALL, &error);
	if (res == false) {
		printf("shiva_register_handler failed: %s\n",
		    shiva_error_msg(&error));
		return -1;
	}
	printf("SHAKTI MAIN: %p\n", &shakti_main);
	printf("HANDLER: %p\n", &shakti_handler);

	shiva_callsite_iterator_init(ctx, &call_iter);
	while (shiva_callsite_iterator_next(&call_iter, &branch) == ELF_ITER_OK) {
		printf("callsite (%#lx) -> %s\n", branch.branch_site, branch.symbol.name);
		res = shiva_trace_set_breakpoint(ctx, &shakti_handler,
		    branch.branch_site + ctx->ulexec.base_vaddr, &error);
		if (res == false) {
			printf("shiva_trace_register_breakpoint failed: %s\n",
			    shiva_error_msg(&error));
			return -1;
		}
		printf("Set breakpoint at %#lx\n", branch.branch_site + ctx->ulexec.base_vaddr);
	}
#if 0
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
#endif
	
	printf("Read value: %#lx\n", out);
	printf("\n");
	return 0;
}

