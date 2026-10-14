/*
 * This plugin/module is the default one. It is an interactive
 * debugging engine.
 */

#include "../shiva.h"

int my_check_serial(char *s)
{
	return 1;

}

int
shakti_main(shiva_ctx_t *ctx)
{
	bool res;
	shiva_error_t error;
	shiva_callsite_iterator_t call_iter;
	struct shiva_branch_site branch;
	struct elf_symbol symbol;

	res = shiva_trace(ctx, 0, SHIVA_TRACE_OP_ATTACH,
	    NULL, NULL, 0, &error);
	if (res == false) {
		printf("shiva_trace failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	res = shiva_trace_register_handler(ctx, (void *)&my_check_serial,
	    SHIVA_TRACE_BP_TRAMPOLINE, &error);
	if (res == false) {
		printf("shiva_register_handler failed: %s\n",
		    shiva_error_msg(&error));
		return -1;
	}
	if (elf_symbol_by_name(&ctx->elfobj, "check_serial", &symbol) == false) {
		printf("failed to find symbol 'check_serial'\n");
		return -1;
	}
	uint64_t val = symbol.value + ctx->ulexec.base_vaddr;
	res = shiva_trace_set_breakpoint(ctx, (void *)my_check_serial,
	    val, NULL, &error);
	if (res == false) {
		printf("shiva_trace_set_breakpoint failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	return 0;
}

