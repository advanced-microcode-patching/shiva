/*
 * This plugin/module is the default one. It is an interactive
 * debugging engine.
 */

#include "../shiva.h"

void my_print_string(const char *s)
{
	struct shiva_ctx *ctx = ctx_global;
	struct shiva_trace_handler *handler;
	struct shiva_trace_bp *bp;
	shiva_error_t error;
	void (*o_print_string)(const char *);
	char buf[256];
	uint64_t vaddr;
	bool res;

	snprintf(buf, sizeof(buf), "Hijacked string: %s", s);
	handler = shiva_trace_find_handler(ctx, &my_print_string);
	if (handler == NULL) {
		printf("Failed to find handler struct for my_print_string\n");
		exit(-1);
	}
	/*
	 * Find the breakpoint struct associated with this handler/hijack
	 * function.
	 */
	SHIVA_TRACE_BP_STRUCT(bp, handler);
	vaddr = (uint64_t)bp->symbol.value + ctx->ulexec.base_vaddr;
	/*
	 * Restore original code bytes of function 'print_string'
	 */
	res = shiva_trace_write(ctx, 0, (void *)vaddr, &bp->insn.o_insn, bp->bp_len, &error);
	if (res == false) {
		printf("shiva_trace_write failed: %s\n", shiva_error_msg(&error));
		exit(-1);
	}
	/*
	 * Call the original print_string
	 */
	o_print_string = (void *)vaddr;
	o_print_string(buf);

	/*
	 * Restore our trampoline back in place.
	 */
	res = shiva_trace_write(ctx, 0, (void *)vaddr, &bp->insn.o_insn, bp->bp_len, &error);
        if (res == false) {
                printf("shiva_trace_write failed: %s\n", shiva_error_msg(&error));
                exit(-1);
        }

	return;

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
	res = shiva_trace_register_handler(ctx, (void *)&my_print_string,
	    SHIVA_TRACE_BP_TRAMPOLINE, &error);
	if (res == false) {
		printf("shiva_register_handler failed: %s\n",
		    shiva_error_msg(&error));
		return -1;
	}
	if (elf_symbol_by_name(&ctx->elfobj, "print_string", &symbol) == false) {
		printf("failed to find symbol 'print_string'\n");
		return -1;
	}
	uint64_t val = symbol.value + ctx->ulexec.base_vaddr;
	res = shiva_trace_set_breakpoint(ctx, (void *)my_print_string,
	    val, &error);
	if (res == false) {
		printf("shiva_trace_set_breakpoint failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	return 0;
}

