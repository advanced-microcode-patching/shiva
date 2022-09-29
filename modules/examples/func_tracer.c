/*
 * This plugin/module is the default one. It is an interactive
 * debugging engine.
 */

#include "../shiva.h"

/*
 * Handles hooked callsites
 */
void *
callsite_handler(void *arg)
{
	shiva_trace_getregs_x86_64(&ctx_global->regs.regset_x86_64);
	struct shiva_ctx *ctx = ctx_global;
	void *retaddr = __builtin_return_address(0);
	void *frmaddr = __builtin_frame_address(1);
	struct shiva_trace_handler *handler;
	struct shiva_trace_bp *bp;
	uint64_t o_target;

	ctx->regs.regset_x86_64.rbp = (uint64_t)frmaddr;
	ctx->regs.regset_x86_64.rip = (uint64_t)retaddr - 5;
	ctx->regs.regset_x86_64.rdi = (uint64_t)arg;

	handler = shiva_trace_find_handler(ctx, &callsite_handler);
	if (handler == NULL) {
		printf("Failed to find handler struct for callsite_handler\n");
		exit(-1);
	}
	/*
	 * Get the breakpoint struct associated with the call-hook-breakpoint
	 * "SHIVA_TRACE_BP_CALL" that triggered our handler.
	 */
	SHIVA_TRACE_BP_STRUCT(bp, handler);
	printf("[CALL] %s\n", bp->call_target_symname);
	SHIVA_TRACE_CALL_ORIGINAL(bp);
}

int
shakti_main(shiva_ctx_t *ctx)
{
	bool res;
	shiva_error_t error;
	shiva_callsite_iterator_t call_iter;
	struct shiva_branch_site branch;
	struct shiva_trace_handler trace_handler;

	printf("Target '%s': %#lx\n", ctx->path, ctx->ulexec.base_vaddr);
	printf("LDSO '/lib64/ld-linux.so': %#lx\n", ctx->ulexec.ldso.base_vaddr);
	printf("Module './shakti_runtime.o': %#lx\n", &callsite_handler);

	res = shiva_trace(ctx, 0, SHIVA_TRACE_OP_ATTACH,
	    NULL, NULL, 0, &error);
	if (res == false) {
		printf("shiva_trace failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	res = shiva_trace_register_handler(ctx, (void *)&callsite_handler,
	    SHIVA_TRACE_BP_CALL, &error);
	if (res == false) {
		printf("shiva_register_handler failed: %s\n",
		    shiva_error_msg(&error));
		return -1;
	}
	shiva_callsite_iterator_init(ctx, &call_iter);
	while (shiva_callsite_iterator_next(&call_iter, &branch) == ELF_ITER_OK) {
		//if ((branch.branch_flags & SHIVA_BRANCH_F_PLTCALL) == 0)
			//continue;
		res = shiva_trace_set_breakpoint(ctx, (void *)&callsite_handler,
		    branch.branch_site + ctx->ulexec.base_vaddr, NULL, &error);
		if (res == false) {
			printf("shiva_trace_register_breakpoint failed: %s\n",
			    shiva_error_msg(&error));
			return -1;
		}
	}
	return 0;
}

