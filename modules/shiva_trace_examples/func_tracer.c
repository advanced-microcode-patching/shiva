/*
 * This plugin/module is the default one. It is an interactive
 * debugging engine.
 */

#include "shiva.h"
#include "shiva_module.h"

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
	printf("[CALL] %s  o_target=%#lx  is_plt=%d  callsite_retaddr=%#lx\n",
        bp->call_target_symname, bp->o_target,
       	(bp->call_target_symname && strstr(bp->call_target_symname, "@plt") != NULL),
       bp->callsite_retaddr);

	fflush(stdout);
	SHIVA_TRACE_CALL_ORIGINAL(bp);
}

int
shiva_init(shiva_ctx_t *ctx)
{
	bool res;
	shiva_error_t error;
	shiva_callsite_iterator_t call_iter;
	struct shiva_branch_site branch;
	struct shiva_trace_handler trace_handler;
	elf_pltgot_iterator_t pltgot_iter;
	struct elf_pltgot_entry pltgot_entry;

	printf("Target '%s': %#lx\n", ctx->path, ctx->ulexec.base_vaddr);
	printf("LDSO '/lib64/ld-linux.so': %#lx\n", ctx->ulexec.ldso.base_vaddr);
	printf("Module './shakti_runtime.o': %p\n", &callsite_handler);

	res = shiva_trace(ctx, 0, SHIVA_TRACE_OP_ATTACH,
	    NULL, NULL, 0, &error);
	if (res == false) {
		printf("shiva_trace failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	/*
	 * Extremely fast breakpoints that hook call offsets from
	 * immediate alls, rather than use standard int3
	 */
	res = shiva_trace_register_handler(ctx, (void *)&callsite_handler,
	    SHIVA_TRACE_BP_CALL, &error);
	if (res == false) {
		printf("shiva_register_handler failed: %s\n",
		    shiva_error_msg(&error));
		return -1;
	}

	/*
	 * Extremely fast breakpoints that hook the PLTGOT directly
	 * and setup a handler, rather than use standard int3.
	 */
#if 0
	res = shiva_trace_register_handler(ctx, (void *)&pltgot_handler,
	    SHIVA_TRACE_BP_PLTGOT, &error);
	if (res == false) {
		printf("shiva_trace_register_handler failed: %s\n",
		    shiva_error_msg(&error));
		return -1;
	}
#endif
	/*
	 * Set 'e8' immediate call breakpoints. Which replace the call offset
	 * on every e8 call. Ignore calls to PLT, instead we use the
	 * PLTGOT breakpoint type to handle those ones.
	 */
	shiva_callsite_iterator_init(ctx, &call_iter);
	while (shiva_callsite_iterator_next(&call_iter, &branch) == ELF_ITER_OK) {
		if (branch.branch_flags & SHIVA_BRANCH_F_PLTCALL)
			continue;
		res = shiva_trace_set_breakpoint(ctx, (void *)&callsite_handler,
		    RUNTIME_BASE(branch.branch_site), NULL, &error);
		if (res == false) {
			printf("shiva_trace_register_breakpoint failed: %s\n",
			    shiva_error_msg(&error));
			return -1;
		}
	}
#if 0
	elf_pltgot_iterator_init(&ctx->elfobj, &pltgot_iter);
	while (elf_pltgot_iterator_next(&pltgot_iter, &pltgot_entry) == ELF_ITER_OK) {
		uint64_t got_addr = RUNTIME_BASE(pltgot_entry.offset);

		res = shiva_trace_set_breakpoint(ctx, (void *)&pltgot_handler,
		    0, NULL, &error);
#endif
	return 0;
}

