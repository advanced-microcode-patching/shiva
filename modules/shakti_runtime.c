/*
 * This plugin/module is the default one. It is an interactive
 * debugging engine.
 */

#include "../shiva.h"

//extern struct shiva_ctx *ctx_global;

void __attribute__((naked)) shakti_store_regs_x86_64(void)
{
        __asm__ __volatile__(
        "mov %%rax, %[rax]\n\t"
        "mov %%rbx, %[rbx]\n\t"
        "mov %%rcx, %[rcx]\n\t"
        "mov %%rdx, %[rdx]\n\t"
        "mov %%rsi, %[rsi]\n\t"
        "mov %%rdi, %[rdi]\n\t"
        "mov %%rbp, %[rbp]\n\t"
        "mov %%rsp, %[rsp]\n\t"
        "mov %%r8, %[r8]\n\t"
        "mov %%r9, %[r9]\n\t"
        "mov %%r10, %[r10]\n\t"
        "mov %%r11, %[r11]\n\t"
        "mov %%r12, %[r12]\n\t"
        "mov %%r13, %[r13]\n\t"
        "mov %%r14, %[r14]\n\t"
        "mov %%r15, %[r15]\n\t"
        "lea (%%rip), %%rbx\n\t" // use rbx to store rip
        "mov %%rbx, %[rip]\n\t"
        "mov %[rbx], %%rbx\n\t" // restore rbx value
        : [rax] "=g"(ctx_global->regs.regset_x86_64.rax), [rbx] "=g"(ctx_global->regs.regset_x86_64.rbx),
          [rcx] "=g"(ctx_global->regs.regset_x86_64.rcx), [rdx] "=g"(ctx_global->regs.regset_x86_64.rdx),
          [rsi] "=g"(ctx_global->regs.regset_x86_64.rsi), [rdi] "=g"(ctx_global->regs.regset_x86_64.rdi),
          [rbp] "=g"(ctx_global->regs.regset_x86_64.rbp), [rsp] "=g"(ctx_global->regs.regset_x86_64.rsp),
          [r8]  "=g"(ctx_global->regs.regset_x86_64.r8),  [r9]  "=g"(ctx_global->regs.regset_x86_64.r9),
          [r10] "=g"(ctx_global->regs.regset_x86_64.r10), [r11] "=g"(ctx_global->regs.regset_x86_64.r11),
          [r12] "=g"(ctx_global->regs.regset_x86_64.r12), [r13] "=g"(ctx_global->regs.regset_x86_64.r13),
          [r14] "=g"(ctx_global->regs.regset_x86_64.r14), [r15] "=g"(ctx_global->regs.regset_x86_64.r15),
          [rip] "=g"(ctx_global->regs.regset_x86_64.rip)
        ::"%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi",
          "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15",
          "memory"
        );

	__asm__("ret");
}

void *
shakti_handler(void)
{
	shakti_store_regs_x86_64();
	struct shiva_ctx *ctx = ctx_global;
	void *retaddr = __builtin_return_address(0);
	struct shiva_trace_handler *current;
	struct shiva_trace_bp *bp;
	uint64_t o_target;

	//printf("Ctx: %p\n", ctx);
#if 0
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
#endif
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
	res = shiva_trace_register_handler(ctx, (void *)&shakti_handler,
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
		res = shiva_trace_set_breakpoint(ctx, (void *)&shakti_handler,
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

