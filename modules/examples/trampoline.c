/*
 * This plugin/module is the default one. It is an interactive
 * debugging engine.
 */

#include "../shiva.h"

void __attribute__((naked)) shakti_store_regs_x86_64(struct shiva_trace_regset_x86_64 *regs)
{
	__asm__ __volatile__(
		"movq %rax, (%rdi)\n\t"
		"movq %rbx, 8(%rdi)\n\t"
		"movq %rcx, 16(%rdi)\n\t"
		"movq %rdx, 24(%rdi)\n\t"
		"movq %rsi, 32(%rdi)\n\t"
		//"movq %rdi, 40(%rdi)\n\t"
		"movq %r8,  48(%rdi)\n\t"
		"movq %r9,  56(%rdi)\n\t"
		"movq %r10, 64(%rdi)\n\t"
		"movq %r11, 72(%rdi)\n\t"
		"movq %r12, 80(%rdi)\n\t"
		"movq %r13, 88(%rdi)\n\t"
		"movq %r14, 96(%rdi)\n\t"
		"movq %r15, 104(%rdi)\n\t"
		"ret\n\t"
		);
}

void my_print_string(const char *s)
{
	struct shiva_ctx *ctx = ctx_global;
	struct shiva_trace_handler *handler;
	struct shiva_trace_bp *bp;
	void (*o_print_string)(const char *);
	unsigned long vaddr;
	char buf[256];

	snprintf(buf, sizeof(buf), "Hijacked string: %s", s);
	handler = shiva_trace_find_handler(ctx, &my_print_string);
	if (handler == NULL)
		printf("Failed to find handler struct for my_print_string\n");
		exit(-1);
	}
	SHIVA_TRACE_BP_STRUCT(bp, handler);
	vaddr = (uint64_t)bp->symbol.value + ctx->ulexec.base_vaddr;
	shiva_trace_write(ctx, 0, (void *)addr, &bp->insn.o_insn, bp->bp_len);
	o_print_string = (void *)vaddr;
	o_print_string(buf);
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
	res = shiva_trace_set_breakpoint(ctx, (void *)my_print_string,
	    symbol.value + ctx->ulexec.base_vaddr, &error);
	if (res == false) {
		printf("shiva_trace_set_breakpoint failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	return 0;
}

