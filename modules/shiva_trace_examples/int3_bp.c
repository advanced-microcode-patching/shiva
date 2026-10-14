/*
 * This module demonstrates the pltgot hooking mechanism.
 * The symbol 'puts@plt' is hijacked via the GOT pointer
 * and redirected to (*n_puts)() handler. This is does using
 * the Shiva trace API.
 */

#include "shiva.h"
#include "shiva_module.h"
#include <ucontext.h>

uint64_t o_insn[2];

void
bp_handler(int sig, siginfo_t *si, void *data)
{
	
	ucontext_t *uctx = (ucontext_t *)data;
	shiva_error_t error;
	uint64_t rip;
	bool res;

	/*
	 * RESTORE REGISTER STATE FROM CTX
	 * and jmp <RIP - 1>
	 */
	printf("SIGNUM: %d Breakpoint hit at %#llx\n", sig,
	    uctx->uc_mcontext.gregs[REG_RIP] - 1);
	rip = uctx->uc_mcontext.gregs[REG_RIP] - 1;

	/*
	 * Remove breakpoint from instruction
	 */
	res = shiva_trace_write(ctx_global, 0, (void *)rip, &o_insn, 1, &error);
	if (res == false) {
		printf("shiva_trace_write failed\n");
		return;
	}
	/*
	 * Rewind stack, restore regs, and do an equivelent to
	 * a longjmp back to the instruction that trapped.
	 * We let __rt_sigreturn handle this and returning
	 * back to the original function before the breakpoint.
	 */
	uctx->uc_mcontext.gregs[REG_RIP] = (greg_t)rip;

	return;
}

int
shakti_main(shiva_ctx_t *ctx)
{
	bool res;
	shiva_error_t error;
	struct elf_symbol symbol;

	res = shiva_trace(ctx, 0, SHIVA_TRACE_OP_ATTACH,
	    NULL, NULL, 0, &error);
	if (res == false) {
		printf("shiva_trace failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	res = shiva_trace_register_handler(ctx, (void *)&bp_handler,
	    SHIVA_TRACE_BP_INT3, &error);
	if (res == false) {
		printf("shiva_register_handler failed: %s\n",
		    shiva_error_msg(&error));
		return -1;
	}
	if (elf_symbol_by_name(&ctx->elfobj, "main", &symbol) == false) {
		printf("couldn't find sybol main in target\n");
		return -1;
	}

	if (shiva_trace(ctx, 0, SHIVA_TRACE_OP_PEEK,
	    (void *)((uint64_t)symbol.value + ctx->ulexec.base_vaddr), &o_insn[0], 16, &error) == false) {
		printf("shiva_trace PEEK failed on %p\n",
		    (void *)((uint64_t)symbol.value + ctx->ulexec.base_vaddr));
		return -1;
	}
	res = shiva_trace_set_breakpoint(ctx, (void *)&bp_handler,
	    symbol.value + ctx->ulexec.base_vaddr, NULL, &error);
	if (res == false) {
		printf("shiva_trace_set_breakpoint failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	return 0;
}

