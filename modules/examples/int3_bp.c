/*
 * This module demonstrates the pltgot hooking mechanism.
 * The symbol 'puts@plt' is hijacked via the GOT pointer
 * and redirected to (*n_puts)() handler. This is does using
 * the Shiva trace API.
 */

#include "../shiva.h"
#include <ucontext.h>


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
	printf("SIGNUM: %d Breakpoint hit at %#lx\n", sig,
	    uctx->uc_mcontext.gregs[REG_RIP] - 1);
	rip = uctx->uc_mcontext.gregs[REG_RIP] - 1;

	int8_t val = 0x55;

	/*
	 * Remove breakpoint from instruction
	 */
	res = shiva_trace_write(ctx_global, 0, (void *)rip, &val, 1, &error);
	if (res == false) {
		printf("shiva_trace_write failed\n");
		return;
	}
	/*
	 * Rewind stack, restore regs, and do an equivelent to
	 * a longjmp back to the instruction that trapped.
	 * TODO: Eventually when there is a compiler wrapper
	 * (i.e. shiva-gcc) then these macros will automatically
	 * be placed into certain functions
	 */
	SHIVA_TRACE_LONGJMP_RETURN(&uctx->uc_mcontext.gregs[0], rip);
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
	printf("Setting breakpoint at %#lx\n", symbol.value + ctx->ulexec.base_vaddr);
	res = shiva_trace_set_breakpoint(ctx, (void *)&bp_handler,
	    symbol.value + ctx->ulexec.base_vaddr, NULL, &error);
	if (res == false) {
		printf("shiva_trace_set_breakpoint failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	return 0;
}

