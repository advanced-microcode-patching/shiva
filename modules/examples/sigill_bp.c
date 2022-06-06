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

	printf("SIGNUM: %d Breakpoint hit at %p\n", sig, si->si_addr);
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
	    SHIVA_TRACE_BP_SIGILL, &error);
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
