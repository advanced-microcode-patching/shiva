/*
 * This module demonstrates the pltgot hooking mechanism.
 * The symbol 'puts@plt' is hijacked via the GOT pointer
 * and redirected to (*n_puts)() handler. This is does using
 * the Shiva trace API.
 */

#include "../shiva.h"

/*
 * This function services all PLT calls, and enforces
 * forwards and backwards edge CFI. If the return address
 * of the function that was invoked doesn't match it's
 * CFI data stored in the breakpoints retaddr's list,
 * then we cancel execution with an exit.
 */
int plt_handler(void *arg)
{
	shiva_trace_getregs_x86_64(&ctx_global->regs.regset_x86_64);
	void *__ret = __builtin_return_address(0);
	shiva_trace_handler_t *handler;
	struct shiva_trace_bp *bp;
	struct shiva_addr_struct *addr;
	void * (*fp)(uint64_t a, uint64_t b, uint64_t c, uint64_t d);
	struct elf_symbol symbol;

	ctx_global->regs.regset_x86_64.rip = (uint64_t)__ret - 5;
	ctx_global->regs.regset_x86_64.rdi = (uint64_t)arg;

	handler = shiva_trace_find_handler(ctx_global, &plt_handler);
	if (handler == NULL) {
		printf("Failed to find handler struct for plt_handler\n");
		exit(-1);
	}
	TAILQ_FOREACH(bp, &handler->bp_tqlist, _linkage) {
		if (bp->bp_type == SHIVA_TRACE_BP_PLTGOT) {
			TAILQ_FOREACH(addr, &bp->retaddr_list, _linkage) {
				if (addr->addr == __ret) {
					/*
					 * XXX
					 * This is a work around. In the future we need to add
					 * in the ability to resolve the shared library objects.
					 * no big deal, just gonna take a minute.
					 */
					if (elf_symbol_by_name(&ctx_global->shiva_elfobj, bp->symbol.name,
					    &symbol) == true) {
						fp = ctx_global->shiva.base == 0x400000 ? (void *)symbol.value :
						    (void *) ((uint64_t)symbol.value + ctx_global->shiva.base);
						/*
						 * Call original function. NOTE: We are not
						 * calling the original .so version of the function.
						 * We are instead calling the one within the shiva
						 * musl-libc, assuming it even exists. Like I said
						 * temporary work around.
						 */
						return fp(ctx_global->regs.regset_x86_64.rdi,
							  ctx_global->regs.regset_x86_64.rsi,
							  ctx_global->regs.regset_x86_64.rdx,
							  ctx_global->regs.regset_x86_64.rcx);

					}
				}
			}
		}
	}
	printf("!!! Detected illegal return address in PLT\n");
	exit(EXIT_FAILURE);
}


int
shakti_main(shiva_ctx_t *ctx)
{
	bool res;
	shiva_error_t error;
	elf_plt_iterator_t plt_iter;
	struct elf_plt plt_entry;

	res = shiva_trace(ctx, 0, SHIVA_TRACE_OP_ATTACH,
	    NULL, NULL, 0, &error);
	if (res == false) {
		printf("shiva_trace failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	res = shiva_trace_register_handler(ctx, (void *)&plt_handler,
	    SHIVA_TRACE_BP_PLTGOT, &error);
	if (res == false) {
		printf("shiva_register_handler failed: %s\n",
		    shiva_error_msg(&error));
		return -1;
	}

	elf_plt_iterator_init(&ctx->elfobj, &plt_iter);
	while (elf_plt_iterator_next(&plt_iter, &plt_entry) == ELF_ITER_OK) {
		/*
		 * libelfmaster will assign the PLT symbol name "PLT-0" for the
		 * PLT-0 entry in the .plt section.
		 */
		if (strcmp(plt_entry.symname, "PLT-0") == 0)
			continue;
		res = shiva_trace_set_breakpoint(ctx, (void *)&plt_handler,
		    0, plt_entry.symname, &error);
		if (res == false) {
			printf("shiva_trace_set_breakpoint failed: %s\n", shiva_error_msg(&error));
			return -1;
		}
	}
	return 0;
}
