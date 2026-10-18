/*
 * This module is an example of writing a function tracer in the form
 * of a Shiva module. Instead of setting traditional breakpoints (i.e int3)
 * on each function, we instead use some of the alternative breakpoint capabilities
 * that the ShivaTrace API offers; namely the SHIVA_TRACE_BP_CALL and SHIVA_TRACE_BP_PLTGOT
 * which insert hooks rather than actual int3 instructions.
 *
 * The result is a function tracer that is insanely fast. Orders of magnitude
 * faster than ltrace for example which relies on ptrace().
 */

#include "shiva.h"
#include "shiva_module.h"

/*
 * Handles PLTGOT hooks. Every call into a PLT stub will land in our
 * pltgot_handler() which will print the func@plt information and
 * then finish up  by calling the original function (the original GOT value)
 * This handler is registered below in the shiva_init() function.
 */
void * pltgot_handler(void *r1, void *r2, void *r3, void *r4, void *r5, void *r6, void *r7)
{
	shiva_trace_getregs_x86_64(&ctx_global->regs.regset_x86_64);
	struct shiva_ctx *ctx = ctx_global;
	struct shiva_trace_bp *bp;
	struct shiva_trace_handler *handler;

	handler = shiva_trace_find_handler(ctx, &pltgot_handler);
	if (handler == NULL) {
		fprintf(stderr, "Failed to find handler struct for callsite_handler\n");
		exit(-1);
	}
	/*
	 * Get the breakpoint struct associated with the PLTGOT breakpoint
	 * that triggered our pltgot_handler()
	 */
	SHIVA_TRACE_BP_STRUCT(bp, handler);
	printf("[CALL] %s@plt (GOT address: %#lx GOT value %#lx)\n",
	    bp->symbol.name, bp->bp_addr, bp->o_target);
	fflush(stdout);
	SHIVA_TRACE_CALL_ORIGINAL(bp);
}
/*
 * Handles hooked callsites. The SHIVA_TRACE_BP_CALL breakpoint type
 * hooks calls by patching the call offsets. This is our callsite_handler()
 * that we wil register (As shown in shiva_init).
 */
void *
callsite_handler(void *arg)
{
	void *entry_rsp;
	__asm__ __volatile__("mov %%rsp, %0" : "=r"(entry_rsp));
	struct shiva_ctx *ctx = ctx_global;
	void *retaddr = __builtin_return_address(0);
	void *frmaddr = __builtin_frame_address(1);
	struct shiva_trace_handler *handler;
	struct shiva_trace_bp *bp;
	uint64_t o_target;
	shiva_trace_jumpbuf_t jmpbuf;

	shiva_trace_setjmp_x86_64(&jmpbuf);
	shiva_trace_getregs_x86_64(&ctx->regs.regset_x86_64);
	/*
	 * Fixup registers clobbered by getregs
	 * */
	ctx->regs.regset_x86_64.rbp = (uint64_t)__builtin_frame_address(1);
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
	if (strncmp(bp->call_target_symname, "fn_0x", 5) == 0) {
		printf("[CALL] %s\n", bp->call_target_symname);
	} else {
		printf("[CALL] %s@%#lx\n", bp->call_target_symname, RUNTIME_BASE(bp->symbol.value));
	}
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
	elf_pltgot_iterator_t pltgot_iter;
	struct elf_pltgot_entry pltgot_entry;

	printf("Target '%s': %#lx\n", ctx->path, ctx->ulexec.base_vaddr);

	res = shiva_trace(ctx, 0, SHIVA_TRACE_OP_ATTACH,
	    NULL, NULL, 0, &error);
	if (res == false) {
		printf("shiva_trace failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	/*
	 * Fast breakpoints that hook call offsets from
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
	 * Fast breakpoints that hook the PLTGOT directly
	 * and setup a handler, rather than use standard int3.
	 */
	res = shiva_trace_register_handler(ctx, (void *)&pltgot_handler,
	    SHIVA_TRACE_BP_PLTGOT, &error);
	if (res == false) {
		printf("shiva_trace_register_handler failed: %s\n",
		    shiva_error_msg(&error));
		return -1;
	}
	/*
	 * Set 'e8' immediate call breakpoints. Which replace the call offset
	 * on every e8 call. Ignore calls to PLT, instead we use the
	 * PLTGOT breakpoint type to handle those ones.
	 */
	shiva_callsite_iterator_init(ctx, &call_iter);
	while (shiva_callsite_iterator_next(&call_iter, &branch) == ELF_ITER_OK) {
		if (branch.branch_flags & SHIVA_BRANCH_F_PLTCALL) // ignore this case we handle it later with PLTGOT breakpoints
			continue;
		printf("Setting breakpoint on %s\n", branch.symbol.name);
		res = shiva_trace_set_breakpoint(ctx, (void *)&callsite_handler,
		    RUNTIME_BASE(branch.branch_site), NULL, &error);
		if (res == false) {
			printf("shiva_trace_register_breakpoint failed: %s\n",
			    shiva_error_msg(&error));
			return -1;
		}
	}
	elf_pltgot_iterator_init(&ctx->elfobj, &pltgot_iter);
	while (elf_pltgot_iterator_next(&pltgot_iter, &pltgot_entry) == ELF_ITER_OK) {
		uint64_t got_addr = RUNTIME_BASE(pltgot_entry.offset);

		if (pltgot_entry.flags & ELF_PLTGOT_PLT_STUB_F) {
			res = shiva_trace_set_breakpoint(ctx, (void *)&pltgot_handler,
			    got_addr, NULL, &error);
			if (res == false) {
				printf("shiva_trace_set_breakpoint() failed %#lx\n", got_addr);
				return -1;
			}
		}
	}
	return 0;
}

