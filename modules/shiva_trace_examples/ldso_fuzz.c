/*
 * Fuzz the LDSO via modifications to PT_DYNAMIC
 * and relocation tables, etc.
 */

#include "../shiva.h"

#define MAX_DT_VALUE 30

void *assert_handler(void *arg)
{
	shiva_trace_getregs_x86_64(&ctx_global->regs.regset_x86_64);

	struct shiva_ctx *ctx = ctx_global;

	void *retaddr = __builtin_return_address(0);
	void *frmaddr = __builtin_frame_address(1);
	struct shiva_trace_handler *handler;
	struct shiva_trace_bp *bp;
	uint64_t o_target;

	/*
	 * Even after we call shakti_store_regs_x86_64 we must
	 * fix the clobbered rbp, rip, and rdi registers with
	 * their correct values at the time this handler was
	 * called.
	 */
	ctx->regs.regset_x86_64.rbp = (uint64_t)frmaddr;
	ctx->regs.regset_x86_64.rip = (uint64_t)retaddr - 5;
	ctx->regs.regset_x86_64.rdi = (uint64_t)arg;

	handler = shiva_trace_find_handler(ctx, &assert_handler);
	if (handler == NULL) {
		printf("Failed to find handler struct for shakti_handler\n");
		exit(-1);
	}
	/*
	 * Get the shiva_trace_bp struct pointer that correlates
	 * to the call-hook-breakpoint. Then find the call-hook
	 * breakpoint that triggered our handler.
	 */
	SHIVA_TRACE_BP_STRUCT(bp, handler);
	printf("LDSO ASSERT CALL\n", bp->call_target_symname);
	//SHIVA_TRACE_CALL_ORIGINAL(bp);

}

int
shakti_main(shiva_ctx_t *ctx)
{
	bool res;
	shiva_error_t error;
	struct elf_segment phdr;
	size_t dcount;
	uint32_t v, b;
	struct timeval tv;
	shiva_auxv_iterator_t a_iter;
	struct shiva_auxv_entry a_entry;
	uint64_t tag_value, highest_vaddr, rand_val;
	static int global_count = 0;
	bool second_run = false;

	if (ctx != ctx_global) {
		second_run = true;
		ctx = ctx_global;
	}
	printf("LDSO-FUZZ v0.1 (Shiva runtime engine)\n");
	printf("&ctx->elfobj: %p\n", &ctx->elfobj);
	if (elf_segment_by_p_type(&ctx->elfobj, PT_DYNAMIC, &phdr) == false) {
		printf("Cannot find dynamic segment\n");
		exit(-1);
	}
	dcount = phdr.filesz / sizeof(Elf64_Dyn);
	res = shiva_trace(ctx, 0, SHIVA_TRACE_OP_ATTACH,
	    NULL, NULL, 0, &error);
	if (res == false) {
		printf("shiva_trace failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	/*
	 * Let's only provide values as high as the executable address space
	 * goes, in some instances. In other instances we will send a random
	 * uint64_t
	 */
	highest_vaddr = elf_data_base(&ctx->elfobj) + elf_data_filesz(&ctx->elfobj);
	gettimeofday(NULL, &tv);
	srand(tv.tv_usec);
	while (1) {
		rand_val = (tag_value % 2 == 0) ? (rand() & (highest_vaddr - 1)) :
		    rand() & ~(uint64_t)0ULL;
		gettimeofday(&tv, NULL);
		srand(tv.tv_usec);
		tag_value = rand() & (MAX_DT_VALUE - 1);
		if (shiva_target_dynamic_set(ctx, tag_value, rand_val) == true)
			break;
	}

	/*
	 * Install hook on LDSO calls into __GI___assert_fail()
	 */
	if (second_run == false) {
		printf("SETTING CALL BREAKPOING on 0x101e480\n");
		res = shiva_trace_register_handler(ctx, (void *)&assert_handler,
	    	    SHIVA_TRACE_BP_CALL, &error);
		if (res == false ) {
			printf("shiva_trace_register_handler() failed\n");
			return false;
		}
		res = shiva_trace_set_breakpoint(ctx, (void *)assert_handler,
	    	    (uint64_t)0x101e480, NULL, &error);
		if (res == false) {
			printf("set breakpoint failed\n");
			return false;
		}
	}
		/*
		 * Install hook for LDSO assert calls (__GI___assert_fail)
		 */
	printf("Set DTAG %d with %#lx\n", tag_value, rand_val);
	/*
	 * Hook the AT_ENTRY value so that it points back to our module after
	 * LDSO is done. Only use the auxiliary vector created
	 * by the userland-exec, since this is the one that is being passed
	 * to LDSO.
	 */
	if (shiva_auxv_iterator_init(ctx, &a_iter,
	    ctx->ulexec.auxv.vector) == false) {
		printf("shiva_auxv_iterator_init failed\n");
		exit(-1);
	}
	while (shiva_auxv_iterator_next(&a_iter, &a_entry) == SHIVA_ITER_OK) {
		if (a_entry.type == AT_ENTRY) {
			uint64_t entry;

			/*
			 * This isn't an API function but we will call into
			 * it illegaly (It's in shiva_module.c, the linker code).
			 */
			if (module_entrypoint(ctx->module.runtime, &entry) == false) {
				printf("couldn't find module entrypoint, exiting...\n");
				exit(-1);
			}
			/*
			 * Set AT_ENTRY to the entry point of our module. (Normally
			 * it points to the target program, of course).
			 */
			if (shiva_auxv_set_value(&a_iter, entry) == false) {
				printf("shiva_auxv_set_value failed (Setting %#lx)\n", entry);
				exit(-1);
			}
			printf("Set AT_ENTRY = %#lx\n", entry);
		}
	}
	printf("Returning from module\n");
	return 0;
}

