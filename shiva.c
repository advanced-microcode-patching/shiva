#include "shiva.h"
#include <time.h>

struct shiva_ctx *ctx_global;

void
shiva_init_lists(struct shiva_ctx *ctx)
{
	TAILQ_INIT(&ctx->tailq.mmap_tqlist);
	TAILQ_INIT(&ctx->tailq.thread_tqlist);
	TAILQ_INIT(&ctx->tailq.branch_tqlist);
	TAILQ_INIT(&ctx->tailq.xref_tqlist);
	TAILQ_INIT(&ctx->tailq.trace_handlers_tqlist);
	return;
}

bool
shiva_build_trace_data(struct shiva_ctx *ctx)
{
	elf_error_t error;
	struct elf_section section;
	int bits;

	if (elf_open_object(ctx->path, &ctx->elfobj, ELF_LOAD_F_FORENSICS,
	    &error) == false) {
	    fprintf(stderr, "elf_open_object(%s, ...) failed: %s\n", ctx->path,
		elf_error_msg(&error));
		return false;
	}
	if (elf_section_by_name(&ctx->elfobj, ".text", &section) == false) {
		fprintf(stderr, "elf_section_by_name failed to find \".text\"\n");
		return false;
	}
	bits = elf_class(&ctx->elfobj) == elfclass64 ? 64 : 32;
	ctx->disas.textptr = elf_address_pointer(&ctx->elfobj, section.address);
	if (ctx->disas.textptr == NULL) {
		fprintf(stderr, "elf_address_pointer(%p, %#lx) failed\n",
		    &ctx->elfobj, section.address);
		return false;
	}
	ctx->disas.base = section.address;
#if 0
	ud_init(&ctx->disas.ud_obj);
	ud_set_input_buffer(&ctx->disas.ud_obj, ctx->disas.textptr, section.size);
	ud_set_mode(&ctx->disas.ud_obj, bits);
	ud_set_syntax(&ctx->disas.ud_obj, UD_SYN_INTEL);
	while (ud_disassemble(&ctx->disas.ud_obj) != 0) {
		printf("%-20s %s\n", ud_insn_hex(&ctx->disas.ud_obj),
		    ud_insn_asm(&ctx->disas.ud_obj));
	}
#endif
	return true;
}

int test_mark(void)
{
	int i = 1;

	if (i < 1)
		return 1;
	else return 0;
}
bool
shiva_build_target_argv(struct shiva_ctx *ctx, char **argv, int argc)
{
	char **p;
	int addend, i;

	/*
	 * If there are no initial shiva args, then build the
	 * argument vector starting from argv[1], otherwise from
	 * argv[2].
	 */
	addend = (argv[1][0] != '-') ? 1 : 2;

	ctx->path = shiva_strdup(argv[addend]);
	ctx->args = (char **)shiva_malloc((argc - addend) * sizeof(char *));
	for (i = 0, p = &argv[addend]; i != argc - addend; p++, i++)
		*(ctx->args + i) = shiva_strdup(*p);
	*(ctx->args + i) = NULL;
	ctx->argcount = i;
	ctx->argv = &argv[addend];
	ctx->argc = argc - addend;
	return true;
}

bool
shiva_interp_mode(struct shiva_ctx *ctx)
{
	struct elf_section section;
	elf_error_t error;
	uint64_t *rsp;
	shiva_auxv_iterator_t auxv_iter;
	struct shiva_auxv_entry auxv_entry;
	uint64_t entry_point;
	bool res;
	shiva_maps_iterator_t maps_iter;
	struct shiva_mmap_entry mmap_entry;
	uint8_t *o_stack, *n_stack;
	uint64_t o_stack_addr;
	size_t copy_len;
	uint64_t o_stack_end = 0;

	ctx_global = ctx;
	shiva_init_lists(ctx);

	shiva_debug("Interp mode, ctx: %p\n", ctx);
	if (shiva_build_trace_data(ctx) == false) {
		fprintf(stderr, "shiva_build_trace_data() failed\n");
		return false;
	}

	if (elf_section_by_name(&ctx->elfobj, ".rela.text", &section) == true) {
		fprintf(stderr, "Warning: Found .text relocations in '%s'. This may alter"
		    " the effects of breakpoints/instrumentation\n", elf_pathname(&ctx->elfobj));
	}

#ifdef SPEED_TEST
	struct timespec tv, tv2;
	double elapsed_time;
	clock_gettime(CLOCK_REALTIME, &tv);
#endif
	if (shiva_analyze_run(ctx) == false) {
		fprintf(stderr, "Failed to run the analyzers\n");
		exit(EXIT_FAILURE);
	}
#ifdef SPEED_TEST
	clock_gettime(CLOCK_REALTIME, &tv2);
	fprintf(stdout, "time to generate xref/branch data: %zu:%zu ms.\n", (size_t)tv2.tv_sec - (size_t)tv.tv_sec,
	    (size_t)tv2.tv_nsec - (size_t)tv.tv_nsec);

#endif

	if (shiva_maps_build_list(ctx) == false) {
		fprintf(stderr, "shiva_maps_build_list() failed\n");
		return false;
	}

	shiva_maps_iterator_init(ctx, &maps_iter);
	while (shiva_maps_iterator_next(&maps_iter, &mmap_entry) == SHIVA_ITER_OK) {
		if (mmap_entry.mmap_type == SHIVA_MMAP_TYPE_STACK) {
			o_stack_end = mmap_entry.base + mmap_entry.len;
			shiva_debug("Original stack upper bound: %#lx\n", o_stack_end);
			break;
		}
	}
	if (o_stack_end == 0) {
		fprintf(stderr, "Unable to find SHIVA_MMAP_TYPE_STACK entry\n");
		return false;
	}
	ctx->shiva.base = mmap_entry.base;
	shiva_debug("Setting shiva base: %#lx\n", mmap_entry.base);
	/*
	 * Since we're in interpreter mode we did not use the ulexec, but
	 * have to set the base address of the target executable which
	 * was mapped into memory by the kernel. This base_vaddr value
	 * is used by the shiva_trace API internally, and must be set.
	 */
	res = shiva_maps_get_base(ctx, &ctx->ulexec.base_vaddr);
	if (res == false) {
		fprintf(stderr, "shiva_maps_get_base() failed\n");
		return false;
	}
	shiva_debug("Setting target base: %#lx\n", ctx->ulexec.base_vaddr);

	if (shiva_target_has_prelinking(ctx) == true) {
		if (shiva_target_get_module_path(ctx, ctx->module_path) == false) {
			fprintf(stderr, "shiva_target_get_module_path() failed\n");
			return false;
		}
	} else {
		fprintf(stderr, "Shiva ELF Interpreter mode doesn't work without first using shiva-ld"
		    " to prelink the target ELF binary\n");
		return false;
		/* XXX */
		char *mpath = getenv("SHIVA_MODULE_PATH");
		if (mpath != NULL) {
			strcpy(ctx->module_path, mpath);
		} else {
			strcpy(ctx->module_path, SHIVA_DEFAULT_MODULE_PATH);
		}
	}

	/*
	 * Get the entry point of the target executable. Stored in AT_ENTRY
	 * of the auxiliary vector.
	 */
	if (shiva_auxv_iterator_init(ctx, &auxv_iter, NULL) == false) {
		fprintf(stderr, "shiva_auxv_iterator_init failed\n");
		return false;
	}
	while (shiva_auxv_iterator_next(&auxv_iter, &auxv_entry) == SHIVA_ITER_OK) {
		if (auxv_entry.type == AT_ENTRY) {
			ctx->ulexec.entry_point = auxv_entry.value;
			shiva_debug("[1] Entry point: %#lx\n", entry_point);
			break;
		}
	}
	if (shiva_module_loader(ctx, ctx->module_path,
	    &ctx->module.runtime, SHIVA_MODULE_F_RUNTIME) == false) {
		fprintf(stderr, "shiva_module_loader failed\n");
		return false;
	}
	shiva_debug("Target base after module: %#lx\n", ctx->ulexec.base_vaddr);
	if (elf_type(&ctx->elfobj) != ET_DYN) {
		fprintf(stderr, "Shiva only supports PIE ELF binaries.\n");
		return false;
	}

	if (elf_open_object(SHIVA_LDSO_PATH, &ctx->ldsobj, ELF_LOAD_F_STRICT, &error) == false) {
		fprintf(stderr, "elf_open_object(%s, ...) failed: %s\n",
		    SHIVA_LDSO_PATH, elf_error_msg(&error));
		return false;
	}
	/*
	 * NOTE: In interpreter mode don't need to userland-execve the
	 * target, but we will borrow one of the functions from shiva_ulexec.c
	 * to load the real dynamic linker into the address space for execution :)
	 */
	if (shiva_ulexec_load_elf_binary(ctx, &ctx->ldsobj, true) == false) {
		fprintf(stderr, "shiva_ulexec_load_elf_binary(%p, %s, true) failed\n",
		    ctx, elf_pathname(&ctx->ldsobj));
		return false;
	}
	/*
	 * We must create a new stack before passing control to LDSO. Normally in interpreter
	 * mode it wouldn't matter since we can just re-use the stack, auxv, etc. In our case
	 * though we call back to various data structures, symbols and code within the Shiva
	 * interpreter, and the Shiva stack data will be corrupted if we don't use a separate
	 * stack for the target executable.
	 */
	n_stack = shiva_ulexec_allocstack(ctx);
	if (n_stack == NULL) {
		fprintf(stderr, "shiva_ulexec_allocstack failed\n");
		return false;
	}
	/*
	 * Set rsp to near the top of the stack at &argc
	 */
	rsp = (uint64_t *)ctx->argv;
	rsp--;

	/*
	 * COPY THE TOP OF OLD STACK TO TOP OF NEW STACK
	 * We want to copy the top-most page of the old stack onto the top-most
	 * page of the new stack. To be more specific we're copying less than
	 * a page, starting at &argc and then copying everything after that.
	 */
	o_stack = (uint8_t *)rsp;
	o_stack_addr = (uint64_t)o_stack;
	copy_len = o_stack_end - o_stack_addr;
	
	shiva_debug("o_stack_addr: %#lx o_stack_end: %#lx\n", o_stack_addr, o_stack_end);
	/*
	 * shiva_ulexec_allocstack() returns a pointer that points to the very
	 * end of the stack (Top of the stack really).
	 */
	shiva_debug("copy_len: %d\n", copy_len);
	shiva_debug("Copying to %p from %p\n", n_stack - copy_len, o_stack);
	n_stack = n_stack - copy_len;
	memcpy(n_stack, o_stack, copy_len);

	/*
	 * rsp must now point to our new stack, right at &argc
	 */
	rsp = (uint64_t *)n_stack;
	shiva_debug("Target entry point: %#lx\n", entry_point);
	shiva_debug("LDSO entry point: %#lx\n", ctx->ulexec.ldso.entry_point);

#if 0
	/*
	 * OLD SOLUTION-- DOESN'T work.
	 * XXX: In the event that our module installed .got.plt hooks, we
	 * must disable DT_BINDNOW before passing control to the RTLD, otherwise
	 * our hooks will be overwritten by RTLD in strict linking mode.
	 * We are basically disabling RELRO (read-only relocations) which is a
	 * security issue. In the future we should inject PLT hooks purely by
	 * injecting JUMPSLOT relocations (Although this won't natively work
	 * with RTLD since it isn't aware of Shiva.
	 */
	(void) shiva_target_dynamic_set(ctx, DT_FLAGS, 0);
	(void) shiva_target_dynamic_set(ctx, DT_FLAGS_1, 0);
#endif
	/*
	 * NEW Solution-- works.
	 * STRICT LINKING (flags: PIE NOW) can be a problem for us since it
	 * will overwrite any PLT hooks that are set.
	 *
	 * Our solution is to create an alternate .rela.plt that excludes the
	 * JUMP_SLOT relocation entry for the symbol we are hooking.
	 *
	 * Update DT_JMPREL to point to our new symbol table.
	 *
	 * These steps are to be carried out from within the shiva_trace API,
	 * specifically shiva_trace_set_breakpoint case PLTGOT_HOOK 
	 */
	test_mark(); /* Used for debugging Shiva with GDB. I set a breakpoint on test_mark() */
	uint64_t *ptr = (void *)rsp;
	SHIVA_ULEXEC_LDSO_TRANSFER(rsp, ctx->ulexec.ldso.entry_point, entry_point);

	return true;

}

int main(int argc, char **argv, char **envp)
{
	shiva_ctx_t ctx;
	struct elf_section section;
	shiva_maps_iterator_t maps_iter;
	struct shiva_mmap_entry mmap_entry;
	char *p, *target_path;

	/*
	 * Initialize everything in the context.
	 */
	memset(&ctx, 0, sizeof(ctx));

	/*
	 * Determine whether we are in interpreter mode
	 */
	target_path = realpath("/proc/self/exe", NULL);
	if (target_path == NULL) {
		fprintf(stderr, "realpath failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	p = strrchr(target_path, '/') + 1;
	if (strcmp(p, "shiva") != 0) {
		shiva_debug("Running in interpreter mode\n");

		ctx.envp = envp;
		ctx.argv = argv;
		ctx.argc = argc;
		ctx.path = target_path;
		ctx.flags |= SHIVA_OPTS_F_INTERP_MODE;
		if (shiva_interp_mode(&ctx) == false) {
			fprintf(stderr, "shiva_interp_mode failed\n");
			exit(EXIT_FAILURE);
		}
	}
	/*
	 * Everything from here down assumes Shiva will be running in standalone
	 * mode (On the command line).
	 */

	if (argc < 2 || (argc == 2 && argv[1][0] == '-')) {
		printf("Usage: %s [-u] <prog> [<prog> args]\n", argv[0]);
		printf("-u	userland-exec mode. shiva simply loads and executes the target program\n");
		printf("-s	static ELF binary (Doesn't use an RTLD)\n");
		printf("example: shiva -u /some/program <program args>\n");
		exit(EXIT_FAILURE);
	}

#if 0
	act.sa_handler = shiva_sighandle;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGINT, &act, NULL);
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
#endif
	ctx.envp = envp;
	ctx.argv = argv;

	if (shiva_build_target_argv(&ctx, argv, argc) == false) {
		fprintf(stderr, "build_target_argv failed\n");
		exit(EXIT_FAILURE);
	}

	shiva_init_lists(&ctx);
	ctx_global = &ctx;

	shiva_debug("ctx_global: %p &ctx_global: %p\n", ctx_global, &ctx_global);
	if (access(ctx.path, F_OK) != 0) {
		fprintf(stderr, "Could not access binary path: %s\n", ctx.path);
		exit(EXIT_FAILURE);
	}

	if (argv[1][0] == '-') {
		char *p;

		for (p = &(*(*(argv + 1) + 1)); *p != '\0'; p++) {
			switch (*p) {
			case 'u':
				ctx.flags |= SHIVA_OPTS_F_ULEXEC_ONLY;
				break;
			case 's':
				ctx.flags |= SHIVA_OPTS_F_STATIC_ELF;
				break;
			default:
				break;
			}
		}
	}

	if (shiva_build_trace_data(&ctx) == false) {
		fprintf(stderr, "shiva_build_trace_data() failed\n");
		exit(EXIT_FAILURE);
	}
	if (elf_section_by_name(&ctx.elfobj, ".rela.text", &section) == true) {
		fprintf(stderr, "Warning: Found .text relocations in '%s'. This may alter"
		    " the effects of breakpoint debugging\n", elf_pathname(&ctx.elfobj));
	}
	if (shiva_ulexec_prep(&ctx) == false) {
		fprintf(stderr, "shiva_ulexec_prep() failed\n");
		exit(EXIT_FAILURE);
	}

	if (shiva_maps_build_list(&ctx) == false) {
		fprintf(stderr, "shiva_maps_build_list() failed\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * XXX
	 * In ARM this seems to find the wrong base address for Shiva. Fortunately
	 * our interpreter is only ET_EXEC (Not ET_DYN) in aarch64. Nonetheless
	 * why is this code returnin the stack address instead of the base of Shiva?
	 * TODO
	 */
	shiva_maps_iterator_init(&ctx, &maps_iter);
	while (shiva_maps_iterator_next(&maps_iter, &mmap_entry) == SHIVA_ITER_OK) {
		if (mmap_entry.mmap_type == SHIVA_MMAP_TYPE_SHIVA && mmap_entry.prot == PROT_READ) {
			break;
		}
	}
	ctx.shiva.base = mmap_entry.base;

	/*
	 * Now that we've got the target binary (The debugee) loaded
	 * into memory, we can run some analyzers on it to acquire
	 * information (i.e. callsite locations).
	 */
#ifdef SPEED_TEST
	struct timespec tv, tv2;
	double elapsed_time;
	clock_gettime(CLOCK_REALTIME, &tv);
#endif
	if (shiva_analyze_run(&ctx) == false) {
		fprintf(stderr, "Failed to run the analyzers\n");
		exit(EXIT_FAILURE);
	}
#ifdef SPEED_TEST
	clock_gettime(CLOCK_REALTIME, &tv2);
	fprintf(stdout, "time to generate xref/branch data: %zu:%zu ms.\n", (size_t)tv2.tv_sec - (size_t)tv.tv_sec,
	    (size_t)tv2.tv_nsec - (size_t)tv.tv_nsec);
#endif
	/*
	 * This flag tells Shiva to ul_exec the target binary without installing
	 * any patches at runtime.
	 */
	if (ctx.flags & SHIVA_OPTS_F_ULEXEC_ONLY)
		goto transfer_control;

	if (shiva_target_has_prelinking(&ctx) == true) {
		if (shiva_target_get_module_path(&ctx, ctx.module_path) == false) {
			fprintf(stderr, "shiva_target_get_module_path() failed\n");
			return false;
		}
	} else {
		char *mpath = getenv("SHIVA_MODULE_PATH");
		if (mpath != NULL) {
			strcpy(ctx.module_path, mpath);
		} else {
			/*
			 * If the target binary has no shiva-prelinking
			 * and we are executing it with /lib/shiva directly
			 * then we can flip on ulexec mode. Shiva won't load
			 * any modules. it will simply pass control to ld-linux.so
			 * and effectively ulexec the target ELF binary.
			 */
			ctx.flags |= SHIVA_OPTS_F_ULEXEC_ONLY;
		}
	}

	if (ctx.flags & SHIVA_OPTS_F_ULEXEC_ONLY)
		goto transfer_control;

	if (shiva_module_loader(&ctx, ctx.module_path,
	    &ctx.module.runtime, SHIVA_MODULE_F_RUNTIME) == false) {
		fprintf(stderr, "shiva_module_loader failed\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * Once the module has finished executing, we pass control
	 * to LDSO.
	 */
transfer_control:
	test_mark();
	shiva_debug("Passing control to entry point: %#lx\n", ctx.ulexec.entry_point);
	shiva_debug("LDSO entry point: %#lx\n", ctx.ulexec.ldso.entry_point);
	SHIVA_ULEXEC_LDSO_TRANSFER(ctx.ulexec.rsp_start, ctx.ulexec.ldso.entry_point,
	    ctx.ulexec.entry_point);

	return true;
}
