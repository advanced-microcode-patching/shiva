#include "shiva.h"

struct shiva_ctx *ctx_global;

void
shiva_init_lists(struct shiva_ctx *ctx)
{
	TAILQ_INIT(&ctx->tailq.mmap_tqlist);
	TAILQ_INIT(&ctx->tailq.thread_tqlist);
	TAILQ_INIT(&ctx->tailq.branch_tqlist);
	TAILQ_INIT(&ctx->tailq.trace_handlers_tqlist);
	return;
}

bool
shiva_build_trace_data(struct shiva_ctx *ctx)
{
	elf_error_t error;
	struct elf_section section;
	uint8_t *code;
	int i, bits;

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
	char *interp;
	uint64_t *rsp;
	shiva_auxv_iterator_t auxv_iter;
	struct shiva_auxv_entry auxv_entry;
	uint64_t entry_point;
	bool res;

	ctx_global = ctx;
	shiva_init_lists(ctx);

	if (shiva_build_trace_data(ctx) == false) {
		fprintf(stderr, "shiva_build_trace_data() failed\n");
		return false;
	}

	if (elf_section_by_name(&ctx->elfobj, ".rela.text", &section) == true) {
		fprintf(stderr, "Warning: Found .text relocations in '%s'. This may alter"
		    " the effects of breakpoints/instrumentation\n", elf_pathname(&ctx->elfobj));
	}
	
	if (shiva_analyze_run(ctx) == false) {
		fprintf(stderr, "Failed to run the analyzers\n");
		return false;
	}
	if (shiva_maps_build_list(ctx) == false) {
		fprintf(stderr, "shiva_maps_build_list() failed\n");
		return false;
	}
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
	/*
	 * Loads the runtime module, and then passes control to
	 * shakti_main() (Within the module) before passing control
	 * to LDSO.
	 */
	printf("Loading module\n");
	if (shiva_module_loader(ctx, "./modules/shakti_runtime.o",
	    &ctx->module.runtime, SHIVA_MODULE_F_RUNTIME) == false) {
		fprintf(stderr, "shiva_module_loader failed\n");
		exit(EXIT_FAILURE);
	}
	if (elf_type(&ctx->elfobj) != ET_DYN) {
		fprintf(stderr, "Shiva only supports PIE ELF binaries.\n");
		return false;
	}
#if 0
	interp = elf_interpreter_path(&ctx->elfobj);
	if (interp == NULL) {
		fprintf(stderr,
	  	    "Shiva currently only supports dynamically linked ELF binaries\n");
		return false;
	}
#endif
	if (elf_open_object(SHIVA_LDSO_PATH, &ctx->ldsobj, ELF_LOAD_F_STRICT, &error) == false) {
		fprintf(stderr, "elf_open_object(%s, ...) failed: %s\n",
		    interp, elf_error_msg(&error));
		return false;
	}
	/*
	 * NOTE: In interpreter mode we are not needing to userland execve the
	 * target, but we will borrow one of the functions from shiva_ulexec.c
	 * to load the real  dynamic linker into the address space for execution :)
	 */
	if (shiva_ulexec_load_elf_binary(ctx, &ctx->ldsobj, true) == false) {
		fprintf(stderr, "shiva_ulexec_load_elf_binary(%p, %s, true) failed\n",
		    ctx, elf_pathname(&ctx->ldsobj));
		return false;
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
			entry_point = auxv_entry.value;
			shiva_debug("Entry point: %#lx\n", entry_point);
			break;
		}
	}
	/*
	 * Set rsp to near the top of the stack at &argc
	 */
	rsp = (uint64_t *)ctx->argv;
	rsp--;

	shiva_debug("Passing control to entry point: %#lx\n", entry_point);
        shiva_debug("LDSO entry point: %#lx\n", ctx->ulexec.ldso.entry_point);
        SHIVA_ULEXEC_LDSO_TRANSFER(rsp, ctx->ulexec.ldso.entry_point, entry_point);

	return true;

}

int main(int argc, char **argv, char **envp)
{
	shiva_ctx_t ctx;
	int opt, i, subend;
	struct elf_section section;
	struct sigaction act;
	sigset_t set;

	char *path, *p, *target_path;

	/*
	 * Initialize everything in the context.
	 */
	memset(&ctx, 0, sizeof(ctx));

	/*
	 * Determine whether we are in interpreter mode
	 */
	target_path = realpath("/proc/self/exe", path);
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
		printf("example: shiva -u /some/program <program args>\n");
		exit(EXIT_FAILURE);
	}

	act.sa_handler = shiva_sighandle;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGINT, &act, NULL);
	sigemptyset(&set);
	sigaddset(&set, SIGINT);

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
	 * Now that we've got the target binary (The debugee) loaded
	 * into memory, we can run some analyzers on it to acquire
	 * information (i.e. callsite locations).
	 */
	if (shiva_analyze_run(&ctx) == false) {
		fprintf(stderr, "Failed to run the analyzers\n");
		exit(EXIT_FAILURE);
	}
	/*
	 * shiva_module_loader will load modules/shakti_module.o
	 * into an executable region within our address space.
	 * It will then pass control to the module.
	 */
	if (ctx.flags & SHIVA_OPTS_F_ULEXEC_ONLY)
		goto transfer_control;

	if (shiva_module_loader(&ctx, "./modules/shakti_runtime.o",
	    &ctx.module.runtime, SHIVA_MODULE_F_RUNTIME) == false) {
		fprintf(stderr, "shiva_module_loader failed\n");
		exit(EXIT_FAILURE);
	}
	/*
	 * Once the module has finished executing, we pass control
	 * to LDSO.
	 */
transfer_control:
	shiva_debug("Passing control to entry point: %#lx\n", ctx.ulexec.entry_point);
	shiva_debug("LDSO entry point: %#lx\n", ctx.ulexec.ldso.entry_point);
	SHIVA_ULEXEC_LDSO_TRANSFER(ctx.ulexec.rsp_start, ctx.ulexec.ldso.entry_point,
	    ctx.ulexec.entry_point);

	return true;
}
