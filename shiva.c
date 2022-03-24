#include "shiva.h"

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

int main(int argc, char **argv, char **envp)
{
	shiva_ctx_t ctx;
	int opt, i, subend;
	struct elf_section section;
	struct sigaction act;
	sigset_t set;
	act.sa_handler = shiva_sighandle;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGINT, &act, NULL);
	sigemptyset(&set);
	sigaddset(&set, SIGINT);

	/*
	 * Initialize everything in the context.
	 */
	memset(&ctx, 0, sizeof(ctx));

	if ((argc < 2) || (argc == 2 && argv[1][0] == '-')) {
		printf("Usage: %s [-sbr] <prog> [<prog> args]\n", argv[0]);
		printf("[-s] string values\n");
		printf("[-b] branch control flow\n");
		printf("[-r] return values\n");
		printf("Example: shiva -sbr /bin/ls -lR\n");
		exit(EXIT_FAILURE);
	}

	ctx.envp = envp;

	if (shiva_build_target_argv(&ctx, argv, argc) == false) {
		fprintf(stderr, "build_target_argv failed\n");
		exit(EXIT_FAILURE);
	}

	shiva_init_lists(&ctx);

	if (access(ctx.path, F_OK) != 0) {
		fprintf(stderr, "Could not access binary path: %s\n", ctx.path);
		exit(EXIT_FAILURE);
	}

	if (argv[1][0] == '-') {
		char *p;

		for (p = &(*(*(argv + 1) + 1)); *p != '\0'; p++) {
			switch (*p) {
			case 's':
				ctx.flags |= SHIVA_F_STRING_ARGS;
				break;
			case 'b':
				ctx.flags |= SHIVA_F_JMP_CFLOW;
				break;
			case 'r':
				ctx.flags |= SHIVA_F_RETURN_FLOW;
				break;
			default:
				break;
			}
		}
	}
	shiva_debug("Target path: %s\n", ctx.path);
	shiva_debug("Target args: ");
#if DEBUG
	for (i = 0; i < ctx.argcount; i++) {
		printf("%s ", ctx.args[i]);
	}
#endif
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
	if (shiva_module_loader(&ctx, "./modules/shakti_runtime.o",
	    &ctx.module.runtime, SHIVA_MODULE_F_RUNTIME) == false) {
		fprintf(stderr, "shiva_module_loader failed\n");
		exit(EXIT_FAILURE);
	}
	SHIVA_ULEXEC_LDSO_TRANSFER(ctx.ulexec.rsp_start, ctx.ulexec.ldso.entry_point,
            ctx.ulexec.entry_point);

	return true;
}
