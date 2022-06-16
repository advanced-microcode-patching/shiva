#include "shiva.h"


/*
 * XXX: We are no longer using this code as a workaround...
 *
 * The Shiva interpreter is a static executable, and it is not PIE.
 * Therefore it will be mapped to an address range much lower than
 * the target executable, and the module. The executable, the module,
 * and the shiva interpreter must all be within 4GB range of eachother.
 * Ultimately we must fix this by modifying the build so that it creates
 * a proper static-pie executable with musl-libc.
 *
 * NOTE: Shiva (The interpreter) contains all of the musl-libc symbols
 * and shiva_trace symbols that will be referenced by the loaded module.
 * Module relocations such as R_X86_64_PC32 will not be able to properly
 * relocate if Shiva is mapped beyond 4GB away. Otherwise we would have
 * to use a large code model with everything and that would suck.
 */
bool
shiva_proc_duplicate_image(struct shiva_ctx *ctx)
{
	int pid;
	char *args[] = {"shiva", NULL};
	FILE *fp;
	char buf[PATH_MAX + 1];
	char *p;
	int status;

	/*
	 * shiva_proc_duplicate_image relies on ctx->shiva_path
	 * already being set by shiva_maps_build_maps_list()
	 */
	assert(ctx->shiva_path != NULL);

	if ((pid = fork()) < 0) {
		perror("fork");
		return false;
	}

	if (pid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
			perror("PTRACE_TRACEME");
			return false;
		}
		ptrace(PTRACE_SETOPTIONS, 0, 0, PTRACE_O_TRACEEXIT);
		execve(ctx->shiva_path, args, NULL);
		exit(0);
	}
	waitpid(0, &status, WNOHANG);
	ctx->duplicate_pid = pid;

	fp = fopen("/proc/%d/exe", "r");
	if (fp == NULL) {
		perror("fopen");
		return false;
	}
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (strstr(buf, "shiva") != NULL) {
			p = strchr(buf, '-');
			*p = '\0';
			ctx->duplicate_base = strtoul(buf, NULL, 16);
			printf("duplicate base: %#lx\n", ctx->duplicate_base);
			return true;
		}
	}	
	return false;
}
