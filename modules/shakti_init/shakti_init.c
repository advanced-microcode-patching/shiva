/*
 * Initialization code to be linked into shiva modules
 * Finds the auxv, and passes the AT_FLAGS value which is
 * set to the shiva_ctx_t struct pointer, to the module
 * function main()
 */
#include "../../shiva.h"

int shakti_main(shiva_ctx_t *) __attribute__((weak));

void
shakti_module_init(int argc, char **argv, char **envp)
{
	int i;
	Elf64_auxv_t *auxv;

	for (i = 0; envp[i] != NULL; i++)
		;
	auxv = (Elf64_auxv_t *)&envp[i + 1];
	while (auxv[i].a_un.a_val != AT_NULL) {
		if (auxv[i].a_type == AT_FLAGS) {
			shakti_main((shiva_ctx_t *)auxv[i].a_un.a_val);
		}
	}
	return;
}
