#define _GNU_SOURCE
#include "shiva_module.h"
#include "shiva.h"
#include "libelfmaster.h"

SHIVA_MODULE_POST_LDSO; // Module should begin executing shiva_init() after ld-linux.so has already run
int
shiva_init(struct shiva_ctx *ctx)
{
	elfobj_t *elfobj = &ctx->elfobj;
	elf_section_iterator_t shdr_iter;
	struct elf_section shdr;
	size_t i = 0;

	printf("Printing ELF section headers of program before runtime!\n");

	elf_section_iterator_init(elfobj, &shdr_iter);
	while (elf_section_iterator_next(&shdr_iter, &shdr) == ELF_ITER_OK) {
        	printf("[%02x] %s\n", i++, shdr.name);
	}
}
