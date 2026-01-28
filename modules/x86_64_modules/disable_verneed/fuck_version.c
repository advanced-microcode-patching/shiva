#define _GNU_SOURCE
#include "../../include/shiva_module.h"
#include "../../../shiva.h"
#include "/opt/elfmaster/include/libelfmaster.h"

SHIVA_MODULE_PRE_EXEC_PHASE;

int
shiva_init(struct shiva_ctx *ctx)
{
	elfobj_t *elfobj = &ctx->elfobj;
	elf_error_t error;
	elf_segment_iterator_t phdr_iter;
	struct elf_segment phdr;
	struct elf_section shdr;
	uint64_t dynamic_addr;
	size_t i, j;
	uint64_t versym_addr;

	elf_segment_iterator_init(elfobj, &phdr_iter);
	while (elf_segment_iterator_next(&phdr_iter, &phdr) == ELF_ITER_OK) {
		if (phdr.type == PT_DYNAMIC) {
			dynamic_addr = RUNTIME_BASE(phdr.vaddr);
			break;
		}
	}
	if (dynamic_addr > 0) {
		Elf64_Dyn *dyn = (Elf64_Dyn *)dynamic_addr;
		uint16_t *vptr;

		for (i = 0; dyn[i].d_tag != DT_NULL; i++) {
			switch(dyn[i].d_tag) {
			case DT_VERNEED:
				dyn[i].d_tag = DT_NULL;
				break;
			case DT_VERSYM:
				versym_addr = RUNTIME_BASE(dyn[i].d_un.d_ptr);
				(void )mprotect(versym_addr & ~4095, 8192, PROT_READ|PROT_WRITE|PROT_EXEC);
				dyn[i].d_tag = DT_NULL;
				dyn[i].d_un.d_ptr = (void *)0UL;
				vptr = (uint16_t *)versym_addr;
				if (elf_section_by_name(elfobj, ".gnu.version", &shdr) == false ) {
					fprintf(stderr, "elf_section_by_name() failed .gnu.version\n");
					return -1;
				}
				for (j = 0; j < (shdr.size / shdr.entsize) - 1; j++) {
					vptr[j] = 1;
				}
				break;
			case DT_VERNEEDNUM:
			case DT_VERDEF:
				dyn[i].d_tag = DT_NULL;
				dyn[i].d_un.d_ptr = (void *)0UL;
				break;
			default:
				break;
			}
		}
	}
	return 0;
}
