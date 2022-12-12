/*
 * This source file contains code that tweak, alter, read and write
 * to the memory space of the executable target program.
 */
#include "shiva.h"

/*
 * This function modifies the "live" dynamic segment in memory. It will modify
 * the first dynamic tag found of type 'tag' and change it to 'value'.
 */
bool
shiva_target_dynamic_set(struct shiva_ctx *ctx, uint64_t tag, uint64_t value)
{
	int i;
	uint64_t phdr_vaddr = ctx->ulexec.base_vaddr + elf_phoff(&ctx->elfobj);
	Elf64_Phdr *phdr = (Elf64_Phdr *)phdr_vaddr;
	Elf64_Dyn *dyn = NULL;

	for (i = 0; i < elf_segment_count(&ctx->elfobj); i++) {
		if (phdr[i].p_type != PT_DYNAMIC)
			continue;
		dyn = (Elf64_Dyn *)((uint64_t)(phdr[i].p_vaddr + ctx->ulexec.base_vaddr));
		break;
	}
	if (dyn == NULL) {
		fprintf(stderr, "shiva_target_dynamic_tag() failed, dyn == NULL\n");
		return false;
	}

	for (i = 0; dyn[i].d_tag != DT_NULL; i++) {
		if (dyn[i].d_tag == tag) {
			shiva_debug("Set dynamic tag %d: %#lx\n", dyn[i].d_tag, value);
			dyn[i].d_un.d_val = value;
			return true;
		}
	}
	return false;
}

bool
shiva_target_dynamic_get(struct shiva_ctx *ctx, uint64_t tag, uint64_t *out)
{
        int i;
        uint64_t phdr_vaddr = ctx->ulexec.base_vaddr + elf_phoff(&ctx->elfobj);
        Elf64_Phdr *phdr = (Elf64_Phdr *)phdr_vaddr;
        Elf64_Dyn *dyn = NULL;

        for (i = 0; i < elf_segment_count(&ctx->elfobj); i++) {
                if (phdr[i].p_type != PT_DYNAMIC)
                        continue;
                dyn = (Elf64_Dyn *)((uint64_t)(phdr[i].p_vaddr + ctx->ulexec.base_vaddr));
                break;
        }
        if (dyn == NULL) {
                fprintf(stderr, "shiva_target_dynamic_tag() failed, dyn == NULL\n");
                return false;
        }

        for (i = 0; dyn[i].d_tag != DT_NULL; i++) {
                if (dyn[i].d_tag == tag) {
                        shiva_debug("Get dynamic tag %d: %#lx\n", dyn[i].d_tag, value);
                        *out = dyn[i].d_un.d_val;
                        return true;
                }
        }
        return false;
}

