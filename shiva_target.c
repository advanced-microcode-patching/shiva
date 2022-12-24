/*
 * This source file contains code that tweak, alter, read and write
 * to the memory space of the executable target program.
 */
#include "shiva.h"

bool
shiva_target_has_prelinking(struct shiva_ctx *ctx)
{
	uint32_t magic = *(uint32_t *)&ctx->elfobj.mem[EI_PAD];

	if (magic == (uint32_t)SHIVA_SIGNATURE)
		return true;
	return false;
}

/*
 * Will copy a string from src address of binary.
 * Copies up to 4095 bytes of a string, leaving 1 byte for NULL terminator.
 */
bool
shiva_target_copy_string(struct shiva_ctx *ctx, char *dst, const char *src, size_t *len_out)
{
	elfobj_t *elfobj = &ctx->elfobj;
	int i;
	uint64_t byte;
	bool res;
	char *d = dst;

	for (i = 0 ;; i++) {
		res = elf_read_address(elfobj, (uint64_t)src + i, &byte, ELF_BYTE);
		if (res == false) {
			fprintf(stderr, "elf_read_address() failed at %lx\n", (uint64_t)src + i);
			return false;
		}
		*(d++) = byte;
		if (i >= PATH_MAX - 1)
			break;
		if (byte == 0)
			break;
	}
	*len_out = i - 1;
	return true;
}

/*
 * TODO: This function can cause an overflow on the second
 * shiva_target_copy_string() call. 
 */
bool
shiva_target_get_module_path(struct shiva_ctx *ctx, char *buf)
{
	uint64_t search_addr, basename_addr;
	char tmp[PATH_MAX];
	size_t len;
	bool res;

	if (shiva_target_dynamic_get(ctx, SHIVA_DT_SEARCH, &search_addr) == false) {
                fprintf(stderr, "shiva_target_dynamic_get(%p, SHIVA_DT_SEARCH, ...) failed\n",
                    ctx);
                return false;
        }
        if (shiva_target_dynamic_get(ctx, SHIVA_DT_NEEDED, &basename_addr) == false) {
                fprintf(stderr, "shiva_target_dynamic_get(%p, SHIVA_DT_NEEDED, ...) failed\n",
                    ctx);
                return false;
        }
	res = shiva_target_copy_string(ctx, tmp, (const char *)search_addr, &len);
        if (res == false) {
                fprintf(stderr, "shiva_target_copy_string() failed at %#lx\n", (uint64_t)search_addr);
                return false;
        }
	if (tmp[len] != '/' && len < 4095) {
		tmp[len + 1] = '/';
		len += 1;
	}
        res = shiva_target_copy_string(ctx, &tmp[len + 1], (const char *)basename_addr, &len);
        if (res == false) {
                fprintf(stderr, "shiva_target_copy_string() failed at %#lx\n", (uint64_t)basename_addr);
                return false;
        }
	strcpy(buf, tmp);
	return true;
}


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
                        shiva_debug("Get dynamic tag %d: %#lx\n", dyn[i].d_tag, dyn[i].d_un.d_val);
                        *out = dyn[i].d_un.d_val;
                        return true;
                }
        }
        return false;
}

