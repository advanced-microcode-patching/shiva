#include "shiva.h"
#include "shiva_debug.h"
#include "modules/include/shiva_module.h"
#include <sys/mman.h>

#define RELOC_MASK(n)	((1U << n) - 1)

/*
 * The purpose of this code is to take a relocatable object,
 * and turn it into a runtime executable module. This means
 * that we must organize SHF_ALLOC and SHF_ALLOC|SHF_ sections into the text
 * segment, and SHF_WRITE sections into the data segment.
 */

#ifdef __x86_64__
/*
 * Our custom PLT stubs are a simple IP relative indirect
 * JMP into the global offset table.
 * i.e. jmp *0x0(%rip)
 * NOTE: Our linker uses strict linking.
 */
uint8_t plt_stub[6] = "\xff\x25\x00\x00\x00\x00";
#elif __aarch64__
/*
 * Our PLT stub requires 8 bytes in ARM64 assembly.
 */
uint8_t plt_stub[8] = "\x11\x00\x00\x58"  /* ldr	x17, got_entry_mem */
		      "\x20\x02\x1f\xd6"; /* br x17			   */
#endif

static bool module_has_transforms(struct shiva_module *);
static bool get_section_mapping(struct shiva_module *, char *, struct shiva_module_section_mapping *);
static bool enable_post_linker(struct shiva_module *);
/*
 * Returns the name of the ELF section that the symbol lives in, within the
 * loaded ET_REL module.
 */
static char *
module_symbol_shndx_str(struct shiva_module *linker, struct elf_symbol *symbol)
{
	struct elf_section *section = shiva_malloc(sizeof(*section));
	uint16_t shndx = symbol->shndx;

	shiva_debug("SHNDX: %d\n", shndx);
	if (shndx == SHN_COMMON) {
		shiva_debug("Symbols SHN_COMMON, we will assume .bss data\n");
		return ".bss";
	}
	/*
	 * What section does our symbol live in?
	 */
	if (elf_section_by_index(&linker->elfobj, shndx, section)
	    == false)
		return NULL;
	return section->name;
}

static void
transfer_to_module(struct shiva_ctx *ctx, uint64_t entry)
{
	void (*fn)(void *arg) = (void (*)(void *))entry;

	return fn(ctx);
}
#ifdef __aarch64__
static bool
install_aarch64_call26_patch(struct shiva_ctx *ctx, struct shiva_module *linker,
    struct shiva_branch_site *e, struct elf_symbol *patch_symbol,
    struct shiva_transform *transform)
{
	/*
	 * The patch_symbol->value will be a symbol value found within the patch
	 * module, containing an offset into the text section which is the first
	 * section within a Shiva modules text segment.
	 */
	uint64_t target_vaddr = patch_symbol->value + linker->text_vaddr;
	uint32_t insn_bytes = e->o_insn;
	uint32_t call_offset;
	shiva_error_t error;
	bool res;

	shiva_debug("patch_symbol->value: %#lx\n", patch_symbol->value);
	shiva_debug("transform: %p\n", transform);
	/*
	 * In the event of a transform, we are re-linking the executable to a function
	 * that has been transformed with a splice, which requires that we don't use
	 * the patch_symbol.value (Since it will have been moved), instead we use the
	 * transform->segment_offset.
	 */
	target_vaddr = (transform == NULL) ? patch_symbol->value + linker->text_vaddr :
	    linker->text_vaddr + transform->segment_offset;

	shiva_debug("target_vaddr is %#lx\n", target_vaddr);
	if (transform == NULL) {
		if (module_has_transforms(linker) == true) {
			shiva_debug("Increasing target vaddr by %zu bytes\n", linker->tf_text_offset);
			target_vaddr += linker->tf_text_offset;
		} else {
			shiva_debug("Module has no transforms\n");
		}
	}

	shiva_debug("PATCHING BRANCH SITE: %#lx\n", e->branch_site);
	call_offset = (target_vaddr - ((e->branch_site + ctx->ulexec.base_vaddr))) >> 2;

	shiva_debug("target_vaddr: %#lx branch_site: %#lx\n",
	    target_vaddr, e->branch_site + ctx->ulexec.base_vaddr);
	shiva_debug("call_offset: %#lx encoded: %#lx\n", call_offset * 4, call_offset);
	shiva_debug("old insn_bytes: %#x\n", insn_bytes);

	insn_bytes = (insn_bytes & ~RELOC_MASK(26)) | (call_offset & RELOC_MASK(26));
	/*
	 * XXX
	 * Technically the shiva_trace API shouldn't be used from within Shiva.
	 * It's Akin to the Kernel invoking syscalls. Although atleast we aren't
	 * calling shiva_trace(), but rather one of it's utility functions for
	 * writing to memory. This won't cause any harm, but it's not congruent
	 * with the modeled use cases of Shiva trace API which is meant to be invoked
	 * by modules.
	 */
	res = shiva_trace_write(ctx, 0, (void *)e->branch_site + ctx->ulexec.base_vaddr,
	    (void *)&insn_bytes, 4, &error);
	if (res == false) {
		fprintf(stderr, "sihva_trace_write failed: %s\n", shiva_error_msg(&error));
		return false;
	}
	return true;
}
#elif __x86_64__
static bool
install_x86_64_call_imm_patch(struct shiva_ctx *ctx, struct shiva_module *linker,
    struct shiva_branch_site *e, struct elf_symbol *patch_symbol,
    struct shiva_transform *transform)
{
	/*
	 * The patch_symbol->value will be a symbol value found within the patch
	 * module, containing an offset into the text section which is the first
	 * section within a Shiva modules text segment.
	 */
	uint64_t target_vaddr = patch_symbol->value + linker->text_vaddr;
	uint8_t insn_bytes[SHIVA_MAX_INST_LEN];
	uint32_t call_offset;
	shiva_error_t error;
	bool res;

	shiva_debug("patch_symbol->value: %#lx\n", patch_symbol->value);
	shiva_debug("transform: %p\n", transform);
	/*
	 * In the event of a transform, we are re-linking the executable to a function
	 * that has been transformed with a splice, which requires that we don't use
	 * the patch_symbol.value (Since it will have been moved), instead we use the
	 * transform->segment_offset.
	 */
	target_vaddr = (transform == NULL) ? patch_symbol->value + linker->text_vaddr :
	    linker->text_vaddr + transform->segment_offset;

	shiva_debug("target_vaddr is %#lx\n", target_vaddr);
	if (transform == NULL) {
		if (module_has_transforms(linker) == true) {
			shiva_debug("Increasing target vaddr by %zu bytes\n", linker->tf_text_offset);
			target_vaddr += linker->tf_text_offset;
		} else {
			shiva_debug("Module has no transforms\n");
		}
	}

	shiva_debug("PATCHING BRANCH SITE: %#lx\n", e->branch_site);
	memcpy(&insn_bytes, &e->o_insn, sizeof(insn_bytes));
	shiva_debug("call_offset = %#lx - %#lx\n",
	    target_vaddr, e->branch_site + ctx->ulexec.base_vaddr);
	call_offset = (target_vaddr - (e->branch_site + ctx->ulexec.base_vaddr));
	call_offset -= 5; /* subtract length of call instruction */
	*(uint32_t *)&insn_bytes[1] = call_offset;
	/*
	 * XXX
	 * Technically the shiva_trace API shouldn't be used from within Shiva.
	 * It's Akin to the Kernel invoking syscalls. Although atleast we aren't
	 * calling shiva_trace(), but rather one of it's utility functions for
	 * writing to memory. This won't cause any harm, but it's not congruent
	 * with the modeled use cases of Shiva trace API which is meant to be invoked
	 * by modules.
	 */
	res = shiva_trace_write(ctx, 0, (void *)e->branch_site + ctx->ulexec.base_vaddr,
	    (void *)&insn_bytes, 5, &error);
	if (res == false) {
		fprintf(stderr, "sihva_trace_write failed: %s\n", shiva_error_msg(&error));
		return false;
	}
	return true;

}
#endif

#ifdef __x86_64__
static bool
install_x86_64_trampoline(struct shiva_ctx *ctx, struct shiva_module *linker,
    struct shiva_branch_site *e, struct elf_symbol *patch_symbol,
    struct shiva_transform *transform)
{
	uint64_t target_vaddr = patch_symbol->value + linker->text_vaddr;
	uint8_t trampcode[] = "\xe9\x00\x00\x00\x00";

	/*
	 * In the event of a transform, we are re-linking the executable to a function
	 * that has been transformed with a splice, which requires that we don't use
	 * the patch_symbol.value (Since it will have been moved), instead we use the
	 * transform->segment_offset.
	 */
	target_vaddr = (transform == NULL) ? patch_symbol->value + linker->text_vaddr :
	    linker->text_vaddr + transform->segment_offset;

	shiva_debug("target_vaddr is %#lx\n", target_vaddr);
	if (transform == NULL) {
		if (module_has_transforms(linker) == true) {
			shiva_debug("Increasing target vaddr by %zu bytes\n", linker->tf_text_offset);
			target_vaddr += linker->tf_text_offset;
		} else {
			shiva_debug("Module has no transforms\n");
		}
	}
	uint32_t tramp_offset = target_vaddr - (e->branch_site + linker->target_base) - 5;
	shiva_debug("Trampoline offset is %x\n", tramp_offset);
	*(uint32_t *)&trampcode[1] = tramp_offset;
	return true;
}
#endif
/*
 * XXX does not properly handle xrefs from target executable
 * to fully transformed function.
 * TODO
 */
#ifdef __aarch64__
static bool
install_aarch64_xref_patch(struct shiva_ctx *ctx, struct shiva_module *linker,
    struct shiva_xref_site *e, struct elf_symbol *patch_symbol)
{

	uint32_t n_adrp_insn;
	uint32_t n_add_insn;
	uint32_t n_ldr_insn;
	uint32_t n_str_insn;
	int32_t rel_val, xoffset;
	uint64_t rel_addr = e->adrp_site + ctx->ulexec.base_vaddr;
	uint64_t var_segment;
	uint8_t *rel_unit;
	struct elf_section shdr;
	struct shiva_module_section_mapping smap;
	shiva_error_t error;
	bool res;
	char *shdr_name = NULL;

	if (patch_symbol->shndx == SHN_COMMON) {
		shiva_debug("shndx == SHN_COMMON for var: %s. Assuming it's a .bss\n",
		    patch_symbol->name);
		shdr_name = ".bss";
	} else {
		if (elf_section_by_index(&linker->elfobj, patch_symbol->shndx, &shdr) == false) {
			fprintf(stderr, "Failed to find section index: %d in module: %s\n",
			    patch_symbol->shndx, elf_pathname(&linker->elfobj));
			return false;
		}
		shdr_name = shdr.name;
	}

	if (get_section_mapping(linker, shdr_name, &smap) == false) {
		fprintf(stderr, "Failed to retrieve section data for %s\n", shdr_name);
		return false;
	}

	switch(smap.map_attribute) {
	case LP_SECTION_TEXTSEGMENT:
		shiva_debug("VARSEGMENT(Text): %#lx\n", linker->text_vaddr);
		var_segment = linker->text_vaddr;
		break;
	case LP_SECTION_DATASEGMENT:
		shiva_debug("VARSEGMENT(Data): %#lx\n", linker->data_vaddr);
		var_segment = linker->data_vaddr;
		break;
	case LP_SECTION_BSS_SEGMENT:
		shiva_debug("VARSEGMENT(Bss): %#lx\n", linker->bss_vaddr);
		var_segment = linker->bss_vaddr;
		break;
	default:
		fprintf(stderr, "Unknown section attribute for '%s'\n", shdr_name);
		return false;
	}

	/*
	 * SHIVA_XREF_INDIRECT external linking patch
	 *
	 * An indirect XREF is an indirect access to a variable, 
	 * such as a .bss variable most commonly:
	 *
	 * adrp		x0, <segment_offset> ; get page aligned address of text + segment_offset
	 * ldr		x0, [x0, #pgoff] ; retrieve the address of the .bss variable from the .got
	 * ldr		w1, [x0] ; load the .bss variable from memory into w1
	 *
	 * The absolute address to the variable is computed at runtime via the R_AARCH64_RELATIVE
	 * relocations: base + addend
	 *
	 * Our solution is clean: 
	 * 1. locate the R_AARCH64_RELATIVE relocation who's r_addend is equal
	 * to the offset of the original .bss variable.
	 * 2. Calculate the offset of the new patch .bss variable from the base of the executable:
	 *	new_var_addr - executable_base - 4
	 * 3. Store the offset as the updated r_addend field in the relocation entry
	 *
	 * This is a great example of Cross relocation. Shiva is manipulating LDSO meta-data
	 * to influence the behavior of ld-linux.so. The ld-linux.so rtld will parse the
	 * R_AARCH64_RELATIVE relocations and apply the new offset for the patched version
	 * of the .bss variable.
	 *
	 * TODO: We are assuming that the indirection here is specifically related to
	 * a RELATIVE relocation. !!! In the future we should check to see whether the offset/address
	 * of this xref instruction exists as an r_offset within the .rela.dyn section and if it
	 * does check to see what it's relocation type is, it could be R_GLOB_DAT, R_COPY , etc.
	 */
	if (e->flags & SHIVA_XREF_F_INDIRECT) {
		int i;
		Elf64_Rela *rela;
		size_t relasz;
		uint64_t rela_ptr;
		uint64_t var_addr = patch_symbol->value + var_segment;

		e->got = (uint64_t *)((uint64_t)e->got + ctx->ulexec.base_vaddr);

		if (shiva_target_dynamic_get(ctx, DT_RELASZ, &relasz) == false) {
			fprintf(stderr, "shiva_target_dynamic_get(%p, DT_RELASZ, ...) failed\n",
			    ctx);
			return false;
		}

		if (shiva_target_dynamic_get(ctx, DT_RELA, &rela_ptr) == false) {
			fprintf(stderr, "shiva_target_dynamic_set(%p, DT_RELA, ...) failed\n",
			    ctx);
			return false;
		}
		rela_ptr += ctx->ulexec.base_vaddr;
		rela = (void *)rela_ptr;
		for (i = 0; i < relasz / sizeof(Elf64_Rela); i++) {
			if (rela[i].r_addend == *(e->got)) {
				uint64_t relval = var_addr - ctx->ulexec.base_vaddr - 4;

				shiva_debug("Found RELATIVE rela.dyn relocation entry for %s\n",
				    patch_symbol->name);
				shiva_debug("Patching rela[%d].r_addend with %#lx\n", i, relval);
				res = shiva_trace_write(ctx, 0, (void *)&rela[i].r_addend, (void *)&relval,
				    8, &error);
				if (res == false) {
					fprintf(stderr, "shiva_trace_write failed: %s\n",
					    shiva_error_msg(&error));
					return false;
				}
				/*
				 * XXX - We do not support ELF32 at the moment, but if we did
				 * the Elf32_Rel doesn't contain an r_addend field. The rtld
				 * retrieves it from the relocation unit. We overwrite the
				 * addend (Pointed to by e->got) with the correct offset to
				 * the global object (the symbol), i.e. a variable in the .bss.
				 * This call to shiva_trace_write() isn't necessary on 64bit.
				 */
				res = shiva_trace_write(ctx, 0, (void *)e->got, (void *)&relval,
				    8, &error);
				if (res == false) {
					fprintf(stderr, "shiva_trace_write failed: %s\n",
					    shiva_error_msg(&error));
					return false;
				}
			}
		}
		return true;
	}

	shiva_debug("var_segment: %#lx base_vaddr: %#lx\n", var_segment, ctx->ulexec.base_vaddr);
	xoffset = rel_val = (int32_t)(ELF_PAGESTART(patch_symbol->value + var_segment) - ELF_PAGESTART(rel_addr));
	rel_val >>= 12;

	n_adrp_insn = e->adrp_o_insn & 0xffffffff;
	n_adrp_insn = (n_adrp_insn & ~((RELOC_MASK (2) << 29) | (RELOC_MASK(19) << 5)))
	    | ((rel_val & RELOC_MASK(2)) << 29) | ((rel_val & (RELOC_MASK(19) << 2)) << 3);

	switch(e->type) {
	case SHIVA_XREF_TYPE_UNKNOWN:
		return false;
	case SHIVA_XREF_TYPE_ADRP_ADD:
		rel_unit = (uint8_t *)e->adrp_site + ctx->ulexec.base_vaddr; // address of unit we are patching in target ELF executable
		shiva_debug("Installing SHIVA_XREF_TYPE_ADRP_ADD patch at %#lx\n", e->adrp_site + ctx->ulexec.base_vaddr);
		res = shiva_trace_write(ctx, 0, (void *)rel_unit,
		    (void *)&n_adrp_insn, 4, &error);
		if (res == false) {
			fprintf(stderr, "shiva_trace_write failed: %s\n", shiva_error_msg(&error));
			return false;
		}
		rel_val = patch_symbol->value;
		shiva_debug("Add offset: %#lx\n", rel_val);
		n_add_insn = e->next_o_insn;
		n_add_insn = (n_add_insn & ~(RELOC_MASK(12) << 10)) | ((rel_val & RELOC_MASK(12)) << 10);

		rel_unit += sizeof(uint32_t);
		res = shiva_trace_write(ctx, 0, (void *)rel_unit,
		    (void *)&n_add_insn, 4, &error);
		if (res == false) {
			fprintf(stderr, "shiva_trace_write failed: %s\n", shiva_error_msg(&error));
			return false;
		}
		break;
	case SHIVA_XREF_TYPE_ADRP_LDR:
		rel_unit = (uint8_t *)e->adrp_site + ctx->ulexec.base_vaddr;
		rel_val = patch_symbol->value;
		shiva_debug("Installing SHIVA_XREF_TYPE_ADRP_LDR patch at %#lx\n",
		    e->adrp_site + ctx->ulexec.base_vaddr);
		shiva_debug("SHIVA_XREF_TYPE_ADRP_LDR not yet supported\n");
		assert(true);
		break;
	}
	return true;

}
#elif __x86_64__
static bool
install_x86_64_xref_patch(struct shiva_ctx *ctx, struct shiva_module *linker,
    struct shiva_xref_site *e, struct elf_symbol *patch_symbol)
{
	uint64_t rel_addr = e->rip_rel_site + ctx->ulexec.base_vaddr;
	uint64_t var_segment, rel_val;
	uint8_t *rel_unit;
	struct elf_section shdr;
	struct shiva_module_section_mapping smap;
	shiva_error_t error;
	bool res;
	char *shdr_name = NULL;

	if (patch_symbol->shndx == SHN_COMMON) {
		shiva_debug("shndx == SHN_COMMON for var: %s. Assuming it's a .bss\n",
		    patch_symbol->name);
		shdr_name = ".bss";
	} else {
		if (elf_section_by_index(&linker->elfobj, patch_symbol->shndx, &shdr) == false) {
			fprintf(stderr, "Failed to find section index: %d in module: %s\n",
			    patch_symbol->shndx, elf_pathname(&linker->elfobj));
			return false;
		}
		shdr_name = shdr.name;
	}

	if (get_section_mapping(linker, shdr_name, &smap) == false) {
		fprintf(stderr, "Failed to retrieve section data for %s\n", shdr_name);
		return false;
	}

	switch(smap.map_attribute) {
	case LP_SECTION_TEXTSEGMENT:
		shiva_debug("VARSEGMENT(Text): %#lx\n", linker->text_vaddr);
		var_segment = linker->text_vaddr;
		break;
	case LP_SECTION_DATASEGMENT:
		shiva_debug("VARSEGMENT(Data): %#lx\n", linker->data_vaddr);
		var_segment = linker->data_vaddr;
		break;
	case LP_SECTION_BSS_SEGMENT:
		shiva_debug("VARSEGMENT(Bss): %#lx\n", linker->bss_vaddr);
		var_segment = linker->bss_vaddr;
		break;
	default:
		fprintf(stderr, "Unknown section attribute for '%s'\n", shdr_name);
		return false;
	}

	if (e->flags & SHIVA_XREF_F_INDIRECT) {
		int i;
		Elf64_Rela *rela;
		size_t relasz;
		uint64_t rela_ptr;
		uint64_t var_addr = patch_symbol->value + var_segment;

		e->got = (uint64_t *)((uint64_t)e->got + ctx->ulexec.base_vaddr);

		if (shiva_target_dynamic_get(ctx, DT_RELASZ, &relasz) == false) {
			fprintf(stderr, "shiva_target_dynamic_get(%p, DT_RELASZ, ...) failed\n",
			    ctx);
			return false;
		}

		if (shiva_target_dynamic_get(ctx, DT_RELA, &rela_ptr) == false) {
			fprintf(stderr, "shiva_target_dynamic_set(%p, DT_RELA, ...) failed\n",
			    ctx);
			return false;
		}
		rela_ptr += ctx->ulexec.base_vaddr;
		rela = (void *)rela_ptr;
		shiva_debug("Iterating over target ELF executable's relocation entries\n");
		for (i = 0; i < relasz / sizeof(Elf64_Rela); i++) {
			shiva_debug("Reloc type: %d\n", e->reloc_type);
			switch(e->reloc_type) {
			case R_X86_64_RELATIVE:
				shiva_debug("Relative relocation found, r_addend: %#lx *got: %#lx\n", rela[i].r_addend, *(e->got));
				if (rela[i].r_addend == *(e->got)) {
					uint64_t relval = var_addr - ctx->ulexec.base_vaddr;

					shiva_debug("Found RELATIVE rela.dyn relocation entry for %s\n",
					    patch_symbol->name);
					shiva_debug("Patching rela[%d].r_addend with %#lx\n", i, relval);
					res = shiva_trace_write(ctx, 0, (void *)&rela[i].r_addend, (void *)&relval,
					    8, &error);
					 if (res == false) {
						fprintf(stderr, "shiva_trace_write failed: %s\n",
						    shiva_error_msg(&error));
						return false;
					}
					return true;
				}
				break;
			case R_X86_64_COPY:
				fprintf(stderr, "Shiva does not yet support cross relocations for R_X86_64_COPY\n");
				return false;
			case R_X86_64_GLOB_DAT:
				fprintf(stderr, "Shiva does not yet support cross relocations for R_X86_64_GLOB_DAT\n");
				return false;
			}
		}
		return true;
	}
	rel_val = patch_symbol->value + var_segment - rel_addr;
	rel_unit = (uint8_t *)rel_addr + 3;

	switch(e->type) {
	case SHIVA_XREF_TYPE_IP_RELATIVE_LEA:
		rel_unit = (uint8_t *)rel_addr + 3;
		rel_val = (patch_symbol->value + var_segment) - rel_addr - 7;
		res = shiva_trace_write(ctx, 0, (void *)rel_unit, (void *)&rel_val, 4, &error);
		if (res == false) {
			fprintf(stderr, "shiva_trace_write() failed: %s\n", shiva_error_msg(&error));
			return false;
		}
		break;
	case SHIVA_XREF_TYPE_IP_RELATIVE_MOV_LDR:
	case SHIVA_XREF_TYPE_IP_RELATIVE_MOV_STR:
		if (e->addr_size == 8) {
			rel_unit = (uint8_t *)rel_addr + 3;
			rel_val = (patch_symbol->value + var_segment) - rel_addr - 7;
			res = shiva_trace_write(ctx, 0, (void *)rel_unit, (void *)&rel_val, 4, &error);
			if (res == false) {
				fprintf(stderr, "shiva_trace_write() failed: %s\n", shiva_error_msg(&error));
				return false;
			}
		} else if (e->addr_size == 4) {
			rel_unit = (uint8_t *)rel_addr + 2;
			rel_val = (patch_symbol->value + var_segment) - rel_addr - 6;
			res = shiva_trace_write(ctx, 0, (void *)rel_unit, (void *)&rel_val, 4, &error);
			if (res == false) {
				fprintf(stderr, "shiva_trace_write() failed: %s\n", shiva_error_msg(&error));
				return false;
			}
		}
		break;
	}
	return true;
}

#endif

static bool
install_plt_redirect(struct shiva_ctx *ctx, struct shiva_module *linker,
    struct shiva_branch_site *b, struct elf_symbol *patch_symbol)
{
	uint64_t target_vaddr = patch_symbol->value + linker->text_vaddr;
	uint8_t trampcode[] = "\xe9\x00\x00\x00\x00";
	shiva_error_t trace_error;

        /*
         * In the event of a transform, we are re-linking the executable to a function
         * that has been transformed with a splice, which requires that we don't use
         * the patch_symbol.value (Since it will have been moved), instead we use the
         * transform->segment_offset.
         */
        target_vaddr = patch_symbol->value + linker->text_vaddr;
        uint32_t tramp_offset = target_vaddr - (b->branch_site + linker->target_base) - 5;
        shiva_debug("Trampoline offset is %x\n", tramp_offset);
	if (shiva_trace_write(ctx, 0, (void *)(uint8_t *)&trampcode[1], &tramp_offset,
	    sizeof(uint32_t), &trace_error) == false) {
		fprintf(stderr, "shiva_trace_write() failed to write at %p\n", &trampcode[1]);
		return false;
	}
        *(uint32_t *)&trampcode[1] = tramp_offset;
        return true;
}

/*
 * The following function takes care of installing linkage into the ELF executable
 * itself so that it is properly linked to the patch code and data that lives
 * within the patches text and data segment respectively.
 */
static bool
apply_external_patch_links(struct shiva_ctx *ctx, struct shiva_module *linker)
{
	struct shiva_transform *transform = NULL;
	struct shiva_transform *tfptr = NULL;
	shiva_callsite_iterator_t callsites;
	struct shiva_branch_site be, *branch;
	shiva_xref_iterator_t xrefs;
	struct shiva_xref_site xe;
	shiva_iterator_res_t ires;
	struct elf_symbol symbol;
	bool res;
	const char *symname = NULL;
	char tmp_buf[PATH_MAX];

	shiva_callsite_iterator_init(ctx, &callsites);
	while (shiva_callsite_iterator_next(&callsites, &be) == SHIVA_ITER_OK) {
		if (be.branch_flags & SHIVA_BRANCH_F_PLTCALL) {
			char *p = strchr(be.symbol.name, '@');

			strncpy(tmp_buf, be.symbol.name, p - be.symbol.name);
			tmp_buf[PATH_MAX - 1] = '\0';
			symname = tmp_buf;
			/*
			 * NOTE: Use elf_plt functions here instead perhaps?
			 */
			shiva_debug("Looking up PLT symbol: %s\n", symname);
			if (elf_symbol_by_name(&linker->elfobj, symname, &symbol) == true) {
				if (symbol.type != STT_FUNC || symbol.bind != STB_GLOBAL)
					continue;
				shiva_debug("Calling install_plt_redirect to relink %s to patch at %#lx\n",
				    be.symbol.name, symbol.value + linker->text_vaddr);
				res = install_plt_redirect(ctx, linker, &be, &symbol);
				if (res == false) {
					fprintf(stderr, "install_plt_redirect() failed\n");
					return false;
				}
			}
			continue;
		}
		/*
		 * The callsites were found early on in shiva_analyze.c and
		 * contain every branch instruction within the target ELF.
		 */

		/*
		 * Check the patch object file (Represented by &linker->elfobj) to see
		 * if it contains the same function name within it as the one originally
		 * being called. If so then we relink this call instruction to point to
		 * our new relocated function.
		 *
		 * If transformations are involved, then any calls from say main() to
		 * foo(), are relinked to a newly created version of foo with spliced in
		 * patch code. This source transform function will be called:
		 * __shiva_splice_fn_name_foo() in the patch object. So we must search
		 * for it by the correct name.
		 */
		shiva_debug("tfptr: %p\n", tfptr);
		shiva_debug("Callsite %#lx branches to %#lx\n",
		    be.branch_site, be.target_vaddr);
		symname = be.symbol.name;
		if (module_has_transforms(linker) == true) {
			TAILQ_FOREACH(transform, &linker->tailq.transform_list, _linkage) {
				switch(transform->type) {
				case SHIVA_TRANSFORM_SPLICE_FUNCTION:
					shiva_debug("Comparing %s and %s\n",
					    transform->source_symbol.name +
					    strlen(SHIVA_T_SPLICE_FUNC_ID), be.symbol.name);
					if (strcmp(transform->source_symbol.name +
					    strlen(SHIVA_T_SPLICE_FUNC_ID), be.symbol.name) == 0) {
						symname = transform->source_symbol.name;
						shiva_debug("Transform source found: %s\n", symname);
						tfptr = transform;
					}
					break;
				default:
					break;
				}
			}
		}
		shiva_debug("Looking up symname: %s\n", symname);
		if (elf_symbol_by_name(&linker->elfobj, symname,
		    &symbol) == true) {
			if (symbol.type != STT_FUNC ||
			    symbol.bind != STB_GLOBAL)
				continue;
#if __aarch64__
			shiva_debug("Installing patch offset on target at %#lx for %s. Transform: %p\n",
			    be.branch_site + ctx->ulexec.base_vaddr, symbol.name, tfptr);
			res = install_aarch64_call26_patch(ctx, linker, &be, &symbol, tfptr);
			if (res == false) {
				fprintf(stderr, "external linkage failure: "
				    "install_aarch64_call26_patch() failed\n");
				return false;
			}
#elif __x86_64__
			shiva_debug("Installing patch offset on target at %#lx for %s. Transform: %p\n",
			    be.branch_site + ctx->ulexec.base_vaddr, symbol.name, tfptr);
			res = install_x86_64_call_imm_patch(ctx, linker, &be, &symbol, tfptr);
			if (res == false) {
				fprintf(stderr, "external linkage failure: "
				    "install_x86_64_call_imm_patch() failed\n");
				return false;
			}

#endif
		}
		tfptr = NULL;
	}

	shiva_debug("Calling shiva_xref_iterator_init\n");
	shiva_xref_iterator_init(ctx, &xrefs);

	shiva_debug("iterating over xrefs\n");
#ifdef __aarch64__
	while (shiva_xref_iterator_next(&xrefs, &xe) == SHIVA_ITER_OK) {
		switch(xe.type) {
		case SHIVA_XREF_TYPE_UNKNOWN:
			fprintf(stderr, "External linkage failure: "
			    "Discovered unknown XREF insn-sequence at %#lx\n",
			    xe.adrp_site);
			return false;
		case SHIVA_XREF_TYPE_ADRP_LDR:
		case SHIVA_XREF_TYPE_ADRP_STR:
		case SHIVA_XREF_TYPE_ADRP_ADD:
			shiva_debug("Found %s XREF at %#lx for %s\n",
			   (xe.flags & SHIVA_XREF_F_INDIRECT) ? "indirect" : "", xe.adrp_site, xe.symbol.name);
			if (elf_symbol_by_name(&linker->elfobj,
			    (xe.flags & SHIVA_XREF_F_INDIRECT) ? xe.deref_symbol.name : xe.symbol.name,
			    &symbol) == true) {
				shiva_debug("Found symbol for %s\n", xe.symbol.name);
				if (symbol.type != STT_OBJECT ||
				    symbol.bind != STB_GLOBAL)
					continue;
				shiva_debug("Installing xref patch at %#lx for symbol %s\n",
				    xe.adrp_site, xe.symbol.name);
				res = install_aarch64_xref_patch(ctx, linker, &xe, &symbol);
				if (res == false) {
					fprintf(stderr, "install_aarch64_xref_patch() for '%s' failed\n",
					    symbol.name);
					return false;
				}
			}
			break;
		default:
			break;
		}
	}
#elif __x86_64__
	while (shiva_xref_iterator_next(&xrefs, &xe) == SHIVA_ITER_OK) {
		switch(xe.type) {
		case SHIVA_XREF_TYPE_UNKNOWN:
			fprintf(stderr, "External linkage failure: "
			    "Discovered unknown XREF insn-sequence at %#lx\n",
			    xe.rip_rel_site);
			return false;
		case SHIVA_XREF_TYPE_IP_RELATIVE_LEA:
		case SHIVA_XREF_TYPE_IP_RELATIVE_MOV_LDR:
		case SHIVA_XREF_TYPE_IP_RELATIVE_MOV_STR:
			shiva_debug("Found %s XREF at %#lx for %s\n",
			    (xe.flags & SHIVA_XREF_F_INDIRECT) ? "indirect" : "", xe.rip_rel_site, xe.symbol.name);
			if (elf_symbol_by_name(&linker->elfobj,
			    (xe.flags & SHIVA_XREF_F_INDIRECT) ? xe.deref_symbol.name : xe.symbol.name,
			    &symbol) == true) {
				shiva_debug("Found symbol for %s\n", xe.symbol.name);
				if (symbol.type != STT_OBJECT ||
				    symbol.bind != STB_GLOBAL)
					continue;
				shiva_debug("Installing xref patch at %#lx for symbol %s\n",
				    xe.rip_rel_site, xe.symbol.name);
				res = install_x86_64_xref_patch(ctx, linker, &xe, &symbol);
				if (res == false) {
					fprintf(stderr, "install_aarch64_xref_patch() for '%s' failed\n",
					    symbol.name);
					return false;
				}
			}
		}
	}
#endif
	return true;
}
/*
 * Module entry point. Lookup symbol "shakti_main"
 */
static bool
module_entrypoint(struct shiva_module *linker, uint64_t *entry)
{
	struct elf_symbol symbol;

	if (elf_symbol_by_name(&linker->elfobj, "shakti_main", &symbol) == false) {
		shiva_debug("elf_symbol_by_name failed to find 'shakti_main'\n");
		return false;
	}
	shiva_debug("Module text: %#lx\n", linker->text_vaddr);
	*entry = linker->text_vaddr + symbol.value;
	return true;
}

static bool
got_entry_by_name(struct shiva_module *linker, char *name, struct shiva_module_got_entry *out)
{
	struct shiva_module_got_entry *got_entry;

	TAILQ_FOREACH(got_entry, &linker->tailq.got_list, _linkage) {
		if (strcmp(got_entry->symname, name) == 0) {
			memcpy(out, got_entry, sizeof(*out));
			return true;
		}
	}
	return false;
}

/*
 * Shiva Module's have a .got.plt section at the end
 * of the data segment in memory.
 * 
 * "Shiva Module layout"
 * [text segment]: 0x8000000 (.text, .rodata)
 * [data segment]: 0x9000000 (.data, .got, .bss)
 *
 * We patch the .got with the correct address to
 * either a libc function (That is resolved to
 * the musl-libc within the Shiva executable) or
 * a function native to the Shiva module itself.
 */
static bool
resolve_pltgot_entries(struct shiva_module *linker)
{
	uint64_t gotaddr, so_base;
	uint64_t *GOT;
	struct shiva_module_got_entry *current;
	char *so_path;
	bool res;

	/*
	 * Order of symbol resolution:
	 * 1. Resolve symbol from local Shiva module (i.e. patch.o)
	 * 2. Resolve symbol from target executable
	 * 3. Resolve symbol from targets shared library dependencies.
	 */
	gotaddr = linker->data_vaddr + linker->pltgot_off;
	TAILQ_FOREACH(current, &linker->tailq.got_list, _linkage) {
		struct elf_symbol symbol;

		/*
		 * Setup the modules internal GOT table.
		 */
		GOT = (uint64_t *)((uint64_t)(linker->data_vaddr + linker->pltgot_off + current->gotoff));
		shiva_debug("Processing GOT[%s](%#lx)\n", current->symname, (uint64_t)GOT);
		/*
		 * First look for the functions symbol within the loaded Shiva module
		 */
		if (elf_symbol_by_name(&linker->elfobj, current->symname, &symbol) == true) {
			/*
			 * TODO: investigate why we are accepting STT_OBJECT here. This is our
			 * PLT/GOT for the Shiva module. Should only be function calls in this
			 * part of the GOT, I think... Could cause a bug.
			 */
			if (symbol.type == STT_FUNC || symbol.type == STT_OBJECT) {
				shiva_debug("Setting [%#lx] GOT entry '%s' to %#lx\n",
				    linker->data_vaddr + linker->pltgot_off +
				    current->gotoff, current->symname, symbol.value + linker->text_vaddr +
				    (module_has_transforms(linker) == true ? linker->tf_text_offset : 0));
				*GOT = symbol.value + linker->text_vaddr +
				    (module_has_transforms(linker) == true ? linker->tf_text_offset : 0);
				shiva_debug("*GOT = %#lx (Address within Shiva module)\n", *GOT);
				continue;
			}
		}
		/*
		 * If the PLTGOT entry doesn't point to a symbol within the Shiva module
		 * itself, then let's check to see if we find it in the target executable.
		 * Only applicable if linking mode is set: SHIVA_LINKING_MICROCODE_PATCH
		 */
		if (linker->mode == SHIVA_LINKING_MICROCODE_PATCH) {
			bool in_target = false;
			struct elf_plt plt_entry;
			struct shiva_module_delayed_reloc *delay_rel;
			ENTRY e, *ep;

			e.key = current->symname;
			e.data = NULL;

			/*
			 * Handle the special case of SHIVA_HELPER_CALL_EXTERNAL()
			 * macro. Symbols are in the patch object, but give Shiva
			 * descriptive information about resolving an external symbol
			 * within the target. See SHIVA HELPER macros in documentation.
			 */
			shiva_debug("Searching cache for %s\n", current->symname);
			if (hsearch_r(e, FIND, &ep, &linker->cache.helpers) != 0) {
				char *real_symname;
				/*
				 * We are dealing with a helper symbol that denotes that
				 * we need to resolve the GOT entry with the value of the
				 * external version of a given symbol. See SHIVA_HELPER macros
				 * in documentation.
				 */
				real_symname = strstr(symbol.name, "_orig_func_");
				real_symname += strlen("_orig_func_");

				shiva_debug("Looking up symbol: '%s' in target\n", real_symname);
				if (elf_symbol_by_name(linker->target_elfobj, real_symname,
				    &symbol) == true) {
					if (symbol.value == 0 || symbol.type != STT_FUNC) {
						fprintf(stderr, "external symbol is invalid: %s\n",
						    symbol.name);
						return false;
					}
					shiva_debug("Resolving helper function '%s' to external symbol '%s'"
					    " = %#lx\n", symbol.name, real_symname,
					    symbol.value + linker->target_base);
					*(uint64_t *)GOT = symbol.value + linker->target_base;
					continue;
				}
			}
			/*
			 * Next we handle all other cases
			 */
			shiva_debug("Looking up symbol '%s' in target %s\n", current->symname,
			    elf_pathname(linker->target_elfobj));
			if (elf_symbol_by_name(linker->target_elfobj, current->symname,
			    &symbol) == true) {
				if (symbol.value == 0 && symbol.type == STT_FUNC) {
					if (elf_plt_by_name(linker->target_elfobj,
					    symbol.name, &plt_entry) == true) {
						struct elf_symbol tmp;
						char path_out[PATH_MAX];

						shiva_debug("Symbol '%s' is a PLT entry, let's look it up in the shared libraries\n",
						    symbol.name);
						res = shiva_so_resolve_symbol(linker, (char *)symbol.name, &tmp, &so_path);
						if (res == false) {
							fprintf(stderr, "Failed to resolve symbol '%s' in shared libs\n",
							    symbol.name);
							return false;
						}
						if (realpath(so_path, path_out) == NULL) {
							perror("realpath");
							return false;
						}
						delay_rel = shiva_malloc(sizeof(*delay_rel));
						delay_rel->rel_unit = (uint8_t *)GOT;
						delay_rel->rel_addr = (uint64_t)GOT;
						delay_rel->symval = tmp.value;
						delay_rel->symname = shiva_strdup(symbol.name);
						strncpy(delay_rel->so_path, path_out, PATH_MAX);
						delay_rel->so_path[PATH_MAX - 1] = '\0';
						shiva_debug("Delayed relocation for GOT[%s] -> lookup %s\n",
						    symbol.name, delay_rel->so_path);
						/*
						 * We don't fill out the value of the GOT. The shared library
						 * whom the symbol lives in hasn't even been loaded by the
						 * ld-linux.so yes. Once ld-linux.so is finished it will pass
						 * control to shiva_post_linker() function once the base address
						 * can be known of the library. We must insert a delayed relocation
						 * entry.
						 */
						if (enable_post_linker(linker) == false) {
							fprintf(stderr, "failed to enable delayed relocs\n");
							return false;
						}
						TAILQ_INSERT_TAIL(&linker->tailq.delayed_reloc_list, delay_rel, _linkage);
					} else {
						fprintf(stderr, "Undefined linking behavior: No PLT entry for STT_FUNC '%s' with zero value\n",
						    symbol.name);
						return false;
					}
				} else if (symbol.value > 0 && symbol.type == STT_FUNC) {
					shiva_debug("resolved symbol in target: %s\n", elf_pathname(linker->target_elfobj));
					*(uint64_t *)GOT = symbol.value + linker->target_base;
				}
			} else {
				/*
				 * The symbol isn't in the target ELF exectutable, or in the Shiva
				 * module. Let's try resolving it from the shared library dependencies
				 * listed in the targets dynamic segment.
				 */
				struct elf_symbol tmp;
				char path_out[PATH_MAX];

				res = shiva_so_resolve_symbol(linker, (char *)symbol.name, &tmp, &so_path);
				if (res == false) {
					fprintf(stderr, "Failed to resolve symbol '%s' in shared libs\n",
					    symbol.name);
					return false;
				}
				if (realpath(so_path, path_out) == NULL) {
					perror("realpath");
					return false;
				}
				delay_rel = shiva_malloc(sizeof(*delay_rel));
				delay_rel->rel_unit = (uint8_t *)GOT;
				delay_rel->rel_addr = (uint64_t)GOT;
				delay_rel->symval = tmp.value;
				delay_rel->symname = shiva_strdup(symbol.name);
				strncpy(delay_rel->so_path, path_out, PATH_MAX);
				delay_rel->so_path[PATH_MAX - 1] = '\0';
				shiva_debug("Delayed relocation for GOT[%s] -> lookup %s\n",
				    symbol.name, delay_rel->so_path);
				/*
				 * We don't fill out the value of the GOT. The shared library
				 * whom the symbol lives in hasn't even been loaded by the
				 * ld-linux.so yes. Once ld-linux.so is finished it will pass
				 * control to shiva_post_linker() function once the base address
				 * can be known of the library. We must insert a delayed relocation
				 * entry.
				 */
				 if (enable_post_linker(linker) == false) {
					fprintf(stderr, "failed to enable delayed relocs\n");
					return false;
				}
				TAILQ_INSERT_TAIL(&linker->tailq.delayed_reloc_list, delay_rel, _linkage);
				continue;
			}
			/*
			 * This next condition only exists on x86_64 currently anyway.
			 * We may remove linker->mode from the AMP version of Shiva
			 * and start erraticating old linking styles that are still
			 * important, but not so much to AMP. Although I think it could
			 * be?
			 */
		} else if (linker->mode == SHIVA_LINKING_MODULE) {
			if (elf_symbol_by_name(&linker->self, current->symname, &symbol) == false) {
				fprintf(stderr, "Could not resolve symbol '%s'. Linkage failure!\n",
				    current->symname);
				return false;
			}
			*(uint64_t *)GOT = symbol.value;
			shiva_debug("Found symbol '%s':%#lx within the Shiva API\n", current->symname,
			    symbol.value);
		} else {
			fprintf(stderr, " Undefined linking behavior\n");
			shiva_debug("undefined linking behavior\n");
			return false;
		}
	}
	return true;
}

static bool
patch_plt_stubs(struct shiva_module *linker)
{
	size_t i = 0;
	struct shiva_module_plt_entry *current;
	uint8_t *stub;
	uint64_t gotaddr, pltaddr, gotoff;

	TAILQ_FOREACH(current, &linker->tailq.plt_list, _linkage) {
		struct shiva_module_got_entry got_entry;

		if (got_entry_by_name(linker, current->symname, &got_entry) == false) {
			fprintf(stderr, "Unable to find GOT entry for '%s'\n", current->symname);
			return false;
		}

		stub = &linker->text_mem[linker->plt_off + i * sizeof(plt_stub)];
		gotaddr = linker->data_vaddr + linker->pltgot_off + got_entry.gotoff;
		pltaddr = linker->text_vaddr + (linker->plt_off + i * sizeof(plt_stub));
		gotoff = gotaddr - pltaddr - sizeof(plt_stub);
#ifdef __x86_64__
		*(uint32_t *)&stub[2] = gotoff;
#elif __aarch64__
		shiva_debug("got_addr: %#lx\n", gotaddr);
		uint32_t rval = ((gotaddr - pltaddr) >> 2);
		uint32_t insn_bytes = *(uint32_t *)&stub[0];
		insn_bytes = (insn_bytes & ~(RELOC_MASK(19) << 5)) | ((rval & RELOC_MASK(19)) << 5);
		*(uint32_t *)&stub[0] = insn_bytes;
#endif
		i++;
		shiva_debug("SYMNAME: %s PLTADDR: %#lx GOTADDR: %#lx GOTOFF: %#lx\n", current->symname, pltaddr, gotaddr, gotoff);
		shiva_debug("Fixedup PLT stub with GOT offset: %#lx\n", gotoff);
	}
	return true;
}

static bool
get_section_mapping(struct shiva_module *linker, char *shdrname, struct shiva_module_section_mapping *smap)
{
	struct shiva_module_section_mapping *current;

	TAILQ_FOREACH(current, &linker->tailq.section_maplist, _linkage) {
		if (strcmp(shdrname, current->name) != 0)
			continue;
		memcpy(smap, current, sizeof(*smap));
		return true;
	}
	return false;
}

/*
 * An STT_NOTYPE symbol was found within the Shiva module;
 * This must be an external reference to a symbol. Search order:
 * 1. Check target executable for symbol.
 * 2. Check target executable's dependencies (DT_NEEDED) for symbol.
 */
#define RESOLVER_TARGET_SHIVA_SELF 0
#define RESOLVER_TARGET_EXECUTABLE 1
#define RESOLVER_TARGET_SO_RESOLVE 2
static bool
internal_symresolve(struct shiva_module *linker, char *symname,
    struct elf_symbol *symbol, uint64_t *e_type, uint64_t *type, char *path_out)
{
	struct elf_symbol tmp;
	struct elfobj *elfobj = linker->mode == SHIVA_LINKING_MODULE ?
	    &linker->self : linker->target_elfobj;
	bool res;

	shiva_debug("Looking up symbol %s in %s\n", symname, linker->mode ==
	    SHIVA_LINKING_MODULE ? "the Shiva Interpreter" : "target ELF executable");

	res = elf_symbol_by_name(elfobj, symname, &tmp);
	*e_type = elf_type(elfobj);
	if (res == true) {
		switch(tmp.type) {
		case STT_NOTYPE:
			/*
			 * XXX this NOTYPE case is somewhat undefined. We're looking for a symbol
			 * that was STT_NOTYPE in the Shiva patch, and so we search externally for
			 * it, and it is again STT_NOTYPE. I think we might only hit this case
			 * by random. Temporarily commenting this code out, I'm pretty sure this
			 * is an invalid ELF linking path to take.
			 */
			shiva_debug("Found symbol '%s' in target, but it's NOTYPE\n", symname);
			shiva_debug("Undefined linking behavior\n");
			return false;
		case STT_FUNC:
		case STT_OBJECT:
			shiva_debug("Found symbol '%s' in %s\n", symname, linker->mode == SHIVA_LINKING_MODULE ?
			    "shiva binary" : "target binary");
			if (linker->mode == SHIVA_LINKING_MODULE) {
				*type = RESOLVER_TARGET_SHIVA_SELF;
			} else {
				*type = RESOLVER_TARGET_EXECUTABLE;
			}
			memcpy(symbol, &tmp, sizeof(*symbol));
			return true;
		default:
			return false;
		}
	} else if (res == false && linker->mode == SHIVA_LINKING_MICROCODE_PATCH) {
		char *so_path;

		res = shiva_so_resolve_symbol(linker, (char *)symname, &tmp, &so_path);
		if (res == true) {
			*type = RESOLVER_TARGET_SO_RESOLVE;
			*e_type = ET_DYN;
			if (realpath(so_path, path_out) == NULL) {
				perror("realpath");
				return false;
			}
			shiva_debug("Found symbol '%s:%#lx' within shared library '%s'\n", symname,
			    tmp.value, path_out);
			memcpy(symbol, &tmp, sizeof(*symbol));
			return true;
		}
		res = elf_symbol_by_name(&linker->self, symname, &tmp);
		if (res == true) {
			*type = RESOLVER_TARGET_SHIVA_SELF;
			*e_type = elf_type(&linker->self);
			shiva_debug("Found symbol '%s' within the Shiva binary: %#lx\n", symname, tmp.value);
			memcpy(symbol, &tmp, sizeof(*symbol));
			return true;
		} else {
			shiva_debug("Failed to find symbol '%s'\n", symname);
			return false;
		}
	}
	return false;
}

static bool
enable_post_linker(struct shiva_module *linker)
{

	shiva_ctx_t *ctx = linker->ctx;
	shiva_auxv_iterator_t a_iter;
	struct shiva_auxv_entry a_entry;

	if (linker->flags & SHIVA_MODULE_F_DELAYED_RELOCS)
		return true;

	shiva_debug("Enabling post linker for delayed relocations\n");
	linker->flags |= SHIVA_MODULE_F_DELAYED_RELOCS;
	if (shiva_auxv_iterator_init(ctx, &a_iter,
	    ctx->ulexec.auxv.vector) == false) {
		fprintf(stderr, "shiva_auxv_iterator_init failed\n");
		return false;
	}
	while (shiva_auxv_iterator_next(&a_iter, &a_entry) == SHIVA_ITER_OK) {
		if (a_entry.type == AT_ENTRY) {
			uint64_t entry;

			/*
			 * IMPORTANT NOTE:
			 * In our aarch64 implementation, shiva is an ET_EXEC
			 * so we can pass a function address as absolute. In
			 * other implementations we would have to create a macro
			 * to entry = GET_RIP() - &shiva_post_linker
			 * -- In aarch64 Shiva we can just pass &shiva_post_linker address
			 *  directly.
			 */
			shiva_debug("Enabling post linker, setting AT_ENTRY to %#lx\n",
			    &shiva_post_linker);
			entry = (uint64_t)&shiva_post_linker;
#if __x86_64__
			entry += 8; // we jump past the first two instructions of shiva_post_linker
#endif
			if (shiva_auxv_set_value(&a_iter, entry) == false) {
				fprintf(stderr, "shiva_auxv_set_value failed (Setting %#lx)\n", entry);
				return false;
			}
			break;
		}
	}
	return true;
}

bool
is_text_encoding_reloc(struct shiva_module *linker, uint64_t r_offset)
{
	struct elf_section shdr;
	elf_symtab_iterator_t sym_iter;
	struct elf_symbol symbol;
	bool found_sym = false;

	shiva_debug("r_offset: %#lx\n", r_offset);

	assert(elf_section_by_name(&linker->elfobj, ".text", &shdr) == true);
	shiva_debug("r_offset: %#lx shdr.offset: %#lx shdr.size: %#lx\n", r_offset, shdr.offset,
	    shdr.size);
	elf_symtab_iterator_init(&linker->elfobj, &sym_iter);
	while (elf_symtab_iterator_next(&sym_iter, &symbol) == ELF_ITER_OK) {
		if (symbol.type != STT_FUNC)
			continue;
		if (r_offset >= symbol.value && r_offset < symbol.value + symbol.size) {
			found_sym = true;
		}
	}
	return !found_sym;
}

bool
update_relocs_with_transforms(struct shiva_module *linker,
    struct elf_relocation *rel, struct shiva_transform *transform,
    char *shdrname)
{

	if (module_has_transforms(linker) == true &&
	    strcmp(shdrname, ".text") == 0 && transform != NULL) {
		bool text_on_text_reloc = false;
		bool text_encoding = false;
		/*
		 * We are relocating code that has been spliced into a target
		 * function, via transformation.
		 * Relocation offset equals offset of function we are transforming (segment_offset)
		 * plus the splice offset (transform->offset) plus the original relocation offset.
		 */
		shiva_debug("Transform splice relocation: segment_offset %#lx transform_offset %#lx\n",
		    transform->segment_offset, transform->offset);
		shiva_debug("Rel type: %d\n", rel->type);
#if __aarch64__
		if (rel->type == R_AARCH64_ADR_PREL_PG_HI21 ||
		    rel->type == R_AARCH64_ADD_ABS_LO12_NC) {
			shiva_debug("Testing rel.symname: %s with .text\n",
			    rel->symname);
			if (strcmp(rel->symname, ".text") == 0) {
				shiva_debug("Found text on text relocation\n");
				shiva_debug("Increasing r_addend by %zu bytes\n",
				    transform->splice.copy_len3 +
				    transform->segment_offset + transform->offset);
				rel->addend += transform->segment_offset + transform->offset;
				rel->addend += transform->splice.copy_len3;
			}
		}
#endif
		/*
		 * XXX In the future maybe just check to see if this is
		 * an R_AARCH64_ABS64 relocation.
		 */
#if __aarch64__
		if (is_text_encoding_reloc(linker, rel->offset) == true) {
			shiva_debug("Text encoding is true! Increasing r_offset by %zu\n",
			    transform->splice.copy_len3);
			/*
			 * See transformation specification on handling
			 * relocations that apply to .text encoded data.
			 */
			shiva_debug("Increasing r_offset(%#lx) to %#lx\n", rel->offset,
			    rel->offset + transform->splice.copy_len3);
			rel->offset += transform->splice.copy_len3;
			text_encoding = true;
		}
#endif
		/*
		 * In the event of relocating a spliced function we must always increase
		 * the rel.offset to match the new location.
		 */
		rel->offset = transform->segment_offset + transform->offset + rel->offset;
	} else {
		shiva_debug("Transforms exist. rel_offset = rel->offset(%#lx)"
		    " + linker->tf_text_offset(%#lx) = %#lx\n", rel->offset,
		    linker->tf_text_offset, rel->offset + linker->tf_text_offset);

		/*
		 * We are relocating code that exists after all splices in our modules
		 * process image.
		 * We update rel.offset with the updated .text offset
		 * based on transformations.
		 */
		rel->offset = linker->tf_text_offset + rel->offset;
		if (strcmp(rel->symname, ".text") == 0) {
			rel->addend += linker->tf_text_offset;
		}
	}
	return true;
}


bool
apply_relocation(struct shiva_module *linker, struct elf_relocation rel,
    struct shiva_transform *transform)
{
	struct shiva_module_plt_entry *current = NULL;
	struct shiva_module_section_mapping *smap_current;
	struct shiva_module_section_mapping smap, smap_tmp;
	uint8_t *rel_unit;
	uint64_t symval;
	uint64_t rel_addr;
	uint64_t rel_val;
	uint32_t insn_bytes;
	struct elf_symbol symbol;
	ENTRY e, *ep;
	struct shiva_module_got_entry got_entry;
	bool res;
	char *symbol_section;
	struct elf_section tmp_shdr;

	char *shdrname = strrchr(rel.shdrname, '.');
	if (shdrname == NULL) {
		shiva_debug("strrchr failed\n");
		return false;
	}
	if (get_section_mapping(linker, shdrname, &smap) == false) {
		shiva_debug("Failed to retrieve section data for %s\n", rel.shdrname);
		return false;
	}
	shiva_debug("Successfully retrieved section mapping for %s\n", shdrname);
	shiva_debug("linker->text_vaddr: %#lx\n", linker->text_vaddr);
	shiva_debug("linker->data_vaddr: %#lx\n", linker->data_vaddr);
	shiva_debug("smap.offset: %#lx\n", smap.offset);

	if (module_has_transforms(linker) == true &&
	    strcmp(shdrname, ".text") == 0 && transform != NULL) {
		if (update_relocs_with_transforms(linker, &rel,
		    transform, shdrname) == false) {
			fprintf(stderr, "Failed to apply transform offsets "
			    "to the relocation records\n");
			return false;
		}
	}
#if defined (__aarch64__)
	switch(rel.type) {
		/* R_AARCH64_ABS64: computation S + A */
		/* This relocation can reference both a symbol and a section
		 * name, so we must handle both scenarios.
		 */
	case R_AARCH64_ABS64:
		/*
		 * Is the symbol a section header, such as .eh_frame or .rodata,
		 * that lives within the Shiva-module itself?
		 */
		shiva_debug("Applying R_AARCH64_ABS64 relocation for symbol %s\n", rel.symname);
		TAILQ_FOREACH(smap_current, &linker->tailq.section_maplist, _linkage) {
			if (strcmp(smap_current->name, rel.symname) != 0)
				continue;
			symval = smap_current->vaddr;
			rel_unit = &linker->text_mem[smap.offset + rel.offset];
			shiva_debug("symval: %#lx symval, rel_addr: %#lx addend: %#lx\n", symval,
			    linker->text_vaddr + smap.offset + rel.offset, rel.addend);
			shiva_debug("rel_val: %#lx\n", symval + rel.addend);
			rel_addr = linker->text_vaddr + smap.offset + rel.offset;
			rel_val = symval + rel.addend;
			*(uint64_t *)&rel_unit[0] = rel_val;
			return true;
		}
		/*
		 * Is the symbol found in the ET_REL Shiva module?
		 */
		if (elf_symbol_by_name(&linker->elfobj, rel.symname,
		    &symbol) == true) {
			if (symbol.type == STT_NOTYPE) {
				uint64_t e_type, target_type;
				char so_path[PATH_MAX];
				/*
				 * internal_symresolve() will search in the following order:
				 * 1. Search the Shiva module: patch1.o, patch2.o, ...
				 * 2. Search the target executable
				 * 3. Search the target executables shared library dependencies
				 */
				shiva_debug("Internal symresolve on %s\n", rel.symname);
				res = internal_symresolve(linker, rel.symname,
				    &symbol, &e_type, &target_type, so_path);
				if (res == true) {
					uint64_t so_base;
					struct shiva_module_delayed_reloc *delay_rel;
					char path_out[PATH_MAX];
					char *so_path;
					struct elf_symbol tmp;

					switch(target_type) {
					case RESOLVER_TARGET_SHIVA_SELF:
						symval = e_type == ET_EXEC ? symbol.value :
						    symbol.value + linker->shiva_base;
						break;
					case RESOLVER_TARGET_EXECUTABLE:
						symval = e_type == ET_EXEC ? symbol.value :
						    symbol.value + linker->target_base;
						break;
					case RESOLVER_TARGET_SO_RESOLVE:
						/*
						 * DELAYED RELOCATIONS
						 *
						 * In the event that this is a libc.so symbol we can
						 * resolve the symbol value offset but we won't know
						 * the base of libc.so until ld-linux.so loads it.
						 * Insert this as a delayed relocation so that the
						 * shiva_post_linker code can handle it later.
						 */
						res = shiva_so_resolve_symbol(linker, (char *)symbol.name, &tmp, &so_path);
						if (res == false) {
							fprintf(stderr, "Failed to resolve symbol '%s' in shared libs\n",
							    symbol.name);
							return false;
						}
						if (realpath(so_path, path_out) == NULL) {
							perror("realpath");
							return false;
						}

						delay_rel = shiva_malloc(sizeof(*delay_rel));
						delay_rel->rel_unit = &linker->text_mem[smap.offset + rel.offset];
						delay_rel->rel_addr = linker->text_vaddr + smap.offset + rel.offset;
						delay_rel->symval = tmp.value;
						delay_rel->symname = shiva_strdup(symbol.name);
						strncpy(delay_rel->so_path, path_out, PATH_MAX);
						delay_rel->so_path[PATH_MAX - 1] = '\0';

						if (enable_post_linker(linker) == false) {
							fprintf(stderr, "Failed to enable delayed relocs\n");
							return false;
						}
						shiva_debug("Delayed relocation for symbol '%s', must resolve in %s\n",
						    symbol.name, delay_rel->so_path);
						TAILQ_INSERT_TAIL(&linker->tailq.delayed_reloc_list, delay_rel, _linkage);
						return true;
					}
					shiva_debug("Symval: %#lx\n", symval);
					rel_unit = &linker->text_mem[smap.offset + rel.offset];
					rel_addr = linker->text_vaddr + smap.offset + rel.offset;
					rel_val = symval + rel.addend;
					shiva_debug("Symbol: %s\n", rel.symname);
					shiva_debug("rel_val = %#lx + %#lx\n", symval, rel.addend);
					shiva_debug("rel_addr: %#lx rel_val: %#x\n", rel_addr, rel_val);
					*(uint64_t *)&rel_unit[0] = rel_val;
					return true;
				} else {
					fprintf(stderr, "Failed to find relocation "
					    "symbol: %s\n", rel.symname);
					return false;
				}
			} else {
				/*
				 * A symbol was found in the Shiva ET_REL module that
				 * is not a section name.
				 */
				symbol_section = module_symbol_shndx_str(linker, &symbol);
				if (symbol_section == NULL) {
					fprintf(stderr, "Failed to find home-section for symbol: %s "
					    "in module '%s'\n", symbol.name, elf_pathname(&linker->elfobj));
					return false;
				}
				if (elf_section_by_name(&linker->elfobj, symbol_section, &tmp_shdr) == false) {
					fprintf(stderr, "Unable to look up symbol '%s' in module '%s'\n",
					    symbol.name, elf_pathname(&linker->elfobj));
					return false;
				}
				/*
				 * Create special handling of relocation for .bss scenario.
				 */
				if (tmp_shdr.type == SHT_NOBITS && symbol.shndx == SHN_COMMON) {
					if ((tmp_shdr.flags & SHF_ALLOC|SHF_WRITE) == SHF_ALLOC|SHF_WRITE) {
						ENTRY e, *ep;

						e.key = (char *)symbol.name;
						e.data = NULL;

						shiva_debug(".bss variable being allocated\n");

						if (hsearch_r(e, FIND, &ep, &linker->cache.bss) == 0) {
							fprintf(stderr, "Unable to find symbol '%s' in"
							    " the the bss cache\n", symbol.name);
							return false;
						}
						shiva_debug("[!] BSS scenario. symval = %#lx + %#lx\n",
						    linker->bss_vaddr, ((struct shiva_module_bss_entry *)(ep->data))->offset);
						symval = linker->bss_vaddr;
						symval += ((struct shiva_module_bss_entry *)(ep->data))->offset;
						rel_unit = &linker->text_mem[smap.offset + rel.offset];
						rel_addr = linker->text_vaddr + smap.offset + rel.offset;
					}
				} else if (tmp_shdr.flags & SHF_ALLOC) {
					if (!(tmp_shdr.flags & SHF_WRITE)) {
					/*
					 * If the symbol lives in a section that's SHF_ALLOC but not
					 * SHF_WRITE then it goes into our modules text segment. For
					 * example symbols in .rodata, and .text would be stored in
					 * the text segment of the module.
					 */
						symval = linker->text_vaddr + symbol.value;
						rel_unit = &linker->text_mem[smap.offset + rel.offset];
						rel_addr = linker->text_vaddr + smap.offset + rel.offset;
					} else {
						symval = linker->data_vaddr + symbol.value;
						rel_unit = &linker->text_mem[smap.offset + rel.offset];
						rel_addr = linker->text_vaddr + smap.offset + rel.offset;
					}
				}
				rel_val = symval + rel.addend;
				shiva_debug("Symbol: %s\n", rel.symname);
				shiva_debug("rel_val = %#lx + %#lx\n", symval, rel.addend);
				shiva_debug("rel_addr: %#lx rel_val: %#x\n", rel_addr, rel_val);
				*(uint64_t *)&rel_unit[0] = rel_val;
				return true;
			}
		}
		break;
	case R_AARCH64_CALL26: /* ((S + A - P) >> 2) & 0x3ffffff */
		/*
		 * NOTE: Every immediate call (i.e. bl <offset>) will cause our
		 * linker to emit an internal PLT stub within the module.
		 * So in this case, the symbol 'S' is the address of the PLT
		 * stub.
		 */
		TAILQ_FOREACH(current, &linker->tailq.plt_list, _linkage) {
			if (strcmp(rel.symname, current->symname) != 0)
				continue;
			shiva_debug("Applying R_AARCH64_CALL26 relocation for %s\n", current->symname);
			shiva_debug("%s@shivaPLT: %#lx\n", current->symname, current->vaddr);
			rel_unit = &linker->text_mem[smap.offset + rel.offset];
			rel_addr = linker->text_vaddr + smap.offset + rel.offset;
			rel_val = ((current->vaddr + rel.addend - rel_addr)) >> 2;
			shiva_debug("rel_val = ((%#lx + %#lx - %#lx) >> 2)\n", current->vaddr,
			    rel.addend, rel_addr);
			shiva_debug("rel_addr: %#lx rel_val: %#x\n", rel_addr, rel_val);
			memcpy(&insn_bytes, &rel_unit[0], sizeof(uint32_t));
			insn_bytes = (insn_bytes & ~RELOC_MASK(26) | rel_val & RELOC_MASK(26));
			*(uint32_t *)&rel_unit[0] = insn_bytes;
			return true;
		}
		break;
	case R_AARCH64_ADD_ABS_LO12_NC: /* (S + A) & 0xfff */
		/*
		 * Does the relocation symbol reference a section header name?
		 * i.e. '.text'.
		 */
		TAILQ_FOREACH(smap_current, &linker->tailq.section_maplist, _linkage) {
			if (strcmp(smap_current->name, rel.symname) != 0)
				continue;
			shiva_debug("Applying R_AARCH64_ADD_ABS_LO12_NC relocation for %s\n",
			    rel.symname);
			symval = smap_current->vaddr;
			rel_unit = &linker->text_mem[smap.offset + rel.offset];
			rel_addr = linker->text_vaddr + smap.offset + rel.offset;
			rel_val = symval + rel.addend;
			shiva_debug("rel_addr: %#lx symval: %#lx rel.addend: %#lx\n",
			    rel_addr, symval, rel.addend);
			shiva_debug("rel_val = (%#lx + %#lx) & 0xfff;\n", symval, rel.addend);
			memcpy(&insn_bytes, &rel_unit[0], sizeof(uint32_t));
			insn_bytes = (insn_bytes & ~(RELOC_MASK(12) << 10)) | ((rel_val & RELOC_MASK(12)) << 10);
			shiva_debug("insn_bytes: %#x\n", (uint32_t)insn_bytes);
			*(uint32_t *)&rel_unit[0] = insn_bytes;
			return true;
		}
		/* TODO: Does this reloc apply to functions or data object? */
		break;
	case R_AARCH64_ADR_PREL_PG_HI21: /* ((PAGE(S+A) - PAGE(P)) >> 12) & 0x1fffff */
		/*
		 * Does the relocation symbol reference a section header name?
		 * It usually references `.text` as it's symbol.
		 */

		TAILQ_FOREACH(smap_current, &linker->tailq.section_maplist, _linkage) {
			if (strcmp(smap_current->name, rel.symname) != 0)
				continue;
			shiva_debug("Applying R_AARCH64_ADR_PREL_PG_HI21 relocation for %s\n",
			    rel.symname);
			symval = smap_current->vaddr;
			rel_unit = &linker->text_mem[smap.offset + rel.offset];
			rel_addr = linker->text_vaddr + smap.offset + rel.offset;
			rel_val = ELF_PAGESTART(symval + rel.addend) - ELF_PAGESTART(rel_addr);
			rel_val = rel_val >> 12;
			memcpy(&insn_bytes, &rel_unit[0], sizeof(uint32_t));
			/*
			 * Re-encode the instruction with the new IMM field of ADR
			 */
			insn_bytes = (insn_bytes & ~((RELOC_MASK (2) << 29) | (RELOC_MASK(19) << 5)))
			    | ((rel_val & RELOC_MASK(2)) << 29) | ((rel_val & (RELOC_MASK(19) << 2)) << 3);
			*(uint32_t *)&rel_unit[0] = insn_bytes;
			shiva_debug("rel_addr: %#lx rel_val: %#lx\n", rel_addr, rel_val);
			return true;
		}
		/*
		 * TODO: Does this reloc apply to function or data symbols too?
		 * haven't seen it yet.
		 */
		break;
	}
#endif


		

shiva_debug("Going to apply a relocation of type: %d\n", rel.type);

#if defined(__x86_64__)
	switch(rel.type) {
	case R_X86_64_PLTOFF64: /* computation L - GOT + A */
		TAILQ_FOREACH(current, &linker->tailq.plt_list, _linkage) {
			if (strcmp(rel.symname, current->symname) != 0)
				continue;
			shiva_debug("Applying PLTOFF64 relocation for %s\n",
			    current->symname);
			rel_unit = &linker->text_mem[smap.offset + rel.offset];
			rel_addr = linker->text_vaddr + smap.offset + rel.offset;
			rel_val = /* L */ current->vaddr - /* GOT */
			    (linker->data_vaddr + linker->pltgot_off) + /* A */ rel.addend;
			shiva_debug("rel_addr: %#lx rel_val: %#lx\n", rel_addr, rel_val);
			*(uint64_t *)&rel_unit[0] = rel_val;
			return true;
		}
		break;	/*The offset from the GOT to the current position */
	case R_X86_64_GOTPC64: /* computation: GOT - P + A */
		shiva_debug("Applying GOTPC64 relocation for _GLOBAL_OFFSET_TABLE_ + %d\n", rel.addend);
		rel_unit = &linker->text_mem[smap.offset + rel.offset];
		rel_addr = linker->text_vaddr + smap.offset + rel.offset;
		rel_val = (linker->data_vaddr + linker->pltgot_off) - rel_addr + rel.addend;
		shiva_debug("Subtracting GOT(%lx) from REL_ADDR+REL_ADDEND(%lx)\n", 
		    (linker->data_vaddr + linker->pltgot_off),rel_addr + rel.addend);
		*(uint64_t *)&rel_unit[0] = rel_val;
		return true;
		break;
	case R_X86_64_GOT64:
		shiva_debug("Applying GOT64 relocation for %s\n", rel.symname);
		e.key = rel.symname;
		e.data = NULL;

		if (hsearch_r(e, FIND, &ep, &linker->cache.got) == 0) {
			fprintf(stderr, "Unable to find symbol '%s' in GOT cache, cannot resolve GOT64 relocation\n",
			    rel.symname);
			return false;
		}
		memcpy(&got_entry, ep->data, sizeof(got_entry));
		rel_unit = &linker->text_mem[smap.offset + rel.offset];
		rel_addr = linker->text_vaddr + smap.offset + rel.offset;
		rel_val = got_entry.gotoff;
		shiva_debug("rel_addr: %#lx rel_val: %#lx\n", rel_addr, rel_val);
		*(uint64_t *)&rel_unit[0] = rel_val;
		return true;
		break;
	case R_X86_64_GOTOFF64:
		shiva_debug("Applying GOTOFF64 relocation for %s\n", rel.symname);
		/*
		 * Calculate offset from symbol to base of GOT.
		 * NOTE: This is an unusual relocation. It uses GOT as an anchor
		 * and finds the offset to the symbol. It then subtracts the offset
		 * from the GOT to resolve the symbol address. The symbol is then
		 * invoked indirectly via call *reg
		 */
		if (elf_symbol_by_name(&linker->elfobj, rel.symname, &symbol) == true) {
			rel_unit = &linker->text_mem[smap.offset + rel.offset];
			rel_addr = linker->text_vaddr + smap.offset + rel.offset;
			if (strncmp(rel.symname, ".LC", 3) == 0) {
				/*
				 * Symbol is likely pointing to locations within
				 * the .rodata section. We will need to add symbol value
				 * to the base of .rodata section instead of the text segment address.
				 * This is because these label symbols have values that are relative
				 * to the base of '.rodata'
				 */
				if (get_section_mapping(linker, ".rodata", &smap_tmp) == false) {
					fprintf(stderr, "Failed to retrieve section data for %s\n", rel.shdrname);
					return false;
				}

				rel_val = (symbol.value + smap_tmp.vaddr) + rel.addend -
				    (linker->data_vaddr + linker->pltgot_off);
			} else {
				struct elf_section tmpshdr;
				struct elf_symbol tmpsym;

				if (elf_symbol_by_name(&linker->elfobj, rel.symname, &tmpsym) == false) {
					fprintf(stderr, "Failed to retrieve symbol: %s\n", rel.symname);
					return false;
				}
				if (elf_section_by_index(&linker->elfobj, tmpsym.shndx, &tmpshdr) == false) {
					fprintf(stderr, "Failed to retrive section index %d\n", tmpsym.shndx);
					return false;
				}
				if (strcmp(tmpshdr.name, ".data") == 0) {
					rel_val = (symbol.value + linker->data_vaddr) + rel.addend -
					    (linker->data_vaddr + linker->pltgot_off);
				} else if (strcmp(tmpshdr.name, ".text") == 0) {
					rel_val = (symbol.value + linker->text_vaddr) + rel.addend -
					    (linker->data_vaddr + linker->pltgot_off);
				} else if (strcmp(tmpshdr.name, ".bss") == 0) {
					rel_val = (symbol.value + linker->bss_vaddr) + rel.addend -
					    (linker->data_vaddr + linker->pltgot_off);
				} else {
					fprintf(stderr, "GOTOFF64 applies to unknown section target %s (fixme)\n",
					    tmpshdr.name);
					return false;
				}
			}
			shiva_debug("rel_addr: %#lx rel_val: %#lx\n", rel_addr, rel_val);
			*(int64_t *)&rel_unit[0] = rel_val;
			return true;
		}
		break;
	case R_X86_64_PLT32: /* computation: L + A - P */
		TAILQ_FOREACH(current, &linker->tailq.plt_list, _linkage) {
			if (strcmp(rel.symname, current->symname) != 0)
				continue;
			shiva_debug("Applying PLT32 relocation for %s\n", current->symname);
			rel_unit = &linker->text_mem[smap.offset + rel.offset];
			rel_addr = linker->text_vaddr + smap.offset + rel.offset;
			rel_val = current->vaddr + rel.addend - rel_addr;
			shiva_debug("rel_addr: %#lx rel_val: %#x\n", rel_addr, rel_val);
			*(uint32_t *)&rel_unit[0] = rel_val;
			return true;
		}
		break;
	case R_X86_64_PC32: /* computation: S + A - P */
		shiva_debug("Applying PC32 relocation for %s\n", rel.symname);
		if (rel.symname[0] == '.') { /* symname is a section name in this case */
			/*
			 * i.e. if rel.symname is ".eh_frame" then we must find that section
			 * mapping to get it's address, as our symbol value. therefore S =
			 * address of ".eh_frame" mapping.
			 */
			TAILQ_FOREACH(smap_current, &linker->tailq.section_maplist, _linkage) {
				if (strcmp(smap_current->name, rel.symname) != 0)
					continue;
				symval = smap_current->vaddr;
				rel_unit = &linker->text_mem[smap.offset + rel.offset];
				rel_addr = linker->text_vaddr + smap.offset + rel.offset;
				rel_val = symval + rel.addend - rel_addr;
				shiva_debug("Section: %s\n", rel.symname)
				shiva_debug("rel_val = %#lx + %#lx - %#lx\n", symval, rel.addend, rel_addr);
				shiva_debug("rel_addr: %#lx rel_val: %#x\n", rel_addr, rel_val);
				*(uint32_t *)&rel_unit[0] = rel_val;
				return true;
			}
		} else { /* Handling a non-section-name symbol. */
			/*
			 * First look for symbol inside of the module, and if it doesn't exist
			 * there let's look inside of the debuggers symbol table.
			 */
			/* 1. Check module for symbol */
			shiva_debug("Checking module for symbol\n");
			if (elf_symbol_by_name(&linker->elfobj, rel.symname,
			    &symbol) == true) {
				/*
				 * If the symbol is a NOTYPE then it is an external reference
				 * to a symbol somewhere else (i.e. shiva_ctx_t *global_ctx).
				 * Probably exists in the debugger binary.
				 */
				if (symbol.type == STT_NOTYPE)
					goto internal_lookup;
				shiva_debug("Symbol value for %s: %#lx\n", rel.symname, symbol.value);
				symval = linker->text_vaddr + symbol.value;
				rel_unit = &linker->text_mem[smap.offset + rel.offset];
				rel_addr = linker->text_vaddr + smap.offset + rel.offset;
				rel_val = symval + rel.addend - rel_addr;
				shiva_debug("Symbol: %s\n", rel.symname);
				shiva_debug("rel_val = %#lx + %#lx - %#lx\n", symval, rel.addend, rel_addr);
				shiva_debug("rel_addr: %#lx rel_val: %#x\n", rel_addr, rel_val);
				*(uint32_t *)&rel_unit[0] = rel_val;
				return true;
			}
			/* 
			 * 2. Look up the symbol from within the Shiva binary itself.
			 */
internal_lookup:
			shiva_debug("Looking up symbol %s inside of Shiva\n");
			if (elf_symbol_by_name(&linker->self, rel.symname,
			    &symbol) == true) {
				shiva_debug("Internal symbol lookup\n");
				shiva_debug("Symbol value for %s: %#lx\n", rel.symname, symbol.value);
				/*
				 * Note if we found this symbol within the "/bin/shiva" executable
				 * instead of the loaded module, then we can simply assign
				 * symbol.value as the symval, instead of symbol.value + linker->text_vaddr
				 * (Which adds the module text segment to symbol.value).
				 */
/*
 * NOTE:
 * aarch64 interpreter is ET_EXEC and we don't need to add
 * the linker->shiva_base to it.
 */
#ifdef __x86_64__
#ifdef SHIVA_STANDALONE
				symval = symbol.value;
#else
				symval = symbol.value + linker->shiva_base;
#endif
#elif __aarch64__
				symval = symbol.value;
#endif
				rel_unit = &linker->text_mem[smap.offset + rel.offset];
				rel_addr = linker->text_vaddr + smap.offset + rel.offset;
				rel_val = symval + rel.addend - rel_addr;
				shiva_debug("Symbol: %s\n", rel.symname);
				shiva_debug("rel_val = %#lx + %#lx - %#lx\n", symval, rel.addend, rel_addr);
				shiva_debug("rel_addr: %#lx rel_val: %#x\n", rel_addr, rel_val);
				*(uint32_t *)&rel_unit[0] = rel_val;
				return true;
			} else {
				fprintf(stderr, "Failed to find relocation symbol: %s\n", rel.symname);
				return false;
			}
		}
	}
#endif
	return false;
}
bool
relocate_module(struct shiva_module *linker)
{
	struct elf_relocation_iterator rel_iter;
	struct elf_relocation rel;
	bool res;
	char *shdrname;
	struct shiva_transform *transform;
	struct shiva_transform *tf_ptr = NULL;

	elf_relocation_iterator_init(&linker->elfobj, &rel_iter);
	while (elf_relocation_iterator_next(&rel_iter, &rel) == ELF_ITER_OK) {
		tf_ptr = NULL;
		shdrname = strrchr(rel.shdrname, '.');
		if (shdrname == NULL) {
			shiva_debug("strrchr parse error");
			return false;
		}
		if (strcmp(shdrname, ".eh_frame") == 0) {
			/*
			 * We don't need to process relocations for .eh_frame. Maybe
			 * in the future for module debugging purposes.
			 */
			continue;
		}
		shiva_debug("Relocation in %s (offset: %#lx) for symbol %s\n", shdrname,
		    rel.offset, rel.symname);
		/*
		 * Check transformation records and see if the current relocation
		 * record is fixing up code within one of our transform source
		 * functions.
		 */
		TAILQ_FOREACH(transform, &linker->tailq.transform_list, _linkage) {
			shiva_debug("Is rel.offset(%#lx) within the range of %#lx-%#lx\n", rel.offset,		
			    transform->source_symbol.value,
			    transform->source_symbol.value + transform->source_symbol.size +
			    transform->ext_len);

			/*
			 * Does rel.offset fit within the range of a function that is to be spliced?
			 * We actually check to see if it fits within the range of the transformed
			 * function + the padding between it and the next function. This padding is
			 * used in ELF .text relocations in AARCH64
			 */
			if (rel.offset >= transform->source_symbol.value &&
			    rel.offset < transform->source_symbol.value +
			    transform->source_symbol.size + transform->ext_len) {
				shiva_debug("This .text relocation applies to transform code in: %s\n",
				    transform->source_symbol.name);
				tf_ptr = transform;
				break;
			}
		}
		shiva_debug("Relocation symbol name: %s\n", rel.symname);
		res = apply_relocation(linker, rel, tf_ptr);
		if (res == false) {
			shiva_debug("Failed to apply %s relocation at offset %#lx\n",
			    rel.shdrname, rel.offset);
			return false;
		}
	}
	return true;
}

static bool
module_has_transforms(struct shiva_module *linker)
{
	if (linker->flags & SHIVA_MODULE_F_TRANSFORM)
		return true;
	return false;
}

/*
 * This function copies the code/data from a given section into it's
 * respective memory mapped segment (i.e. the text segment).
 * Section data is copied from elfobj to the respective memory mapped segment
 * pointed to by dst. The section data to be copied is described by
 * section. Without the segment_offset this function would not be re-entrant.
 * The segment_offset tells us at which offset within the segment to copy the given
 * section data to.
 *
 * NOTE: Sections should be created on aligned boundaries, especially as it
 * pertains to ARM, otherwise the relocation encodings can't decode to values
 * based on a power of 2.
 */
bool
elf_section_map(struct shiva_module *linker, elfobj_t *elfobj, uint8_t *dst, 
    struct elf_section section, uint64_t *segment_offset)
{
	size_t rem = section.size % sizeof(uint64_t);
	uint64_t qword;
	bool res;
	size_t i = 0;

	if (strcmp(section.name, ".text") == 0 &&
	    module_has_transforms(linker)  == true) {
		/*
		 * Handle any transformations for the .text section, such
		 * as function splicing.
		 */
		shiva_debug("section address: %p\n", section);
		res = shiva_tf_process_transforms(linker, dst, section, segment_offset);
		if (res == false) {
			fprintf(stderr, "shiva_tf_process_transforms() failed\n");
			return false;
		}
	}
	shiva_debug("Reading from offset %#lx - %#lx\n", section.offset,
	    section.offset + section.size);
	for (i = 0; i < section.size; i += sizeof(uint64_t)) {
		if (i + sizeof(uint64_t) > section.size) {
			size_t j;
			  shiva_debug("%d + sizeof(uint64_t) >= %d\n", i, section.size);

			/*
			 * If there are 7 or less remaining bytes we cannot read
			 * by QWORD and will read the remainder byte by byte
			 */
			shiva_debug("writing out remainder: %d bytes\n", rem);
			for (j = 0; j < rem; j++) {
				shiva_debug("Reading remaining byte from offset: %zu\n",
				    section.offset + i + j);
				res = elf_read_offset(elfobj, section.offset + i + j,
				    &qword, ELF_BYTE);
				if (res == false) {
					shiva_debug("elf_read_offset failed at %#lx\n",
					    section.offset + i + j);
					return false;
				}
				dst[*segment_offset + i + j] = (uint8_t)qword;
			}
			break;
		}
		shiva_debug("Reading qword from offset: %zu\n", section.offset + i);
		res = elf_read_offset(elfobj, section.offset + i, &qword, ELF_QWORD);
		if (res == false) {
			shiva_debug("elf_read_offset failed at %#lx\n", section.offset + i);
			return false;
		}
		shiva_debug("qword: %#lx\n", qword);
		*(uint64_t *)&dst[*segment_offset + i] = qword;
	}
	*segment_offset += section.size;
	return true;
}
/*
 * 1. Calculate .bss size in relocatable object. The sh_size value will be
 * set to zero in an ET_REL. So we must find every STT_OBJECT symbol who's
 * shndx value is set to SHN_COMMON. This indicates that the symbol is not
 * allocated for on disk and is apart of a common block of unallocated memory.
 * ld(1) stores uninitialized variable symbols as STT_OBJECT/STB_GLOBAL with
 * an st_value equal to the size of the variable (Instead of an offset). We
 * will use this data to build our own information about where to store the
 * variable and at what offsets, internally.
 *
 * 2. As we calculate the bss size, we might as well store the .bss variable
 * symbol information, offset from the end of the data segment in a cache.
 * This way when we are linking a new variable in with a COMMON shndx we
 * can check the cache, which already contains the underlying linking data
 * that is required my Shiva.
 */
#define MAX_BSS_COUNT 512 /* XXX This should be configurable/tunable */

bool
calculate_bss_size(struct shiva_module *linker, size_t *out)
{
	elfobj_t *elfobj = &linker->elfobj; //ptr to ELF ET_REL patch
	struct elf_symbol symbol;
	elf_symtab_iterator_t symtab_iter;
	struct shiva_module_bss_entry *bss_entry;
	ENTRY e, *ep;
	uint64_t var_offset = 0;
	size_t bss_size = 0;
	char *shdr_name;

	TAILQ_INIT(&linker->tailq.bss_list);
	(void) hcreate_r(MAX_BSS_COUNT, &linker->cache.bss);

	elf_symtab_iterator_init(elfobj, &symtab_iter);
	while (elf_symtab_iterator_next(&symtab_iter, &symbol) == ELF_ITER_OK) {
		if (symbol.bind != STT_OBJECT)
			continue;
		shdr_name = module_symbol_shndx_str(linker, &symbol);
		if (shdr_name == NULL) {
			fprintf(stderr, "Failed to find section associated with symbol"
			    " index %d\n", symbol.shndx);
			return false;
		}
		if (symbol.shndx == SHN_COMMON || (strcmp(shdr_name, ".bss") == 0)) {
			e.key = (char *)symbol.name;
			e.data = NULL;

			/*
			 * If the symbol already exists, then move on.
			 */
			if (hsearch_r(e, FIND, &ep, &linker->cache.bss) != 0)
				continue;
			bss_entry = shiva_malloc(sizeof(*bss_entry));
			bss_entry->symname = (char *)symbol.name;
			bss_entry->addr = linker->bss_vaddr + var_offset;
			bss_entry->offset = var_offset;
			var_offset += symbol.size;

			e.key = (char *)bss_entry->symname;
			e.data = bss_entry;

			if (hsearch_r(e, ENTER, &ep, &linker->cache.bss) == 0) {
				free(bss_entry);
				fprintf(stderr, "Failed to add .bss entry into cache: '%s'\n",
				    symbol.name);
				return false;
			}

			shiva_debug("Inserting entry '%s' into .bss"
			    " cache and .bss list\n", symbol.name);
			TAILQ_INSERT_TAIL(&linker->tailq.bss_list, bss_entry, _linkage);
			bss_size += symbol.size;
		}
	}
	*out = bss_size;
	return true;
}

#define MAX_GOT_COUNT 4096 * 10

/*
 * Generally our modules data segment looks like this:
 * 0x6000000				
 * [.data section, .got section, .bss]
 * We must calculate the needed size of all global data, got entries,
 * and the bss.
 */
bool
calculate_data_size(struct shiva_module *linker)
{
	struct elf_section section;
	elf_section_iterator_t iter;
	struct elf_relocation rel;
	elf_relocation_iterator_t rel_iter;
	struct shiva_module_got_entry *got_entry;
	ENTRY e, *ep;
	uint64_t offset;
	size_t bss_len = 0;

	elf_section_iterator_init(&linker->elfobj, &iter);
	while (elf_section_iterator_next(&iter, &section) == ELF_ITER_OK) {
		if (section.flags == (SHF_ALLOC|SHF_WRITE)) {
			/*
			 * Skip .bss for now, we want to place it after our
			 * .got area in the data segment.
			 */
			if (strcmp(section.name, ".bss") == 0)
				continue;
			shiva_debug("Increasing data segment len for section: %s len: %d\n",
			    section.name, section.size);
			linker->data_size += section.size;
		}
	}
	linker->pltgot_off = linker->data_size;

	if (elf_section_by_name(&linker->elfobj, ".bss", &section) == false) {
		shiva_debug("elf_section_by_name() failed\n");
		return false;
	}
	/*
	 * Generally the .bss section will be set to a section
	 * size of 0. We must calculate the size by finding STB_GLOBAL
	 * symbols that have a symbol index set to SHN_COMMON.
	 */
	if (calculate_bss_size(linker, &bss_len) == false) {
		fprintf(stderr, "calculate_bss_len() failed\n");
		return false;
	}
	linker->bss_size = bss_len;
	/*
	 * Make room for the .bss
	 */
	shiva_debug("bss len: %d\n", bss_len);
	linker->data_size += bss_len;
	shiva_debug("data_size: %d\n", linker->data_size);
	/*
	 * Create cache for GOT entries.
	 */
	(void) hcreate_r(MAX_GOT_COUNT, &linker->cache.got);

	TAILQ_INIT(&linker->tailq.got_list);

	offset = 0;

	elf_relocation_iterator_init(&linker->elfobj, &rel_iter);
	while (elf_relocation_iterator_next(&rel_iter, &rel) == ELF_ITER_OK) {
		switch(rel.type) {
#ifdef __x86_64__
		case R_X86_64_PLT32:
		case R_X86_64_GOT64:
		case R_X86_64_PLTOFF64:
#elif __aarch64__
		case R_AARCH64_CALL26:
#endif
			/*
			 * Create room for the modules pltgot
			 */
			/*
			 * Cache symbol so we don't create duplicate GOT entries
			*/
			e.key = (char *)rel.symname;
			e.data = (char *)rel.symname;

			/*
			 * If we already have this symbol then move on.
			 */
			if (hsearch_r(e, FIND, &ep, &linker->cache.got) != 0)
				continue;

			got_entry = shiva_malloc(sizeof(*got_entry));
			got_entry->symname = rel.symname; /* rel.symname will be valid until elf is unloaded */
			got_entry->gotaddr = linker->data_vaddr + linker->pltgot_off + offset;
			got_entry->gotoff = offset;

			e.key = (char *)got_entry->symname;
			e.data = got_entry;

			if (hsearch_r(e, ENTER, &ep, &linker->cache.got) == 0) {
				free(got_entry);
				fprintf(stderr, "Failed to add symbol: '%s'\n",
				    rel.symname);
				return false;
			}

			shiva_debug("Inserting entry into GOT cache and GOT list\n"
			    "GOT entry for %s\n", got_entry->symname);
			TAILQ_INSERT_TAIL(&linker->tailq.got_list, got_entry, _linkage);
			offset += sizeof(uint64_t);

			linker->data_size += sizeof(uint64_t);
			linker->pltgot_size += sizeof(uint64_t);
			break;
		default:
			break;
		}
	}
	/*
	 * Offset from beginning of data segment.
	 * The .bss lives right after our modules .got section in memory.
	 */
	linker->bss_off = linker->data_size;
	shiva_debug("Shiva module data segment size: %zu\n", linker->data_size);
	return true;
}

bool
calculate_text_size(struct shiva_module *linker)
{
	struct elf_section section;
	elf_section_iterator_t iter;
	struct elf_relocation rel;
	elf_relocation_iterator_t rel_iter;
	struct shiva_transform *transform;
	size_t total_tf_len = 0; /* total transform length */
	/*
	 * Look for Transformation records that help us to determine
	 * what size the modules .text area is.
	 */
	TAILQ_FOREACH(transform, &linker->tailq.transform_list, _linkage) {
		switch(transform->type) {
		case SHIVA_TRANSFORM_SPLICE_FUNCTION:
			shiva_debug("Calculate room for function splicing on %s\n",
			    transform->target_symbol.name);
			total_tf_len += transform->target_symbol.size;
			total_tf_len += (transform->new_len > transform->old_len) ?
			    transform->new_len - transform->old_len : 0;
			break;
		default:
			break;
		}
	}
	shiva_debug("Transform records require a total of %zu bytes\n",
	    total_tf_len);

	linker->text_size += total_tf_len;
	elf_section_iterator_init(&linker->elfobj, &iter);
	/*
	 * When using some transforms such as function splicing then text_size
	 * += section.size will be somewhat to completely redundant, thus
	 * giving our image some extra padding.
	 */
	while (elf_section_iterator_next(&iter, &section) == ELF_ITER_OK) {
		if (section.flags & SHF_ALLOC) {
			if (section.flags & SHF_WRITE)
				continue;
			/*
			 * Looking only for section types of AX, and A
			 */
			linker->text_size += section.size;
		}
	}
	linker->plt_off = linker->text_size;
	elf_relocation_iterator_init(&linker->elfobj, &rel_iter);
	while (elf_relocation_iterator_next(&rel_iter, &rel) == ELF_ITER_OK) {
#ifdef __x86_64__
		if (rel.type == R_X86_64_PLT32 || rel.type == R_X86_64_PLTOFF64) {
#elif __aarch64__
		if (rel.type == R_AARCH64_CALL26) {
#endif
			/*
			 * Create room for each PLT stub
			 */
			linker->plt_size += sizeof(plt_stub);
			linker->text_size += sizeof(plt_stub);
			linker->plt_count++;
		}
	}
	if (linker->text_size == 0) {
		linker->flags |= SHIVA_MODULE_F_DUMMY_TEXT;
		linker->text_size = 4096;
	}
	shiva_debug("LPM text segment size: %zu\n", linker->text_size);
	shiva_debug("PLT Count: %zu\n", linker->plt_count);
	return true;
}

bool
create_data_image(struct shiva_ctx *ctx, struct shiva_module *linker)
{
	elf_section_iterator_t shdr_iter;
	struct elf_section section;
	bool res;
	size_t data_size_aligned;
	size_t off = 0;
	size_t count = 0;

#if 0
	/*
	 * I commented this out, because even though the data_size may be
	 * 0, we need a data segment area to house the .bss. 
	 */
	if (linker->data_size == 0) {
		shiva_debug("No data segment is needed\n");
		return true; // we need no data segment
	}
#endif
	uint64_t mmap_flags = (ctx->flags & SHIVA_OPTS_F_INTERP_MODE) ? MAP_PRIVATE|MAP_ANONYMOUS :
	    MAP_PRIVATE|MAP_ANONYMOUS;
	uint64_t mmap_base = 0;

	if (ctx->flags & SHIVA_OPTS_F_INTERP_MODE) {
		mmap_base = ELF_PAGEALIGN(linker->text_vaddr + linker->text_size, PAGE_SIZE);
	} else {
		mmap_base = ELF_PAGEALIGN(linker->text_vaddr + linker->text_size, PAGE_SIZE);
		mmap_flags |= MAP_32BIT;
	}
	/*
	 * TODO In the event that there is no data segment (i.e. data_size == 0)
	 * then we still allocate PAGE_SIZE bytes for any .bss data.
	 * In the future we need to assume that the .bss could be larger
	 * than PAGE_SIZE and fix this.
	 */
	data_size_aligned = linker->data_size == 0 ? PAGE_SIZE :
	    ELF_PAGEALIGN(linker->data_size, PAGE_SIZE);
	shiva_debug("ELF data segment len: %zu\n", data_size_aligned);
	linker->data_mem = mmap((void *)mmap_base, data_size_aligned, PROT_READ|PROT_WRITE,
	    mmap_flags, -1, 0);
	if (linker->data_mem == MAP_FAILED) {
		shiva_debug("mmap failed: %s\n", strerror(errno));
		return false;
	}
	linker->data_vaddr = (uint64_t)linker->data_mem;
	elf_section_iterator_init(&linker->elfobj, &shdr_iter);
	while (elf_section_iterator_next(&shdr_iter, &section) == ELF_ITER_OK) {
		if (section.flags & SHF_WRITE) {
			struct shiva_module_section_mapping *n;

			/*
			 * We don't map sections if their sh_size == 0, however
			 * we make an exception for the .bss. ET_REL objects don't
			 * give the size of the .bss section, instead they expect
			 * the linker to build it based on symbols with an SHN_COMMON
			 * shndx value, and build your own offsets into the location
			 * that you choose to store them.
			 */
			if (strcmp(section.name, ".bss") != 0 && section.size == 0)
				continue;
			shiva_debug("Attempting to map section %s(offset: %zu) into data segment"
			    " at address %p\n", section.name, off, linker->data_mem + off);
			/*
			 * If it's the .bss then we don't need to map anything, it's
			 * uninitialized.
			 */
			if (section.type != SHT_NOBITS) {
				res = elf_section_map(linker, &linker->elfobj, linker->data_mem,
				    section, &off);
				if (res == false) {
					shiva_debug("elf_section_map failed\n");
					return false;
				}
			}
			n = malloc(sizeof(*n));
			if (n == NULL) {
				shiva_debug("malloc failed\n");
				return false;
			}
			n->map_attribute = (section.type == SHT_NOBITS) ? LP_SECTION_BSS_SEGMENT :
			    LP_SECTION_DATASEGMENT;
			n->vaddr = (section.type == SHT_NOBITS) ? linker->data_vaddr + linker->bss_off 
			    : (uint64_t)linker->data_mem + count;
			n->offset = (section.type == SHT_NOBITS) ? linker->bss_off : count;
			n->size = (section.type == SHT_NOBITS) ? linker->bss_size : section.size;
			n->name = section.name;
			shiva_debug("Inserting section to segment mapping\n");
			shiva_debug("Address: %#lx\n", n->vaddr);
			shiva_debug("Offset: %#lx\n", n->offset);
			shiva_debug("Size: %#lx\n", n->size);
			TAILQ_INSERT_TAIL(&linker->tailq.section_maplist, n, _linkage);
			count += section.size;
			shiva_debug("COUNT: %zu\n", count);
		}
	}
	linker->bss_vaddr = linker->data_vaddr + linker->bss_off;
	return true;
}

bool
create_text_image(struct shiva_ctx *ctx, struct shiva_module *linker)
{
	elf_section_iterator_t shdr_iter;
	struct elf_section section;
	elf_relocation_iterator_t rel_iter;
	struct elf_relocation rel;
	bool res;
	size_t text_size_aligned;
	size_t off = 0;
	size_t count = 0;
	int i;
	struct shiva_transform *transform;
	size_t total_transforms_len = 0;

	/*
	 * NOTE: We map the module to segments within a 32bit address range.
	 * This avoids the problem of call offsets larger than 32bits. The
	 * target program that we are ulexec'ing is always mapped to the same
	 * 32bit address at runtime, and therefore trampolines between the
	 * debugger and debugee can be sure to use 32bit offsets. Therefore
	 * we use MAP_32BIT with mmap. This worked just fine until we started
	 * running shiva as an interpreter, in which case the kernel is going
	 * to load the target executable to a much higher address space.
	 * In this case we won't use the MAP_32BIT.
	 */
	uint64_t mmap_flags = (ctx->flags & SHIVA_OPTS_F_INTERP_MODE) ? MAP_PRIVATE|MAP_ANONYMOUS :
	    MAP_PRIVATE|MAP_ANONYMOUS;
	uint64_t mmap_base = 0;

	/*
	 * If we are in interpreter mode, then we were not responsible for
	 * mapping the target executable into memory. The kernel will map the
	 * executable to a high address, making it impossible to use IP relative
	 * addressing or 5 byte jumps and calls that are dispatched between the
	 * module and the target executable. To correct this we make sure that the
	 * module is mapped to an address space right after the heap, to ensure
	 * that the module is within a 4GB range of the target executable.
	 */
	if (ctx->flags & SHIVA_OPTS_F_INTERP_MODE) {

		shiva_maps_iterator_t maps_iter;
		struct shiva_mmap_entry mmap_entry;

		shiva_maps_iterator_init(ctx, &maps_iter);
		while (shiva_maps_iterator_next(&maps_iter, &mmap_entry) == SHIVA_ITER_OK) {
			if (mmap_entry.mmap_type == SHIVA_MMAP_TYPE_HEAP) {
				mmap_base = ELF_PAGEALIGN(mmap_entry.base + mmap_entry.len, PAGE_SIZE);
				mmap_base += 4096 * 8;
				break;
			}
		}
		if (mmap_base == 0) {
			fprintf(stderr, "Warning, couldn't find heap location which we use to "
			    "indicate the load bias for the module '%s' text segment\n",
			    elf_pathname(&linker->elfobj));
		}
	} else {
		mmap_base = 0x6000000;
		mmap_flags |= MAP_32BIT;
		mmap_flags |= MAP_FIXED;
	}
	text_size_aligned = ELF_PAGEALIGN(linker->text_size, PAGE_SIZE);
	linker->text_mem = mmap((void *)mmap_base, text_size_aligned, PROT_READ|PROT_WRITE|PROT_EXEC,
	    mmap_flags, -1, 0);
	if (linker->text_mem == MAP_FAILED) {
		shiva_debug("mmap failed: %s\n", strerror(errno));
		return false;
	}
	shiva_debug("Module text segment: %p\n", linker->text_mem);
	linker->text_vaddr = (uint64_t)linker->text_mem;

	elf_section_iterator_init(&linker->elfobj, &shdr_iter);
	while (elf_section_iterator_next(&shdr_iter, &section) == ELF_ITER_OK) {
		if (section.flags & SHF_ALLOC) {
			if (section.flags & SHF_WRITE) // skip if its for the data segment
				continue;
			struct shiva_module_section_mapping *n;

			/*
			 * If we made it here then the section should be
			 * placed into the text segment :)
			 */
			if (section.size == 0)
				continue;
			if (strcmp(section.name, ".eh_frame") == 0) {
				shiva_debug("Skipping section .eh_frame (Unused)\n");
				continue;
			}
			if (strstr(section.name, ".note") != NULL) {
				shiva_debug("Skipping note sections\n");
				continue;
			}
			shiva_debug("Attempting to map section %s(offset: %zu) into text segment"
			    " at address %p\n", section.name, off, linker->text_mem + off);
			res = elf_section_map(linker, &linker->elfobj, linker->text_mem,
			    section, &off);
			if (res == false) {
				shiva_debug("elf_section_map failed\n");
				return false;
			}
			n = malloc(sizeof(*n));
			if (n == NULL) {
				shiva_debug("malloc failed\n");
				return false;
			}
			n->map_attribute = LP_SECTION_TEXTSEGMENT;
			n->vaddr = (unsigned long)linker->text_mem + count;
			n->offset = count; // offset within text segment that section lives at
			n->size = section.size;
			n->name = strdup(section.name);
			if (n->name == NULL) {
				shiva_debug("strdup: %s\n", strerror(errno));
				return false;
			}
			shiva_debug("Inserting section to segment mapping\n");
			shiva_debug("Address: %#lx\n", n->vaddr);
			shiva_debug("Offset: %#lx\n", n->offset);
			shiva_debug("Size: %#lx\n", n->size);
			TAILQ_INSERT_TAIL(&linker->tailq.section_maplist, n, _linkage);
			count = (module_has_transforms(linker) == true) ? off :  count + section.size;
		}
	}
	shiva_debug("count: %zu off: %zu\n", count, off);
	linker->plt_off = (off + 16) & ~15;
	elf_relocation_iterator_init(&linker->elfobj, &rel_iter);
	for (i = 0; elf_relocation_iterator_next(&rel_iter, &rel) == ELF_ITER_OK;) {
		if (i == 0) {
			struct shiva_module_section_mapping *n;

			n = malloc(sizeof(*n));
			if (n == NULL) {
				shiva_debug("malloc: %s\n", strerror(errno));
				return false;
			}
			n->map_attribute = LP_SECTION_TEXTSEGMENT;
			n->vaddr = linker->text_vaddr + linker->plt_off;
			n->size = section.size;
			n->name = strdup(".plt");
			if (n->name == NULL) {
				shiva_debug("strdup: %s\n", strerror(errno));
				return false;
			}
			TAILQ_INSERT_TAIL(&linker->tailq.section_maplist, n, _linkage);
		}
		/*
		 * ELF Relocs for creating internal PLT linkage to external (And local) calls.
		 * X86_64 --
		 *	Small code model: R_X86_64_PLT32 indicates that we are patching
		 *	call offsets into the PLT.
		 *
		 *	Large code model: R_X86_64_PLTOFF indicates that we are patching
		 *	an absolute address that will be called indirectly
		 * AARCH64 --
		 *	Small and Large code model will use R_AARCH_CALL26 relocations
		 *	to encode 26bit offsets.
		 */
#ifdef __x86_64__
		if (rel.type != R_X86_64_PLT32 && rel.type != R_X86_64_PLTOFF64)
			continue;
#elif __aarch64__
		if (rel.type != R_AARCH64_CALL26)
			continue;
#endif

		/*
		 * We have a tailq list for the address/offset of each PLT entry
		 * and it's corresponding symbol.
		 */
		struct shiva_module_plt_entry *plt;

		plt = calloc(1, sizeof(*plt));
		if (plt == NULL) {
			shiva_debug("malloc: %s\n", strerror(errno));
			return false;
		}
		plt->symname = strdup(rel.symname);
		if (plt->symname == NULL) {
			shiva_debug("strdup: %s\n", strerror(errno));
			return false;
		}
		plt->offset = linker->plt_off + i * sizeof(plt_stub);
		plt->vaddr = linker->text_vaddr + linker->plt_off + i * sizeof(plt_stub);
		plt->plt_count++;
		TAILQ_INSERT_TAIL(&linker->tailq.plt_list, plt, _linkage);

		shiva_debug("Copying PLT stub to %#lx, offset %#lx\n",
		    linker->text_vaddr + linker->plt_off + i * sizeof(plt_stub),
		    linker->plt_off + i * sizeof(plt_stub));

		memcpy(&linker->text_mem[linker->plt_off + i * sizeof(plt_stub)],
		    plt_stub, sizeof(plt_stub));
		i++;
	}
	return true;
}

static bool
get_tf_function_refs(struct shiva_ctx *ctx, struct shiva_module *linker,
    struct shiva_transform *transform)
{
	struct shiva_xref_site xref;
	struct shiva_branch_site *branch;
	shiva_xref_iterator_t xrefs;

	TAILQ_INIT(&transform->xref_list);
	TAILQ_INIT(&transform->branch_list);

	shiva_debug("get_tf_function_refs:\n");

	shiva_xref_iterator_init(ctx, &xrefs);
	while (shiva_xref_iterator_next(&xrefs, &xref) == SHIVA_ITER_OK) {
		if ((xref.flags & SHIVA_XREF_F_SRC_SYMINFO) == 0)
			continue;
		shiva_debug("Comparing %s and %s\n", xref.current_function.name, transform->target_symbol.name);
		if (strcmp(xref.current_function.name, transform->target_symbol.name) == 0) {
			shiva_debug("XREF site in transform target '%s'\n",
			    transform->target_symbol.name);
			struct shiva_xref_site *xp = shiva_malloc(sizeof(*xp));

			memcpy(xp, &xref, sizeof(*xp));
			TAILQ_INSERT_TAIL(&transform->xref_list, xp, _linkage);
		}
	}
	TAILQ_FOREACH(branch, &ctx->tailq.branch_tqlist, _linkage) {
		if ((branch->branch_flags & SHIVA_BRANCH_F_SRC_SYMINFO) == 0)
			continue;
		if (strcmp(branch->current_function.name, transform->target_symbol.name) == 0) {
			struct shiva_branch_site *tmp = shiva_malloc(sizeof(struct shiva_branch_site));

			memcpy(tmp, branch, sizeof(*branch));
			shiva_debug("BRANCH site in transform target '%s': %s\n",
			    transform->target_symbol.name, branch->insn_string);
			TAILQ_INSERT_TAIL(&transform->branch_list, tmp, _linkage);
		}
	}
	return true;
}

/*
 * TODO: Replace this ugly function. We just need to have a list of functions
 * sorted by address, created during the loading of the ELF ET_REL object.
 */
bool
next_function_by_address(elfobj_t *elfobj, uint64_t current_func, struct elf_symbol *out)
{
	elf_symtab_iterator_t sym_iter;
	struct elf_symbol symbol, orig, lo = {0};
	uint64_t lo_vaddr = current_func;
	size_t c = 0;
	bool found_lo_vaddr = false;

	elf_symtab_iterator_init(elfobj, &sym_iter);
	while (elf_symtab_iterator_next(&sym_iter, &symbol) == ELF_ITER_OK) {
		if (symbol.value >= current_func && symbol.type == STT_FUNC) {
			if (symbol.value == current_func) {
				memcpy(&orig, &symbol, sizeof(symbol));
				continue;
			}
			if (c++ == 0) {
				shiva_debug("c++ == 0\n");
				shiva_debug("lo_vaddr = %#lx(%s)\n", symbol.value, symbol.name);
				if (lo_vaddr != symbol.value)
					found_lo_vaddr = true;
				lo_vaddr = symbol.value;
				memcpy(&lo, &symbol, sizeof(symbol));
			} else {
				shiva_debug("if lo_vaddr: %#lx is > %#lx(%s)\n", lo_vaddr,
				    symbol.value, symbol.name);
				if (lo_vaddr > symbol.value) {
					found_lo_vaddr = true;
					lo_vaddr = symbol.value;
					shiva_debug("lo_vaddr now set to %#lx\n", symbol.value);
					memcpy(&lo, &symbol, sizeof(symbol));
				}
			}
		}
	}

	shiva_debug("Next STT_FUNC symbol is %#lx\n", lo_vaddr);
	if (found_lo_vaddr == true) {
		shiva_debug("Copying lo.value: %#lx to out\n", lo.value);
		memcpy(out, &lo, sizeof(*out));
	} else {
		shiva_debug("Copying orig symbol to out\n");
		memcpy(out, &orig, sizeof(*out));
	}
	return true;
}

#define SHIVA_HELPERS_MAX 4096

static bool
validate_helpers(struct shiva_ctx *ctx, struct shiva_module *linker)
{
	struct elf_section shdr;
	elf_section_iterator_t shdr_iter;
	struct elf_symbol symbol, target_sym;
	elf_symtab_iterator_t sym_iter;
	char *dst_symname;
	struct shiva_helper *helper;
	ENTRY e, *ep;

	(void) hcreate_r(SHIVA_HELPERS_MAX, &linker->cache.helpers);

	elf_symtab_iterator_init(&linker->elfobj, &sym_iter);
	while (elf_symtab_iterator_next(&sym_iter, &symbol) == ELF_ITER_OK) {
		if (symbol.type != STT_NOTYPE || symbol.bind != STB_GLOBAL)
			continue;
		if (strncasecmp(symbol.name, SHIVA_HELPER_CALL_EXTERNAL_ID,
		    strlen(SHIVA_HELPER_CALL_EXTERNAL_ID)) == 0) {
			dst_symname = strstr(symbol.name, "_orig_func_");
			if (dst_symname == NULL) {
				fprintf(stderr, "Invalid format to "
				    "SHIVA_HELPER_CALL_EXTERNAL\n");
				return false;
			}
			dst_symname += strlen("_orig_func_");
			shiva_debug("Function %s\n", dst_symname);
			if (elf_symbol_by_name(linker->target_elfobj,
				dst_symname, &target_sym) == false) {
				fprintf(stderr, "The symbol doesn't exist: %s not found in %s\n",
				    dst_symname, elf_pathname(linker->target_elfobj));
				return false;
			}

			e.key = (char *)symbol.name; /* i.e. __shiva_helper_orig_func */
			e.data = NULL;

			if (hsearch_r(e, FIND, &ep, &linker->cache.helpers) != 0)
				continue;

			helper = shiva_malloc(sizeof(*helper));
			helper->type = SHIVA_HELPER_CALL_EXTERNAL;
			memcpy(&helper->symbol, &target_sym, sizeof(struct elf_symbol));

			if (hsearch_r(e, ENTER, &ep, &linker->cache.helpers) == 0) {
				free(helper);
				fprintf(stderr, "Failed to add helper: %s\n", symbol.name);
				return false;
			}
			shiva_debug("Inserting helper record\n"
					"Helper type: SHIVA_HEPLER_CALL_EXTERNAL\n"
					"External symbol value: %#lx\n", target_sym.value);
			TAILQ_INSERT_TAIL(&linker->tailq.helper_list, helper, _linkage);
		}
	}

	return true;
}

/*
 * Transformations (formerly known as PTD)
 * If there are any transformations, make internal transformation
 * records.
 */
#define ARM_INSN_LEN 4

static bool
validate_transformations(struct shiva_ctx *ctx, struct shiva_module *linker)
{
	struct shiva_branch_site *branch;
	struct elf_section shdr;
	elf_section_iterator_t shdr_iter;
	/*
	 * tf_sym holds symbol data for the transform symbol found in the module,
	 * i.e. "__shiva_splice_insert_<func_name>" is a transformation directive
	 * stored as a symbol. The target_sym will hold the symbol data for the
	 * target function name in the target ELF binary.
	 */
	struct elf_symbol tf_sym, target_sym;
	elf_symtab_iterator_t sym_iter;
	struct shiva_transform *transform, *next_tf;
	uint64_t insert_vaddr, extend_vaddr, tf_val;
	char *dst_symname;
	char tmp[PATH_MAX];

	shiva_debug("Transform validator\n");
	/*
	 * PHASE-1 of transform validation:
	 * Scan the Shiva module for any symbol names that indicate
	 * transformation mnemonics, i.e. __shiva_splice_fn_name_<function_name>
	 * indicates that the user wants to splice code into <function_name> --
	 * We therefore create a transform entry for this splice request and
	 * we store the entry in a tailq-linked-list.
	 *
	 * Sanity checks on the transform data (symbol data) is performed.
	 */
	elf_symtab_iterator_init(&linker->elfobj, &sym_iter);
	while (elf_symtab_iterator_next(&sym_iter, &tf_sym) == ELF_ITER_OK) {
		shiva_debug("transform symbol '%s'\n", tf_sym.name);
		if (tf_sym.type == STT_FUNC) {
			if (strncmp(tf_sym.name, SHIVA_T_SPLICE_FUNC_ID,
			    strlen(SHIVA_T_SPLICE_FUNC_ID)) == 0) {
				shiva_debug("transform op: %s\n", SHIVA_T_SPLICE_FUNC_ID);
				dst_symname = strstr(tf_sym.name, "_fn_name_");
				if (dst_symname == NULL) {
					fprintf(stderr, "Invalid format to SHIVA_T_SPLICE_FUNCTION: %s\n",
					    tf_sym.name);
					return false;
				}
				dst_symname += strlen("_fn_name_");
				shiva_debug("Function %s\n", dst_symname);
				if (elf_symbol_by_name(linker->target_elfobj,
				    dst_symname, &target_sym) == false) {
					fprintf(stderr, "Transform target symbol doesn't exist: %s not found\n",
					    dst_symname);
					return false;
				}
				shiva_debug("Found symbol information in target executable, for %s\n",
				    dst_symname);
				transform = shiva_malloc(sizeof(*transform));
				transform->type = SHIVA_TRANSFORM_SPLICE_FUNCTION;
				memcpy(&transform->target_symbol, &target_sym,
				    sizeof(struct elf_symbol));
				memcpy(&transform->source_symbol, &tf_sym,
				    sizeof(struct elf_symbol));
				transform->name = (char *)target_sym.name;
				transform->ptr = NULL;
				shiva_debug("Source symbol '%s' value: %zu size: %zu\n",
				    transform->source_symbol.name, transform->source_symbol.value, transform->source_symbol.size);

				shiva_debug("Inserting transform entry: %s\n", transform->name);
				TAILQ_INSERT_TAIL(&linker->tailq.transform_list, transform, _linkage);
			}
		}
	}

	/*
	 * PHASE-2 of transform validation.
	 * We now pass over our linked list of transforms, and fill out the
	 * rest of each transform entry.
	 *
	 * For every transform entry of type: SHIVA_TRANFORM_SPLICE_FUNCTION, we
	 * must locate the corresponding transform inputs, which are two symbols:
	 * 1. __shiva_splice_insert_<func_name>
	 * 2. __shiva_splice_extend_<func_name>
	 * And read their stored values, from within the .shiva.transform section
	 * of the module. The values are stored as: transform->insert_vaddr, and
	 * transform->extend_vaddr respectively.
	 * Lastly we must build the tailq lists for branches and xrefs within the
	 * transform entry of the function we are splicing. All of these will need
	 * to be relinked at transformation time. All of this branch/xref data was
	 * collected by shiva_analyze_find_calls():shiva_analyze.c initially and
	 * get_tf_function_refs() will store the relevant entries for each transform.
	 */
	if (TAILQ_EMPTY(&linker->tailq.transform_list))
		shiva_debug("List is empty?\n");
	TAILQ_FOREACH(transform, &linker->tailq.transform_list, _linkage) {
		shiva_debug("Checking type: %d\n", transform->type);
		switch(transform->type) {
		case SHIVA_TRANSFORM_SPLICE_FUNCTION:
			shiva_debug("case SHIVA_TRANFORM_SPLICE_FUNCTION:\n");
			if (get_tf_function_refs(ctx, linker, transform) == false) {
				fprintf(stderr, "Failed to gather xref and branch data from %s\n",
				    transform->name);
				return false;
			}
			strcpy(tmp, SHIVA_T_SPLICE_INSERT_ID);
			strncat(tmp, transform->name,
			    PATH_MAX - strlen(SHIVA_T_SPLICE_INSERT_ID));
			tmp[sizeof(tmp) - 1] = '\0';
			shiva_debug("Checking '%s' symbol cache for %s\n",
			    elf_pathname(&linker->elfobj), tmp);
			if (elf_symbol_by_name(&linker->elfobj,
			   tmp, &tf_sym) == false) {
				fprintf(stderr, "Failed to find transform input '%s'\n",
				    tmp);
				goto fail;
			}
			shiva_debug("Looking for section at index %d\n", tf_sym.shndx);
			if (elf_section_by_index(&linker->elfobj, tf_sym.shndx,
			    &shdr) == false) {
				fprintf(stderr, "Failed to find section index %d\n",
				    tf_sym.shndx);
				goto fail;
			}
			if (strcmp(shdr.name, ".shiva.transform") != 0) {
				fprintf(stderr, "Symbol '%s' corresponds to wrong section: '%s'"
				    " and not '.shiva.transform'\n", tf_sym.name, shdr.name);
				goto fail;
			}
			assert(tf_sym.size == sizeof(Elf64_Addr) ||
			    tf_sym.size == sizeof(Elf32_Addr));
			typewidth_t tpw = tf_sym.size == 8 ? ELF_QWORD : ELF_DWORD;
			/*
			 * TO CLARIFY: We are reading from the .shiva.transform
			 * section + (symbol offset of __shiva_splice_insert_<func_name>)
			 * which holds the value of the patches insertion address.
			 */
			if (elf_read_offset(&linker->elfobj, shdr.offset + tf_sym.value,
			    &tf_val, tpw) == false) {
				fprintf(stderr, "Failed to read transform input '%s' value"
				    " at %#lx in %s\n", tf_sym.name, shdr.offset + tf_sym.value,
				    elf_pathname(&linker->elfobj));
				goto fail;
			}
			insert_vaddr = tf_val;
			shiva_debug("%s: (deferenced at offset %#lx): %#lx\n", tf_sym.name,
			    shdr.offset + tf_sym.value, tf_val);

			memset(tmp, 0, sizeof(tmp));
			strcpy(tmp, SHIVA_T_SPLICE_EXTEND_ID);
			strncat(tmp, transform->name,
			    PATH_MAX - strlen(SHIVA_T_SPLICE_EXTEND_ID));
			tmp[sizeof(tmp) - 1] = '\0';
			shiva_debug("Checking symbol cache for %s\n", tmp);
			if (elf_symbol_by_name(&linker->elfobj,
			    tmp, &tf_sym) == false) {
				fprintf(stderr, "Failed to find transform input '%s'\n",
				    tmp);
				goto fail;
			}
			shiva_debug("Looking for section at index %d\n", tf_sym.shndx);
			if (elf_section_by_index(&linker->elfobj, tf_sym.shndx,
			    &shdr) == false) {
				fprintf(stderr, "Failed to find section index %d\n",
				    tf_sym.shndx);
				goto fail;
			}
			if (strcmp(shdr.name, ".shiva.transform") != 0) {
				fprintf(stderr, "Symbol '%s' corresponds to wrong section: '%s'"
				    " and not '.shiva.transform'\n", tf_sym.name, shdr.name);
				goto fail;
			}
			assert(tf_sym.size == sizeof(Elf64_Addr) ||
			    tf_sym.size == sizeof(Elf32_Addr));
			tpw = tf_sym.size == 8 ? ELF_QWORD : ELF_DWORD;
			/*
			 * We are reading from variable __shiva_splice_extend_<fnname>
			 */
			if (elf_read_offset(&linker->elfobj, shdr.offset + tf_sym.value,
			    &tf_val, tpw) == false) {
				fprintf(stderr, "Failed to read transform input '%s' value"
				    " at %#lx in %s\n", tf_sym.name, shdr.offset + tf_sym.value,
				    elf_pathname(&linker->elfobj));
				goto fail;
			}
			extend_vaddr = tf_val;
			shiva_debug("%s: (deferenced at offset %#lx): %#lx\n", tf_sym.name,
			    shdr.offset + tf_sym.value, tf_val)
			/*
			 * If we've made it here, then we know that the transform
			 * arguments for SHIVA_T_SPLICE have been properly included
			 * in the Shiva module. Lets finish filling out the transform
			 * entry.
			 */

			/* Function offset where splice insertion happens
			 * TODO: Sanity checks on insert_vaddr, extend_vaddr
			 */
			shiva_debug("transform->offset = %#lx - %#lx\n", insert_vaddr,
			    target_sym.value);
			transform->offset = insert_vaddr - target_sym.value;
			transform->old_len = extend_vaddr - insert_vaddr;
			transform->new_len = transform->source_symbol.size;
			shiva_debug("transform->new_len: %#lx\n", transform->new_len);
			/*
			 * In ARM64 .text relocations are often used that access
			 * read-only data stored right in the .text at the end of
			 * a given function. We must make room for this read-only
			 * data at the end of a function, so that the code which
			 * accesses the data after it's relocated, works properly.
			 */
			struct elf_symbol next_func;
			struct elf_section text_shdr;
			bool res;

			shiva_debug("Calling next_function_by_address."
			    " source_symbol.value: %#lx and size %#lx\n",
			    transform->source_symbol.value, transform->source_symbol.size);
			res = next_function_by_address(&linker->elfobj,
			    transform->source_symbol.value, &next_func);
			if (res == false) {
				fprintf(stderr, "next_function_by_address() failed\n");
				return false;
			}
			/*
			 * If there is no next function beyond the current function
			 * ... Then write out N bytes. Where N is section_size - 
			 * function.offset + function.size
			 */
			shiva_debug("next_func.value: %#lx\n", next_func.value);
			shiva_debug("source_symbol.value: %#lx\n",
			    transform->source_symbol.value);
			if (elf_section_by_name(&linker->elfobj, ".text", &text_shdr) == false) {
				fprintf(stderr,
				    "elf_section_by_name(%p, \".text\", ...) failed\n", &linker->elfobj);
				return false;
			}
			if (next_func.value == transform->source_symbol.value) {
				/*
				 * There is no function that lives after
				 * transform->source_symbol.value
				 */
				size_t padlen;

				memcpy(&transform->next_func, &transform->source_symbol,
				    sizeof(struct elf_symbol));
				shiva_debug("shdr.size: %d source_symbol.value + size: %d\n",
				    text_shdr.size, transform->source_symbol.value + transform->source_symbol.size);
				padlen = text_shdr.size - (transform->source_symbol.value +
				    transform->source_symbol.size);
				shiva_debug("padlen = %d - %d + %d\n", 
				    text_shdr.size, transform->source_symbol.value, transform->source_symbol.size);
				transform->ext_len = padlen;
				shiva_debug("ext_len is %d bytes\n", transform->ext_len);
#if 0
				shiva_debug("Increasing new_len(%zu) by %zu bytes\n",
				    transform->new_len, padlen);
				transform->new_len += padlen;
#endif
			} else {
				/*
				 * A function does exist after transform->source_symbol.value
				 */
				size_t padlen;

				memcpy(&transform->next_func, &next_func, sizeof(next_func));
				shiva_debug("new_len is currently %d\n", transform->new_len);
				shiva_debug("%lx - %lx + %lx\n",
				    next_func.value, transform->source_symbol.value,
				    transform->source_symbol.size);
				shiva_debug("ext_len is %d bytes\n",
				    next_func.value -
				    (transform->source_symbol.value + transform->source_symbol.size));
				padlen = next_func.value -
				    (transform->source_symbol.value + transform->source_symbol.size);
				transform->ext_len = padlen;
			}
			shiva_debug("new_len is now: %d\n", transform->new_len);
			/*
			 * How does the splice behave?
			 * REPLACE: we are replacing B bytes of code with B bytes code.
			 * NOP_PAD: the patch code is smaller than the target, so pad it with nops.
			 * EXTEND: the patch code is larger than the target, so extend the function size.
			 * INJECT: (Coupled with extend) signifies an extension between two contiguous addresses;
			 * in other words we are not overwriting any code, just adding new code.
			 */
			if (transform->new_len == transform->old_len) {
				transform->flags |= SHIVA_TRANSFORM_F_REPLACE;
			} else if (transform->new_len < transform->old_len) {
				transform->flags |=
				    (SHIVA_TRANSFORM_F_NOP_PAD | SHIVA_TRANSFORM_F_REPLACE);
			} else if ((transform->new_len > transform->old_len) &&
				    transform->old_len > ARM_INSN_LEN) {
				transform->flags |=
				    (SHIVA_TRANSFORM_F_EXTEND);
			} else if (transform->old_len == ARM_INSN_LEN && transform->new_len > 0) {
				transform->flags |=
				    (SHIVA_TRANSFORM_F_EXTEND | SHIVA_TRANSFORM_F_INJECT);
				transform->offset += ARM_INSN_LEN;
				transform->old_len = 0;
			} else if (transform->old_len == 0 && transform->new_len == 0) {
				fprintf(stderr, "Invalid patch lengths. Length of patch: %zu,"
				    " Length of patch area: %zu\n", transform->new_len, transform->old_len);
				return false;
			}
			memset(tmp, 0, sizeof(tmp));
			strcpy(tmp, SHIVA_T_SPLICE_FUNC_ID);
			strncat(tmp, transform->name,
			    PATH_MAX - strlen(SHIVA_T_SPLICE_FUNC_ID));
			tmp[sizeof(tmp) - 1] = '\0';

			if (elf_symbol_by_name(&linker->elfobj, tmp,
			    &tf_sym) == false) {
				fprintf(stderr, "elf_symbol_by_name failed '%s'\n", tmp);
				goto fail;
			}
			if (elf_section_by_index(&linker->elfobj, tf_sym.shndx,
			    &shdr) == false) {
				fprintf(stderr, "elf_section_by_index failed, invalid index %d\n",
				    tf_sym.shndx);
				goto fail;
			}
			assert((transform->ptr = elf_offset_pointer(&linker->elfobj,
			    shdr.offset + tf_sym.value)) != NULL);
			/*
			 * transform->ptr should now point to something like
			 * __shiva_splice_fn_name_<func_name>();
			 * Which is a function in the module who's code is
			 * meant to be spliced into the target ELF function
			 * transform->name.
			 */
			shiva_debug("Finalized transform record '%s'\n", transform->name);
			shiva_debug("offset:\t%#lx\n", transform->offset);
			shiva_debug("old_len:\t%#lx\n", transform->old_len);
			shiva_debug("new_len:\t%#lx\n", transform->new_len);
			shiva_debug("flags:\t%#lx\n", transform->flags);
			shiva_debug("transform symbol: %s\n", transform->source_symbol.name);
			shiva_debug("target symbol: %s\n", transform->target_symbol.name);
		}
	}
	if (TAILQ_EMPTY(&linker->tailq.transform_list) == 0) {
		/*
		 * We have a transform entry in the list, so
		 * set the appropriate module/linker flag.
		 */
		shiva_debug("Setting transform flag for linker\n");
		linker->flags |= SHIVA_MODULE_F_TRANSFORM;
	}

	return true;

fail:
	free(transform);
	return false;
}

/*
 * Our linker has two modes:
 * 1. Link Shiva modules, who's init function is always STT_FUNC:shakti_main()
 * 2. Link a microcode patch driven by targetted symbol interposition.
 */
static void
set_linker_mode(struct shiva_module *linker)
{
	struct elf_symbol symbol;

	if (elf_symbol_by_name(&linker->elfobj, "shakti_main", &symbol) == false) {
		linker->mode = SHIVA_LINKING_MICROCODE_PATCH;
	} else {
		if (symbol.type != STT_FUNC || symbol.bind != STB_GLOBAL) {
			linker->mode = SHIVA_LINKING_MICROCODE_PATCH;
		} else {
			linker->mode = SHIVA_LINKING_MODULE;
		}
	}
	return;
}
static bool
apply_memory_protection(struct shiva_module *linker)
{
	if (mprotect(linker->text_mem,
	    ELF_PAGEALIGN(linker->text_size, PAGE_SIZE),
	    PROT_READ|PROT_EXEC) < 0) {
		perror("mprotect");
		return false;
	}
	return true;
}

/*
 * NOTE: const char *path: path to the ELF module
 */
bool
shiva_module_loader(struct shiva_ctx *ctx, const char *path, struct shiva_module **linkerptr, uint64_t flags)
{
	struct shiva_module *linker;
	elf_error_t error;
	bool res;
	uint64_t entry;
	char *shiva_path;

	linker = malloc(sizeof(struct shiva_module));
	if (linker == NULL) {
		shiva_debug("Malloc failed\n");
		return false;
	}
	memset(linker, 0, sizeof(*linker));
	linker->target_elfobj = &ctx->elfobj;
	linker->flags = flags;
	linker->shiva_base = ctx->shiva.base;
	linker->target_base = ctx->ulexec.base_vaddr;
	linker->ctx = ctx;
	*linkerptr = linker;

	shiva_debug("ctx_global: %p\n", ctx_global);
	shiva_debug("linker: %p\n", linker);
	TAILQ_INIT(&linker->tailq.transform_list);
	TAILQ_INIT(&linker->tailq.helper_list);
	TAILQ_INIT(&linker->tailq.section_maplist);
	TAILQ_INIT(&linker->tailq.plt_list);
	TAILQ_INIT(&linker->tailq.delayed_reloc_list);

	shiva_debug("elf_open_object(%s, ...)\n", path);

	/*
	 * Open the module ELF object (I.E. modules/shakti_runtime.o)
	 */
	res = elf_open_object(path, &linker->elfobj,
	    ELF_LOAD_F_STRICT, &error);
	if (res == false) {
		shiva_debug("1st. elf_open_object(%s, ...) failed: %s\n", path, elf_error_msg(&error));
		return false;
	}
	/*
	 * Open our self (The debugger/interpreter) ELF object.
	 */
	shiva_path = (ctx->flags & SHIVA_OPTS_F_INTERP_MODE) ?
	    elf_interpreter_path(&ctx->elfobj) : "/proc/self/exe";

	if (elf_open_object(shiva_path, &linker->self, ELF_LOAD_F_STRICT,
	    &error) == false) {
		shiva_debug("elf_open_object(%s, ...) failed: %s\n",
		    "/proc/self/exe", elf_error_msg(&error));
		return false;
	}
	memcpy(&ctx->shiva_elfobj, &linker->self, sizeof(elfobj_t));

	set_linker_mode(linker);
	switch(linker->mode) {
	case SHIVA_LINKING_MODULE:
		shiva_debug("Shiva linker mode: <MODULE>\n");
		break;
	case SHIVA_LINKING_MICROCODE_PATCH:
		shiva_debug("Shiva linker mode: <MICROCODE PATCH>\n");
		break;
	case SHIVA_LINKING_UNKNOWN:
		shiva_debug("Unknown linking mode, quitting\n");
		return false;
	}
	if (validate_transformations(ctx, linker) == false) {
		fprintf(stderr, "Failed to validate transformations\n");
		return false;
	}
	if (validate_helpers(ctx, linker) == false) {
		fprintf(stderr, "Failed to validate helpers\n");
		return false;
	}
	if (calculate_text_size(linker) == false) {
		shiva_debug("Failed to calculate .text size for parasite module\n");
		return false;
	}
	if (calculate_data_size(linker) == false) {
		shiva_debug("Failed to calculate .data size for parasite module\n");
		return false;
	}
	if (create_text_image(ctx, linker) == false) {
		shiva_debug("Failed to create text segment\n");
		return false;
	}
	if (create_data_image(ctx, linker) == false) {
		shiva_debug("Failed to create data segment\n");
		return false;
	}
	if (relocate_module(linker) == false) {
		shiva_debug("Failed to relocate module\n");
		return false;
	}
	if (patch_plt_stubs(linker) == false) {
		shiva_debug("Failed to patch PLT stubs\n");
		return false;
	}
	if (resolve_pltgot_entries(linker) == false) {
		shiva_debug("Failed to resolve PLTGOT entries\n");
		return false;
	}
	if ((linker->flags & SHIVA_MODULE_F_DELAYED_RELOCS) == 0) {
		if (apply_memory_protection(linker) == false) {
			shiva_debug("Failed to apply module segment memory protection\n");
			return false;
		}
	}

	/*
	 * If we are linking a Shiva module, then we pass control to the
	 * init function of the module "shakti_main()"
	 * Otherwise, if we are linking a microcode patch we don't pass
	 * control to it directly, it is executed through patching hooks
	 * within the target executable.
	 */
	if (linker->mode == SHIVA_LINKING_MICROCODE_PATCH) {
		shiva_debug("Finished relocating patch\n");
		if (apply_external_patch_links(ctx, linker) == false) {
			shiva_debug("Failed to apply patches to target executable: %s\n",
			    elf_pathname(linker->target_elfobj));
			return false;
		}
		return true;
	}

	if (module_entrypoint(linker, &entry) == false) {
		shiva_debug("Failed to get module entry point\n");
		return false;
	}
	shiva_debug("ModuleEntry point address: %#lx\n", entry);
	transfer_to_module(ctx, entry);
	shiva_debug("Successfully executed module\n");
	return true;
}
