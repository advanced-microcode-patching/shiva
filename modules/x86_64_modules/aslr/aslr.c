#define _GNU_SOURCE
#include "../../include/shiva_module.h"
#include "../../../shiva.h"
#include "/opt/elfmaster/include/libelfmaster.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/queue.h>
/*
 * These function entries are a list of all
 * function within the .text section. We will
 * use transformations to modify the relocations
 * so that we can relocate the newly ordered
 * functions.
 */

typedef struct reloc_entry {
	struct elf_relocation rel;
	TAILQ_ENTRY(reloc_entry) _linkage;
} reloc_entry_t;

#define ASLR_FUNC_F_ENTRYPOINT	(1 << 0) // is pointed to by ehdr->e_entry

#define ELF_RUNTIME_BASE(x) (x + ctx->ulexec.base_vaddr)

typedef struct func_entry {
	uint64_t base_vaddr;	// on disk
	uint64_t runtime_vaddr; // after initial ASLR at runtime
	uint64_t new_base_vaddr; // at runtime after Granular ASLR (New location)
	uint8_t *o_mem;		// memory of old location
	uint8_t *n_mem;		// memory mapping of new location
	struct elf_symbol symbol;
	struct elf_section section;
	size_t func_len;
	uint64_t flags;
	TAILQ_HEAD(, reloc_entry) reloc_list;
	TAILQ_ENTRY(func_entry) _linkage;
} func_entry_t;

typedef struct aslr_ctx {
	TAILQ_HEAD(, func_entry) orig_func_list; // orig funclist
	uint64_t base_vaddr;
} aslr_ctx_t;

#define HEAP_INITIALIZER NULL

struct elf_section text_section, got_section;

bool
build_func_list(struct shiva_ctx *ctx, struct aslr_ctx *aslr,
    size_t *fn_count)
{
	size_t text_size;
	uint64_t text_addr;
	struct elf_section text;
	struct elf_symbol symbol;
	elf_relocation_iterator_t rel_iter;
	elf_symtab_iterator_t sym_iter;
	struct elf_relocation rel;

	TAILQ_INIT(&aslr->orig_func_list);

	if (elf_section_by_name(&ctx->elfobj, ".text", &text) == false) {
		fprintf(stderr, "Failed to get section .text\n");
		return false;
	}
	text_section = text;

	if (elf_section_by_name(&ctx->elfobj, ".got", &got_section) == false ) {
		fprintf(stderr, "Failed to get section .got\n");
		return false;
	}
	elf_symtab_iterator_init(&ctx->elfobj, &sym_iter);
	while (elf_symtab_iterator_next(&sym_iter, &symbol) == ELF_ITER_OK) {
		if (symbol.type != STT_FUNC)
			continue;
		if (symbol.bind != STB_GLOBAL)
			continue;
		if (symbol.value >= text.address &&
		    symbol.value < text.address + text.size) {
			struct func_entry *fe;

			fe = calloc(1, sizeof(*fe));
			if (fe == NULL) {
				perror("calloc");
				return false;
			}

			/*
			 * This function lives in the .text
			 */
			if (symbol.value == elf_entry_point(&ctx->elfobj)) {
				fe->flags |= ASLR_FUNC_F_ENTRYPOINT;
			}
			fe->symbol = symbol;
			fe->section = text;
			fe->base_vaddr = symbol.value;
			fe->func_len = symbol.size;

			TAILQ_INIT(&fe->reloc_list);

			/*
			 * The .rela.text section in an ELF executable will
			 * contain r_offset values that are absolute values vs.
			 * values that are relative to the beginning of the
			 * .text section as is the case with ET_REL objects.
			 * This makes sense since the absolute addresses didn't
			 * exist until the ET_REL objects were linked into a
			 * final executable, and thus the relocation tables get
			 * updated with the absolute r_offset's.
			 *
			 * NOTE: See -z --emit-relocs
			 */
			elf_relocation_iterator_init(&ctx->elfobj, &rel_iter);
			while (elf_relocation_iterator_next(&rel_iter, &rel)
			    == ELF_ITER_OK) {
				if (strcmp(rel.shdrname, ".rela.text") != 0)
					continue;
				if (rel.offset < fe->base_vaddr)
					continue;
				if (rel.offset >= fe->base_vaddr + fe->func_len)
					continue;
				/*
				 * Only process relocs that are fixing up the
				 * current function.
				 */
				struct reloc_entry *re = malloc(sizeof(*re));
				if (re == NULL) {
					perror("malloc");
					return false;
				}
				memcpy(&re->rel, &rel, sizeof(struct elf_relocation));
				TAILQ_INSERT_TAIL(&fe->reloc_list, re, _linkage);
			}
			fe->runtime_vaddr = fe->base_vaddr + ctx->ulexec.base_vaddr;
			/*
			 * Create new memory mapping to move function into.
			 */
			fe->n_mem = mmap(NULL/*(void *)ctx->ulexec.base_vaddr*/, fe->func_len, PROT_READ|PROT_WRITE|PROT_EXEC,
			    MAP_32BIT|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
			if (fe->n_mem == MAP_FAILED) {
				perror("mmap");
				return false;
			}
			fe->new_base_vaddr = (uint64_t)fe->n_mem;
			fe->o_mem = (uint8_t *)fe->runtime_vaddr;
			TAILQ_INSERT_TAIL(&aslr->orig_func_list, fe, _linkage);
			*fn_count++;
		}
	}
	return true;
}

#define ASLR_REL_F_NEEDS_PLTGOT (1 << 0)

bool
relocate_function(struct shiva_ctx *ctx, struct aslr_ctx *aslr, struct func_entry *fe)
{
	uint64_t page_vaddr;
	struct reloc_entry *rel_entry;
	bool res;
	uint8_t movabs_rdi[] = "\x48\xbf\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t rip_call[] = "\xff\x15\x00\x00\x00\x00";
	uint64_t rel_flags = 0;

	if (fe->flags & ASLR_FUNC_F_ENTRYPOINT) {
		shiva_debug("RELOCATIONG ENTRY POINT %s\n", fe->symbol.name);
	}
	TAILQ_FOREACH(rel_entry, &fe->reloc_list, _linkage) {
		uint8_t *r_ptr = (fe->flags & ASLR_FUNC_F_ENTRYPOINT) ?
		    (uint8_t *)(ctx->ulexec.base_vaddr + rel_entry->rel.offset) :
		    fe->n_mem + rel_entry->rel.offset;
		uint64_t rel_addr = (uint64_t)r_ptr;
		uint64_t rel_val;
		uint64_t plt_addr;
		struct elf_plt plt;
		struct elf_section shdr, got;
		uint64_t symval;
		struct elf_symbol symbol;
		char *p;

		page_vaddr = (uint64_t)r_ptr & ~4095;

		p = strchr(rel_entry->rel.symname, '@');
		if (p != NULL)
			*p = '\0';

		shiva_debug("Relocation type: %lu\n", rel_entry->rel.type);
		shiva_debug("Relocation offset: %#lx\n", rel_entry->rel.offset);
		shiva_debug("Relunit: %p\n", r_ptr);
		shiva_debug("Symbol name: %s\n", rel_entry->rel.symname);

		(void )mprotect((void *)page_vaddr, 4096, PROT_READ|PROT_WRITE|PROT_EXEC);

		switch(rel_entry->rel.type) {
		case R_X86_64_GOTPC64: /* GOT - P + A */
			if (elf_section_by_name(&ctx->elfobj, ".got", &got) == false) {
				fprintf(stderr, "elf_section_by_name() failed on .got\n");
				return false;
			}
			shiva_debug("R_X86_64_GOTPC64\n");
			rel_val = ELF_RUNTIME_BASE(got.address) - rel_addr + rel_entry->rel.addend;
			shiva_debug("rel_val = %#lx - %#lx + %#lx\n", ELF_RUNTIME_BASE(got.address));
			shiva_debug("Setting %p to %#lx\n", r_ptr, rel_val);
			*(uint64_t *)r_ptr = rel_val;
			break;
		case R_X86_64_GOTOFF64:
			shiva_debug("R_X86_64_GOTOFF64\n");
			if (elf_symbol_by_name(&ctx->elfobj, rel_entry->rel.symname, &symbol) == false) {
				fprintf(stderr, "elf_symbol_by_name failed on %s\n", symbol.name);
				return false;
			}
			if (strncmp(rel_entry->rel.symname, ".LC", 3) == 0) {
				if (elf_section_by_name(&ctx->elfobj, ".got", &got) == false) {
					fprintf(stderr, "elf_section_by_name() failed on .got\n");
					return false;
				}
				rel_val = ELF_RUNTIME_BASE(symbol.value) + rel_entry->rel.addend -
				    ELF_RUNTIME_BASE(got.address);
			} else {
				shiva_debug("UNHANDLED relocation for symname %s\n", rel_entry->rel.symname);
				// TODO
			}
			shiva_debug("R_X86_64_GOTOFF64 setting r_ptr(%p) to %#x\n",
			    r_ptr, rel_val);
			*(int64_t *)r_ptr = rel_val;
			break;
		case R_X86_64_PLTOFF64: /* L - GOT + A */
			shiva_debug("R_X86_64_PLTOFF64\n");
			if (elf_plt_by_name(&ctx->elfobj, rel_entry->rel.symname,
			    &plt) == false) {
				fprintf(stderr, "elf_plt_by_name() failed on %s\n",
				    rel_entry->rel.symname);
				return false;
			}
			if (elf_section_by_name(&ctx->elfobj, ".got", &got) == false) {
				fprintf(stderr, "elf_section_by_name() failed on .got\n");
				return false;
			}
			symval = plt.addr + ctx->ulexec.base_vaddr;
			shiva_debug("symval:(%#lx) - got:(%#lx) + addend(%#lx)\n",
			    symval, ELF_RUNTIME_BASE(got.address), rel_entry->rel.addend);
			rel_val = symval - ELF_RUNTIME_BASE(got.address) + rel_entry->rel.addend;
			shiva_debug("rel_val: %#x\n", rel_val);
			shiva_debug("Setting PLT encoded-offset to GOT offset %#lx\n", got.address +
			    rel_entry->rel.addend);
			*(uint32_t *)r_ptr = rel_val;
			break;
#if 0
		case R_X86_64_GOTPCREL:
			//printf("R_X86_64_GOTPCREL, target symbol %s\n", rel_entry->rel.symname);
			break;
		case R_X86_64_GOTPCRELX:
			//printf("R_X86_64_GOTPCRELX\n");
			if (strcmp(rel_entry->rel.symname, "__libc_start_main") == 0) {
				printf("Ignoring relocation with target symbol __libc_start_main\n");
				break;
			}
			break;
		case R_X86_64_PLT32: /* L + A - P */
			shiva_debug("R_X86_64_PLT32\n");
			res = elf_plt_by_name(&ctx->elfobj, rel_entry->rel.symname,
			    &plt);
			if (res == false) {
				fprintf(stderr, "elf_plt_by_name() failed on %s\n",
				    rel_entry->rel.symname);
				return false;
			}
			plt_addr = plt.addr + ctx->ulexec.base_vaddr;
			rel_val = plt_addr + rel_entry->rel.addend - rel_addr;
			shiva_debug("Setting X86_64_PLT32 reloc value to %x (destination symbol is PLT entry %#lx)\n",
			    rel_val, plt_addr);
			*(uint32_t *)r_ptr = rel_val;
			break;
#endif
		case R_X86_64_PC32: /* S + A - P */
			shiva_debug("R_X86_64_PC32\n");
			if (rel_entry->rel.symname[0] == '.') {
				res = elf_section_by_name(&ctx->elfobj, rel_entry->rel.symname,
				    &shdr);
				if (res == false) {
					fprintf(stderr, "elf_section_by_name() on %s failed\n",
					    rel_entry->rel.symname);
					return false;
				}
				symval = ELF_RUNTIME_BASE(shdr.address);
				rel_val = symval + rel_entry->rel.addend - rel_addr;
				shiva_debug("Setting R_X86_64_PC32 reloc value to %#x (destination symbol %s:%#lx)\n",
				   rel_val, rel_entry->rel.symname, symval);
				*(uint32_t *)&r_ptr[0] = rel_val;
				break;
			} else {
				if (elf_symbol_by_name(&ctx->elfobj, rel_entry->rel.symname,
				    &symbol) == true) {
					struct func_entry *tmp;

					if (symbol.type == STT_FUNC) {
						shiva_debug("Searching for symbol %s\n", symbol.name);
						TAILQ_FOREACH(tmp, &aslr->orig_func_list, _linkage) {
							if (strcmp(tmp->symbol.name, rel_entry->rel.symname) != 0)
								continue;
							if (fe->flags & ASLR_FUNC_F_ENTRYPOINT) {
								if (strcmp(tmp->symbol.name, "main") == 0) {
									uint8_t *new_r_ptr;

									new_r_ptr = r_ptr + 6;
									uint32_t offset = *(uint32_t *)new_r_ptr;
									*(uint32_t *)&rip_call[2] = offset - 3;
									*(uint64_t *)&movabs_rdi[2] = tmp->new_base_vaddr;
									new_r_ptr = r_ptr - 3;
									memcpy(new_r_ptr, movabs_rdi, sizeof(movabs_rdi));
									new_r_ptr += sizeof(movabs_rdi) - 1;
									memcpy(new_r_ptr, rip_call, sizeof(rip_call));
									break;
								}
							}
							symval = tmp->new_base_vaddr;
							rel_val = symval + rel_entry->rel.addend - rel_addr;
							shiva_debug("Setting X86_64_PC32 reloc value to %#x"
							    " destination symbol %s:%#lx)\n", rel_val,
							    rel_entry->rel.symname, symval);
							*(uint32_t *)r_ptr = rel_val;
						}
					}
				}
				break;
			}
		}
	}

	(void)mprotect((void *)page_vaddr,
	    4096,
	    PROT_READ|PROT_EXEC);

	return true;
}

bool
move_function(struct shiva_ctx *ctx, struct aslr_ctx *aslr, struct func_entry *fe)
{

	size_t delta;
	struct reloc_entry *rel_entry;

	/*
	 * Copy function code from its old address to its new address
	 */
	memcpy(fe->n_mem, (uint8_t *)fe->runtime_vaddr, fe->func_len);
	/*
	 * Update the relocation entries for that function so that they
	 * reflect the correct r_offset's after it is moved.
	 */
	TAILQ_FOREACH(rel_entry, &fe->reloc_list, _linkage) {
		delta = rel_entry->rel.offset - fe->base_vaddr;
		rel_entry->rel.offset = delta;
	}
	/*
	 * Now that function has been moved to a new location
	 * fixup the function using the modified relocation records.
	 */
	return relocate_function(ctx, aslr, fe);
}

bool
remove_old_function(struct shiva_ctx *ctx, struct func_entry *fe)
{
	int ret;

	/*
	 * Simply zero it out
	 */
	ret = mprotect((void *)(fe->runtime_vaddr & ~4095), fe->func_len, PROT_READ|PROT_WRITE|PROT_EXEC);
	memset((void *)fe->runtime_vaddr, 0, fe->func_len - 1);
	ret = mprotect((void *)(fe->runtime_vaddr & ~4095), fe->func_len, PROT_READ|PROT_EXEC);

	return ret ? false : true;
}

bool
randomize_func_locations(struct shiva_ctx *ctx, struct aslr_ctx *aslr,
    size_t fn_count)
{
	struct func_entry *fe;
	bool res;

	(void)fn_count;

	TAILQ_FOREACH(fe, &aslr->orig_func_list, _linkage) {
		if (fe->flags & ASLR_FUNC_F_ENTRYPOINT) {
			/*
			 * This function is probably _start and
			 * we therefore do not move it, we leave it
			 * as the entrypoint, but we must fixup its
			 * relocations to point to the new main() etc.
			 */
			res = relocate_function(ctx, aslr, fe);
			if (res == false) {
				fprintf(stderr, "Failed to relocate entrypoint function %s\n",
				    fe->symbol.name);
				return false;
			}
			continue;
		}
		shiva_debug("Moving function: %s\n", fe->symbol.name);
		res = move_function(ctx, aslr, fe);		
		if (res == false) {
			fprintf(stderr, "Failed to move function %s\n", fe->symbol.name);
			return false;
		}
		res = remove_old_function(ctx, fe);
	}
	return true;
}

int
shiva_init(struct shiva_ctx *ctx)
{
	struct aslr_ctx aslr;
	size_t fn_count;

	if (build_func_list(ctx, &aslr, &fn_count) == false) {
		fprintf(stderr, "build_func_list() failed on .text\n");
		return -1;
	}
	
	if (randomize_func_locations(ctx, &aslr, fn_count) == false) {
		fprintf(stderr, "randomize_func_locations() failed\n");
		return -1;
	}
}
