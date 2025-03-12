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
	TAILQ_HEAD(, func_entry) aslr_func_list; // re-ordered funclist
	uint64_t base_vaddr;
} aslr_ctx_t;

#define HEAP_INITIALIZER NULL

struct elf_section text_section, got_section;
uint8_t *heap_buf = HEAP_INITIALIZER;

#define CHUNK_SIZE 32

void *
my_malloc(size_t len, uint8_t **mem)
{
	static int alloc_lens = 0;

	if (*mem == NULL) {
		*mem = mmap(NULL, 0x200000,
		    PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (*mem == MAP_FAILED) {
			printf("malloc failed with mmap\n");
			exit(-1);
		}
		return (void *)*mem;
	}
	*mem += (len = len + CHUNK_SIZE & ~(CHUNK_SIZE - 1));
	printf("Allocating %zu bytes with my_malloc\n", len);
	return (void *)((char *)*mem - len);
}

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
	TAILQ_INIT(&aslr->aslr_func_list);

	printf("Getting .text section\n");

	if (elf_section_by_name(&ctx->elfobj, ".text", &text) == false) {
		fprintf(stderr, "Failed to get section .text\n");
		return false;
	}
	text_section = text;

	if (elf_section_by_name(&ctx->elfobj, ".got", &got_section) == false ) {
		fprintf(stderr, "Failed to get section .got\n");
		return false;
	}
	printf("Iterating over functions\n");
	elf_symtab_iterator_init(&ctx->elfobj, &sym_iter);
	while (elf_symtab_iterator_next(&sym_iter, &symbol) == ELF_ITER_OK) {
		if (symbol.type != STT_FUNC)
			continue;
		if (symbol.bind != STB_GLOBAL)
			continue;
		printf("Found global function. Is it > than %#lx and <= %#lx\n", text.address, text.address + text.size);
		if (symbol.value >= text.address &&
		    symbol.value < text.address + text.size) {
			struct func_entry *fe;

			printf("Allocating function entry\n");
			fflush(stdout);
			fe = calloc(1, sizeof(*fe));
			if (fe == NULL) {
				perror("calloc");
				return false;
			}

			/*
			 * This function lives in the .text
			 */
			if (symbol.value == elf_entry_point(&ctx->elfobj)) {
				printf("Found function %s with entrypoint\n",
				    symbol.name);
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
				printf("Inserting relocation type %lu for .text in %s\n",
				    re->rel.type, symbol.name);
				TAILQ_INSERT_TAIL(&fe->reloc_list, re, _linkage);
			}
			printf("Inserting function %s\n", fe->symbol.name);
			fe->runtime_vaddr = fe->base_vaddr + ctx->ulexec.base_vaddr;
			/*
			 * Create new memory mapping to move function into.
			 */
			fe->n_mem = mmap(NULL, fe->func_len, PROT_READ|PROT_WRITE|PROT_EXEC,
			    MAP_32BIT|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
			if (fe->n_mem == MAP_FAILED) {
				perror("mmap");
				return false;
			}
			fe->new_base_vaddr = (uint64_t)fe->n_mem;
			printf("NEW BASE ADDRESS OF %s is %#lx\n", fe->symbol.name, fe->new_base_vaddr);
			fe->o_mem = (uint8_t *)fe->runtime_vaddr;
			TAILQ_INSERT_TAIL(&aslr->orig_func_list, fe, _linkage);
			*fn_count++;
		}
	}
	return true;
}

bool
relocate_function(struct shiva_ctx *ctx, struct aslr_ctx *aslr, struct func_entry *fe)
{
	uint64_t page_vaddr;
	struct reloc_entry *rel_entry;
	bool res;

	printf("Fixing up function %s\n", fe->symbol.name);

	TAILQ_FOREACH(rel_entry, &fe->reloc_list, _linkage) {
		uint8_t *r_ptr = (fe->flags & ASLR_FUNC_F_ENTRYPOINT) ?
		    (uint8_t *)(ctx->ulexec.base_vaddr + rel_entry->rel.offset) : fe->n_mem + rel_entry->rel.offset;
		uint64_t rel_addr = (uint64_t)r_ptr;
		uint32_t rel_val;
		uint64_t plt_addr;
		struct elf_plt plt;
		struct elf_section shdr;
		uint64_t symval;
		struct elf_symbol symbol;
		char *p;

		page_vaddr = (uint64_t)r_ptr & ~4095;

		p = strchr(rel_entry->rel.symname, '@');
		if (p != NULL)
			*p = '\0';

		printf("Relocation type: %lu\n", rel_entry->rel.type);
		printf("Relocation offset: %#lx\n", rel_entry->rel.offset);
		printf("Relunit: %p\n", r_ptr);

		(void )mprotect((void *)page_vaddr, 4096, PROT_READ|PROT_WRITE|PROT_EXEC);

		switch(rel_entry->rel.type) {
		case R_X86_64_GOTPCREL:
			printf("R_X86_64_GOTPCREL, target symbol %s\n", rel_entry->rel.symname);
			break;
		case R_X86_64_GOTPCRELX:
			printf("R_X86_64_GOTPCRELX\n");
			if (strcmp(rel_entry->rel.symname, "__libc_start_main") == 0) {
				printf("Ignoring relocation with target symbol __libc_start_main\n");
				break;
			}
			break;
		case R_X86_64_PLT32: /* L + A - P */
			printf("R_X86_64_PLT32\n");
			res = elf_plt_by_name(&ctx->elfobj, rel_entry->rel.symname,
			    &plt);
			if (res == false) {
				fprintf(stderr, "elf_plt_by_name() failed on %s\n",
				    rel_entry->rel.symname);
				return false;
			}
			plt_addr = plt.addr + ctx->ulexec.base_vaddr;
			rel_val = plt_addr + rel_entry->rel.addend - rel_addr;
			printf("Setting X86_64_PLT32 reloc value to %x (destination symbol is PLT entry %#lx)\n",
			    rel_val, plt_addr);
			*(uint32_t *)r_ptr = rel_val;
			printf("Setting ptr %p to %#lx succeeded\n", r_ptr, rel_val);
			break;
		case R_X86_64_PC32: /* S + A - P */
			printf("R_X86_64_PC32\n");
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
				printf("Setting R_X86_64_PC32 reloc value to %#x (destination symbol %s:%#lx)\n",
				    rel_val, rel_entry->rel.symname, symval);
				*(uint32_t *)&r_ptr[0] = rel_val;
				break;
			} else {
				if (elf_symbol_by_name(&ctx->elfobj, rel_entry->rel.symname,
				    &symbol) == true) {
					struct func_entry *tmp;

					if (symbol.type == STT_FUNC) {
						printf("Searching for symbol %s\n", symbol.name);
						TAILQ_FOREACH(tmp, &aslr->orig_func_list, _linkage) {
							if (strcmp(tmp->symbol.name, rel_entry->rel.symname) != 0)
								continue;
							symval = tmp->new_base_vaddr;
							rel_val = symval + rel_entry->rel.addend - rel_addr;
							printf("Setting X86_64_PC32 reloc value to %#x"
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
	(void)mprotect((void *)page_vaddr, 4096, PROT_READ|PROT_EXEC);
	return true;
}

bool
move_function(struct shiva_ctx *ctx, struct aslr_ctx *aslr, struct func_entry *fe)
{

	size_t delta;
	struct reloc_entry *rel_entry;

	printf("Moving function %s\n", fe->symbol.name);
	memcpy(fe->n_mem, (uint8_t *)fe->runtime_vaddr, fe->func_len);
	delta = fe->base_vaddr - text_section.address;
	TAILQ_FOREACH(rel_entry, &fe->reloc_list, _linkage) {
		delta = rel_entry->rel.offset - fe->base_vaddr;
		printf("Updating relocation type %lu: changing offset from %#lx to %#lx\n", 
		    rel_entry->rel.type, rel_entry->rel.offset, delta);

		rel_entry->rel.offset = delta;
	}
	printf("Calling relocate_function on %s\n", fe->symbol.name);
	return relocate_function(ctx, aslr, fe);
}

bool
remove_old_function(struct shiva_ctx *ctx, struct func_entry *fe)
{
	int ret;

	/*
	 * Simply zero it out
	 */
	printf("%s -- len: %zu at %#lx\n", fe->symbol.name, fe->func_len, fe->runtime_vaddr);
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
			printf("Fixing up entrypoint code\n");
			res = relocate_function(ctx, aslr, fe);
			if (res == false) {
				fprintf(stderr, "Failed to relocate entrypoint function %s\n",
				    fe->symbol.name);
				return false;
			}
			continue;
		}
		res = move_function(ctx, aslr, fe);		
		if (res == false) {
			fprintf(stderr, "Failed to move function %s\n", fe->symbol.name);
			return false;
		}
		printf("Removing old function %s\n", fe->symbol.name);
		res = remove_old_function(ctx, fe);
		printf("Finished removing old function\n");
	}
	return true;
}

int
shiva_init(struct shiva_ctx *ctx)
{
	struct aslr_ctx aslr;
	size_t fn_count;

	printf("Calling build_func_list\n");
	if (build_func_list(ctx, &aslr, &fn_count) == false) {
		fprintf(stderr, "build_func_list() failed on .text\n");
		return -1;
	}
	
	if (randomize_func_locations(ctx, &aslr, fn_count) == false) {
		fprintf(stderr, "randomize_func_locations() failed\n");
		return -1;
	}
}
