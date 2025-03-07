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

typedef struct func_entry {
	uint64_t base_vaddr;
	struct elf_symbol symbol;
	struct elf_section section;
	size_t func_len;
	uint64_t flags;
	int new_entry_number;
	int old_entry_number;
	TAILQ_HEAD(, reloc_entry) reloc_list;
	TAILQ_ENTRY(func_entry) _linkage;
} func_entry_t;

typedef struct aslr_ctx {
	TAILQ_HEAD(, func_entry) orig_func_list; // orig funclist
	TAILQ_HEAD(, func_entry) aslr_func_list; // re-ordered funclist
	uint64_t base_vaddr;
} aslr_ctx_t;


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
			if (symbol.value == elf_entry_point(&ctx->elfobj))
				fe->flags |= ASLR_FUNC_F_ENTRYPOINT;
			fe->symbol = symbol;
			fe->section = text;
			fe->base_vaddr = symbol.value;
			fe->func_len = symbol.size;

			TAILQ_INIT(&fe->reloc_list);

			/*
			 * The .rela.text section in an ELF executable will
			 * contain r_offset values that are absolute vs.
			 * relative to the beginning of the .text section
			 * as is the case with ET_REL objects. This makes
			 * sense since the absolute addresses didn't exist
			 * until the ET_REL objects were linked into a final
			 * executable, and thus the relocation tables get
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
				re->rel = rel;
				printf("Inserting relocation for .text in %s\n",
				    symbol.name);
				TAILQ_INSERT_TAIL(&fe->reloc_list, re, _linkage);
			}
			printf("Inserting function %s\n", fe->symbol.name);
			fe->old_entry_number = fn_count;
			TAILQ_INSERT_TAIL(&aslr->orig_func_list, fe, _linkage);
			*fn_count++;
		}
	}
	return true;
}

bool
reorder_func_list(struct shiva_ctx *ctx, struct aslr_ctx *aslr,
    size_t fn_count)
{
	struct func_entry *fe;
	int *order_map = alloca(fn_count * sizeof(size_t));
	int order, i;

	for (i = 0; i < fn_count; i++)
		order_map[i] = -1;

	TAILQ_INIT(&aslr->aslr_func_list);

	TAILQ_FOREACH(fe, &aslr->orig_func_list, _linkage) {
		order = rand() % fn_count;
		if (order_map[order] != -1)
			continue;
		order_map[order] = rand() % fn_count;
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

	if (reorder_func_list(ctx, &aslr, fn_count) == false) {
		fprintf(stderr, "reorder_func_list() failed\n");
		return -1;
	}
}
