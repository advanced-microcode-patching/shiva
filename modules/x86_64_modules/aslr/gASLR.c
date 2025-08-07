/*
 * X86_64 gASLR by Ryan O'Neill
 * A 2025 Shiva module
 *
 * Target program must be built with a large code model:
 *	gcc -mcmodel=large
 * Target program must be built with preserved text relocations:
 *	gcc -Wl,--emit-relocs
 *
 * cp gASLR.o /opt/shiva/modules
 * shiva-ld -e <binary> -p gASLR.o -s /opt/shiva/modules -i /lib/shiva -o test -d
 *
 */

#define _GNU_SOURCE
#include "../../include/shiva_module.h"
#include "../../../shiva.h"
#include "/opt/elfmaster/include/libelfmaster.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/queue.h>

#include <stdarg.h>
#include <stdio.h>

#if defined DEBUG
	#define aslr_debug(...) {\
	do {\
		fprintf(stdout, "[%s:%s:%d] ", __FILE__, __func__, __LINE__); \
		fprintf(stdout, __VA_ARGS__);	\
	} while(0); \
}
#else
	  #define aslr_debug(...)
#endif

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
			 * updated with the absolute r_offset's that are relative
			 * to the base (instead of relative to the .text section).
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
			fe->n_mem = mmap(NULL, fe->func_len, PROT_READ|PROT_WRITE,
			    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
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

/*
 * returns true or false
 * stores the offset of a given GOT entry (From the beginning of the GOT)
 * into uint64_t *gotoff
 */
bool
find_gotoff_by_symbol(struct shiva_ctx *ctx, const char *symname, uint64_t *gotoff)
{
	struct elf_section got;

	if (elf_section_by_name(&ctx->elfobj, ".got", &got) == false) {
		fprintf(stderr, "elf_section_by_name() failed on .got\n");
		return false;
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
		aslr_debug("Relocating entry point  %s\n", fe->symbol.name);
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

		aslr_debug("Relocation type: %lu\n", rel_entry->rel.type);
		aslr_debug("Relocation offset: %#lx\n", rel_entry->rel.offset);
		aslr_debug("Relunit: %p\n", r_ptr);
		aslr_debug("Symbol name: %s\n", rel_entry->rel.symname);

		(void )mprotect((void *)page_vaddr, 4096, PROT_READ|PROT_WRITE|PROT_EXEC);

		if (elf_section_by_name(&ctx->elfobj, ".got", &got) == false) {
			fprintf(stderr, "elf_section_by_name() failed on .got\n");
			return false;
		}

#if 0
		if (rel_entry->rel.type == R_X86_64_GOTPCRELX || rel_entry->rel.type == R_X86_64_GOTPCREL) {
			elf_dynsym_iterator_t dsym_iter;
			size_t symoffset = 0;
			struct elf_symbol tmp;

			elf_dynsym_iterator_init(&ctx->elfobj, &dsym_iter);
			while (elf_dynsym_iterator_next(&dsym_iter, &tmp) == ELF_ITER_OK) {
				if (strcmp(tmp.name, rel_entry->rel.symname) == 0) {
					uint64_t got_entry; // address of the GOT entry for the symbol
					struct elf_symbol sym;

					aslr_debug("R_X86_64_GOTPCREL(X) processing symbol %s\n", tmp.name);
					/*
					 * First 3 entries of GOT[0, 1, 2] are reserved (hence the "sizeof(uintptr_t) * 3")
					 */
					got_entry = ELF_RUNTIME_BASE(got.address) + symoffset + (sizeof(uintptr_t) * 3);
					if (elf_symbol_by_name(&ctx->elfobj, tmp.name, &sym) == false) {
						fprintf(stderr, "elf_symbol_by_name() failed to resolve symbol %s\n", tmp.name);
						return false;
					}
					rel_val = got_entry - ELF_RUNTIME_BASE(sym.value);
					aslr_debug("rel_val = %#lx - %#lx\n", got_entry, ELF_RUNTIME_BASE(sym.value));
					aslr_debug("symoffset in got is %zu\n", symoffset);
					aslr_debug("Setting reloc value to %#lx\n", rel_val);
					*(uint64_t *)r_ptr = rel_val;
					goto success;
				}
				symoffset += sizeof(uintptr_t);
			 }
#endif
		if (rel_entry->rel.type == R_X86_64_GOT64) {
			struct elf_symbol tmp;
			elf_dynsym_iterator_t dsym_iter;
			size_t symoffset = 0;

			elf_dynsym_iterator_init(&ctx->elfobj, &dsym_iter);
			while (elf_dynsym_iterator_next(&dsym_iter, &tmp) == ELF_ITER_OK) {
				struct elf_plt plt_entry;

				if (elf_section_by_name(&ctx->elfobj, ".got", &got) == false) {
					fprintf(stderr, "elf_section_by_name() failed on .got\n");
					return false;
				}

#if 0
				printf("Continuing...\n");
				if (elf_plt_by_name(&ctx->elfobj, tmp.name, &plt_entry) == false) {
					aslr_debug("No PLT entry for %s, skipping...\n", tmp.name);
					continue;
				}
#endif
				/* This symbol should be related to a GLOB_DAT or JUMPSLOT
				 * relocation.
				 */

				printf("Comparing %s and %s\n", tmp.name, rel_entry->rel.symname);
				if (strcmp(tmp.name, rel_entry->rel.symname) == 0) {
					aslr_debug("R_X86_64_GOT64 processing symbol %s\n", tmp.name);
					/*
					 * First 3 entries of GOT[0, 1, 2] are reserved
					 */
					rel_val = symoffset + (sizeof(uintptr_t) * 3);
					aslr_debug("symoffset in got is %zu\n", symoffset);
					aslr_debug("Setting reloc value to %#lx\n", rel_val);
					*(uint64_t *)r_ptr = rel_val;
					goto success;
				}
				symoffset += sizeof(uintptr_t);
			}
#if 0
			elf_dynsym_iterator_init(&ctx->elfobj, &dsym_iter);
			while (elf_dynsym_iterator_next(&dsym_iter, &tmp) == ELF_ITER_OK) {
				if (tmp.type != STT_OBJECT && tmp.type != STT_NOTYPE)
					continue;
				 if (strcmp(tmp.name, rel_entry->rel.symname) == 0) {
					aslr_debug("R_X86_64_GOT64 processing symbol %s\n", tmp.name);
					aslr_debug("Type: %d\n", tmp.type);
					 /*
					 * First 3 entries of GOT[0, 1, 2] are reserved
					 */
					rel_val = symoffset + (sizeof(uintptr_t) * 3);
					aslr_debug("symoffset in got is %zu\n", symoffset);
					aslr_debug("Setting reloc value to %#lx\n", rel_val);
					*(uint64_t *)r_ptr = rel_val;
					goto success;
				}
				symoffset += sizeof(uintptr_t);
			}
#endif
			fprintf(stderr, "Failed to find symbol for R_X86_64_GOT64 reloc entry\n");
			return false;
		}
		aslr_debug("Made it to reloc switch() case\n");
		switch(rel_entry->rel.type) {
		case R_X86_64_GOTPC64: /* GOT - P + A */
			if (elf_section_by_name(&ctx->elfobj, ".got", &got) == false) {
				fprintf(stderr, "elf_section_by_name() failed on .got\n");
				return false;
			}
			aslr_debug("R_X86_64_GOTPC64\n");
			rel_val = ELF_RUNTIME_BASE(got.address) - rel_addr + rel_entry->rel.addend;
			aslr_debug("rel_val = %#lx - %#lx + %#lx\n", ELF_RUNTIME_BASE(got.address),
			    rel_addr, rel_entry->rel.addend);
			aslr_debug("Setting %p to %#lx\n", r_ptr, rel_val);
			*(uint64_t *)r_ptr = rel_val;
			break;
		case R_X86_64_GOTOFF64:
			aslr_debug("R_X86_64_GOTOFF64\n");
			if (elf_symbol_by_name(&ctx->elfobj, rel_entry->rel.symname, &symbol) == false) {
				fprintf(stderr, "elf_symbol_by_name failed on %s\n", symbol.name);
				return false;
			}
			if (symbol.type == STT_FUNC && symbol.bind == STB_GLOBAL) {
				struct func_entry *tmp;

				TAILQ_FOREACH(tmp, &aslr->orig_func_list, _linkage) {
					if (strcmp(tmp->symbol.name, rel_entry->rel.symname) != 0)
						continue;
					symval = tmp->new_base_vaddr;
					aslr_debug("symval set to %#lx\n", symval);
					break;
				}
			} else {
				symval = ELF_RUNTIME_BASE(symbol.value);
				aslr_debug("symval set to %#lx\n", symval);
			}

			rel_val = symval + rel_entry->rel.addend -
			    ELF_RUNTIME_BASE(got.address);

			aslr_debug("R_X86_64_GOTOFF64 setting r_ptr(%p) to rel_val: %#x\n",
			    r_ptr, rel_val);

			*(int64_t *)r_ptr = rel_val;
			break;
		case R_X86_64_PLTOFF64: /* L - GOT + A */
			aslr_debug("R_X86_64_PLTOFF64\n");
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
			aslr_debug("symval:(%#lx) - got:(%#lx) + addend(%#lx)\n",
			    symval, ELF_RUNTIME_BASE(got.address), rel_entry->rel.addend);
			rel_val = symval - ELF_RUNTIME_BASE(got.address) + rel_entry->rel.addend;
			aslr_debug("rel_val: %#x\n", rel_val);
			aslr_debug("Setting PLT encoded-offset to GOT offset %#lx\n", got.address +
			    rel_entry->rel.addend);
			*(uint32_t *)r_ptr = rel_val;
			break;
		case R_X86_64_PC32: /* S + A - P */
			aslr_debug("R_X86_64_PC32\n");
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
				aslr_debug("Setting R_X86_64_PC32(1) reloc value (r_ptr: %p) to rel_val: %#x (destination symbol %s:%#lx)\n",
				   r_ptr, rel_val, rel_entry->rel.symname, symval);
				*(uint32_t *)&r_ptr[0] = rel_val;
				break;
			} else {
				if (elf_symbol_by_name(&ctx->elfobj, rel_entry->rel.symname,
				    &symbol) == false) {
					fprintf(stderr, "elf_symbol_by_name() failed to find symbol %s\n",
					    symbol.name);
					return false;
				}
				struct func_entry *tmp;

				if (symbol.type != STT_FUNC)
					break;

				aslr_debug("Searching for symbol %s\n", symbol.name);
				TAILQ_FOREACH(tmp, &aslr->orig_func_list, _linkage) {
					if (strcmp(tmp->symbol.name, rel_entry->rel.symname) != 0)
						continue;
					if (fe->flags & ASLR_FUNC_F_ENTRYPOINT) {
						/*
						 * Instead of solving the normal relocation for
						 * a R_X86_64_PC32 here, we actually replace an
						 * entire 'lea 0x0(%rip), $rdi' instruction with
						 * a 'movabs <new_main> $rdi'. The memory mapping
						 * where main() lives will likely exceed what can
						 * be encoded into a 4 byte offset.
						 *
						 * init routes (i.e. _start, __libc_start_main, etc.)
						 * are all already compiled into the crt*.o files. So
						 * while main() and all other functions compiled may
						 * be in a large code model, the init routines are not.
						 */ 
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
					aslr_debug("Setting X86_64_PC32(2) reloc value to rel_val: %#x"
					    " destination symbol %s:%#lx)\n", rel_val,
					    rel_entry->rel.symname, symval);
					*(uint32_t *)r_ptr = rel_val;
				}
			}
			break;
		default:
			printf("Unhandled relocation type %d: %s\n", rel_entry->rel.type,
			    elf_reloc_type_string(&ctx->elfobj, rel_entry->rel.type));
			break;
	}
}

success:
	aslr_debug("Setting mprotect PROT_READ|PROT_EXEC on %p\n", (void *)page_vaddr);
	(void)mprotect((void *)page_vaddr,
	    4096,
	    PROT_READ|PROT_EXEC);

	aslr_debug("Returning\n");
	return true;
}

bool
move_function(struct shiva_ctx *ctx, struct aslr_ctx *aslr, struct func_entry *fe)
{

	size_t delta;
	struct reloc_entry *rel_entry;

	aslr_debug("Moving function %s to %p\n", fe->symbol.name, fe->n_mem);
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
	size_t mlen;
	size_t pgoff;

	/*
	 * Simply zero it out
	 */
	aslr_debug("removing old code/data\n");
	aslr_debug("fe: %p\n", fe);
	aslr_debug("fe->runtime_vaddr: %#lx\n", fe->runtime_vaddr);

	pgoff = ELF_PAGEOFFSET(fe->runtime_vaddr);
	aslr_debug("pgoff: %zu\n", pgoff);

	ret = mprotect((void *)(fe->runtime_vaddr & ~4095), fe->func_len + pgoff, PROT_READ|PROT_WRITE|PROT_EXEC);
	aslr_debug("Calling memset on %#lx of %d bytes\n", fe->runtime_vaddr, fe->func_len - 1);
	memset((void *)fe->runtime_vaddr, 0, fe->func_len - 1);
	aslr_debug("Done calling memset\n");
	ret = mprotect((void *)(fe->runtime_vaddr & ~4095), fe->func_len + pgoff, PROT_READ|PROT_EXEC);

	aslr_debug("Returning... \n");
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
		aslr_debug("Moving function: %s\n", fe->symbol.name);
		res = move_function(ctx, aslr, fe);		
		if (res == false) {
			fprintf(stderr, "Failed to move function %s\n", fe->symbol.name);
			return false;
		}
		aslr_debug("Function %s was moved sucessfuly, now lets scrub the old version\n",
		    fe->symbol.name);
		res = remove_old_function(ctx, fe);
		aslr_debug("Function %s was scrubbed from its original location\n", fe->symbol.name);
	}
	return true;
}

int
shiva_init(struct shiva_ctx *ctx)
{
	struct aslr_ctx aslr;
	size_t fn_count;

	aslr_debug("Building func list\n");

	if (build_func_list(ctx, &aslr, &fn_count) == false) {
		fprintf(stderr, "build_func_list() failed on .text\n");
		return -1;
	}

	aslr_debug("Randomizing func locations\n");
	if (randomize_func_locations(ctx, &aslr, fn_count) == false) {
		fprintf(stderr, "randomize_func_locations() failed\n");
		return -1;
	}
	aslr_debug("Leaving module\n");
}
