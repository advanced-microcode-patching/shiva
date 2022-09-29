#include "shiva.h"
#include "shiva_debug.h"
#include <sys/mman.h>

/*
 * The purpose of this code is to take a relocatable object,
 * and turn it into a runtime executable module. This means
 * that we must organize SHF_ALLOC and SHF_ALLOC|SHF_ sections into the text
 * segment, and SHF_WRITE sections into the data segment.
 */

/*
 * Our custom PLT stubs are a simple IP relative indirect
 * JMP into the global offset table.
 * i.e. jmp *0x0(%rip)
 * NOTE: Our linker uses strict linking.
 */
uint8_t plt_stub[6] = "\xff\x25\x00\x00\x00\x00";

static void
transfer_to_module(struct shiva_ctx *ctx, uint64_t entry)
{
	__asm__ __volatile__ ("mov %0, %%rdi\n" :: "r"(ctx));
	__asm__ __volatile__ ("mov %0, %%rax\n"
			      "call *%%rax" :: "r" (entry));
	return;
}
/*
 * Module entry point. Lookup symbol "main"
 */
static bool
module_entrypoint(struct shiva_module *linker, uint64_t *entry)
{
	struct elf_symbol symbol;
	char *entry_symbol;

	if (linker->flags & SHIVA_MODULE_F_RUNTIME) {
		entry_symbol = "shakti_main";
	} else if (linker->flags & SHIVA_MODULE_F_INIT) {
		entry_symbol = "shakti_module_init";
	}
	if (elf_symbol_by_name(&linker->elfobj, entry_symbol, &symbol) == false) {
		shiva_debug("elf_symbol_by_name failed to find '%s'\n", entry_symbol);
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
 * Our custom interpreter is built with musl-libc. Lets
 * locate the path to our interpreter (i.e. /home/elfmaster/shiva_interp)
 * and resolve the modules external library calls to the corresponding
 * musl-libc functions in memory.
 */
static bool
resolve_pltgot_entries(struct shiva_module *linker)
{
	uint64_t gotaddr;
	uint64_t *GOT;
	struct shiva_module_got_entry *current = NULL;

	gotaddr = linker->data_vaddr + linker->pltgot_off;

	TAILQ_FOREACH(current, &linker->tailq.got_list, _linkage) {
		struct elf_symbol symbol;

		if (elf_symbol_by_name(&linker->elfobj, current->symname, &symbol) == true) {
			if (symbol.type == STT_FUNC || symbol.type == STT_OBJECT) {
				shiva_debug("Setting [%#lx] GOT entry '%s' to %#lx\n",
				    linker->data_vaddr + linker->pltgot_off + current->gotoff, current->symname, symbol.value + linker->text_vaddr);
				GOT = (uint64_t *)linker->data_vaddr + linker->pltgot_off + current->gotoff;
				*GOT = symbol.value + linker->text_vaddr;
				continue;
			}
		}
		if (elf_symbol_by_name(&linker->self, current->symname, &symbol) == false) {
			fprintf(stderr, "Could not resolve symbol '%s'. Linkage failure!\n",
			    current->symname);
			return false;
		}
		shiva_debug("Found symbol '%s' within Shiva. Symbol value: %#lx Shiva base: %#lx\n",
		    current->symname, symbol.value, linker->shiva_base);
		GOT = (uint64_t *)((uint64_t)(linker->data_vaddr + linker->pltgot_off + current->gotoff));
#ifdef SHIVA_STANDALONE
		/*
		 * NOTE: Shiva is now linked as an ET_EXEC in standalone mode to promote
		 * certain capabilities, such as 'SHIVA_TRACE_BP_CALL' hooks, which only work
		 * in small code models.
		 */
		*(uint64_t *)GOT = symbol.value;
#else
		*(uint64_t *)GOT = symbol.value + linker->shiva_base;
#endif
	}
#if 0
	/*
	 * Here we are using the relocation iterator to retrieve the PLT32
	 * relocations from the loaded module, and then resolve the symbols
	 * associated with them from our own binary "shiva_interp" which has
	 * musl-libc code statically linked within it. NOTE: gcc may also
	 * create PLT relocations for function calls that are local to the
	 * module itself, so first try to resolve symbols in the module before we
	 * check within shiva_interp itself. 
	 */
	elf_relocation_iterator_init(&linker->elfobj, &rel_iter);
	while (elf_relocation_iterator_next(&rel_iter, &rel) == ELF_ITER_OK) {
		if (rel.type != R_X86_64_PLT32 && rel.type != R_X86_64_GOT64)
			continue;
		if ((elf_symbol_by_name(&linker->elfobj, rel.symname, &symbol) == true) &&
		    symbol.type == STT_FUNC) {
			shiva_debug("Setting [%#lx] GOT entry '%s' to %#lx\n", gotaddr,
			    rel.symname, symbol.value + linker->text_vaddr);
			GOT = (uint64_t *)gotaddr;
			*GOT = symbol.value + linker->text_vaddr;
			gotaddr += sizeof(uint64_t);
			continue;
		}
		/*
		 * If the symbol doesn't exist within the module itself, let's see
		 * if we can find it within the debugger itself which is statically
		 * linked to musl-libc.
		 */
		if (elf_symbol_by_name(&linker->self, rel.symname, &symbol) == false) {
		    shiva_debug("Could not resolve symbol '%s'."
		    " runtime-linkage failure\n", rel.symname);
			return false;
		}
		printf("Found symbol in shiva, symbol value: %#lx shiva base: %#lx\n",
		    symbol.value, linker->shiva_base);
		printf("Setting [%#lx] GOT entry '%s' to %#lx\n", gotaddr, rel.symname,
		    symbol.value + linker->shiva_base);
		GOT = (uint64_t *)gotaddr;
		*GOT = symbol.value + linker->shiva_base;
		gotaddr += sizeof(uint64_t);
	}
#endif
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
		*(uint32_t *)&stub[2] = gotoff;
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

bool
apply_relocation(struct shiva_module *linker, struct elf_relocation rel)
{
	struct shiva_module_plt_entry *current = NULL;
	struct shiva_module_section_mapping *smap_current;
	struct shiva_module_section_mapping smap, smap_tmp;
	uint8_t *rel_unit;
	uint64_t symval;
	uint64_t rel_addr;
	uint64_t rel_val;
	struct elf_symbol symbol;
	ENTRY e, *ep;
	struct shiva_module_got_entry got_entry;

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
	shiva_debug("smap.offset: %#lx\n", smap.offset);

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
                			shiva_debug("Failed to retrieve section data for %s\n", rel.shdrname);
                			return false;
        			}

				rel_val = (symbol.value + smap_tmp.vaddr) + rel.addend -
				    (linker->data_vaddr + linker->pltgot_off);
			} else {
				rel_val = (symbol.value + linker->text_vaddr) + rel.addend -
				    (linker->data_vaddr + linker->pltgot_off);
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
#ifdef SHIVA_STANDALONE
				symval = symbol.value;
#else
				symval = symbol.value + linker->shiva_base;
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
	return false;
}
bool
relocate_module(struct shiva_module *linker)
{
	struct elf_relocation_iterator rel_iter;
	struct elf_relocation rel;
	bool res;
	char *shdrname;

	elf_relocation_iterator_init(&linker->elfobj, &rel_iter);
	while (elf_relocation_iterator_next(&rel_iter, &rel) == ELF_ITER_OK) {
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
		res = apply_relocation(linker, rel);
		if (res == false) {
			shiva_debug("Failed to apply %s relocation at offset %#lx\n",
			    rel.shdrname, rel.offset);
			return false;
		}
	}
	return true;
}
/*
 * This function copies the code/data from a given section into it's
 * respective memory mapped segment (i.e. the text segment).
 * Section data is copied from elfobj to the respective memory mapped segment
 * pointed to by dst. The section data to be copied is described by
 * section. Without the segment_offset this function would not be re-entrant.
 * The segment_offset tells us at which offset within the segment to copy the given
 * section data to.
 */
bool
elf_section_map(elfobj_t *elfobj, uint8_t *dst, struct elf_section section,
    uint64_t *segment_offset)
{
	size_t rem = section.size % sizeof(uint64_t);
	uint64_t qword;
	bool res;
	size_t i = 0;

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

#define MAX_GOT_COUNT 4096 * 10

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

	elf_section_iterator_init(&linker->elfobj, &iter);
	while (elf_section_iterator_next(&iter, &section) == ELF_ITER_OK) {
		if (section.flags == (SHF_ALLOC|SHF_WRITE)) {
			linker->data_size += section.size;
		}
	}
	linker->pltgot_off = linker->data_size;

	if (elf_section_by_name(&linker->elfobj, ".bss", &section) == false) {
		shiva_debug("elf_section_by_name() failed\n");
		return false;
	}
	/*
	 * Make room for the .bss
	 */
	linker->data_size += section.size;

	/*
	 * Create cache for GOT entries.
	 */
	(void) hcreate_r(MAX_GOT_COUNT, &linker->cache.got);

	TAILQ_INIT(&linker->tailq.got_list);

	offset = 0;

	elf_relocation_iterator_init(&linker->elfobj, &rel_iter);
	while (elf_relocation_iterator_next(&rel_iter, &rel) == ELF_ITER_OK) {
		switch(rel.type) {
		case R_X86_64_PLT32:
		case R_X86_64_GOT64:
		case R_X86_64_PLTOFF64:
			/*
			 * Create room for the modules pltgot
			 */
		//	linker->data_size += sizeof(uint64_t);
		//	linker->pltgot_size += sizeof(uint64_t);
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

			shiva_debug("Inserting entries into GOT cache and GOT list\n");
			TAILQ_INSERT_TAIL(&linker->tailq.got_list, got_entry, _linkage);
			offset += sizeof(uint64_t);

			linker->data_size += sizeof(uint64_t);
			linker->pltgot_size += sizeof(uint64_t);
			break;
		default:
			break;
		}
	}

	shiva_debug("LPM data segment size: %zu\n", linker->data_size);
	return true;
}

bool
calculate_text_size(struct shiva_module *linker)
{
	struct elf_section section;
	elf_section_iterator_t iter;
	struct elf_relocation rel;
	elf_relocation_iterator_t rel_iter;

	elf_section_iterator_init(&linker->elfobj, &iter);
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
		if (rel.type == R_X86_64_PLT32 || rel.type == R_X86_64_PLTOFF64) {
			/*
			 * Create room for each PLT stub
			 */
			linker->plt_size += sizeof(plt_stub);
			linker->text_size += sizeof(plt_stub);
			linker->plt_count++;
		}
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

	if (linker->data_size == 0) {
		shiva_debug("No data segment is needed\n");
		return true; // we need no data segment
	}

	uint64_t mmap_flags = (ctx->flags & SHIVA_OPTS_F_INTERP_MODE) ? MAP_PRIVATE|MAP_ANONYMOUS :
	    MAP_PRIVATE|MAP_ANONYMOUS;
	uint64_t mmap_base = 0;

	if (ctx->flags & SHIVA_OPTS_F_INTERP_MODE) {
		mmap_base = ELF_PAGEALIGN(linker->text_vaddr + linker->text_size, PAGE_SIZE);
	} else {
		mmap_base = ELF_PAGEALIGN(linker->text_vaddr + linker->text_size, PAGE_SIZE);
		mmap_flags |= MAP_32BIT;
	}
	data_size_aligned = ELF_PAGEALIGN(linker->data_size, PAGE_SIZE);
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

			if (section.size == 0)
				continue;
			shiva_debug("Attempting to map section %s(offset: %zu) into data segment"
			    " at address %p\n", section.name, off, linker->data_mem + off);
			res = elf_section_map(&linker->elfobj, linker->data_mem,
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
			n->map_attribute = LP_SECTION_DATASEGMENT;
			n->vaddr = (unsigned long)linker->data_mem + count;
			n->offset = count; // offset within data segment that section lives at
			n->size = section.size;
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
			res = elf_section_map(&linker->elfobj, linker->text_mem,
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
			count += section.size;
			shiva_debug("COUNT: %zu\n", count);
		}
	}
	shiva_debug("count: %zu off: %zu\n", count, off);
	linker->plt_off = off;
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
		if (rel.type != R_X86_64_PLT32 && rel.type != R_X86_64_PLTOFF64)
			continue;
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
	linker->flags = flags;
	linker->shiva_base = ctx->shiva.base;
	*linkerptr = linker;
	
	TAILQ_INIT(&linker->tailq.section_maplist);
	TAILQ_INIT(&linker->tailq.plt_list);

	shiva_debug("elf_open_object(%s, ...)\n", path);

	/*
	 * Open the module ELF object (I.E. modules/shakti_runtime.o)
	 */
	res = elf_open_object(path, &linker->elfobj,
	    ELF_LOAD_F_STRICT, &error);
	if (res == false) {
		shiva_debug("elf_open_object(%s, ...) failed\n", path);
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
	if (module_entrypoint(linker, &entry) == false) {
		shiva_debug("Failed to get module entry point\n");
		return false;
	}
	shiva_debug("Entry point address: %#lx\n", entry);
	transfer_to_module(ctx, entry);
	shiva_debug("Successfully executed module\n");
	return true;
}


