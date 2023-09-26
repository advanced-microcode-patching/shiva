/*
 * shiva_analyze.c - Functions for performing control flow analysis, and gathering other
 */
#include "shiva.h"

#define BIT_MASK(n)	((1U << n) - 1)
#ifdef __aarch64__
#define ARM_INSN_LEN 4
#endif

/*
 * Way to many args, turn this into a macro.
 */
static inline bool
shiva_analyze_make_xref(struct shiva_ctx *ctx, struct elf_symbol *symbol, struct elf_symbol *deref_symbol,
    struct elf_symbol *src_func, int xref_type, uint64_t xref_flags, uint64_t adrp_site,
    uint64_t adrp_imm, uint64_t next_imm,
    uint32_t adrp_o_bytes, uint32_t next_o_bytes)
{
	struct shiva_xref_site *xref;
	uint64_t gotaddr;

	xref = calloc(1, sizeof(*xref));
	if (xref == NULL) {
		perror("calloc");
		return false;
	}
	shiva_debug("XREF (Type: %d): site: %#lx target: %s(%#lx)\n",
	    xref_type, adrp_site, symbol->name, symbol->value);
	if (xref_flags & SHIVA_XREF_F_INDIRECT) {
		memcpy(&xref->deref_symbol, deref_symbol, sizeof(struct elf_symbol));
		gotaddr = (adrp_site & ~0xfff) + adrp_imm + next_imm;
		xref->got = (uint64_t *)gotaddr;
	}
	xref->type = xref_type;
	xref->flags = xref_flags;
	xref->adrp_imm = adrp_imm;
	xref->adrp_site = adrp_site;
	xref->next_imm = next_imm;
	xref->next_site = adrp_site + ARM_INSN_LEN;
	xref->adrp_o_insn = adrp_o_bytes; //*(uint32_t *)&tmp_ptr[c];
	xref->next_o_insn = next_o_bytes; //*(uint32_t *)&tmp_ptr[c + ARM_INSN_LEN];
	xref->target_vaddr = (adrp_site & ~0xfff) + adrp_imm + next_imm;
	shiva_debug("ADRP(%#lx): %x\n", adrp_site, xref->adrp_o_insn);
	shiva_debug("NEXT(%#lx): %x\n", xref->next_site, xref->next_o_insn);
	memcpy(&xref->symbol, symbol, sizeof(*symbol));
	if (src_func != NULL)
		memcpy(&xref->current_function, src_func, sizeof(*src_func));
	TAILQ_INSERT_TAIL(&ctx->tailq.xref_tqlist, xref, _linkage);
	return true;
}

static bool
shiva_analyze_build_aarch64_jmp(struct shiva_ctx *ctx, uint64_t pc_vaddr)
{
	struct shiva_branch_site *tmp;
	struct elf_symbol tmp_sym;
	char *p = strchr(ctx->disas.insn->op_str, '#');

	if (p == NULL) {
		fprintf(stderr,
		    "Unforseen parsing error in shiva_analyze_build_aarch64_jmp\n");
		return false;
	}
	tmp = calloc(1, sizeof(*tmp));
	if (tmp == NULL) {
		perror("calloc");
		return false;
	}
	tmp->target_vaddr = strtoul((p + 1), NULL, 16);
	tmp->branch_site = pc_vaddr;
	tmp->branch_type = SHIVA_BRANCH_JMP;
	tmp->insn_string = shiva_xfmtstrdup("%s %s",
	    ctx->disas.insn->mnemonic, ctx->disas.insn->op_str);
	if (elf_symbol_by_range(&ctx->elfobj, pc_vaddr,
	    &tmp_sym) == true) {
		tmp->branch_flags |= SHIVA_BRANCH_F_SRC_SYMINFO;
		memcpy(&tmp->current_function, &tmp_sym, sizeof(tmp_sym));
		shiva_debug("Source function found: %s\n", tmp_sym.name);
	}
	/*
	 * Unconditional branch at a PC-relative offset
	 */
	shiva_debug("Found branch: %#lx:%s\n", pc_vaddr, tmp->insn_string);
	TAILQ_INSERT_TAIL(&ctx->tailq.branch_tqlist, tmp, _linkage);
	return true;
}

bool
shiva_analyze_find_calls(struct shiva_ctx *ctx)
{
	struct elf_section section;
	struct elf_symbol symbol;
	const uint8_t *ptr;
	uint64_t call_site, call_addr, retaddr;
	uint64_t current_address = ctx->disas.base;
	int64_t call_offset;
	int bits;

	if (elf_section_by_name(&ctx->elfobj, ".text", &section) == false) {
		fprintf(stderr, "elf_section_by_name() failed\n");
		return false;
	
	}
#ifdef __x86_64__
	bits = elf_class(&ctx->elfobj) == elfclass64 ? 64 : 32;
	ud_init(&ctx->disas.ud_obj);
	ud_set_input_buffer(&ctx->disas.ud_obj, ctx->disas.textptr, section.size);
	ud_set_mode(&ctx->disas.ud_obj, bits);
	ud_set_syntax(&ctx->disas.ud_obj, UD_SYN_INTEL);
	while (ud_disassemble(&ctx->disas.ud_obj) != 0) {
		struct shiva_branch_site *tmp;
		size_t insn_len = ud_insn_len(&ctx->disas.ud_obj);

		shiva_debug("insn_len: %zu\n", insn_len);
		memset(&symbol, 0, sizeof(symbol));

		if (ud_insn_mnemonic(&ctx->disas.ud_obj) != UD_Icall) {
			current_address += insn_len;
			continue;
		}
		shiva_debug("%-20s %s\n", ud_insn_hex(&ctx->disas.ud_obj),
		    ud_insn_asm(&ctx->disas.ud_obj));
		ptr = ud_insn_ptr(&ctx->disas.ud_obj);
		assert(ptr != NULL);
		if (ptr[0] != 0xe8) {
			current_address += insn_len;
			continue;
		}
		tmp = calloc(1, sizeof(*tmp));
		if (tmp == NULL) {
			perror("calloc");
			return false;
		}
		call_offset = *(uint32_t *)&ptr[1];
		call_site = current_address;
		call_addr = call_site + call_offset + 5;
		call_addr &= 0xffffffff;
		retaddr = call_site + insn_len;

		if (elf_symbol_by_value_lookup(&ctx->elfobj, call_addr,
		    &symbol) == false) {
			/*
			 * It's possible the call is calling a plt entry
			 * which won't be in the symbol table. We can search
			 * by PLT entry.
			 */
			struct elf_plt plt_entry;
			elf_plt_iterator_t plt_iter;

			elf_plt_iterator_init(&ctx->elfobj, &plt_iter);
			while (elf_plt_iterator_next(&plt_iter, &plt_entry) == ELF_ITER_OK) {
				if (plt_entry.addr == call_addr) {
					symbol.name = shiva_xfmtstrdup("%s@plt", plt_entry.symname);
					symbol.type = STT_FUNC;
					symbol.bind = STB_GLOBAL;
					symbol.size = 0;
					tmp->branch_flags |= SHIVA_BRANCH_F_PLTCALL;
				}
			}
			if (symbol.name == NULL) {
				symbol.name = shiva_xfmtstrdup("fn_%#lx", call_addr);
				if (symbol.name == NULL) {
					perror("strdup");
					return false;
				}
				symbol.value = call_addr;
				symbol.type = STT_FUNC;
				symbol.size = 0;
				symbol.bind = STB_GLOBAL;
			}
		}
		tmp->retaddr = retaddr;
		tmp->target_vaddr = call_addr;
		memcpy(&tmp->symbol, &symbol, sizeof(symbol));
		tmp->branch_type = SHIVA_BRANCH_CALL;
		tmp->branch_site = call_site;
		TAILQ_INSERT_TAIL(&ctx->tailq.branch_tqlist, tmp, _linkage);
		current_address += insn_len;
	}
#elif __aarch64__
	struct shiva_branch_site *tmp;
	int xref_type;
	size_t c, i, j;
	size_t code_len = section.size - 1;
	uint64_t code_vaddr = section.address; /* Points to .text */
	uint8_t *code_ptr = ctx->disas.textptr;
	uint8_t *tmp_ptr = code_ptr;
	elf_symtab_iterator_t symtab_iter;
	cs_detail insnack_detail = {{0}};
	cs_insn insnack = {0};
	ctx->disas.insn = &insnack;
	if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN,
	    &ctx->disas.handle) != CS_ERR_OK) {
		fprintf(stderr, "cs_open failed\n");
		return false;
	}

	shiva_debug("disassembling text(%#lx), %d bytes\n", section.address, section.size);
	for (c = 0 ;; c += ARM_INSN_LEN) {
		bool res;

		shiva_debug("Address: %#lx\n", section.address + c);
		shiva_debug("(uint32_t)textptr: %#x\n", *(uint32_t *)code_ptr);
		if (c >= section.size)
			break;
		shiva_debug("code_ptr: %p\n", code_ptr);
		res = cs_disasm_iter(ctx->disas.handle, (void *)&code_ptr, &code_len,
		    &code_vaddr, ctx->disas.insn);
		if (res == false) {
			shiva_debug("code_ptr after fail: %p\n", code_ptr);
			shiva_debug("code_vaddr after fail: %lx\n", code_vaddr);
			code_vaddr += ARM_INSN_LEN;
			code_ptr += ARM_INSN_LEN;
			continue;
		}
#if 0
		for (;;) {
			if (*(uint32_t *)code_ptr[c + 4] != 0)
				break;
			code_vaddr += ARM_INSN_LEN;
			c += ARM_INSN_LEN;
		}
#endif
		shiva_debug("0x%"PRIx64":\t%s\t\t%s\n", ctx->disas.insn->address,
		    ctx->disas.insn->mnemonic, ctx->disas.insn->op_str);
		if (strcmp(ctx->disas.insn->mnemonic, "b") == 0) {
			if (shiva_analyze_build_aarch64_jmp(ctx, section.address + c)
			    == false) {
				fprintf(stderr, "shiva_analyze_build_aarch64_jmp(%p, %#lx) failed\n",
				    ctx, section.address + c);
				return false;
			}
		}
		if (strncmp(ctx->disas.insn->mnemonic, "b.", 2) == 0) {
			/*
			 * Branch instructions:
			 * b.eq, b.ne, b.gt, b.ge, b.lt, b.le, b.ls, b.hi,
			 * b.cc, b.cs, b.cond
			 */
			if (shiva_analyze_build_aarch64_jmp(ctx, section.address + c)
			    == false) {
				fprintf(stderr, "shiva_analyze_build_aarch64_jmp(%p, %#lx) failed\n",
				    ctx, section.address + c);
				return false;
			}
		} else if (strncmp(ctx->disas.insn->mnemonic, "cb", 2) == 0) {
			/*
			 * Compare and branch
			 * cbnz, cbz
			 */
			if (shiva_analyze_build_aarch64_jmp(ctx, section.address + c)
			    == false) {
				fprintf(stderr, "shiva_analyze_build_aarch64_jmp(%p, %#lx) failed\n",
				    ctx, section.address + c);
				return false;
			}

		} else if (strncmp(ctx->disas.insn->mnemonic, "tb", 2) == 0) {
			/*
			 * Test bit and branch
			 * tbz, tbnz
			 */
			if (shiva_analyze_build_aarch64_jmp(ctx, section.address + c)
			    == false) {
				fprintf(stderr, "shiva_analyze_build_aarch64_jmp(%p, %#lx) failed\n",
				    ctx, section.address + c);
				return false;
			}

		} else if (strcmp(ctx->disas.insn->mnemonic, "bl") == 0) {
			struct shiva_branch_site *tmp;
			uint64_t addr;
			struct elf_symbol tmp_sym;
			char *p = strchr(ctx->disas.insn->op_str, '#');

			if (p == NULL) {
				continue;
				fprintf(stderr, "unexpected error parsing: '%s %s'\n",
				    ctx->disas.insn->mnemonic, ctx->disas.insn->op_str);
				return false;
			}
			call_site = section.address + c;
			call_addr = strtoul((p + 1), NULL, 16);
			retaddr = call_site + ARM_INSN_LEN;
			memset(&symbol, 0, sizeof(symbol));
			tmp = calloc(1, sizeof(*tmp));
			if (tmp == NULL) {
				perror("calloc");
				return false;
			}

			if (elf_symbol_by_value_lookup(&ctx->elfobj, call_addr,
			    &symbol) == false) {
				struct elf_plt plt_entry;
				elf_plt_iterator_t plt_iter;

				symbol.name = NULL;

				elf_plt_iterator_init(&ctx->elfobj, &plt_iter);
				while (elf_plt_iterator_next(&plt_iter, &plt_entry) == ELF_ITER_OK) {
					if (plt_entry.addr == call_addr) {
						symbol.name = shiva_xfmtstrdup("%s@plt", plt_entry.symname);
						symbol.type = STT_FUNC;
						symbol.bind = STB_GLOBAL;
						symbol.size = 0;
						tmp->branch_flags |= SHIVA_BRANCH_F_PLTCALL;
					}
				}
				if (symbol.name == NULL) {
					symbol.name = shiva_xfmtstrdup("fn_%#lx", call_addr);
					if (symbol.name == NULL) {
						perror("strdup");
						return false;
					}
					symbol.value = call_addr;
					symbol.type = STT_FUNC;
					symbol.size = symbol.size;
					symbol.bind = STB_GLOBAL;
				}
			}
			tmp->retaddr = retaddr;
			tmp->target_vaddr = call_addr;
			memcpy(&tmp->o_insn, tmp_ptr + c, ARM_INSN_LEN);
			memcpy(&tmp->symbol, &symbol, sizeof(symbol));
			tmp->branch_type = SHIVA_BRANCH_CALL;
			tmp->branch_site = call_site;
			tmp->branch_flags |= SHIVA_BRANCH_F_DST_SYMINFO;
			tmp->insn_string = shiva_xfmtstrdup("%s %s",
			    ctx->disas.insn->mnemonic, ctx->disas.insn->op_str);

			if (elf_symbol_by_range(&ctx->elfobj, code_vaddr - 4,
			    &tmp_sym) == true) {
				tmp->branch_flags |= SHIVA_BRANCH_F_SRC_SYMINFO;
				memcpy(&tmp->current_function, &tmp_sym, sizeof(tmp_sym));
				shiva_debug("Source symbol included: %s\n", tmp_sym.name);
			}
			shiva_debug("Inserting branch for symbol %s callsite: %#lx\n", tmp->symbol.name, tmp->branch_site);
			TAILQ_INSERT_TAIL(&ctx->tailq.branch_tqlist, tmp, _linkage);
			shiva_debug("Done inserting it\n");
		} else if (strcmp(ctx->disas.insn->mnemonic, "adrp") == 0) {
			uint64_t adrp_imm, adrp_site;
			uint32_t adrp_o_bytes = *(uint32_t *)ctx->disas.insn->bytes;
			uint32_t next_o_bytes;

			/*
			 * We're looking for several combinations that could be
			 * used to reference/access global data.
			 * scenario: 1
			 * adrp x0, #0x1000 (data segment)
			 * ldr x0, [x0, #0x16 (variable offset)]
			 * 
			 * adrp x0, #0x1000
			 * add x0, x0, #0x16
			 */
			struct shiva_xref_site *xref;
			struct elf_symbol symbol;
			uint64_t xref_site, xref_addr, target_page;
			char *p = strchr(ctx->disas.insn->op_str, '#');

			if (p == NULL) {
				continue;
				fprintf(stderr, "unexpected error parsing: '%s %s'\n",
				    ctx->disas.insn->mnemonic, ctx->disas.insn->op_str);
				return false;
			}
			adrp_site = section.address + c;
			adrp_imm = strtoul((p + 1), NULL, 16);
			target_page = (adrp_site & ~0xfff) + adrp_imm;
			res = cs_disasm_iter(ctx->disas.handle, (void *)&code_ptr, &code_len,
			    &code_vaddr, ctx->disas.insn);
			if (res == false) {
				fprintf(stderr, "cs_disasm_iter() failed\n");
				return false;
			}
			next_o_bytes = *(uint32_t *)ctx->disas.insn->bytes;
			c += ARM_INSN_LEN;
			xref = calloc(1, sizeof(*xref));
			if (xref == NULL) {
				perror("calloc");
				return false;
			}
			/*
			 * Is the next instruction and ldr?
			 */
			if (strcmp(ctx->disas.insn->mnemonic, "ldr") == 0) {
				xref_type = SHIVA_XREF_TYPE_ADRP_LDR;
			} else if (strcmp(ctx->disas.insn->mnemonic, "str") == 0) {
				xref_type = SHIVA_XREF_TYPE_ADRP_STR;
			} else if (strcmp(ctx->disas.insn->mnemonic, "add") == 0) {
				xref_type = SHIVA_XREF_TYPE_ADRP_ADD;
			} else {
				xref_type = SHIVA_XREF_TYPE_UNKNOWN;
			}

			if (xref_type == SHIVA_XREF_TYPE_UNKNOWN) {
				/*
				 * We don't know this combination of instructions for
				 * forming an XREF.
				 */
				continue;
			}

			uint32_t tmp_imm;
			uint64_t qword;
			uint64_t xref_flags = 0;
			bool found_symbol = false;

			p = strchr(ctx->disas.insn->op_str, '#');
			if (p == NULL) {
				continue;
				fprintf(stderr, "unexpected error parsing: '%s %s'\n",
				    ctx->disas.insn->mnemonic, ctx->disas.insn->op_str);
				return false;
			}
			tmp_imm = strtoul((p + 1), NULL, 16);
			shiva_debug("Looking up symbol at address %#lx in"
			    " the target executable\n", target_page + tmp_imm);
			/*
			 * Look up the symbol that this xref points to.
			 */
			if (elf_symbol_by_value_lookup(&ctx->elfobj, target_page + tmp_imm,
			    &symbol) == true) {
				shiva_debug("Target xref symbol '%s'\n", symbol.name);
				found_symbol = true;
			}
			/*
			 * Does target_page + tmp_imm lead to storage of the address
			 * we are looking for? Or does it calculate directly to the
			 * address? First let's try to read 8 bytes from the address
			 * and see if there's an indirect absolute value we are looking
			 * for: (i.e. a .got[entry] pointing to a .bss variable.
			 */
			shiva_debug("Reading from address %#lx\n", target_page + tmp_imm);
			if (elf_read_address(&ctx->elfobj, target_page + tmp_imm,
			    &qword, ELF_QWORD) == false) {
				shiva_debug("Failed to read address %#lx\n", target_page + tmp_imm);
				continue;
			}
			/*
			 * Create a symbol to represent the location represented by adrp.
			 * We have not found one, so we create one because it will be used
			 * to install external re-linking patches for adrp sequences.
			 */
			if (found_symbol == false) {
				struct elf_section shdr;

				res = elf_section_by_address(&ctx->elfobj, target_page + tmp_imm,
				    &shdr);
				if (res == false) {
					fprintf(stderr, "Unable to find section associated with addr: %#lx\n",
					    target_page + tmp_imm);
					return false;
				}
				shiva_debug("%#lx - section.address:%#lx = %#lx\n", target_page + tmp_imm, shdr.address,
				    target_page + tmp_imm - shdr.address);
				symbol.name = shiva_xfmtstrdup("%s+%lx", shdr.name,
				    target_page + tmp_imm - shdr.address);
				symbol.value = target_page + tmp_imm;
				symbol.size = sizeof(uint64_t);
				symbol.bind = STB_GLOBAL;
				symbol.type = STT_OBJECT;
				symbol.visibility = STV_PROTECTED;
				if (elf_section_index_by_name(&ctx->elfobj, shdr.name, (uint64_t *)&symbol.shndx)
				    == false) {
					fprintf(stderr, "Failed to find section index for %s in %s\n",
					    shdr.name, elf_pathname(&ctx->elfobj));
					return true;
				}
			}
			/*
			 * We must get the name of the function that the
			 * xref code is within. This is necessary later on
			 * if transformations happen.
			 */
			struct elf_symbol tmp_sym, deref_symbol;
			struct elf_symbol *src_func = NULL;

			if (elf_symbol_by_range(&ctx->elfobj, code_vaddr - 4,
			    &tmp_sym) == true) {
				xref_flags |= SHIVA_XREF_F_SRC_SYMINFO;
				src_func = shiva_malloc(sizeof(*src_func));
				memcpy(src_func, &tmp_sym, sizeof(*src_func));
				shiva_debug("Source symbol included: %s\n", tmp_sym.name);
			}
			shiva_debug("Looking up value %#lx found at %#lx\n", qword, target_page + tmp_imm);
			res = elf_symbol_by_value_lookup(&ctx->elfobj,
			    qword, &deref_symbol);
			if (res == true) {
				xref_flags |= SHIVA_XREF_F_INDIRECT;
				shiva_debug("XREF (Indirect via GOT) (Type: %d): Site: %#lx target: %s (Deref)-> %s(%#lx)\n",
				    xref_type, adrp_site, symbol.name ? symbol.name : "<unknown>",
				    deref_symbol.name, deref_symbol.value);
			}
			res = shiva_analyze_make_xref(ctx, &symbol, &deref_symbol, src_func, xref_type, xref_flags, adrp_site,
			    adrp_imm, tmp_imm, adrp_o_bytes, next_o_bytes);
			if (res == false ) {
				fprintf(stderr, "shiva_analyze_install_xref failed\n");
				return false;
			}
			continue;
		}
	}
#endif
	return true;
}

/*
 * Simple macro to check the .shiva.strtab offset
 * before accessing potentially invalid memory.
 */
#define VALIDATE_STRTAB_OFFSET(name) do { \
	if (name >= shiva_strtab_shdr.size) { \
		fprintf(stderr, "[%zu] invalid offset into .shiva.strtab string table\n", \
		    (size_t)name); \
		return false;	\
	} \
} while (0)

bool
shiva_analyze_run(struct shiva_ctx *ctx)
{
	if (shiva_target_has_prelinking(ctx) == false) {
		shiva_debug("Running shiva_analyze_find_calls\n");
		return shiva_analyze_find_calls(ctx);
	}
	/*
	 * If the binary has been prelinked then it should have
	 * .shiva.xref and .shiva.branch sections which contain
	 * the CFG generated by shiva-ld.
	 */
	struct elf_section xref_shdr;
	struct elf_section branch_shdr;
	struct elf_section shiva_strtab_shdr;
	struct shiva_xref_site xref_site = {0};
	struct shiva_xref_site *xref_new;
	struct shiva_branch_site branch_site = {0};
	struct shiva_branch_site *branch_new;
	size_t i, j;
	bool res;
	uint64_t qword;
	uint8_t *xptr;

	/*
	 * Read .shiva.xref entries. Memory references (i.e. load/store)
	 */
	if (elf_section_by_name(&ctx->elfobj, ".shiva.xref",
	    &xref_shdr) == false) {
		fprintf(stderr, "elf_section_by_name failed to find .shiva.xref\n");
		return false;
	}
	if (elf_section_by_index(&ctx->elfobj, xref_shdr.link,
	    &shiva_strtab_shdr) == false) {
		fprintf(stderr, "elf_section_by_index failed to find shdr at index %u\n",
		    xref_shdr.link);
		return false;
	}

	char *shiva_strtab =(char *)&ctx->elfobj.mem[shiva_strtab_shdr.offset];

	printf("First characters: %s\n", shiva_strtab);
	for (i = 0; i < xref_shdr.size; i += xref_shdr.entsize) {
		for (xptr = (uint8_t *)&xref_site, j = 0; j < xref_shdr.entsize; j += 8) {
			res = elf_read_offset(&ctx->elfobj, xref_shdr.offset + i + j, &qword, ELF_QWORD);
			if (res == false) {
				fprintf(stderr, "elf_read_offset failed at offset %#lx\n",
				    xref_shdr.offset + i);
				return false;
			}
			memcpy(xptr + j, (uint8_t *)&qword, 8);
		}

		/*
		 * When we read the xref_site structs in, their symbol structs
		 * char *name was replaced with a 'uint32_t name' offset into a
		 * string table.  We must convert this offset back into a
		 * pointer into the .shiva.strtab
		 */
		shiva_debug("Imported XREF for symbol %d\n", xref_site.symbol.name);
		xref_new = shiva_malloc(sizeof(*xref_new));
		memcpy(xref_new, &xref_site, sizeof(struct shiva_xref_site));

		if (xref_site.flags & SHIVA_XREF_F_INDIRECT) {
			shiva_debug("validate %u\n", (uint32_t)xref_site.deref_symbol.name);
			VALIDATE_STRTAB_OFFSET((size_t)xref_site.deref_symbol.name);
			xref_new->deref_symbol.name = 
			    (char *)&shiva_strtab[(size_t)xref_site.deref_symbol.name];
			shiva_debug("deref_symbol.name = %s\n", xref_new->deref_symbol.name);
		}
		shiva_debug("validate %zu\n", xref_site.symbol.name);
		VALIDATE_STRTAB_OFFSET((size_t)xref_site.symbol.name);
		xref_new->symbol.name = (char *)&shiva_strtab[(size_t)xref_site.symbol.name];
		shiva_debug("validate %zu\n", (size_t)xref_site.current_function.name);
		VALIDATE_STRTAB_OFFSET((size_t)xref_site.current_function.name);
		xref_new->current_function.name = 
		    (char *)&shiva_strtab[(size_t)xref_site.current_function.name];
		TAILQ_INSERT_TAIL(&ctx->tailq.xref_tqlist, xref_new, _linkage);
		shiva_debug("current_function.name = %s\n", xref_new->current_function.name);
		shiva_debug("symbol.name: %s\n", xref_new->symbol.name);
	}

	if (elf_section_by_name(&ctx->elfobj, ".shiva.branch",
	    &branch_shdr) == false) {
		fprintf(stderr, "elf_section_by_name failed to find .shiva.branch\n");
		return false;
	}

	/*
	 * Read .shiva.branch data into memory.
	 */
	for (i = 0; i < branch_shdr.size; i+= branch_shdr.entsize) {
		for (xptr = (uint8_t *)&branch_site, j = 0; j < branch_shdr.entsize; j+= 8) {
			res = elf_read_offset(&ctx->elfobj, branch_shdr.offset + i + j, &qword, ELF_QWORD);
			if (res == false) {
				fprintf(stderr, "elf_read_offset failed at offset %#lx\n",
				    branch_shdr.offset + i);
				return false;
			}
			memcpy(xptr + j, (uint8_t *)&qword, 8);
		}
		shiva_debug("Imported branch for symbol %s\n", (char *)&shiva_strtab[(size_t)branch_site.symbol.name]);
		branch_new = shiva_malloc(sizeof(struct shiva_branch_site));
		memcpy(branch_new, &branch_site, sizeof(struct shiva_branch_site));
		VALIDATE_STRTAB_OFFSET((size_t)branch_site.symbol.name);
		branch_new->symbol.name = (char *)&shiva_strtab[(size_t)branch_site.symbol.name];
		VALIDATE_STRTAB_OFFSET((size_t)branch_site.current_function.name);
		branch_new->current_function.name = (char *)&shiva_strtab[(size_t)branch_site.current_function.name];
		TAILQ_INSERT_TAIL(&ctx->tailq.branch_tqlist, branch_new, _linkage);
	}
	return true;
}
