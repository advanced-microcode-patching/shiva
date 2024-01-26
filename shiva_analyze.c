/*
 * shiva_analyze.c - Functions for performing control flow analysis, and gathering other
 */
#include "shiva.h"

#define BIT_MASK(n)	((1U << n) - 1)
#define ARM_INSN_LEN 4

#ifdef __aarch64__
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
#endif

static bool
shiva_analyze_build_jmp(struct shiva_ctx *ctx, uint64_t pc_vaddr)
{
	struct shiva_branch_site *tmp;
	struct elf_symbol tmp_sym;
#ifdef __aarch64__
	char *p = strchr(ctx->disas.insn->op_str, '#');
	if (p == NULL) {
		fprintf(stderr,
		    "Unforseen parsing error in shiva_analyze_build_jmp\n");
		return false;
	}
#endif
	tmp = calloc(1, sizeof(*tmp));
	if (tmp == NULL) {
		perror("calloc");
		return false;
	}
#ifdef __aarch64__
	tmp->target_vaddr = strtoul((p + 1), NULL, 16);
#elif __x86_64__
	tmp->target_vaddr = strtoul(ctx->disas.insn->op_str, NULL, 16);
#endif
	shiva_debug("Stored target address: %#lx\n", tmp->target_vaddr);
	tmp->branch_site = pc_vaddr;
	tmp->branch_type = SHIVA_BRANCH_JMP;
	tmp->insn_string = shiva_xfmtstrdup("%s %s",
	    ctx->disas.insn->mnemonic, ctx->disas.insn->op_str);
	memcpy(&tmp->o_insn[0], (uint8_t *)tmp->branch_site + ctx->ulexec.base_vaddr,
	    ctx->disas.insn->size);
	if (elf_symbol_by_range(&ctx->elfobj, pc_vaddr,
	    &tmp_sym) == true) {
		tmp->branch_flags |= SHIVA_BRANCH_F_SRC_SYMINFO;
		memcpy(&tmp->current_function, &tmp_sym, sizeof(tmp_sym));
		shiva_debug("Source function found: %s\n", tmp_sym.name);
	}
	/*
	 * unconditional branch at a PC-relative offset
	 */
	shiva_debug("Inserting branch entry. Branch:%#lx:%s\n", tmp->insn_string);
	shiva_debug("Found branch: %#lx:%s\n", pc_vaddr, tmp->insn_string);
	TAILQ_INSERT_TAIL(&ctx->tailq.branch_tqlist, tmp, _linkage);
	return true;
}

#ifdef __x86_64__
static bool
shiva_analyze_branches_x86_64(struct shiva_ctx *ctx, struct elf_section text, bool *res)
{
	size_t c = ctx->disas.insn_offset;

	*res = false;

	shiva_debug("Mnemonic: %s\n", ctx->disas.insn->mnemonic);

	if (strncmp(ctx->disas.insn->mnemonic, "j", 1) == 0) {
		if (shiva_analyze_build_jmp(ctx, text.address + c)
		    == false) {
			fprintf(stderr, "shiva_analyze_branches_x86_64(%p, %#lx) failed\n",
			    ctx, text.address + c);
			return false;
		}
		*res = true;
	} else if (strcmp(ctx->disas.insn->mnemonic, "jmp") == 0) {
		if (shiva_analyze_build_jmp(ctx, text.address + c)
		    == false) {
			fprintf(stderr, "shiva_analyze_branches_x86_64(%p, %#lx) failed\n",
			    ctx, text.address + c);
			return false;
		}
	}
	return true;
}

#elif __aarch64__
static bool
shiva_analyze_branches_aarch64(struct shiva_ctx *ctx, struct elf_section text, bool *res)
{
	size_t c = ctx->disas.insn_offset;
	
	*res = false;

	shiva_debug("Mnemonic: %s\n", ctx->disas.insn->mnemonic);

	if (strcmp(ctx->disas.insn->mnemonic, "b") == 0) {
		if (shiva_analyze_build_jmp(ctx, text.address + c)
		    == false) {
			fprintf(stderr, "shiva_analyze_build_aarch64_jmp(%p, %#lx) failed\n",
			    ctx, text.address + c);
			return false;
		}
		*res = true;
	}
	if (strncmp(ctx->disas.insn->mnemonic, "b.", 2) == 0) {
		/*
		 * Branch instructions:
		 * b.eq, b.ne, b.gt, b.ge, b.lt, b.le, b.ls, b.hi,
		 * b.cc, b.cs, b.cond
		 */
		if (shiva_analyze_build_jmp(ctx, text.address + c)
		    == false) {
			fprintf(stderr, "shiva_analyze_build_aarch64_jmp(%p, %#lx) failed\n",
			    ctx, text.address + c);
			return false;
		}
		*res = true;
	} else if (strncmp(ctx->disas.insn->mnemonic, "cb", 2) == 0) {
		/*
		 * Compare and branch
		 * cbnz, cbz
		 */
		if (shiva_analyze_build_jmp(ctx, text.address + c)
		    == false) {
			fprintf(stderr, "shiva_analyze_build_aarch64_jmp(%p, %#lx) failed\n",
			    ctx, text.address + c);
			return false;
		}
		*res = true;

	} else if (strncmp(ctx->disas.insn->mnemonic, "tb", 2) == 0) {
		/*
		 * Test bit and branch
		 * tbz, tbnz
		 */
		if (shiva_analyze_build_jmp(ctx, text.address + c)
		    == false) {
			fprintf(stderr, "shiva_analyze_build_aarch64_jmp(%p, %#lx) failed\n",
			    ctx, text.address + c);
			return false;
		}
		*res = true;
	}
	return true;
}
#endif

#ifdef __x86_64__
static bool
shiva_analyze_xrefs_x86_64(struct shiva_ctx *ctx, struct elf_section text)
{
	cs_x86 *x86 = &ctx->disas.insn->detail->x86;
	struct elf_symbol tmp_sym, deref_symbol;
	struct elf_symbol *src_func = NULL;
	struct elf_symbol symbol;
	uint64_t qword;
	bool found_symbol = false;
	int i;
	bool res, found_insn = false;

	struct shiva_xref_site *xref = calloc(1, sizeof(*xref));
	if (xref == NULL) {
		perror("calloc");
		return false;
	}

	xref->type = SHIVA_XREF_TYPE_UNKNOWN;

	uint64_t current_vaddr = ctx->disas.base + ctx->disas.c;
	/*
	 * TODO: Figure out why the cs_option for detail
	 * doesn't work. It crashes cs_disasm_iter() due to
	 * not initializing and setting up detail. Therefore
	 * we parse the instructions the less elegant way
	 * by parsing the mnemonic and operator strings.
	 */
	if (strcmp(ctx->disas.insn->mnemonic, "mov") == 0) {
		cs_insn *insn = ctx->disas.insn;
		char *p, *op2, *op1;
		char op_str[160]; /* from capstone.h */

		strncpy(op_str, insn->op_str, sizeof(op_str));
		op_str[sizeof(op_str) - 1] = '\0';

		op1 = op_str;
		op2 = strchr(op_str, ',') + 2;

		/*
		 * NOTE: We start at &op1[1] (Instead of just op1) to move past
		 * the 'q' or the 'd', as this operand could be "qword ptr"
		 * or "dword ptr" in the string we are analyzing.
		 */
		if (strncmp(&op1[1], "word ptr [rip +", 15) == 0) {
			xref->type = SHIVA_XREF_TYPE_IP_RELATIVE_MOV_STR;
			xref->rip_rel_site = current_vaddr;
			p = strchr(op1, '+') + 2;
			*(char *)strchr(p, ']') = '\0';
			xref->rip_rel_disp = strtoul(p, NULL, 16);
			found_insn = true;
			shiva_debug("xref->type: SHIVA_XREF_TYPE_IP_RELATIVE_MOV_STR at site: %#lx\n",
			    xref->rip_rel_site);
			xref->addr_size = (op1[0] == 'q') ? 8 : 4;
		} else if (strncmp(&op2[1], "word ptr [rip +", 15) == 0) {
			xref->type = SHIVA_XREF_TYPE_IP_RELATIVE_MOV_LDR;
			xref->rip_rel_site = current_vaddr;
			p = strchr(op2, '+') + 2;
			*(char *)strchr(p, ']') = '\0';
			xref->rip_rel_disp = strtoul(p, NULL, 16);
			found_insn = true;
			shiva_debug("xref->type: SHIVA_XREF_TYPE_IP_RELATIVE_MOV_LDR at site: %#lx\n",
			    xref->rip_rel_site);
			xref->addr_size = (op2[0] == 'q') ? 8 : 4;
		}
	} else if (strcmp(ctx->disas.insn->mnemonic, "lea") == 0) {
		cs_insn *insn = ctx->disas.insn;
		char *p, *op2;
		char op_str[160]; /* from capstone.h */

		strncpy(op_str, insn->op_str, sizeof(op_str));
		op_str[sizeof(op_str) - 1] = '\0';

		op2 = strchr(op_str, ',') + 2;
		if (strncmp(op2, "[rip +", 6) == 0) {
			xref->type = SHIVA_XREF_TYPE_IP_RELATIVE_LEA;
			xref->rip_rel_site = current_vaddr;
			p = strchr(op2, '+') + 2;
			*(char *)strchr(p, ']') = '\0';
			xref->rip_rel_disp = strtoul(p, NULL, 16);
			xref->addr_size = 8;
			found_insn = true;
			shiva_debug("xref->type: SHIVA_XREF_TYPE_IP_RELATIVE_LEA\n");
		}
	}

	if (found_insn == false)
		return true;
	xref->target_vaddr = xref->rip_rel_site + xref->rip_rel_disp + ctx->disas.insn->size;
	shiva_debug("Searching for symbol associated with address: %#lx\n", xref->target_vaddr);

	xref->insn_len = ctx->disas.insn->size;
	shiva_debug("Instruction len: %zu\n", xref->insn_len);
	/*
	 * Here we copy the x86_64 instruction byte sequence
	 * into xref->rip_rel_o_insn[16]
	 */
	for (i = 0; i < xref->insn_len; i++) {
		uint64_t b;

		if (elf_read_address(&ctx->elfobj, xref->rip_rel_site + i,
		    &b, ELF_BYTE) == false) {
			fprintf(stderr, "elf_read_address() failed reading addr %#lx\n",
			    xref->rip_rel_site);
			return false;
		}
		xref->rip_rel_o_insn[i] = (uint8_t)b;
	}
	memset(&symbol, 0, sizeof(symbol));

	/*
	 * Search, find, build symbolic information for XREF
	 */
	if (elf_symbol_by_value_lookup(&ctx->elfobj, xref->target_vaddr,
	    &symbol) == true) {
		shiva_debug("Target xref symbol '%s'\n", symbol.name);
		found_symbol = true;
	}
	if (found_symbol == false) {
		struct elf_section shdr;

		res = elf_section_by_address(&ctx->elfobj, xref->target_vaddr, &shdr);
		if (res == false) {
			fprintf(stderr, "Unable to find section associated with addr: %#lx\n",
			    xref->target_vaddr);
			return false;
		}
		symbol.name = shiva_xfmtstrdup("%s+%lx", shdr.name,
		    xref->target_vaddr - shdr.address);
		symbol.value = xref->target_vaddr;
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
		shiva_debug("Created custom symbol name: %s\n", symbol.name);
	}
	memcpy(&xref->symbol, &symbol, sizeof(symbol));

	struct elf_relocation rel;
	elf_relocation_iterator_t rel_iter;

	elf_relocation_iterator_init(&ctx->elfobj, &rel_iter);
	while (elf_relocation_iterator_next(&rel_iter, &rel) == ELF_ITER_OK) {
		if (strcmp(rel.shdrname, ".rela.dyn") != 0)
			continue;
		if (rel.offset != xref->target_vaddr)
			continue;
		switch (rel.type) {
		case R_X86_64_RELATIVE:

			if (elf_read_address(&ctx->elfobj, xref->target_vaddr, &qword,
			    ELF_QWORD) == false) {
				fprintf(stderr, "elf_read_address() failed to read %#lx\n", xref->target_vaddr);
				return false;
			}
			/*
			 * If It's a relative relocation, then it's r_offset will be in the
			 * data section, and never in the .bss. We can safely dereference
			 * target_vaddr to see if an offset lives there that points to another
			 * symbol.
			 */
			res = elf_symbol_by_value_lookup(&ctx->elfobj, qword, &deref_symbol);
			if (res == true) {
				xref->flags |= SHIVA_XREF_F_INDIRECT;
				xref->reloc_type = R_X86_64_RELATIVE;
				xref->got = (uint64_t *)xref->target_vaddr;
				shiva_debug("XREF (Indirect via GOT): Site: %#lx Target: %s (Deref)-> %s(%#lx)\n",
				    xref->rip_rel_site, symbol.name ? symbol.name : "<unknown>",
				    deref_symbol.name, deref_symbol.value);
				memcpy(&xref->deref_symbol, &deref_symbol, sizeof(struct elf_symbol));
			}
			break;
		case R_X86_64_COPY:
			if (elf_symbol_by_name(&ctx->elfobj, rel.symname, &deref_symbol) == true) {
				xref->flags |= SHIVA_XREF_F_INDIRECT;
				xref->reloc_type = R_X86_64_COPY;
				xref->got = (uint64_t *)xref->target_vaddr;
				shiva_debug("XREF (Indirect via GOT): Site: %#lx Target: %s (Deref)-> %s(%#lx)\n",
				    xref->rip_rel_site, symbol.name ? symbol.name : "<unknown>",
				    deref_symbol.name, deref_symbol.value);
				memcpy(&xref->deref_symbol, &deref_symbol, sizeof(struct elf_symbol));
			}
			break;
		case R_X86_64_GLOB_DAT:
			if (elf_symbol_by_name(&ctx->elfobj, rel.symname, &deref_symbol) == true) {
				xref->flags |= SHIVA_XREF_F_INDIRECT;
				xref->reloc_type = R_X86_64_GLOB_DAT;
				xref->got = (uint64_t *)xref->target_vaddr;
				shiva_debug("XREF (Indirect via GOT): Site: %#lx Target: %s (Deref)-> %s(%#lx)\n",
				    xref->rip_rel_site, symbol.name ? symbol.name : "<unknown>",
				    deref_symbol.name, deref_symbol.value);
				memcpy(&xref->deref_symbol, &deref_symbol, sizeof(struct elf_symbol));
			}
			break;
		default:
			break;
		}
	}

	if (elf_symbol_by_range(&ctx->elfobj,
	    current_vaddr, &tmp_sym) == true) {
		xref->flags |= SHIVA_XREF_F_SRC_SYMINFO;
		memcpy(&xref->current_function, &tmp_sym, sizeof(tmp_sym));
		shiva_debug("Source symbol included: %s\n", tmp_sym.name);
	}

	/*
	 * Insert xref entry
	 */
	shiva_debug("Inserting xref type: %d\n", xref->type);
	shiva_debug("Site: %#lx\n", xref->rip_rel_site);
	shiva_debug("Target: %s\n", symbol.name);
	TAILQ_INSERT_TAIL(&ctx->tailq.xref_tqlist, xref, _linkage);
	return true;
}
#elif __aarch64__
static bool
shiva_analyze_xrefs_aarch64(struct shiva_ctx *ctx, struct elf_section text)
{

	size_t code_len = ctx->disas.code_len;
	uint64_t code_vaddr = ctx->disas.code_vaddr;
	uint8_t *code_ptr = ctx->disas.code_ptr;

	if (strcmp(ctx->disas.insn->mnemonic, "adrp") == 0) {
		uint64_t adrp_imm, adrp_site;
		uint32_t adrp_o_bytes = *(uint32_t *)ctx->disas.insn->bytes;
		uint32_t next_o_bytes;

		shiva_debug("ADRP found\n");
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
		int xref_type;
		bool res;

		char *p = strchr(ctx->disas.insn->op_str, '#');

		if (p == NULL) {
			return true;
		}
		adrp_site = text.address + ctx->disas.c;
		adrp_imm = strtoul((p + 1), NULL, 16);
		target_page = (adrp_site & ~0xfff) + adrp_imm;
		res = cs_disasm_iter(ctx->disas.handle, (void *)&ctx->disas.code_ptr, 
		    &ctx->disas.code_len, &ctx->disas.code_vaddr, ctx->disas.insn);
		if (res == false) {
			fprintf(stderr, "cs_disasm_iter() failed\n");
			return false;
		}
		next_o_bytes = *(uint32_t *)ctx->disas.insn->bytes;
		ctx->disas.c += ARM_INSN_LEN;
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
			return true;
		}

		uint32_t tmp_imm;
		uint64_t qword;
		uint64_t xref_flags = 0;
		bool found_symbol = false;

		p = strchr(ctx->disas.insn->op_str, '#');
		if (p == NULL) {
			return true;
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
			return true;
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

		if (elf_symbol_by_range(&ctx->elfobj, ctx->disas.code_vaddr - 4,
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
	}
	return true;
}
#endif

bool 
shiva_analyze_call(struct shiva_ctx *ctx, struct elf_section text, bool *res)
{

	struct shiva_branch_site *tmp;
	int xref_type;
	size_t i, j;
	elf_symtab_iterator_t symtab_iter;

	shiva_debug("Mnemonic: %s\n", ctx->disas.insn->mnemonic);

#ifdef __aarch64__
	if (strcmp(ctx->disas.insn->mnemonic, "bl") == 0) {
#elif __x86_64__
	if (strcmp(ctx->disas.insn->mnemonic, "call") == 0) {
#endif
		struct shiva_branch_site *tmp;
		uint64_t addr, call_addr, call_site, retaddr;
		struct elf_symbol tmp_sym, symbol;
		shiva_debug("op_str: %s\n", ctx->disas.insn->op_str);
#ifdef __aarch64__
		char *p = strchr(ctx->disas.insn->op_str, '#');
		if (p == NULL)
			return true;
#endif
		*res = true;

		call_site = text.address + ctx->disas.c;
#ifdef __aarch64__
		call_addr = strtoul((p + 1), NULL, 16);
#elif __x86_64__
		call_addr = strtoul(ctx->disas.insn->op_str, NULL, 16);
#endif		
		retaddr = call_site + ctx->disas.insn->size;
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
					symbol.size = 16;
					symbol.value = call_addr; /* PLTCALL types get their symbol value set to addr of PLT entry */
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
		shiva_debug("CODE_PTR(%p): %lx at insn-offset %lx\n",
		    ctx->disas.code_ptr, *(uint32_t *)(ctx->disas.code_ptr - ctx->disas.insn->size), ctx->disas.insn_offset);
		memcpy(&tmp->o_insn, ctx->disas.code_ptr - ctx->disas.insn->size, ctx->disas.insn->size);
		memcpy(&tmp->symbol, &symbol, sizeof(symbol));
		tmp->branch_type = SHIVA_BRANCH_CALL;
		tmp->branch_site = call_site;
		tmp->branch_flags |= SHIVA_BRANCH_F_DST_SYMINFO;
		tmp->insn_string = shiva_xfmtstrdup("%s %s",
		    ctx->disas.insn->mnemonic, ctx->disas.insn->op_str);

		if (elf_symbol_by_range(&ctx->elfobj, ctx->disas.code_vaddr - 4,
		    &tmp_sym) == true) {
			tmp->branch_flags |= SHIVA_BRANCH_F_SRC_SYMINFO;
			memcpy(&tmp->current_function, &tmp_sym, sizeof(tmp_sym));
			shiva_debug("Source symbol included: %s\n", tmp_sym.name);
		}
		shiva_debug("Inserting branch for symbol %s callsite: %#lx\n", tmp->symbol.name, tmp->branch_site);
		TAILQ_INSERT_TAIL(&ctx->tailq.branch_tqlist, tmp, _linkage);
	}
	return true;
}

bool
shiva_analyze_branch(struct shiva_ctx *ctx, struct elf_section text, bool *res)
{
	bool retval;

#ifdef __aarch64__
	retval = shiva_analyze_branches_aarch64(ctx, text, res);
#elif __x86_64__
	retval = shiva_analyze_branches_x86_64(ctx, text, res);
#endif
	return retval;
}

bool
shiva_analyze_xref(struct shiva_ctx *ctx, struct elf_section text)
{
	bool res;
#ifdef __aarch64__
	shiva_debug("Calling shiva_analyze_xrefs_aarch64\n");
	res = shiva_analyze_xrefs_aarch64(ctx, text);
#elif __x86_64__
	res = shiva_analyze_xrefs_x86_64(ctx, text);
#endif
	return res;
}

bool
shiva_analyze_control_flow(struct shiva_ctx *ctx)
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
	ctx->disas.textptr = elf_address_pointer(&ctx->elfobj, section.address);
	struct shiva_branch_site *tmp;
	int xref_type;
	size_t i, j;
	elf_symtab_iterator_t symtab_iter;
	ctx->disas.code_vaddr = section.address; /* points to .text */
	ctx->disas.code_ptr = ctx->disas.textptr;
	ctx->disas.code_len = section.size - 1;
	uint8_t *tmp_ptr = ctx->disas.code_ptr;

#ifdef __x86_64__
	shiva_debug("CS_ARCH: CS_ARCH_X86\n");
	shiva_debug("CS_MODE: CS_MODE_64\n");
	cs_arch target_arch = CS_ARCH_X86;
	cs_mode mode = CS_MODE_64;
#elif __aarch64__
	cs_arch target_arch = CS_ARCH_ARM64;
	cs_mode mode = CS_MODE_LITTLE_ENDIAN;
#endif

	if (cs_open(target_arch, mode,
	    &ctx->disas.handle) != CS_ERR_OK) {
		fprintf(stderr, "cs_open failed\n");
		return false;
	}
	ctx->disas.insn = cs_malloc(ctx->disas.handle);
	/*
	 * For some reason CS_OPT_DETAIL is breaking
	 * cs_disasm_itercs_option(ctx->disas.handle, CS_OPT_DETAIL, CS_OPT_ON);
	 * -- We may alternatively parse the mnemonic and op strings
	 * cs_option(ctx->disas.handle, CS_OPT_DETAIL, CS_OPT_ON);
	 */

	shiva_debug("disassembling text(%#lx), %d bytes\n", section.address, section.size);
	for (ctx->disas.c = 0 ;; ctx->disas.c += ctx->disas.insn->size) {
		bool res, found;

		shiva_debug("Address: %#lx\n", section.address + ctx->disas.c);
		if (ctx->disas.c >= section.size)
			break;

		shiva_debug("code_ptr: %p\n", ctx->disas.code_ptr);
		shiva_debug("Counter offset: %d\n", ctx->disas.c);

		shiva_debug("insn->detail: %p\n", ctx->disas.insn->detail);
		res = cs_disasm_iter(ctx->disas.handle, (void *)&ctx->disas.code_ptr, &ctx->disas.code_len,
		    &ctx->disas.code_vaddr, ctx->disas.insn);
		if (res == false) {
			shiva_debug("code_ptr after fail: %p\n", ctx->disas.code_ptr);
			shiva_debug("code_vaddr after fail: %lx\n", ctx->disas.code_vaddr);
			shiva_debug("current insn len: %d\n", ctx->disas.insn->size);
			ctx->disas.code_vaddr += ctx->disas.insn->size;
			ctx->disas.code_ptr += ctx->disas.insn->size;
			continue;
		}
		shiva_debug("Mnemonic: %s\n", ctx->disas.insn->mnemonic);
		shiva_debug("INSN SIZE: %d\n", ctx->disas.insn->size);
		shiva_debug("0x%" PRIx64 ":\t%s\t\t%s\n", ctx->disas.insn->address,
		    ctx->disas.insn->mnemonic, ctx->disas.insn->op_str);

		shiva_debug("ctx->disas.c = %d\n", ctx->disas.c);
		/*
		 * NOTE:
		 * Shiva_analyze_branch updates ctx->disas.c internally so we
		 * should instead rely on "size_t insn_offset" which will remain
		 * the same offset between all three of these next 'shiva_analyze'
		 * functions. Otherwise the offset of ctx->disas.c will change from
		 * the call to shiva_analyze_branches to shiva_analyze_calls.
		 */
		ctx->disas.insn_offset = ctx->disas.c;

		res = shiva_analyze_branch(ctx, section, &found);
		if (res == false) {
			fprintf(stderr, "shiva_analyze_branches() failed\n");
			return false;
		}
		if (found == true)
			continue;

		shiva_debug("Running shiva_analyze_calls()\n");
		res = shiva_analyze_call(ctx, section, &found);
		if (res == false) {
			fprintf(stderr, "shiva_analyze_branches() failed\n");
			return false;
		}
		if (found == true)
			continue;

		shiva_debug("Running shiva_analyze_xrefs()\n");
		res = shiva_analyze_xref(ctx, section);
		if (res == false) {
			fprintf(stderr, "shiva_analyze_xrefs() failed\n");
			return false;
		}
	}
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

	if (shiva_target_has_prelinking(ctx) == false) {
		shiva_debug("Running shiva_analyze_find_calls\n");
		return shiva_analyze_control_flow(ctx);
	} else if ((ctx->prelink_flags & SHIVA_PRELINK_F_CFG_ENABLED) == 0) {
		shiva_debug("Prelink-CFG meta-data missing, running shiva_analye_find_calls\n");
		 return shiva_analyze_control_flow(ctx);
	}

	/*
	 * If the binary has been prelinked and has the appropriate
	 * CFG data:
	 * .shiva.xref and .shiva.branch sections which contain
	 * the CFG generated by shiva-ld, then we made it here.
	 */

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
		VALIDATE_STRTAB_OFFSET((size_t)branch_site.insn_string);
		branch_new->insn_string = (char *)&shiva_strtab[(size_t)branch_site.insn_string];
		TAILQ_INSERT_TAIL(&ctx->tailq.branch_tqlist, branch_new, _linkage);
	}
	return true;
}
