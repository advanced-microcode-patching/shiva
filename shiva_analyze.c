/*
 * shiva_analyze.c - Functions for performing control flow analysis, and gathering other
 */
#include "shiva.h"

#define BIT_MASK(n)	((1U << n) - 1)
#ifdef __aarch64__
#define ARM_INSN_LEN 4
#endif

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
		shiva_debug("(uint32_t)textptr: %#x\n", *(uint32_t *)&code_ptr[c]);
		if (c >= section.size)
			break;
		res = cs_disasm_iter(ctx->disas.handle, (void *)&code_ptr, &code_len,
		    &code_vaddr, ctx->disas.insn);
		for (;;) {
			if (*(uint32_t *)code_ptr != 0)
				break;
			code_ptr += ARM_INSN_LEN;
			code_vaddr += ARM_INSN_LEN;
			c += ARM_INSN_LEN;
		}
		shiva_debug("0x%"PRIx64":\t%s\t\t%s\n", ctx->disas.insn->address,
		    ctx->disas.insn->mnemonic, ctx->disas.insn->op_str);
		if (strcmp(ctx->disas.insn->mnemonic, "bl") == 0) {
			struct shiva_branch_site *tmp;
			uint64_t addr;
			char *p = strchr(ctx->disas.insn->op_str, '#');

			if (p == NULL) {
				fprintf(stderr, "unexpected error parsing: '%s'\n",
				    ctx->disas.insn->op_str);
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
			shiva_debug("Inserting branch for symbol %s\n", symbol.name);
			TAILQ_INSERT_TAIL(&ctx->tailq.branch_tqlist, tmp, _linkage);
		} else if (strcmp(ctx->disas.insn->mnemonic, "adrp") == 0) {
			uint64_t adrp_imm, adrp_site;
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
				fprintf(stderr, "unexpected error parsing: '%s'\n",
				    ctx->disas.insn->op_str);
				return false;
			}
			adrp_site = section.address + c;
			adrp_imm = strtoul((p + 1), NULL, 16);
			target_page = (adrp_site & ~0xfff) + adrp_imm;
			res = cs_disasm_iter(ctx->disas.handle, (void *)&code_ptr, &code_len,
			    &code_vaddr, ctx->disas.insn);
			c += ARM_INSN_LEN;
			if (res == false) {
				fprintf(stderr, "cs_disasm_iter() failed\n");
				return false;
			}
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

			p = strchr(ctx->disas.insn->op_str, '#');
			if (p == NULL) {
				fprintf(stderr, "unexpected error parsing: '%s'\n",
				    ctx->disas.insn->op_str);
				return false;
			}
			tmp_imm = strtoul((p + 1), NULL, 16);
			shiva_debug("Looking up symbol at address %#lx in"
			    " the target executable\n", target_page + tmp_imm);
			if (elf_symbol_by_value_lookup(&ctx->elfobj,
			    target_page + tmp_imm, &symbol) == true) {
				xref = calloc(1, sizeof(*xref));
				if (xref == NULL) {
					perror("calloc");
					return false;
				}
				shiva_debug("XREF (Type: %d): site: %#lx target: %s(%#lx)\n",
				    xref_type, adrp_site, symbol.name, symbol.value);
				xref->type = xref_type;
				xref->adrp_imm = adrp_imm;
				xref->adrp_site = adrp_site;
				xref->tmp_imm = tmp_imm;
				xref->tmp_site = adrp_site + ARM_INSN_LEN;
				xref->adrp_o_insn = *(uint32_t *)code_ptr - ARM_INSN_LEN;
				xref->tmp_o_insn = *(uint32_t *)code_ptr;
				printf("ADRP: %x\n", xref->adrp_o_insn);
				printf("NEXT: %x\n", xref->tmp_o_insn);
				memcpy(&xref->symbol, &symbol, sizeof(symbol));
				TAILQ_INSERT_TAIL(&ctx->tailq.xref_tqlist, xref, _linkage);
			}
		}
	}
#endif
	return true;
}

bool
shiva_analyze_run(struct shiva_ctx *ctx)
{
	shiva_debug("Running shiva_analyze_find_calls\n");
	return shiva_analyze_find_calls(ctx);
}
