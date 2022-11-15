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
	size_t c, i, j;
	size_t code_len = section.size - 1;
	uint64_t code_vaddr = section.address; /* Points to .text */
	struct elf_symbol;
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
		res = cs_disasm_iter(ctx->disas.handle, &code_ptr, &code_len,
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
			struct shiva_branch_site *tmp;
			uint64_t xref_site, xref_addr;
			char *p = strchr(ctx->disas.insn->op_str, '#');

                        if (p == NULL) {
                                fprintf(stderr, "unexpected error parsing: '%s'\n",
                                    ctx->disas.insn->op_str);
                                return false;
                        }
			adrp_site = section.address + c;
			adrp_imm = strtoul((p + 1), NULL, 16);
			target_page = (adrp_site & ~0xfff) + adrp_imm;



		}
	}
#if 0
	
	printf("Address of .text: %#lx\n", section.address);
	printf("Looping through %d bytes\n", section.size);
	for (i = 0; i < section.size; i+=4) {
		uint64_t insn;
		uint8_t *iptr = &insn;

		if (elf_read_address(&ctx->elfobj,
		    section.address + i, &insn, ELF_DWORD /*32bit*/) == false) {
			fprintf(stderr, "elf_read_address() failed\n");
			return false;
		}
		/*
		 * AARCH64 bl instruction (Branch with link)
		 */
		
		if ((insn & 0xff000000) == 0x94) {
			int64_t imm;

			imm = insn & BIT_MASK(26 - 1);
			printf("Imm: %x", insn);
			printf("Found BL instruction: %x\n", insn);

		}
		printf(".");
		printf("i: %d\n", i);
	}
#endif
#endif
	return true;
}

bool
shiva_analyze_run(struct shiva_ctx *ctx)
{
	shiva_debug("Running shiva_analyze_find_calls\n");
	return shiva_analyze_find_calls(ctx);
}
