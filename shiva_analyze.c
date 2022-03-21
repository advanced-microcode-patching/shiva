/*
 * shiva_analyze.c - Functions for performing control flow analysis, and gathering other
 */
#include "shiva.h"

bool
shiva_analyze_find_calls(struct shiva_ctx *ctx)
{
	struct elf_section section;
	struct elf_symbol symbol;
	const uint8_t *ptr;
	uint64_t call_site, call_addr, runtime_addr;
	uint64_t current_address = ctx->disas.base;
	int64_t call_offset;
	int bits;

	if (elf_section_by_name(&ctx->elfobj, ".text", &section) == false) {
		fprintf(stderr, "elf_section_by_name() failed\n");
		return false;
	}
	bits = elf_class(&ctx->elfobj) == elfclass64 ? 64 : 32;
	ud_init(&ctx->disas.ud_obj);
	ud_set_input_buffer(&ctx->disas.ud_obj, ctx->disas.textptr, section.size);
	ud_set_mode(&ctx->disas.ud_obj, bits);
	ud_set_syntax(&ctx->disas.ud_obj, UD_SYN_INTEL);
	while (ud_disassemble(&ctx->disas.ud_obj) != 0) {
		struct shiva_branch_site *tmp;
		size_t insn_len = ud_insn_len(&ctx->disas.ud_obj);

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
		printf("Found a call instruction\n");
		tmp = calloc(1, sizeof(*tmp));
		if (tmp == NULL) {
			perror("calloc");
			return false;
		}
		int i;
		for (i = 0; i < 5; i++) {
			printf("%02x ", ptr[i]);
		}
		printf("\n");
		call_offset = *(uint32_t *)&ptr[1];
		printf("call_offset: %#lx\n", call_offset);
		call_site = current_address;
		printf("call_site: %#lx\n", call_site);
		call_addr = call_site + call_offset + 5;
		call_addr &= 0xffffffff;
		printf("call_addr: %#lx\n", call_addr);
		if (elf_symbol_by_value(&ctx->elfobj, call_addr,
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
				printf("Comparing %#lx to call_addr: %#lx\n", plt_entry.addr, call_addr);
				if (plt_entry.addr == call_addr) {
					symbol.name = shiva_xfmtstrdup("%s@plt", plt_entry.symname);
					symbol.type = STT_FUNC;
					symbol.bind = STB_GLOBAL;
					symbol.size = 0;
					break;
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
		printf("symbol name: %s\n", symbol.name);
		memcpy(&tmp->symbol, &symbol, sizeof(symbol));
		tmp->branch_type = SHIVA_BRANCH_CALL;
		tmp->target_vaddr = runtime_addr;
		tmp->branch_site = call_site;
		TAILQ_INSERT_TAIL(&ctx->tailq.branch_tqlist, tmp, _linkage);
		current_address += insn_len;
	}
	return true;
}

bool
shiva_analyze_run(struct shiva_ctx *ctx)
{
	shiva_debug("Running shiva_analyze_find_calls\n");
	return shiva_analyze_find_calls(ctx);
}
